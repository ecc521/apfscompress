//! Accuracy backtest for `engine::estimate_chunked` (the `estimate`
//! subcommand's predictor): how far off is its probe-and-extrapolate guess
//! from a real compression pass, at various `probe_size`s, and whether
//! scattered-chunk sampling (what `estimate_chunked` actually uses) beats a
//! leading-prefix probe (what `compress`'s `probe_chunked` uses instead).
//! Since the accept/reject decision is made against the extrapolated total,
//! estimate can be wrong either way: a window-gate false reject, or a false
//! accept from over-optimistic extrapolation. Ground truth per file is a
//! real, complete compression pass per candidate, replayed against each
//! probe subset (same trick as `probe_size_sweep.rs`).
//!
//! Run with:
//!   find /some/dir -type f | cargo run --release -p apfscompress-bench --bin estimate_accuracy_sweep > out.tsv
//! Env vars: MAX_RATIO, PROBE_SIZES (same meaning as `probe_size_sweep.rs`).
//!
//! Output: one TSV row per considered file to stdout; to stderr, per
//! probe_size x strategy (prefix/scattered), decision-accuracy counts and a
//! total-disk-usage comparison of estimated vs. actual.

use apfscompress::algo::Algo;
use apfscompress::chunker;
use apfscompress::decmpfs;
use apfscompress::policy::{self, Config};
use rayon::prelude::*;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

/// The race `estimate` runs by default, so the backtest tracks the shipped setting.
fn candidates() -> Vec<Algo> {
    let cfg = Config::default();
    cfg.algorithms.as_slice().to_vec()
}

const DEFAULT_PROBE_SIZES: &[u64] = &[
    64 * 1024,
    128 * 1024,
    256 * 1024,
    512 * 1024,
    1024 * 1024,
    2 * 1024 * 1024,
    5 * 1024 * 1024,
    16 * 1024 * 1024,
];

fn probe_sizes() -> Vec<u64> {
    std::env::var("PROBE_SIZES")
        .ok()
        .map(|s| s.split(',').filter_map(|p| p.trim().parse::<u64>().ok()).collect::<Vec<_>>())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_PROBE_SIZES.to_vec())
}

fn max_ratio() -> f64 {
    std::env::var("MAX_RATIO").ok().and_then(|s| s.parse().ok()).unwrap_or(1.0)
}

/// See `probe_size_sweep.rs` - same deterministic stand-in for "scattered
/// across the file" (no RNG needed).
fn scattered_indices(k: usize, n: usize) -> Vec<usize> {
    if n == 0 {
        return Vec::new();
    }
    let k = k.min(n).max(1);
    if k >= n {
        return (0..n).collect();
    }
    (0..k).map(|i| (i * n) / k).collect()
}

/// One candidate algorithm's real, whole-file per-chunk compressed sizes,
/// computed once per file then replayed against arbitrary index subsets
/// (prefix or scattered) to answer every swept probe_size without
/// recompressing, same trick `probe_size_sweep.rs` uses.
struct AlgoChunks {
    chunk_bytes: Vec<u64>,
    overhead: u64, // rsrc_footprint_overhead(algo, ranges.len()); depends on whole-file chunk count, not the window
}

fn window_footprint(ac: &AlgoChunks, indices: &[usize]) -> u64 {
    decmpfs::HEADER_LEN as u64 + ac.overhead + indices.iter().map(|&i| ac.chunk_bytes[i]).sum::<u64>()
}

#[derive(Clone, Copy)]
struct Prediction {
    accept: bool,
    predicted_footprint: u64,
    exact: bool,
    /// True when the window itself failed its own scaled gate (same failure
    /// mode as `compress_chunked`). `false` with `accept == false` can also
    /// mean the window passed but the extrapolated total failed the
    /// whole-file gate - a second, estimate-only rejection path.
    window_gate_rejected: bool,
}

struct FileResult {
    path: PathBuf,
    size: u64,
    real_footprint: u64,
    real_accept: bool,
    /// [probe_size index][strategy: 0=prefix, 1=scattered]
    predictions: Vec<[Prediction; 2]>,
}

enum Verdict {
    Considered(FileResult),
    Skipped(String),
    Error(String),
}

fn predict(ranges: &[(usize, usize)], algos: &[AlgoChunks], size: u64, max_ratio: f64, indices: &[usize]) -> Prediction {
    let uncompressed_total: u64 = indices.iter().map(|&i| (ranges[i].1 - ranges[i].0) as u64).sum();
    let probe_target = policy::target_size(uncompressed_total, max_ratio);

    let (best_idx, window_footprint_bytes) =
        algos.iter().enumerate().map(|(i, ac)| (i, window_footprint(ac, indices))).min_by_key(|&(_, f)| f).unwrap();

    if policy::cumulative_exceeds_target(window_footprint_bytes, probe_target) {
        return Prediction { accept: false, predicted_footprint: window_footprint_bytes, exact: false, window_gate_rejected: true };
    }

    let exact = indices.len() >= ranges.len();
    let predicted_footprint = if exact {
        window_footprint_bytes
    } else {
        let ac = &algos[best_idx];
        let probe_data_bytes = window_footprint_bytes - decmpfs::HEADER_LEN as u64 - ac.overhead;
        let remaining_uncompressed = size - uncompressed_total;
        let predicted_ratio = probe_data_bytes as f64 / uncompressed_total as f64;
        let predicted_remaining = (remaining_uncompressed as f64 * predicted_ratio).round() as u64;
        window_footprint_bytes + predicted_remaining
    };

    let target = policy::target_size(size, max_ratio);
    let accept = !policy::cumulative_exceeds_target(predicted_footprint, target);
    Prediction { accept, predicted_footprint, exact, window_gate_rejected: false }
}

fn evaluate(path: &Path, cfg: &Config, sizes: &[u64]) -> Verdict {
    match policy::should_skip(path, cfg) {
        Ok(Some(reason)) => return Verdict::Skipped(format!("{reason:?}")),
        Err(e) => return Verdict::Error(format!("stat: {e}")),
        Ok(None) => {}
    }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return Verdict::Error(format!("read: {e}")),
    };
    let size = data.len() as u64;
    if data.len() <= decmpfs::MAX_INLINE_PAYLOAD {
        return Verdict::Skipped("Inline".to_string()); // always exact, no extrapolation to test
    }

    let ranges = chunker::chunk_ranges(size);
    let algos: Vec<AlgoChunks> = candidates()
        .iter()
        .map(|&algo| {
            let chunks = chunker::compress_chunks(&data, algo);
            let chunk_bytes = chunks.iter().map(|c| c.bytes.len() as u64).collect();
            let overhead = decmpfs::rsrc_footprint_overhead(algo, ranges.len());
            AlgoChunks { chunk_bytes, overhead }
        })
        .collect();

    let all_indices: Vec<usize> = (0..ranges.len()).collect();
    let real_footprint = algos.iter().map(|ac| window_footprint(ac, &all_indices)).min().unwrap();
    let target = policy::target_size(size, cfg.max_ratio);
    let real_accept = !policy::cumulative_exceeds_target(real_footprint, target);

    let predictions = sizes
        .iter()
        .map(|&probe_size| {
            let k = ranges.iter().take_while(|&&(s, _)| (s as u64) < probe_size).count().max(1).min(ranges.len());
            let prefix_indices: Vec<usize> = (0..k).collect();
            let scattered_idx = scattered_indices(k, ranges.len());
            [
                predict(&ranges, &algos, size, cfg.max_ratio, &prefix_indices),
                predict(&ranges, &algos, size, cfg.max_ratio, &scattered_idx),
            ]
        })
        .collect();

    Verdict::Considered(FileResult { path: path.to_path_buf(), size, real_footprint, real_accept, predictions })
}

#[derive(Default, Clone, Copy)]
struct Aggregate {
    considered: u64,
    exact: u64,
    extrapolated: u64,
    window_gate_false_reject: u64,
    extrap_false_accept: u64,
    extrap_false_reject: u64,
    /// Sum of |predicted - real| / real over extrapolated files only, to
    /// average into a mean absolute percentage error afterwards.
    abs_pct_error_sum: f64,
    total_original: u64,
    /// What's actually left on disk after a real compress run: real_footprint
    /// where the file truly compresses, else original_size (left untouched).
    true_kept: u64,
    /// Same, but from this strategy's own accept decision and predicted
    /// number - what a user trusting `apfscompress estimate`'s total would
    /// expect the tree's disk usage to become.
    predicted_kept: u64,
}

fn main() {
    let sizes = probe_sizes();
    let cfg = Config { max_ratio: max_ratio(), algorithms: policy::Algorithms::custom(candidates()).unwrap(), ..Config::default() };

    let stdin = io::stdin();
    let paths: Vec<PathBuf> = stdin
        .lock()
        .lines()
        .map_while(Result::ok)
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .map(PathBuf::from)
        .collect();

    let results: Vec<Verdict> = paths.par_iter().map(|p| evaluate(p, &cfg, &sizes)).collect();

    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let header: String = sizes.iter().map(|s| format!("\tpredp={s}\tpreds={s}")).collect::<Vec<_>>().join("");
    let _ = writeln!(out, "# path\tsize\treal_footprint\treal_accept{header}");

    let mut skip_reasons: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut errored: u64 = 0;
    let mut agg_prefix: Vec<Aggregate> = sizes.iter().map(|_| Aggregate::default()).collect();
    let mut agg_scattered: Vec<Aggregate> = sizes.iter().map(|_| Aggregate::default()).collect();

    for v in results {
        match v {
            Verdict::Skipped(reason) => *skip_reasons.entry(reason).or_insert(0) += 1,
            Verdict::Error(msg) => {
                errored += 1;
                eprintln!("error: {msg}");
            }
            Verdict::Considered(r) => {
                let cols: String = r
                    .predictions
                    .iter()
                    .map(|p| format!("\t{}\t{}", p[0].predicted_footprint, p[1].predicted_footprint))
                    .collect::<Vec<_>>()
                    .join("");
                let _ = writeln!(out, "{}\t{}\t{}\t{}{}", r.path.display(), r.size, r.real_footprint, r.real_accept, cols);

                for (aggs, idx) in [(&mut agg_prefix, 0usize), (&mut agg_scattered, 1usize)] {
                    for (agg, p) in aggs.iter_mut().zip(r.predictions.iter()) {
                        let p = p[idx];
                        agg.considered += 1;
                        agg.total_original += r.size;
                        agg.true_kept += if r.real_accept { r.real_footprint } else { r.size };
                        agg.predicted_kept += if p.accept { p.predicted_footprint } else { r.size };

                        if p.window_gate_rejected {
                            if r.real_accept {
                                agg.window_gate_false_reject += 1;
                            }
                            continue;
                        }
                        if p.exact {
                            agg.exact += 1;
                            continue;
                        }
                        agg.extrapolated += 1;
                        agg.abs_pct_error_sum +=
                            ((p.predicted_footprint as f64 - r.real_footprint as f64) / r.real_footprint as f64).abs();
                        match (p.accept, r.real_accept) {
                            (true, false) => agg.extrap_false_accept += 1,
                            (false, true) => agg.extrap_false_reject += 1,
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    let skipped: u64 = skip_reasons.values().sum();
    eprintln!(
        "considered={} skipped={} ({:?}) errored={}",
        agg_prefix.first().map(|a| a.considered).unwrap_or(0),
        skipped,
        skip_reasons,
        errored
    );

    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    eprintln!(
        "\n{:>10} | {:>6} {:>6} {:>8} {:>8} {:>8} {:>8} | {:>6} {:>6} {:>8} {:>8} {:>8} {:>8}",
        "probe_size", "exact", "extrap", "win_rej", "fls_acc", "fls_rej", "mape%", "exact", "extrap", "win_rej", "fls_acc", "fls_rej", "mape%"
    );
    eprintln!("-- decision accuracy: prefix (left) vs scattered (right) --");
    for i in 0..sizes.len() {
        let row = |a: Aggregate| -> String {
            let mape = if a.extrapolated > 0 { 100.0 * a.abs_pct_error_sum / a.extrapolated as f64 } else { 0.0 };
            format!(
                "{:>6} {:>6} {:>8} {:>8} {:>8} {:>7.2}%",
                a.exact, a.extrapolated, a.window_gate_false_reject, a.extrap_false_accept, a.extrap_false_reject, mape
            )
        };
        eprintln!("{:>10} | {} | {}", sizes[i], row(agg_prefix[i]), row(agg_scattered[i]));
    }

    eprintln!("\n-- total disk usage after, GiB: what a user trusting the estimate would expect vs. real --");
    eprintln!(
        "{:>10} | {:>10} {:>10} {:>10} | {:>10} {:>10} {:>10}",
        "probe_size", "true_GiB", "pred_GiB", "err_GiB", "true_GiB", "pred_GiB", "err_GiB"
    );
    for i in 0..sizes.len() {
        let row = |a: Aggregate| -> String {
            let true_gib = a.true_kept as f64 / GIB;
            let pred_gib = a.predicted_kept as f64 / GIB;
            format!("{:>10.4} {:>10.4} {:>10.4}", true_gib, pred_gib, pred_gib - true_gib)
        };
        eprintln!("{:>10} | {} | {}", sizes[i], row(agg_prefix[i]), row(agg_scattered[i]));
    }
    if let Some(a) = agg_prefix.first() {
        eprintln!("\n(total_original = {:.4} GiB, same both strategies/all probe sizes)", a.total_original as f64 / GIB);
    }
}
