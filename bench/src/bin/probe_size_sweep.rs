//! Sweeps `Config::probe_size` against a real corpus: how would a smaller
//! probe window change accept/reject decisions and CPU cost, without
//! running the race N times. Compares a prefix probe (first N chunks, what
//! `compress` uses) against N chunks spread evenly across the file (what
//! `estimate` uses).
//!
//! Key invariant: with one race algorithm, whenever the window's own gate
//! passes, `compress_chunked`'s decision always matches a whole-file probe
//! (see `engine.rs`), so a smaller `probe_size` can only produce a false
//! reject, never a false accept. One real LZFSE pass per file, replayed
//! against each probe size's precomputed chunk sizes, answers every size.
//!
//! Only chunked-path files that `policy::should_skip` (default `Config`)
//! lets through are considered; this excludes already-`UF_COMPRESSED` files,
//! whose recompression basis diverges from the probe-window basis.
//!
//! Run with:
//!   find /some/dir -type f | cargo run --release -p apfscompress-bench --bin probe_size_sweep > out.tsv
//! Env vars: MAX_RATIO (default 1.0), PROBE_SIZES (default a 64KiB-16MiB
//! ladder including the current 5MiB default).
//!
//! Output: one TSV row per file to stdout (ground truth plus prefix/scattered
//! accept per probe_size); to stderr, per-probe_size tables of bytes needed
//! to decide vs. whole-file bytes, and missed savings among false rejects.

use apfscompress::algo::Algo;
use apfscompress::chunker;
use apfscompress::decmpfs::{self, ChunkOutput};
use apfscompress::policy::{self, Config};
use rayon::prelude::*;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

/// The single algorithm the replay uses; see the invariant above for why it
/// must be one algorithm rather than a race.
const ALGO: Algo = Algo::Lzfse;

const DEFAULT_PROBE_SIZES: &[u64] = &[
    64 * 1024,
    128 * 1024,
    256 * 1024,
    512 * 1024,
    1024 * 1024,
    2 * 1024 * 1024,
    5 * 1024 * 1024, // current Config::default() probe_size
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

/// `k` chunk indices spread evenly across `[0, n)`, starting at 0: a
/// deterministic stand-in for "sample chunks scattered across the file"
/// that needs no RNG. Falls back to every index once `k >= n`.
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

/// Whether a probe window over exactly `indices` (into `ranges`/`chunks`)
/// would reject at `max_ratio`, and how many uncompressed bytes that window
/// covers. Shared by both the prefix and scattered strategies - only the
/// index selection differs between them.
fn window_gate(ranges: &[(usize, usize)], chunks: &[ChunkOutput], overhead: u64, max_ratio: f64, indices: &[usize]) -> (bool, u64) {
    let uncompressed_total: u64 = indices.iter().map(|&i| (ranges[i].1 - ranges[i].0) as u64).sum();
    let compressed_total: u64 =
        decmpfs::HEADER_LEN as u64 + overhead + indices.iter().map(|&i| chunks[i].bytes.len() as u64).sum::<u64>();
    let target = policy::target_size(uncompressed_total, max_ratio);
    (policy::cumulative_exceeds_target(compressed_total, target), uncompressed_total)
}

/// Whether this file would be accepted under one strategy at one probe_size,
/// and how many uncompressed bytes had to be fed through LZFSE to reach that
/// decision (window-only on a probe reject, whole file on an accept).
#[derive(Clone, Copy)]
struct ProbeOutcome {
    accept: bool,
    bytes_to_decide: u64,
}

struct ProbeAtSize {
    probe_size: u64,
    prefix: ProbeOutcome,
    scattered: ProbeOutcome,
}

struct FileResult {
    path: PathBuf,
    size: u64,
    ground_truth_accept: bool,
    /// The real whole-file compressed footprint (header + overhead + every
    /// chunk's compressed bytes): what a false-reject at some `probe_size`
    /// actually gave up, in bytes. Always populated since it falls out of
    /// the same one-pass compression this tool already does.
    whole_file_footprint: u64,
    per_probe: Vec<ProbeAtSize>,
}

enum Verdict {
    Considered(FileResult),
    Skipped(String),
    Error(String),
}

/// Mirrors `compress_chunked`'s own probe-window arithmetic (engine.rs)
/// exactly for the prefix strategy - same window selection, overhead basis,
/// and gate, just replayed against one precomputed compression pass. The
/// scattered strategy reuses the same gate and chunk count, just a
/// different index selection (see `scattered_indices`).
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
        return Verdict::Skipped("Inline".to_string());
    }

    let ranges = chunker::chunk_ranges(size);
    let chunks = chunker::compress_chunks(&data, ALGO);
    let overhead = decmpfs::rsrc_footprint_overhead(ALGO, ranges.len());

    let whole_bytes: u64 = chunks.iter().map(|c| c.bytes.len() as u64).sum();
    let whole_file_footprint = decmpfs::HEADER_LEN as u64 + overhead + whole_bytes;
    let target = policy::target_size(size, cfg.max_ratio);
    let ground_truth_accept = !policy::cumulative_exceeds_target(whole_file_footprint, target);

    let per_probe = sizes
        .iter()
        .map(|&probe_size| {
            let probe_chunk_count =
                ranges.iter().take_while(|&&(s, _)| (s as u64) < probe_size).count().max(1).min(ranges.len());

            let prefix_indices: Vec<usize> = (0..probe_chunk_count).collect();
            let (rejected_prefix, unc_prefix) = window_gate(&ranges, &chunks, overhead, cfg.max_ratio, &prefix_indices);
            let prefix = if rejected_prefix {
                ProbeOutcome { accept: false, bytes_to_decide: unc_prefix }
            } else {
                ProbeOutcome { accept: ground_truth_accept, bytes_to_decide: size }
            };

            let scattered_idx = scattered_indices(probe_chunk_count, ranges.len());
            let (rejected_scattered, unc_scattered) = window_gate(&ranges, &chunks, overhead, cfg.max_ratio, &scattered_idx);
            let scattered = if rejected_scattered {
                ProbeOutcome { accept: false, bytes_to_decide: unc_scattered }
            } else {
                ProbeOutcome { accept: ground_truth_accept, bytes_to_decide: size }
            };

            ProbeAtSize { probe_size, prefix, scattered }
        })
        .collect();

    Verdict::Considered(FileResult { path: path.to_path_buf(), size, ground_truth_accept, whole_file_footprint, per_probe })
}

#[derive(Default, Clone, Copy)]
struct Aggregate {
    considered: u64,
    ground_truth_accepts: u64,
    agree: u64,
    false_rejects: u64,
    bytes_to_decide: u64,
    whole_file_bytes: u64,
    /// Sums over just the false-rejected files at this probe_size - what
    /// compressing them for real would have actually produced, so the
    /// "missed savings" (original - would_be_compressed) can be reported in
    /// bytes, not just a count of how many files disagreed.
    false_reject_original: u64,
    false_reject_would_be_compressed: u64,
}

impl Aggregate {
    fn accumulate(&mut self, file_size: u64, whole_file_footprint: u64, ground_truth_accept: bool, o: ProbeOutcome) {
        self.considered += 1;
        self.whole_file_bytes += file_size;
        self.bytes_to_decide += o.bytes_to_decide;
        if ground_truth_accept {
            self.ground_truth_accepts += 1;
        }
        if o.accept == ground_truth_accept {
            self.agree += 1;
        } else {
            // Only possible mismatch direction - see this file's module doc
            // comment.
            self.false_rejects += 1;
            self.false_reject_original += file_size;
            self.false_reject_would_be_compressed += whole_file_footprint;
        }
    }
}

fn main() {
    let sizes = probe_sizes();
    let cfg = Config { max_ratio: max_ratio(), ..Config::default() };

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

    let header: String = sizes.iter().map(|s| format!("\tprobe={s}p\tprobe={s}s")).collect::<Vec<_>>().join("");
    let _ = writeln!(out, "# path\tsize\tground_truth{header}");

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
                let gt = if r.ground_truth_accept { "accept" } else { "reject" };
                let cols: String = r
                    .per_probe
                    .iter()
                    .map(|p| {
                        format!(
                            "\t{}:{}\t{}:{}",
                            p.probe_size,
                            if p.prefix.accept { "accept" } else { "reject" },
                            p.probe_size,
                            if p.scattered.accept { "accept" } else { "reject" }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("");
                let _ = writeln!(out, "{}\t{}\t{}{}", r.path.display(), r.size, gt, cols);

                for ((ap, asc), p) in agg_prefix.iter_mut().zip(agg_scattered.iter_mut()).zip(r.per_probe.iter()) {
                    ap.accumulate(r.size, r.whole_file_footprint, r.ground_truth_accept, p.prefix);
                    asc.accumulate(r.size, r.whole_file_footprint, r.ground_truth_accept, p.scattered);
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

    // bytes_vs_full% is sum(bytes_to_decide)/sum(whole_file_bytes) - a ratio
    // of totals (bigger files weigh more), not a mean of each file's percentage.
    eprintln!(
        "\n{:>10} | {:>8} {:>10} {:>10} | {:>8} {:>10} {:>10}",
        "probe_size", "prefix", "", "", "scattered", "", ""
    );
    eprintln!(
        "{:>10} | {:>8} {:>10} {:>10} | {:>8} {:>10} {:>10}",
        "", "agree%", "probed_GiB", "vs_full%", "agree%", "probed_GiB", "vs_full%"
    );
    for i in 0..sizes.len() {
        let (size, p, s) = (sizes[i], agg_prefix[i], agg_scattered[i]);
        let agree = |a: Aggregate| if a.considered > 0 { 100.0 * a.agree as f64 / a.considered as f64 } else { 0.0 };
        let vs_full =
            |a: Aggregate| if a.whole_file_bytes > 0 { 100.0 * a.bytes_to_decide as f64 / a.whole_file_bytes as f64 } else { 0.0 };
        eprintln!(
            "{:>10} | {:>7.1}% {:>10.3} {:>9.1}% | {:>7.1}% {:>10.3} {:>9.1}%",
            size,
            agree(p),
            p.bytes_to_decide as f64 / GIB,
            vs_full(p),
            agree(s),
            s.bytes_to_decide as f64 / GIB,
            vs_full(s)
        );
    }

    eprintln!("\n-- false-rejected files only: what compressing them for real would have produced --");
    eprintln!(
        "{:>10} | {:>6} {:>10} {:>8} {:>10} | {:>6} {:>10} {:>8} {:>10}",
        "probe_size", "ct", "orig_GiB", "ratio", "missed_GiB", "ct", "orig_GiB", "ratio", "missed_GiB"
    );
    for i in 0..sizes.len() {
        let (size, p, s) = (sizes[i], agg_prefix[i], agg_scattered[i]);
        let row = |a: Aggregate| -> String {
            if a.false_rejects == 0 {
                return format!("{:>6} {:>10} {:>8} {:>10}", 0, "-", "-", "-");
            }
            let orig_gib = a.false_reject_original as f64 / GIB;
            let ratio = a.false_reject_would_be_compressed as f64 / a.false_reject_original as f64;
            let missed_gib = orig_gib - a.false_reject_would_be_compressed as f64 / GIB;
            format!("{:>6} {:>10.4} {:>8.3} {:>10.4}", a.false_rejects, orig_gib, ratio, missed_gib)
        };
        eprintln!("{:>10} | {} | {}", size, row(p), row(s));
    }
}
