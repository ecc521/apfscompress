//! Measures whether `compress_chunked`'s probe window costs anything extra
//! over a single fully-parallel dispatch (`chunker::compress_chunks`) of the
//! same chunks. A regression guard: `compress_chunked` must not regress into
//! wave-batching, which adds a straggler tax (each wave is a barrier, so a
//! slow-core thread stalls it, and scratch-buffer reuse resets every wave).
//!
//! Run with `cargo run --release -p apfscompress-bench --bin bench_scheduling`.
//! Part 1 sweeps probe-window sizes vs. thread count; part 2 compares the
//! default 5MB window against unbounded on one 100MB file. Ratio near 1.0x
//! is healthy; well above it means the probe window adds overhead.

use apfscompress::algo::Algo;
use apfscompress::{chunker, decmpfs, engine, policy};
use std::time::Instant;

fn compressible(n: usize) -> Vec<u8> {
    b"The quick brown fox jumps over the lazy dog. ".iter().copied().cycle().take(n).collect()
}

fn main() {
    let threads = rayon::current_num_threads();
    println!("rayon thread pool size: {threads}  (this machine's core mix -- see `sysctl hw.perflevel*` for P/E split)\n");

    println!("--- dispatch parity: highly compressible data across probe-window sizes ---");
    println!(
        "{:>16}  {:>10}  {:>14}  {:>14}  {:>7}",
        "chunks (xthreads)", "size", "probe window", "one-shot", "ratio"
    );
    let chunk_size = decmpfs::CHUNK_SIZE;
    for &mult in &[1usize, 2, 4, 8, 16] {
        let n_chunks = threads * mult;
        let size = n_chunks * chunk_size;
        let data = compressible(size);
        let iters: u32 = if size > 32 * 1024 * 1024 { 5 } else { 15 };

        // Make the whole buffer the probe window, so this measures the
        // probe-window dispatch specifically, not a mix with the post-probe phase.
        let cfg = policy::Config {
            probe_size: size as u64,
            max_ratio: 1.0,
            algorithms: policy::Algorithms::single(Algo::Lzfse),
            ..policy::Config::default()
        };

        let start = Instant::now();
        for _ in 0..iters {
            let _ = engine::compress_bytes(&data, &cfg);
        }
        let probe_time = start.elapsed() / iters;

        let start = Instant::now();
        for _ in 0..iters {
            let _ = chunker::compress_chunks(&data, Algo::Lzfse);
        }
        let oneshot_time = start.elapsed() / iters;

        let ratio = probe_time.as_secs_f64() / oneshot_time.as_secs_f64();
        println!(
            "{:>13} ({mult:>2}x)  {:>8.2}MB  {:>12.3}ms  {:>12.3}ms  {ratio:>6.2}x",
            n_chunks,
            size as f64 / 1_000_000.0,
            probe_time.as_secs_f64() * 1000.0,
            oneshot_time.as_secs_f64() * 1000.0,
        );
    }
    println!();

    // Part 2: default probe_size (5MB) vs unbounded (set to the file's own
    // size, so the post-probe phase never runs); single-algorithm only.
    println!("--- realistic file: 100MB highly compressible, default probe window (5MB) vs unbounded ---");
    {
        let size = 100 * 1024 * 1024;
        let data = compressible(size);
        let iters: u32 = 5;

        let default_cfg = policy::Config {
            algorithms: policy::Algorithms::single(Algo::Lzfse),
            ..policy::Config::default()
        };
        assert_eq!(default_cfg.probe_size, 5 * 1024 * 1024, "this comparison assumes the real default");

        let unbounded_cfg =
            policy::Config { probe_size: size as u64, ..default_cfg.clone() };

        let start = Instant::now();
        for _ in 0..iters {
            let _ = engine::compress_bytes(&data, &default_cfg);
        }
        let default_time = start.elapsed() / iters;

        let start = Instant::now();
        for _ in 0..iters {
            let _ = engine::compress_bytes(&data, &unbounded_cfg);
        }
        let unbounded_time = start.elapsed() / iters;

        println!(
            "  default (5MB probe): {:.2}ms   unbounded probe: {:.2}ms   ratio: {:.3}x",
            default_time.as_secs_f64() * 1000.0,
            unbounded_time.as_secs_f64() * 1000.0,
            default_time.as_secs_f64() / unbounded_time.as_secs_f64(),
        );
    }
}
