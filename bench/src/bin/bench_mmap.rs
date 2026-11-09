//! Measures `mmap` vs `fs::read` for a one-shot sequential full-file scan,
//! and whether `MADV_SEQUENTIAL` changes anything. Informs `MappedInput`'s
//! `MMAP_THRESHOLD` in engine.rs. Deliberately warm-cache: that's the
//! realistic case for `map_file_readonly`, which only runs on a
//! just-`clonefile`d staged file, never a cold file from disk/network.
//!
//! Run with `cargo run --release -p apfscompress-bench --bin bench_mmap`.
//! Prints mean time per iteration for `fs::read`, `mmap` (no advice), and
//! `mmap` with `MADV_SEQUENTIAL`, one row per file size. Lower is better.

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

/// Forces every byte to actually be touched (page faults for `mmap`, real
/// copies for `fs::read`). Without this, an untouched mapping is nearly free
/// to create and would misrepresent real usage, which reads every byte
/// during compression.
fn checksum(data: &[u8]) -> u64 {
    let mut sum = 0u64;
    for &b in data {
        sum = sum.wrapping_add(b as u64);
    }
    sum
}

fn bench_read(path: &Path, iters: u32) -> (Duration, u64) {
    let mut total = Duration::ZERO;
    let mut sum = 0u64;
    for _ in 0..iters {
        let start = Instant::now();
        let data = fs::read(path).unwrap();
        sum = sum.wrapping_add(checksum(&data));
        total += start.elapsed();
    }
    (total / iters, sum)
}

fn bench_mmap(path: &Path, iters: u32, advise: bool) -> (Duration, u64) {
    let mut total = Duration::ZERO;
    let mut sum = 0u64;
    for _ in 0..iters {
        let start = Instant::now();
        let file = fs::File::open(path).unwrap();
        let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
        if advise {
            let _ = mmap.advise(memmap2::Advice::Sequential);
        }
        sum = sum.wrapping_add(checksum(&mmap[..]));
        total += start.elapsed();
    }
    (total / iters, sum)
}

fn human(n: usize) -> String {
    if n >= 1024 * 1024 { format!("{}MB", n / 1024 / 1024) } else { format!("{}KB", n / 1024) }
}

fn main() {
    let dir = tempfile::tempdir().unwrap();

    println!("=== mmap vs fs::read, one-shot sequential full scan, warm cache ===\n");
    println!("{:>8}  {:>7}  {:>14}  {:>18}  {:>18}", "size", "iters", "fs::read", "mmap (no advise)", "mmap (Sequential)");

    for &size in &[64usize * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024, 64 * 1024 * 1024, 256 * 1024 * 1024] {
        let path = dir.path().join(format!("f_{size}.bin"));
        // Content doesn't matter for I/O cost: not asking libcompression to
        // do anything here, just measuring raw byte-touching cost.
        fs::write(&path, vec![0xABu8; size]).unwrap();

        let iters = if size >= 64 * 1024 * 1024 { 5 } else if size >= 4 * 1024 * 1024 { 20 } else { 100 };

        let (read_time, s1) = bench_read(&path, iters);
        let (mmap_time, s2) = bench_mmap(&path, iters, false);
        let (mmap_seq_time, s3) = bench_mmap(&path, iters, true);
        // Sums are meaningless (fixed content): they only exist so the
        // compiler can't optimize the read/touch loops away as dead code.
        assert_eq!(s1, s2);
        assert_eq!(s2, s3);

        println!(
            "{:>8}  {:>7}  {:>12.3}ms  {:>16.3}ms  {:>16.3}ms",
            human(size),
            iters,
            read_time.as_secs_f64() * 1000.0,
            mmap_time.as_secs_f64() * 1000.0,
            mmap_seq_time.as_secs_f64() * 1000.0,
        );
    }
}
