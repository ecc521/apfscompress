//! Measures three things: libcompression scratch-buffer sizes per algorithm,
//! flate2 vs raw libcompression ZLIB (size and speed), and per-64KB-chunk
//! LZFSE compression time variance (informs whether continuous work-stealing
//! would beat wave batching).
//!
//! Run with `cargo run --release -p apfscompress-bench --bin bench_algos`.
//! Prints three sections: scratch buffer sizes, a size/throughput table for
//! flate2 vs raw libcompression ZLIB vs LZFSE, and a latency distribution
//! (min/p50/p95/max/mean/stddev) for LZFSE chunk compression.

use apfscompress::algo::{self, Algo};
use apfscompress::sys;
use std::io::Write;
use std::time::Instant;

fn compressible_chunk(seed: u8, size: usize) -> Vec<u8> {
    // Realistic-ish text-like repetitive content, not degenerate all-zeros.
    let words = ["the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "lorem", "ipsum"];
    let mut v = Vec::with_capacity(size);
    let mut i = seed as usize;
    while v.len() < size {
        v.extend_from_slice(words[i % words.len()].as_bytes());
        v.push(b' ');
        i += 1;
    }
    v.truncate(size);
    v
}

/// Higher-entropy, less-repetitive "prose-like" content: a word list cycled
/// with a deterministic xorshift, plus varied punctuation/casing. Less
/// degenerately easy than `compressible_chunk`'s fixed round-robin, to avoid
/// over-flattering every compressor equally.
fn prose_like_chunk(seed: u32, size: usize) -> Vec<u8> {
    let words = [
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "system", "compression",
        "kernel", "volume", "extent", "block", "chunk", "algorithm", "resource", "fork", "header",
        "table", "APFS", "decmpfs", "xattr", "clone", "stage", "atomic", "rename", "thread", "pool",
        "wave", "probe", "window", "ratio", "target", "guarantee", "sentinel", "scratch", "buffer",
    ];
    let mut v = Vec::with_capacity(size);
    let mut x = seed.wrapping_mul(2654435761).wrapping_add(1);
    while v.len() < size {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        let w = words[(x as usize) % words.len()];
        if (x >> 3).is_multiple_of(11) {
            v.push(w.as_bytes()[0].to_ascii_uppercase());
            v.extend_from_slice(&w.as_bytes()[1..]);
        } else {
            v.extend_from_slice(w.as_bytes());
        }
        v.push(if (x >> 7).is_multiple_of(23) { b'.' } else { b' ' });
    }
    v.truncate(size);
    v
}

fn main() {
    println!("=== scratch buffer sizes (compression_*_scratch_buffer_size) ===");
    for (name, alg) in [
        ("LZFSE", sys::COMPRESSION_LZFSE),
        ("LZVN", sys::COMPRESSION_LZVN),
        ("LZBITMAP", sys::COMPRESSION_LZBITMAP),
        ("ZLIB (unused in our pipeline, for reference)", sys::COMPRESSION_ZLIB),
    ] {
        unsafe {
            let enc = sys::compression_encode_scratch_buffer_size(alg);
            let dec = sys::compression_decode_scratch_buffer_size(alg);
            println!("  {name:45} encode_scratch={enc:>8} bytes  decode_scratch={dec:>8} bytes");
        }
    }

    println!("\n=== flate2 (our ZLIB backend, level 9) vs raw libcompression COMPRESSION_ZLIB, output SIZE and speed ===");
    println!("(libcompression's ZLIB is NOT what we ship - raw DEFLATE, kernel rejects it for type 3 -");
    println!(" comparing anyway since it's the same DEFLATE family, just to see how the implementations compare)\n");
    #[allow(clippy::type_complexity)] // benchmark scaffolding, not library code
    let generators: [(&str, fn(u32, usize) -> Vec<u8>); 2] = [
        ("repetitive 10-word cycle", |s, n| compressible_chunk(s as u8, n)),
        ("varied prose-like", prose_like_chunk),
    ];
    for (label, generate) in generators {
        println!("  -- {label} --");
        for size in [4096usize, 65536, 1_000_000] {
            let data = generate(0, size);
            const ITERS: u32 = 50;

            let start = Instant::now();
            let mut flate2_len = 0;
            for _ in 0..ITERS {
                flate2_len = algo::compress_chunk(&data, Algo::Zlib(9)).map(|v| v.len()).unwrap_or(data.len());
            }
            let flate2_time = start.elapsed() / ITERS;
            let flate2_mb_s = (data.len() as f64 / 1_000_000.0) / flate2_time.as_secs_f64();

            let cap = data.len() - 1;
            let mut dst = vec![0u8; cap];
            let start = Instant::now();
            let mut raw_len = 0usize;
            for _ in 0..ITERS {
                raw_len = unsafe {
                    sys::compression_encode_buffer(
                        dst.as_mut_ptr(),
                        dst.len(),
                        data.as_ptr(),
                        data.len(),
                        std::ptr::null_mut(),
                        sys::COMPRESSION_ZLIB,
                    )
                };
            }
            let raw_time = start.elapsed() / ITERS;
            let raw_mb_s = (data.len() as f64 / 1_000_000.0) / raw_time.as_secs_f64();

            // Also compare against LZFSE (our default) at the same size: is
            // ZLIB's output ballpark-competitive, not just vs. raw deflate.
            let lzfse_len = algo::compress_chunk(&data, Algo::Lzfse).map(|v| v.len()).unwrap_or(data.len());

            println!(
                "    {size:>8} bytes in -> flate2: {flate2_len:>7} out, {flate2_mb_s:>6.1} MB/s   libcompression-raw-deflate: {raw_len:>7} out, {raw_mb_s:>6.1} MB/s   LZFSE (for reference): {lzfse_len:>7} out"
            );
        }
    }

    println!("\n=== per-64KB-chunk compression time variance (LZFSE, informs wave vs. continuous-flow) ===");
    let n = 200;
    let chunks: Vec<Vec<u8>> = (0..n).map(|i| compressible_chunk(i as u8, 65536)).collect();
    let mut times = Vec::with_capacity(n);
    for c in &chunks {
        let start = Instant::now();
        let _ = algo::compress_chunk(c, Algo::Lzfse);
        times.push(start.elapsed().as_nanos() as f64);
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean: f64 = times.iter().sum::<f64>() / n as f64;
    let variance: f64 = times.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / n as f64;
    let stddev = variance.sqrt();
    println!(
        "  n={n}  min={:.1}us  p50={:.1}us  p95={:.1}us  max={:.1}us  mean={:.1}us  stddev={:.1}us  (stddev/mean={:.1}%)",
        times[0] / 1000.0,
        times[n / 2] / 1000.0,
        times[(n as f64 * 0.95) as usize] / 1000.0,
        times[n - 1] / 1000.0,
        mean / 1000.0,
        stddev / 1000.0,
        100.0 * stddev / mean
    );

    std::io::stdout().flush().ok();
}
