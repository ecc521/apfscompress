//! Measures whether `walk::walk_files`'s single background DFS thread can
//! bottleneck a skip-heavy tree, where serial `read_dir` cost and per-file
//! consumer work are close enough that the walker paces the whole run.
//! Builds a synthetic tree of many tiny (sub-`MIN_FILE_SIZE`) files, then
//! compares: walk-alone (drain the channel, no work), skip-alone
//! (`should_skip` over a collected `Vec<PathBuf>`, fanned out via rayon -
//! the consumer's ceiling), and pipeline (`walk_files` piped into
//! `par_bridge().for_each(should_skip)`, the real shape).
//!
//! Run with `cargo run --release -p apfscompress-bench --bin walk_bottleneck_bench`.
//! Prints files/sec for each, then pipeline/walk-alone and pipeline/skip-alone
//! ratios: near 1.0x on the former means the walker paces the run; near 1.0x
//! on the latter means the consumer does. Env vars: BENCH_FILES (default
//! 200_000), BENCH_FANOUT (default 40).

use apfscompress::policy::{self, Config};
use apfscompress::walk;
use rayon::prelude::*;
use std::path::PathBuf;
use std::time::Instant;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Creates `total` 1-byte files (well under the default `MIN_FILE_SIZE`
/// floor) spread across a directory tree `fanout` subdirs wide, deep enough
/// to hold them all: a shape meant to resemble a dense `node_modules` rather
/// than one flat directory with a million entries.
fn build_tiny_tree(root: &std::path::Path, total: usize, fanout: usize) {
    let mut created = 0usize;
    let mut level: Vec<PathBuf> = vec![root.to_path_buf()];
    // Grow one directory level at a time until there are enough leaf
    // directories that `fanout` files each covers `total`.
    while created < total {
        let mut next_level = Vec::new();
        for dir in &level {
            for i in 0..fanout {
                let sub = dir.join(format!("d{i}"));
                std::fs::create_dir_all(&sub).unwrap();
                next_level.push(sub);
            }
        }
        for dir in &next_level {
            for i in 0..fanout {
                if created >= total {
                    break;
                }
                std::fs::write(dir.join(format!("f{i}.txt")), b"x").unwrap();
                created += 1;
            }
            if created >= total {
                break;
            }
        }
        level = next_level;
    }
}

fn main() {
    let total = env_usize("BENCH_FILES", 200_000);
    let fanout = env_usize("BENCH_FANOUT", 40);

    let dir = tempfile::tempdir().expect("tempdir");
    eprintln!("building {total} tiny files (fanout {fanout}) under {:?} ...", dir.path());
    let build_start = Instant::now();
    build_tiny_tree(dir.path(), total, fanout);
    eprintln!("build took {:?}", build_start.elapsed());

    // (1) walk-alone: drain the channel, no per-item work.
    let t = Instant::now();
    let mut walked = 0usize;
    for _path in walk::walk_files(dir.path().to_path_buf()).unwrap() {
        walked += 1;
    }
    let walk_alone = t.elapsed();
    eprintln!(
        "walk-alone:  {walked} files in {walk_alone:?}  ({:.0} files/sec)",
        walked as f64 / walk_alone.as_secs_f64()
    );

    // (2) skip-alone: collect paths first (untimed), then race should_skip
    // over every core via rayon, decoupled from the walker entirely.
    let paths: Vec<PathBuf> = walk::walk_files(dir.path().to_path_buf()).unwrap().collect();
    let cfg = Config::default();
    let t = Instant::now();
    paths.par_iter().for_each(|p| {
        let _ = policy::should_skip(p, &cfg);
    });
    let skip_alone = t.elapsed();
    eprintln!(
        "skip-alone:  {} files in {skip_alone:?}  ({:.0} files/sec, {} rayon threads)",
        paths.len(),
        paths.len() as f64 / skip_alone.as_secs_f64(),
        rayon::current_num_threads()
    );

    // (3) pipeline: the real shape run_compress/run_decompress use - walker
    // feeding a channel, rayon workers draining it via par_bridge. should_skip
    // only inspects, so the count matches `walked` from (1).
    let t = Instant::now();
    walk::walk_files(dir.path().to_path_buf())
        .unwrap()
        .par_bridge()
        .for_each(|p| {
            let _ = policy::should_skip(&p, &cfg);
        });
    let pipeline = t.elapsed();
    eprintln!(
        "pipeline:    {walked} files in {pipeline:?}  ({:.0} files/sec)",
        walked as f64 / pipeline.as_secs_f64()
    );

    eprintln!();
    eprintln!(
        "pipeline / walk-alone   = {:.2}x  (near 1.0x => walker is the pacing factor)",
        pipeline.as_secs_f64() / walk_alone.as_secs_f64()
    );
    eprintln!(
        "pipeline / skip-alone   = {:.2}x  (near 1.0x => consumer is the pacing factor)",
        pipeline.as_secs_f64() / skip_alone.as_secs_f64()
    );
}
