//! Conformance fuzzing of the files we write, judged by the kernel.
//!
//! The encoders' own bitstreams are crush-lz's to test. What this checks is
//! our layer around them: the decmpfs header, inline versus resource-fork
//! placement, the chunk table, per-chunk stored sentinels and format
//! markers. Each case writes a seeded random file, compresses it through the
//! real `compress_file` with a random algorithm, level or race, and requires
//! a plain `read()` (the kernel's decmpfs decoder) to return the original.
//!
//! `cargo test` runs a short deterministic smoke pass. For a long campaign:
//!
//!   CONFORMANCE_ITERS=20000 CONFORMANCE_SEED=7 \
//!     cargo test --release --test decmpfs_conformance -- --ignored --nocapture
//!
//! `CONFORMANCE_DIR` puts the scratch files on another volume, such as an
//! APFS RAM disk, which keeps a long run off the SSD:
//!
//!   dev=$(diskutil image attach --noMount ram://4194304)   # 2 GiB
//!   diskutil erasevolume APFS RAMDisk $dev
//!   CONFORMANCE_DIR=/Volumes/RAMDisk ...
//!   diskutil eject $dev
//!
//! 20,000 cases take about a minute in release.
//!
//! A failure prints the seed and case number; `CONFORMANCE_ONLY=<case>`
//! with the same seed replays just that case.

mod common;

use apfscompress::algo::{self, Algo};
use common::{Rng, fill, pick_algo, pick_size};
use apfscompress::decmpfs::{self, CHUNK_SIZE, MAX_INLINE_PAYLOAD};
use apfscompress::engine::{self, Outcome};
use apfscompress::{fsops, sys};
use apfscompress::policy::{Algorithms, Config};
use std::collections::BTreeMap;
use std::fs;
use std::os::macos::fs::MetadataExt;
use std::path::Path;

/// One case. Returns the decmpfs type written, or `None` if the file was
/// left uncompressed.
fn run_case(seed: u64, case: u64, dir: &Path) -> Option<u32> {
    let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ case.wrapping_add(1).wrapping_mul(0xD1B5_4A32_D192_ED03));
    r.next();
    let size = pick_size(&mut r);
    let data = fill(&mut r, size);

    let n = if r.below(4) == 0 { 2 + r.below(2) } else { 1 };
    let algos: Vec<Algo> = (0..n).map(|_| pick_algo(&mut r)).filter(|&a| algo::is_supported(a)).collect();
    if algos.is_empty() {
        return None;
    }
    let cfg = Config {
        algorithms: Algorithms::custom(algos.clone()).unwrap(),
        // Write whatever comes out, so every framing path is reached even
        // when the result does not shrink.
        max_ratio: 4.0,
        min_file_size: Some(1),
        // The check below is the kernel read-back; don't do it twice.
        paranoid: false,
        ..Config::default()
    };

    let path = dir.join(format!("case-{case}.bin"));
    fs::write(&path, &data).unwrap();
    let ctx = || format!("seed {seed} case {case}: {size} bytes, {algos:?}");
    let outcome = engine::compress_file(&path, &cfg).unwrap_or_else(|e| panic!("{}: compress_file failed: {e}", ctx()));
    // Read the type before the read-back, and confirm the read really goes
    // through the kernel's decmpfs decoder rather than a plain data fork.
    let written = matches!(outcome, Outcome::Compressed { .. }).then(|| {
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(meta.st_flags() & sys::UF_COMPRESSED != 0, "{}: reported compressed but UF_COMPRESSED is clear", ctx());
        let xattr = fsops::get_xattr(&path, "com.apple.decmpfs").unwrap();
        decmpfs::Header::from_bytes(&xattr).unwrap().compression_type
    });
    let back = fs::read(&path).unwrap_or_else(|e| panic!("{}: kernel read failed: {e}", ctx()));
    if back != data {
        let at = back.iter().zip(&data).position(|(a, b)| a != b).unwrap_or(back.len().min(data.len()));
        panic!("{}: kernel read-back differs (read {} bytes, first difference at {at}), outcome {outcome:?}", ctx(), back.len());
    }
    if written.is_some() {
        let ours = engine::decompress_bytes(&path).unwrap_or_else(|e| panic!("{}: our decoder failed: {e}", ctx()));
        assert!(ours == data, "{}: our decoder disagrees with the kernel", ctx());
    }
    fs::remove_file(&path).unwrap();
    written
}

fn campaign(default_iters: u64) {
    let env = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u64>().ok());
    let seed = env("CONFORMANCE_SEED").unwrap_or(1);
    let iters = env("CONFORMANCE_ITERS").unwrap_or(default_iters);
    let root = std::env::var_os("CONFORMANCE_DIR").map(std::path::PathBuf::from);
    let dir = match &root {
        Some(r) => tempfile::tempdir_in(r).unwrap(),
        None => tempfile::tempdir().unwrap(),
    };
    let cases: Vec<u64> = match env("CONFORMANCE_ONLY") {
        Some(c) => vec![c],
        None => (0..iters).collect(),
    };
    let mut by_type: BTreeMap<u32, usize> = BTreeMap::new();
    for &c in &cases {
        if let Some(t) = run_case(seed, c, dir.path()) {
            *by_type.entry(t).or_default() += 1;
        }
    }
    let compressed: usize = by_type.values().sum();
    // Odd decmpfs types hold the payload inline in the xattr, even ones in
    // the resource fork.
    eprintln!("seed {seed}: {} cases, all read back intact; written by decmpfs type: {by_type:?}", cases.len());
    // Guards against a change that quietly stops writing compressed files.
    assert!(compressed * 2 > cases.len(), "only {compressed} of {} cases were written compressed", cases.len());
}

/// Bytes no encoder can shrink.
fn noise(seed: u64, n: usize) -> Vec<u8> {
    let mut r = Rng(seed | 1);
    (0..n).map(|_| r.next() as u8).collect()
}

fn text(n: usize) -> Vec<u8> {
    b"the quick brown fox jumps over the lazy dog; ".iter().copied().cycle().take(n).collect()
}

/// The inputs most likely to trip the growth paths: whole files and single
/// chunks that come out larger than they went in, at the sizes where our
/// framing changes shape.
fn incompressible_shapes() -> Vec<(&'static str, Vec<u8>)> {
    let c = CHUNK_SIZE;
    let inline = MAX_INLINE_PAYLOAD;
    let mut mixed = Vec::new();
    for i in 0..5 {
        mixed.extend(if i % 2 == 0 { noise(i, c) } else { text(c) });
    }
    vec![
        ("noise 1 byte", noise(1, 1)),
        ("noise 17 bytes", noise(2, 17)),
        ("noise at the inline cap", noise(3, inline)),
        ("noise just over the inline cap", noise(4, inline + 1)),
        ("noise one chunk minus 1", noise(5, c - 1)),
        ("noise exactly one chunk", noise(6, c)),
        ("noise one chunk plus 1", noise(7, c + 1)),
        ("noise four chunks", noise(8, 4 * c)),
        ("text then a noise chunk", [text(3 * c), noise(9, c)].concat()),
        ("text then a 1-byte noise tail", [text(2 * c), noise(10, 1)].concat()),
        ("noise then a text tail", [noise(11, 2 * c), text(100)].concat()),
        ("alternating noise and text chunks", mixed),
        ("text that shrinks inline, noise that would not", [text(inline), noise(12, inline)].concat()),
    ]
}

#[test]
fn incompressible_input_reads_back() {
    let mut algos: Vec<Algo> = algo::all_algos().to_vec();
    algos.extend([Algo::Zlib(1), Algo::CrushLzfse(-2), Algo::CrushLzvn(-2), Algo::CrushLzbitmap(-2), Algo::CrushLz4(-2)]);
    algos.extend([Algo::CrushLzvn(10), Algo::CrushLzbitmap(10), Algo::CrushLz4(10)]);
    algos.retain(|&a| algo::is_supported(a));

    let dir = tempfile::tempdir().unwrap();
    let (mut written, mut grown) = (0, 0);
    for (name, data) in incompressible_shapes() {
        for &a in &algos {
            // 1.0 is the shipped default, where growth must be refused and the
            // file left alone; 4.0 forces the grown result onto disk.
            for max_ratio in [1.0, 4.0] {
                let path = dir.path().join("f.bin");
                fs::write(&path, &data).unwrap();
                let cfg = Config {
                    algorithms: Algorithms::single(a),
                    max_ratio,
                    min_file_size: Some(1),
                    paranoid: false,
                    ..Config::default()
                };
                let ctx = format!("{name} ({} bytes), {a:?}, max_ratio {max_ratio}", data.len());
                let outcome = engine::compress_file(&path, &cfg).unwrap_or_else(|e| panic!("{ctx}: compress_file failed: {e}"));
                assert!(fs::read(&path).unwrap() == data, "{ctx}: kernel read-back differs, outcome {outcome:?}");
                // Mostly-text files with noise chunks must still compress:
                // the noise chunks fall back to stored, the rest shrink.
                let mostly_text = name.starts_with("text then") || name.starts_with("alternating");
                if mostly_text && max_ratio == 1.0 && a != Algo::Stored {
                    assert!(
                        matches!(outcome, Outcome::Compressed { .. }),
                        "{ctx}: a compressible file with some incompressible chunks was not compressed: {outcome:?}"
                    );
                }
                if let Outcome::Compressed { original_size, compressed_size, .. } = outcome {
                    assert!(
                        max_ratio > 1.0 || compressed_size <= original_size,
                        "{ctx}: wrote a result larger than the input under max_ratio 1.0"
                    );
                    written += 1;
                    grown += usize::from(compressed_size > original_size);
                }
            }
        }
    }
    // Stored always fits under 4.0, so at least that much must reach disk,
    // and some of it must be larger than the input or growth went untested.
    eprintln!("{written} written compressed, {grown} of them larger than the input");
    assert!(written >= incompressible_shapes().len(), "only {written} cases were written compressed");
    assert!(grown > 0, "no case wrote a result larger than its input");
}

#[test]
fn kernel_reads_back_what_we_write() {
    campaign(300);
}

#[test]
#[ignore = "long campaign; set CONFORMANCE_ITERS"]
fn kernel_reads_back_what_we_write_campaign() {
    campaign(20_000);
}
