//! Fuzzing of our own decmpfs decoder (`engine::decompress_parts`).
//!
//! Two properties, checked separately:
//!
//! - Parity on valid input. Everything our writer produces must decode to
//!   the original (also checked through real files, against the kernel, in
//!   `decmpfs_conformance`), and every file Apple's tools already compressed
//!   on this machine must decode to what the kernel returns
//!   (`apple_written_files_decode_like_the_kernel`, opt-in).
//! - Robustness on hostile input. Valid encodings with their headers, chunk
//!   tables and chunk bytes damaged must never panic, and any success must
//!   return exactly the size the header claims. Rejecting damaged input is
//!   fine. This runs in memory only: handing damaged decmpfs data to the
//!   kernel is left out on purpose, since a kernel decoder bug there can take
//!   the machine down rather than fail a test.
//!
//! Kernel comparison: `damaged_input_matches_the_kernel` writes each damaged
//! input as a real compressed file and compares the kernel's `read()` with
//! our decoder. It needs `DECODER_KERNEL_DIR` on a scratch volume, such as an
//! APFS RAM disk (see `decmpfs_conformance` for the commands), and only
//! reports differences unless `DECODER_STRICT=1`.
//!
//! Long campaign:
//!
//!   DECODER_ITERS=200000 DECODER_SEED=3 \
//!     cargo test --release --test decmpfs_decoder_fuzz -- --ignored --nocapture

mod common;

use apfscompress::algo::{self, Algo};
use apfscompress::decmpfs::{self, CHUNK_SIZE, Header};
use apfscompress::engine::{self, CompressedPayload};
use apfscompress::policy::{Algorithms, Config};
use apfscompress::{fsops, sys};
use common::{Rng, fill, pick_algo, pick_size};
use std::collections::BTreeMap;
use std::io::Read;
use std::os::macos::fs::MetadataExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;

/// A valid encoding of `data`: the decmpfs xattr, plus the resource fork for
/// the chunked types.
fn encode(data: &[u8], a: Algo) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    let cfg = Config { algorithms: Algorithms::single(a), max_ratio: 4.0, ..Config::default() };
    let (winner, payload) = engine::compress_bytes_against(data, &cfg, data.len() as u64)?;
    Some(match payload {
        CompressedPayload::Inline(x) => (x, None),
        CompressedPayload::Chunked { header_xattr, chunks } => {
            (header_xattr, Some(decmpfs::build_resource_fork_for(winner, &chunks)))
        }
    })
}

fn interesting_u64(r: &mut Rng, size: u64) -> u64 {
    let c = CHUNK_SIZE as u64;
    let picks = [0, 1, size.wrapping_sub(1), size + 1, size + c, size * 2, c, c - 1, c + 1, u32::MAX as u64, u64::MAX, r.next()];
    picks[r.below(picks.len() as u64) as usize]
}

fn interesting_u32(r: &mut Rng, len: usize) -> u32 {
    let picks = [0, 4, 8, len as u32, len as u32 + 1, len as u32 - 1, u32::MAX, r.below(len as u64 + 1) as u32, r.next() as u32];
    picks[r.below(picks.len() as u64) as usize]
}

/// Applies one to three damaging edits, each aimed at a field the decoder
/// trusts or at raw bytes.
fn mutate(r: &mut Rng, xattr: &mut Vec<u8>, rsrc: &mut Option<Vec<u8>>, size: u64) -> Vec<&'static str> {
    let mut did = Vec::new();
    for _ in 0..1 + r.below(3) {
        let op = r.below(11);
        did.push(match op {
            0 => "xattr bit flip",
            1 => "header size",
            2 => "header type",
            3 => "xattr truncated",
            4 => "xattr extended",
            5 => "rsrc dropped or added",
            _ => "rsrc edit",
        });
        match op {
            0 if !xattr.is_empty() => {
                let i = r.below(xattr.len() as u64) as usize;
                xattr[i] ^= 1 << r.below(8);
            }
            1 if xattr.len() >= 16 => xattr[8..16].copy_from_slice(&interesting_u64(r, size).to_le_bytes()),
            2 if xattr.len() >= 8 => {
                let mut t = if r.below(4) == 0 { r.next() as u32 } else { r.below(20) as u32 };
                // The kernel waits 15 s for a type 5 decoder that never
                // registers before failing, which only slows the comparison.
                if t == 5 {
                    t = 6;
                }
                xattr[4..8].copy_from_slice(&t.to_le_bytes());
            }
            3 => xattr.truncate(r.below(xattr.len() as u64 + 1) as usize),
            4 => xattr.extend((0..1 + r.below(64)).map(|_| r.next() as u8)),
            5 => *rsrc = if rsrc.is_some() { None } else { Some((0..r.below(4096)).map(|_| r.next() as u8).collect()) },
            _ => {
                let Some(fork) = rsrc.as_mut() else { continue };
                if fork.is_empty() {
                    continue;
                }
                match r.below(5) {
                    // Chunk-table and descriptor fields sit near the front.
                    0 | 1 => {
                        let span = fork.len().min(512);
                        let at = r.below(span.saturating_sub(3) as u64 + 1) as usize & !3;
                        if at + 4 <= fork.len() {
                            let len = fork.len();
                            let v = interesting_u32(r, len);
                            if r.below(2) == 0 {
                                fork[at..at + 4].copy_from_slice(&v.to_le_bytes());
                            } else {
                                fork[at..at + 4].copy_from_slice(&v.to_be_bytes());
                            }
                        }
                    }
                    2 => {
                        let i = r.below(fork.len() as u64) as usize;
                        fork[i] = r.next() as u8;
                    }
                    3 => fork.truncate(r.below(fork.len() as u64) as usize),
                    _ => fork.extend((0..1 + r.below(256)).map(|_| r.next() as u8)),
                }
            }
        }
    }
    did
}

/// One damaged input, with what it was damaged from.
struct Case<'a> {
    id: String,
    data: &'a [u8],
    x: Vec<u8>,
    f: Option<Vec<u8>>,
    unchanged: bool,
    mutations: Vec<&'static str>,
    orig_x: &'a [u8],
    orig_f: Option<&'a [u8]>,
}

/// Replays the damaged inputs for `seed` deterministically. Each valid base
/// encoding is checked first, then `per_base` damaged copies go to `visit`.
fn for_each_case(seed: u64, bases: u64, per_base: u64, mut visit: impl FnMut(Case)) {
    for b in 0..bases {
        base_cases(seed, b, per_base, &mut visit);
    }
}

/// The damaged inputs for one base encoding; bases are independent, so they
/// can run in parallel.
fn base_cases(seed: u64, b: u64, per_base: u64, visit: &mut impl FnMut(Case)) {
    {
        let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (b + 1).wrapping_mul(0xD1B5_4A32_D192_ED03));
        r.next();
        let size = pick_size(&mut r).clamp(1, 6 * CHUNK_SIZE);
        let data = fill(&mut r, size);
        let a = pick_algo(&mut r);
        if !algo::is_supported(a) {
            return;
        }
        let Some((xattr, rsrc)) = encode(&data, a) else { return };
        let base = format!("seed {seed} base {b} ({size} bytes, {a:?})");

        let clean = engine::decompress_parts(&xattr, rsrc.as_deref()).unwrap_or_else(|e| panic!("{base}: valid encoding rejected: {e}"));
        assert!(clean == data, "{base}: valid encoding decoded to different bytes");

        for m in 0..per_base {
            let (mut x, mut f) = (xattr.clone(), rsrc.clone());
            let mutations = mutate(&mut r, &mut x, &mut f, size as u64);
            let unchanged = x == xattr && f == rsrc;
            visit(Case { id: format!("{base} mutation {m}"), data: &data, x, f, unchanged, mutations, orig_x: &xattr, orig_f: rsrc.as_deref() });
        }
    }
}

/// The changed byte ranges between two buffers, for replaying one case.
fn describe_diff(name: &str, before: Option<&[u8]>, after: Option<&[u8]>) -> String {
    let (Some(b), Some(a)) = (before, after) else {
        return format!("{name}: {} -> {}", before.map_or("absent".into(), |b| format!("{} bytes", b.len())), after.map_or("absent".into(), |a| format!("{} bytes", a.len())));
    };
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < a.len().min(b.len()) {
        if a[i] != b[i] {
            let start = i;
            while i < a.len().min(b.len()) && a[i] != b[i] {
                i += 1;
            }
            ranges.push(format!("[{start}..{i}) {:02x?} -> {:02x?}", &b[start..i.min(start + 8)], &a[start..i.min(start + 8)]));
        }
        i += 1;
    }
    format!("{name}: {} -> {} bytes; changed {}", b.len(), a.len(), if ranges.is_empty() { "nothing in the overlap".into() } else { ranges.join(", ") })
}

fn run(seed: u64, bases: u64, per_base: u64) -> (u64, u64) {
    let (mut accepted, mut rejected) = (0, 0);
    for_each_case(seed, bases, per_base, |c| {
        let result = catch_unwind(AssertUnwindSafe(|| engine::decompress_parts(&c.x, c.f.as_deref())))
            .unwrap_or_else(|_| panic!("{}: decoder panicked", c.id));
        match result {
            Ok(out) => {
                let claim = Header::from_bytes(&c.x).expect("decoded without a header").uncompressed_size;
                assert_eq!(out.len() as u64, claim, "{}: output length disagrees with the header", c.id);
                if c.unchanged {
                    assert!(out == c.data, "{}: unchanged input decoded differently", c.id);
                }
                accepted += 1;
            }
            Err(_) => rejected += 1,
        }
    });
    (accepted, rejected)
}

fn campaign(default_iters: u64) {
    let env = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u64>().ok());
    let seed = env("DECODER_SEED").unwrap_or(1);
    let iters = env("DECODER_ITERS").unwrap_or(default_iters);
    let per_base = 25;
    let (accepted, rejected) = run(seed, iters.div_ceil(per_base), per_base);
    eprintln!("seed {seed}: {} damaged inputs, {accepted} decoded, {rejected} rejected, no panics", accepted + rejected);
    assert!(rejected > 0 && accepted > 0, "mutations should produce both outcomes");
}

#[test]
fn damaged_input_never_panics() {
    campaign(3000);
}

#[test]
#[ignore = "long campaign; set DECODER_ITERS"]
fn damaged_input_never_panics_campaign() {
    campaign(200_000);
}

/// Every file on this machine that Apple's tools compressed must decode
/// through ours to the same bytes the kernel returns. Read-only. Set
/// `DECODER_ROOTS` (comma-separated) to widen it, e.g. to `/System/Library`.
#[test]
#[ignore = "walks the filesystem"]
fn apple_written_files_decode_like_the_kernel() {
    let roots = std::env::var("DECODER_ROOTS").unwrap_or_else(|_| "/Applications,/System/Applications".into());
    let mut by_type = std::collections::BTreeMap::<u32, usize>::new();
    let mut mismatches = Vec::new();
    for root in roots.split(',') {
        for f in apfscompress::walk::collect_files(std::path::Path::new(root)).unwrap_or_default() {
            let Ok(meta) = std::fs::symlink_metadata(&f) else { continue };
            if meta.st_flags() & sys::UF_COMPRESSED == 0 {
                continue;
            }
            // Files we cannot read (permissions) say nothing either way.
            let (Ok(xattr), Ok(kernel)) = (fsops::get_xattr(&f, "com.apple.decmpfs"), std::fs::read(&f)) else { continue };
            let Some(header) = Header::from_bytes(&xattr) else { continue };
            *by_type.entry(header.compression_type).or_default() += 1;
            match engine::decompress_bytes(&f) {
                Ok(ours) if ours == kernel => {}
                Ok(_) => mismatches.push(format!("{}: different bytes", f.display())),
                Err(e) => mismatches.push(format!("{}: {e}", f.display())),
            }
        }
    }
    eprintln!("checked by decmpfs type: {by_type:?}");
    assert!(mismatches.is_empty(), "{} files decode differently from the kernel:\n{}", mismatches.len(), mismatches.join("\n"));
}

/// The most the kernel comparison reads back, so a damaged header claiming
/// gigabytes cannot make it read them. Nothing the fuzzer builds decodes to
/// more than a few hundred KiB.
const KERNEL_READ_LIMIT: u64 = 8 << 20;

/// What the kernel returns for a file carrying these xattrs, or `None` if it
/// refuses the flag or the read.
fn kernel_decode(path: &std::path::Path, x: &[u8], f: Option<&[u8]>) -> Option<Vec<u8>> {
    std::fs::write(path, b"").unwrap();
    fsops::set_xattr(path, "com.apple.decmpfs", x).ok()?;
    if let Some(f) = f {
        fsops::set_xattr(path, "com.apple.ResourceFork", f).ok()?;
    }
    fsops::set_compressed_flag(path).ok()?;
    let mut out = Vec::new();
    std::fs::File::open(path).ok()?.take(KERNEL_READ_LIMIT + 1).read_to_end(&mut out).ok()?;
    Some(out)
}

#[derive(Default)]
struct Report {
    counts: BTreeMap<&'static str, u64>,
    samples: BTreeMap<&'static str, Vec<String>>,
}

impl Report {
    fn add(&mut self, kind: &'static str, sample: Option<String>) {
        *self.counts.entry(kind).or_default() += 1;
        if let Some(s) = sample {
            let list = self.samples.entry(kind).or_default();
            if list.len() < 6 {
                list.push(s);
            }
        }
    }
}

/// Classifies one damaged input by comparing the kernel with our decoder.
fn compare_with_kernel(c: &Case, path: &std::path::Path, report: &Mutex<Report>) {
    let header = Header::from_bytes(&c.x);
    let claim = header.map(|h| h.uncompressed_size);
    // The kernel shows a file it cannot decode as empty rather than failing
    // the read, so anything but the claimed length is a rejection, and a
    // claim of 0 cannot be told apart from one.
    let kernel = kernel_decode(path, &c.x, c.f.as_deref()).filter(|k| claim == Some(k.len() as u64) && !k.is_empty());
    let _ = std::fs::remove_file(path);
    let ours = engine::decompress_parts(&c.x, c.f.as_deref()).map_err(|e| e.to_string());
    let ours_ok = ours.as_ref().ok().filter(|o| !o.is_empty());

    let orig = |v: &Vec<u8>| if v.as_slice() == c.data { "original" } else { "not the original" };
    let (kind, detail) = match (&kernel, ours_ok) {
        (Some(k), Some(o)) if k == o => ("agree: same bytes", None),
        (None, None) => ("agree: both rejected or empty", None),
        (Some(k), Some(o)) => {
            let at = k.iter().zip(o).position(|(a, b)| a != b).unwrap_or(k.len().min(o.len()));
            ("DIFFER: both decoded, different bytes", Some(format!("{} bytes, first difference at {at}; kernel {}, ours {}", k.len(), orig(k), orig(o))))
        }
        (Some(k), None) => {
            let why = ours.as_ref().err().map_or("empty", String::as_str);
            ("kernel decoded, we rejected", Some(format!("kernel {} bytes, {}; ours: {why}", k.len(), orig(k))))
        }
        (None, Some(o)) => ("we decoded, kernel rejected", Some(format!("ours {} bytes, {}", o.len(), orig(o)))),
    };
    let sample = detail.map(|d| format!("{} (type {:?}; {}): {d}", c.id, header.map(|h| h.compression_type), c.mutations.join(", ")));
    report.lock().unwrap().add(kind, sample);
}

#[test]
#[ignore = "hands damaged decmpfs files to the kernel; set DECODER_KERNEL_DIR"]
fn damaged_input_matches_the_kernel() {
    use rayon::prelude::*;
    let root = std::env::var_os("DECODER_KERNEL_DIR").expect("set DECODER_KERNEL_DIR to a scratch volume, e.g. a RAM disk");
    let dir = tempfile::tempdir_in(root).unwrap();
    let env = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u64>().ok());
    let seed = env("DECODER_SEED").unwrap_or(1);
    let iters = env("DECODER_ITERS").unwrap_or(20_000);
    let per_base = 25;

    // DECODER_ONLY=<base>:<mutation> replays one case and shows its damage.
    if let Ok(only) = std::env::var("DECODER_ONLY") {
        let (b, m) = only.split_once(':').expect("DECODER_ONLY=<base>:<mutation>");
        let (b, m): (u64, String) = (b.parse().unwrap(), format!("mutation {m}"));
        let report = Mutex::new(Report::default());
        base_cases(seed, b, per_base, &mut |c| {
            if c.id.ends_with(&m) {
                eprintln!("{}\n  {}\n  {}", c.id, describe_diff("decmpfs xattr", Some(c.orig_x), Some(&c.x)), describe_diff("resource fork", c.orig_f, c.f.as_deref()));
                compare_with_kernel(&c, &dir.path().join("only"), &report);
            }
        });
        eprintln!("  result: {:?}", report.into_inner().unwrap().counts);
        return;
    }

    let report = Mutex::new(Report::default());
    (0..iters.div_ceil(per_base)).into_par_iter().for_each(|b| {
        let path = dir.path().join(format!("case-{b}"));
        base_cases(seed, b, per_base, &mut |c| compare_with_kernel(&c, &path, &report));
    });

    let report = report.into_inner().unwrap();
    eprintln!("seed {seed}:");
    for (kind, n) in &report.counts {
        eprintln!("  {n:>7}  {kind}");
        for s in report.samples.get(kind).into_iter().flatten() {
            eprintln!("             {s}");
        }
    }
    if std::env::var_os("DECODER_STRICT").is_some() {
        assert!(!report.counts.contains_key("DIFFER: both decoded, different bytes"), "decoders produced different bytes");
    }
}
