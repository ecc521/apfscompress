//! Integration tests for the CLI orchestration layer (`run_compress` /
//! `run_decompress` / `run_info` / `run_sweep` in `src/main.rs`), which has
//! no other test coverage: these invoke the real built binary as a
//! subprocess and check its exit code and stdout/stderr, not any internal
//! function.

use std::path::Path;
use std::process::{Command, Output};

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_apfscompress")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin_path()).args(args).output().expect("failed to spawn apfscompress binary")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn compressible(n: usize) -> Vec<u8> {
    b"The quick brown fox jumps over the lazy dog. ".repeat(n)
}

/// A small, fast xorshift PRNG, so no external "rand" dependency is needed.
fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    let mut x: u32 = 0xACE1u32;
    for _ in 0..n {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        v.push((x & 0xff) as u8);
    }
    v
}

/// Base64-encodes `data`, giving ASCII text with a 64-symbol alphabet: unlike
/// raw random bytes it's modestly compressible, but nowhere near as
/// compressible as `compressible()`'s repeated text.
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len() * 4 / 3 + 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { TABLE[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[(n & 63) as usize] as char } else { '=' });
    }
    out
}

#[test]
fn compress_info_decompress_round_trip_on_a_single_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.txt");
    let original = compressible(5000);
    std::fs::write(&path, &original).unwrap();

    let out = run(&["compress", path.to_str().unwrap()]);
    assert!(out.status.success(), "compress failed: {}", stderr(&out));
    let s = stdout(&out);
    assert!(s.contains("compressed"), "expected a compressed line, got: {s}");
    assert!(s.contains("smaller)"), "expected a size-reduction summary line, got: {s}");

    let out = run(&["info", path.to_str().unwrap()]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("type"), "expected info to report a decmpfs type, got: {s}");
    assert!(s.contains("smaller"), "expected info to report a size reduction, got: {s}");

    let out = run(&["decompress", path.to_str().unwrap()]);
    assert!(out.status.success(), "decompress failed: {}", stderr(&out));

    let restored = std::fs::read(&path).unwrap();
    assert_eq!(restored, original, "decompressed bytes must match the original exactly");
}

#[test]
fn compress_accepts_a_bare_relative_path() {
    let dir = tempfile::tempdir().unwrap();
    let data = compressible(2000);
    std::fs::write(dir.path().join("bare.txt"), &data).unwrap();

    let out = Command::new(bin_path()).args(["compress", "bare.txt"]).current_dir(dir.path()).output().unwrap();
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("1 compressed"), "stdout: {}", stdout(&out));
    assert_eq!(std::fs::read(dir.path().join("bare.txt")).unwrap(), data);
}

#[test]
fn compress_a_directory_counts_files_and_does_not_follow_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("sub");
    let subsub = sub.join("subsub");
    std::fs::create_dir_all(&subsub).unwrap();

    let a = dir.path().join("a.txt");
    let b = sub.join("b.txt");
    let c = subsub.join("c.txt");
    for f in [&a, &b, &c] {
        std::fs::write(f, compressible(5000)).unwrap();
    }

    // A symlink to a separate tree outside the directory being compressed;
    // if it were followed, its target would get compressed too.
    let outside_dir = tempfile::tempdir().unwrap();
    let outside_target = outside_dir.path().join("outside.txt");
    let outside_original = compressible(5000);
    std::fs::write(&outside_target, &outside_original).unwrap();
    std::os::unix::fs::symlink(&outside_target, dir.path().join("link.txt")).unwrap();

    let out = run(&["compress", dir.path().to_str().unwrap()]);
    assert!(out.status.success(), "compress failed: {}", stderr(&out));
    let s = stdout(&out);
    assert!(s.contains("3 compressed,"), "expected exactly 3 files compressed, got: {s}");

    // The symlink's target must be untouched: not followed, not compressed.
    assert_eq!(std::fs::read(&outside_target).unwrap(), outside_original);
}

#[test]
fn recompressing_an_already_compressed_file_is_skipped_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.bin");
    std::fs::write(&path, compressible(5000)).unwrap();

    let out = run(&["compress", path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("compressed"));

    // Default recompress policy is Never: a second pass must skip it.
    let out = run(&["compress", path.to_str().unwrap()]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("skipped"), "expected a skipped line, got: {s}");
    assert!(s.contains("AlreadyCompressed"), "expected AlreadyCompressed as the skip reason, got: {s}");
}

#[test]
fn dry_run_reports_without_writing_anything() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.bin");
    let original = compressible(5000);
    std::fs::write(&path, &original).unwrap();

    let out = run(&["compress", "--dry-run", path.to_str().unwrap()]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("would-compress"), "expected a would-compress line, got: {s}");
    assert!(s.contains("[dry run, nothing written]"), "expected the dry-run suffix, got: {s}");

    // Nothing actually written: the file's bytes and compression state are
    // both untouched.
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let out = run(&["info", path.to_str().unwrap()]);
    assert!(stdout(&out).contains("not compressed"), "dry run must not have actually compressed the file");
}

#[test]
fn max_ratio_zero_is_rejected_with_exit_code_2() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.bin");
    std::fs::write(&path, compressible(5000)).unwrap();

    let out = run(&["compress", "--max-ratio", "0", path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--max-ratio"), "expected the error to mention --max-ratio, got: {}", stderr(&out));
}

#[test]
fn max_ratio_negative_is_rejected_with_exit_code_2() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.bin");
    std::fs::write(&path, compressible(5000)).unwrap();

    let out = run(&["compress", "--max-ratio=-1", path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--max-ratio"), "expected the error to mention --max-ratio, got: {}", stderr(&out));
}

#[test]
fn strict_max_ratio_reports_no_benefit_while_default_compresses() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.bin");
    // Base64 of random bytes is modestly compressible (a 64-symbol alphabet
    // isn't full entropy), but nowhere near --max-ratio 0.001's 99.9% shrink.
    let text = base64_encode(&random_bytes(20_000));
    std::fs::write(&path, text.as_bytes()).unwrap();

    let out = run(&["compress", "--max-ratio", "0.001", path.to_str().unwrap()]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("0 compressed,"), "expected nothing to clear a 99.9% shrink target, got: {s}");
    assert!(s.contains("no-benefit"), "expected a no-benefit line, got: {s}");

    // Default --max-ratio (1.0) must compress the same content just fine.
    let out = run(&["compress", path.to_str().unwrap()]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("1 compressed,"), "expected the default ratio to compress the file, got: {s}");
}

#[test]
fn algo_race_across_multiple_files_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..3 {
        std::fs::write(dir.path().join(format!("f{i}.bin")), compressible(5000)).unwrap();
    }

    let out = run(&["compress", "--algo", "lzfse,zlib", dir.path().to_str().unwrap()]);
    assert!(out.status.success(), "algo race compress failed: {}", stderr(&out));
    let s = stdout(&out);
    assert!(s.contains("3 compressed,"), "expected all 3 files compressed, got: {s}");
    // The per-algorithm breakdown line only prints when more than one
    // algorithm won a file, which is timing/content dependent, so it's
    // not asserted on directly.
}

#[test]
fn compressing_a_nonexistent_path_errors_with_nonzero_exit() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does_not_exist");

    let out = run(&["compress", missing.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("cannot read"), "expected a 'cannot read' error, got: {}", stderr(&out));
}

#[test]
fn sweep_removes_an_orphaned_staging_file() {
    let dir = tempfile::tempdir().unwrap();
    let orphan = dir.path().join(".apfscompress.tmp.orphan123");
    std::fs::write(&orphan, b"stale staging leftover").unwrap();
    let real = dir.path().join("real.txt");
    std::fs::write(&real, b"keep me").unwrap();

    let out = run(&["sweep", dir.path().to_str().unwrap()]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("removed 1 orphaned staging file(s)"), "expected a removal count, got: {s}");
    assert!(!Path::new(&orphan).exists(), "orphaned staging file should be gone");
    assert!(real.exists(), "unrelated real file must be left alone");
}
