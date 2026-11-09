//! Compressing files that share blocks with APFS clones must never cost
//! free space. Measured on a fresh APFS disk image, so nothing else writes
//! to the volume meanwhile.

use apfscompress::engine::{self, Outcome};
use apfscompress::policy::{Algorithms, Config, SkipReason};
use apfscompress::{algo::Algo, fsops};
use std::fs;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const SIZE: usize = 10 << 20;

/// 16-letter text that LZFSE compresses to about half.
fn half_compressible(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            b'a' + (x % 16) as u8
        })
        .collect()
}

/// A scratch APFS volume, detached when dropped.
struct Volume {
    point: PathBuf,
    _dir: tempfile::TempDir,
}

impl Volume {
    fn new() -> Volume {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("clones.sparseimage");
        let point = dir.path().join("mnt");
        let ok = Command::new("hdiutil")
            .args(["create", "-quiet", "-size", "256m", "-fs", "APFS", "-volname", "CloneTest", "-type", "SPARSE"])
            .arg(&image)
            .status()
            .unwrap()
            .success();
        assert!(ok, "hdiutil create failed");
        fs::create_dir(&point).unwrap();
        let ok = Command::new("hdiutil")
            .args(["attach", "-quiet", "-nobrowse", "-noautoopen", "-mountpoint"])
            .arg(&point)
            .arg(&image)
            .status()
            .unwrap()
            .success();
        assert!(ok, "hdiutil attach failed");
        Volume { point, _dir: dir }
    }

    /// Free bytes, once two readings in a row agree.
    fn free(&self) -> i64 {
        unsafe extern "C" {
            // <unistd.h>; a global sync() would wait on every other volume too.
            fn sync_volume_np(path: *const libc::c_char, flags: libc::c_int) -> libc::c_int;
        }
        const SYNC_VOLUME_WAIT: libc::c_int = 0x02;
        let path = std::ffi::CString::new(self.point.as_os_str().as_encoded_bytes()).unwrap();
        let read = || {
            assert_eq!(unsafe { sync_volume_np(path.as_ptr(), SYNC_VOLUME_WAIT) }, 0);
            let mut st: libc::statfs = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::statfs(path.as_ptr(), &mut st) }, 0);
            st.f_bavail as i64 * st.f_bsize as i64
        };
        let mut last = read();
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let now = read();
            if now == last {
                return now;
            }
            last = now;
        }
        last
    }
}

impl Drop for Volume {
    fn drop(&mut self) {
        let _ = Command::new("hdiutil").args(["detach", "-force", "-quiet"]).arg(&self.point).status();
    }
}

/// An original and `clones` exact clones of it.
fn group(dir: &Path, clones: usize) -> Vec<PathBuf> {
    fs::create_dir(dir).unwrap();
    let original = dir.join("0");
    fs::write(&original, half_compressible(SIZE, 1)).unwrap();
    let mut files = vec![original.clone()];
    for i in 1..=clones {
        let clone = dir.join(i.to_string());
        fsops::clone_file(&original, &clone).unwrap();
        files.push(clone);
    }
    files
}

/// Rewrites `path`'s first `mib` MiB, so that much of it is its own.
fn rewrite(path: &Path, mib: usize) {
    let f = fs::OpenOptions::new().write(true).open(path).unwrap();
    f.write_all_at(&half_compressible(mib << 20, 2), 0).unwrap();
    f.sync_all().unwrap();
}

fn compress_all(files: &[PathBuf], cfg: &Config) -> Vec<Outcome> {
    files.iter().map(|f| engine::compress_file(f, cfg).unwrap()).collect()
}

#[test]
fn compressing_a_clone_group_never_costs_free_space() {
    let vol = Volume::new();
    let cfg = Config { algorithms: Algorithms::single(Algo::Lzfse), ..Config::default() };

    // Four exact clones, plus one with a tenth of it rewritten: compressing
    // any of them alone would free less than it writes.
    let mut files = group(&vol.point.join("exact"), 5);
    rewrite(&files[5], 1);
    let before = vol.free();
    let outcomes = compress_all(&files, &cfg);
    let after = vol.free();
    assert!(
        outcomes.iter().all(|o| *o == Outcome::Skipped(SkipReason::SharedWithClones)),
        "{outcomes:?}"
    );
    assert!(after >= before, "free space fell by {} bytes", before - after);

    // A clone with nine tenths rewritten frees space by compressing, and
    // then so does its original, which it no longer shares much with.
    files = group(&vol.point.join("rewritten"), 1);
    rewrite(&files[1], 9);
    files.reverse();
    let before = vol.free();
    let outcomes = compress_all(&files, &cfg);
    let after = vol.free();
    assert!(outcomes.iter().all(|o| matches!(o, Outcome::Compressed { .. })), "{outcomes:?}");
    assert!(after - before > (SIZE as i64) / 2, "freed only {} bytes", after - before);

    // Without the rule, the same exact clones cost space: each becomes its
    // own compressed copy.
    let files = group(&vol.point.join("unguarded"), 3);
    let before = vol.free();
    let outcomes = compress_all(&files, &Config { skip_clones: false, ..cfg });
    let after = vol.free();
    assert!(outcomes.iter().all(|o| matches!(o, Outcome::Compressed { .. })), "{outcomes:?}");
    assert!(before - after > (SIZE as i64) / 2, "free space changed by {} bytes", after - before);
}
