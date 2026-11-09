//! Directory-tree file walking, shared by every subcommand that operates on
//! "a file, or every eligible file under a directory" (`main.rs`'s
//! `Compress`/`Decompress`/`Info`) and by `estimate::estimate_tree`. Kept
//! here rather than in `main.rs` so a caller linking this crate directly can
//! walk a tree without going through the CLI binary.

use crate::swap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

/// Backpressure bound on in-flight (discovered but not yet consumed) paths -
/// see `walk_files`. Large enough to absorb ordinary bursts without
/// stalling on every send, small enough to cap a full-disk scan to a
/// fixed, low memory ceiling if the consumer falls behind.
const CHANNEL_BOUND: usize = 10_000;

/// Streams every regular file (not directory, symlink, or orphaned staging
/// file) under `root` through a channel, walking from a background thread
/// so work starts as soon as the first files are found instead of
/// materializing the whole list first. Bounded by `CHANNEL_BOUND`: once
/// that many paths are buffered, the walker blocks on `send`, so a slow
/// consumer caps memory instead of the walker racing ahead.
pub fn walk_files(root: PathBuf) -> io::Result<mpsc::IntoIter<PathBuf>> {
    let meta = fs::symlink_metadata(&root)?;
    let (tx, rx) = mpsc::sync_channel(CHANNEL_BOUND);

    if meta.file_type().is_symlink() {
        // Don't follow a symlink passed directly either, matching
        // should_skip's own refusal. Nothing sent; channel closes empty.
    } else if meta.is_file() {
        let _ = tx.send(root);
    } else {
        std::thread::spawn(move || {
            let mut stack = vec![root];
            while let Some(dir) = stack.pop() {
                let Ok(entries) = fs::read_dir(&dir) else { continue };
                for entry in entries.flatten() {
                    let Ok(ft) = entry.file_type() else { continue };
                    // Skipped, never removed: when staging falls back to the
                    // target's own directory, files here may be live clones
                    // mid-compression. `sweep` cleans up crash leftovers.
                    let is_staging = entry.file_name().to_str().is_some_and(swap::is_staging_file_name);
                    if is_staging {
                        continue;
                    } else if ft.is_symlink() {
                        continue; // never follow symlinks, matches should_skip's own refusal
                    } else if ft.is_dir() {
                        stack.push(entry.path());
                    } else if ft.is_file() && tx.send(entry.path()).is_err() {
                        return; // receiver dropped, stop walking
                    }
                }
            }
        });
    }
    Ok(rx.into_iter())
}

/// Materialized-Vec convenience wrapper over `walk_files`, for callers that
/// want the whole list (tests, `Info` where deterministic ordering reads
/// more naturally than completion order). Hot paths use `walk_files`
/// directly instead, so they never pay this cost on a huge tree.
pub fn collect_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    Ok(walk_files(root.to_path_buf())?.collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // Adversarial: walk_files/collect_files symlink handling, recursion,
    // and root-path error propagation.

    #[test]
    fn collect_files_single_file_root() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.txt");
        std::fs::write(&path, b"x").unwrap();
        assert_eq!(collect_files(&path).unwrap(), vec![path]);
    }

    #[test]
    fn collect_files_nonexistent_root_errors() {
        // The root itself surfaces a real Err (checked synchronously);
        // errors on subdirectories mid-walk are best-effort skipped instead.
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does_not_exist");
        assert!(collect_files(&missing).is_err());
    }

    #[test]
    fn collect_files_symlink_root_is_not_followed() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.txt");
        let link = dir.path().join("link.txt");
        std::fs::write(&real, b"x").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // A symlink passed directly as the root must not be treated as the
        // file it points to - matches should_skip's own symlink refusal.
        assert_eq!(collect_files(&link).unwrap(), Vec::<PathBuf>::new());
    }

    #[test]
    fn collect_files_skips_nested_symlinks_but_finds_real_files() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let real = sub.join("real.txt");
        let link = sub.join("link.txt");
        std::fs::write(&real, b"x").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let files = collect_files(dir.path()).unwrap();
        assert_eq!(files, vec![real]);
    }

    #[test]
    fn collect_files_recurses_nested_directories() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a");
        let b = a.join("b");
        std::fs::create_dir_all(&b).unwrap();
        let f1 = dir.path().join("top.txt");
        let f2 = a.join("mid.txt");
        let f3 = b.join("deep.txt");
        for f in [&f1, &f2, &f3] {
            std::fs::write(f, b"x").unwrap();
        }

        let mut files = collect_files(dir.path()).unwrap();
        files.sort();
        let mut expected = vec![f1, f2, f3];
        expected.sort();
        assert_eq!(files, expected);
    }

    #[test]
    fn collect_files_excludes_staging_files_without_removing_them() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.txt");
        std::fs::write(&real, b"x").unwrap();
        let staging = dir.path().join(".apfscompress.tmp.maybe-in-flight");
        std::fs::write(&staging, b"clone").unwrap();

        let files = collect_files(dir.path()).unwrap();
        assert_eq!(files, vec![real]);
        assert!(staging.exists(), "the walk must not delete a staging file another worker may be using");
    }

    #[test]
    fn walk_files_streams_before_the_whole_tree_is_known() {
        // Exercises the streaming property directly: iterates the raw
        // Receiver (not collect_files's Vec) so the first item is
        // receivable before the whole tree is known.
        let dir = tempdir().unwrap();
        for i in 0..20 {
            std::fs::write(dir.path().join(format!("f{i}.txt")), b"x").unwrap();
        }
        let mut count = 0;
        for _path in walk_files(dir.path().to_path_buf()).unwrap() {
            count += 1;
        }
        assert_eq!(count, 20);
    }
}
