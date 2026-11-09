//! Atomic staging + promote: clone the target into a private, same-`st_dev`
//! directory (see `preferred_staging_dir`), write the compressed form into
//! the clone, then swap it into the original's place (see `promote`). `sweep_orphans` cleans up
//! staging files left by a hard crash.
//!
//! As root the target path may run through directories an untrusted process
//! can write, so `stage()` walks it with `O_NOFOLLOW` (rejecting any symlink
//! component) and records the target's and parent's inode identity, which
//! `promote()` rechecks right before the swap. clonefile and renamex_np still
//! act by path, so a redirect in the sub-syscall gap between a recheck and the
//! very next call isn't prevented, only detected on the next recheck; fully
//! closing it needs `clonefileat`/`renameatx_np` relative to a held dir fd.
//!
//! `clonefile()` doesn't reliably preserve ownership, so `stage()` verifies
//! and restores it. It also bumps atime/mtime on later writes; `stage()`
//! captures the originals so the caller can restore them via an fd opened
//! after `UF_COMPRESSED` is set (opening before would decompress it back
//! off) - and after the flag itself is set, since setting it re-bumps mtime.
//! `ctime` can't be restored at all; no syscall sets it directly.

use std::fs::{self, FileTimes};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Prefix for staging files - stable and grep-able so `sweep_orphans` can
/// find crash leftovers without needing the original filename.
const STAGE_PREFIX: &str = ".apfscompress.tmp.";

/// Whether `file_name` looks like one of our own staging files, so callers
/// walking a directory tree can skip (or clean up) our scratch files.
pub fn is_staging_file_name(file_name: &str) -> bool {
    file_name.starts_with(STAGE_PREFIX)
}

/// A clone of a target file, mid-compression. Drop without calling
/// `promote` to leave it for later cleanup (or call `discard`).
pub struct StagedFile {
    pub path: PathBuf,
    /// The original target's atime/mtime, captured before any write
    /// touches the clone. `pub(crate)`: the caller (`engine::commit_compressed`)
    /// applies this to an fd it already holds open, per the ordering
    /// constraints in this module's doc comment.
    pub(crate) original_times: FileTimes,
    /// The target as it was just before cloning.
    pub snapshot: TargetSnapshot,
    /// `(target ids, parent ids)` from a symlink-free walk at stage time,
    /// rechecked before the swap. `Some` only for a root operation, where an
    /// untrusted process could redirect the path (see `stage`).
    root_ids: Option<((u64, u64), (u64, u64))>,
}

/// Identity, change time and attributes of a target, taken before it's
/// read or cloned. A rename over a target that changed since would silently
/// discard the change, so [`StagedFile::promote`] checks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetSnapshot {
    stat: StatFields,
    ctime: (i64, i64),
    /// See [`fsops::attrs_fingerprint`](crate::fsops::attrs_fingerprint).
    attrs: u64,
}

/// What `lstat` reports about a target other than its change time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatFields {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    mode: u32,
    flags: u32,
    uid: u32,
    gid: u32,
}

impl StatFields {
    fn of(meta: &fs::Metadata) -> Self {
        use std::os::macos::fs::MetadataExt as MacMetadataExt;
        StatFields {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.len(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            mode: meta.mode(),
            flags: meta.st_flags(),
            uid: meta.uid(),
            gid: meta.gid(),
        }
    }
}

fn ctime_of(meta: &fs::Metadata) -> (i64, i64) {
    (meta.ctime(), meta.ctime_nsec())
}

/// Times `unchanged` re-reads a target whose attributes moved while being
/// read, before calling it changed.
const STABLE_READ_TRIES: usize = 3;

impl TargetSnapshot {
    /// `meta` is `target`'s metadata; the attribute fingerprint is read
    /// after it, so a change landing between the two is caught by the
    /// later comparisons or already in the clone.
    pub fn of(meta: &fs::Metadata, target: &Path) -> io::Result<Self> {
        Ok(TargetSnapshot {
            stat: StatFields::of(meta),
            ctime: ctime_of(meta),
            attrs: crate::fsops::attrs_fingerprint(target)?,
        })
    }

    /// Whether `target` is still the same, unmodified file. The inode
    /// catches a replacement, such as an editor's save-by-rename. A moved
    /// ctime alone doesn't count as a change: other processes bump it
    /// without altering anything, a no-op chmod or setxattr being enough,
    /// and a launched app's own updater or a file picker will do it to files
    /// inside a bundle. So when only the ctime differs, everything it could
    /// stand for is compared instead: size, mtime, mode, flags, owner,
    /// xattrs and ACL.
    pub fn unchanged(&self, target: &Path) -> io::Result<bool> {
        for _ in 0..STABLE_READ_TRIES {
            let before = fs::symlink_metadata(target)?;
            if StatFields::of(&before) != self.stat {
                return Ok(false);
            }
            if ctime_of(&before) == self.ctime {
                return Ok(true);
            }
            let attrs = crate::fsops::attrs_fingerprint(target)?;
            let after = fs::symlink_metadata(target)?;
            // Read while something else was changing it: try again rather
            // than trust a fingerprint that may belong to neither state.
            if ctime_of(&after) != ctime_of(&before) || StatFields::of(&after) != self.stat {
                continue;
            }
            return Ok(attrs == self.attrs);
        }
        Ok(false)
    }

    /// Whether `path` is the same file with the same content and attributes,
    /// judged without ctime, which a rename moves.
    fn same_file_and_attrs(&self, path: &Path) -> bool {
        let Ok(meta) = fs::symlink_metadata(path) else { return false };
        StatFields::of(&meta) == self.stat && crate::fsops::attrs_fingerprint(path).is_ok_and(|a| a == self.attrs)
    }
}

impl StagedFile {
    /// Clones `target` into a staging file, in whichever directory
    /// `preferred_staging_dir` picks, with an unguessable name. The clone
    /// inherits `target`'s owner/mode/xattrs. Caller writes the decmpfs
    /// xattr(s), truncates the clone's data fork, and sets UF_COMPRESSED
    /// before calling `promote`.
    pub fn stage(target: &Path) -> io::Result<Self> {
        let parent = match target.parent() {
            Some(p) if p.as_os_str().is_empty() => Path::new("."), // a bare relative name
            Some(p) => p,
            None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "target has no parent directory")),
        };
        // Captured before cloning, for the mode/group checks below; atime/mtime
        // restoration is handled via `original_times` (see module doc).
        // As root the path may lead through directories an untrusted process
        // can write (e.g. /Applications). Walk it with O_NOFOLLOW so a symlink
        // component fails rather than redirecting the clone, and record the
        // target's and parent's identity to recheck just before the swap.
        // clonefile still resolves the path by name, so a swap in the gap
        // between this walk and the clone below is caught by that recheck, not
        // prevented here; the residual is documented on `promote`.
        let root_ids = if crate::fsops::euid() == 0 {
            Some(crate::fsops::walk_ids_nofollow(target)?)
        } else {
            None
        };
        let target_meta = fs::symlink_metadata(target)?;
        let staging_dir = preferred_staging_dir(parent, target_meta.gid())?;
        let staged_path = staging_dir.join(format!("{STAGE_PREFIX}{}", Uuid::new_v4()));
        let snapshot = TargetSnapshot::of(&target_meta, target)?;
        let original_times =
            FileTimes::new().set_accessed(target_meta.accessed()?).set_modified(target_meta.modified()?);

        crate::fsops::clone_file(target, &staged_path)?;

        let meta = fs::symlink_metadata(&staged_path)?;

        // TOCTOU guard: if `target` became a symlink after the caller's checks,
        // CLONE_NOFOLLOW clones the symlink itself; reject before a later open() follows it.
        if meta.file_type().is_symlink() {
            let _ = fs::remove_file(&staged_path);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "target became a symlink before staging - aborting",
            ));
        }

        // The replacement must keep the original's owner. clonefile(2) copies
        // it when the caller is root and substitutes the caller otherwise, so
        // this passes for root, or for a caller who owns the file, and refuses
        // anyone else rather than hand them someone else's file.
        if meta.uid() != target_meta.uid() {
            let _ = fs::remove_file(&staged_path);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "staged clone's owner does not match the original file - refusing to change its owner",
            ));
        }

        // Compare permission bits only: clonefile(2) strips setuid/setgid, but
        // a setuid/setgid target is already rejected earlier by `policy::should_skip`.
        if meta.mode() & 0o777 != target_meta.mode() & 0o777 {
            let _ = fs::remove_file(&staged_path);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "staged clone's permission bits do not match the original file - refusing to promote",
            ));
        }

        // Only when no staging directory had the target's group (see
        // `preferred_staging_dir`).
        if meta.gid() != target_meta.gid()
            && let Err(e) = restore_group(&staged_path, target_meta.gid())
        {
            let _ = fs::remove_file(&staged_path);
            return Err(e);
        }

        Ok(StagedFile { path: staged_path, original_times, snapshot, root_ids })
    }

    /// Truncates the staged file's data fork to zero; the decmpfs xattr(s)
    /// carry the compressed content from here on.
    pub fn truncate_data_fork(&self) -> io::Result<()> {
        let f = fs::OpenOptions::new().write(true).open(&self.path)?;
        f.set_len(0)
    }

    /// Atomically swaps the staged file into `target`'s place, provided
    /// `target` is still the file `snapshot` describes. Returns `false`,
    /// with `target` as it was and the staged file gone, if it changed.
    ///
    /// Checked on both sides of the swap: before it, the whole snapshot;
    /// after it, the swapped-out file by everything but ctime, which the
    /// swap itself moves. A file replaced, written to or re-attributed
    /// between the two is swapped back untouched, where a plain rename
    /// would destroy the change. Only a change after that second check
    /// goes unnoticed.
    pub fn promote(self, target: &Path, snapshot: &TargetSnapshot) -> io::Result<bool> {
        // A target that can't be read (deleted, say) counts as changed, so
        // it isn't resurrected.
        if !snapshot.unchanged(target).unwrap_or(false) {
            let _ = self.discard();
            return Ok(false);
        }
        // For a root operation, refuse the swap unless the path still has no
        // symlink component and the target and its parent are the same inodes
        // seen at stage time. This closes the window against a redirect of an
        // intermediate directory; only the sub-syscall gap between this recheck
        // and the rename below remains (see the module note).
        if let Some(staged_ids) = self.root_ids {
            let ok = crate::fsops::walk_ids_nofollow(target).is_ok_and(|now| now == staged_ids)
                && crate::fsops::target_and_parent_ids(target).is_ok_and(|now| now == staged_ids);
            if !ok {
                let _ = self.discard();
                return Ok(false);
            }
        }
        // A failed rename leaves the staged file in place, so remove it. It
        // can fail with ENOSPC: APFS allocates new metadata blocks for it.
        match crate::fsops::rename_swap(&self.path, target) {
            Ok(()) => {}
            // A volume without swap support: the check above is all there is.
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTSUP | libc::EINVAL)) => {
                if let Err(e) = fs::rename(&self.path, target) {
                    let _ = self.discard();
                    return Err(e);
                }
                return Ok(true);
            }
            Err(e) => {
                let _ = self.discard();
                return Err(e);
            }
        }
        // `self.path` now holds whatever was at `target`.
        let kept = snapshot.same_file_and_attrs(&self.path);
        if kept {
            let _ = fs::remove_file(&self.path);
            return Ok(true);
        }
        crate::fsops::rename_swap(&self.path, target).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("{} changed while being replaced and couldn't be swapped back; it is at {}: {e}", target.display(), self.path.display()),
            )
        })?;
        let _ = fs::remove_file(&self.path);
        Ok(false)
    }

    /// Explicitly discards the staged file. Prefer this over letting
    /// `StagedFile` drop silently so failures are visible to the caller.
    pub fn discard(self) -> io::Result<()> {
        fs::remove_file(&self.path)
    }
}

/// Sets a staged clone's group back to the target's. Changing to a group
/// the caller isn't a member of fails with EPERM, reported as
/// [`GroupNotRestorable`] so callers can skip the file rather than fail.
fn restore_group(staged_path: &Path, gid: u32) -> io::Result<()> {
    crate::fsops::chown_group(staged_path, gid).map_err(|e| {
        if e.raw_os_error() == Some(libc::EPERM) {
            io::Error::new(io::ErrorKind::PermissionDenied, GroupNotRestorable)
        } else {
            io::Error::new(e.kind(), format!("could not restore the original file's group on the staged clone: {e}"))
        }
    })
}

/// No staging directory gives new files the target's group, and the caller
/// isn't a member of it, so a staged copy can't carry it.
#[derive(Debug)]
pub struct GroupNotRestorable;

impl std::fmt::Display for GroupNotRestorable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the file's group can't be set on a staged copy: the caller isn't a member of it")
    }
}

impl std::error::Error for GroupNotRestorable {}

/// Whether `e` is [`GroupNotRestorable`], as opposed to any other staging error.
pub fn is_group_not_restorable(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<GroupNotRestorable>())
}

/// Ensures a private (`0700`, owned by `euid`) directory exists at `path`.
/// Returns `Ok(true)` if it's now safe to stage into (freshly created and
/// locked down atomically, or already existing and verified as ours).
/// `Ok(false)` if something unverifiable is there (wrong owner, or a
/// symlink planted at the name); the caller should fall back to an
/// unpredictable name instead.
fn ensure_private_dir(path: &Path, euid: u32) -> io::Result<bool> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let meta = fs::symlink_metadata(path)?;
            Ok(meta.is_dir() && meta.uid() == euid && meta.mode() & 0o777 == 0o700)
        }
        Err(e) => Err(e),
    }
}

/// Picks a same-`st_dev` staging directory for `same_dir`'s volume. The
/// candidates, in order of preference:
/// 1. `$TMPDIR` - per-user private temp dir, already ours; absent for
///    `sudo`/root daemons.
/// 2. `/tmp/<euid>.apfscompress` - fixed, reusable across invocations.
/// 3. `/tmp/<euid>.apfscompress.<uuid>` - used if tier 2 exists but isn't
///    verifiably ours; reusable within this process only.
/// 4. `same_dir` itself - required for cross-volume targets.
///
/// An unprivileged clone takes its directory's group, and setting it back
/// needs membership in the target's group. So the first candidate whose
/// group is already `target_gid` wins, with no change needed; typically
/// `$TMPDIR` (`staff`), `/tmp` (`wheel`) or the target's own directory. If
/// none has it, the first candidate is used and `stage()` restores the group.
///
/// Every tier is checked against `st_dev` first. `stage()`'s post-clone
/// ownership check catches any tier lacking real POSIX ownership.
fn preferred_staging_dir(same_dir: &Path, target_gid: u32) -> io::Result<PathBuf> {
    let target_dev = fs::metadata(same_dir)?.dev();
    let euid = crate::fsops::euid();
    let mut candidates = Vec::new();

    if let Some(tmpdir) = std::env::var_os("TMPDIR") {
        let tmpdir = PathBuf::from(tmpdir);
        if fs::metadata(&tmpdir).ok().map(|m| m.dev()) == Some(target_dev) {
            candidates.push(tmpdir);
        }
    }

    let tmp = Path::new("/tmp");
    if fs::metadata(tmp).ok().map(|m| m.dev()) == Some(target_dev) {
        let standard = tmp.join(format!("{euid}.apfscompress"));
        if let Ok(true) = ensure_private_dir(&standard, euid) {
            candidates.push(standard);
        } else {
            let random = tmp.join(format!("{euid}.apfscompress.{}", Uuid::new_v4()));
            if let Ok(true) = ensure_private_dir(&random, euid) {
                candidates.push(random);
            }
        }
    }

    // Root never stages where someone else could rename or replace the
    // staged file between the steps that write it by path.
    let others_may_write = |dir: &Path| {
        fs::symlink_metadata(dir).map_or(true, |m| !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0)
    };
    if euid != 0 || !others_may_write(same_dir) {
        candidates.push(same_dir.to_path_buf());
    }
    if candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no staging directory on this volume that only root can write to",
        ));
    }
    let group_of = |dir: &Path| fs::metadata(dir).ok().map(|m| m.gid());
    let chosen = match candidates.iter().position(|dir| group_of(dir) == Some(target_gid)) {
        Some(i) => candidates.swap_remove(i),
        None => candidates.swap_remove(0),
    };
    // Invariant this function must never violate: rename()/clonefile()
    // require same-filesystem regardless of which directory got picked.
    debug_assert_eq!(
        fs::metadata(&chosen).map(|m| m.dev()).unwrap_or(target_dev),
        target_dev,
        "preferred_staging_dir chose a directory on a different filesystem than the target"
    );
    Ok(chosen)
}

/// Removes any `.apfscompress.tmp.*` leftovers in `dir` left by a hard
/// crash; normal error paths already clean up via `discard`. Returns the
/// count removed.
///
/// Not safe to run concurrently with an in-flight compress/decompress in
/// the same directory: it deletes staging files unconditionally, including
/// one mid-use elsewhere. Call this between runs, not during one.
pub fn sweep_orphans(dir: &Path) -> io::Result<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str()
            && name.starts_with(STAGE_PREFIX)
                && fs::remove_file(entry.path()).is_ok() {
                    removed += 1;
                }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn ensure_private_dir_creates_it_locked_down() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("private");
        let euid = crate::fsops::euid();

        assert!(ensure_private_dir(&path, euid).unwrap());
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.mode() & 0o777, 0o700);
    }

    #[test]
    fn ensure_private_dir_reuses_a_verified_existing_directory() {
        // A second call must accept what an earlier one created rather than
        // erroring on AlreadyExists.
        let dir = tempdir().unwrap();
        let path = dir.path().join("private");
        let euid = crate::fsops::euid();

        assert!(ensure_private_dir(&path, euid).unwrap());
        assert!(ensure_private_dir(&path, euid).unwrap());
    }

    #[test]
    fn ensure_private_dir_rejects_a_symlink_planted_at_the_name() {
        let dir = tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let path = dir.path().join("private");
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();

        assert!(!ensure_private_dir(&path, crate::fsops::euid()).unwrap());
    }

    #[test]
    fn ensure_private_dir_rejects_a_directory_with_looser_permissions() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("private");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(!ensure_private_dir(&path, crate::fsops::euid()).unwrap());
    }

    #[test]
    fn stage_rejects_a_symlink_target() {
        // clonefile(CLONE_NOFOLLOW) clones a symlink target as a symlink;
        // stage() must reject that rather than let a later open() follow it.
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.txt");
        let link = dir.path().join("link.txt");
        fs::write(&real, b"actual content").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let result = StagedFile::stage(&link);
        assert!(result.is_err(), "staging a symlink target should be rejected");
        // No leftover staging file, and the symlink/target are untouched.
        assert_eq!(fs::read(&link).unwrap(), b"actual content");
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            2,
            "no orphaned staging file should remain after a rejected stage"
        );
    }

    #[test]
    fn stage_preserves_target_group_regardless_of_staging_directory_default() {
        // clonefile(2) substitutes whatever group a plain new file would get
        // in the staging directory when unprivileged; stage() must restore it.
        let dir = tempdir().unwrap();
        let target = dir.path().join("file.bin");
        fs::write(&target, b"data").unwrap();
        let target_gid = fs::metadata(&target).unwrap().gid();

        let staged = StagedFile::stage(&target).unwrap();
        let staged_gid = fs::metadata(&staged.path).unwrap().gid();
        assert_eq!(
            staged_gid, target_gid,
            "staged clone's group must match the original file's group"
        );
        staged.discard().unwrap();
    }

    #[test]
    fn a_wheel_file_in_tmp_stages_where_new_files_are_wheel() {
        // Files created under /tmp are group `wheel`, which most users
        // aren't members of, so the clone must land where no chown is needed.
        let dir = tempfile::Builder::new().tempdir_in("/private/tmp").unwrap();
        let target = dir.path().join("file.bin");
        fs::write(&target, b"data").unwrap();
        let gid = fs::metadata(&target).unwrap().gid();

        let staged = StagedFile::stage(&target).unwrap();
        assert_eq!(fs::metadata(&staged.path).unwrap().gid(), gid);
        staged.discard().unwrap();
    }

    #[test]
    fn restoring_a_group_the_caller_lacks_is_reported_as_not_restorable() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("file.bin");
        fs::write(&file, b"data").unwrap();
        match restore_group(&file, 0) {
            // Root, or a member of wheel: nothing to test here.
            Ok(()) => {}
            Err(e) => assert!(is_group_not_restorable(&e), "{e}"),
        }
    }

    #[test]
    fn preferred_staging_dir_matches_device_or_falls_back() {
        let dir = tempdir().unwrap();
        let chosen = preferred_staging_dir(dir.path(), fs::metadata(dir.path()).unwrap().gid()).unwrap();
        let chosen_dev = fs::metadata(&chosen).unwrap().dev();
        let target_dev = fs::metadata(dir.path()).unwrap().dev();
        // Whichever it picked must be same-filesystem as the target.
        assert_eq!(chosen_dev, target_dev);
    }

    #[test]
    fn stage_promote_roundtrip() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("file.bin");
        fs::write(&target, b"original data").unwrap();

        let staged = StagedFile::stage(&target).unwrap();
        assert!(staged.path.exists());
        assert_ne!(staged.path, target);

        fs::write(&staged.path, b"new content").unwrap();
        let snapshot = staged.snapshot;
        assert!(staged.promote(&target, &snapshot).unwrap());

        assert_eq!(fs::read(&target).unwrap(), b"new content");
    }

    #[test]
    fn snapshot_notices_content_xattr_and_replacement_changes() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("t.txt");
        let fresh = |s: &str| {
            fs::write(&target, s).unwrap();
            let staged = StagedFile::stage(&target).unwrap();
            let snapshot = staged.snapshot;
            staged.discard().unwrap();
            assert!(snapshot.unchanged(&target).unwrap(), "staging alone must not count as a change");
            snapshot
        };

        let snapshot = fresh("one");
        fs::write(&target, "two").unwrap();
        assert!(!snapshot.unchanged(&target).unwrap(), "content change");

        let snapshot = fresh("three");
        crate::fsops::set_xattr(&target, "com.example.tag", b"x").unwrap();
        assert!(!snapshot.unchanged(&target).unwrap(), "xattr change");

        let snapshot = fresh("four");
        let other = dir.path().join("o.txt");
        fs::write(&other, "four").unwrap();
        fs::rename(&other, &target).unwrap();
        assert!(!snapshot.unchanged(&target).unwrap(), "replaced by rename");

        let snapshot = fresh("five");
        fs::remove_file(&target).unwrap();
        assert!(snapshot.unchanged(&target).is_err(), "deleted");
    }

    #[test]
    fn snapshot_ignores_a_ctime_bump_that_changed_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let target = dir.path().join("t.txt");
        fs::write(&target, "content").unwrap();
        crate::fsops::set_xattr(&target, "com.example.tag", b"v").unwrap();
        let snapshot = TargetSnapshot::of(&fs::symlink_metadata(&target).unwrap(), &target).unwrap();
        let ctime = || fs::symlink_metadata(&target).unwrap().ctime_nsec();

        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        let mut seen = vec![ctime()];
        let mut bump = |label: &str, f: &dyn Fn()| {
            std::thread::sleep(std::time::Duration::from_millis(5));
            f();
            let now = ctime();
            assert_ne!(seen.last(), Some(&now), "{label} was expected to move ctime");
            seen.push(now);
            assert!(snapshot.unchanged(&target).unwrap(), "{label} changed nothing");
        };
        bump("chmod to the same mode", &|| fs::set_permissions(&target, fs::Permissions::from_mode(mode)).unwrap());
        bump("setxattr to the same value", &|| crate::fsops::set_xattr(&target, "com.example.tag", b"v").unwrap());
    }

    #[test]
    fn snapshot_still_notices_attribute_changes_that_move_ctime() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let target = dir.path().join("t.txt");
        let fresh = || {
            fs::write(&target, "content").unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
            for name in crate::fsops::list_xattr_names_for_test(&target) {
                crate::fsops::remove_xattr(&target, &name).unwrap();
            }
            crate::fsops::set_xattr(&target, "com.example.tag", b"v1").unwrap();
            TargetSnapshot::of(&fs::symlink_metadata(&target).unwrap(), &target).unwrap()
        };

        let snapshot = fresh();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!snapshot.unchanged(&target).unwrap(), "mode");

        let snapshot = fresh();
        crate::fsops::set_xattr(&target, "com.example.tag", b"v2").unwrap();
        assert!(!snapshot.unchanged(&target).unwrap(), "xattr value, same size");

        let snapshot = fresh();
        crate::fsops::remove_xattr(&target, "com.example.tag").unwrap();
        assert!(!snapshot.unchanged(&target).unwrap(), "xattr removed");

        let snapshot = fresh();
        crate::fsops::set_xattr(&target, "com.example.other", b"v1").unwrap();
        assert!(!snapshot.unchanged(&target).unwrap(), "xattr added");
    }

    #[test]
    fn promote_proceeds_after_a_ctime_only_bump() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let target = dir.path().join("t.txt");
        fs::write(&target, "original").unwrap();
        let staged = StagedFile::stage(&target).unwrap();
        fs::write(&staged.path, "new").unwrap();
        let snapshot = staged.snapshot;

        std::thread::sleep(std::time::Duration::from_millis(5));
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        fs::set_permissions(&target, fs::Permissions::from_mode(mode)).unwrap();

        assert!(staged.promote(&target, &snapshot).unwrap());
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
    }

    #[test]
    fn promote_leaves_a_target_replaced_since_the_snapshot_alone() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("t.txt");
        fs::write(&target, "original").unwrap();
        let staged = StagedFile::stage(&target).unwrap();
        let (staged_path, snapshot) = (staged.path.clone(), staged.snapshot);

        let replacement = dir.path().join("r.txt");
        fs::write(&replacement, "someone else's save").unwrap();
        fs::rename(&replacement, &target).unwrap();

        assert!(!staged.promote(&target, &snapshot).unwrap());
        assert_eq!(fs::read_to_string(&target).unwrap(), "someone else's save");
        assert!(!staged_path.exists(), "the staged file must be cleaned up");
    }

    #[test]
    fn promote_removes_the_staged_file_when_the_swap_fails() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("t.txt");
        fs::write(&target, "original").unwrap();
        // An immutable target makes the swap fail with EPERM, standing in
        // for the ENOSPC a full volume gives.
        let c = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::chflags(c.as_ptr(), libc::UF_IMMUTABLE) }, 0);
        let staged = StagedFile::stage(&target).unwrap();
        let (staged_path, snapshot) = (staged.path.clone(), staged.snapshot);
        // The clone inherits the flag; only the target should keep it.
        let s = std::ffi::CString::new(staged_path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::chflags(s.as_ptr(), 0) }, 0);

        let result = staged.promote(&target, &snapshot);
        unsafe { libc::chflags(c.as_ptr(), 0) };
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
        assert!(!staged_path.exists(), "the staged file must be cleaned up");
    }

    #[test]
    fn promote_swaps_and_removes_the_original() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("t.txt");
        fs::write(&target, "original").unwrap();
        let staged = StagedFile::stage(&target).unwrap();
        fs::write(&staged.path, "new").unwrap();
        let (staged_path, snapshot) = (staged.path.clone(), staged.snapshot);

        assert!(staged.promote(&target, &snapshot).unwrap());
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        assert!(!staged_path.exists(), "the swapped-out original must be removed");
    }

    #[test]
    fn stage_discard_leaves_target_untouched() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("file.bin");
        fs::write(&target, b"original data").unwrap();

        let staged = StagedFile::stage(&target).unwrap();
        let staged_path = staged.path.clone();
        staged.discard().unwrap();

        assert!(!staged_path.exists());
        assert_eq!(fs::read(&target).unwrap(), b"original data");
    }

    #[test]
    fn sweep_orphans_removes_only_staging_files() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("real_file.txt"), b"keep me").unwrap();
        fs::write(dir.path().join(format!("{STAGE_PREFIX}abc123")), b"orphan").unwrap();
        fs::write(dir.path().join(format!("{STAGE_PREFIX}def456")), b"orphan2").unwrap();

        let removed = sweep_orphans(dir.path()).unwrap();
        assert_eq!(removed, 2);
        assert!(dir.path().join("real_file.txt").exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn truncate_data_fork_zeroes_length() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("file.bin");
        fs::write(&target, vec![0u8; 5000]).unwrap();

        let staged = StagedFile::stage(&target).unwrap();
        assert_eq!(fs::metadata(&staged.path).unwrap().len(), 5000);
        staged.truncate_data_fork().unwrap();
        assert_eq!(fs::metadata(&staged.path).unwrap().len(), 0);
    }

    // A target with no parent directory (e.g. a bare relative filename) must
    // fail cleanly, not panic on an empty-path clonefile() call downstream.
    #[test]
    fn stage_rejects_the_root() {
        // The only target with no parent; a bare relative name stages
        // beside itself (see `tests/cli.rs`).
        assert!(StagedFile::stage(Path::new("/")).is_err());
    }
}
