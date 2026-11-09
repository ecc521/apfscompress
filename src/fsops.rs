//! Safe wrappers over the raw FFI in `sys.rs` - xattrs, chflags, clonefile,
//! euid. No decmpfs/policy knowledge here.

use crate::sys;
use std::ffi::CString;
use std::io;
use std::os::macos::fs::MetadataExt as MacMetadataExt;
use std::os::raw::c_void;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

fn path_to_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

pub fn set_xattr(path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
    let cpath = path_to_cstring(path)?;
    let cname = CString::new(name).expect("xattr names never contain NUL");
    let rc = unsafe {
        sys::setxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            value.as_ptr() as *const c_void,
            value.len(),
            0,
            sys::XATTR_NOFOLLOW,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Reads an xattr's value. Always passes `XATTR_SHOWCOMPRESSION` alongside
/// `XATTR_NOFOLLOW`: once `UF_COMPRESSED` is set, a
/// plain `getxattr()` without this flag can no longer see
/// `com.apple.decmpfs` (fails ENOATTR) even though it's still there.
/// Harmless for ordinary xattrs.
pub fn get_xattr(path: &Path, name: &str) -> io::Result<Vec<u8>> {
    let cpath = path_to_cstring(path)?;
    let cname = CString::new(name).expect("xattr names never contain NUL");
    let options = sys::XATTR_NOFOLLOW | sys::XATTR_SHOWCOMPRESSION;
    let size = unsafe {
        sys::getxattr(cpath.as_ptr(), cname.as_ptr(), std::ptr::null_mut(), 0, 0, options)
    };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u8; size as usize];
    if buf.is_empty() {
        return Ok(buf);
    }
    let got = unsafe {
        sys::getxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            0,
            options,
        )
    };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(got as usize);
    Ok(buf)
}

/// Largest xattr value hashed by [`attrs_fingerprint`]. Bigger ones, such as
/// a compressed file's resource fork, count by name and size alone.
const FINGERPRINT_VALUE_LIMIT: usize = 64 * 1024;

/// `path`'s xattr names, as `listxattr` returns them.
fn list_xattr_names(path: &Path) -> io::Result<Vec<Vec<u8>>> {
    let cpath = path_to_cstring(path)?;
    let options = sys::XATTR_NOFOLLOW | sys::XATTR_SHOWCOMPRESSION;
    let size = unsafe { sys::listxattr(cpath.as_ptr(), std::ptr::null_mut(), 0, options) };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u8; size as usize];
    let got = unsafe { sys::listxattr(cpath.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len(), options) };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(got as usize);
    Ok(buf.split(|&b| b == 0).filter(|n| !n.is_empty()).map(<[u8]>::to_vec).collect())
}

/// `path`'s ACL as text, or `None` when it has none.
fn acl_text(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let cpath = path_to_cstring(path)?;
    let acl = unsafe { sys::acl_get_link_np(cpath.as_ptr(), sys::ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        return match io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOENT | libc::ENOTSUP | libc::EINVAL) => Ok(None),
            _ => Err(io::Error::last_os_error()),
        };
    }
    let mut len: isize = 0;
    let text = unsafe { sys::acl_to_text(acl, &mut len) };
    let out = if text.is_null() {
        Err(io::Error::last_os_error())
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(text as *const u8, len.max(0) as usize) }.to_vec();
        unsafe { sys::acl_free(text as *mut c_void) };
        Ok(Some(bytes))
    };
    unsafe { sys::acl_free(acl) };
    out
}

/// A hash of what `lstat` doesn't show but a ctime bump may stand for: the
/// xattrs (names, sizes, and values up to [`FINGERPRINT_VALUE_LIMIT`]) and
/// the ACL. Equal fingerprints plus equal `lstat` fields mean a moved ctime
/// changed nothing.
pub fn attrs_fingerprint(path: &Path) -> io::Result<u64> {
    use std::hash::{Hash, Hasher};
    let mut names = list_xattr_names(path)?;
    names.sort();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for name in &names {
        name.hash(&mut h);
        let cname = CString::new(name.as_slice()).map_err(|_| io::Error::other("xattr name with NUL"))?;
        let cpath = path_to_cstring(path)?;
        let options = sys::XATTR_NOFOLLOW | sys::XATTR_SHOWCOMPRESSION;
        let size = unsafe { sys::getxattr(cpath.as_ptr(), cname.as_ptr(), std::ptr::null_mut(), 0, 0, options) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        size.hash(&mut h);
        if (size as usize) <= FINGERPRINT_VALUE_LIMIT {
            let name = std::str::from_utf8(name).map_err(|_| io::Error::other("non-UTF-8 xattr name"))?;
            get_xattr(path, name)?.hash(&mut h);
        }
    }
    acl_text(path)?.hash(&mut h);
    Ok(h.finish())
}

#[cfg(test)]
pub fn list_xattr_names_for_test(path: &Path) -> Vec<String> {
    list_xattr_names(path).unwrap().into_iter().map(|n| String::from_utf8(n).unwrap()).collect()
}

pub fn remove_xattr(path: &Path, name: &str) -> io::Result<()> {
    let cpath = path_to_cstring(path)?;
    let cname = CString::new(name).expect("xattr names never contain NUL");
    let rc = unsafe { sys::removexattr(cpath.as_ptr(), cname.as_ptr(), sys::XATTR_NOFOLLOW) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn set_compressed_flag(path: &Path) -> io::Result<()> {
    let cpath = path_to_cstring(path)?;
    let rc = unsafe { sys::chflags(cpath.as_ptr(), sys::UF_COMPRESSED) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// fd-relative counterpart of `set_compressed_flag`.
pub fn set_compressed_flag_fd(file: &std::fs::File) -> io::Result<()> {
    let rc = unsafe { sys::fchflags(file.as_raw_fd(), sys::UF_COMPRESSED) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Clears UF_COMPRESSED while preserving any other flags already set.
pub fn clear_compressed_flag(path: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    let new_flags = meta.st_flags() & !sys::UF_COMPRESSED;
    let cpath = path_to_cstring(path)?;
    let rc = unsafe { sys::chflags(cpath.as_ptr(), new_flags) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Copy-on-write clone via `clonefile(2)`. Inherits mode and xattrs, but
/// owner/group are copied verbatim only when the caller can chown (root);
/// otherwise they're substituted as if freshly created via `openat(2)`.
/// Setuid/setgid bits are always stripped. Callers that need ownership
/// preserved (`swap::StagedFile::stage`) must verify it themselves.
///
/// Passes `CLONE_ACL`; without it the source's ACL isn't copied at all,
/// which would silently strip a compressed file's ACL after promotion.
pub fn clone_file(src: &Path, dst: &Path) -> io::Result<()> {
    let csrc = path_to_cstring(src)?;
    let cdst = path_to_cstring(dst)?;
    let rc = unsafe { sys::clonefile(csrc.as_ptr(), cdst.as_ptr(), sys::CLONE_NOFOLLOW | sys::CLONE_ACL) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn euid() -> u32 {
    unsafe { sys::geteuid() }
}

/// Walks `path` a component at a time with `openat(O_NOFOLLOW)`, so a symlink
/// anywhere in it fails the open rather than being followed, and returns the
/// `(st_dev, st_ino)` of the final file and of its parent directory, read
/// from the fds the walk opened (never re-resolved by path). Used before a
/// root operation so an untrusted process can't redirect it by swapping an
/// intermediate directory for a symlink between the check and the work.
///
/// `path` must be absolute. A symlink component gives `ELOOP`.
pub fn walk_ids_nofollow(path: &Path) -> io::Result<((u64, u64), (u64, u64))> {
    use std::os::fd::{FromRawFd, OwnedFd};
    if !path.is_absolute() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path must be absolute"));
    }
    let flags = libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let open_dir = |dir: libc::c_int, name: &std::ffi::CStr| -> io::Result<OwnedFd> {
        let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_DIRECTORY) };
        if fd < 0 { Err(io::Error::last_os_error()) } else { Ok(unsafe { OwnedFd::from_raw_fd(fd) }) }
    };
    let ids = |fd: libc::c_int| -> io::Result<(u64, u64)> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((st.st_dev as u64, st.st_ino as u64))
    };
    let mut dir = open_dir(libc::AT_FDCWD, c"/")?;
    let comps: Vec<_> = path.components().collect();
    // The last real component is the file; everything before it is a directory.
    let (last, parents) = match comps.as_slice() {
        [std::path::Component::RootDir, rest @ ..] if !rest.is_empty() => (rest.last().unwrap(), &rest[..rest.len() - 1]),
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "path has no file component")),
    };
    for comp in parents {
        let name = CString::new(comp.as_os_str().as_bytes())?;
        dir = open_dir(dir.as_raw_fd(), &name)?;
    }
    let parent_ids = ids(dir.as_raw_fd())?;
    let name = CString::new(last.as_os_str().as_bytes())?;
    let file_fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if file_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file_fd = unsafe { OwnedFd::from_raw_fd(file_fd) };
    Ok((ids(file_fd.as_raw_fd())?, parent_ids))
}

/// `(st_dev, st_ino)` of `path` and of its parent, by `lstat` (the final
/// component is not followed). Cheap recheck to pair with an earlier
/// [`walk_ids_nofollow`].
pub fn target_and_parent_ids(path: &Path) -> io::Result<((u64, u64), (u64, u64))> {
    let m = std::fs::symlink_metadata(path)?;
    let parent = path.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent"))?;
    let pm = std::fs::symlink_metadata(parent)?;
    Ok(((m.st_dev() as u64, m.st_ino()), (pm.st_dev() as u64, pm.st_ino())))
}

/// Atomically exchanges the files at `a` and `b` (`renamex_np` with
/// `RENAME_SWAP`); both must exist on the same volume.
pub fn rename_swap(a: &Path, b: &Path) -> io::Result<()> {
    let (ca, cb) = (path_to_cstring(a)?, path_to_cstring(b)?);
    let rc = unsafe { libc::renamex_np(ca.as_ptr(), cb.as_ptr(), libc::RENAME_SWAP) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Changes only the group of `path`, leaving the owner untouched (passes
/// `(uid_t)-1` for the owner argument, `chown(2)`'s documented sentinel for
/// "don't change this").
pub fn chown_group(path: &Path, gid: u32) -> io::Result<()> {
    let cpath = path_to_cstring(path)?;
    let rc = unsafe { sys::chown(cpath.as_ptr(), u32::MAX, gid) };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// One 64-bit `ATTR_CMNEXT_*` attribute of `path` (not following a final
/// symlink) via `getattrlist(FSOPT_ATTR_CMN_EXTENDED)`. `None` when the
/// volume doesn't report it: anything but APFS, or an older macOS.
fn common_extended_u64(path: &Path, attr: libc::attrgroup_t) -> io::Result<Option<u64>> {
    let cpath = path_to_cstring(path)?;
    let mut list: libc::attrlist = unsafe { std::mem::zeroed() };
    list.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    list.commonattr = libc::ATTR_CMN_RETURNED_ATTRS;
    list.forkattr = attr;
    // u32 length, then the returned attribute_set_t (five u32 groups, the
    // last being forkattr), then the value.
    let mut buf = [0u8; 32];
    let options = libc::FSOPT_ATTR_CMN_EXTENDED | libc::FSOPT_NOFOLLOW;
    let rc = unsafe {
        libc::getattrlist(
            cpath.as_ptr(),
            &mut list as *mut libc::attrlist as *mut c_void,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            options,
        )
    };
    if rc != 0 {
        let e = io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::EINVAL | libc::ENOTSUP) => Ok(None),
            _ => Err(e),
        };
    }
    let returned_fork = u32::from_ne_bytes(buf[20..24].try_into().unwrap());
    if returned_fork & attr == 0 {
        return Ok(None);
    }
    Ok(Some(u64::from_ne_bytes(buf[24..32].try_into().unwrap())))
}

/// `path`'s APFS extended flags (`EF_*` in <sys/stat.h>, such as
/// `sys::EF_SHARES_ALL_BLOCKS`), or `None` where the volume has none. Costs
/// about as much as an `lstat`. `EF_SHARES_ALL_BLOCKS` covers the resource
/// fork too, so it holds for a compressed file's clones, and it clears once
/// any block becomes the file's own. `EF_MAY_SHARE_BLOCKS` never clears once
/// set, so it only says sharing is possible.
pub fn ext_flags(path: &Path) -> io::Result<Option<u64>> {
    common_extended_u64(path, libc::ATTR_CMNEXT_EXT_FLAGS)
}

/// Bytes of `path`'s data fork that no clone shares
/// (`ATTR_CMNEXT_PRIVATESIZE`), or `None` where the volume can't say. Counts
/// the data fork only: a compressed file, whose content is in its resource
/// fork, reports 0 however much of it is its own.
///
/// Takes time in proportion to the file's extents: about a microsecond for
/// an ordinary file, but milliseconds for a clone fragmented by thousands
/// of small rewrites. Check [`ext_flags`] first, which is cheap.
pub fn private_size(path: &Path) -> io::Result<Option<u64>> {
    common_extended_u64(path, libc::ATTR_CMNEXT_PRIVATESIZE)
}

/// Path to a file's resource fork via the `..namedfork/rsrc` pseudo-path -
/// same storage as the `com.apple.ResourceFork` xattr, but reachable as an
/// ordinary file supporting streaming read/write/seek, so a large write can
/// stream out incrementally instead of one in-memory `setxattr()` call.
pub fn resource_fork_path(path: &Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push("/..namedfork/rsrc");
    std::path::PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn resource_fork_namedfork_write_visible_via_getxattr() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"main fork content").unwrap();

        let rsrc_path = resource_fork_path(&path);
        let mut f =
            std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&rsrc_path).unwrap();
        // Out-of-order write to confirm this is a real seekable fd, not a
        // write-once shim.
        f.seek(SeekFrom::Start(4)).unwrap();
        f.write_all(b"tail").unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(b"head").unwrap();
        drop(f);

        let via_xattr = get_xattr(&path, "com.apple.ResourceFork").unwrap();
        assert_eq!(via_xattr, b"headtail");
        // Main data fork must be untouched by writes to the resource fork.
        assert_eq!(std::fs::read(&path).unwrap(), b"main fork content");
    }

    #[test]
    fn xattr_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.txt");
        std::fs::write(&path, b"hello").unwrap();
        set_xattr(&path, "com.apfscompress.test", b"payload-bytes").unwrap();
        let back = get_xattr(&path, "com.apfscompress.test").unwrap();
        assert_eq!(back, b"payload-bytes");
    }

    #[test]
    fn clone_then_independent_xattr() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst.txt");
        std::fs::write(&src, b"original content").unwrap();
        clone_file(&src, &dst).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"original content");

        set_xattr(&dst, "com.apfscompress.test", b"only-on-clone").unwrap();
        assert!(get_xattr(&src, "com.apfscompress.test").is_err());
        assert_eq!(get_xattr(&dst, "com.apfscompress.test").unwrap(), b"only-on-clone");
    }

    #[test]
    fn path_with_embedded_nul_byte_is_rejected_cleanly() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let bad_path = std::path::PathBuf::from(OsString::from_vec(b"/tmp/bad\0path".to_vec()));

        assert!(set_xattr(&bad_path, "com.apfscompress.test", b"x").is_err());
        assert!(get_xattr(&bad_path, "com.apfscompress.test").is_err());
        assert!(remove_xattr(&bad_path, "com.apfscompress.test").is_err());
        assert!(clone_file(&bad_path, Path::new("/tmp/irrelevant-dst")).is_err());
    }

    #[test]
    fn clone_preserves_owner_and_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst.txt");
        std::fs::write(&src, b"x").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o640)).unwrap();
        clone_file(&src, &dst).unwrap();
        let src_meta = std::fs::metadata(&src).unwrap();
        let dst_meta = std::fs::metadata(&dst).unwrap();
        assert_eq!(src_meta.permissions().mode() & 0o777, dst_meta.permissions().mode() & 0o777);
    }

    /// Builds a single-entry "user:self:allow:read,write,delete" ACL and
    /// applies it to `path` via the raw entry API (`acl_init` ->
    /// `acl_create_entry` -> tag/qualifier/permset -> `acl_set_link_np`).
    #[cfg(test)]
    fn set_test_acl(path: &Path) {
        use sys::*;
        unsafe {
            let mut acl = acl_init(1);
            assert!(!acl.is_null(), "acl_init failed");
            let mut entry: AclEntryT = std::ptr::null_mut();
            assert_eq!(acl_create_entry(&mut acl, &mut entry), 0, "acl_create_entry failed");
            assert_eq!(acl_set_tag_type(entry, ACL_EXTENDED_ALLOW), 0, "acl_set_tag_type failed");
            let uid = euid();
            assert_eq!(acl_set_qualifier(entry, &uid as *const u32 as *const c_void), 0, "acl_set_qualifier failed");
            let mut permset: AclPermsetT = std::ptr::null_mut();
            assert_eq!(acl_get_permset(entry, &mut permset), 0, "acl_get_permset failed");
            for perm in [ACL_READ_DATA, ACL_WRITE_DATA, ACL_DELETE] {
                assert_eq!(acl_add_perm(permset, perm), 0, "acl_add_perm failed");
            }
            assert_eq!(acl_set_permset(entry, permset), 0, "acl_set_permset failed");
            let cpath = path_to_cstring(path).unwrap();
            let rc = acl_set_link_np(cpath.as_ptr(), ACL_TYPE_EXTENDED, acl);
            acl_free(acl as *mut c_void);
            assert_eq!(rc, 0, "acl_set_link_np failed - does this filesystem support ACLs?");
        }
    }

    /// Reads `path`'s ACL back as text (empty string if it has none), for
    /// comparison. `acl_get_link_np` returning null (no ACL present) is
    /// reported as `None` rather than treated as an error.
    #[cfg(test)]
    fn read_acl_text(path: &Path) -> Option<String> {
        use sys::*;
        unsafe {
            let cpath = path_to_cstring(path).unwrap();
            let acl = acl_get_link_np(cpath.as_ptr(), ACL_TYPE_EXTENDED);
            if acl.is_null() {
                return None;
            }
            let mut len: isize = 0;
            let text_ptr = acl_to_text(acl, &mut len);
            let text = if text_ptr.is_null() {
                None
            } else {
                Some(std::ffi::CStr::from_ptr(text_ptr).to_string_lossy().into_owned())
            };
            acl_free(acl as *mut c_void);
            text
        }
    }

    #[test]
    fn fingerprint_tracks_xattrs_and_acl_but_not_ctime() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"x").unwrap();
        let base = attrs_fingerprint(&path).unwrap();

        set_xattr(&path, "com.example.a", b"1").unwrap();
        let with_xattr = attrs_fingerprint(&path).unwrap();
        assert_ne!(base, with_xattr);
        set_xattr(&path, "com.example.a", b"1").unwrap();
        assert_eq!(with_xattr, attrs_fingerprint(&path).unwrap(), "rewriting the same value");
        set_xattr(&path, "com.example.a", b"2").unwrap();
        assert_ne!(with_xattr, attrs_fingerprint(&path).unwrap(), "same size, other value");

        remove_xattr(&path, "com.example.a").unwrap();
        assert_eq!(base, attrs_fingerprint(&path).unwrap());
        set_test_acl(&path);
        assert_ne!(base, attrs_fingerprint(&path).unwrap(), "ACL");
    }

    /// A bare `clonefile()` call does not copy the source's ACL at all,
    /// which would silently strip it once the clone is renamed over the original.
    #[test]
    fn clone_preserves_acl() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("dst.txt");
        std::fs::write(&src, b"x").unwrap();

        set_test_acl(&src);
        let src_acl = read_acl_text(&src).expect("test setup didn't actually set an ACL");
        assert!(src_acl.contains("read,write,delete"), "unexpected ACL text: {src_acl}");

        clone_file(&src, &dst).unwrap();

        let dst_acl = read_acl_text(&dst);
        assert_eq!(
            dst_acl.as_deref(),
            Some(src_acl.as_str()),
            "clone_file must preserve the source's ACL, not just its POSIX mode bits"
        );
    }

    #[test]
    fn walk_ids_nofollow_matches_lstat_and_refuses_symlink_components() {
        let dir = tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let sub = root.join("sub");
        std::fs::create_dir(&sub).unwrap();
        let file = sub.join("f");
        std::fs::write(&file, b"x").unwrap();

        let (ids, parent_ids) = walk_ids_nofollow(&file).unwrap();
        assert_eq!(Some((ids, parent_ids)), target_and_parent_ids(&file).ok());

        // A symlinked leaf is refused (ELOOP).
        let link = sub.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(walk_ids_nofollow(&link).is_err());

        // A symlinked intermediate directory is refused too.
        let via = root.join("via");
        std::os::unix::fs::symlink(&sub, &via).unwrap();
        assert!(walk_ids_nofollow(&via.join("f")).is_err());

        assert!(walk_ids_nofollow(Path::new("relative/f")).is_err());
    }
}
