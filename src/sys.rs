//! Raw FFI declarations. Everything unsafe lives here; every other module
//! calls into safe wrappers only. Two link targets:
//! - libSystem (implicit, always linked on macOS): setxattr/getxattr/chflags/clonefile/geteuid
//! - libcompression (explicit `-lcompression`): compression_encode_buffer etc.

use std::os::raw::{c_char, c_int, c_void};

pub const XATTR_NOFOLLOW: c_int = 0x0001;
/// Required to read `com.apple.decmpfs` back once `UF_COMPRESSED` is set - see
/// `fsops::get_xattr`.
pub const XATTR_SHOWCOMPRESSION: c_int = 0x0020;

pub const UF_COMPRESSED: u32 = 0x0000_0020;

/// Extended flags (`EF_*` in <sys/stat.h>), read with `fsops::ext_flags`.
/// The file may share blocks with a clone. Sticky: set once it has ever been
/// cloned (including by our own staging), never cleared.
pub const EF_MAY_SHARE_BLOCKS: u64 = 0x0000_0001;
/// Every block of the file, resource fork included, is shared with a clone.
pub const EF_SHARES_ALL_BLOCKS: u64 = 0x0000_0040;

pub const CLONE_NOFOLLOW: c_int = 0x0001;
/// Without this, `clonefile(2)` doesn't copy the source's ACL - the clone
/// only inherits whatever ACL the destination directory applies (typically
/// none for our staging dirs). `swap::StagedFile::promote` then renames the
/// clone over the original, so omitting this would silently strip its ACL.
pub const CLONE_ACL: c_int = 0x0004;

/// Matches `compression_algorithm` in <compression.h>.
pub type CompressionAlgorithm = u32;
/// Unused: libcompression's `COMPRESSION_ZLIB` produces raw DEFLATE, not
/// zlib-wrapped output, so `Algo::Zlib` routes through libdeflate instead.
/// Kept as a reference marker for that gotcha - see `algo.rs`.
pub const COMPRESSION_ZLIB: CompressionAlgorithm = 0x205;
pub const COMPRESSION_LZFSE: CompressionAlgorithm = 0x801;
pub const COMPRESSION_LZBITMAP: CompressionAlgorithm = 0x702;
// No public constant in <compression.h>; `compression_encode_buffer` and
// `compression_decode_buffer` accept this value for raw LZVN.
pub const COMPRESSION_LZVN: CompressionAlgorithm = 0x900;
/// Public in <compression.h> ("available starting OS X 10.11"), but that is
/// the *framework* decoder. The decmpfs types that select it (15/16) are a
/// separate, much newer kernel-side addition - see `algo::min_os_version`.
pub const COMPRESSION_LZ4: CompressionAlgorithm = 0x100;

unsafe extern "C" {
    /// `sysctlbyname(3)`. Used only to read `kern.osproductversion`; a
    /// `null` `oldp` asks for the size the value needs.
    pub fn sysctlbyname(
        name: *const c_char,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *mut c_void,
        newlen: usize,
    ) -> c_int;
}

#[link(name = "compression")]
unsafe extern "C" {
    pub fn compression_encode_buffer(
        dst_buffer: *mut u8,
        dst_size: usize,
        src_buffer: *const u8,
        src_size: usize,
        scratch_buffer: *mut c_void,
        algorithm: CompressionAlgorithm,
    ) -> usize;

    pub fn compression_encode_scratch_buffer_size(algorithm: CompressionAlgorithm) -> usize;
    // Unused by the library (decode passes NULL scratch); read by
    // bench/src/bin/bench_algos.rs to report each algorithm's decode scratch size.
    pub fn compression_decode_scratch_buffer_size(algorithm: CompressionAlgorithm) -> usize;

    pub fn compression_decode_buffer(
        dst_buffer: *mut u8,
        dst_size: usize,
        src_buffer: *const u8,
        src_size: usize,
        scratch_buffer: *mut c_void,
        algorithm: CompressionAlgorithm,
    ) -> usize;
}

unsafe extern "C" {
    // xattr (macOS signature: has `position`, unlike Linux).
    pub fn setxattr(
        path: *const c_char,
        name: *const c_char,
        value: *const c_void,
        size: usize,
        position: u32,
        options: c_int,
    ) -> c_int;

    pub fn getxattr(
        path: *const c_char,
        name: *const c_char,
        value: *mut c_void,
        size: usize,
        position: u32,
        options: c_int,
    ) -> isize;

    pub fn removexattr(path: *const c_char, name: *const c_char, options: c_int) -> c_int;

    pub fn listxattr(path: *const c_char, namebuf: *mut c_char, size: usize, options: c_int) -> isize;

    // ACL (<sys/acl.h>), read-only: `fsops::acl_text`.
    pub fn acl_get_link_np(path: *const c_char, acl_type: u32) -> AclT;
    pub fn acl_to_text(acl: AclT, len_p: *mut isize) -> *mut c_char;
    pub fn acl_free(obj: *mut c_void) -> c_int;

    // flags.
    pub fn chflags(path: *const c_char, flags: u32) -> c_int;
    // fd-relative counterpart of chflags.
    pub fn fchflags(fd: c_int, flags: u32) -> c_int;

    // ownership (uid_t/gid_t are `unsigned int` on macOS).
    pub fn chown(path: *const c_char, uid: u32, gid: u32) -> c_int;

    // clonefile (<sys/clonefile.h>).
    pub fn clonefile(src: *const c_char, dst: *const c_char, flags: c_int) -> c_int;

    pub fn geteuid() -> u32;
}

pub type AclT = *mut c_void;
pub const ACL_TYPE_EXTENDED: u32 = 0x0000_0100;

// ACL setters (<sys/acl.h>), test-only. Production code only reads ACLs
// (clonefile(CLONE_ACL) copies them; see `fsops::clone_file`). These exist
// so `clone_preserves_acl` can set/read an ACL via syscalls instead of
// spawning `chmod`/`ls`, which can destabilize other tests running
// concurrently in the same process.
#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod acl {
    use super::*;

    pub type AclEntryT = *mut c_void;
    pub type AclPermsetT = *mut c_void;

    pub const ACL_EXTENDED_ALLOW: c_int = 1;
    pub const ACL_READ_DATA: c_int = 1 << 1;
    pub const ACL_WRITE_DATA: c_int = 1 << 2;
    pub const ACL_DELETE: c_int = 1 << 4;

    unsafe extern "C" {
        pub fn acl_init(count: c_int) -> AclT;
        pub fn acl_create_entry(acl: *mut AclT, entry: *mut AclEntryT) -> c_int;
        pub fn acl_set_tag_type(entry: AclEntryT, tag_type: c_int) -> c_int;
        pub fn acl_set_qualifier(entry: AclEntryT, qualifier: *const c_void) -> c_int;
        pub fn acl_get_permset(entry: AclEntryT, permset: *mut AclPermsetT) -> c_int;
        pub fn acl_add_perm(permset: AclPermsetT, perm: c_int) -> c_int;
        pub fn acl_set_permset(entry: AclEntryT, permset: AclPermsetT) -> c_int;
        pub fn acl_set_link_np(path: *const c_char, acl_type: u32, acl: AclT) -> c_int;
    }
}
#[cfg(test)]
pub use acl::*;
