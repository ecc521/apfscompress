//! Which files some process could still write to.
//!
//! Compressing swaps a new inode in under the file's name. A process that
//! already has the file open for writing keeps writing to the old inode,
//! and those writes are lost when it closes it. The same goes for a shared,
//! writable memory mapping, which outlives the descriptor that made it. So a
//! file that any process has open or mapped for writing is left alone.
//! (Decompressing needs no such check: opening a compressed file for writing
//! makes the kernel decompress it there and then.)
//!
//! The set comes from libproc: every process's descriptors (`FWRITE`) and
//! file-backed memory regions (shared and writable). Root sees every
//! process; anyone else sees only their own, which are the processes that
//! can write their files anyway. On a busy Mac the descriptors of every
//! process take about 15 ms to scan and the mappings about 125 ms, so each
//! is shared as a snapshot and rescanned once older than its own limit.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

/// How stale the descriptor snapshot may be. Nearly every writer is caught
/// here: a mapping is made from a descriptor opened for writing.
pub const FDS_MAX_AGE: Duration = Duration::from_millis(500);
/// How stale the mapping snapshot may be.
pub const MAPPINGS_MAX_AGE: Duration = Duration::from_secs(5);
/// How long one process's descriptors or mappings may take to read. A
/// libproc call can block for a second or more on a vnode that process is
/// busy with (a search of the whole disk, a stalled network volume), and
/// every check waits on the shared snapshot.
const PROCESS_BUDGET: Duration = Duration::from_millis(250);
/// How long a process that went over budget is left out of later scans.
/// Its writers are missed meanwhile.
const SLOW_PROCESS_SKIP: Duration = Duration::from_secs(60);

/// `(st_dev, st_ino)`, as `stat` reports them.
pub type FileId = (u32, u64);

// From <sys/proc_info.h>; libc has the entry points but not these layouts.
const PROC_PIDFDVNODEINFO: libc::c_int = 1;
const PROC_PIDREGIONPATHINFO: libc::c_int = 8;
/// Like `PROC_PIDREGIONPATHINFO`, but steps over regions with no file behind
/// them: about 60 times fewer calls. The value is from XNU's open-source
/// `bsd/sys/proc_info.h` (macOS 10.13 and later); it is not in the SDK header,
/// so `PROC_PIDREGIONPATHINFO` stays as a fallback.
const PROC_PIDREGIONPATHINFO2: libc::c_int = 22;
const FWRITE: u32 = 0x2;
const VM_PROT_WRITE: u32 = 0x2;
/// A region's inheritance is `VM_INHERIT_SHARE` for `MAP_SHARED` and
/// `VM_INHERIT_COPY` for `MAP_PRIVATE`. Its share mode doesn't tell them
/// apart while only one process maps the file.
const VM_INHERIT_SHARE: u32 = 0;

#[repr(C)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: libc::off_t,
    fi_type: i32,
    fi_guardflags: u32,
}

#[repr(C)]
struct VnodeInfo {
    vi_stat: libc::vinfo_stat,
    vi_type: libc::c_int,
    vi_pad: libc::c_int,
    vi_fsid: libc::fsid_t,
}

#[repr(C)]
struct VnodeFdInfo {
    pfi: ProcFileInfo,
    pvi: VnodeInfo,
}

#[repr(C)]
struct ProcRegionInfo {
    pri_protection: u32,
    pri_max_protection: u32,
    pri_inheritance: u32,
    pri_flags: u32,
    pri_offset: u64,
    pri_behavior: u32,
    pri_user_wired_count: u32,
    pri_user_tag: u32,
    pri_pages_resident: u32,
    pri_pages_shared_now_private: u32,
    pri_pages_swapped_out: u32,
    pri_pages_dirtied: u32,
    pri_ref_count: u32,
    pri_shadow_depth: u32,
    pri_share_mode: u32,
    pri_private_pages_resident: u32,
    pri_shared_pages_resident: u32,
    pri_obj_id: u32,
    pri_depth: u32,
    pri_address: u64,
    pri_size: u64,
}

#[repr(C)]
struct RegionWithPathInfo {
    prp_prinfo: ProcRegionInfo,
    prp_vip_vi: VnodeInfo,
    prp_vip_path: [libc::c_char; libc::PATH_MAX as usize],
}

/// Files open or mapped for writing, as of when it was taken.
pub struct Writers {
    files: HashSet<FileId>,
    /// When the scan began, so it reflects nothing older than this.
    taken: Instant,
}

impl Writers {
    /// Descriptors and mappings of every process this one may inspect.
    pub fn scan() -> Writers {
        let taken = Instant::now();
        let mut files = Self::scan_fds().files;
        files.extend(Self::scan_mappings().files);
        Writers { files, taken }
    }

    /// Adds every process's writers with `add`, which gives up on a process
    /// at its deadline. A process that does is recorded in `slow` and
    /// skipped until its entry expires.
    fn scan_with(add: AddWriters, slow: &Mutex<SlowProcesses>) -> Writers {
        let taken = Instant::now();
        let mut skip = slow.lock().unwrap_or_else(|e| e.into_inner()).clone();
        skip.retain(|_, until| *until > taken);
        let mut files = HashSet::new();
        let pids: Vec<_> = all_pids().into_iter().filter(|p| *p != 0 && !skip.contains_key(p)).collect();
        for pid in pids {
            if !add(pid, &mut files, Instant::now() + PROCESS_BUDGET) {
                skip.insert(pid, Instant::now() + SLOW_PROCESS_SKIP);
            }
        }
        *slow.lock().unwrap_or_else(|e| e.into_inner()) = skip;
        Writers { files, taken }
    }

    fn scan_fds() -> Writers {
        Self::scan_with(add_writable_fds, &SLOW_FDS)
    }

    fn scan_mappings() -> Writers {
        Self::scan_with(add_writable_mappings, &SLOW_MAPPINGS)
    }

    pub fn contains(&self, id: FileId) -> bool {
        self.files.contains(&id)
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// Adds one process's writers; false if it stopped at the deadline.
type AddWriters = fn(libc::c_int, &mut HashSet<FileId>, Instant) -> bool;

/// Processes left out of scans, each until the time given.
type SlowProcesses = HashMap<libc::c_int, Instant>;

static SLOW_FDS: LazyLock<Mutex<SlowProcesses>> = LazyLock::new(Default::default);

fn all_pids() -> Vec<libc::c_int> {
    // Sized from a first call, with room for processes started in between.
    let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if n <= 0 {
        return Vec::new();
    }
    let mut pids = vec![0 as libc::c_int; n as usize + 64];
    let bytes = (pids.len() * size_of::<libc::c_int>()) as libc::c_int;
    let got = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
    pids.truncate(got.max(0) as usize);
    pids
}

fn add_writable_fds(pid: libc::c_int, files: &mut HashSet<FileId>, deadline: Instant) -> bool {
    let size = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if size <= 0 {
        return true;
    }
    let mut fds: Vec<libc::proc_fdinfo> = Vec::with_capacity(size as usize / size_of::<libc::proc_fdinfo>() + 16);
    let bytes = (fds.capacity() * size_of::<libc::proc_fdinfo>()) as libc::c_int;
    let got = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), bytes) };
    if got <= 0 {
        return true;
    }
    unsafe { fds.set_len(got as usize / size_of::<libc::proc_fdinfo>()) };
    for fd in fds.iter().filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_VNODE as u32) {
        if Instant::now() > deadline {
            return false;
        }
        let mut info = std::mem::MaybeUninit::<VnodeFdInfo>::zeroed();
        let n = unsafe {
            libc::proc_pidfdinfo(
                pid,
                fd.proc_fd,
                PROC_PIDFDVNODEINFO,
                info.as_mut_ptr().cast(),
                size_of::<VnodeFdInfo>() as libc::c_int,
            )
        };
        if n as usize != size_of::<VnodeFdInfo>() {
            continue;
        }
        let info = unsafe { info.assume_init() };
        if info.pfi.fi_openflags & FWRITE != 0 {
            files.insert((info.pvi.vi_stat.vst_dev, info.pvi.vi_stat.vst_ino));
        }
    }
    true
}

/// One region at or after `address`, or `None` past the last.
fn region(pid: libc::c_int, flavor: libc::c_int, address: u64) -> Option<RegionWithPathInfo> {
    let mut info = std::mem::MaybeUninit::<RegionWithPathInfo>::zeroed();
    let n = unsafe {
        libc::proc_pidinfo(pid, flavor, address, info.as_mut_ptr().cast(), size_of::<RegionWithPathInfo>() as libc::c_int)
    };
    (n as usize == size_of::<RegionWithPathInfo>()).then(|| unsafe { info.assume_init() })
}

/// The faster region flavor if this kernel has it, checked once against
/// this process, which always maps at least its own executable.
fn region_flavor() -> libc::c_int {
    use std::sync::OnceLock;
    static FLAVOR: OnceLock<libc::c_int> = OnceLock::new();
    *FLAVOR.get_or_init(|| {
        let me = std::process::id() as libc::c_int;
        if region(me, PROC_PIDREGIONPATHINFO2, 0).is_some() { PROC_PIDREGIONPATHINFO2 } else { PROC_PIDREGIONPATHINFO }
    })
}

fn add_writable_mappings(pid: libc::c_int, files: &mut HashSet<FileId>, deadline: Instant) -> bool {
    let flavor = region_flavor();
    let mut address: u64 = 0;
    while let Some(info) = region(pid, flavor, address) {
        if Instant::now() > deadline {
            return false;
        }
        let r = &info.prp_prinfo;
        let st = &info.prp_vip_vi.vi_stat;
        if r.pri_inheritance == VM_INHERIT_SHARE && r.pri_protection & VM_PROT_WRITE != 0 && st.vst_ino != 0 {
            files.insert((st.vst_dev, st.vst_ino));
        }
        let next = r.pri_address.saturating_add(r.pri_size);
        if next <= address {
            return true;
        }
        address = next;
    }
    true
}

static FDS: Mutex<Option<Arc<Writers>>> = Mutex::new(None);
static MAPPINGS: Mutex<Option<Arc<Writers>>> = Mutex::new(None);
static SLOW_MAPPINGS: LazyLock<Mutex<SlowProcesses>> = LazyLock::new(Default::default);

/// The shared snapshot in `slot`, rescanned with `scan` unless it was taken
/// after `since`.
fn cached(slot: &Mutex<Option<Arc<Writers>>>, since: Instant, scan: fn() -> Writers) -> Arc<Writers> {
    let mut shared = slot.lock().unwrap_or_else(|e| e.into_inner());
    match &*shared {
        Some(w) if w.taken >= since => Arc::clone(w),
        _ => {
            let w = Arc::new(scan());
            *shared = Some(Arc::clone(&w));
            w
        }
    }
}

/// Drops the shared snapshots, so the next check scans afresh.
pub fn refresh() {
    for slot in [&FDS, &MAPPINGS] {
        *slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// Whether some process has `path` open or mapped for writing. A writer that
/// opened it within the last `FDS_MAX_AGE` (or mapped it within
/// `MAPPINGS_MAX_AGE`) may be missed; one that has since closed never counts.
/// A file that can't be looked up counts as not open; the caller's own open
/// will fail.
pub fn is_open_for_writing(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(m) => {
            // A hit in a snapshot may be a writer that has finished since, so
            // it is confirmed against one taken after this call began. Hits
            // are rare, so the rescan seldom runs.
            let (id, now) = ((m.dev() as u32, m.ino()), Instant::now());
            let open_in = |slot, max_age, scan| {
                cached(slot, now.checked_sub(max_age).unwrap_or(now), scan).contains(id)
                    && cached(slot, now, scan).contains(id)
            };
            open_in(&FDS, FDS_MAX_AGE, Writers::scan_fds as fn() -> Writers)
                || open_in(&MAPPINGS, MAPPINGS_MAX_AGE, Writers::scan_mappings)
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::os::fd::AsRawFd;

    fn id(path: &Path) -> FileId {
        let m = std::fs::metadata(path).unwrap();
        (m.dev() as u32, m.ino())
    }

    fn map(path: &Path, flags: libc::c_int) -> *mut libc::c_void {
        let f = OpenOptions::new().read(true).write(true).open(path).unwrap();
        let m = unsafe { libc::mmap(std::ptr::null_mut(), 16384, libc::PROT_READ | libc::PROT_WRITE, flags, f.as_raw_fd(), 0) };
        assert_ne!(m, libc::MAP_FAILED);
        m // `f` closes here; the mapping stays.
    }

    #[test]
    fn a_file_open_for_writing_is_found_and_a_read_only_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let (w, r) = (dir.path().join("w"), dir.path().join("r"));
        std::fs::write(&w, b"x").unwrap();
        std::fs::write(&r, b"x").unwrap();
        let _writer = OpenOptions::new().append(true).open(&w).unwrap();
        let _reader = File::open(&r).unwrap();
        let s = Writers::scan();
        assert!(s.contains(id(&w)));
        assert!(!s.contains(id(&r)));
    }

    #[test]
    fn a_shared_writable_mapping_counts_after_its_descriptor_closes_and_a_private_one_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let (shared, private) = (dir.path().join("shared"), dir.path().join("private"));
        std::fs::write(&shared, vec![0u8; 16384]).unwrap();
        std::fs::write(&private, vec![0u8; 16384]).unwrap();
        let s_map = map(&shared, libc::MAP_SHARED);
        let p_map = map(&private, libc::MAP_PRIVATE);
        let s = Writers::scan();
        assert!(s.contains(id(&shared)), "shared mapping missed once its descriptor was closed");
        assert!(!s.contains(id(&private)), "a private mapping never writes back");
        unsafe {
            libc::munmap(s_map, 16384);
            libc::munmap(p_map, 16384);
        }
        assert!(!Writers::scan().contains(id(&shared)));
    }

    #[test]
    fn another_process_holding_a_file_open_for_append_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("child");
        std::fs::write(&p, b"x").unwrap();
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("exec 3>>'{}'; sleep 30", p.display()))
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut seen = false;
        while Instant::now() < deadline && !seen {
            seen = Writers::scan().contains(id(&p));
        }
        let _ = child.kill();
        let _ = child.wait();
        assert!(seen, "another process's writable descriptor was missed");
    }

    #[test]
    fn is_open_for_writing_sees_a_writer_after_a_refresh_and_stops_after_it_closes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"x").unwrap();
        let writer = OpenOptions::new().write(true).open(&p).unwrap();
        refresh();
        assert!(is_open_for_writing(&p));
        drop(writer);
        refresh();
        assert!(!is_open_for_writing(&p));
    }

    #[test]
    fn a_process_over_budget_is_skipped_until_its_entry_expires() {
        fn never_finishes(_: libc::c_int, _: &mut HashSet<FileId>, _: Instant) -> bool {
            false
        }
        let me = std::process::id() as libc::c_int;
        let slow = Mutex::new(SlowProcesses::new());
        Writers::scan_with(never_finishes, &slow);
        assert!(slow.lock().unwrap().contains_key(&me), "an over-budget process wasn't recorded");

        // Skipped while its entry lasts, so its writers go unseen.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w");
        std::fs::write(&p, b"x").unwrap();
        let _writer = OpenOptions::new().append(true).open(&p).unwrap();
        assert!(!Writers::scan_with(add_writable_fds, &slow).contains(id(&p)));

        slow.lock().unwrap().insert(me, Instant::now() - Duration::from_secs(1));
        assert!(Writers::scan_with(add_writable_fds, &slow).contains(id(&p)));
        assert!(!slow.lock().unwrap().contains_key(&me), "an expired entry wasn't dropped");
    }

    #[test]
    fn a_scan_is_fast_enough_to_repeat() {
        let t = Instant::now();
        let s = Writers::scan();
        assert!(!s.is_empty(), "this process's own stdout and stderr are writable files");
        assert!(t.elapsed() < Duration::from_secs(2), "scan took {:?}", t.elapsed());
    }
}
