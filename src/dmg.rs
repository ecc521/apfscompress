//! Disk image plumbing for `apfscompress dmg`: stage an app or an existing
//! image's volume into a scratch folder, and build a new image from it.
//!
//! A file compressed with decmpfs stays compressed inside a UDIF image built
//! by `hdiutil create -srcfolder`, and Finder, `ditto` and `NSFileManager`
//! all keep it compressed when copying it out. So compressing an app before
//! it is imaged means it installs already compressed. `cp -R` and zip
//! archives do not carry the compression.
//!
//! Everything here shells out to `hdiutil`, `ditto`, `diskutil` and
//! `plutil`, which exist on every macOS a developer builds on.

use crate::algo::{self, Algo, OsVersion};
use std::ffi::CStr;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The filesystem inside an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filesystem {
    Hfs,
    Apfs,
}

impl Filesystem {
    /// The name `hdiutil create -fs` takes.
    pub fn hdiutil_name(self) -> &'static str {
        match self {
            Filesystem::Hfs => "HFS+",
            Filesystem::Apfs => "APFS",
        }
    }

    /// The oldest macOS that can mount it.
    pub fn min_os_version(self) -> OsVersion {
        match self {
            Filesystem::Hfs => (10, 0),
            Filesystem::Apfs => (10, 13),
        }
    }
}

/// Volume-level bookkeeping that should not be carried into a new image:
/// each mount recreates what it needs.
const VOLUME_METADATA: [&str; 5] = [".fseventsd", ".Trashes", ".Spotlight-V100", ".TemporaryItems", ".DocumentRevisions-V100"];

/// Runs `program` and returns its stdout, or an error carrying its stderr.
fn run(program: &str, args: &[&std::ffi::OsStr]) -> io::Result<String> {
    let out = Command::new(program).args(args).output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // hdiutil prefixes deprecation notices to otherwise useful errors.
        let msg: Vec<&str> = stderr.lines().filter(|l| !l.contains("is deprecated")).collect();
        return Err(io::Error::other(format!("{program} failed: {}", msg.join(" ").trim())));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A mounted image, detached when dropped.
pub struct Mounted {
    point: PathBuf,
    attached: bool,
}

impl Mounted {
    /// Attaches `image` read-only at `point`, which is created if missing.
    /// Not shown in Finder, and no auto-open.
    pub fn attach(image: &Path, point: &Path) -> io::Result<Mounted> {
        fs::create_dir_all(point)?;
        run(
            "hdiutil",
            &[
                "attach".as_ref(),
                "-nobrowse".as_ref(),
                "-readonly".as_ref(),
                "-noverify".as_ref(),
                "-noautoopen".as_ref(),
                "-mountpoint".as_ref(),
                point.as_os_str(),
                image.as_os_str(),
            ],
        )?;
        Ok(Mounted { point: point.to_path_buf(), attached: true })
    }

    pub fn path(&self) -> &Path {
        &self.point
    }

    pub fn detach(mut self) -> io::Result<()> {
        self.attached = false;
        run("hdiutil", &["detach".as_ref(), "-quiet".as_ref(), self.point.as_os_str()]).map(|_| ())
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        if self.attached {
            let _ = run("hdiutil", &["detach".as_ref(), "-force".as_ref(), "-quiet".as_ref(), self.point.as_os_str()]);
        }
    }
}

/// The UDIF format of `image`, such as `UDZO` or `ULFO`.
pub fn image_format(image: &Path) -> io::Result<String> {
    let info = run("hdiutil", &["imageinfo".as_ref(), image.as_os_str()])?;
    info.lines()
        .find_map(|l| l.strip_prefix("Format: "))
        .map(|f| f.trim().to_string())
        .ok_or_else(|| io::Error::other(format!("hdiutil imageinfo reported no format for {}", image.display())))
}

/// The name of the volume mounted at `point`.
pub fn volume_name(point: &Path) -> io::Result<String> {
    let info = run("diskutil", &["info".as_ref(), point.as_os_str()])?;
    info.lines()
        .find_map(|l| l.trim_start().strip_prefix("Volume Name:"))
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .ok_or_else(|| io::Error::other(format!("diskutil reported no volume name for {}", point.display())))
}

/// The filesystem mounted at `point`.
pub fn filesystem(point: &Path) -> io::Result<Filesystem> {
    let c = std::ffi::CString::new(point.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let name = unsafe { CStr::from_ptr(st.f_fstypename.as_ptr()) }.to_string_lossy();
    match name.as_ref() {
        "hfs" => Ok(Filesystem::Hfs),
        "apfs" => Ok(Filesystem::Apfs),
        other => Err(io::Error::other(format!("unsupported filesystem {other:?} in the image"))),
    }
}

/// Copies `src` to `dst` with `ditto`, which keeps symlinks, extended
/// attributes, ACLs and existing compression. `dst` must not exist; for a
/// directory, its contents land directly in `dst`.
pub fn ditto(src: &Path, dst: &Path) -> io::Result<()> {
    run("ditto", &[src.as_os_str(), dst.as_os_str()]).map(|_| ())
}

/// Copies the volume mounted at `point` into `dst`, minus volume-level
/// bookkeeping that the new image will create for itself.
pub fn copy_volume(point: &Path, dst: &Path) -> io::Result<()> {
    ditto(point, dst)?;
    for name in VOLUME_METADATA {
        let p = dst.join(name);
        if p.exists() {
            fs::remove_dir_all(&p).or_else(|_| fs::remove_file(&p))?;
        }
    }
    Ok(())
}

/// Builds an image of `format` from the contents of `src`, using `work` (an
/// empty scratch folder) for the intermediate image.
///
/// `hdiutil create -srcfolder` leaves out the volume root's `.DS_Store`,
/// which holds the Finder window layout, and the root's Finder info, which
/// carries the custom volume icon flag. So the image is built writable first,
/// those are put back, and it is converted to `format` at the end.
pub fn create(src: &Path, out: &Path, volume_name: &str, fs: Filesystem, format: &str, work: &Path) -> io::Result<()> {
    let rw = work.join("rw.dmg");
    run(
        "hdiutil",
        &[
            "create".as_ref(),
            "-quiet".as_ref(),
            "-srcfolder".as_ref(),
            src.as_os_str(),
            "-volname".as_ref(),
            volume_name.as_ref(),
            "-fs".as_ref(),
            fs.hdiutil_name().as_ref(),
            "-format".as_ref(),
            "UDRW".as_ref(),
            rw.as_os_str(),
        ],
    )?;

    let point = work.join("rw");
    fs::create_dir_all(&point)?;
    run(
        "hdiutil",
        &[
            "attach".as_ref(),
            "-nobrowse".as_ref(),
            "-noverify".as_ref(),
            "-noautoopen".as_ref(),
            "-mountpoint".as_ref(),
            point.as_os_str(),
            rw.as_os_str(),
        ],
    )?;
    let mounted = Mounted { point: point.clone(), attached: true };
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let dst = point.join(entry.file_name());
        if fs::symlink_metadata(&dst).is_err() {
            ditto(&entry.path(), &dst)?;
        }
    }
    if let Ok(info) = run("xattr", &["-px".as_ref(), "com.apple.FinderInfo".as_ref(), src.as_os_str()]) {
        let hex: String = info.split_whitespace().collect();
        run("xattr", &["-wx".as_ref(), "com.apple.FinderInfo".as_ref(), hex.as_ref(), point.as_os_str()])?;
    }
    let events = point.join(".fseventsd");
    if events.exists() {
        fs::remove_dir_all(&events)?;
    }
    mounted.detach()?;

    run(
        "hdiutil",
        &[
            "convert".as_ref(),
            "-quiet".as_ref(),
            "-ov".as_ref(),
            rw.as_os_str(),
            "-format".as_ref(),
            format.as_ref(),
            "-o".as_ref(),
            out.as_os_str(),
        ],
    )?;
    fs::remove_file(&rw)
}

/// Every `.app` bundle under `root`, not descending into bundles.
pub fn app_bundles(root: &Path) -> Vec<PathBuf> {
    let mut apps = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if !ft.is_dir() {
                continue;
            }
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "app") {
                apps.push(path);
            } else {
                stack.push(path);
            }
        }
    }
    apps.sort();
    apps
}

/// The app's `LSMinimumSystemVersion`, if it declares one.
pub fn app_min_os_version(app: &Path) -> Option<OsVersion> {
    let plist = app.join("Contents/Info.plist");
    let out = run(
        "plutil",
        &["-extract".as_ref(), "LSMinimumSystemVersion".as_ref(), "raw".as_ref(), "-o".as_ref(), "-".as_ref(), plist.as_os_str()],
    )
    .ok()?;
    algo::parse_os_version(out.trim())
}

/// Keeps only the members of `algos` that `target` can decode.
pub fn readable_on(algos: &[Algo], target: OsVersion) -> Vec<Algo> {
    algos.iter().copied().filter(|&a| algo::min_os_version(a) <= target).collect()
}

/// On-disk bytes of every regular file under `root`, counting a hard-linked
/// file once.
pub fn footprint(root: &Path) -> io::Result<u64> {
    let mut seen = std::collections::HashSet::new();
    let mut total = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let meta = fs::symlink_metadata(entry.path())?;
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() && seen.insert((meta.dev(), meta.ino())) {
                total += meta.blocks() * 512;
            }
        }
    }
    Ok(total)
}

/// How an image's contents compare with the tree it was built from.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Comparison {
    pub files: u64,
    /// Files compressed in the source tree.
    pub compressed: u64,
    /// Of those, how many are still compressed in the image.
    pub still_compressed: u64,
    /// Relative paths missing from the image or with different contents.
    pub mismatched: Vec<PathBuf>,
}

/// Compares every regular file under `source` with its counterpart under
/// `image`, byte for byte, and checks that compressed files stayed so.
pub fn compare(source: &Path, image: &Path) -> io::Result<Comparison> {
    let mut c = Comparison::default();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        for entry in fs::read_dir(source.join(&rel))? {
            let entry = entry?;
            let rel = rel.join(entry.file_name());
            let meta = fs::symlink_metadata(entry.path())?;
            if meta.is_dir() {
                stack.push(rel);
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            c.files += 1;
            let is_compressed = |m: &fs::Metadata| {
                use std::os::macos::fs::MetadataExt as _;
                m.st_flags() & crate::sys::UF_COMPRESSED != 0
            };
            let theirs = image.join(&rel);
            let same = match fs::symlink_metadata(&theirs) {
                Ok(m) if m.is_file() && m.len() == meta.len() => {
                    if is_compressed(&meta) {
                        c.compressed += 1;
                        if is_compressed(&m) {
                            c.still_compressed += 1;
                        }
                    }
                    fs::read(entry.path())? == fs::read(&theirs)?
                }
                _ => false,
            };
            if !same {
                c.mismatched.push(rel);
            }
        }
    }
    c.mismatched.sort();
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readable_on_drops_formats_the_target_cannot_decode() {
        let race = [Algo::CrushLzbitmap(6), Algo::CrushLzfse(10), Algo::CrushLz4(6)];
        assert_eq!(readable_on(&race, (11, 0)), vec![Algo::CrushLzfse(10)]);
        assert_eq!(readable_on(&race, (12, 0)), vec![Algo::CrushLzbitmap(6), Algo::CrushLzfse(10)]);
        assert_eq!(readable_on(&race, (27, 0)), race.to_vec());
        assert!(readable_on(&race, (10, 10)).is_empty());
    }

    #[test]
    fn app_bundles_finds_apps_without_entering_them() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("A.app/Contents/Frameworks/Helper.app")).unwrap();
        fs::create_dir_all(dir.path().join("sub/B.app/Contents")).unwrap();
        fs::create_dir_all(dir.path().join(".background")).unwrap();
        let found: Vec<_> = app_bundles(dir.path()).iter().map(|p| p.strip_prefix(dir.path()).unwrap().to_path_buf()).collect();
        assert_eq!(found, vec![PathBuf::from("A.app"), PathBuf::from("sub/B.app")]);
    }
}
