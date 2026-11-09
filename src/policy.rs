//! Config defaults, skip rules, and the reject-decision predicates.

use crate::algo::Algo;
use crate::decmpfs;
use crate::sys::UF_COMPRESSED;
use std::fs;
use std::io;
use std::os::macos::fs::MetadataExt as MacMetadataExt;
use std::os::unix::fs::MetadataExt as UnixMetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Whether to reconsider a file that's already `UF_COMPRESSED`. The OS only
/// ever writes LZVN or stored, never LZFSE, so `Never` leaves a lot of
/// already-compressed content permanently unconsidered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecompressPolicy {
    /// Default: an already-compressed file is always skipped, regardless of
    /// its algorithm.
    Never,
    /// Cheap gate: read just the decmpfs header (one `getxattr`) and skip if
    /// the current algorithm is already among the race candidates. A coarse
    /// heuristic - it doesn't know which candidate would actually win, only
    /// that the current one is viable.
    IfDifferentAlgo,
    /// Always reconsider. The shrink check then compares against the file's
    /// current compressed footprint, not its logical size - see
    /// `current_compressed_footprint` and `engine::compress_bytes_against`.
    Always,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Accept only if the compressed result is at most this fraction of the
    /// basis size. 1.0 accepts anything that doesn't grow; 0.8 requires at
    /// least 20% savings; a value above 1.0 permits growth.
    pub max_ratio: f64,
    /// Bytes of the file compressed up front per candidate; selects the race
    /// winner and gates go/no-go before the rest of the file compresses.
    /// Caps the memory a rejected large file can cost - see
    /// `engine::compress_chunked`.
    pub probe_size: u64,
    /// Candidate encoders raced on each file. See [`Algorithms`], and
    /// [`Config::for_race_level`] for the usual way to pick them.
    pub algorithms: Algorithms,
    /// Read the staged file back through the kernel (a plain `read()`, the
    /// same path any other process takes) and require a byte-for-byte match
    /// with the original before promoting it.
    ///
    /// **Defaults to `true`.** The encoders are already fuzzed against
    /// Apple's decoders in crush-lz, so this turns near-certainty into
    /// certainty for each file actually written, and also catches a kernel
    /// too old for a format. Decoding is far faster than encoding at the
    /// denser levels, so that certainty is cheap: well under the cost of the
    /// encode except on the fastest encoders.
    pub paranoid: bool,
    pub skip_extensions: Vec<String>,
    /// `None` uses the volume's real block size (`st_blksize`; 4096 on APFS
    /// here). Below one block, compression usually can't reduce disk usage:
    /// APFS only skips a dedicated extent when the whole decmpfs xattr fits
    /// inline in its own on-disk record (~130 bytes here, under decmpfs's
    /// ~3.8KB inline cap). `Some(n)` overrides with an explicit floor.
    pub min_file_size: Option<u64>,
    /// Files above this size are skipped before any work is attempted (no
    /// clone, read, or compression). A flat safety ceiling, not tuned to the
    /// resource-fork format's own 4GiB limit (see `engine::checked_offset`),
    /// which still applies regardless of this setting.
    pub max_file_size: u64,
    pub recompress: RecompressPolicy,
    /// Evaluate and report what would happen - algorithm chosen, resulting
    /// size - without staging, writing, or touching the file at all.
    pub dry_run: bool,
    /// `None` (default): no age gate. `Some(d)`: skip files modified within
    /// `d` of now. A file rewritten after compression is transparently
    /// decompressed by the kernel until the next run recompresses it, so
    /// compressing one still being edited just wastes work. Useful on a
    /// recurring run over a mix of active and settled content.
    pub min_age: Option<Duration>,
    /// Skip a file that any process this one can inspect has open or mapped
    /// for writing (see `openfiles`). On by default: such a writer would
    /// otherwise lose everything it writes after the swap.
    pub skip_open_for_writing: bool,
    /// Leave a file alone when APFS clones share its blocks and compressing
    /// it would free less than it writes (see
    /// [`SkipReason::SharedWithClones`]). On by default. Turn it off when
    /// the compressed files themselves are the goal rather than the space,
    /// as `dmg` does for the clones `ditto` makes of an app.
    pub skip_clones: bool,
}

/// Flat default for `Config::max_file_size` - see that field's doc comment
/// for why this doesn't need to be precisely tuned to the resource-fork
/// format's real ceiling.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024;

impl Default for Config {
    fn default() -> Self {
        Config {
            max_ratio: 1.0,
            probe_size: 5 * 1024 * 1024,
            algorithms: Algorithms::race_level(DEFAULT_RACE_LEVEL).expect("default level is in range"),
            paranoid: true,
            skip_extensions: default_skip_extensions(),
            min_file_size: None,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            recompress: RecompressPolicy::Never,
            dry_run: false,
            min_age: None,
            skip_open_for_writing: true,
            skip_clones: true,
        }
    }
}

impl Config {
    /// `Config::default()` racing the curated combo for `level` (see
    /// [`race_profile`]). `None` outside `RACE_PROFILE_MIN..=RACE_PROFILE_MAX`.
    pub fn for_race_level(level: u8) -> Option<Self> {
        Config::default().with_race_level(level)
    }

    /// This config, racing the curated combo for `level` instead.
    pub fn with_race_level(self, level: u8) -> Option<Self> {
        Some(self.with_algorithms(Algorithms::race_level(level)?))
    }

    pub fn with_algorithms(self, algorithms: Algorithms) -> Self {
        Config { algorithms, ..self }
    }
}

/// The encoders raced on each file: every member compresses the probe
/// window, and the smallest result compresses the rest (see
/// `engine::compress_bytes_against`). Never empty; a single member means no
/// race.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Algorithms {
    algos: Vec<Algo>,
    level: Option<u8>,
}

impl Algorithms {
    /// The curated combo for `level` - see [`race_profile`]. `None` outside
    /// `RACE_PROFILE_MIN..=RACE_PROFILE_MAX`.
    pub fn race_level(level: u8) -> Option<Self> {
        Some(Algorithms { algos: race_profile(level)?, level: Some(level) })
    }

    /// A hand-picked race. `None` if `algos` is empty. On an exact tie the
    /// earlier member wins, so list faster-decoding formats first.
    pub fn custom(algos: Vec<Algo>) -> Option<Self> {
        (!algos.is_empty()).then_some(Algorithms { algos, level: None })
    }

    /// Just `algo`, no race.
    pub fn single(algo: Algo) -> Self {
        Algorithms { algos: vec![algo], level: None }
    }

    pub fn as_slice(&self) -> &[Algo] {
        &self.algos
    }

    /// The race level these came from, or `None` for a custom set.
    pub fn level(&self) -> Option<u8> {
        self.level
    }
}

/// Lowest/highest accepted level for [`race_profile`].
pub const RACE_PROFILE_MIN: u8 = 0;
pub const RACE_PROFILE_MAX: u8 = 10;

/// A curated race combo, `0` (fastest/cheapest) to `10` (slowest/densest) -
/// an alternative to hand-listing algorithms via `--algo` for anyone who
/// just wants a point on the measured speed/ratio curve without learning
/// the full candidate space. `None` outside `RACE_PROFILE_MIN..=RACE_PROFILE_MAX`.
///
/// Each level is a point on the measured Pareto frontier of every race over
/// the lzbitmap, lzfse and zlib families (each Apple encoder plus every
/// crush-lz or libdeflate level), picked log-spaced by encode throughput and
/// with any member dropped whose absence costs under 0.0005 of ratio. A race
/// costs the sum of its members' encode time, so single algorithms hold the
/// fast end. LZ4 is left out: it needs macOS 27.0 and, measured, wins
/// essentially nothing in a race that already has lzbitmap.
///
/// Members are listed fastest-decoding format first, so an exact tie lands
/// in the faster format.
///
/// Derived 2026-11-08 on crush-lz's standard corpus (`corpus/segments/main`,
/// 500 MiB) on an Apple M5 Max, with `bench/`'s `race_frontier`, from median
/// encode times over four sweeps of every family. It is a snapshot, not a
/// promise: re-run that after any crush-lz change.
pub fn race_profile(level: u8) -> Option<Vec<Algo>> {
    use crate::algo::Algo::{CrushLzbitmap, CrushLzfse, Zlib};
    Some(match level {
        0 => vec![CrushLzfse(-2)],
        1 => vec![CrushLzfse(-1)],
        2 => vec![Zlib(6)],
        3 => vec![CrushLzbitmap(0), CrushLzfse(5)],
        4 => vec![CrushLzbitmap(1), CrushLzfse(5), Zlib(6)],
        5 => vec![CrushLzbitmap(5), CrushLzfse(5), Zlib(8)],
        6 => vec![CrushLzbitmap(3), CrushLzfse(6), Zlib(7)],
        7 => vec![CrushLzbitmap(1), CrushLzfse(8)],
        8 => vec![CrushLzbitmap(5), CrushLzfse(9)],
        9 => vec![CrushLzbitmap(9), CrushLzfse(10)],
        10 => vec![CrushLzbitmap(8), CrushLzfse(11)],
        _ => return None,
    })
}

/// The race level `Config::default()` uses, and so what `compress` and
/// `estimate` run without `--algo` or `--race-level`. Measured at 0.2620
/// against Apple LZFSE's 0.2942, at a similar cost to a single deep
/// crushlzfse level, and with no zlib member it decodes at LZFSE speed.
pub const DEFAULT_RACE_LEVEL: u8 = 9;

/// Empty: no extension is skipped by default. Formats that look
/// already-compressed (zip, jpg, mp4, dmg, etc.) were measured on real
/// files and still had real slack: `.dmg` averaged 32.8% smaller, and codec formats like
/// mp3/webp/png had a few percent left in container bytes. Not needed as a
/// safety net either: `max_ratio` rejects any growing result, and
/// `probe_size` bounds the cost of finding that out.
fn default_skip_extensions() -> Vec<String> {
    Vec::new()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkipReason {
    Symlink,
    AlreadyCompressed,
    /// `rename()` can repoint only one link, so the others would keep the
    /// uncompressed original.
    HardLinked,
    AlreadySparse,
    ExtensionExcluded,
    TooSmall,
    TooLarge,
    /// Files above the inline payload cap go through the chunked write path
    /// (`engine::compress_bytes_against`), which unconditionally truncates
    /// `com.apple.ResourceFork` - destroying any genuine resource-fork
    /// content (e.g. a custom Finder icon). Skipped to avoid silent
    /// content loss.
    HasResourceFork,
    /// `clonefile(2)` unconditionally strips setuid/setgid (see
    /// `fsops::clone_file`), so the clone+rename swap can never carry
    /// either bit over. Skipped rather than silently promoting a file with
    /// weaker permissions.
    SetuidOrSetgid,
    /// Modified more recently than `Config::min_age` allows. Off by default -
    /// see that field's doc comment for the reasoning.
    RecentlyModified,
    /// Changed (content, xattrs, mode or flags) or replaced while it was
    /// being compressed. Left as the other writer made it; a later run can
    /// try again.
    ChangedDuringCompression,
    /// Its group can't be carried to a staged copy: no staging directory
    /// gives new files that group, and the caller isn't a member of it.
    GroupNotRestorable,
    /// Some process has it open or mapped for writing, and would go on
    /// writing to the old copy after the swap. See `openfiles`.
    OpenForWriting,
    /// Shares its blocks with APFS clones (Finder's Duplicate, `cp -c`,
    /// `ditto`, pnpm's store), so compressing it would free too little: the
    /// shared blocks stay allocated for the clones, and the compressed copy
    /// is new data. Compressing frees only the file's private bytes (see
    /// [`block_sharing`]), so a result must fit `max_ratio` of those, not of
    /// the file's size. An exact clone frees nothing and is skipped up front
    /// by `should_skip`; a partly shared one is judged once its compressed
    /// size is known. Off with `Config::skip_clones`.
    SharedWithClones,
}

/// How much of a file's storage it shares with APFS clones, and so how much
/// compressing it can free. See [`block_sharing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockSharing {
    /// Shares nothing, or the volume can't tell (not APFS): compressing frees
    /// everything the file allocates.
    Unshared,
    /// Shares some blocks with clones; only `private_bytes` of its data fork
    /// are its own.
    Partial { private_bytes: u64 },
    /// Every block is shared (an exact clone): compressing frees nothing.
    All,
}

impl BlockSharing {
    /// The most that compressing the file can free, given the bytes it
    /// allocates now (`st_blocks * 512`).
    pub fn releasable(self, allocated: u64) -> u64 {
        match self {
            BlockSharing::Unshared => allocated,
            BlockSharing::Partial { private_bytes } => private_bytes.min(allocated),
            BlockSharing::All => 0,
        }
    }

    /// `basis` (the size a compressed result is measured against: the
    /// logical size, or the current compressed footprint when recompressing)
    /// capped at the bytes compressing would free. `target_size` of this is
    /// the largest result worth writing, which is how the engine judges
    /// [`SkipReason::SharedWithClones`].
    pub fn cap_basis(self, basis: u64) -> u64 {
        match self {
            BlockSharing::Unshared => basis,
            BlockSharing::Partial { private_bytes } => basis.min(private_bytes),
            BlockSharing::All => 0,
        }
    }
}

/// How much of the file at `path` is shared with APFS clones. Measured,
/// compressing a file frees exactly its private bytes and writes its
/// compressed size, so the net saving is the difference; see
/// [`BlockSharing::cap_basis`].
///
/// One cheap `getattrlist` for `EF_SHARES_ALL_BLOCKS`/`EF_MAY_SHARE_BLOCKS`
/// (see `fsops::ext_flags`), plus `fsops::private_size` only for an
/// uncompressed file that may share some blocks. A compressed file is `All`
/// or `Unshared`, never `Partial`: APFS doesn't count its resource fork as
/// private, and the fork can't be partly shared, since writing to a
/// compressed file decompresses it. Snapshots are not considered.
pub fn block_sharing(path: &Path) -> io::Result<BlockSharing> {
    let Some(flags) = crate::fsops::ext_flags(path)? else {
        return Ok(BlockSharing::Unshared);
    };
    if flags & crate::sys::EF_SHARES_ALL_BLOCKS != 0 {
        return Ok(BlockSharing::All);
    }
    if flags & crate::sys::EF_MAY_SHARE_BLOCKS == 0 {
        return Ok(BlockSharing::Unshared);
    }
    let meta = fs::symlink_metadata(path)?;
    if meta.st_flags() & UF_COMPRESSED != 0 {
        return Ok(BlockSharing::Unshared);
    }
    Ok(match crate::fsops::private_size(path)? {
        Some(0) => BlockSharing::All,
        Some(p) if p < meta.blocks() * 512 => BlockSharing::Partial { private_bytes: p },
        _ => BlockSharing::Unshared,
    })
}

/// Checks the cheap, metadata-only skip rules. Not quite free of content
/// reads: `RecompressPolicy::IfDifferentAlgo` reads the decmpfs xattr
/// header (16 bytes, one `getxattr`) for an already-compressed file, still
/// far cheaper than fully re-evaluating the content.
pub fn should_skip(path: &Path, cfg: &Config) -> io::Result<Option<SkipReason>> {
    let meta = fs::symlink_metadata(path)?;

    if meta.file_type().is_symlink() {
        return Ok(Some(SkipReason::Symlink));
    }

    let already_compressed = (meta.st_flags() & UF_COMPRESSED) != 0;

    if already_compressed {
        match cfg.recompress {
            RecompressPolicy::Never => return Ok(Some(SkipReason::AlreadyCompressed)),
            RecompressPolicy::Always => {} // always worth reconsidering
            RecompressPolicy::IfDifferentAlgo => {
                if current_algo_already_optimal(path, cfg)? {
                    return Ok(Some(SkipReason::AlreadyCompressed));
                }
            }
        }
    }

    if meta.nlink() > 1 {
        return Ok(Some(SkipReason::HardLinked));
    }

    // 0o4000 = S_ISUID, 0o2000 = S_ISGID. Independent of size or
    // compressibility (see `SkipReason::SetuidOrSetgid`).
    if meta.mode() & 0o6000 != 0 {
        return Ok(Some(SkipReason::SetuidOrSetgid));
    }

    let logical_size = meta.len();
    let disk_usage = meta.blocks() * 512;
    // Skipped when already-compressed: its disk_usage < logical_size by
    // construction isn't evidence of an intentionally sparse original, and
    // applying this check here would make Always/IfDifferentAlgo unreachable.
    if !already_compressed && disk_usage < logical_size {
        // Sparse (or otherwise using less disk than its logical size
        // implies); compressing further risks disturbing an intentional
        // layout (e.g. a sparse disk image).
        return Ok(Some(SkipReason::AlreadySparse));
    }

    // Only the chunked write path can clobber a resource fork (see
    // `SkipReason::HasResourceFork`); size alone decides that path. Skipped
    // for an already-compressed file being reconsidered: its resource fork
    // is our own prior data, not foreign content.
    if !already_compressed
        && logical_size > decmpfs::MAX_INLINE_PAYLOAD as u64
        && crate::fsops::get_xattr(path, "com.apple.ResourceFork").is_ok_and(|v| !v.is_empty())
    {
        return Ok(Some(SkipReason::HasResourceFork));
    }

    let min_size = cfg.min_file_size.unwrap_or_else(|| meta.blksize());
    if logical_size < min_size {
        return Ok(Some(SkipReason::TooSmall));
    }

    if logical_size > cfg.max_file_size {
        return Ok(Some(SkipReason::TooLarge));
    }

    if let Some(min_age) = cfg.min_age {
        let modified = meta.modified()?;
        // A future mtime (clock skew or set forward) is treated as "just
        // modified": duration_since's Err collapses to zero age, the
        // conservative read.
        let age = SystemTime::now().duration_since(modified).unwrap_or(Duration::ZERO);
        if age < min_age {
            return Ok(Some(SkipReason::RecentlyModified));
        }
    }

    if let Some(ext) = path.extension().and_then(|e| e.to_str())
        && cfg.skip_extensions.iter().any(|s| s.eq_ignore_ascii_case(ext)) {
            return Ok(Some(SkipReason::ExtensionExcluded));
        }

    // One cheap getattrlist; a partly shared file is judged by the engine
    // once its compressed size is known.
    if cfg.skip_clones
        && crate::fsops::ext_flags(path)?.is_some_and(|f| f & crate::sys::EF_SHARES_ALL_BLOCKS != 0)
    {
        return Ok(Some(SkipReason::SharedWithClones));
    }

    // Last: the only check that may scan other processes.
    if cfg.skip_open_for_writing && crate::openfiles::is_open_for_writing(path) {
        return Ok(Some(SkipReason::OpenForWriting));
    }
    Ok(None)
}

/// Reads just the decmpfs header (no decompression) to check whether the
/// current algorithm is already among the race candidates - if so,
/// `IfDifferentAlgo` has nothing to gain by re-evaluating. Errs toward
/// re-evaluating (`false`) on an unreadable/unparsable header: a stale skip
/// is worse than a wasted evaluation.
fn current_algo_already_optimal(path: &Path, cfg: &Config) -> io::Result<bool> {
    let Ok(xattr) = crate::fsops::get_xattr(path, "com.apple.decmpfs") else {
        return Ok(false);
    };
    let Some(header) = decmpfs::Header::from_bytes(&xattr) else {
        return Ok(false);
    };
    let Some(current_algo) = decmpfs::algo_for_type(header.compression_type) else {
        return Ok(false);
    };
    let candidates = cfg.algorithms.as_slice();
    // Compared by algorithm family, not full equality: algo_for_type
    // recovers Zlib at a nominal level (0), so a direct `==` against e.g.
    // Zlib(9) would spuriously say "not optimal" for every zlib file.
    Ok(candidates.iter().any(|&c| same_algo_family(c, current_algo)))
}

/// Whether two algorithms produce the same decmpfs on-disk type, and so are
/// indistinguishable once written.
///
/// Keyed on the type, not an enumerated list of pairs: every format here
/// has multiple encoders behind it (Lzfse/CrushLzfse, Zlib at any level),
/// and `algo_for_type` only recovers the nominal Apple variant, never the
/// encoder or level. Deriving the answer from `xattr_type` handles a new
/// encoder for an existing format automatically.
fn same_algo_family(a: Algo, b: Algo) -> bool {
    decmpfs::xattr_type(a) == decmpfs::xattr_type(b)
}

/// Total on-disk footprint of a file's *current* compressed representation -
/// the decmpfs xattr plus the resource fork if present. Used as the
/// shrink-check basis when recompressing; see `engine::compress_bytes_against`
/// for why this, not the logical size, is the right basis.
pub fn current_compressed_footprint(path: &Path) -> io::Result<u64> {
    let decmpfs_len = crate::fsops::get_xattr(path, "com.apple.decmpfs")?.len() as u64;
    let rsrc_len = crate::fsops::get_xattr(path, "com.apple.ResourceFork")
        .map(|v| v.len() as u64)
        .unwrap_or(0);
    Ok(decmpfs_len + rsrc_len)
}

/// Max allowed compressed size for a file of `original_size` bytes at
/// `max_ratio`. At ratio 1.0 this is exactly `original_size` - a same-size
/// result passes, only a strictly larger one is rejected.
pub fn target_size(original_size: u64, max_ratio: f64) -> u64 {
    let t = (original_size as f64) * max_ratio;
    t.max(0.0) as u64
}

/// Boundary reject check: is the real total, once a window (probe window
/// or remainder) finishes compressing, over that window's `target`? A
/// heuristic, not provably safe - a chunk beyond this window could in
/// theory redeem a bad start, which is what `probe_size` tunes. A cheaper
/// mid-dispatch bail-out is possible but not implemented; see
/// `ROADMAP.md`'s "Boundary Early-Resolve" entry.
pub fn cumulative_exceeds_target(compressed_so_far: u64, target: u64) -> bool {
    compressed_so_far > target
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn symlink_is_skipped() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("real.txt");
        let link = dir.path().join("link.txt");
        fs::write(&target, b"hello world, long enough to pass size floor").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let reason = should_skip(&link, &Config::default()).unwrap();
        assert_eq!(reason, Some(SkipReason::Symlink));
    }

    #[test]
    fn hardlinked_file_is_skipped() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        fs::write(&a, b"hello world, long enough to pass size floor").unwrap();
        fs::hard_link(&a, &b).unwrap();

        let reason = should_skip(&a, &Config::default()).unwrap();
        assert_eq!(reason, Some(SkipReason::HardLinked));
    }

    #[test]
    fn tiny_file_is_skipped() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tiny.txt");
        fs::write(&path, b"short").unwrap();
        let reason = should_skip(&path, &Config::default()).unwrap();
        assert_eq!(reason, Some(SkipReason::TooSmall));
    }

    #[test]
    fn no_extension_is_skipped_by_default() {
        // default_skip_extensions() is empty; see its doc comment for why.
        let dir = tempdir().unwrap();
        let path = dir.path().join("photo.jpg");
        fs::write(&path, vec![0u8; 5000]).unwrap();
        let reason = should_skip(&path, &Config::default()).unwrap();
        assert_eq!(reason, None);
    }

    #[test]
    fn excluded_extension_is_skipped_when_configured() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("photo.jpg");
        // Above the block-size floor (default min_file_size tracks
        // st_blksize) so this exercises the extension check, not TooSmall.
        fs::write(&path, vec![0u8; 5000]).unwrap();
        let cfg = Config { skip_extensions: vec!["jpg".to_string()], ..Config::default() };
        let reason = should_skip(&path, &cfg).unwrap();
        assert_eq!(reason, Some(SkipReason::ExtensionExcluded));
    }

    #[test]
    fn ordinary_file_is_not_skipped() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.bin");
        fs::write(&path, vec![b'a'; 5000]).unwrap();
        let reason = should_skip(&path, &Config::default()).unwrap();
        assert_eq!(reason, None);
    }

    /// Regression test: `clonefile(2)` strips setuid/setgid unconditionally
    /// (see `SkipReason::SetuidOrSetgid`), so such files must be skipped,
    /// not silently promoted with weaker permissions.
    #[test]
    fn setuid_and_setgid_files_are_skipped() {
        let dir = tempdir().unwrap();
        for (name, mode) in [("suid.bin", 0o4644u32), ("sgid.bin", 0o2644u32)] {
            let path = dir.path().join(name);
            fs::write(&path, vec![b'a'; 5000]).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                fs::metadata(&path).unwrap().mode() & 0o6000,
                mode & 0o6000,
                "test setup: setuid/setgid bit didn't actually take on this filesystem"
            );

            let reason = should_skip(&path, &Config::default()).unwrap();
            assert_eq!(reason, Some(SkipReason::SetuidOrSetgid), "{name} should be skipped");
        }
    }

    /// Regression test: a file above the inline cap goes through the
    /// chunked write path, which unconditionally truncates
    /// `com.apple.ResourceFork` (see `engine::write_resource_fork_streaming`),
    /// so genuine resource-fork content (e.g. a Finder icon) must be
    /// skipped, not silently lost.
    #[test]
    fn file_with_existing_resource_fork_is_skipped() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("has_icon.bin");
        fs::write(&path, vec![b'a'; 5000]).unwrap(); // above MAX_INLINE_PAYLOAD
        crate::fsops::set_xattr(&path, "com.apple.ResourceFork", b"PRETEND_ICON_RESOURCE_DATA").unwrap();

        let reason = should_skip(&path, &Config::default()).unwrap();
        assert_eq!(reason, Some(SkipReason::HasResourceFork));
    }

    /// A resource fork on an inline-sized file is never at risk (the inline
    /// path never touches `com.apple.ResourceFork`), so it must not be
    /// skipped. `min_file_size` is lowered since the default block size
    /// sits above `MAX_INLINE_PAYLOAD`, which would otherwise reject it as
    /// `TooSmall` first.
    #[test]
    fn small_file_with_resource_fork_is_not_skipped() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("small_icon.bin");
        fs::write(&path, vec![b'a'; 200]).unwrap(); // well under MAX_INLINE_PAYLOAD
        crate::fsops::set_xattr(&path, "com.apple.ResourceFork", b"PRETEND_ICON_RESOURCE_DATA").unwrap();

        let cfg = Config { min_file_size: Some(50), ..Config::default() };
        let reason = should_skip(&path, &cfg).unwrap();
        assert_eq!(reason, None);
    }

    #[test]
    fn sparse_file_is_skipped() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sparse.bin");
        let f = fs::File::create(&path).unwrap();
        // Pure ftruncate-extend (no bytes written) makes a real hole on
        // APFS (st_blocks stays 0); seek+write-one-byte doesn't reliably.
        f.set_len(10 * 1024 * 1024).unwrap();
        drop(f);

        let meta = fs::metadata(&path).unwrap();
        assert!(
            meta.blocks() * 512 < meta.len(),
            "test setup didn't actually produce a sparse file on this filesystem"
        );

        let reason = should_skip(&path, &Config::default()).unwrap();
        assert_eq!(reason, Some(SkipReason::AlreadySparse));
    }

    #[test]
    fn already_compressed_file_is_skipped() {
        // chflags(UF_COMPRESSED) silently doesn't stick without a valid
        // com.apple.decmpfs xattr already present, so this (like the real
        // swap pipeline) must write the xattr before setting the flag.
        let dir = tempdir().unwrap();
        let path = dir.path().join("compressed.bin");
        let data = vec![b'a'; 5000];
        fs::write(&path, &data).unwrap();

        let compressed = crate::algo::compress_chunk(&data, crate::algo::Algo::Lzfse).unwrap();
        let xattr = crate::decmpfs::build_inline(crate::algo::Algo::Lzfse, data.len() as u64, &compressed);
        crate::fsops::set_xattr(&path, "com.apple.decmpfs", &xattr).unwrap();
        fs::File::options().write(true).open(&path).unwrap().set_len(0).unwrap();
        crate::fsops::set_compressed_flag(&path).unwrap();

        let reason = should_skip(&path, &Config::default()).unwrap();
        assert_eq!(reason, Some(SkipReason::AlreadyCompressed));
    }

    /// Writes a real, kernel-valid inline decmpfs xattr for `algo` onto
    /// `path` and sets UF_COMPRESSED - shared setup for the RecompressPolicy
    /// tests below.
    fn make_already_compressed(path: &std::path::Path, data: &[u8], algo: Algo) {
        fs::write(path, data).unwrap();
        let compressed = crate::algo::compress_chunk(data, algo).unwrap();
        let xattr = decmpfs::build_inline(algo, data.len() as u64, &compressed);
        crate::fsops::set_xattr(path, "com.apple.decmpfs", &xattr).unwrap();
        fs::File::options().write(true).open(path).unwrap().set_len(0).unwrap();
        crate::fsops::set_compressed_flag(path).unwrap();
    }

    #[test]
    fn recompress_never_always_skips_already_compressed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        make_already_compressed(&path, &vec![b'a'; 5000], Algo::Lzvn);

        let cfg = Config { recompress: RecompressPolicy::Never, ..Config::default() };
        assert_eq!(should_skip(&path, &cfg).unwrap(), Some(SkipReason::AlreadyCompressed));
    }

    #[test]
    fn recompress_always_never_skips_for_being_already_compressed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        // LZVN is never in the default candidates. This alone wouldn't
        // catch Always behaving like IfDifferentAlgo (see the next test),
        // but confirms Always doesn't skip.
        make_already_compressed(&path, &vec![b'a'; 5000], Algo::Lzvn);

        let cfg = Config { recompress: RecompressPolicy::Always, ..Config::default() };
        assert_eq!(should_skip(&path, &cfg).unwrap(), None);
    }

    #[test]
    fn recompress_if_different_algo_skips_when_already_optimal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        // Already compressed with a candidate algorithm; IfDifferentAlgo
        // should consider this optimal and skip, unlike Always.
        make_already_compressed(&path, &vec![b'a'; 5000], Algo::Lzfse);

        let cfg = Config {
            recompress: RecompressPolicy::IfDifferentAlgo,
            algorithms: Algorithms::custom(vec![Algo::Lzfse]).unwrap(),
            ..Config::default()
        };
        assert_eq!(should_skip(&path, &cfg).unwrap(), Some(SkipReason::AlreadyCompressed));
    }

    #[test]
    fn recompress_if_different_algo_proceeds_when_algo_differs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        // Compressed with LZVN, but candidates only offer LZFSE; worth
        // reconsidering.
        make_already_compressed(&path, &vec![b'a'; 5000], Algo::Lzvn);

        let cfg = Config {
            recompress: RecompressPolicy::IfDifferentAlgo,
            algorithms: Algorithms::custom(vec![Algo::Lzfse]).unwrap(),
            ..Config::default()
        };
        assert_eq!(should_skip(&path, &cfg).unwrap(), None);
    }

    #[test]
    fn recompress_if_different_algo_ignores_zlib_level_mismatch() {
        // Regression: algo_for_type recovers Zlib at nominal level 0
        // (decmpfs doesn't store the level), so full equality against e.g.
        // Zlib(9) would wrongly say "not optimal" for every zlib file.
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        make_already_compressed(&path, &vec![b'a'; 500], Algo::Zlib(3));

        let cfg = Config {
            recompress: RecompressPolicy::IfDifferentAlgo,
            algorithms: Algorithms::custom(vec![Algo::Zlib(9)]).unwrap(),
            ..Config::default()
        };
        assert_eq!(should_skip(&path, &cfg).unwrap(), Some(SkipReason::AlreadyCompressed));
    }

    #[test]
    fn current_compressed_footprint_matches_actual_xattr_sizes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        let data = vec![b'a'; 5000];
        make_already_compressed(&path, &data, Algo::Lzfse);

        let footprint = current_compressed_footprint(&path).unwrap();
        let real_len = crate::fsops::get_xattr(&path, "com.apple.decmpfs").unwrap().len() as u64;
        assert_eq!(footprint, real_len); // inline: no resource fork, so footprint == xattr len alone
    }

    #[test]
    fn min_file_size_override_is_respected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("small.bin");
        fs::write(&path, vec![0u8; 100]).unwrap();

        // Below any real block size, but within an explicit override.
        let cfg = Config { min_file_size: Some(50), ..Config::default() };
        assert_eq!(should_skip(&path, &cfg).unwrap(), None);

        let cfg_strict = Config { min_file_size: Some(1000), ..Config::default() };
        assert_eq!(should_skip(&path, &cfg_strict).unwrap(), Some(SkipReason::TooSmall));
    }

    #[test]
    fn max_file_size_override_is_respected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chunky.bin");
        fs::write(&path, vec![0u8; 5000]).unwrap();

        // A cap smaller than the file must skip it, cheaply (metadata-only,
        // no clone/compress attempted).
        let cfg_strict = Config { max_file_size: 1000, ..Config::default() };
        assert_eq!(should_skip(&path, &cfg_strict).unwrap(), Some(SkipReason::TooLarge));

        // A cap comfortably above the file must not skip it for this reason.
        let cfg_lenient = Config { max_file_size: 1_000_000, ..Config::default() };
        assert_eq!(should_skip(&path, &cfg_lenient).unwrap(), None);
    }

    #[test]
    fn default_max_file_size_does_not_skip_ordinary_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ordinary.bin");
        fs::write(&path, vec![b'a'; 5000]).unwrap();
        assert_eq!(should_skip(&path, &Config::default()).unwrap(), None);
    }

    #[test]
    fn readonly_permission_bits_dont_trigger_skip() {
        // Sanity check that should_skip only looks at the rules above, not
        // general permission bits (compression itself is a separate concern
        // handled by swap/clonefile permission inheritance).
        let dir = tempdir().unwrap();
        let path = dir.path().join("ro.bin");
        fs::write(&path, vec![b'a'; 5000]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        let reason = should_skip(&path, &Config::default()).unwrap();
        assert_eq!(reason, None);
    }

    #[test]
    fn recently_modified_file_is_skipped_when_min_age_configured() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fresh.bin");
        fs::write(&path, vec![b'a'; 5000]).unwrap();

        let cfg = Config { min_age: Some(std::time::Duration::from_secs(3600)), ..Config::default() };
        assert_eq!(should_skip(&path, &cfg).unwrap(), Some(SkipReason::RecentlyModified));
    }

    #[test]
    fn old_enough_file_is_not_skipped_for_min_age() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settled.bin");
        fs::write(&path, vec![b'a'; 5000]).unwrap();
        let long_ago = SystemTime::now() - Duration::from_secs(30 * 24 * 3600);
        let times = fs::FileTimes::new().set_modified(long_ago);
        fs::File::options().write(true).open(&path).unwrap().set_times(times).unwrap();

        let cfg = Config { min_age: Some(Duration::from_secs(3600)), ..Config::default() };
        assert_eq!(should_skip(&path, &cfg).unwrap(), None);
    }

    #[test]
    fn min_age_none_by_default_does_not_skip_fresh_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fresh.bin");
        fs::write(&path, vec![b'a'; 5000]).unwrap();
        assert_eq!(should_skip(&path, &Config::default()).unwrap(), None);
    }

    #[test]
    fn target_size_ratio_one_allows_equal_size() {
        assert_eq!(target_size(1000, 1.0), 1000);
        assert!(!cumulative_exceeds_target(1000, target_size(1000, 1.0)));
        assert!(cumulative_exceeds_target(1001, target_size(1000, 1.0)));
    }

    #[test]
    fn target_size_stricter_ratio() {
        // must save at least 20%
        let target = target_size(1000, 0.80);
        assert_eq!(target, 800);
        assert!(!cumulative_exceeds_target(800, target));
        assert!(cumulative_exceeds_target(801, target));
    }

    #[test]
    fn cumulative_reject_is_monotonic_safe() {
        // Once compressed_so_far exceeds target, adding more (>=0) bytes
        // keeps it exceeding - this is the "provably safe" property.
        let target = 1000u64;
        let mut so_far = 1001u64; // already over
        assert!(cumulative_exceeds_target(so_far, target));
        so_far += 500; // more chunks added
        assert!(cumulative_exceeds_target(so_far, target));
    }

    #[test]
    fn race_profile_covers_every_documented_level() {
        for level in RACE_PROFILE_MIN..=RACE_PROFILE_MAX {
            let combo = race_profile(level).unwrap_or_else(|| panic!("level {level} should resolve"));
            assert!(!combo.is_empty(), "level {level} has no members");
        }
    }

    #[test]
    fn race_profile_rejects_out_of_range_levels() {
        // No below-range case to check: RACE_PROFILE_MIN is 0 and level is
        // u8, so there's no representable value under it.
        assert_eq!(race_profile(RACE_PROFILE_MAX + 1), None);
    }

    #[test]
    fn default_race_level_is_in_range() {
        assert!((RACE_PROFILE_MIN..=RACE_PROFILE_MAX).contains(&DEFAULT_RACE_LEVEL));
        assert_eq!(Config::default().algorithms, Algorithms::race_level(DEFAULT_RACE_LEVEL).unwrap());
        assert_eq!(Config::default().algorithms.level(), Some(DEFAULT_RACE_LEVEL));
    }

    #[test]
    fn with_race_level_replaces_algorithms_and_keeps_other_fields() {
        let base = Config { max_ratio: 0.5, ..Config::default() };
        let cfg = base.with_race_level(3).unwrap();
        assert_eq!(cfg.algorithms.as_slice(), race_profile(3).unwrap().as_slice());
        assert_eq!(cfg.algorithms.level(), Some(3));
        assert_eq!(cfg.max_ratio, 0.5);
        assert!(Config::for_race_level(RACE_PROFILE_MAX + 1).is_none());
    }

    #[test]
    fn custom_algorithms_reject_empty_and_carry_no_level() {
        assert_eq!(Algorithms::custom(Vec::new()), None);
        let a = Algorithms::custom(vec![Algo::Lzfse, Algo::Zlib(9)]).unwrap();
        assert_eq!(a.as_slice(), &[Algo::Lzfse, Algo::Zlib(9)]);
        assert_eq!(a.level(), None);
        assert_eq!(Algorithms::single(Algo::Lzvn).as_slice(), &[Algo::Lzvn]);
    }
}
