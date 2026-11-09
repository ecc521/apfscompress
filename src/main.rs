use apfscompress::algo::{self, Algo};
use apfscompress::walk::{collect_files, walk_files};
use apfscompress::batch::{self, FileResult};
use apfscompress::control::Control;
use apfscompress::{decmpfs, dmg, engine, estimate, fsops, policy};
use clap::{Args, Parser, Subcommand, ValueEnum};
use rayon::prelude::*;
use std::os::macos::fs::MetadataExt as MacMetadataExt;
use std::os::unix::fs::MetadataExt as UnixMetadataExt;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "apfscompress",
    version,
    about = "Transparent APFS/HFS+ file compression (decmpfs): LZFSE, LZVN, LZBITMAP, LZ4 and ZLIB, \
             each with both Apple's encoder and a tunable crush-lz alternative"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Worker threads for compression, decompression and estimation.
    /// Defaults to one per logical core.
    #[arg(long, short = 'j', global = true)]
    jobs: Option<std::num::NonZeroUsize>,
}

#[derive(Subcommand)]
enum Command {
    /// Compress a file, or every eligible file under a directory.
    Compress {
        path: PathBuf,
        #[command(flatten)]
        select: SelectArgs,
        /// Skip the post-write check that reads the compressed file back and
        /// compares it byte-for-byte with the original. On by default.
        #[arg(long)]
        no_paranoid: bool,
        /// Report what would happen (algorithm, resulting size) without
        /// writing anything.
        #[arg(long)]
        dry_run: bool,
        /// Print detail for uncommon outcomes: currently, files whose
        /// compressed form would exceed the resource fork's ~4GiB limit.
        #[arg(long)]
        verbose: bool,
    },
    /// Decompress a file, or every compressed file under a directory.
    Decompress {
        path: PathBuf,
        /// Report what would be decompressed (and the resulting size)
        /// without touching anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print decmpfs status for a file, or every file under a directory.
    Info { path: PathBuf },
    /// Remove orphaned staging files left behind by a crash, under a directory.
    Sweep { path: PathBuf },
    /// List the compression algorithms this build offers, the decmpfs type
    /// each writes, and whether this system's kernel can read it back.
    Algos,
    /// Predict compression savings for a file, or every eligible file under a
    /// directory, without writing or fully compressing anything. Files
    /// larger than `--probe-size` are extrapolated from a leading sample; see
    /// the printed exact-vs-extrapolated counts to gauge accuracy.
    Estimate {
        path: PathBuf,
        #[command(flatten)]
        select: SelectArgs,
        /// Bytes of each file's leading data actually compressed to produce
        /// its estimate; anything beyond this is extrapolated, not measured.
        /// Larger values trade speed for accuracy on big files.
        #[arg(long, default_value_t = policy::Config::default().probe_size)]
        probe_size: u64,
    },
    /// Build a disk image whose files are already compressed, so an app
    /// dragged out of it in Finder installs compressed. Takes an `.app`, or
    /// an existing `.dmg` whose volume (background, layout, Applications
    /// link) is carried over as is. Sign and notarize the result afterwards.
    Dmg {
        /// An `.app` bundle, or a `.dmg` to rebuild.
        input: PathBuf,
        /// Where to write the new image. Overwritten if it exists.
        #[arg(long, short = 'o')]
        output: PathBuf,
        /// The oldest macOS the image must work on, e.g. 11.0. Formats it
        /// can't decode are left out of the race. Defaults to the lowest
        /// `LSMinimumSystemVersion` among the apps in the image.
        #[arg(long)]
        min_macos: Option<String>,
        /// UDIF format of the image, e.g. UDZO, ULFO, ULMO. Defaults to the
        /// input image's, or UDZO for an app.
        #[arg(long)]
        format: Option<String>,
        /// Filesystem inside the image. Defaults to the input image's, or
        /// HFS+ for an app.
        #[arg(long, value_enum)]
        filesystem: Option<FilesystemArg>,
        /// Volume name. Defaults to the input image's, or the app's name.
        #[arg(long)]
        volume_name: Option<String>,
        /// For an `.app` input, leave out the usual link to /Applications.
        #[arg(long)]
        no_applications_link: bool,
        #[command(flatten)]
        select: SelectArgs,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum FilesystemArg {
    #[value(name = "HFS+", alias = "hfs")]
    Hfs,
    #[value(name = "APFS", alias = "apfs")]
    Apfs,
}

impl From<FilesystemArg> for dmg::Filesystem {
    fn from(f: FilesystemArg) -> Self {
        match f {
            FilesystemArg::Hfs => dmg::Filesystem::Hfs,
            FilesystemArg::Apfs => dmg::Filesystem::Apfs,
        }
    }
}

/// Flags shared by `compress` and `estimate`: which files are eligible and
/// what to compress them with.
#[derive(Args)]
struct SelectArgs {
    /// Algorithm(s), comma-separated: one = single-shot, two or more = race
    /// (smallest wins). Default: race level 9.
    ///
    /// Apple encoders (no level): lzfse, lzvn, lzbitmap, lz4 (needs macOS
    /// 27.0). Crush-lz alternatives add a level, trading speed for ratio:
    /// crushlzfse[:-5..11] (default 8), crushlzvn[:-5..10] (8),
    /// crushlzbitmap[:-5..12] (7), crushlz4[:-5..10] (6). Also
    /// zlib[:1..12] (default 12), and stored (never compresses).
    ///
    /// Example: --algo lzfse,crushlzfse:8,zlib:6. See `apfscompress algos`.
    #[arg(long)]
    algo: Option<String>,
    /// Pick a race combo (0 = fastest/cheapest, 10 = slowest/densest)
    /// from a measured table instead of hand-listing algorithms with
    /// --algo. Conflicts with --algo.
    #[arg(long, conflicts_with = "algo", value_parser = clap::value_parser!(u8).range(policy::RACE_PROFILE_MIN as i64..=policy::RACE_PROFILE_MAX as i64))]
    race_level: Option<u8>,
    /// Accept only if the compressed result is at most this fraction of
    /// the original size (decimal): 1.0 (default) accepts anything that
    /// doesn't grow, 0.8 requires at least 20% savings. Values above 1.0
    /// permit growth. Must be greater than 0.
    #[arg(long, default_value_t = 1.0)]
    max_ratio: f64,
    /// Whether to reconsider files already transparently compressed by
    /// something else (e.g. ditto, which never uses LZFSE).
    #[arg(long, value_enum, default_value = "never")]
    recompress: RecompressArg,
    /// Skip files larger than this (bytes) before any work. A flat safety
    /// ceiling; the resource-fork format's own ~4GiB limit still applies
    /// regardless (see --verbose).
    #[arg(long, default_value_t = policy::DEFAULT_MAX_FILE_SIZE)]
    max_file_size: u64,
    /// Skip files smaller than this (bytes). Defaults to the filesystem's
    /// block size, since a real disk-usage win below that requires the
    /// compressed xattr to be small enough for APFS to store inline.
    #[arg(long)]
    min_file_size: Option<u64>,
    /// Skip files modified more recently than this. Off by default; useful
    /// on a recurring/scheduled run so CPU is spent only on files that have
    /// settled (any later write decompresses a file again anyway). Accepts
    /// a bare number of seconds or a suffixed duration: 45s, 30m, 24h, 7d, 2w.
    #[arg(long)]
    min_age: Option<String>,
    /// Comma-separated file extensions to skip entirely (no leading dot,
    /// case-insensitive). Nothing is skipped by default, since `--max-ratio`
    /// already guarantees a result is only accepted if it doesn't grow; use
    /// this to opt specific extensions out of the CPU cost of trying.
    #[arg(long)]
    skip_extensions: Option<String>,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum RecompressArg {
    Never,
    IfDifferentAlgo,
    Always,
}

impl From<RecompressArg> for policy::RecompressPolicy {
    fn from(a: RecompressArg) -> Self {
        match a {
            RecompressArg::Never => policy::RecompressPolicy::Never,
            RecompressArg::IfDifferentAlgo => policy::RecompressPolicy::IfDifferentAlgo,
            RecompressArg::Always => policy::RecompressPolicy::Always,
        }
    }
}

/// Parses one `name` or `name:level` algorithm spec.
///
/// The level is libdeflate's 1-12 for `zlib`, and each `crush*` encoder's
/// own scale otherwise (those start at -2, so don't assume non-negative).
/// The four Apple encoders take no level: libcompression's buffer API has
/// no level/quality parameter for them, so a level there is a user error.
fn parse_algo_spec(spec: &str) -> Result<Algo, String> {
    let spec = spec.trim();
    let (name, level) = match spec.split_once(':') {
        Some((n, l)) => (n, Some(l)),
        None => (spec, None),
    };
    match name.to_ascii_lowercase().as_str() {
        "zlib" => {
            let (min, max) = (algo::ZLIB_MIN_LEVEL, algo::ZLIB_MAX_LEVEL);
            let level = match level {
                None => algo::ZLIB_DEFAULT_LEVEL,
                Some(l) => l
                    .parse::<u8>()
                    .map_err(|_| format!("invalid zlib level {l:?} (expected an integer {min}-{max})"))?,
            };
            // libdeflate accepts level 0 but we refuse it: it emits
            // uncompressed DEFLATE blocks, which only grow the input.
            if level == 0 {
                return Err(
                    "zlib level 0 means \"no compression\" -- it only ever grows the input. \
                     Use \"stored\" if you want an uncompressed decmpfs file, or a level of 1 or more"
                        .to_string(),
                );
            }
            if level > max {
                return Err(format!("zlib level must be {min}-{max}, got {level}"));
            }
            Ok(Algo::Zlib(level))
        }
        "crushlzfse" => crush_level(level, "crushlzfse", crushlzfse::Level::MIN.0, crushlzfse::Level::MAX.0,
            algo::CRUSHLZFSE_DEFAULT_LEVEL).map(Algo::CrushLzfse),
        "crushlzvn" => crush_level(level, "crushlzvn", crushlzfse::lzvn::Level::MIN.0, crushlzfse::lzvn::Level::MAX.0,
            algo::CRUSHLZVN_DEFAULT_LEVEL).map(Algo::CrushLzvn),
        "crushlzbitmap" => crush_level(level, "crushlzbitmap", lzbitmap::Level::MIN.0, lzbitmap::Level::MAX.0,
            algo::CRUSHLZBITMAP_DEFAULT_LEVEL).map(Algo::CrushLzbitmap),
        "crushlz4" => crush_level(level, "crushlz4", crushlz4::Level::MIN.0, crushlz4::Level::MAX.0,
            algo::CRUSHLZ4_DEFAULT_LEVEL).map(Algo::CrushLz4),
        "lzfse" => reject_level(level, "lzfse").map(|()| Algo::Lzfse),
        "lzvn" => reject_level(level, "lzvn").map(|()| Algo::Lzvn),
        "lzbitmap" => reject_level(level, "lzbitmap").map(|()| Algo::Lzbitmap),
        "lz4" => reject_level(level, "lz4").map(|()| Algo::Lz4),
        "stored" => reject_level(level, "stored").map(|()| Algo::Stored),
        other => Err(format!(
            "unknown algorithm {other:?} (expected one of: {})",
            algo::all_algos().iter().map(algo_spec_name).collect::<Vec<_>>().join(", ")
        )),
    }
}

/// Parses `--skip-extensions`'s comma-separated spec into the replacement
/// list: an empty (or all-whitespace) spec means "skip nothing", not "one
/// empty-string extension that never matches anything real".
fn parse_extension_list(spec: &str) -> Vec<String> {
    if spec.trim().is_empty() {
        return Vec::new();
    }
    spec.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

/// Parses a `--min-age` duration spec: a bare integer (seconds) or an
/// integer with a single-letter unit suffix (s, m, h, d, w).
fn parse_duration_spec(spec: &str) -> Result<std::time::Duration, String> {
    let spec = spec.trim();
    let usage = "expected e.g. \"45s\", \"30m\", \"24h\", \"7d\", \"2w\", or a bare number of seconds";
    if spec.is_empty() {
        return Err(format!("empty duration ({usage})"));
    }
    let split_at = spec.find(|c: char| !c.is_ascii_digit()).unwrap_or(spec.len());
    let (num, unit) = spec.split_at(split_at);
    let n: u64 = num.parse().map_err(|_| format!("invalid duration {spec:?} ({usage})"))?;
    let multiplier: u64 = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        "w" => 604_800,
        other => return Err(format!("unknown duration unit {other:?} in {spec:?} (expected s, m, h, d, or w)")),
    };
    let secs = n.checked_mul(multiplier).ok_or_else(|| format!("duration {spec:?} overflows"))?;
    Ok(std::time::Duration::from_secs(secs))
}

/// Prints every algorithm with its decmpfs type and whether this kernel can
/// decode it. Driven by `algo::all_algos` and `algo::is_supported` rather
/// than a list written out here, so it cannot drift from what
/// `parse_algo_spec` actually accepts.
fn run_algos() -> i32 {
    let (major, minor) = algo::os_version();
    println!("macOS {major}.{minor}\n");
    println!("{:<15} {:<7} {:<9} {:<9} STATUS", "NAME", "TYPES", "LEVEL", "NEEDS");
    for a in algo::all_algos() {
        let name = algo_spec_name(&a);
        let types = match decmpfs::rsrc_type(a) {
            Some(r) => format!("{}/{}", decmpfs::xattr_type(a), r),
            None => decmpfs::xattr_type(a).to_string(),
        };
        let level = match a.level() {
            Some(l) => l.to_string(),
            None => "-".to_string(),
        };
        let (need_major, need_minor) = algo::min_os_version(a);
        let status = if algo::is_supported(a) { "available" } else { "UNAVAILABLE on this system" };
        println!("{name:<15} {types:<7} {level:<9} {:<9} {status}", format!("{need_major}.{need_minor}"));
    }
    0
}

fn reject_level(level: Option<&str>, name: &str) -> Result<(), String> {
    match level {
        Some(l) => Err(format!(
            "{name} doesn't support a compression level -- libcompression's buffer API has no level \
             parameter for it. Got \"{name}:{l}\"; try \"crush{name}:{l}\", which encodes the same \
             on-disk format with a tunable level."
        )),
        None => Ok(()),
    }
}

/// Shared level parsing for the four `crush*` encoders, which differ only in
/// their name and their crate's own range. Range-checked here rather than
/// left to the crate, which clamps silently: `crushlzfse:99` quietly
/// becoming level 10 is the wrong answer for a user-facing flag.
fn crush_level(level: Option<&str>, name: &str, min: i32, max: i32, default: i32) -> Result<i32, String> {
    let lvl = match level {
        None => default,
        Some(l) => l
            .parse::<i32>()
            .map_err(|_| format!("invalid {name} level {l:?} (expected an integer {min}-{max})"))?,
    };
    if !(min..=max).contains(&lvl) {
        return Err(format!("{name} level must be {min}-{max}, got {lvl}"));
    }
    Ok(lvl)
}

/// The spec name that parses back to `algo`, for help and error text. The
/// inverse of `parse_algo_spec`'s name arm, so the two cannot drift.
fn algo_spec_name(algo: &Algo) -> &'static str {
    match algo {
        Algo::Zlib(_) => "zlib",
        Algo::Lzfse => "lzfse",
        Algo::CrushLzfse(_) => "crushlzfse",
        Algo::Lzvn => "lzvn",
        Algo::CrushLzvn(_) => "crushlzvn",
        Algo::Lzbitmap => "lzbitmap",
        Algo::CrushLzbitmap(_) => "crushlzbitmap",
        Algo::Lz4 => "lz4",
        Algo::CrushLz4(_) => "crushlz4",
        Algo::Stored => "stored",
    }
}

/// Parses a comma-separated algorithm list. Empty entries (e.g. a trailing
/// comma) are rejected explicitly rather than silently dropped.
fn parse_algo_list(spec: &str) -> Result<Vec<Algo>, String> {
    spec.split(',')
        .map(|s| {
            let s = s.trim();
            if s.is_empty() {
                return Err("empty algorithm entry (check for a stray comma)".to_string());
            }
            parse_algo_spec(s)
        })
        .collect()
}

impl SelectArgs {
    /// The `Config` these flags describe, exiting with a usage error on a
    /// bad value. With neither `--algo` nor `--race-level`, the algorithm
    /// choice is `Config::default()`'s.
    fn into_config(self) -> policy::Config {
        let usage = |flag: &str, e: &dyn std::fmt::Display| -> ! {
            eprintln!("apfscompress: {flag}: {e}");
            std::process::exit(2);
        };
        if self.max_ratio <= 0.0 || self.max_ratio.is_nan() {
            usage("--max-ratio", &format!("must be greater than 0, got {}", self.max_ratio));
        }
        let min_age = self.min_age.map(|spec| parse_duration_spec(&spec).unwrap_or_else(|e| usage("--min-age", &e)));
        let mut cfg = policy::Config {
            max_ratio: self.max_ratio,
            recompress: self.recompress.into(),
            max_file_size: self.max_file_size,
            min_file_size: self.min_file_size,
            min_age,
            ..policy::Config::default()
        };
        if let Some(spec) = self.skip_extensions {
            cfg.skip_extensions = parse_extension_list(&spec);
        }
        // clap's `conflicts_with` refuses both flags at once, and its range
        // validator refuses a race level outside `race_profile`'s table.
        let algorithms = match (self.race_level, self.algo) {
            (Some(level), _) => policy::Algorithms::race_level(level).expect("clap already validated the range"),
            (None, Some(spec)) => {
                let algos = parse_algo_list(&spec).unwrap_or_else(|e| usage("--algo", &e));
                policy::Algorithms::custom(algos).unwrap_or_else(|| usage("--algo", &"no algorithms given"))
            }
            (None, None) => return cfg,
        };
        cfg.with_algorithms(algorithms)
    }
}

fn main() {
    let cli = Cli::parse();
    if let Some(jobs) = cli.jobs {
        // Only fails if the global pool was already built, which nothing
        // before this point does.
        rayon::ThreadPoolBuilder::new()
            .num_threads(jobs.get())
            .build_global()
            .expect("global rayon pool is configured once, before any use");
    }
    let code = match cli.command {
        Command::Compress { path, select, no_paranoid, dry_run, verbose } => {
            let cfg = policy::Config { paranoid: !no_paranoid, dry_run, ..select.into_config() };
            run_compress(&path, &cfg, verbose)
        }
        Command::Decompress { path, dry_run } => run_decompress(&path, dry_run),
        Command::Info { path } => run_info(&path),
        Command::Sweep { path } => run_sweep(&path),
        Command::Algos => run_algos(),
        Command::Estimate { path, select, probe_size } => {
            let cfg = policy::Config { probe_size, ..select.into_config() };
            run_estimate(&path, &cfg)
        }
        Command::Dmg { input, output, min_macos, format, filesystem, volume_name, no_applications_link, select } => {
            let min_macos = min_macos.map(|v| {
                algo::parse_os_version(&v).unwrap_or_else(|| {
                    eprintln!("apfscompress: --min-macos: expected a version like 11.0, got {v:?}");
                    std::process::exit(2);
                })
            });
            let opts = DmgArgs {
                min_macos,
                format,
                filesystem: filesystem.map(Into::into),
                volume_name,
                applications_link: !no_applications_link,
            };
            run_dmg(&input, &output, opts, select.into_config())
        }
    };
    std::process::exit(code);
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = n as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n}B")
    } else {
        format!("{size:.1}{}", UNITS[unit])
    }
}

#[derive(Default)]
struct AlgoStats {
    count: u64,
    original: u64,
    compressed: u64,
}

fn run_compress(path: &Path, cfg: &policy::Config, verbose: bool) -> i32 {
    // No startup sweep of /tmp: a global sweep here would delete a
    // *concurrent* apfscompress run's in-flight clones. Same-directory
    // fallback leftovers are still caught opportunistically by walk_files
    // below and by the explicit `sweep` command.
    let files = match walk_files(path.to_path_buf()) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("apfscompress: cannot read {}: {e}", path.display());
            return 1;
        }
    };

    let compressed = AtomicU64::new(0);
    let skipped = AtomicU64::new(0);
    let not_worthwhile = AtomicU64::new(0);
    let errors = AtomicU64::new(0);
    let total_original = AtomicU64::new(0);
    let total_compressed = AtomicU64::new(0);
    let algo_stats: Mutex<HashMap<Algo, AlgoStats>> = Mutex::new(HashMap::new());
    // Files process concurrently, so lines print in completion order, not
    // input order (like `xargs -P`), letting finished files report
    // immediately rather than waiting on a slow one ahead of them.
    let verb = if cfg.dry_run { "would-compress" } else { "compressed    " };
    let start = Instant::now();

    let results = match batch::compress_files(files, cfg.clone(), Arc::new(Control::new())) {
        Ok(results) => results,
        Err(e) => {
            eprintln!("apfscompress: cannot start compressing: {e}");
            return 1;
        }
    };
    for FileResult { path: f, outcome } in results {
        match outcome {
            Ok(engine::Outcome::Compressed { algo, original_size, compressed_size }) => {
                compressed.fetch_add(1, Ordering::Relaxed);
                total_original.fetch_add(original_size, Ordering::Relaxed);
                total_compressed.fetch_add(compressed_size, Ordering::Relaxed);
                {
                    let mut stats = algo_stats.lock().unwrap();
                    let entry = stats.entry(algo).or_default();
                    entry.count += 1;
                    entry.original += original_size;
                    entry.compressed += compressed_size;
                }
                println!(
                    "{verb} {} ({algo:?}, {} -> {})",
                    f.display(),
                    human_bytes(original_size),
                    human_bytes(compressed_size)
                );
            }
            Ok(engine::Outcome::Skipped(reason)) => {
                skipped.fetch_add(1, Ordering::Relaxed);
                println!("skipped        {} ({reason:?})", f.display());
            }
            Ok(engine::Outcome::NotWorthwhile { original_size, reason }) => {
                not_worthwhile.fetch_add(1, Ordering::Relaxed);
                if verbose && reason == engine::NotWorthwhileReason::ExceedsResourceForkLimit {
                    println!(
                        "no-benefit     {} (compressed representation would exceed the resource-fork format's ~4GiB limit; original {})",
                        f.display(),
                        human_bytes(original_size)
                    );
                } else {
                    println!("no-benefit     {}", f.display());
                }
            }
            Ok(engine::Outcome::Cancelled) => unreachable!("nothing cancels the CLI's Control"),
            Err(e) => {
                errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("error          {}: {e}", f.display());
            }
        }
    }

    let compressed = compressed.load(Ordering::Relaxed);
    let skipped = skipped.load(Ordering::Relaxed);
    let not_worthwhile = not_worthwhile.load(Ordering::Relaxed);
    let errors = errors.load(Ordering::Relaxed);
    let total_original = total_original.load(Ordering::Relaxed);
    let total_compressed = total_compressed.load(Ordering::Relaxed);

    let elapsed = start.elapsed();

    let verb_label = if cfg.dry_run { "would-compress" } else { "compressed" };
    println!("\n{compressed} {verb_label}, {skipped} skipped, {not_worthwhile} no-benefit, {errors} errors");

    let algo_stats = algo_stats.into_inner().unwrap();
    if algo_stats.len() > 1 {
        let mut entries: Vec<(Algo, AlgoStats)> = algo_stats.into_iter().collect();
        entries.sort_by_key(|(_, s)| std::cmp::Reverse(s.count));
        let breakdown = entries
            .iter()
            .map(|(algo, s)| format!("{algo:?} ({} files, {} -> {})", s.count, human_bytes(s.original), human_bytes(s.compressed)))
            .collect::<Vec<_>>()
            .join(", ");
        println!("{breakdown}");
    }

    if compressed > 0 {
        let pct = 100.0 * (1.0 - total_compressed as f64 / total_original as f64);
        if cfg.dry_run {
            let secs = elapsed.as_secs_f64();
            let mbps = if secs > 0.0 { (total_original as f64 / (1024.0 * 1024.0)) / secs } else { 0.0 };
            println!(
                "{} -> {} ({pct:.1}% smaller) ({mbps:.1} MB/s) [dry run, nothing written]",
                human_bytes(total_original),
                human_bytes(total_compressed),
            );
        } else {
            println!(
                "{} -> {} ({pct:.1}% smaller)",
                human_bytes(total_original),
                human_bytes(total_compressed),
            );
        }
    }

    if errors > 0 { 1 } else { 0 }
}

/// `dmg`'s choices, before defaults from the input are filled in.
struct DmgArgs {
    min_macos: Option<algo::OsVersion>,
    format: Option<String>,
    filesystem: Option<dmg::Filesystem>,
    volume_name: Option<String>,
    applications_link: bool,
}

/// A private scratch folder, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> std::io::Result<Scratch> {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("apfscompress-dmg-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Scratch(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_dmg(input: &Path, output: &Path, args: DmgArgs, cfg: policy::Config) -> i32 {
    match build_dmg(input, output, args, cfg) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("apfscompress: {e}");
            1
        }
    }
}

fn build_dmg(input: &Path, output: &Path, args: DmgArgs, cfg: policy::Config) -> Result<(), String> {
    fn io(what: &str) -> impl Fn(std::io::Error) -> String + '_ {
        move |e| format!("{what}: {e}")
    }
    let meta = std::fs::metadata(input).map_err(io(&format!("cannot read {}", input.display())))?;
    let scratch = Scratch::new().map_err(io("cannot create a scratch folder"))?;
    let root = scratch.0.join("volume");

    // Stage the volume's contents, and take the image's settings from the
    // input unless overridden.
    let (volume_name, format, filesystem) = if meta.is_dir() {
        let name = input
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .ok_or_else(|| format!("{} has no name", input.display()))?;
        std::fs::create_dir(&root).map_err(io("cannot stage the app"))?;
        let app_name = input.file_name().expect("file_stem succeeded");
        dmg::ditto(input, &root.join(app_name)).map_err(io("cannot copy the app"))?;
        if args.applications_link {
            std::os::unix::fs::symlink("/Applications", root.join("Applications"))
                .map_err(io("cannot add the Applications link"))?;
        }
        (
            args.volume_name.unwrap_or(name),
            args.format.unwrap_or_else(|| "UDZO".to_string()),
            args.filesystem.unwrap_or(dmg::Filesystem::Hfs),
        )
    } else {
        let format = dmg::image_format(input).map_err(io("cannot read the image"))?;
        let source = dmg::Mounted::attach(input, &scratch.0.join("source")).map_err(io("cannot mount the image"))?;
        let name = dmg::volume_name(source.path()).map_err(io("cannot read the volume name"))?;
        let filesystem = dmg::filesystem(source.path()).map_err(io("cannot read the image's filesystem"))?;
        dmg::copy_volume(source.path(), &root).map_err(io("cannot copy the image's contents"))?;
        source.detach().map_err(io("cannot unmount the image"))?;
        (args.volume_name.unwrap_or(name), args.format.unwrap_or(format), args.filesystem.unwrap_or(filesystem))
    };

    // Only formats every supported macOS can read: a file in a format the
    // kernel predates cannot be opened at all.
    let target = match args.min_macos {
        Some(v) => v,
        None => dmg::app_bundles(&root).iter().filter_map(|a| dmg::app_min_os_version(a)).min().ok_or(
            "no app in the image declares LSMinimumSystemVersion, so the oldest macOS it must work on is unknown; \
             pass --min-macos",
        )?,
    };
    let (fs_major, fs_minor) = filesystem.min_os_version();
    if (fs_major, fs_minor) > target {
        return Err(format!(
            "an {} image needs macOS {fs_major}.{fs_minor}, newer than the {}.{} it must support; use --filesystem HFS+",
            filesystem.hdiutil_name(),
            target.0,
            target.1
        ));
    }
    // `ditto` staged the files as clones of the input when it shares their
    // volume. What matters here is the image, not space on this volume.
    let cfg = policy::Config { skip_clones: false, ..cfg };
    let readable = dmg::readable_on(cfg.algorithms.as_slice(), target);
    if readable.is_empty() {
        return Err(format!("none of the chosen formats can be read on macOS {}.{}", target.0, target.1));
    }
    let cfg = if readable.len() < cfg.algorithms.as_slice().len() {
        cfg.with_algorithms(policy::Algorithms::custom(readable.clone()).expect("not empty"))
    } else {
        cfg
    };
    let race: Vec<String> = readable
        .iter()
        .map(|a| match a.level() {
            Some(l) => format!("{}:{l}", algo_spec_name(a)),
            None => algo_spec_name(a).to_string(),
        })
        .collect();
    println!("macOS {}.{} and later: racing {}", target.0, target.1, race.join(", "));

    let before = dmg::footprint(&root).map_err(io("cannot measure the staged files"))?;
    let files = walk_files(root.clone()).map_err(io("cannot read the staged files"))?;
    let results = batch::compress_files(files, cfg, Arc::new(Control::new())).map_err(io("cannot start compressing"))?;
    let (mut total, mut compressed, mut errors) = (0u64, 0u64, 0u64);
    for FileResult { path, outcome } in results {
        total += 1;
        match outcome {
            Ok(engine::Outcome::Compressed { .. }) => compressed += 1,
            Ok(_) => {}
            Err(e) => {
                errors += 1;
                eprintln!("error          {}: {e}", path.strip_prefix(&root).unwrap_or(&path).display());
            }
        }
    }
    if errors > 0 {
        return Err(format!("{errors} files could not be compressed; no image written"));
    }
    let after = dmg::footprint(&root).map_err(io("cannot measure the staged files"))?;

    dmg::create(&root, output, &volume_name, filesystem, &format, &scratch.0).map_err(io("cannot create the image"))?;

    // Read the image back: every file must be there, byte for byte, and
    // still compressed.
    let check = dmg::Mounted::attach(output, &scratch.0.join("check")).map_err(io("cannot mount the new image"))?;
    let cmp = dmg::compare(&root, check.path()).map_err(io("cannot compare the new image"))?;
    check.detach().map_err(io("cannot unmount the new image"))?;
    if let Some(first) = cmp.mismatched.first() {
        return Err(format!(
            "{} files in the new image differ from the staged copy, e.g. {}",
            cmp.mismatched.len(),
            first.display()
        ));
    }
    if cmp.still_compressed < cmp.compressed {
        return Err(format!(
            "{} of {} compressed files lost their compression in the new image",
            cmp.compressed - cmp.still_compressed,
            cmp.compressed
        ));
    }

    let image_size = std::fs::metadata(output).map(|m| m.len()).unwrap_or(0);
    let pct = if before > 0 { 100.0 * (1.0 - after as f64 / before as f64) } else { 0.0 };
    println!("{compressed} of {total} files compressed");
    println!("installed size: {} -> {} ({pct:.1}% smaller)", human_bytes(before), human_bytes(after));
    println!(
        "wrote {} ({format}, {}, {}), verified",
        output.display(),
        filesystem.hdiutil_name(),
        human_bytes(image_size)
    );
    println!("next: codesign the image, then notarize and staple it");
    Ok(())
}

/// Thin formatter over `estimate::estimate_tree` - all the actual walking,
/// prediction, and aggregation lives in the library (see that function's doc
/// comment for why), so a caller linking this crate directly gets the same
/// `TreeEstimate` this just prints.
fn run_estimate(path: &Path, cfg: &policy::Config) -> i32 {
    let start = Instant::now();
    let result = match estimate::estimate_tree(path, cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("apfscompress: cannot read {}: {e}", path.display());
            return 1;
        }
    };
    let elapsed = start.elapsed();

    println!(
        "{} eligible ({} exact, {} extrapolated from a probe), {} no-benefit, {} errors",
        result.eligible_files, result.exact_files, result.estimated_files, result.not_worthwhile_files, result.error_files
    );

    if !result.skipped_files_by_reason.is_empty() {
        let mut reasons: Vec<(policy::SkipReason, u64)> = result.skipped_files_by_reason.into_iter().collect();
        reasons.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        let breakdown =
            reasons.iter().map(|(r, n)| format!("{r:?}: {n}")).collect::<Vec<_>>().join(", ");
        println!("skipped: {breakdown}");
    }

    if result.eligible_files > 0 {
        let pct = 100.0 * (1.0 - result.predicted_compressed_bytes as f64 / result.original_bytes as f64);
        println!(
            "predicted: {} -> {} ({pct:.1}% smaller)  [estimate: {} of {} files extrapolated from a probe, not fully compressed]",
            human_bytes(result.original_bytes),
            human_bytes(result.predicted_compressed_bytes),
            result.estimated_files,
            result.eligible_files,
        );
    }
    println!("elapsed: {:.2}s", elapsed.as_secs_f64());

    0
}

fn run_decompress(path: &Path, dry_run: bool) -> i32 {
    let files = match walk_files(path.to_path_buf()) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("apfscompress: cannot read {}: {e}", path.display());
            return 1;
        }
    };

    let decompressed = AtomicU64::new(0);
    let errors = AtomicU64::new(0);
    let verb = if dry_run { "would-decompress" } else { "decompressed    " };

    files.par_bridge().for_each(|f| {
        let is_compressed = std::fs::symlink_metadata(&f)
            .map(|m| (m.st_flags() & apfscompress::sys::UF_COMPRESSED) != 0)
            .unwrap_or(false);
        if !is_compressed {
            return; // nothing to do
        }

        if dry_run {
            // No staging, no reading through the kernel decompressor.
            // Unlike compress's dry-run (which must run the candidate
            // algorithm to know the resulting size), decompress is an
            // unconditional full reversal: the resulting size is already
            // in the decmpfs header (one getxattr, 16 bytes).
            match fsops::get_xattr(&f, "com.apple.decmpfs")
                .ok()
                .and_then(|x| apfscompress::decmpfs::Header::from_bytes(&x))
            {
                Some(header) => {
                    decompressed.fetch_add(1, Ordering::Relaxed);
                    let footprint = policy::current_compressed_footprint(&f).unwrap_or(0);
                    println!(
                        "{verb} {} ({} -> {})",
                        f.display(),
                        human_bytes(footprint),
                        human_bytes(header.uncompressed_size)
                    );
                }
                None => {
                    errors.fetch_add(1, Ordering::Relaxed);
                    eprintln!("error             {}: decmpfs xattr unreadable", f.display());
                }
            }
            return;
        }

        match engine::decompress_file(&f) {
            Ok(()) => {
                decompressed.fetch_add(1, Ordering::Relaxed);
                println!("{verb} {}", f.display());
            }
            Err(e) => {
                errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("error             {}: {e}", f.display());
            }
        }
    });

    let decompressed = decompressed.load(Ordering::Relaxed);
    let errors = errors.load(Ordering::Relaxed);
    let verb_label = if dry_run { "would-decompress" } else { "decompressed" };
    let suffix = if dry_run { " [dry run, nothing written]" } else { "" };
    println!("\n{decompressed} {verb_label}, {errors} errors{suffix}");

    if errors > 0 { 1 } else { 0 }
}

fn run_info(path: &Path) -> i32 {
    let files = match collect_files(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("apfscompress: cannot read {}: {e}", path.display());
            return 1;
        }
    };

    for f in &files {
        let meta = match std::fs::symlink_metadata(f) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("{}: {e}", f.display());
                continue;
            }
        };
        let disk_usage = meta.blocks() * 512;
        let is_compressed = (meta.st_flags() & apfscompress::sys::UF_COMPRESSED) != 0;
        if !is_compressed {
            println!("{}: not compressed ({})", f.display(), human_bytes(meta.len()));
            continue;
        }
        match fsops::get_xattr(f, "com.apple.decmpfs")
            .ok()
            .and_then(|x| apfscompress::decmpfs::Header::from_bytes(&x))
        {
            Some(header) => println!(
                "{}: type {}, {} -> {} on disk ({:.1}% smaller)",
                f.display(),
                header.compression_type,
                human_bytes(header.uncompressed_size),
                human_bytes(disk_usage),
                100.0 * (1.0 - disk_usage as f64 / header.uncompressed_size.max(1) as f64)
            ),
            None => println!("{}: compressed (decmpfs xattr unreadable)", f.display()),
        }
    }
    0
}

fn run_sweep(path: &Path) -> i32 {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("apfscompress: {e}");
            return 1;
        }
    };
    let dirs: Vec<PathBuf> = if meta.is_dir() {
        let mut stack = vec![path.to_path_buf()];
        let mut dirs = Vec::new();
        while let Some(d) = stack.pop() {
            dirs.push(d.clone());
            if let Ok(entries) = std::fs::read_dir(&d) {
                for entry in entries.flatten() {
                    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        stack.push(entry.path());
                    }
                }
            }
        }
        dirs
    } else {
        vec![path.parent().unwrap_or(path).to_path_buf()]
    };

    let mut total = 0;
    for d in dirs {
        if let Ok(n) = apfscompress::swap::sweep_orphans(&d) {
            total += n;
        }
    }
    println!("removed {total} orphaned staging file(s)");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- adversarial: human_bytes boundary values, right at each unit
    // rollover (1024 exactly, one byte short of rolling over, etc).

    #[test]
    fn human_bytes_boundaries() {
        assert_eq!(human_bytes(0), "0B");
        assert_eq!(human_bytes(1), "1B");
        assert_eq!(human_bytes(1023), "1023B"); // one byte short of KB
        assert_eq!(human_bytes(1024), "1.0KB"); // exact rollover
        assert_eq!(human_bytes(1024 * 1024 - 1), "1024.0KB"); // one byte short of MB, still KB-formatted
        assert_eq!(human_bytes(1024 * 1024), "1.0MB");
        assert_eq!(human_bytes(1024 * 1024 * 1024), "1.0GB");
        assert_eq!(human_bytes(1024u64 * 1024 * 1024 * 1024), "1.0TB");
        // Largest unit (TB) must not index past UNITS even for huge values.
        assert_eq!(human_bytes(u64::MAX), format!("{:.1}TB", u64::MAX as f64 / (1024f64.powi(4))));
    }

    // --- adversarial: algorithm spec parsing ---

    #[test]
    fn parse_algo_spec_basic_names() {
        assert_eq!(parse_algo_spec("lzfse"), Ok(Algo::Lzfse));
        assert_eq!(parse_algo_spec("lzvn"), Ok(Algo::Lzvn));
        assert_eq!(parse_algo_spec("lzbitmap"), Ok(Algo::Lzbitmap));
        assert_eq!(parse_algo_spec("stored"), Ok(Algo::Stored));
        assert_eq!(parse_algo_spec("zlib"), Ok(Algo::Zlib(algo::ZLIB_DEFAULT_LEVEL))); // default: max level
    }

    #[test]
    fn parse_algo_spec_is_case_insensitive_and_trims_whitespace() {
        assert_eq!(parse_algo_spec("LZFSE"), Ok(Algo::Lzfse));
        assert_eq!(parse_algo_spec("  lzfse  "), Ok(Algo::Lzfse));
        assert_eq!(parse_algo_spec("ZLIB:3"), Ok(Algo::Zlib(3)));
    }

    #[test]
    fn parse_algo_spec_zlib_level() {
        assert_eq!(parse_algo_spec("zlib:5"), Ok(Algo::Zlib(5)));
        assert_eq!(parse_algo_spec("zlib:9"), Ok(Algo::Zlib(9)));
        // libdeflate's scale runs past zlib's historical 9.
        assert_eq!(parse_algo_spec("zlib:12"), Ok(Algo::Zlib(12)));
        assert_eq!(parse_algo_spec("zlib:1"), Ok(Algo::Zlib(algo::ZLIB_MIN_LEVEL)));
    }

    #[test]
    fn parse_algo_spec_rejects_zlib_level_zero_by_name() {
        // Valid to libdeflate, useless to us: level 0 emits uncompressed
        // DEFLATE blocks, which only ever grow the input. The error should
        // say so and point at `stored`, not read as a range complaint.
        let err = parse_algo_spec("zlib:0").expect_err("level 0 should be rejected");
        assert!(err.contains("no compression"), "unhelpful message: {err:?}");
        assert!(err.contains("stored"), "should point at the stored algorithm: {err:?}");
    }

    #[test]
    fn parse_algo_spec_rejects_out_of_range_zlib_level() {
        assert!(parse_algo_spec("zlib:13").is_err());
        assert!(parse_algo_spec("zlib:255").is_err());
        // 10-12 were out of range on zlib's scale and are in range on
        // libdeflate's; this pins the move rather than leaving it implicit.
        for l in algo::ZLIB_MIN_LEVEL..=algo::ZLIB_MAX_LEVEL {
            assert_eq!(parse_algo_spec(&format!("zlib:{l}")), Ok(Algo::Zlib(l)), "level {l} should parse");
        }
    }

    #[test]
    fn parse_algo_spec_rejects_non_numeric_zlib_level() {
        assert!(parse_algo_spec("zlib:max").is_err());
        assert!(parse_algo_spec("zlib:").is_err());
    }

    #[test]
    fn parse_algo_spec_crushlzfse_level() {
        assert_eq!(parse_algo_spec("crushlzfse"), Ok(Algo::CrushLzfse(algo::CRUSHLZFSE_DEFAULT_LEVEL)));
        assert_eq!(parse_algo_spec("crushlzfse:0"), Ok(Algo::CrushLzfse(0)));
        assert_eq!(parse_algo_spec("CRUSHLZFSE:5"), Ok(Algo::CrushLzfse(5)));
        // Written against the crate's own bounds rather than literals, since
        // the scale is not 0-based (Level::MIN is negative).
        assert_eq!(
            parse_algo_spec(&format!("crushlzfse:{}", crushlzfse::Level::MIN.0)),
            Ok(Algo::CrushLzfse(crushlzfse::Level::MIN.0))
        );
        assert_eq!(
            parse_algo_spec(&format!("crushlzfse:{}", crushlzfse::Level::MAX.0)),
            Ok(Algo::CrushLzfse(crushlzfse::Level::MAX.0))
        );
        // Negative levels are real, not an error.
        assert_eq!(parse_algo_spec("crushlzfse:-1"), Ok(Algo::CrushLzfse(-1)));
    }

    #[test]
    fn parse_algo_spec_accepts_every_algorithm_the_inventory_lists() {
        // The inventory and the parser must agree in both directions: every
        // name `all_algos` reports must parse, and must parse back to the
        // same variant at the same default level.
        for expected in algo::all_algos() {
            let name = algo_spec_name(&expected);
            assert_eq!(parse_algo_spec(name), Ok(expected), "bare {name:?} should give {expected:?}");
        }
    }

    #[test]
    fn parse_algo_spec_levels_the_new_crush_encoders() {
        assert_eq!(parse_algo_spec("crushlzvn"), Ok(Algo::CrushLzvn(algo::CRUSHLZVN_DEFAULT_LEVEL)));
        assert_eq!(parse_algo_spec("crushlzbitmap:3"), Ok(Algo::CrushLzbitmap(3)));
        assert_eq!(parse_algo_spec("CrushLZ4:-2"), Ok(Algo::CrushLz4(-2)));
        assert_eq!(parse_algo_spec("lz4"), Ok(Algo::Lz4));
        // Encoder ladders can grow independently; validate each crate's bounds.
        for (name, min, max) in [
            ("crushlzfse", crushlzfse::Level::MIN.0, crushlzfse::Level::MAX.0),
            ("crushlzvn", crushlzfse::lzvn::Level::MIN.0, crushlzfse::lzvn::Level::MAX.0),
            ("crushlzbitmap", lzbitmap::Level::MIN.0, lzbitmap::Level::MAX.0),
            ("crushlz4", crushlz4::Level::MIN.0, crushlz4::Level::MAX.0),
        ] {
            assert!(parse_algo_spec(&format!("{name}:{min}")).is_ok(), "{name} should accept {min}");
            assert!(parse_algo_spec(&format!("{name}:{max}")).is_ok(), "{name} should accept {max}");
            assert!(parse_algo_spec(&format!("{name}:{}", max + 1)).is_err(), "{name} should reject levels above {max}");
            assert!(parse_algo_spec(&format!("{name}:{}", min - 1)).is_err(), "{name} should reject levels below {min}");
            assert!(parse_algo_spec(&format!("{name}:x")).is_err(), "{name} should reject a non-integer");
        }
    }

    #[test]
    fn parse_algo_spec_rejects_a_level_on_the_apple_encoders() {
        // None of libcompression's four take a level; the error should point
        // at the crush variant that does.
        for name in ["lzfse", "lzvn", "lzbitmap", "lz4"] {
            let err = parse_algo_spec(&format!("{name}:5")).expect_err("should reject a level");
            assert!(err.contains(&format!("crush{name}")), "{name}: error should suggest crush{name}, got {err:?}");
        }
    }

    #[test]
    fn parse_algo_spec_rejects_out_of_range_crushlzfse_level() {
        assert!(parse_algo_spec(&format!("crushlzfse:{}", crushlzfse::Level::MAX.0 + 1)).is_err());
        assert!(parse_algo_spec(&format!("crushlzfse:{}", crushlzfse::Level::MIN.0 - 1)).is_err());
        assert!(parse_algo_spec("crushlzfse:many").is_err());
    }

    #[test]
    fn parse_algo_spec_rejects_level_on_algorithms_without_one() {
        // libcompression's buffer API has no level/quality parameter for any
        // of these; a level here is a user error worth surfacing.
        for spec in ["lzfse:5", "lzvn:1", "lzbitmap:9", "stored:0"] {
            assert!(parse_algo_spec(spec).is_err(), "{spec} should be rejected");
        }
    }

    #[test]
    fn parse_algo_spec_rejects_unknown_algorithm() {
        assert!(parse_algo_spec("gzip").is_err());
        assert!(parse_algo_spec("").is_err());
    }

    #[test]
    fn parse_algo_list_single_algorithm() {
        assert_eq!(parse_algo_list("lzfse"), Ok(vec![Algo::Lzfse]));
    }

    #[test]
    fn parse_algo_list_multiple_algorithms_implies_race() {
        assert_eq!(parse_algo_list("lzfse,zlib:6"), Ok(vec![Algo::Lzfse, Algo::Zlib(6)]));
        assert_eq!(
            parse_algo_list("lzfse, zlib, lzvn"), // whitespace around commas tolerated
            Ok(vec![Algo::Lzfse, Algo::Zlib(algo::ZLIB_DEFAULT_LEVEL), Algo::Lzvn])
        );
    }

    #[test]
    fn parse_algo_list_rejects_empty_entries() {
        assert!(parse_algo_list("lzfse,,zlib").is_err()); // double comma
        assert!(parse_algo_list("lzfse,").is_err()); // trailing comma
        assert!(parse_algo_list(",lzfse").is_err()); // leading comma
        assert!(parse_algo_list("").is_err());
    }

    #[test]
    fn parse_duration_spec_units() {
        assert_eq!(parse_duration_spec("45"), Ok(std::time::Duration::from_secs(45))); // bare number: seconds
        assert_eq!(parse_duration_spec("45s"), Ok(std::time::Duration::from_secs(45)));
        assert_eq!(parse_duration_spec("30m"), Ok(std::time::Duration::from_secs(30 * 60)));
        assert_eq!(parse_duration_spec("24h"), Ok(std::time::Duration::from_secs(24 * 3600)));
        assert_eq!(parse_duration_spec("7d"), Ok(std::time::Duration::from_secs(7 * 86400)));
        assert_eq!(parse_duration_spec("2w"), Ok(std::time::Duration::from_secs(2 * 604_800)));
    }

    #[test]
    fn parse_duration_spec_rejects_bad_input() {
        assert!(parse_duration_spec("").is_err());
        assert!(parse_duration_spec("d").is_err()); // no number
        assert!(parse_duration_spec("7x").is_err()); // unknown unit
        assert!(parse_duration_spec("7.5d").is_err()); // fractional not supported
        assert!(parse_duration_spec(&format!("{}d", u64::MAX)).is_err()); // overflow
    }

    #[test]
    fn parse_algo_list_one_bad_entry_fails_the_whole_list() {
        // Not "parse what we can": a typo in a race list should be a hard
        // error, not silently racing fewer algorithms than the user asked for.
        assert!(parse_algo_list("lzfse,not-a-real-algo,zlib").is_err());
    }

}
