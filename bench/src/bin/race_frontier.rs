//! Race frontiers by algorithm group: crush-lz publishes each encoder's own
//! level ladder, but only this tool measures what happens when encoders
//! race. Sweeps every level of one on-disk format family over a corpus,
//! keeping per-file compressed size and decode time, then combines those
//! tables post-hoc into every race a group allows, with no recompression.
//!
//! Two modes:
//!   race_frontier sweep <family> <corpus-dir> <out.tsv>
//!   race_frontier analyze [--full] <tsv>...
//! `family` is one of lzfse, zlib, lzbitmap, lz4. The zlib family uses
//! libdeflate levels 1–12; the others include Apple and crush-lz encoders.
//! Sweep each family, then `analyze`
//! all four; by default it prints the densest race at or above each of a
//! fixed speed ladder per group, `--full` prints every frontier point.
//!
//! Cost model: a race compresses with every member and keeps the smallest,
//! so encode time sums the members' times (ties go to the first member);
//! encode throughput is aggregate over the rayon pool, decode is
//! single-threaded through the same system decoder the kernel uses.

use apfscompress::algo::{self, Algo, EncodeScratch};
use apfscompress::chunker;
use rayon::prelude::*;
use std::fmt::Write as _;
use std::io::{BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

fn family(name: &str) -> Option<Vec<Algo>> {
    // Every level each crate accepts.
    let crush = |f: fn(i32) -> Algo, lo: i32, hi: i32| (lo..=hi).map(f).collect::<Vec<_>>();
    Some(match name {
        "lzfse" => [vec![Algo::Lzfse], crush(Algo::CrushLzfse, crushlzfse::Level::MIN.0, crushlzfse::Level::MAX.0)].concat(),
        "zlib" => (1..=12).map(Algo::Zlib).collect(),
        "lzbitmap" => {
            [vec![Algo::Lzbitmap], crush(Algo::CrushLzbitmap, lzbitmap::Level::MIN.0, lzbitmap::Level::MAX.0)].concat()
        }
        "lz4" => [vec![Algo::Lz4], crush(Algo::CrushLz4, crushlz4::Level::MIN.0, crushlz4::Level::MAX.0)].concat(),
        _ => return None,
    })
}

fn spec(a: Algo) -> String {
    match a {
        Algo::Lzfse => "lzfse".into(),
        Algo::Lzbitmap => "lzbitmap".into(),
        Algo::Lz4 => "lz4".into(),
        Algo::Zlib(l) => format!("zlib:{l}"),
        Algo::CrushLzfse(l) => format!("crushlzfse:{l}"),
        Algo::CrushLzbitmap(l) => format!("crushlzbitmap:{l}"),
        Algo::CrushLz4(l) => format!("crushlz4:{l}"),
        other => format!("{other:?}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("sweep") if args.len() == 4 => sweep(&args[1], Path::new(&args[2]), Path::new(&args[3])),
        Some("analyze") if args.len() >= 2 => {
            let full = args[1] == "--full";
            analyze(&args[if full { 2 } else { 1 }..], full)
        }
        _ => {
            eprintln!("usage: race_frontier sweep <lzfse|zlib|lzbitmap|lz4> <corpus-dir> <out.tsv>");
            eprintln!("       race_frontier analyze [--full] <tsv>...");
            std::process::exit(2);
        }
    }
}

// ---------------------------------------------------------------- sweep

fn sweep(fam: &str, dir: &Path, out: &Path) {
    let algos = family(fam).unwrap_or_else(|| panic!("unknown family {fam:?}"));
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read corpus dir")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.is_file())
        .collect();
    paths.sort();
    let files: Vec<Vec<u8>> = paths.iter().map(|p| std::fs::read(p).expect("read corpus file")).collect();
    let total: u64 = files.iter().map(|f| f.len() as u64).sum();
    let flat: Vec<(usize, usize, usize)> = files
        .iter()
        .enumerate()
        .flat_map(|(fi, f)| chunker::chunk_ranges(f.len() as u64).into_iter().map(move |(s, e)| (fi, s, e)))
        .collect();
    eprintln!("{fam}: {} files, {:.1} MiB, {} chunks, {} levels", files.len(), mib(total), flat.len(), algos.len());

    // Per candidate: encode seconds, and per file (bytes, decode ns).
    let mut enc_secs = Vec::new();
    let mut per_file: Vec<Vec<(u64, u64)>> = Vec::new();
    for &a in &algos {
        let start = Instant::now();
        let chunks: Vec<Option<Vec<u8>>> = flat
            .par_iter()
            .map_init(EncodeScratch::default, |s, &(fi, lo, hi)| algo::compress_chunk_with_scratch(&files[fi][lo..hi], a, s))
            .collect();
        let secs = start.elapsed().as_secs_f64();

        let mut rows = vec![(0u64, 0u64); files.len()];
        for (&(fi, lo, hi), c) in flat.iter().zip(&chunks) {
            let orig = &files[fi][lo..hi];
            let t = Instant::now();
            // A chunk that did not shrink is stored raw, so reading it is a copy.
            let back = match c {
                Some(c) => algo::decompress_chunk(c, a, orig.len()),
                None => Some(orig.to_vec()),
            };
            rows[fi].1 += t.elapsed().as_nanos() as u64;
            assert_eq!(back.as_deref(), Some(orig), "{} failed to round-trip {}", spec(a), paths[fi].display());
            rows[fi].0 += c.as_ref().map_or(orig.len(), Vec::len) as u64;
        }
        let bytes: u64 = rows.iter().map(|r| r.0).sum();
        let dec: u64 = rows.iter().map(|r| r.1).sum();
        eprintln!(
            "  {:<16} ratio {:.4}  enc {:>8.1} MiB/s  dec {:>8.1} MiB/s",
            spec(a),
            bytes as f64 / total as f64,
            mib(total) / secs,
            mib(total) / (dec as f64 / 1e9)
        );
        enc_secs.push(secs);
        per_file.push(rows);
    }

    let mut w = BufWriter::new(std::fs::File::create(out).expect("create output"));
    let names: Vec<String> = algos.iter().map(|&a| spec(a)).collect();
    writeln!(w, "#candidates\t{}", names.join("\t")).unwrap();
    writeln!(w, "#enc_secs\t{}", enc_secs.iter().map(|s| format!("{s:.6}")).collect::<Vec<_>>().join("\t")).unwrap();
    for (fi, p) in paths.iter().enumerate() {
        let mut line = format!("{}\t{}", p.display(), files[fi].len());
        for rows in &per_file {
            let _ = write!(line, "\t{}\t{}", rows[fi].0, rows[fi].1);
        }
        writeln!(w, "{line}").unwrap();
    }
}

// -------------------------------------------------------------- analyze

struct Candidate {
    name: String,
    family: String,
    enc_secs: f64,
    /// Per file: (compressed bytes, decode ns).
    files: Vec<(u64, u64)>,
}

fn load(paths: &[String]) -> (Vec<u64>, Vec<Candidate>) {
    let mut sizes: Option<Vec<(String, u64)>> = None;
    let mut cands = Vec::new();
    for p in paths {
        let f = std::io::BufReader::new(std::fs::File::open(p).expect("open tsv"));
        let mut lines = f.lines().map(Result::unwrap);
        let names: Vec<String> = lines.next().unwrap().split('\t').skip(1).map(str::to_owned).collect();
        let secs: Vec<f64> = lines.next().unwrap().split('\t').skip(1).map(|s| s.parse().unwrap()).collect();
        let fam = Path::new(p).file_stem().unwrap().to_string_lossy().into_owned();
        let first = cands.len();
        for (n, s) in names.iter().zip(&secs) {
            cands.push(Candidate { name: n.clone(), family: fam.clone(), enc_secs: *s, files: Vec::new() });
        }
        let mut these = Vec::new();
        for line in lines {
            let cols: Vec<&str> = line.split('\t').collect();
            these.push((cols[0].to_owned(), cols[1].parse::<u64>().unwrap()));
            for (k, pair) in cols[2..].chunks(2).enumerate() {
                cands[first + k].files.push((pair[0].parse().unwrap(), pair[1].parse().unwrap()));
            }
        }
        match &sizes {
            None => sizes = Some(these),
            Some(prev) => assert_eq!(prev, &these, "{p} was swept over a different corpus"),
        }
    }
    (sizes.unwrap().into_iter().map(|(_, s)| s).collect(), cands)
}

struct Point {
    members: Vec<usize>,
    bytes: u64,
    enc_secs: f64,
    dec_ns: u64,
    /// Original bytes of the files each member won.
    wins: Vec<u64>,
}

fn analyze(paths: &[String], full: bool) {
    let (sizes, cands) = load(paths);
    let total: u64 = sizes.iter().sum();
    eprintln!("{} files, {:.1} MiB, {} candidates\n", sizes.len(), mib(total), cands.len());

    // Members are listed fastest-decoding format first, so an exact tie goes
    // to the faster read, the same ordering advice the README gives for --algo.
    // Each group is the union of one or more races, each race naming the
    // families it draws one level from.
    let groups: &[(&str, &[&[&str]])] = &[
        ("zlib", &[&["zlib"]]),
        ("lzfse", &[&["lzfse"]]),
        ("lzbitmap", &[&["lzbitmap"]]),
        ("lzfse + zlib", &[&["lzfse", "zlib"]]),
        ("lzbitmap + lzfse + zlib", &[&["lzbitmap", "lzfse", "zlib"]]),
        ("lz4 + lzbitmap + lzfse + zlib  [macOS 27+]", &[&["lz4", "lzbitmap", "lzfse", "zlib"]]),
        ("lz4 + lzbitmap  [macOS 27+]", &[&["lz4", "lzbitmap"]]),
        ("lz4 + lzbitmap + lzfse  [macOS 27+]", &[&["lz4", "lzbitmap", "lzfse"]]),
        (
            "any race over lzbitmap, lzfse, zlib  [--race-level candidates]",
            &[
                &["lzbitmap"],
                &["lzfse"],
                &["zlib"],
                &["lzbitmap", "lzfse"],
                &["lzbitmap", "zlib"],
                &["lzfse", "zlib"],
                &["lzbitmap", "lzfse", "zlib"],
            ],
        ),
    ];
    let reference = cands.iter().position(|c| c.name == "lzfse");

    for (title, races) in groups {
        let mut combos = Vec::new();
        for fams in *races {
            let per_fam: Vec<Vec<usize>> =
                fams.iter().map(|f| (0..cands.len()).filter(|&i| cands[i].family == *f).collect()).collect();
            if per_fam.iter().any(Vec::is_empty) {
                combos.clear();
                break;
            }
            combos.extend(product(&per_fam));
        }
        if combos.is_empty() {
            eprintln!("=== {title}: skipped, a family was not swept\n");
            continue;
        }
        let points: Vec<Point> = combos.into_par_iter().map(|m| race(&m, &cands, &sizes)).collect();

        println!("=== {title}  ({} combos)", points.len());
        if let Some(r) = reference {
            let p = race(&[r], &cands, &sizes);
            println!("    reference: Apple lzfse  ratio {:.4}", p.bytes as f64 / total as f64);
        }
        // One family means one decoder, so a decode frontier would only rank noise.
        let axes: &[(&str, bool)] = if races.iter().any(|r| r.len() > 1) { &[("encode", false), ("decode", true)] } else { &[("encode", false)] };
        for &(axis, key) in axes {
            let front = frontier(&points, total, key);
            let speed = |p: &Point| if key { mib(total) / (p.dec_ns as f64 / 1e9) } else { mib(total) / p.enc_secs };
            // The frontier is fastest-first with strictly improving ratio, so
            // the densest point at or above a speed is the last one that clears it.
            let shown: Vec<usize> = if full {
                front
            } else {
                let mut v: Vec<usize> = TIERS_MIBPS
                    .iter()
                    .filter_map(|&t| front.iter().rev().copied().find(|&i| speed(&points[i]) >= t))
                    .collect();
                v.dedup();
                v
            };
            println!("  {} by {axis} speed:", if full { "frontier" } else { "densest race at or above each speed" });
            println!("    {:>7} {:>10} {:>10}  combo (share of input each member won)", "ratio", "enc MiB/s", "dec MiB/s");
            for i in shown {
                let p = &points[i];
                let label: Vec<String> = p
                    .members
                    .iter()
                    .zip(&p.wins)
                    .map(|(&m, &w)| format!("{} {:.0}%", cands[m].name, 100.0 * w as f64 / total as f64))
                    .collect();
                println!(
                    "    {:>7.4} {:>10.1} {:>10.1}  {}",
                    p.bytes as f64 / total as f64,
                    mib(total) / p.enc_secs,
                    mib(total) / (p.dec_ns as f64 / 1e9),
                    label.join(", ")
                );
            }
        }
        println!();
    }
}

/// Speed ladder for the condensed view, in MiB/s.
const TIERS_MIBPS: &[f64] = &[4000.0, 2000.0, 1000.0, 500.0, 250.0, 100.0, 50.0, 25.0, 0.0];

fn product(sets: &[Vec<usize>]) -> Vec<Vec<usize>> {
    sets.iter().fold(vec![Vec::new()], |acc, set| {
        acc.iter().flat_map(|prefix| set.iter().map(move |&x| [prefix.as_slice(), &[x]].concat())).collect()
    })
}

fn race(members: &[usize], cands: &[Candidate], sizes: &[u64]) -> Point {
    let mut p = Point {
        members: members.to_vec(),
        bytes: 0,
        enc_secs: members.iter().map(|&m| cands[m].enc_secs).sum(),
        dec_ns: 0,
        wins: vec![0; members.len()],
    };
    for (fi, &size) in sizes.iter().enumerate() {
        let (k, &m) = members.iter().enumerate().min_by_key(|&(k, &m)| (cands[m].files[fi].0, k)).unwrap();
        let (bytes, dec) = cands[m].files[fi];
        p.bytes += bytes;
        p.dec_ns += dec;
        p.wins[k] += size;
    }
    p
}

/// Points no other point beats on both ratio and the chosen speed, fastest
/// first.
fn frontier(points: &[Point], total: u64, by_decode: bool) -> Vec<usize> {
    let speed = |p: &Point| if by_decode { mib(total) / (p.dec_ns as f64 / 1e9) } else { mib(total) / p.enc_secs };
    let mut idx: Vec<usize> = (0..points.len()).collect();
    idx.sort_by(|&a, &b| speed(&points[b]).total_cmp(&speed(&points[a])).then(points[a].bytes.cmp(&points[b].bytes)));
    let mut best = u64::MAX;
    idx.into_iter()
        .filter(|&i| {
            let keep = points[i].bytes < best;
            best = best.min(points[i].bytes);
            keep
        })
        .collect()
}

fn mib(b: u64) -> f64 {
    b as f64 / (1024.0 * 1024.0)
}
