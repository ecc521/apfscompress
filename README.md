# apfscompress

Transparent file compression for APFS. 

Supports LZFSE, LZVN, LZBITMAP, LZ4 and zlib, with `Compression.framework` encoders,
[crush-lz](https://github.com/ecc521/crush-lz) encoders, and libdeflate.

## Quick start

```bash
cargo install apfscompress
apfscompress estimate /Applications
apfscompress compress ~/Documents/archive
apfscompress compress --race-level 6 -j 8 big-dataset/
```

`estimate` predicts savings without modifying files. `compress` processes
eligible files recursively. The default is race level 9.

## Usage

| command | purpose |
|---|---|
| `compress <path>` | Compress a file or eligible files under a directory |
| `decompress <path>` | Decompress a file or compressed files under a directory |
| `estimate <path>` | Estimate savings without modifying files |
| `info <path>` | Report decmpfs status for a file or directory |
| `sweep <path>` | Remove orphaned staging files left after a crash |
| `algos` | List encoders, decmpfs types and kernel support |
| `dmg <app or dmg> -o <out.dmg>` | Create a disk image containing compressed files |

Run `apfscompress <command> --help` for all options.

### Selecting encoders

`--race-level 0..10` selects a predefined encoder combination, from fastest
to densest. `--algo` selects one encoder or a comma-separated set:

```bash
apfscompress compress --algo crushlzfse:8 archive/
apfscompress compress --algo crushlzbitmap:9,crushlzfse:10 archive/
```

| encoder | levels | default level |
|---|---|---|
| `lzfse`, `lzvn`, `lzbitmap`, `lz4` | Apple encoders; no level parameter | — |
| `crushlzfse` | -5 to 11 | 8 |
| `crushlzvn` | -5 to 10 | 8 |
| `crushlzbitmap` | -5 to 12 | 7 |
| `crushlz4` | -5 to 10 | 6 |
| `zlib` | 1 to 12 (libdeflate) | 12 |
| `stored` | Uncompressed decmpfs data | — |

`--algo` and `--race-level` are mutually exclusive. Kernel support is checked
before compression; use `apfscompress algos` to inspect available formats.
LZ4 decmpfs support requires macOS 27.0.

For large files, candidates compress up to 5 MiB of sample chunks spread
across the file. The candidate with the smallest sampled footprint encodes
the remaining chunks. Files covered by the sample are compared in full.
Exact ties select the first listed encoder; predefined races list
faster-decoding formats first.

`estimate` uses the same sampling policy and extrapolates unsampled data.
Its `--probe-size` option changes the sample size in bytes.

### File selection and writes

Compression writes to a staged clone, reads it back through the kernel,
compares its contents with the original, and replaces the original only
after verification. `--no-paranoid` disables the read-back comparison.

By default:

- Results that increase the file's compressed footprint are rejected.
- Already-compressed files are skipped. Use `--recompress if-different-algo`
  or `--recompress always` to reconsider them.
- Hard-linked files, sparse files, files with resource forks, and files with
  setuid or setgid permissions are skipped.
- Files open or mapped for writing are skipped when the process can be inspected.
  Files changed during compression are left unchanged by the tool.
- Clone-shared files are skipped when compression would write more space
  than it releases. Exact clones are skipped.
- The maximum input file size is 4 GiB. The minimum defaults to the filesystem's
  block size.

Useful options:

| option | purpose |
|---|---|
| `--dry-run` | Report compression or decompression decisions without writing |
| `--max-ratio 0.8` | Require at least 20% reduction against the size basis |
| `--max-file-size BYTES`, `--min-file-size BYTES` | Set file-size limits |
| `--min-age 7d` | Skip recently modified files |
| `--skip-extensions zip,jpg` | Exclude extensions; none are excluded by default |
| `-j N` | Set worker count; default is one per logical core |

When recompressing, the size basis is the current compressed footprint.
For clone-shared files, acceptance also accounts for blocks that remain
allocated to other clones.

## Shipping an app pre-compressed

```bash
apfscompress dmg MyApp.app -o MyApp.dmg
apfscompress dmg MyApp.dmg -o MyApp-small.dmg
```

An app input produces a disk image with an Applications link. Rebuilding an
existing image preserves its layout, background, volume icon, image format
and filesystem unless overridden.

The command selects compression formats supported by the oldest
`LSMinimumSystemVersion` declared by apps in the image. Use `--min-macos`
to override it, or when no app declares a minimum. LZBITMAP requires macOS 12;
LZ4 requires macOS 27. App inputs default to UDZO with HFS+; use `--format`
and `--filesystem` to override these settings.

The resulting image is mounted and checked for file contents and retained
compression. File contents do not change, so app code signatures remain valid.
Sign, notarize and staple the resulting image as usual.

Finder, `ditto` and `NSFileManager` preserve compression when copying files.
`cp -R` and zip archives do not. Zip-based app updates therefore install
uncompressed files.

Example sizes:

| app | installed, as shipped | installed, pre-compressed | image, UDZO |
|---|---|---|---|
| Google Chrome 154 (universal) | 1432 MB | 659 MB | 733 → 657 MB |
| Obsidian 1.8.10 | 458 MB | 178 MB | 206 → 180 MB |

## Benchmarks

[crush-lz corpus](https://github.com/ecc521/crush-lz#reproducing-the-corpus):
500 one-MiB segments, 8,000 chunks. Apple M5 Max, macOS 27.3.
Every family was swept four times; tables use median encode times and
each candidate's decode pass nearest its median total decode time.
Ratio is compressed payload size divided by input size; APFS and decmpfs
metadata overhead is excluded.

Encode throughput is aggregate across 18 cores. Race throughput is calculated
from the sum of its members' measured encode times. Decode throughput is
on one Super core through the system decoder, using the winning format for
each file. These figures measure codec work, excluding filesystem writes
and kernel read-back verification.

### Comparison

| | Ratio | Encode MiB/s | Decode MiB/s |
|---|---|---|---|
| Apple's LZFSE encoder | 0.2942 | 2,683 | 2,005 |
| `--race-level 3` | 0.2803 | 1,346 | 2,138 |
| `--race-level 6` | 0.2728 | 295 | 1,799 |
| **Default (race level 9)** | **0.2620** | **58** | **1,910** |
| `--race-level 10` | 0.2615 | 39 | 1,885 |

### Race levels

| Level | Race | Ratio | Encode MiB/s | Decode MiB/s |
|---|---|---|---|---|
| 0 | `crushlzfse:-2` | 0.3057 | 9,084 | 1,967 |
| 1 | `crushlzfse:-1` | 0.2979 | 6,531 | 1,961 |
| 2 | `zlib:6` | 0.2842 | 2,604 | 1,309 |
| 3 | `crushlzbitmap:0` + `crushlzfse:5` | 0.2803 | 1,346 | 2,138 |
| 4 | `crushlzbitmap:1` + `crushlzfse:5` + `zlib:6` | 0.2783 | 868 | 1,638 |
| 5 | `crushlzbitmap:5` + `crushlzfse:5` + `zlib:8` | 0.2768 | 517 | 1,579 |
| 6 | `crushlzbitmap:3` + `crushlzfse:6` + `zlib:7` | 0.2728 | 295 | 1,799 |
| 7 | `crushlzbitmap:1` + `crushlzfse:8` | 0.2671 | 170 | 1,915 |
| 8 | `crushlzbitmap:5` + `crushlzfse:9` | 0.2638 | 110 | 1,904 |
| **9** | `crushlzbitmap:9` + `crushlzfse:10` | **0.2620** | **58** | **1,910** |
| 10 | `crushlzbitmap:8` + `crushlzfse:11` | 0.2615 | 39 | 1,885 |

### Encoder combinations

Minimum ratio at each encode-throughput threshold:

| Encode speed | zlib | crushlzfse | crushlzfse + zlib | + crushlzbitmap |
|---|---|---|---|---|
| >= 1,000 MiB/s | 0.2817 | 0.2821 | 0.2797 | 0.2792 |
| >= 250 MiB/s | 0.2752 | 0.2711 | 0.2709 | 0.2701 |
| >= 100 MiB/s | 0.2742 | 0.2644 | 0.2644 | 0.2638 |
| >= 50 MiB/s | 0.2742 | 0.2631 | 0.2626 | 0.2618 |
| any | 0.2742 | 0.2625 | 0.2621 | 0.2610 |

### Races restricted to LZBITMAP and LZ4

| Race | Ratio | Encode MiB/s | Decode MiB/s |
|---|---|---|---|
| `lzbitmap` (Apple) | 0.3372 | 6,222 | 4,820 |
| `crushlzbitmap:12` | 0.3071 | 41 | 4,746 |
| `crushlz4:10` + `crushlzbitmap:12` *(macOS 27+)* | 0.3030 | 37 | 4,935 |

### Reproduction

```bash
bench/race_frontier.sh
```

The script sweeps each encoder family over
`../crush-lz/corpus/segments/main` and writes data and a summary to
`target/race_frontier/`. It does not edit this README or the race profiles.
Run it on an idle machine. To show the complete frontier:

```bash
target/release/race_frontier analyze --full target/race_frontier/*.tsv
```

After encoder changes, rerun the sweep and update the benchmark tables and
[`policy::race_profile`](src/policy.rs) as needed.
Other benchmarks are in [`bench/src/bin/`](bench/src/bin).

## Building and testing

macOS is required. Source builds use a sibling crush-lz checkout; published
packages resolve those dependencies from crates.io.

```bash
git clone https://github.com/ecc521/crush-lz ../crush-lz
cargo build --release
cargo test
```

`cargo test` includes short decmpfs conformance and decoder-fuzzing runs.
See [CONTRIBUTING.md](CONTRIBUTING.md) for longer campaigns.

## License

MPL-2.0; see [LICENSE](LICENSE). Dependencies include code under BSD-2-Clause,
BSD-3-Clause, MIT, Apache-2.0 and Unicode-3.0 terms; see
[THIRD-PARTY.md](THIRD-PARTY.md). See [CONTRIBUTING.md](CONTRIBUTING.md)
for contribution terms.
