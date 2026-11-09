//! Orchestration: policy -> chunker/algo -> decmpfs -> swap. The chunked
//! path (`probe_gate`, then `stream_rest`) races candidate algorithms over a
//! bounded probe window to pick a winner and gate the shrink decision before
//! compressing the rest; see their doc comments. Inline (small-file)
//! compression races candidates in full, since there's nothing to bound.

use crate::algo::{self, Algo};
use crate::budget;
use crate::control::{Control, FileProgress};
use crate::decmpfs::{self, ChunkOutput};
use crate::fsops;
use crate::policy::{self, Config, SkipReason};
use crate::swap::{StagedFile, TargetSnapshot};
use crate::sys;
use std::fs::{self, FileTimes};
use std::io;
use std::os::macos::fs::MetadataExt as MacMetadataExt;
use std::path::Path;

const DECMPFS_XATTR: &str = "com.apple.decmpfs";
const RESOURCE_FORK_XATTR: &str = "com.apple.ResourceFork";

/// Where encoding reads its input: bytes already in memory, or a file read
/// with `pread` into a buffer from the input budget (`crate::budget`).
/// Files are read rather than memory-mapped because a map of a file another
/// process truncates raises SIGBUS inside the encoder, while a read just
/// comes back short (an `UnexpectedEof` error).
trait Input: Sync {
    fn len(&self) -> u64;
    /// Fills `dst` with the bytes at `offset`.
    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()>;
}

impl Input for &[u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }

    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()> {
        let start = offset as usize;
        dst.copy_from_slice(&self[start..start + dst.len()]);
        Ok(())
    }
}

/// A file being encoded, with its metadata as of opening it.
struct FileInput {
    file: fs::File,
    meta: fs::Metadata,
}

impl FileInput {
    fn open(path: &Path) -> io::Result<Self> {
        let file = open_nofollow(path)?;
        let meta = file.metadata()?;
        Ok(FileInput { file, meta })
    }
}

/// Opens `path` for reading, refusing a symlink in its last component.
fn open_nofollow(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)
}

impl Input for FileInput {
    fn len(&self) -> u64 {
        self.meta.len()
    }

    fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        self.file.read_exact_at(dst, offset)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Compressed { algo: Algo, original_size: u64, compressed_size: u64 },
    Skipped(SkipReason),
    /// Passed the skip checks but ended up not compressed anyway.
    NotWorthwhile { original_size: u64, reason: NotWorthwhileReason },
    /// Stopped by `Control::cancel`; the file is untouched.
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotWorthwhileReason {
    /// No candidate algorithm cleared `max_ratio`.
    RatioNotMet,
    /// A candidate cleared the ratio, but its compressed representation
    /// would exceed the resource-fork format's 32-bit chunk-offset ceiling
    /// (~4GiB - see `checked_offset`). A hard format limit, so this can
    /// surface even for a file under `Config.max_file_size`.
    ExceedsResourceForkLimit,
}

/// The result of a compression decision, in a shape the write path can act
/// on: `Chunked` keeps individual chunks rather than one assembled
/// resource-fork blob.
pub enum CompressedPayload {
    Inline(Vec<u8>),
    Chunked { header_xattr: Vec<u8>, chunks: Vec<ChunkOutput> },
}

/// Pure in-memory decision: given file contents and config, decides whether
/// compression is worthwhile and returns the winning algorithm plus the
/// payload to write (decmpfs header, and resource-fork chunks if chunked).
/// Returns `None` if no candidate clears `max_ratio`.
pub fn compress_bytes(data: &[u8], cfg: &Config) -> Option<(Algo, CompressedPayload)> {
    compress_bytes_against(data, cfg, data.len() as u64)
}

/// The size a candidate must beat for the file at `path`. An
/// already-`UF_COMPRESSED` file is measured against its current compressed
/// footprint; a fresh file against its logical `original_size`. See
/// `compress_bytes_against` for why. A failed footprint read falls back to
/// `original_size` rather than aborting.
fn recompression_basis(path: &Path, original_size: u64) -> u64 {
    let already_compressed = fs::symlink_metadata(path)
        .map(|m| (crate::sys::UF_COMPRESSED & m.st_flags()) != 0)
        .unwrap_or(false);
    if already_compressed {
        policy::current_compressed_footprint(path).unwrap_or(original_size)
    } else {
        original_size
    }
}

/// Same as `compress_bytes`, but the shrink-ratio target is computed against
/// `target_basis` instead of `data.len()`. This is the single source of
/// truth for the comparison basis: recompressing an already-compressed file
/// uses its current compressed footprint (`recompression_basis`), not its
/// logical size, so recompression can't look like a win just by comparing
/// against a bigger number. Every accept/reject downstream compares against
/// `target`, except `probe_gate`'s probe pre-gate, which can only
/// fail fast and never flips the footprint-based decision.
pub fn compress_bytes_against(data: &[u8], cfg: &Config, target_basis: u64) -> Option<(Algo, CompressedPayload)> {
    let target = policy::target_size(target_basis, cfg.max_ratio);

    if data.len() <= decmpfs::MAX_INLINE_PAYLOAD {
        compress_inline(data, cfg, target)
    } else {
        compress_chunked(data, cfg, target)
    }
}

fn compress_inline(data: &[u8], cfg: &Config, target: u64) -> Option<(Algo, CompressedPayload)> {
    let mut best: Option<(Algo, Vec<u8>)> = None;
    for &algo in cfg.algorithms.as_slice() {
        let payload = if algo == Algo::Stored {
            data.to_vec()
        } else {
            match algo::compress_chunk(data, algo) {
                Some(c) => c,
                None => continue,
            }
        };
        // max_inline_payload_for already nets out the Stored sentinel byte;
        // adding it again here would double-count it.
        if payload.len() > decmpfs::max_inline_payload_for(algo) {
            continue; // doesn't fit inline even though it "compressed"
        }
        let better = best.as_ref().is_none_or(|(_, b)| payload.len() < b.len());
        if better {
            best = Some((algo, payload));
        }
    }
    let (algo, payload) = best?;
    // Backstop: every surviving candidate was already checked against
    // max_inline_payload_for before being allowed into `best`.
    debug_assert!(
        payload.len() <= decmpfs::max_inline_payload_for(algo),
        "compress_inline selected a payload that doesn't actually fit inline"
    );
    let total = decmpfs::HEADER_LEN as u64
        + payload.len() as u64
        + if algo == Algo::Stored { 1 } else { 0 };
    if policy::cumulative_exceeds_target(total, target) {
        return None;
    }
    let xattr = decmpfs::build_inline(algo, data.len() as u64, &payload);
    Some((algo, CompressedPayload::Inline(xattr)))
}

/// `k` chunk indices spread evenly across `[0, n)`, starting at 0 - a
/// deterministic stand-in for "sample chunks scattered across the file".
/// Every index once `k >= n`.
fn scattered_indices(k: usize, n: usize) -> Vec<usize> {
    if n == 0 {
        return Vec::new();
    }
    let k = k.min(n).max(1);
    if k >= n {
        return (0..n).collect();
    }
    (0..k).map(|i| (i * n) / k).collect()
}

/// The winning candidate from `probe_chunked`, plus what its callers need
/// to finish or extrapolate the rest of the file.
struct ProbeOutcome {
    algo: Algo,
    /// The sampled chunks' indices, ascending.
    sampled: Vec<usize>,
    /// `algo`'s output for each of `sampled`, in the same order.
    chunks: Vec<ChunkOutput>,
    /// The whole file's chunk ranges, sampled or not.
    ranges: Vec<(usize, usize)>,
    probe_uncompressed_total: u64,
    /// `HEADER_LEN` + whole-file chunk-table overhead + the probe chunks'
    /// compressed bytes. Exact regardless of probe coverage; only the
    /// remainder is ever approximated (by `estimate_chunked`).
    footprint_so_far: u64,
}

/// Races every candidate algorithm over `cfg.probe_size` worth of chunks
/// spread evenly across the file, and keeps the smallest by full on-disk
/// footprint. A spread-out sample tracks a heterogeneous file's
/// compressibility far better than its first few MiB. Shared by
/// `probe_gate`, whose caller then encodes the rest, and `estimate_chunked`,
/// which extrapolates it, so an estimate predicts the same decision.
/// `None` if no candidate has a chunked form, or if `prog` is cancelled.
fn probe_chunked(input: &dyn Input, cfg: &Config, prog: &FileProgress) -> io::Result<Option<ProbeOutcome>> {
    let candidates: Vec<Algo> = cfg
        .algorithms
        .as_slice()
        .iter()
        .copied()
        .filter(|a| decmpfs::rsrc_type(*a).is_some()) // only algorithms with a chunked (resource-fork) form
        .collect();
    if candidates.is_empty() {
        return Ok(None);
    }

    let ranges = crate::chunker::chunk_ranges(input.len());

    // How many chunks (at least 1, so we always have a real sample) make up
    // `probe_size` bytes.
    let probe_chunk_count = ranges
        .iter()
        .take_while(|&&(s, _)| (s as u64) < cfg.probe_size)
        .count()
        .max(1)
        .min(ranges.len());
    let sampled = scattered_indices(probe_chunk_count, ranges.len());

    // The sampled chunks back to back, with their ranges within that. Runs
    // of adjacent chunks (all of them, when the probe covers the file) are
    // read in one go.
    let probe_uncompressed_total: u64 = sampled.iter().map(|&i| (ranges[i].1 - ranges[i].0) as u64).sum();
    let Some(mut sample) = budget::acquire(probe_uncompressed_total as usize, prog) else {
        return Ok(None);
    };
    let mut sample_ranges = Vec::with_capacity(sampled.len());
    let (mut run_start, mut filled) = (0, 0);
    for (n, &i) in sampled.iter().enumerate() {
        if sampled.get(n + 1) == Some(&(i + 1)) {
            continue; // the run goes on
        }
        let (first, last) = (sampled[run_start], i);
        let (start, end) = (ranges[first].0, ranges[last].1);
        input.read_at(start as u64, &mut sample[filled..filled + end - start])?;
        sample_ranges.extend(ranges[first..=last].iter().map(|&(s, e)| (filled + s - start, filled + e - start)));
        filled += end - start;
        run_start = n + 1;
    }

    // Race the probe window across every candidate, keep the smallest by
    // full footprint (caps peak memory at ~2x the probe's compressed size).
    let mut best: Option<(Algo, Vec<ChunkOutput>, u64)> = None;
    for &algo in &candidates {
        let overhead = decmpfs::rsrc_footprint_overhead(algo, ranges.len());
        let Some(chunks) = compress_range(&sample[..], algo, &sample_ranges, prog, false) else {
            return Ok(None);
        };
        let footprint =
            decmpfs::HEADER_LEN as u64 + overhead + chunks.iter().map(|c| c.bytes.len() as u64).sum::<u64>();
        if best.as_ref().is_none_or(|(_, _, b)| footprint < *b) {
            best = Some((algo, chunks, footprint));
        }
    }
    let (algo, chunks, footprint_so_far) = best.expect("candidates is non-empty");

    Ok(Some(ProbeOutcome { algo, sampled, chunks, ranges, probe_uncompressed_total, footprint_so_far }))
}

/// Where `encode_chunked` sends finished chunks, in file order.
trait ChunkSink {
    /// Called once, after the probe picks `algo` and before any `push`.
    fn begin(&mut self, algo: Algo, num_chunks: usize) -> io::Result<()>;
    fn push(&mut self, chunks: Vec<ChunkOutput>) -> io::Result<()>;
}

/// Keeps every chunk in memory, for `compress_bytes`.
#[derive(Default)]
struct CollectChunks(Vec<ChunkOutput>);

impl ChunkSink for CollectChunks {
    fn begin(&mut self, _algo: Algo, num_chunks: usize) -> io::Result<()> {
        self.0.reserve_exact(num_chunks);
        Ok(())
    }

    fn push(&mut self, chunks: Vec<ChunkOutput>) -> io::Result<()> {
        self.0.extend(chunks);
        Ok(())
    }
}

/// Chunks encoded per batch after the probe (32MiB of input). A file in
/// flight holds its probe plus one batch, whatever its size. Each batch ends
/// in a fork-join that idles workers on its slowest chunks; 128 chunks cost
/// a single large file about 3% wall time against no batching, 512 nothing
/// measurable.
const STREAM_BATCH_CHUNKS: usize = 512;

enum Encoded {
    Done { algo: Algo, footprint: u64 },
    RatioNotMet,
    Cancelled,
}

/// Races the probe (see `probe_chunked`) to pick a winner, and applies the
/// go/no-go shrink gate to it. `Err` with `RatioNotMet` or `Cancelled` when
/// the file stops here.
///
/// Picking from a sample means a heterogeneous file can land on a
/// slightly-worse algorithm, or be rejected where a full race would have
/// passed. Set `probe_size >= file size` to recover optimal selection.
fn probe_gate(input: &dyn Input, cfg: &Config, prog: &FileProgress) -> io::Result<Result<ProbeOutcome, Encoded>> {
    let Some(probe) = probe_chunked(input, cfg, prog)? else {
        return Ok(Err(if prog.cancelled() { Encoded::Cancelled } else { Encoded::RatioNotMet }));
    };
    let probe_target = policy::target_size(probe.probe_uncompressed_total, cfg.max_ratio);
    if policy::cumulative_exceeds_target(probe.footprint_so_far, probe_target) {
        return Ok(Err(Encoded::RatioNotMet));
    }
    prog.add(probe.probe_uncompressed_total);
    Ok(Ok(probe))
}

/// Encodes every chunk the probe didn't, with the winning algorithm, in
/// batches of `STREAM_BATCH_CHUNKS`. Each batch goes to `sink` in file
/// order with the probe's own chunks spliced back in, and encoding stops
/// as soon as the running footprint exceeds `target`. Holds one batch of
/// input and output at a time, plus the probe's output until its chunks
/// come up.
fn stream_rest(
    input: &dyn Input,
    probe: ProbeOutcome,
    target: u64,
    prog: &FileProgress,
    sink: &mut impl ChunkSink,
) -> io::Result<Encoded> {
    let ProbeOutcome { algo, sampled, chunks, ranges, mut footprint_so_far, .. } = probe;
    sink.begin(algo, ranges.len())?;
    let mut probed = sampled.into_iter().zip(chunks).peekable();
    for (b, batch) in ranges.chunks(STREAM_BATCH_CHUNKS).enumerate() {
        let first = b * STREAM_BATCH_CHUNKS;
        let start = batch[0].0;
        let mut out: Vec<Option<ChunkOutput>> = Vec::with_capacity(batch.len());
        let mut todo = Vec::new();
        for (i, &(s, e)) in (first..).zip(batch) {
            match probed.next_if(|(j, _)| *j == i) {
                Some((_, chunk)) => out.push(Some(chunk)),
                None => {
                    todo.push((s - start, e - start));
                    out.push(None);
                }
            }
        }
        if let Some(&(_, todo_end)) = todo.last() {
            let Some(mut data) = budget::acquire(todo_end, prog) else {
                return Ok(Encoded::Cancelled);
            };
            input.read_at(start as u64, &mut data)?;
            let encoded = compress_range(&data, algo, &todo, prog, true);
            drop(data); // returned to the budget before writing, so another file can read
            let Some(encoded) = encoded else {
                return Ok(Encoded::Cancelled);
            };
            footprint_so_far += encoded.iter().map(|c| c.bytes.len() as u64).sum::<u64>();
            if policy::cumulative_exceeds_target(footprint_so_far, target) {
                return Ok(Encoded::RatioNotMet);
            }
            let mut encoded = encoded.into_iter();
            for slot in out.iter_mut().filter(|slot| slot.is_none()) {
                *slot = encoded.next();
            }
        }
        sink.push(out.into_iter().map(|c| c.expect("every chunk is probed or encoded")).collect())?;
    }
    // Also covers a file the probe spanned entirely: when recompressing,
    // the whole-file target can be stricter than the probe's.
    if policy::cumulative_exceeds_target(footprint_so_far, target) {
        return Ok(Encoded::RatioNotMet);
    }
    Ok(Encoded::Done { algo, footprint: footprint_so_far })
}

/// `probe_gate` then `stream_rest`, for callers with nothing to do between.
fn encode_chunked(
    input: &dyn Input,
    cfg: &Config,
    target: u64,
    prog: &FileProgress,
    sink: &mut impl ChunkSink,
) -> io::Result<Encoded> {
    match probe_gate(input, cfg, prog)? {
        Ok(probe) => stream_rest(input, probe, target, prog, sink),
        Err(stopped) => Ok(stopped),
    }
}

/// `encode_chunked` into memory, for `compress_bytes`.
fn compress_chunked(data: &[u8], cfg: &Config, target: u64) -> Option<(Algo, CompressedPayload)> {
    let mut sink = CollectChunks::default();
    let encoded = encode_chunked(&data, cfg, target, &FileProgress::detached(), &mut sink)
        .expect("encoding in memory can't fail");
    let Encoded::Done { algo, footprint } = encoded else {
        return None;
    };
    let chunks = sink.0;
    // Disagreement would mean a silently corrupted decision.
    debug_assert_eq!(footprint, chunked_footprint(algo, chunks.len(), &chunks));
    Some((algo, CompressedPayload::Chunked { header_xattr: chunked_header(algo, data.len() as u64), chunks }))
}

/// The decmpfs xattr for a resource-fork-backed file.
fn chunked_header(algo: Algo, original_size: u64) -> Vec<u8> {
    let compression_type = decmpfs::rsrc_type(algo).expect("probe_chunked only picks chunked types");
    decmpfs::Header { compression_type, uncompressed_size: original_size }.to_bytes().to_vec()
}

/// Algorithm picked and predicted on-disk footprint for a savings estimate -
/// see `estimate_bytes_against`. `exact` is true when the whole file fit
/// inside `cfg.probe_size`, meaning `predicted_footprint` is the real,
/// fully-computed answer rather than an extrapolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EstimateOutcome {
    pub algo: Algo,
    pub predicted_footprint: u64,
    pub exact: bool,
}

/// Chunked counterpart to `estimate_input`'s inline branch: reuses
/// `probe_chunked`'s racing/go-no-go logic, the same sample compression
/// decides on. Once the probe passes, extrapolates the remainder from its observed
/// ratio instead of compressing it, so at most `cfg.probe_size` of real
/// compression is spent per file.
///
/// Known simplification: an extrapolated footprint near the resource-fork
/// format's ~4GiB ceiling isn't checked the way a real compression's
/// `RsrcWriter` is - rare, since it needs a many-GB file that barely
/// compresses.
fn estimate_chunked(input: &dyn Input, cfg: &Config, target: u64) -> io::Result<Option<EstimateOutcome>> {
    let Some(probe) = probe_chunked(input, cfg, &FileProgress::detached())? else {
        return Ok(None);
    };
    let probe_target = policy::target_size(probe.probe_uncompressed_total, cfg.max_ratio);

    if policy::cumulative_exceeds_target(probe.footprint_so_far, probe_target) {
        return Ok(None);
    }

    let exact = probe.sampled.len() >= probe.ranges.len();
    let predicted_footprint = if exact {
        probe.footprint_so_far
    } else {
        // Only the data portion of the remaining chunks is extrapolated -
        // header + full-file chunk-table overhead is already exact (folded
        // into footprint_so_far by probe_chunked).
        let overhead = decmpfs::rsrc_footprint_overhead(probe.algo, probe.ranges.len());
        let probe_data_bytes = probe.footprint_so_far - decmpfs::HEADER_LEN as u64 - overhead;
        let remaining_uncompressed = input.len() - probe.probe_uncompressed_total;
        let predicted_ratio = probe_data_bytes as f64 / probe.probe_uncompressed_total as f64;
        let predicted_remaining = (remaining_uncompressed as f64 * predicted_ratio).round() as u64;
        probe.footprint_so_far + predicted_remaining
    };

    if policy::cumulative_exceeds_target(predicted_footprint, target) {
        return Ok(None);
    }

    Ok(Some(EstimateOutcome { algo: probe.algo, predicted_footprint, exact }))
}

/// Predicts what compressing `input` would produce, without ever
/// compressing more than `cfg.probe_size` of it - see `estimate_chunked`
/// for the chunked path's extrapolation. The inline path is always cheap,
/// so it's computed for real via `compress_inline`.
fn estimate_input(input: &dyn Input, cfg: &Config, target_basis: u64) -> io::Result<Option<EstimateOutcome>> {
    let target = policy::target_size(target_basis, cfg.max_ratio);

    if input.len() <= decmpfs::MAX_INLINE_PAYLOAD as u64 {
        let mut data = vec![0; input.len() as usize];
        input.read_at(0, &mut data)?;
        let Some((algo, CompressedPayload::Inline(xattr))) = compress_inline(&data, cfg, target) else {
            return Ok(None);
        };
        Ok(Some(EstimateOutcome { algo, predicted_footprint: xattr.len() as u64, exact: true }))
    } else {
        estimate_chunked(input, cfg, target)
    }
}

/// Predicts what `compress_bytes_against` would produce - see
/// `estimate_input`.
pub fn estimate_bytes_against(data: &[u8], cfg: &Config, target_basis: u64) -> Option<EstimateOutcome> {
    estimate_input(&data, cfg, target_basis).expect("estimating in memory can't fail")
}

/// Same as `estimate_bytes_against`, but the shrink-ratio target is computed
/// against `data.len()` itself - the non-recompression-basis-aware
/// counterpart to `compress_bytes`.
pub fn estimate_bytes(data: &[u8], cfg: &Config) -> Option<EstimateOutcome> {
    estimate_bytes_against(data, cfg, data.len() as u64)
}

/// Per-file outcome of a savings estimate - the read-only counterpart to
/// `Outcome`, without a `swap`/write-mechanism field since nothing is ever
/// written. `should_skip`/basis logic is identical to `compress_file`'s
/// dry-run path (`dry_run_evaluate`); the difference is that a large file is
/// never fully compressed to find its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstimateFileOutcome {
    Estimated { algo: Algo, original_size: u64, predicted_compressed_size: u64, exact: bool },
    Skipped(SkipReason),
    NotWorthwhile { original_size: u64 },
}

/// Predicts what compressing `path` would do, reading it directly (no
/// staging) and bounding real compression to `cfg.probe_size` per file.
pub fn estimate_file(path: &Path, cfg: &Config) -> io::Result<EstimateFileOutcome> {
    if let Some(reason) = policy::should_skip(path, cfg)? {
        return Ok(EstimateFileOutcome::Skipped(reason));
    }

    let input = FileInput::open(path)?;
    let original_size = input.len();
    let target_basis = recompression_basis(path, original_size);

    match estimate_input(&input, cfg, target_basis)? {
        Some(EstimateOutcome { predicted_footprint, .. })
            if frees_too_little_for_clones(path, target_basis, predicted_footprint, cfg)? =>
        {
            Ok(EstimateFileOutcome::Skipped(SkipReason::SharedWithClones))
        }
        Some(EstimateOutcome { algo, predicted_footprint, exact }) => Ok(EstimateFileOutcome::Estimated {
            algo,
            original_size,
            predicted_compressed_size: predicted_footprint,
            exact,
        }),
        None => Ok(EstimateFileOutcome::NotWorthwhile { original_size }),
    }
}

/// Whether a `footprint`-byte compressed form of `path`, which passed
/// `basis`'s own target, would free too little because APFS clones share
/// its blocks: it exceeds `max_ratio` of the bytes compressing releases.
/// See `SkipReason::SharedWithClones`. During a staged write, call this only
/// once the staged clone has let go of the target's data (after
/// `commit_compressed`): until then it shares every block with the target.
fn frees_too_little_for_clones(path: &Path, basis: u64, footprint: u64, cfg: &Config) -> io::Result<bool> {
    if !cfg.skip_clones {
        return Ok(false);
    }
    let capped = policy::block_sharing(path)?.cap_basis(basis);
    Ok(policy::cumulative_exceeds_target(footprint, policy::target_size(capped, cfg.max_ratio)))
}

/// Total on-disk footprint of a chunked result: the 16-byte decmpfs header
/// (in `com.apple.decmpfs`) plus the full `com.apple.ResourceFork` blob
/// (chunk table + chunk data). `algo`-dependent since ZLIB (type 4) uses a
/// different on-disk layout with different fixed overhead than every other
/// chunked type - see `decmpfs::rsrc_footprint_overhead`.
fn chunked_footprint(algo: Algo, num_chunks: usize, chunks: &[ChunkOutput]) -> u64 {
    let data_total: u64 = chunks.iter().map(|c| c.bytes.len() as u64).sum();
    decmpfs::HEADER_LEN as u64 + decmpfs::rsrc_footprint_overhead(algo, num_chunks) + data_total
}

thread_local! {
    /// Encoder working memory, kept per thread across chunks, batches and
    /// files. `map_init` would rebuild it per rayon job split, which for
    /// streamed batches cost about 10% more CPU at level 9. The encoders
    /// never call back into rayon, so a worker can't re-enter the borrow.
    static ENCODE_SCRATCH: std::cell::RefCell<algo::EncodeScratch> =
        std::cell::RefCell::new(algo::EncodeScratch::default());
}

/// Frees the encoder scratch each thread of the current rayon pool holds
/// (tens of MB per thread at the denser levels). It is rebuilt on the next
/// compression, so call this when going idle, not between files.
pub fn release_scratch() {
    rayon::broadcast(|_| ENCODE_SCRATCH.take());
}

/// Compresses `ranges` of `data` in parallel, reusing each rayon worker's
/// `ENCODE_SCRATCH` rather than letting each encoder allocate and free its
/// own working memory on every chunk.
///
/// Always runs on the rayon pool, even for a range too small to split,
/// which rayon would otherwise encode on the calling thread: that would
/// put encoding (and its scratch) on the caller's threads, such as
/// `batch`'s drivers, on top of the pool's one per core.
///
/// Checks `prog` for cancellation before each chunk, returning `None` once
/// cancelled. With `count`, reports each chunk's input bytes to `prog`.
fn compress_range(
    data: &[u8],
    algo: Algo,
    ranges: &[(usize, usize)],
    prog: &FileProgress,
    count: bool,
) -> Option<Vec<ChunkOutput>> {
    use rayon::prelude::*;
    rayon::scope(|_| {
        ranges
            .par_iter()
            .map(|&(s, e)| {
                if prog.cancelled() {
                    return None;
                }
                let slice = &data[s..e];
                let compressed =
                    ENCODE_SCRATCH.with_borrow_mut(|scratch| algo::compress_chunk_with_scratch(slice, algo, scratch));
                if count {
                    prog.add(slice.len() as u64);
                }
                Some(decmpfs::encode_chunk(algo, slice, compressed))
            })
            .collect()
    })
}

/// Reads a compressed file's xattrs directly and decodes them - independent
/// of the kernel's transparent decompression on normal `read()`. Used for
/// the `decompress` CLI path and for validation mode.
pub fn decompress_bytes(path: &Path) -> io::Result<Vec<u8>> {
    let decmpfs_xattr = fsops::get_xattr(path, DECMPFS_XATTR)?;
    let rsrc = match decmpfs::Header::from_bytes(&decmpfs_xattr) {
        Some(h) if decmpfs::algo_for_type(h.compression_type)
            .is_some_and(|a| decmpfs::rsrc_type(a) == Some(h.compression_type)) =>
        {
            Some(fsops::get_xattr(path, RESOURCE_FORK_XATTR)?)
        }
        _ => None,
    };
    decompress_parts(&decmpfs_xattr, rsrc.as_deref())
}

/// `decompress_bytes` over the raw xattr values rather than a file: the
/// decmpfs xattr, and the resource fork for the chunked types. Makes no
/// assumption the input is well formed.
pub fn decompress_parts(decmpfs_xattr: &[u8], rsrc: Option<&[u8]>) -> io::Result<Vec<u8>> {
    let header = decmpfs::Header::from_bytes(decmpfs_xattr)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad decmpfs header"))?;
    let algo = decmpfs::algo_for_type(header.compression_type)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unrecognized compression type"))?;

    if decmpfs::rsrc_type(algo) == Some(header.compression_type) {
        let rsrc = rsrc.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing resource fork"))?;
        let ranges = if decmpfs::uses_zlib_container(algo) {
            decmpfs::parse_chunk_table_zlib(rsrc)
        } else {
            decmpfs::parse_chunk_table(rsrc)
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad chunk table"))?;
        // Cross-check against the header's own uncompressed_size before
        // allocating or indexing: a corrupted/crash-truncated xattr pair
        // could otherwise cause an unbounded allocation or an underflow
        // panic in `chunk_len`.
        if ranges.len() != decmpfs::chunk_count(header.uncompressed_size) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk table size disagrees with decmpfs header's uncompressed_size",
            ));
        }
        // Grown chunk by chunk rather than reserved up front: the size is only
        // the header's claim, and each chunk is bounded by the decoder anyway.
        let mut out = Vec::new();
        for (i, (start, end)) in ranges.iter().enumerate() {
            let chunk_len = decmpfs::chunk_len(header.uncompressed_size, i);
            let plain = decmpfs::decode_chunk(algo, &rsrc[*start..*end], chunk_len).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("chunk {i} failed to decode"))
            })?;
            out.extend_from_slice(&plain);
        }
        debug_assert_eq!(
            out.len() as u64,
            header.uncompressed_size,
            "decompress_bytes: reconstructed length doesn't match the header's claimed size"
        );
        Ok(out)
    } else {
        decmpfs::parse_inline(algo, decmpfs_xattr)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "inline payload failed to decode"))
    }
}

enum Verified {
    Match,
    Mismatch,
    Cancelled,
}

/// Reads `actual` (through the kernel's real decompression, a plain `read()`
/// like any other process) and `expected` side by side in fixed-size
/// blocks, so the check costs two buffers regardless of file size.
fn verify_matches(actual: &Path, expected: &Path, prog: &FileProgress) -> io::Result<Verified> {
    const VERIFY_BUF_SIZE: usize = 1024 * 1024;
    let (mut actual, mut expected) = (fs::File::open(actual)?, open_nofollow(expected)?);
    let (mut a, mut e) = (vec![0u8; VERIFY_BUF_SIZE], vec![0u8; VERIFY_BUF_SIZE]);
    loop {
        if prog.cancelled() {
            return Ok(Verified::Cancelled);
        }
        let n = fill(&mut actual, &mut a)?;
        if n != fill(&mut expected, &mut e)? || a[..n] != e[..n] {
            return Ok(Verified::Mismatch);
        }
        if n == 0 {
            return Ok(Verified::Match);
        }
    }
}

/// Reads until `buf` is full or `f` hits EOF.
fn fill(f: &mut fs::File, buf: &mut [u8]) -> io::Result<usize> {
    use std::io::Read;
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

/// Compresses `path` via a clone+rename swap, leaving `path` untouched on
/// any error, rejection, or cancellation. Equivalent to
/// [`compress_file_with`] with a fresh [`Control`].
pub fn compress_file(path: &Path, cfg: &Config) -> io::Result<Outcome> {
    compress_file_with(path, cfg, &Control::new())
}

/// [`compress_file`], cancellable and reporting progress through `ctl`.
///
/// Encodes into a clone of `path` and renames it over `path` only once it's
/// a complete compressed file, and `path` hasn't changed in the meantime.
/// Reading from a clone rather than `path`: `clonefile()` snapshots content
/// atomically, so a concurrent write can't leave us encoding a torn mix,
/// and `StagedFile::stage` rejects a clone that turns out to be a symlink.
pub fn compress_file_with(path: &Path, cfg: &Config, ctl: &Control) -> io::Result<Outcome> {
    let prog = FileProgress::new(ctl);
    let outcome = compress_file_inner(path, cfg, &prog)?;
    match outcome {
        Outcome::Compressed { original_size, .. } | Outcome::NotWorthwhile { original_size, .. } => {
            prog.finish(original_size)
        }
        Outcome::Skipped(_) => {
            prog.finish(fs::symlink_metadata(path).map_or(0, |m| if m.is_file() { m.len() } else { 0 }))
        }
        Outcome::Cancelled => {}
    }
    Ok(outcome)
}

fn compress_file_inner(path: &Path, cfg: &Config, prog: &FileProgress) -> io::Result<Outcome> {
    if prog.cancelled() {
        return Ok(Outcome::Cancelled);
    }
    if let Some(reason) = policy::should_skip(path, cfg)? {
        return Ok(Outcome::Skipped(reason));
    }
    if cfg.dry_run {
        return dry_run_evaluate(path, cfg, prog);
    }

    let input = FileInput::open(path)?;
    let snapshot = TargetSnapshot::of(&input.meta, path)?;
    match compress_from(path, &input, snapshot, cfg, prog) {
        // A read cut short by a truncation, say. Whatever the error, a
        // target that changed under us is reported as that.
        Err(_) if !snapshot.unchanged(path).unwrap_or(false) => Ok(Outcome::Skipped(SkipReason::ChangedDuringCompression)),
        other => other,
    }
}

/// Encodes `input`, the file at `path`, and only once the probe says it's
/// worth it stages a clone of `path` to write into and renames it over
/// `path`. A file the probe rejects costs no writes at all.
fn compress_from(
    path: &Path,
    input: &FileInput,
    snapshot: TargetSnapshot,
    cfg: &Config,
    prog: &FileProgress,
) -> io::Result<Outcome> {
    let basis = recompression_basis(path, input.len());
    let target = policy::target_size(basis, cfg.max_ratio);
    let plan = match plan(input, cfg, target, prog)? {
        Ok(plan) => plan,
        Err(outcome) => return Ok(outcome),
    };

    let mut output = match StagedFile::stage(path) {
        Err(e) if crate::swap::is_group_not_restorable(&e) => {
            return Ok(Outcome::Skipped(SkipReason::GroupNotRestorable));
        }
        staged => staged?,
    };
    // The clone must be of the very file that was read and will be encoded.
    if output.snapshot != snapshot {
        let _ = output.discard();
        return Ok(Outcome::Skipped(SkipReason::ChangedDuringCompression));
    }
    // As of opening it: our own reads may have moved atime since.
    output.original_times = FileTimes::new().set_accessed(input.meta.accessed()?).set_modified(input.meta.modified()?);
    match write_staged(path, &output, input, plan, basis, snapshot, cfg, prog) {
        Ok(outcome @ Outcome::Compressed { .. }) => {
            // Again just before the swap: a writer may have opened it since.
            if cfg.skip_open_for_writing && crate::openfiles::is_open_for_writing(path) {
                let _ = output.discard();
                return Ok(Outcome::Skipped(SkipReason::OpenForWriting));
            }
            if output.promote(path, &snapshot)? {
                Ok(outcome)
            } else {
                Ok(Outcome::Skipped(SkipReason::ChangedDuringCompression))
            }
        }
        other => {
            let _ = output.discard();
            other
        }
    }
}

/// Makes `output`, a clone of `path`, its compressed form, measured against
/// `basis` (see `recompression_basis`). Returns `Compressed` only once
/// `output` is complete, frees space despite any clones of `path`, is
/// verified under `cfg.paranoid`, and `path` is unchanged since `snapshot`.
#[allow(clippy::too_many_arguments)]
fn write_staged(
    path: &Path,
    output: &StagedFile,
    input: &FileInput,
    plan: Plan,
    basis: u64,
    snapshot: TargetSnapshot,
    cfg: &Config,
    prog: &FileProgress,
) -> io::Result<Outcome> {
    clear_compressed_state(&output.path)?;
    let rsrc = RsrcWriter::create(fsops::resource_fork_path(&output.path));
    let target = policy::target_size(basis, cfg.max_ratio);
    let encoding = match encode_rest(input, plan, target, prog, rsrc)? {
        Ok(encoding) => encoding,
        Err(outcome) => return Ok(outcome),
    };
    commit_compressed(output, &encoding.decmpfs_xattr)?;

    // Only now: until its data fork was emptied, `output` shared every block
    // with `path`.
    if frees_too_little_for_clones(path, basis, encoding.footprint(), cfg)? {
        return Ok(Outcome::Skipped(SkipReason::SharedWithClones));
    }

    // The kernel's real read-back of the output against the original, which
    // nothing touches until the rename. Proves the OS decodes what we wrote,
    // not just that our encoder and decoder agree.
    let verified = if cfg.paranoid { verify_matches(&output.path, path, prog)? } else { Verified::Match };
    if let Verified::Cancelled = verified {
        return Ok(Outcome::Cancelled);
    }
    // Tells a mismatch caused by someone else's write from a bad encode.
    // `promote` checks again, around the swap itself.
    if !snapshot.unchanged(path).unwrap_or(false) {
        return Ok(Outcome::Skipped(SkipReason::ChangedDuringCompression));
    }
    if let Verified::Mismatch = verified {
        return Err(io::Error::new(io::ErrorKind::InvalidData, VerifyMismatch { algo: encoding.algo }));
    }
    Ok(encoding.into_outcome(input.len()))
}

/// A clone of an already-compressed file carries its flag and decmpfs
/// xattrs; strip them so it can take new compressed content. Its data fork
/// is already empty. `should_skip` rejects files with a genuine resource
/// fork, so any found here is decmpfs's own.
fn clear_compressed_state(path: &Path) -> io::Result<()> {
    if fs::symlink_metadata(path)?.st_flags() & sys::UF_COMPRESSED == 0 {
        return Ok(());
    }
    fsops::clear_compressed_flag(path)?;
    for name in [DECMPFS_XATTR, RESOURCE_FORK_XATTR] {
        match fsops::remove_xattr(path, name) {
            Err(e) if e.raw_os_error() != Some(libc::ENOATTR) => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

/// Makes `output` a compressed file: decmpfs xattr, empty data fork, then
/// `UF_COMPRESSED` and the original times. Flag and times share one fd,
/// opened before the flag is set: a fresh open() on an already-flagged file
/// silently decompresses it, and chflags(UF_COMPRESSED) itself bumps mtime.
fn commit_compressed(output: &StagedFile, decmpfs_xattr: &[u8]) -> io::Result<()> {
    fsops::set_xattr(&output.path, DECMPFS_XATTR, decmpfs_xattr)?;
    output.truncate_data_fork()?;
    let f = fs::OpenOptions::new().write(true).open(&output.path)?;
    fsops::set_compressed_flag_fd(&f)?;
    f.set_times(output.original_times)?;
    Ok(())
}

/// A finished encoding: the decmpfs xattr to set, plus whatever went to
/// the resource fork (nothing, for an inline file).
struct Encoding {
    algo: Algo,
    decmpfs_xattr: Vec<u8>,
    rsrc_len: u64,
}

impl Encoding {
    /// Bytes of xattrs this encoding writes.
    fn footprint(&self) -> u64 {
        self.decmpfs_xattr.len() as u64 + self.rsrc_len
    }

    fn into_outcome(self, original_size: u64) -> Outcome {
        Outcome::Compressed { algo: self.algo, original_size, compressed_size: self.footprint() }
    }
}

/// What can be settled before writing anything.
enum Plan {
    /// Small enough to encode whole, into the decmpfs xattr alone.
    Inline(Encoding),
    /// Resource-fork-backed, with the probe race won and its gate passed.
    Chunked(ProbeOutcome),
}

/// Decides `input`'s fate as far as it can without writing: encodes an
/// inline-sized file outright, or races and gates a larger file's probe.
/// `Ok(Err(outcome))` when the file stops here.
fn plan(input: &dyn Input, cfg: &Config, target: u64, prog: &FileProgress) -> io::Result<Result<Plan, Outcome>> {
    let original_size = input.len();
    let not_worthwhile = Err(Outcome::NotWorthwhile { original_size, reason: NotWorthwhileReason::RatioNotMet });
    if original_size <= decmpfs::MAX_INLINE_PAYLOAD as u64 {
        let mut data = vec![0; original_size as usize];
        input.read_at(0, &mut data)?;
        return Ok(match compress_inline(&data, cfg, target) {
            Some((algo, CompressedPayload::Inline(decmpfs_xattr))) => {
                Ok(Plan::Inline(Encoding { algo, decmpfs_xattr, rsrc_len: 0 }))
            }
            _ => not_worthwhile,
        });
    }
    Ok(match probe_gate(input, cfg, prog)? {
        Ok(probe) => Ok(Plan::Chunked(probe)),
        Err(Encoded::Cancelled) => Err(Outcome::Cancelled),
        Err(_) => not_worthwhile,
    })
}

/// Carries out `plan`, streaming a chunked file's remainder into `rsrc`.
/// `Ok(Err(outcome))` when it stopped short: not worthwhile, or cancelled.
fn encode_rest(
    input: &dyn Input,
    plan: Plan,
    target: u64,
    prog: &FileProgress,
    mut rsrc: RsrcWriter,
) -> io::Result<Result<Encoding, Outcome>> {
    let probe = match plan {
        Plan::Inline(encoding) => return Ok(Ok(encoding)),
        Plan::Chunked(probe) => probe,
    };
    let original_size = input.len();
    let not_worthwhile = |reason| Ok(Err(Outcome::NotWorthwhile { original_size, reason }));
    let result = stream_rest(input, probe, target, prog, &mut rsrc).and_then(|encoded| match encoded {
        Encoded::Done { algo, footprint } => {
            let rsrc_len = rsrc.finish()?;
            debug_assert_eq!(decmpfs::HEADER_LEN as u64 + rsrc_len, footprint);
            Ok(Ok(Encoding { algo, decmpfs_xattr: chunked_header(algo, original_size), rsrc_len }))
        }
        Encoded::RatioNotMet => not_worthwhile(NotWorthwhileReason::RatioNotMet),
        Encoded::Cancelled => Ok(Err(Outcome::Cancelled)),
    });
    match result {
        // Not a real failure: the result cleared the shrink ratio, but its
        // resource fork wouldn't fit the format's 32-bit offsets.
        Err(e) if is_resource_fork_too_large(&e) => not_worthwhile(NotWorthwhileReason::ExceedsResourceForkLimit),
        other => other,
    }
}

/// `plan` then `encode_rest`, for callers with nothing to do between.
fn encode_all(
    input: &dyn Input,
    cfg: &Config,
    target: u64,
    prog: &FileProgress,
    rsrc: RsrcWriter,
) -> io::Result<Result<Encoding, Outcome>> {
    match plan(input, cfg, target, prog)? {
        Ok(plan) => encode_rest(input, plan, target, prog, rsrc),
        Err(outcome) => Ok(Err(outcome)),
    }
}

/// `compress_file`'s dry-run path: the same skip, basis, and encoding
/// logic, reading `path` directly and writing nothing.
fn dry_run_evaluate(path: &Path, cfg: &Config, prog: &FileProgress) -> io::Result<Outcome> {
    let input = FileInput::open(path)?;
    let basis = recompression_basis(path, input.len());
    let target = policy::target_size(basis, cfg.max_ratio);
    Ok(match encode_all(&input, cfg, target, prog, RsrcWriter::measure())? {
        Ok(encoding) if frees_too_little_for_clones(path, basis, encoding.footprint(), cfg)? => {
            Outcome::Skipped(SkipReason::SharedWithClones)
        }
        Ok(encoding) => encoding.into_outcome(input.len()),
        Err(outcome) => outcome,
    })
}

/// Streams chunks into a resource fork in either of its layouts: chunk data
/// as it arrives, then the offset table (and ZLIB's footer) once every size
/// is known. `measure()` does the same layout arithmetic without any I/O,
/// so a dry run hits the same 4GiB ceiling (`checked_offset`) a real write
/// would.
///
/// ZLIB (decmpfs type 4) has a big-endian header, a mixed-endian
/// block-descriptor table and a fixed 50-byte footer; see
/// `decmpfs::ZLIB_RSRC_DESC_OFFSET`/`ZLIB_RSRC_FOOTER`. Every other type
/// uses a little-endian table of chunk end offsets.
struct RsrcWriter {
    path: Option<std::path::PathBuf>,
    file: Option<fs::File>,
    zlib: bool,
    data_start: u64,
    end: u64,
    sizes: Vec<u32>,
}

impl RsrcWriter {
    fn create(path: std::path::PathBuf) -> Self {
        RsrcWriter { path: Some(path), ..Self::measure() }
    }

    fn measure() -> Self {
        RsrcWriter { path: None, file: None, zlib: false, data_start: 0, end: 0, sizes: Vec::new() }
    }

    /// Accounts for one more chunk of `len` bytes, failing once the fork
    /// would outgrow its 32-bit offsets.
    fn record(&mut self, len: usize) -> io::Result<()> {
        self.end += len as u64;
        checked_offset(self.end)?;
        self.sizes.push(len as u32); // a chunk is at most 64KiB plus a sentinel byte
        Ok(())
    }

    /// Writes the table (and footer) and returns the fork's total length.
    fn finish(&mut self) -> io::Result<u64> {
        let n = self.sizes.len();
        let mut header = Vec::with_capacity(self.data_start as usize);
        let footer: &[u8] = if self.zlib {
            let desc_off = decmpfs::ZLIB_RSRC_DESC_OFFSET as u64;
            let base = desc_off + 4;
            let desc_block_len = checked_offset(self.end - desc_off)?;
            let footer_off = checked_offset(self.end)?;
            header.extend(checked_offset(desc_off)?.to_be_bytes());
            header.extend(footer_off.to_be_bytes());
            header.extend(desc_block_len.to_be_bytes());
            header.extend((decmpfs::ZLIB_RSRC_FOOTER.len() as u32).to_be_bytes());
            header.resize(desc_off as usize, 0); // zero padding up to desc_off - see ZLIB_RSRC_DESC_OFFSET
            header.extend((desc_block_len - 4).to_be_bytes());
            header.extend((n as u32).to_le_bytes());
            let mut start = self.data_start;
            for &len in &self.sizes {
                header.extend(checked_offset(start - base)?.to_le_bytes());
                header.extend(len.to_le_bytes());
                start += len as u64;
            }
            &decmpfs::ZLIB_RSRC_FOOTER
        } else {
            let mut end = self.data_start;
            header.extend(checked_offset(end)?.to_le_bytes());
            for &len in &self.sizes {
                end += len as u64;
                header.extend(checked_offset(end)?.to_le_bytes());
            }
            &[]
        };
        debug_assert_eq!(header.len() as u64, self.data_start);
        let len = self.end + footer.len() as u64;
        if let Some(f) = &self.file {
            use std::os::unix::fs::FileExt;
            f.write_all_at(&header, 0)?;
            f.write_all_at(footer, self.end)?;
            f.set_len(len)?;
        }
        Ok(len)
    }
}

impl ChunkSink for RsrcWriter {
    fn begin(&mut self, algo: Algo, num_chunks: usize) -> io::Result<()> {
        self.zlib = decmpfs::uses_zlib_container(algo);
        let footer_len = if self.zlib { decmpfs::ZLIB_RSRC_FOOTER.len() as u64 } else { 0 };
        self.data_start = decmpfs::rsrc_footprint_overhead(algo, num_chunks) - footer_len;
        self.end = self.data_start;
        self.sizes.reserve_exact(num_chunks);
        if let Some(path) = &self.path {
            let f = fs::OpenOptions::new().write(true).create(true).truncate(true).open(path)?;
            // Sized past any possible end first (every chunk stored raw),
            // then trimmed in `finish`: APFS speculatively reserves space
            // for a file that keeps growing through appends and never gives
            // it back, which cost up to 70% on a mid-size fork. Nothing is
            // allocated for the unwritten span.
            let worst_case = self.data_start + num_chunks as u64 * (decmpfs::CHUNK_SIZE as u64 + 1) + footer_len;
            f.set_len(worst_case)?;
            self.file = Some(f);
        }
        Ok(())
    }

    fn push(&mut self, chunks: Vec<ChunkOutput>) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        for c in &chunks {
            let at = self.end;
            self.record(c.bytes.len())?;
            if let Some(f) = &self.file {
                f.write_all_at(&c.bytes, at)?;
            }
        }
        Ok(())
    }
}

/// The error `compress_file` returns when paranoid verification finds the
/// kernel decodes the new file to something other than the original: an
/// encoder or format bug, since a concurrent write is reported as
/// `SkipReason::ChangedDuringCompression` instead. The original is untouched.
#[derive(Debug)]
pub struct VerifyMismatch {
    pub algo: Algo,
}

impl std::fmt::Display for VerifyMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "paranoid verification failed: {:?} output didn't read back as the original - staged file discarded", self.algo)
    }
}

impl std::error::Error for VerifyMismatch {}

/// The [`VerifyMismatch`] behind `e`, if that's what `e` is.
pub fn verify_mismatch(e: &io::Error) -> Option<&VerifyMismatch> {
    e.get_ref()?.downcast_ref()
}

/// Marks an `io::Error` as specifically "this file's compressed
/// representation doesn't fit the resource-fork format's 32-bit offsets" (see
/// `checked_offset`), as opposed to a genuine I/O failure (disk full,
/// permission denied, etc). `compress_file` downcasts on this to tell the two
/// apart: this one downgrades to `Outcome::NotWorthwhile`, real I/O errors
/// stay a hard `Err`.
#[derive(Debug)]
struct ResourceForkTooLarge;

impl std::fmt::Display for ResourceForkTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "resource fork exceeds 4GiB - decmpfs chunk table offsets are 32-bit")
    }
}

impl std::error::Error for ResourceForkTooLarge {}

/// The on-disk chunk table stores offsets as 32-bit fields (the real
/// decmpfs/ResourceFork format the kernel parses) - a resource fork whose
/// cumulative size exceeds `u32::MAX` would silently wrap into a corrupt
/// table via a bare `as u32` cast. Split out from
/// `write_resource_fork_streaming` so the boundary can be tested with a
/// synthetic offset instead of actually writing 4GiB to disk.
fn checked_offset(offset: u64) -> io::Result<u32> {
    u32::try_from(offset).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, ResourceForkTooLarge))
}

/// Whether `e` came specifically from `checked_offset`'s ceiling, as opposed
/// to any other I/O error `write_compressed` might have hit.
fn is_resource_fork_too_large(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.downcast_ref::<ResourceForkTooLarge>().is_some())
}

/// Reverses `compress_file`: stage two independent clones of `path` -> clear
/// flag/remove xattrs on one -> stream from the other (kernel-decompressed)
/// into it -> atomic rename. Two clones because clearing `UF_COMPRESSED` on
/// the read side would also flip its own reads to stop decompressing, so
/// read and write can't share one inode; this also lets `io::copy` stream
/// in bounded chunks instead of buffering the whole file.
///
/// Staging both before reading, same reason as `compress_file`: the clone
/// is the single point of truth, closing both the concurrent-write race and
/// the symlink-swap gap.
pub fn decompress_file(path: &Path) -> io::Result<()> {
    let compressed = StagedFile::stage(path)?; // read side: left compressed, kernel decompresses on read
    let plain = match StagedFile::stage(path) {
        Ok(p) => p,
        Err(e) => {
            let _ = compressed.discard();
            return Err(e);
        }
    };

    let result = (|| -> io::Result<()> {
        fsops::clear_compressed_flag(&plain.path)?;
        let _ = fsops::remove_xattr(&plain.path, RESOURCE_FORK_XATTR); // may not exist (inline types)
        fsops::remove_xattr(&plain.path, DECMPFS_XATTR)?;
        let mut reader = fs::File::open(&compressed.path)?; // kernel decompresses transparently
        let mut writer = fs::OpenOptions::new().write(true).truncate(true).open(&plain.path)?;
        // Full length first, so no write extends the file: APFS keeps the
        // space it speculatively reserves for a file growing through
        // appends (see `RsrcWriter::begin`).
        writer.set_len(reader.metadata()?.len())?;
        let copied = io::copy(&mut reader, &mut writer)?;
        writer.set_len(copied)?;
        writer.set_times(plain.original_times)?;
        Ok(())
    })();

    let snapshot = compressed.snapshot;
    let _ = compressed.discard(); // done with the read side either way

    match result {
        Ok(()) => match plain.promote(path, &snapshot)? {
            true => Ok(()),
            false => Err(io::Error::other("file changed during decompression - left as it is")),
        },
        Err(e) => {
            let _ = plain.discard();
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Algorithms;
    use tempfile::tempdir;

    fn compressible(n: usize) -> Vec<u8> {
        b"The quick brown fox jumps over the lazy dog. ".repeat(n)
    }

    #[test]
    fn file_input_refuses_a_symlink() {
        let dir = tempdir().unwrap();
        let (real, link) = (dir.path().join("real"), dir.path().join("link"));
        fs::write(&real, b"x").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(FileInput::open(&link).is_err());
        assert!(FileInput::open(&real).is_ok());
    }

    #[test]
    fn a_file_open_for_writing_is_skipped_then_compressed_once_closed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let data = compressible(5000);
        fs::write(&path, &data).unwrap();
        let writer = fs::OpenOptions::new().append(true).open(&path).unwrap();
        crate::openfiles::refresh();
        let outcome = compress_file(&path, &Config::default()).unwrap();
        assert!(matches!(outcome, Outcome::Skipped(SkipReason::OpenForWriting)), "{outcome:?}");
        assert_eq!(fs::read(&path).unwrap(), data);

        drop(writer);
        crate::openfiles::refresh();
        let outcome = compress_file(&path, &Config::default()).unwrap();
        assert!(matches!(outcome, Outcome::Compressed { .. }), "{outcome:?}");

        let cfg = Config { skip_open_for_writing: false, ..Config::default() };
        let other = dir.path().join("other");
        fs::write(&other, &data).unwrap();
        let _writer = fs::OpenOptions::new().append(true).open(&other).unwrap();
        crate::openfiles::refresh();
        assert!(matches!(compress_file(&other, &cfg).unwrap(), Outcome::Compressed { .. }), "the switch turns it off");
    }

    fn incompressible(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut x: u32 = 0xACE1u32;
        for _ in 0..n {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            v.push((x & 0xff) as u8);
        }
        v
    }

    #[test]
    fn compress_bytes_inline_picks_smallest_candidate() {
        let data = compressible(50); // small, stays under inline cap
        let cfg = Config { algorithms: Algorithms::custom(vec![Algo::Lzfse, Algo::Zlib(9)]).unwrap(), ..Config::default() };
        let (algo, payload) = compress_bytes(&data, &cfg).expect("should compress");
        let CompressedPayload::Inline(xattr) = payload else { panic!("expected Inline payload") };
        assert!(matches!(algo, Algo::Lzfse | Algo::Zlib(_)));
        let header = decmpfs::Header::from_bytes(&xattr).unwrap();
        assert_eq!(header.uncompressed_size, data.len() as u64);
    }

    #[test]
    fn stored_inline_capacity_boundary_is_exact() {
        // max_inline_payload_for(Stored) is net of the sentinel byte, so
        // exactly that many bytes must fit inline, one more must not. A
        // permissive ratio isolates the capacity check from Stored's growth.
        let cfg = Config {
            algorithms: Algorithms::custom(vec![Algo::Stored]).unwrap(),
            max_ratio: 2.0, // allow up to 2x growth
            ..Config::default()
        };

        let max_ok = incompressible(decmpfs::max_inline_payload_for(Algo::Stored));
        let (algo, payload) =
            compress_bytes(&max_ok, &cfg).expect("exactly-max-size Stored payload must fit inline");
        let CompressedPayload::Inline(xattr) = payload else { panic!("expected Inline payload") };
        assert_eq!(algo, Algo::Stored);
        assert_eq!(xattr.len(), decmpfs::MAX_XATTR_TOTAL); // header(16) + sentinel(1) + payload(3785)

        let one_too_big = incompressible(decmpfs::max_inline_payload_for(Algo::Stored) + 1);
        assert!(one_too_big.len() <= decmpfs::MAX_INLINE_PAYLOAD); // still routed through compress_inline
        assert!(
            compress_bytes(&one_too_big, &cfg).is_none(),
            "one byte over Stored's true capacity must be rejected"
        );
    }

    #[test]
    fn compress_bytes_chunked_includes_zlib_in_race() {
        // Zlib has a real chunked (type 4) form, so it's a legitimate racing
        // candidate for large files too.
        let data = compressible(20_000); // > MAX_INLINE_PAYLOAD, forces chunked path
        let cfg = Config { algorithms: Algorithms::custom(vec![Algo::Lzfse, Algo::Zlib(9)]).unwrap(), ..Config::default() };
        let (algo, payload) = compress_bytes(&data, &cfg).expect("should compress");
        let CompressedPayload::Chunked { header_xattr, chunks } = payload else {
            panic!("expected Chunked payload")
        };
        assert!(!chunks.is_empty());
        let header = decmpfs::Header::from_bytes(&header_xattr).unwrap();
        assert_eq!(header.compression_type, decmpfs::rsrc_type(algo).unwrap());
    }

    #[test]
    fn compress_bytes_rejects_incompressible_at_ratio_zero() {
        let data = incompressible(20_000);
        let cfg = Config::default(); // max_ratio = 1.0
        assert!(compress_bytes(&data, &cfg).is_none());
    }

    #[test]
    fn decompress_bytes_roundtrips_inline_and_chunked() {
        for size in [200usize, 20_000] {
            let data = compressible(size / 47 + 1);
            let data = &data[..data.len().min(size.max(200))];
            let cfg = Config::default();
            let Some((algo, payload)) = compress_bytes(data, &cfg) else {
                continue; // some tiny sizes may not clear the ratio, that's fine
            };
            // Simulate what compress_file would have written, using a real
            // temp file so get_xattr has something to read.
            let dir = tempdir().unwrap();
            let path = dir.path().join("f.bin");
            fs::write(&path, data).unwrap();
            match payload {
                CompressedPayload::Inline(xattr) => {
                    fsops::set_xattr(&path, DECMPFS_XATTR, &xattr).unwrap();
                }
                CompressedPayload::Chunked { header_xattr, chunks } => {
                    fsops::set_xattr(&path, DECMPFS_XATTR, &header_xattr).unwrap();
                    let rsrc = decmpfs::build_resource_fork_for(algo, &chunks);
                    fsops::set_xattr(&path, RESOURCE_FORK_XATTR, &rsrc).unwrap();
                }
            }
            let back = decompress_bytes(&path).unwrap();
            assert_eq!(&back, data);
        }
    }

    #[test]
    fn decompress_bytes_rejects_chunk_table_disagreeing_with_header() {
        // A chunk table that doesn't match the header's uncompressed_size
        // must error cleanly, not panic or silently truncate.
        let data = compressible(3000); // forces the chunked path
        let cfg = Config::default();
        let (algo, payload) = compress_bytes(&data, &cfg).expect("should compress");
        let CompressedPayload::Chunked { header_xattr, chunks } = payload else {
            panic!("expected Chunked payload")
        };
        let rsrc = decmpfs::build_resource_fork_for(algo, &chunks);

        let dir = tempdir().unwrap();
        let path = dir.path().join("corrupt.bin");
        fs::write(&path, &data).unwrap();

        // Tamper with the header's uncompressed_size so it implies a
        // different chunk count than the real table actually has.
        let mut bad_header = decmpfs::Header::from_bytes(&header_xattr).unwrap();
        bad_header.uncompressed_size += decmpfs::CHUNK_SIZE as u64 * 5;
        let bad_xattr = bad_header.to_bytes();
        fsops::set_xattr(&path, DECMPFS_XATTR, &bad_xattr).unwrap();
        fsops::set_xattr(&path, RESOURCE_FORK_XATTR, &rsrc).unwrap();

        let result = decompress_bytes(&path);
        assert!(result.is_err(), "mismatched chunk table/header must error, not panic or truncate silently");
    }

    #[test]
    fn compress_file_end_to_end_real_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("real.txt");
        let data = compressible(3000); // large enough to need the chunked path
        fs::write(&path, &data).unwrap();

        let cfg = Config { paranoid: true, ..Config::default() };
        let outcome = compress_file(&path, &cfg).unwrap();
        match outcome {
            Outcome::Compressed { compressed_size, original_size, .. } => {
                assert!(compressed_size < original_size);
            }
            other => panic!("expected Compressed, got {other:?}"),
        }

        // The real test: read through the normal fs::read path, exercising
        // actual kernel decompression, not our own decode logic.
        let read_back = fs::read(&path).unwrap();
        assert_eq!(read_back, data);

        // Second run should now skip (AlreadyCompressed).
        let outcome2 = compress_file(&path, &cfg).unwrap();
        assert_eq!(outcome2, Outcome::Skipped(SkipReason::AlreadyCompressed));
    }

    /// Confirms the promoted file's mtime/atime survive `StagedFile`'s own
    /// writes (decmpfs xattr, truncate). Back-dates the file first so a
    /// broken restore (leaving it at "now") can't pass by accident.
    #[test]
    fn compress_file_preserves_mtime_and_atime() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("real.txt");
        let data = compressible(3000); // large enough to need the chunked path
        fs::write(&path, &data).unwrap();

        let past = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        let times = fs::FileTimes::new().set_accessed(past).set_modified(past);
        fs::OpenOptions::new().write(true).open(&path).unwrap().set_times(times).unwrap();
        let before = fs::metadata(&path).unwrap();
        assert_eq!(before.modified().unwrap(), past, "test setup: back-dating didn't take");

        let outcome = compress_file(&path, &Config::default()).unwrap();
        assert!(matches!(outcome, Outcome::Compressed { .. }), "expected Compressed, got {outcome:?}");

        let after = fs::metadata(&path).unwrap();
        assert_eq!(after.modified().unwrap(), before.modified().unwrap(), "mtime must survive compression");
        assert_eq!(after.accessed().unwrap(), before.accessed().unwrap(), "atime must survive compression");
    }

    /// End-to-end version of `policy::tests::file_with_existing_resource_fork_is_skipped`:
    /// confirms `compress_file` itself leaves the foreign resource-fork
    /// content untouched, not just that `should_skip` reports the reason.
    #[test]
    fn compress_file_does_not_clobber_an_existing_resource_fork() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("has_icon.bin");
        fs::write(&path, compressible(3000)).unwrap(); // above MAX_INLINE_PAYLOAD, easily compressible
        fsops::set_xattr(&path, RESOURCE_FORK_XATTR, b"PRETEND_ICON_RESOURCE_DATA").unwrap();

        let outcome = compress_file(&path, &Config::default()).unwrap();
        assert_eq!(outcome, Outcome::Skipped(SkipReason::HasResourceFork));
        assert_eq!(fsops::get_xattr(&path, RESOURCE_FORK_XATTR).unwrap(), b"PRETEND_ICON_RESOURCE_DATA");
    }

    #[test]
    fn compress_file_many_chunks_in_probe_window_real_read() {
        // More chunks than any realistic core count, all within one probe
        // dispatch - checks dispatching many chunks at once still round-trips.
        let n_chunks = rayon::current_num_threads() * 3 + 5;
        let dir = tempdir().unwrap();
        let path = dir.path().join("many_chunks.bin");
        let data = compressible(n_chunks * decmpfs::CHUNK_SIZE / 47 + 1);
        fs::write(&path, &data).unwrap();

        let cfg = Config { paranoid: true, algorithms: Algorithms::single(Algo::Lzfse), ..Config::default() };
        let outcome = compress_file(&path, &cfg).unwrap();
        assert!(matches!(outcome, Outcome::Compressed { .. }));

        // Real kernel read-back, not our own decode path.
        assert_eq!(fs::read(&path).unwrap(), data);
    }

    // Type 4 (ZLIB resource fork): the layout was determined from files
    // written by macOS, so these tests exercise the real kernel decompressor,
    // not just our own decode_bytes path.

    #[test]
    fn zlib_type4_end_to_end_real_read_single_chunk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("zlib_single_chunk.bin");
        let data = compressible(3000); // > MAX_INLINE_PAYLOAD, one chunk
        fs::write(&path, &data).unwrap();

        let cfg = Config {
            paranoid: true,
            algorithms: Algorithms::single(Algo::Zlib(9)),
            ..Config::default()
        };
        let outcome = compress_file(&path, &cfg).unwrap();
        let Outcome::Compressed { algo: Algo::Zlib(_), compressed_size, original_size, .. } = outcome else {
            panic!("expected a Zlib compression, got {outcome:?}");
        };
        assert!(compressed_size < original_size);

        // The real test: read through the actual kernel decompressor.
        assert_eq!(fs::read(&path).unwrap(), data);
    }

    #[test]
    fn zlib_type4_end_to_end_real_read_multi_chunk() {
        // Several full 64KB chunks plus a short final chunk, exercising the
        // block-descriptor table with more than one tuple.
        let dir = tempdir().unwrap();
        let path = dir.path().join("zlib_multi_chunk.bin");
        let data = compressible(4 * decmpfs::CHUNK_SIZE / 47 + 1);
        fs::write(&path, &data).unwrap();

        let cfg = Config {
            paranoid: true,
            algorithms: Algorithms::single(Algo::Zlib(9)),
            ..Config::default()
        };
        let outcome = compress_file(&path, &cfg).unwrap();
        assert!(matches!(outcome, Outcome::Compressed { algo: Algo::Zlib(_), .. }), "expected Zlib, got {outcome:?}");
        assert_eq!(fs::read(&path).unwrap(), data);
    }

    #[test]
    fn zlib_type4_handles_incompressible_tail_chunk_via_real_kernel() {
        // A chunk that doesn't compress falls back to the 0xFF sentinel plus
        // raw bytes; the kernel must still read it back correctly.
        let dir = tempdir().unwrap();
        let path = dir.path().join("zlib_incompressible_tail.bin");
        let mut data = compressible(2 * decmpfs::CHUNK_SIZE / 47 + 1); // compresses well
        data.extend(incompressible(500)); // short incompressible tail chunk
        fs::write(&path, &data).unwrap();

        let cfg = Config {
            paranoid: true,
            max_ratio: 2.0, // the incompressible tail may cost a byte; allow it
            algorithms: Algorithms::single(Algo::Zlib(9)),
            ..Config::default()
        };
        let outcome = compress_file(&path, &cfg).unwrap();
        assert!(matches!(outcome, Outcome::Compressed { algo: Algo::Zlib(_), .. }), "expected Zlib, got {outcome:?}");
        assert_eq!(fs::read(&path).unwrap(), data);
    }

    #[test]
    fn zlib_type4_compress_then_decompress_round_trips_through_kernel() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("zlib_roundtrip.bin");
        let data = compressible(3000);
        fs::write(&path, &data).unwrap();

        let cfg = Config { algorithms: Algorithms::single(Algo::Zlib(9)), ..Config::default() };
        let outcome = compress_file(&path, &cfg).unwrap();
        assert!(matches!(outcome, Outcome::Compressed { algo: Algo::Zlib(_), .. }));
        assert_eq!(fs::read(&path).unwrap(), data);

        decompress_file(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), data);
        assert_eq!(policy::should_skip(&path, &Config::default()).unwrap(), None);
    }

    #[test]
    fn incompressible_file_larger_than_probe_window_is_rejected() {
        // A small custom probe_size exercises the boundary path directly
        // rather than relying on the file fitting the default window.
        let dir = tempdir().unwrap();
        let path = dir.path().join("random_large.bin");
        let data = incompressible(decmpfs::CHUNK_SIZE * 20); // 20 chunks, ~1.25MB
        fs::write(&path, &data).unwrap();

        let cfg = Config {
            probe_size: decmpfs::CHUNK_SIZE as u64 * 4, // window = first 4 chunks only
            algorithms: Algorithms::single(Algo::Lzfse),
            ..Config::default()
        };
        let outcome = compress_file(&path, &cfg).unwrap();
        assert!(matches!(outcome, Outcome::NotWorthwhile { .. }));
        assert_eq!(fs::read(&path).unwrap(), data); // untouched
    }

    #[test]
    fn race_larger_than_probe_window_rejects_via_probe() {
        // The probe gates the race path too: rejection must happen after
        // only the probe window is compressed per candidate.
        let dir = tempdir().unwrap();
        let path = dir.path().join("race_random_large.bin");
        let data = incompressible(decmpfs::CHUNK_SIZE * 20); // 20 chunks, ~1.25MB
        fs::write(&path, &data).unwrap();

        let cfg = Config {
            probe_size: decmpfs::CHUNK_SIZE as u64 * 4, // window = first 4 chunks only
            algorithms: Algorithms::custom(vec![Algo::Lzfse, Algo::Zlib(9)]).unwrap(),
            ..Config::default()
        };
        let outcome = compress_file(&path, &cfg).unwrap();
        assert!(matches!(outcome, Outcome::NotWorthwhile { .. }));
        assert_eq!(fs::read(&path).unwrap(), data); // untouched
    }

    #[test]
    fn file_that_passes_the_probe_but_fails_later_is_still_rejected() {
        // The probe window clears its own target easily, but the file as a
        // whole can't clear max_ratio because the much larger remainder
        // barely compresses. Uses a strict ratio (0.1) since the default
        // (1.0) is hard to construct this way (an incompressible tail costs
        // only ~1 byte/chunk via the stored-sentinel fallback).
        let dir = tempdir().unwrap();
        let path = dir.path().join("good_start_bad_finish.bin");
        let mut data = vec![0u8; decmpfs::CHUNK_SIZE * 2]; // probe window: trivially compressible
        data.extend(incompressible(decmpfs::CHUNK_SIZE * 20)); // rest: dominates the file, barely compresses
        fs::write(&path, &data).unwrap();

        let cfg = Config {
            max_ratio: 0.1, // requires 90% savings overall
            probe_size: decmpfs::CHUNK_SIZE as u64 * 2, // window = exactly the compressible part
            algorithms: Algorithms::single(Algo::Lzfse),
            ..Config::default()
        };
        let outcome = compress_file(&path, &cfg).unwrap();
        assert!(matches!(outcome, Outcome::NotWorthwhile { .. }), "expected rejection, got {outcome:?}");
        assert_eq!(fs::read(&path).unwrap(), data); // untouched
    }

    #[test]
    fn compress_then_decompress_file_round_trips_through_kernel() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("real2.txt");
        let data = compressible(3000);
        fs::write(&path, &data).unwrap();

        compress_file(&path, &Config::default()).unwrap();
        assert_eq!(fs::read(&path).unwrap(), data);

        decompress_file(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), data);

        // Should no longer be flagged compressed.
        assert_eq!(policy::should_skip(&path, &Config::default()).unwrap(), None);
    }

    #[test]
    fn decompress_file_keeps_mtime_and_takes_no_more_space_than_a_plain_write() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempdir().unwrap();
        let (path, plain) = (dir.path().join("restored.bin"), dir.path().join("plain.bin"));
        let data = compressible(60_000); // ~2.7MB: many chunks
        fs::write(&path, &data).unwrap();
        fs::write(&plain, &data).unwrap();
        let mtime = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
        fs::OpenOptions::new().write(true).open(&path).unwrap().set_times(FileTimes::new().set_modified(mtime)).unwrap();

        let cfg = Config { min_age: None, ..Config::default() };
        assert!(matches!(compress_file(&path, &cfg).unwrap(), Outcome::Compressed { .. }));
        decompress_file(&path).unwrap();

        let (restored, reference) = (fs::metadata(&path).unwrap(), fs::metadata(&plain).unwrap());
        assert_eq!(fs::read(&path).unwrap(), data);
        assert_eq!(restored.modified().unwrap(), mtime);
        assert!(
            restored.blocks() <= reference.blocks(),
            "restored {} blocks, plain write {}",
            restored.blocks(),
            reference.blocks()
        );
    }

    #[test]
    fn not_worthwhile_leaves_file_untouched() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("random.bin");
        let data = incompressible(20_000);
        fs::write(&path, &data).unwrap();

        let outcome = compress_file(&path, &Config::default()).unwrap();
        assert!(matches!(outcome, Outcome::NotWorthwhile { .. }));
        assert_eq!(fs::read(&path).unwrap(), data);
        assert_eq!(policy::should_skip(&path, &Config::default()).unwrap(), None);
    }

    #[test]
    fn recompress_always_upgrades_lzvn_to_lzfse_via_real_kernel() {
        // The scenario RecompressPolicy exists for: a file `ditto` already
        // compressed with LZVN, which LZFSE can do better on.
        let dir = tempdir().unwrap();
        let path = dir.path().join("already_lzvn.bin");
        let data = compressible(3000); // forces the chunked path
        fs::write(&path, &data).unwrap();

        // Compress with LZVN only, matching what ditto would have done.
        let lzvn_cfg = Config { algorithms: Algorithms::single(Algo::Lzvn), ..Config::default() };
        let outcome = compress_file(&path, &lzvn_cfg).unwrap();
        let Outcome::Compressed { algo: Algo::Lzvn, compressed_size: lzvn_size, .. } = outcome else {
            panic!("expected an LZVN compression, got {outcome:?}");
        };
        assert_eq!(fs::read(&path).unwrap(), data);

        // Never (the default) must leave it alone.
        let outcome = compress_file(&path, &Config::default()).unwrap();
        assert_eq!(outcome, Outcome::Skipped(SkipReason::AlreadyCompressed));

        // Always must recompress with LZFSE and produce a real improvement,
        // verified by re-reading through the actual kernel decompressor.
        let always_cfg = Config {
            recompress: policy::RecompressPolicy::Always,
            algorithms: Algorithms::single(Algo::Lzfse),
            paranoid: true,
            ..Config::default()
        };
        let outcome = compress_file(&path, &always_cfg).unwrap();
        let Outcome::Compressed { algo: Algo::Lzfse, compressed_size: lzfse_size, .. } = outcome else {
            panic!("expected an LZFSE recompression, got {outcome:?}");
        };
        assert!(
            lzfse_size < lzvn_size,
            "recompression should have improved on the LZVN footprint: lzvn={lzvn_size} lzfse={lzfse_size}"
        );
        assert_eq!(fs::read(&path).unwrap(), data); // real kernel read-back, not our own decode
    }

    // Adversarial: malformed/corrupted xattrs reaching decompress_bytes must
    // produce a clean `Err`, never a panic or silently wrong output.

    #[test]
    fn decompress_bytes_rejects_garbage_decmpfs_xattr() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("garbage_header.bin");
        fs::write(&path, b"irrelevant data fork").unwrap();
        fsops::set_xattr(&path, DECMPFS_XATTR, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap(); // too short, bad magic

        let err = decompress_bytes(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn decompress_bytes_rejects_unrecognized_compression_type() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("unknown_type.bin");
        fs::write(&path, b"irrelevant data fork").unwrap();
        // 99 isn't any of the real decmpfs types this crate knows about.
        let header = decmpfs::Header { compression_type: 99, uncompressed_size: 100 };
        fsops::set_xattr(&path, DECMPFS_XATTR, &header.to_bytes()).unwrap();

        let err = decompress_bytes(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn decompress_bytes_rejects_corrupted_inline_payload() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("corrupt_inline.bin");
        fs::write(&path, b"irrelevant data fork").unwrap();

        // A structurally valid inline header (real xattr_type for LZFSE) but
        // a payload that isn't actually a valid LZFSE stream.
        let header =
            decmpfs::Header { compression_type: decmpfs::xattr_type(Algo::Lzfse), uncompressed_size: 5000 };
        let mut xattr = header.to_bytes().to_vec();
        xattr.extend_from_slice(&[0xFFu8; 32]); // not a real compressed stream
        fsops::set_xattr(&path, DECMPFS_XATTR, &xattr).unwrap();

        let err = decompress_bytes(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn decompress_bytes_rejects_garbage_resource_fork() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("corrupt_rsrc.bin");
        fs::write(&path, b"irrelevant data fork").unwrap();

        let header = decmpfs::Header {
            compression_type: decmpfs::rsrc_type(Algo::Lzfse).unwrap(),
            uncompressed_size: decmpfs::CHUNK_SIZE as u64,
        };
        fsops::set_xattr(&path, DECMPFS_XATTR, &header.to_bytes()).unwrap();
        fsops::set_xattr(&path, RESOURCE_FORK_XATTR, &[1, 2, 3]).unwrap(); // too short to hold a table_size

        let err = decompress_bytes(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn decompress_bytes_rejects_tampered_chunk_bytes() {
        // Bit-flip a byte inside one chunk's compressed stream (not the
        // sentinel) - table and header stay consistent, so this exercises
        // decode_chunk's own failure path, not the table/header cross-check.
        let data = compressible(3000); // highly compressible -> real LZFSE, not stored-fallback
        let cfg = Config::default();
        let (algo, payload) = compress_bytes(&data, &cfg).expect("should compress");
        let CompressedPayload::Chunked { header_xattr, mut chunks } = payload else {
            panic!("expected Chunked payload")
        };
        assert!(!chunks[0].bytes.is_empty());
        let mid = chunks[0].bytes.len() / 2;
        chunks[0].bytes[mid] ^= 0xFF; // corrupt a byte well inside the compressed stream

        let rsrc = decmpfs::build_resource_fork_for(algo, &chunks);
        let dir = tempdir().unwrap();
        let path = dir.path().join("tampered_chunk.bin");
        fs::write(&path, &data).unwrap();
        fsops::set_xattr(&path, DECMPFS_XATTR, &header_xattr).unwrap();
        fsops::set_xattr(&path, RESOURCE_FORK_XATTR, &rsrc).unwrap();

        let err = decompress_bytes(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // Adversarial: probe-window boundaries in compress_chunked.

    #[test]
    fn single_chunk_file_through_chunked_path_compresses_correctly() {
        // Smallest possible input to compress_chunked (exactly 1 chunk
        // total), exercising probe_chunk_count's guards at their tightest.
        let dir = tempdir().unwrap();
        let path = dir.path().join("single_chunk.bin");
        let data = compressible((decmpfs::MAX_INLINE_PAYLOAD + 1000) / 47 + 1);
        assert!(data.len() > decmpfs::MAX_INLINE_PAYLOAD);
        assert!(data.len() < decmpfs::CHUNK_SIZE);
        fs::write(&path, &data).unwrap();

        let cfg = Config { paranoid: true, algorithms: Algorithms::single(Algo::Lzfse), ..Config::default() };
        let outcome = compress_file(&path, &cfg).unwrap();
        assert!(matches!(outcome, Outcome::Compressed { .. }));
        assert_eq!(fs::read(&path).unwrap(), data);
    }

    #[test]
    fn probe_size_smaller_than_one_chunk_still_processes_correctly() {
        // probe_size = 0: the `.max(1)` guard must kick in so at least one
        // chunk is still sampled, rather than looping zero times.
        let dir = tempdir().unwrap();
        let path = dir.path().join("zero_probe.bin");
        let data = compressible(3000); // several chunks
        fs::write(&path, &data).unwrap();

        let cfg = Config {
            probe_size: 0,
            algorithms: Algorithms::single(Algo::Lzfse),
            paranoid: true,
            ..Config::default()
        };
        let outcome = compress_file(&path, &cfg).unwrap();
        assert!(matches!(outcome, Outcome::Compressed { .. }));
        assert_eq!(fs::read(&path).unwrap(), data);
    }

    #[test]
    fn file_input_reads_an_empty_file_and_reports_a_truncation_as_eof() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        fs::write(&path, b"").unwrap();
        FileInput::open(&path).unwrap().read_at(0, &mut []).unwrap();

        // A memory map would raise SIGBUS here instead.
        fs::write(&path, vec![7u8; 64 * 1024]).unwrap();
        let input = FileInput::open(&path).unwrap();
        fs::File::options().write(true).open(&path).unwrap().set_len(10).unwrap();
        let err = input.read_at(0, &mut vec![0; 64 * 1024]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    // Adversarial: the real u32 chunk-offset boundary, tested with synthetic
    // numbers rather than an actual 4GiB write to disk.
    #[test]
    fn checked_offset_rejects_beyond_u32_max_cleanly() {
        let err = checked_offset(u32::MAX as u64 + 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn checked_offset_accepts_exactly_u32_max() {
        assert_eq!(checked_offset(u32::MAX as u64).unwrap(), u32::MAX);
    }

    // Adversarial: the marker-based classification that lets compress_file
    // tell "resource fork too large" apart from an ordinary I/O failure.

    #[test]
    fn is_resource_fork_too_large_classifies_the_marker_error() {
        let err = checked_offset(u32::MAX as u64 + 1).unwrap_err();
        assert!(is_resource_fork_too_large(&err));
    }

    #[test]
    fn verify_mismatch_is_recognizable_from_the_io_error() {
        let err = io::Error::new(io::ErrorKind::InvalidData, VerifyMismatch { algo: Algo::Lzfse });
        assert_eq!(verify_mismatch(&err).map(|m| m.algo), Some(Algo::Lzfse));
        assert!(verify_mismatch(&io::Error::new(io::ErrorKind::InvalidData, "other")).is_none());
        assert!(verify_mismatch(&io::Error::from(io::ErrorKind::NotFound)).is_none());
    }

    #[test]
    fn is_resource_fork_too_large_rejects_ordinary_io_errors() {
        let ordinary = io::Error::new(io::ErrorKind::PermissionDenied, "permission denied");
        assert!(!is_resource_fork_too_large(&ordinary));
        let ordinary_invalid_data = io::Error::new(io::ErrorKind::InvalidData, "some other invalid data");
        assert!(
            !is_resource_fork_too_large(&ordinary_invalid_data),
            "classification must key on the marker type, not just ErrorKind::InvalidData"
        );
    }

    /// Asserts a measured `algo` fork holds exactly `at_limit` data bytes
    /// before `record` refuses more.
    fn assert_rsrc_limit_at(algo: Algo, at_limit: u64) {
        let mut w = RsrcWriter::measure();
        w.begin(algo, 1).unwrap();
        w.end += at_limit - 1; // stand-in for gigabytes of earlier chunks
        w.record(1).unwrap();
        let err = w.record(1).unwrap_err();
        assert!(is_resource_fork_too_large(&err));
    }

    #[test]
    fn rsrc_writer_limit_matches_checked_offset_boundary() {
        // The whole fork, table included, must fit 32-bit offsets.
        // table_size for 1 chunk = 8.
        assert_rsrc_limit_at(Algo::Lzfse, u32::MAX as u64 - 8);
    }

    #[test]
    fn rsrc_writer_limit_accounts_for_zlib_type4_overhead() {
        // ZLIB's header sits before the data, so the boundary is lower.
        let footer = decmpfs::ZLIB_RSRC_FOOTER.len() as u64;
        let data_start = decmpfs::rsrc_footprint_overhead(Algo::Zlib(9), 1) - footer;
        assert_rsrc_limit_at(Algo::Zlib(9), u32::MAX as u64 - data_start);
    }

    // Kernel vs our-own-decoder differential checks. Nothing production-side
    // calls `decompress_bytes` - both `paranoid` and `decompress_file` defer
    // to the real kernel via `fs::read` - so this suite is what confirms our
    // decoder's on-disk format understanding is correct, not merely
    // self-consistent with our own encoder.

    /// Reads `path` through both the kernel's decompression and our own
    /// decoder, and asserts all three (kernel, ours, original) agree.
    fn assert_kernel_and_decoder_agree(path: &Path, original: &[u8]) {
        let via_kernel = fs::read(path).expect("kernel read failed");
        let via_decoder = decompress_bytes(path).expect("our decoder failed");
        assert_eq!(via_kernel, original, "kernel decompression disagrees with the original bytes");
        assert_eq!(via_decoder, original, "our decoder disagrees with the original bytes");
        assert_eq!(via_kernel, via_decoder, "kernel and our decoder disagree with each other");
    }

    // Adversarial: dry-run against an already-compressed file exercises
    // recompression_basis without touching the real file.

    #[test]
    fn dry_run_recompress_evaluates_against_compressed_footprint_without_touching_the_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        let data = compressible(3000); // forces the chunked path
        fs::write(&path, &data).unwrap();

        // Real compression first, so the file is UF_COMPRESSED before the
        // dry run below evaluates it.
        let cfg = Config { algorithms: Algorithms::single(Algo::Lzvn), ..Config::default() };
        let outcome = compress_file(&path, &cfg).unwrap();
        let Outcome::Compressed { algo: Algo::Lzvn, .. } = outcome else {
            panic!("expected an LZVN compression, got {outcome:?}");
        };
        let compressed_bytes_before = fs::read(&path).unwrap(); // real kernel read-back
        assert_eq!(compressed_bytes_before, data);

        // Dry-run recompress with Always: must evaluate against the current
        // compressed footprint, not the logical size, and never write.
        let dry_cfg = Config {
            dry_run: true,
            recompress: policy::RecompressPolicy::Always,
            algorithms: Algorithms::single(Algo::Lzfse),
            ..Config::default()
        };
        let outcome = dry_run_evaluate(&path, &dry_cfg, &FileProgress::detached()).unwrap();
        assert!(
            matches!(outcome, Outcome::Compressed { .. } | Outcome::NotWorthwhile { .. }),
            "expected a real verdict, got {outcome:?}"
        );

        // Key property: a dry run must never touch the file either way.
        assert_eq!(fs::read(&path).unwrap(), data);
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!((meta.st_flags() & crate::sys::UF_COMPRESSED) != 0, "dry run must not have cleared UF_COMPRESSED");
        let header_xattr = fsops::get_xattr(&path, DECMPFS_XATTR).unwrap();
        let header = decmpfs::Header::from_bytes(&header_xattr).unwrap();
        assert_eq!(
            decmpfs::algo_for_type(header.compression_type),
            Some(Algo::Lzvn),
            "dry run must not have changed the on-disk algorithm"
        );
    }

    #[test]
    fn dry_run_recompress_via_compress_file_leaves_file_untouched() {
        // Same scenario, but through compress_file's own dry_run branch,
        // the real public entry point every CLI dry-run call goes through.
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        let data = compressible(3000);
        fs::write(&path, &data).unwrap();

        let cfg = Config { algorithms: Algorithms::single(Algo::Lzvn), ..Config::default() };
        compress_file(&path, &cfg).unwrap();
        assert_eq!(fs::read(&path).unwrap(), data);

        let dry_cfg = Config {
            dry_run: true,
            recompress: policy::RecompressPolicy::Always,
            algorithms: Algorithms::single(Algo::Lzfse),
            ..Config::default()
        };
        let outcome = compress_file(&path, &dry_cfg).unwrap();
        assert!(matches!(outcome, Outcome::Compressed { .. } | Outcome::NotWorthwhile { .. }));

        // Untouched by the dry run: real kernel read-back still matches.
        assert_eq!(fs::read(&path).unwrap(), data);
    }

    #[test]
    fn kernel_and_decoder_agree_across_algorithms_and_shapes() {
        // Driven by `all_algos` rather than a list written out here, so a
        // newly added encoder is covered automatically. Filtered by
        // `is_supported` so a machine below a format's floor skips it.
        let algos: Vec<Algo> = algo::all_algos()
            .into_iter()
            // Correctness, not ratio, is under test; zlib's top level would
            // dominate the suite's runtime.
            .map(|a| if matches!(a, Algo::Zlib(_)) { Algo::Zlib(1) } else { a })
            .chain([Algo::Zlib(algo::ZLIB_DEFAULT_LEVEL)])
            .filter(|&a| algo::is_supported(a))
            .collect();
        assert!(algos.len() >= 10, "expected every supported encoder to be exercised, got {algos:?}");

        // Named so a failure says which shape broke, not just which algorithm.
        type Shape = (&'static str, fn() -> Vec<u8>);
        let shapes: [Shape; 5] = [
            ("inline_small", || compressible(50)),
            ("chunked_single", || compressible(3000)),
            ("chunked_multi_wave", || compressible(4 * decmpfs::CHUNK_SIZE / 47 + 1)),
            ("chunked_incompressible_tail", || {
                let mut d = compressible(2 * decmpfs::CHUNK_SIZE / 47 + 1);
                d.extend(incompressible(500));
                d
            }),
            ("chunked_fully_incompressible", || incompressible(3 * decmpfs::CHUNK_SIZE)),
        ];

        for algo in algos {
            for (name, make_data) in shapes {
                let data = make_data();
                let dir = tempdir().unwrap();
                let path = dir.path().join("f.bin");
                fs::write(&path, &data).unwrap();

                let cfg = Config {
                    // Every shape must get compressed and written regardless
                    // of ratio (some combinations, e.g. Stored on
                    // incompressible data, grow slightly) - format
                    // correctness is what's under test, not ratio.
                    max_ratio: 2.0,
                    // inline_small is under the real block-size floor; this
                    // test is about format correctness, not that policy.
                    min_file_size: Some(1),
                    algorithms: Algorithms::single(algo),
                    ..Config::default()
                };
                let outcome = compress_file(&path, &cfg).unwrap();
                assert!(
                    matches!(outcome, Outcome::Compressed { .. }),
                    "{algo:?}/{name}: expected Compressed, got {outcome:?}"
                );

                assert_kernel_and_decoder_agree(&path, &data);
            }
        }
    }

    /// Word salad: compresses, but not trivially, so chunk sizes vary.
    fn varied(len: usize) -> Vec<u8> {
        const WORDS: [&[u8]; 8] =
            [b"apfs ", b"decmpfs ", b"chunk ", b"resource ", b"fork ", b"zlib ", b"lzfse ", b"probe\n"];
        let mut v = Vec::with_capacity(len + 16);
        let mut x: u32 = 0x9E37_79B9;
        while v.len() < len {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            v.extend_from_slice(WORDS[(x & 7) as usize]);
        }
        v.truncate(len);
        v
    }

    /// Several streamed batches past a small probe, ending in a partial chunk.
    const STREAMED_LEN: usize = 3 * STREAM_BATCH_CHUNKS * 64 * 1024 + 12_345;

    fn streaming_cfg(algo: Algo) -> Config {
        Config { algorithms: Algorithms::single(algo), probe_size: 256 * 1024, ..Config::default() }
    }

    #[test]
    fn streamed_resource_fork_matches_the_in_memory_encoding() {
        for algo in [Algo::Lzfse, Algo::Zlib(6)] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("f.bin");
            let data = varied(STREAMED_LEN);
            fs::write(&path, &data).unwrap();
            let cfg = streaming_cfg(algo);

            let Some((_, CompressedPayload::Chunked { header_xattr, chunks })) = compress_bytes(&data, &cfg) else {
                panic!("{algo:?}: expected a chunked in-memory encoding");
            };
            let dry = compress_file(&path, &Config { dry_run: true, ..cfg.clone() }).unwrap();
            let outcome = compress_file(&path, &cfg).unwrap();
            let Outcome::Compressed { compressed_size, .. } = outcome else {
                panic!("{algo:?}: expected Compressed, got {outcome:?}");
            };

            let rsrc = fsops::get_xattr(&path, RESOURCE_FORK_XATTR).unwrap();
            assert_eq!(rsrc, decmpfs::build_resource_fork_for(algo, &chunks), "{algo:?}");
            assert_eq!(fsops::get_xattr(&path, DECMPFS_XATTR).unwrap(), header_xattr, "{algo:?}");
            assert_eq!(compressed_size, (header_xattr.len() + rsrc.len()) as u64, "{algo:?}");
            assert_eq!(dry, outcome, "{algo:?}: dry run must predict the real result exactly");
            let allocated = fs::symlink_metadata(&path).unwrap().st_blocks() * 512;
            assert!(allocated <= rsrc.len().next_multiple_of(4096) as u64, "{algo:?}: {allocated} bytes allocated for a {}-byte fork", rsrc.len());
            assert_kernel_and_decoder_agree(&path, &data);
        }
    }

    #[test]
    fn recompressing_a_chunked_file_reads_its_old_encoding_while_writing_the_new_one() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        let data = varied(STREAMED_LEN);
        fs::write(&path, &data).unwrap();
        let first = compress_file(&path, &streaming_cfg(Algo::Lzvn)).unwrap();
        assert!(matches!(first, Outcome::Compressed { algo: Algo::Lzvn, .. }), "{first:?}");

        let cfg = Config { recompress: policy::RecompressPolicy::Always, ..streaming_cfg(Algo::Zlib(9)) };
        let second = compress_file(&path, &cfg).unwrap();
        assert!(matches!(second, Outcome::Compressed { algo: Algo::Zlib(9), .. }), "{second:?}");
        assert_kernel_and_decoder_agree(&path, &data);
    }

    #[test]
    fn a_file_whose_start_does_not_compress_is_judged_on_all_of_it() {
        // Its first few chunks are random, so a probe of just its start
        // would reject it.
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        let mut data = incompressible(2 * 1024 * 1024);
        data.extend(varied(10 * 1024 * 1024));
        fs::write(&path, &data).unwrap();

        let outcome = compress_file(&path, &streaming_cfg(Algo::Lzfse)).unwrap();
        assert!(matches!(outcome, Outcome::Compressed { .. }), "{outcome:?}");
        assert_kernel_and_decoder_agree(&path, &data);
    }

    #[test]
    fn paranoid_verify_catches_output_that_decodes_to_something_else() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        let other_path = dir.path().join("other.bin");
        let original = varied(STREAMED_LEN);
        let other = compressible(STREAMED_LEN / 45);
        fs::write(&path, &original).unwrap();
        fs::write(&other_path, &other).unwrap();

        // Stage `path` but fill the clone with an encoding of `other`.
        let output = StagedFile::stage(&path).unwrap();
        let prog = FileProgress::detached();
        let rsrc = RsrcWriter::create(fsops::resource_fork_path(&output.path));
        let Ok(Ok(encoding)) = encode_all(&other.as_slice(), &streaming_cfg(Algo::Lzfse), u64::MAX, &prog, rsrc) else {
            panic!("expected an encoding");
        };
        commit_compressed(&output, &encoding.decmpfs_xattr).unwrap();

        assert!(matches!(verify_matches(&output.path, &path, &prog).unwrap(), Verified::Mismatch));
        assert!(matches!(verify_matches(&output.path, &other_path, &prog).unwrap(), Verified::Match));
        output.discard().unwrap();
    }

    #[test]
    fn cancelling_stops_encoding_at_the_next_chunk() {
        /// Cancels as soon as the first (probe) batch arrives.
        struct CancelOnPush<'a>(&'a Control, usize);
        impl ChunkSink for CancelOnPush<'_> {
            fn begin(&mut self, _: Algo, _: usize) -> io::Result<()> {
                Ok(())
            }
            fn push(&mut self, _: Vec<ChunkOutput>) -> io::Result<()> {
                self.0.cancel();
                self.1 += 1;
                Ok(())
            }
        }
        let data = varied(STREAMED_LEN);
        let ctl = Control::new();
        let prog = FileProgress::new(&ctl);
        let mut sink = CancelOnPush(&ctl, 0);
        let encoded = encode_chunked(&data.as_slice(), &streaming_cfg(Algo::Lzfse), u64::MAX, &prog, &mut sink).unwrap();
        assert!(matches!(encoded, Encoded::Cancelled));
        assert_eq!(sink.1, 1, "nothing may be pushed after the cancel");
        assert!(ctl.bytes_done() < data.len() as u64);
    }

    #[test]
    fn a_cancelled_control_leaves_files_untouched() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("f.bin");
        let data = varied(1024 * 1024);
        fs::write(&path, &data).unwrap();
        let ctl = Control::new();
        ctl.cancel();
        assert_eq!(compress_file_with(&path, &Config::default(), &ctl).unwrap(), Outcome::Cancelled);
        assert_eq!(fs::read(&path).unwrap(), data);
        assert_eq!(fs::symlink_metadata(&path).unwrap().st_flags() & sys::UF_COMPRESSED, 0);
        assert_eq!(ctl.bytes_done(), 0);
    }

    #[test]
    fn progress_counts_every_submitted_byte_exactly_once() {
        let dir = tempdir().unwrap();
        let files = [
            ("streamed", varied(STREAMED_LEN)), // compressed, over several batches
            ("random", incompressible(2 * 1024 * 1024)), // rejected at the probe
            ("tiny", b"short".to_vec()), // skipped
        ];
        let ctl = Control::new();
        let mut total = 0;
        for (name, data) in &files {
            let path = dir.path().join(name);
            fs::write(&path, data).unwrap();
            total += data.len() as u64;
            compress_file_with(&path, &streaming_cfg(Algo::Lzfse), &ctl).unwrap();
        }
        assert_eq!(ctl.bytes_done(), total);
    }

    /// Bytes drawn from 16 letters: LZFSE compresses them to about half,
    /// so a clone with 10% of it private frees too little, and one with 90%
    /// private enough.
    fn half_compressible(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                b'a' + (x % 16) as u8
            })
            .collect()
    }

    const CLONE_TEST_SIZE: usize = 10 << 20;

    /// `original`, and a clone of it with its first `rewritten_mib` MiB
    /// rewritten and flushed, so APFS has given them their own blocks.
    fn clone_pair(dir: &Path, name: &str, rewritten_mib: usize) -> (std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::FileExt;
        let (original, clone) = (dir.join(format!("{name}.orig")), dir.join(format!("{name}.clone")));
        fs::write(&original, half_compressible(CLONE_TEST_SIZE, 1)).unwrap();
        fsops::clone_file(&original, &clone).unwrap();
        if rewritten_mib > 0 {
            let f = fs::OpenOptions::new().write(true).open(&clone).unwrap();
            f.write_all_at(&half_compressible(rewritten_mib << 20, 2), 0).unwrap();
            f.sync_all().unwrap();
        }
        (original, clone)
    }

    fn is_compressed(path: &Path) -> bool {
        fs::symlink_metadata(path).unwrap().st_flags() & sys::UF_COMPRESSED != 0
    }

    /// The replaced copy's blocks are released once its last descriptor
    /// closes, which APFS finishes a moment after `compress_file` returns.
    fn wait_until_unshared(path: &Path) {
        for _ in 0..100 {
            if policy::block_sharing(path).unwrap() == policy::BlockSharing::Unshared {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("{} still shares blocks: {:?}", path.display(), policy::block_sharing(path));
    }

    fn lzfse() -> Config {
        Config { algorithms: Algorithms::single(Algo::Lzfse), ..Config::default() }
    }

    #[test]
    fn exact_clones_are_skipped_before_reading() {
        let dir = tempdir().unwrap();
        let (original, clone) = clone_pair(dir.path(), "f", 0);
        let cfg = lzfse();
        for path in [&original, &clone] {
            assert_eq!(policy::block_sharing(path).unwrap(), policy::BlockSharing::All);
            assert_eq!(policy::should_skip(path, &cfg).unwrap(), Some(SkipReason::SharedWithClones));
            assert_eq!(compress_file(path, &cfg).unwrap(), Outcome::Skipped(SkipReason::SharedWithClones));
            assert_eq!(estimate_file(path, &cfg).unwrap(), EstimateFileOutcome::Skipped(SkipReason::SharedWithClones));
            assert!(!is_compressed(path));
        }

        // With the rule off, as for `dmg`, the clone compresses. Its old
        // blocks then belong to the original alone, which is worth
        // compressing too.
        let off = Config { skip_clones: false, ..lzfse() };
        assert!(matches!(compress_file(&clone, &off).unwrap(), Outcome::Compressed { .. }));
        wait_until_unshared(&original);
        assert!(matches!(compress_file(&original, &cfg).unwrap(), Outcome::Compressed { .. }));
        assert_eq!(fs::read(&original).unwrap(), fs::read(&clone).unwrap());
    }

    #[test]
    fn a_partly_shared_clone_is_compressed_only_if_that_frees_space() {
        let dir = tempdir().unwrap();
        let cfg = lzfse();

        // 1 MiB of its own, against about 5 MiB compressed.
        let (_, barely) = clone_pair(dir.path(), "barely", 1);
        let policy::BlockSharing::Partial { private_bytes } = policy::block_sharing(&barely).unwrap() else {
            panic!("{:?}", policy::block_sharing(&barely));
        };
        assert!(private_bytes.abs_diff(1 << 20) <= 64 << 10, "{private_bytes}");
        assert_eq!(policy::should_skip(&barely, &cfg).unwrap(), None, "judged once its size is known");
        let dry = Config { dry_run: true, ..lzfse() };
        assert_eq!(compress_file(&barely, &dry).unwrap(), Outcome::Skipped(SkipReason::SharedWithClones));
        assert_eq!(estimate_file(&barely, &cfg).unwrap(), EstimateFileOutcome::Skipped(SkipReason::SharedWithClones));
        let before = fs::read(&barely).unwrap();
        assert_eq!(compress_file(&barely, &cfg).unwrap(), Outcome::Skipped(SkipReason::SharedWithClones));
        assert!(!is_compressed(&barely));
        assert_eq!(fs::read(&barely).unwrap(), before);
        let leftovers = fs::read_dir(dir.path()).unwrap().filter(|e| {
            e.as_ref().unwrap().file_name().to_str().is_some_and(crate::swap::is_staging_file_name)
        });
        assert_eq!(leftovers.count(), 0, "the staged copy is discarded");

        // 9 MiB of its own: compressing it frees about 4 MiB.
        let (original, mostly) = clone_pair(dir.path(), "mostly", 9);
        assert!(matches!(policy::block_sharing(&mostly).unwrap(), policy::BlockSharing::Partial { .. }));
        assert!(matches!(estimate_file(&mostly, &cfg).unwrap(), EstimateFileOutcome::Estimated { .. }));
        assert!(matches!(compress_file(&mostly, &cfg).unwrap(), Outcome::Compressed { .. }));
        assert!(is_compressed(&mostly));
        let mut expected = half_compressible(CLONE_TEST_SIZE, 1);
        expected[..9 << 20].copy_from_slice(&half_compressible(9 << 20, 2));
        assert_eq!(fs::read(&mostly).unwrap(), expected);
        // Which leaves the original all its own.
        wait_until_unshared(&original);
    }

    #[test]
    fn a_clone_of_a_compressed_file_is_not_recompressed() {
        let dir = tempdir().unwrap();
        let original = dir.path().join("f");
        fs::write(&original, half_compressible(CLONE_TEST_SIZE, 1)).unwrap();
        assert!(matches!(compress_file(&original, &lzfse()).unwrap(), Outcome::Compressed { .. }));
        assert_eq!(policy::block_sharing(&original).unwrap(), policy::BlockSharing::Unshared);

        // The clone shares the resource fork, so a new one would be all new data.
        let clone = dir.path().join("g");
        fsops::clone_file(&original, &clone).unwrap();
        let cfg = Config {
            recompress: policy::RecompressPolicy::Always,
            algorithms: Algorithms::single(Algo::Zlib(9)),
            ..Config::default()
        };
        for path in [&original, &clone] {
            assert_eq!(policy::block_sharing(path).unwrap(), policy::BlockSharing::All);
            assert_eq!(compress_file(path, &cfg).unwrap(), Outcome::Skipped(SkipReason::SharedWithClones));
        }
    }
}
