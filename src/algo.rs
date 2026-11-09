//! Codec dispatch and reusable scratch for decmpfs chunk compression.
//! Apple-compatible formats are decoded through libcompression.framework.

use crate::sys::{self, CompressionAlgorithm};
use std::os::raw::c_void;
use std::ptr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algo {
    /// Routed through libdeflate: libcompression exposes no level for these
    /// formats, and its own zlib output isn't zlib-wrapped (see
    /// `compress_chunk`). Carries libdeflate's level (1-12).
    Zlib(u8),
    Lzfse,
    Lzvn,
    Lzbitmap,
    /// Alternate encoder for `Lzfse`'s on-disk format, from crush-lz's
    /// `crushlzfse` (cost-based optimal-parse). Emits a real LZFSE bitstream
    /// decodable by the system decoder at any level. Carries a level
    /// (`crushlzfse::Level::MIN`-`MAX`, can be negative: -5..5 greedy or
    /// lazy, 6+ optimal parse). Rejects input over `crushlzfse::BLOCK_SIZE` (64 KiB);
    /// see the assertion beside `EncodeScratch`.
    CrushLzfse(i32),
    /// Apple's LZ4, decmpfs types 15/16. Newest type the kernel decodes
    /// (27.0, see `min_os_version`); the framework has supported
    /// `COMPRESSION_LZ4` since 10.11, but only the kernel's support gates us.
    /// Type 15 wants Apple's `bv41`/`bv4-`/`bv4$` frame, not a bare LZ4 block.
    Lz4,
    /// Alternate encoder for `Lzvn`'s on-disk format (types 7/8), from
    /// crush-lz's `crushlzfse::lzvn`. Carries a level
    /// (`crushlzfse::lzvn::Level::MIN`-`MAX`); the optimal-parse tier starts
    /// at 8, everything below it is the greedy matcher.
    CrushLzvn(i32),
    /// Alternate encoder for `Lzbitmap`'s on-disk format (types 13/14), from
    /// crush-lz's `lzbitmap`. Carries a level
    /// (`lzbitmap::Level::MIN`-`MAX`): fast -5..-3, row -2..6, dynamic
    /// programming 7, beam search 8+.
    CrushLzbitmap(i32),
    /// Alternate encoder for `Lz4`'s on-disk format (types 15/16), from
    /// crush-lz's `crushlz4`. Carries a level
    /// (`crushlz4::Level::MIN`-`MAX`). Same frame as `Lz4`, so the kernel
    /// cannot tell which encoder produced it and doesn't need to.
    CrushLz4(i32),
    /// Identity "algorithm" backing decmpfs types 9/10 - always succeeds,
    /// never expands, no libcompression call involved.
    Stored,
}

impl Algo {
    fn raw(self) -> Option<CompressionAlgorithm> {
        match self {
            // CrushLzfse shares Lzfse's raw id for decoding only:
            // compress_chunk_with_scratch intercepts CrushLzfse earlier, but
            // decompress_chunk's fallback path uses this to route it through
            // the system LZFSE decoder.
            Algo::Lzfse | Algo::CrushLzfse(_) => Some(sys::COMPRESSION_LZFSE),
            Algo::Lzvn | Algo::CrushLzvn(_) => Some(sys::COMPRESSION_LZVN),
            Algo::Lzbitmap | Algo::CrushLzbitmap(_) => Some(sys::COMPRESSION_LZBITMAP),
            Algo::Lz4 | Algo::CrushLz4(_) => Some(sys::COMPRESSION_LZ4),
            Algo::Zlib(_) | Algo::Stored => None,
        }
    }

    /// The level this variant carries, if it has one. `None` for the
    /// algorithms whose encoder exposes no knob (`Lzfse`, `Lzvn`,
    /// `Lzbitmap`, `Lz4`, `Stored`).
    pub fn level(self) -> Option<i32> {
        match self {
            Algo::Zlib(l) => Some(l as i32),
            Algo::CrushLzfse(l) | Algo::CrushLzvn(l) | Algo::CrushLzbitmap(l) | Algo::CrushLz4(l) => Some(l),
            Algo::Lzfse | Algo::Lzvn | Algo::Lzbitmap | Algo::Lz4 | Algo::Stored => None,
        }
    }
}

/// A macOS product version as `(major, minor)`, ordered the obvious way:
/// `(10, 11) < (12, 0) < (27, 0)`.
pub type OsVersion = (u32, u32);

/// The macOS version whose *kernel* first decoded this algorithm's decmpfs
/// type - the only thing that decides whether a file we write is readable.
///
/// Keyed on the decmpfs type, not the encoder: `Lzfse` and `CrushLzfse` share
/// a floor (types 11/12) since both produce the same on-disk format.
///
/// Not the same as libcompression's own availability: the framework has
/// decoded LZ4 since 10.11, but nothing selected it from decmpfs until types
/// 15/16 arrived in 27.0.
pub fn min_os_version(algo: Algo) -> OsVersion {
    match algo {
        // Types 3/4, with decmpfs itself.
        Algo::Zlib(_) => (10, 6),
        // Types 7/8 and 9/10.
        Algo::Lzvn | Algo::CrushLzvn(_) | Algo::Stored => (10, 10),
        // Types 11/12, with LZFSE.
        Algo::Lzfse | Algo::CrushLzfse(_) => (10, 11),
        // Types 13/14.
        Algo::Lzbitmap | Algo::CrushLzbitmap(_) => (12, 0),
        // Types 15/16. The only floor a machine in service today can fail.
        Algo::Lz4 | Algo::CrushLz4(_) => (27, 0),
    }
}

/// Whether this system's kernel can read back what `algo` writes.
///
/// A version comparison, not a probe: the decmpfs decompressor registry is
/// kernel-global, so this costs one cached `sysctl` for the whole process.
pub fn is_supported(algo: Algo) -> bool {
    os_version() >= min_os_version(algo)
}

/// libdeflate's maximum, and the highest ratio any encoder here reaches on
/// the type 3/4 container. We compress once and read many times, so the
/// default takes ratio over speed (about 8 MiB/s per thread vs L9's 79).
pub const ZLIB_DEFAULT_LEVEL: u8 = 12;
/// The level scale libdeflate accepts, minus 0: valid to libdeflate but means
/// "emit uncompressed blocks", which can only grow the input.
pub const ZLIB_MIN_LEVEL: u8 = 1;
pub const ZLIB_MAX_LEVEL: u8 = 12;

// These defaults are ours, not crush-lz's (which defaults every codec to its
// fast tier 0); each picks a level in the denser tier instead.

/// The optimal-parse tier starts at 6.
pub const CRUSHLZFSE_DEFAULT_LEVEL: i32 = 8;
/// LZVN's optimal-parse tier starts at 8; below it are the greedy matchers,
/// similar to libcompression's own LZVN encoder.
pub const CRUSHLZVN_DEFAULT_LEVEL: i32 = 8;
/// LZBITMAP's dynamic-programming tier starts at 7.
pub const CRUSHLZBITMAP_DEFAULT_LEVEL: i32 = 7;
/// LZ4's HC tier spans 1 to 10; this is mid-ladder.
pub const CRUSHLZ4_DEFAULT_LEVEL: i32 = 6;

/// Every algorithm this build offers, at the level a bare name resolves to,
/// in the order the CLI lists them. Ignores OS support - see
/// [`supported_algos`] for the filtered form.
pub fn all_algos() -> [Algo; 10] {
    [
        Algo::Lzfse,
        Algo::CrushLzfse(CRUSHLZFSE_DEFAULT_LEVEL),
        Algo::Zlib(ZLIB_DEFAULT_LEVEL),
        Algo::Lzvn,
        Algo::CrushLzvn(CRUSHLZVN_DEFAULT_LEVEL),
        Algo::Lzbitmap,
        Algo::CrushLzbitmap(CRUSHLZBITMAP_DEFAULT_LEVEL),
        Algo::Lz4,
        Algo::CrushLz4(CRUSHLZ4_DEFAULT_LEVEL),
        Algo::Stored,
    ]
}

/// Every algorithm this system can actually read back, at the level a bare
/// name resolves to. The single source of truth for "what can this build
/// offer here", for CLI listing and library callers alike.
pub fn supported_algos() -> Vec<Algo> {
    all_algos().into_iter().filter(|&a| is_supported(a)).collect()
}

/// This system's macOS product version, read once per process.
///
/// `kern.osproductversion` is the marketing version - the same number
/// `sw_vers` prints and the scale `min_os_version` uses, unlike
/// `kern.osversion` (a build string) or `kern.osrelease` (the Darwin
/// version).
///
/// A binary linked against a pre-Big-Sur SDK would get a capped value from
/// `kern.osproductversioncompat` instead; not reachable with our toolchain.
pub fn os_version() -> OsVersion {
    use std::sync::OnceLock;
    static VERSION: OnceLock<OsVersion> = OnceLock::new();
    *VERSION.get_or_init(|| {
        // 12.0, not 0.0: a fallback that's too low disables every algorithm,
        // one too high could green-light a format the kernel can't read.
        read_sysctl_string("kern.osproductversion").and_then(|s| parse_os_version(&s)).unwrap_or((12, 0))
    })
}

/// Reads a string-valued sysctl by name. Two calls: one with a null buffer
/// to learn the length, one to fetch it.
fn read_sysctl_string(name: &str) -> Option<String> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut len: usize = 0;
    // SAFETY: `cname` is a valid NUL-terminated C string that outlives the
    // call; a null `oldp` with a valid `oldlenp` is the documented way to
    // ask for the size, and writes only to `len`.
    let rc = unsafe { sys::sysctlbyname(cname.as_ptr(), ptr::null_mut(), &mut len, ptr::null_mut(), 0) };
    if rc != 0 || len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    // SAFETY: as above, but `oldp` now points at `len` writable bytes, the
    // extent `oldlenp` reports.
    let rc = unsafe { sys::sysctlbyname(cname.as_ptr(), buf.as_mut_ptr().cast(), &mut len, ptr::null_mut(), 0) };
    if rc != 0 {
        return None;
    }
    // The value is NUL-terminated and `len` counts the NUL; take the bytes
    // before it.
    let bytes = buf.get(..len)?.split(|&b| b == 0).next()?;
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

/// Parses `"27.0"` or `"10.11.6"` into `(major, minor)`. A missing minor is
/// 0, so `"27"` is `(27, 0)`; the patch component is ignored, since no
/// decmpfs type has ever landed in one.
pub fn parse_os_version(s: &str) -> Option<OsVersion> {
    let mut parts = s.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().map_or(Some(0), |m| m.parse().ok())?;
    Some((major, minor))
}

/// Per-thread reusable scratch for `compress_chunk_with_scratch`: one region
/// per encoder that benefits from call-to-call reuse. Bundled together so one
/// per thread (see `engine::compress_range`) covers every algorithm a race
/// runs, not just libcompression's.
pub struct EncodeScratch {
    libcompression: Vec<u8>,
    /// One region per crush-lz codec; each carves its region to its own
    /// layout so they cannot share a buffer. Grows lazily, never shrinks, so
    /// a worker only pays for the codecs it actually runs.
    crushlzfse: crushlzfse::Scratch,
    crushlzvn: crushlzfse::lzvn::Scratch,
    crushlzbitmap: lzbitmap::Scratch,
    crushlz4: crushlz4::Scratch,
    /// The libdeflate handle for `Algo::Zlib`, paired with the level it was
    /// built for. `None` until the first zlib chunk; see `compress_zlib`.
    zlib: Option<(u8, libdeflater::Compressor)>,
}

// crushlzfse and crushlzvn refuse input over their fixed block size, so a
// larger decmpfs chunk would turn every chunk into a silent stored fallback.
const _: () = assert!(crate::decmpfs::CHUNK_SIZE <= crushlzfse::BLOCK_SIZE);
const _: () = assert!(crate::decmpfs::CHUNK_SIZE <= crushlzfse::lzvn::BLOCK_SIZE);

impl Default for EncodeScratch {
    fn default() -> Self {
        EncodeScratch {
            libcompression: Vec::new(),
            // Infallible: starts empty; the first compress call sizes it and
            // it only grows thereafter.
            crushlzfse: crushlzfse::Scratch::new(),
            crushlzvn: crushlzfse::lzvn::Scratch::new(),
            crushlzbitmap: lzbitmap::Scratch::new(),
            crushlz4: crushlz4::Scratch::new(),
            zlib: None,
        }
    }
}

/// Compresses `input` with `algo`. Returns `None` if the algorithm couldn't
/// produce output strictly smaller than `input` (falls back to a decmpfs
/// stored sentinel) - except `Algo::Stored`, which always succeeds.
///
/// `Algo::Zlib` does NOT go through libcompression's `COMPRESSION_ZLIB`: that
/// emits raw DEFLATE with no zlib wrapper, which the kernel's type-3 decoder
/// rejects. `compress_zlib` (via libdeflate) produces real zlib output.
pub fn compress_chunk(input: &[u8], algo: Algo) -> Option<Vec<u8>> {
    let mut scratch = EncodeScratch::default();
    compress_chunk_with_scratch(input, algo, &mut scratch)
}

/// Same as `compress_chunk`, but reuses a caller-provided `EncodeScratch`
/// instead of allocating fresh working memory per call - `compress_chunk`
/// pays that cost every chunk by passing a fresh, empty `EncodeScratch`.
/// Callers processing many chunks (e.g. one scratch per thread) should call
/// this directly and reuse `scratch`: every region
/// only grows. Each result still allocates its own destination vector.
pub fn compress_chunk_with_scratch(input: &[u8], algo: Algo, scratch: &mut EncodeScratch) -> Option<Vec<u8>> {
    if algo == Algo::Stored {
        return Some(input.to_vec());
    }
    if input.is_empty() {
        return None;
    }
    if let Algo::Zlib(level) = algo {
        return compress_zlib(input, level, &mut scratch.zlib);
    }
    // Each crush-lz encoder shares `compress_into_with(dst, src, &params,
    // &scratch)`, sized to `compress_bound`: LZBITMAP and LZ4 reject a
    // smaller buffer outright, so `crush_encode` tests the shrink itself.
    match algo {
        Algo::CrushLzfse(l) => {
            let s = &mut scratch.crushlzfse;
            let (p, _) = crushlzfse::Params::for_level(crushlzfse::Level(l));
            return crush_encode(input, crushlzfse::compress_bound(input.len(), &p), |dst, src| crushlzfse::compress_into_with(dst, src, &p, s).ok());
        }
        Algo::CrushLzvn(l) => {
            let s = &mut scratch.crushlzvn;
            let (p, _) = crushlzfse::lzvn::Params::for_level(crushlzfse::lzvn::Level(l));
            return crush_encode(input, crushlzfse::lzvn::compress_bound(input.len(), &p), |dst, src| {
                crushlzfse::lzvn::compress_into_with(dst, src, &p, s).ok()
            });
        }
        Algo::CrushLzbitmap(l) => {
            let s = &mut scratch.crushlzbitmap;
            return crush_encode(input, lzbitmap::compress_bound(input.len()), |dst, src| lzbitmap::compress_into(dst, src, lzbitmap::Level(l), s).ok());
        }
        Algo::CrushLz4(l) => {
            let s = &mut scratch.crushlz4;
            return crush_encode(input, crushlz4::compress_bound(input.len()), |dst, src| crushlz4::compress_into(dst, src, crushlz4::Level(l), s).ok());
        }
        _ => {}
    }
    let raw = algo.raw().expect("non-Zlib, non-crush, non-Stored algo always has a raw id");

    let needed = unsafe { sys::compression_encode_scratch_buffer_size(raw) };
    if scratch.libcompression.len() < needed {
        scratch.libcompression.resize(needed, 0);
    }

    // Cap the destination buffer at input.len() - 1: compression_encode_buffer
    // returns 0 (failure) if the result wouldn't fit, so this makes "doesn't
    // shrink" and "buffer too small" the same signal for free, and guarantees
    // any non-zero return is *strictly* smaller than the input.
    let cap = input.len() - 1;
    if cap == 0 {
        return None;
    }
    let mut dst = vec![0u8; cap];
    let written = unsafe {
        sys::compression_encode_buffer(
            dst.as_mut_ptr(),
            dst.len(),
            input.as_ptr(),
            input.len(),
            scratch.libcompression.as_mut_ptr() as *mut c_void,
            raw,
        )
    };
    // Contract is "0 on failure, else written <= dst_size." If violated,
    // `dst.truncate` below would silently no-op instead of surfacing it,
    // so assert directly.
    debug_assert!(
        written <= dst.len(),
        "compression_encode_buffer reported writing {written} bytes into a {}-byte buffer",
        dst.len()
    );
    if written == 0 {
        return None;
    }
    dst.truncate(written);
    Some(dst)
}

/// Shared body for the four crush-lz encoders: run `encode` into a
/// `bound`-sized buffer, and report anything that doesn't strictly shrink
/// `input` as `None`.
///
/// Every crush-lz codec has its own stored/uncompressed fallback that can
/// emit output >= `input.len()`, which is a success for that crate but not
/// by this function's contract, so a non-shrink is coerced to `None` here.
fn crush_encode<F>(input: &[u8], bound: usize, encode: F) -> Option<Vec<u8>>
where
    F: FnOnce(&mut [u8], &[u8]) -> Option<usize>,
{
    let mut dst = vec![0u8; bound];
    let written = encode(&mut dst, input)?;
    debug_assert!(written <= dst.len(), "crush encoder reported {written} bytes into a {}-byte buffer", dst.len());
    // Done explicitly rather than via a short buffer: costs a
    // `compress_bound`-sized allocation, but the input is one 64 KiB chunk.
    if written >= input.len() {
        return None;
    }
    dst.truncate(written);
    Some(dst)
}

/// Compresses to the zlib-wrapped DEFLATE the decmpfs type 3/4 decoder
/// requires, via libdeflate.
///
/// A libdeflate compressor is bound to its level at construction, so
/// `compressor` carries the level it was built for and is rebuilt only when
/// a caller asks for a different one - in practice once per run.
fn compress_zlib(input: &[u8], level: u8, compressor: &mut Option<(u8, libdeflater::Compressor)>) -> Option<Vec<u8>> {
    if !matches!(compressor, Some((l, _)) if *l == level) {
        // Level 0 means "emit uncompressed blocks" (can only grow input);
        // `parse_algo_spec` rejects it upstream, but don't trust that here.
        let lvl = libdeflater::CompressionLvl::new(i32::from(level)).ok()?;
        if level == 0 {
            return None;
        }
        *compressor = Some((level, libdeflater::Compressor::new(lvl)));
    }
    let comp = &mut compressor.as_mut().expect("just constructed above").1;
    let mut out = vec![0u8; comp.zlib_compress_bound(input.len())];
    // libdeflate, like LZBITMAP and LZ4 above, wants a bound-sized buffer, so
    // the shrink is tested here rather than by handing it a short one.
    let written = comp.zlib_compress(input, &mut out).ok()?;
    if written >= input.len() {
        return None;
    }
    out.truncate(written);
    Some(out)
}


fn decompress_zlib(input: &[u8], uncompressed_len: usize) -> Option<Vec<u8>> {
    // Exact output size is always known here (decmpfs records it), which is
    // exactly what libdeflate's decompressor wants - no growth loop needed.
    let mut out = vec![0u8; uncompressed_len];
    let n = libdeflater::Decompressor::new().zlib_decompress(input, &mut out).ok()?;
    if n != uncompressed_len {
        return None;
    }
    Some(out)
}

/// Decompresses `input` (produced by `compress_chunk` with the same `algo`)
/// back to exactly `uncompressed_len` bytes.
pub fn decompress_chunk(input: &[u8], algo: Algo, uncompressed_len: usize) -> Option<Vec<u8>> {
    // Nothing decmpfs stores decodes to more than one chunk: resource-fork
    // chunks are at most 64 KiB, and the kernel refuses inline files larger
    // than that. The claim comes from an on-disk header, so bound it before
    // it sizes a buffer.
    if uncompressed_len > crate::decmpfs::CHUNK_SIZE {
        return None;
    }
    if algo == Algo::Stored {
        if input.len() != uncompressed_len {
            return None;
        }
        return Some(input.to_vec());
    }
    if uncompressed_len == 0 {
        // A claimed length of 0 is valid only alongside empty input; real
        // compressed bytes with a 0 claim must be rejected.
        return if input.is_empty() { Some(Vec::new()) } else { None };
    }
    if matches!(algo, Algo::Zlib(_)) {
        return decompress_zlib(input, uncompressed_len); // the level never affects decoding
    }
    let raw = algo.raw().expect("non-Zlib, non-Stored algo always has a raw id");
    // One byte larger than claimed, not exact: an exact buffer would fill and
    // report `written == uncompressed_len` even on a truncated over-long
    // decode, hiding the mismatch. The extra byte surfaces it instead.
    let mut dst = vec![0u8; uncompressed_len + 1];
    let written = unsafe {
        sys::compression_decode_buffer(
            dst.as_mut_ptr(),
            dst.len(),
            input.as_ptr(),
            input.len(),
            ptr::null_mut::<c_void>(),
            raw,
        )
    };
    debug_assert!(
        written <= dst.len(),
        "compression_decode_buffer reported writing {written} bytes into a {}-byte buffer",
        dst.len()
    );
    if written != uncompressed_len {
        return None;
    }
    dst.truncate(uncompressed_len);
    Some(dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compressible_data() -> Vec<u8> {
        b"The quick brown fox jumps over the lazy dog. ".repeat(2000)
    }

    /// Same as `compressible_data`, capped at one decmpfs chunk (65536
    /// bytes): CrushLzfse's optimal levels hard-cap at that size.
    fn compressible_data_one_chunk() -> Vec<u8> {
        b"The quick brown fox jumps over the lazy dog. ".iter().copied().cycle().take(65536).collect()
    }

    fn incompressible_data() -> Vec<u8> {
        // Pseudo-random, no external RNG dependency needed for a deterministic test.
        let mut v = Vec::with_capacity(65536);
        let mut x: u32 = 0x2545F491;
        for _ in 0..65536 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            v.push((x & 0xff) as u8);
        }
        v
    }

    #[test]
    fn zlib_roundtrip() {
        let data = compressible_data_one_chunk();
        let compressed = compress_chunk(&data, Algo::Zlib(9)).expect("should compress");
        assert!(compressed.len() < data.len());
        let back = decompress_chunk(&compressed, Algo::Zlib(9), data.len()).expect("should decompress");
        assert_eq!(back, data);
    }

    #[test]
    fn lzfse_roundtrip() {
        let data = compressible_data_one_chunk();
        let compressed = compress_chunk(&data, Algo::Lzfse).expect("should compress");
        assert!(compressed.len() < data.len());
        let back = decompress_chunk(&compressed, Algo::Lzfse, data.len()).expect("should decompress");
        assert_eq!(back, data);
    }

    #[test]
    fn lzvn_roundtrip() {
        let data = compressible_data_one_chunk();
        let compressed = compress_chunk(&data, Algo::Lzvn).expect("should compress");
        assert!(compressed.len() < data.len());
        let back = decompress_chunk(&compressed, Algo::Lzvn, data.len()).expect("should decompress");
        assert_eq!(back, data);
    }

    #[test]
    fn lzbitmap_roundtrip() {
        let data = compressible_data_one_chunk();
        let compressed = compress_chunk(&data, Algo::Lzbitmap).expect("should compress");
        assert!(compressed.len() < data.len());
        let back = decompress_chunk(&compressed, Algo::Lzbitmap, data.len()).expect("should decompress");
        assert_eq!(back, data);
    }


    #[test]
    fn crushlzfse_roundtrip() {
        let data = compressible_data_one_chunk();
        // Level 4 is crushlzfse's cheapest optimal-parse level - below it
        // silently takes the greedy path, which isn't what this tests.
        let compressed = compress_chunk(&data, Algo::CrushLzfse(4)).expect("should compress");
        assert!(compressed.len() < data.len());
        let back = decompress_chunk(&compressed, Algo::CrushLzfse(4), data.len()).expect("should decompress");
        assert_eq!(back, data);
    }

    // decmpfs records only a type (11/12), never which encoder wrote it, so
    // bytes from either encoder must decode via the other.
    #[test]
    fn crushlzfse_output_decodes_as_lzfse_and_vice_versa() {
        let data = compressible_data_one_chunk();
        let via_crush = compress_chunk(&data, Algo::CrushLzfse(3)).expect("should compress");
        let back = decompress_chunk(&via_crush, Algo::Lzfse, data.len()).expect("should decompress");
        assert_eq!(back, data);

        let via_lzfse = compress_chunk(&data, Algo::Lzfse).expect("should compress");
        let back = decompress_chunk(&via_lzfse, Algo::CrushLzfse(3), data.len()).expect("should decompress");
        assert_eq!(back, data);
    }

    #[test]
    fn crushlzfse_reused_scratch_across_growing_levels() {
        // Must not corrupt memory or panic when scratch grows between calls.
        let data = compressible_data_one_chunk();
        let mut scratch = EncodeScratch::default();
        let small = compress_chunk_with_scratch(&data, Algo::CrushLzfse(0), &mut scratch).expect("encode low level");
        let big = compress_chunk_with_scratch(&data, Algo::CrushLzfse(10), &mut scratch).expect("encode high level");
        for compressed in [small, big] {
            let back = decompress_chunk(&compressed, Algo::CrushLzfse(0), data.len()).expect("should decompress");
            assert_eq!(back, data);
        }
    }

    #[test]
    fn stored_roundtrip_is_identity() {
        let data = incompressible_data();
        let stored = compress_chunk(&data, Algo::Stored).expect("stored always succeeds");
        assert_eq!(stored, data);
        let back = decompress_chunk(&stored, Algo::Stored, data.len()).expect("should decompress");
        assert_eq!(back, data);
    }

    #[test]
    fn incompressible_data_fails_to_shrink() {
        let data = incompressible_data();
        // The case the decmpfs stored fallback exists for.
        for algo in [Algo::Zlib(9), Algo::Zlib(1), Algo::Lzfse, Algo::CrushLzfse(3), Algo::Lzvn, Algo::Lzbitmap] {
            assert!(
                compress_chunk(&data, algo).is_none(),
                "{algo:?} unexpectedly shrank incompressible data"
            );
        }
    }

    #[test]
    fn empty_input_never_compresses() {
        assert!(compress_chunk(&[], Algo::Zlib(9)).is_none());
        assert!(compress_chunk(&[], Algo::Zlib(1)).is_none());
        assert!(compress_chunk(&[], Algo::Lzfse).is_none());
    }

    // Stored uniquely succeeds on empty input; intentional (see
    // `Algo::Stored`) but easy to regress silently.
    #[test]
    fn stored_uniquely_succeeds_on_empty_input() {
        assert_eq!(compress_chunk(&[], Algo::Stored), Some(Vec::new()));
        for algo in [Algo::Zlib(9), Algo::Zlib(1), Algo::Lzfse, Algo::CrushLzfse(3), Algo::Lzvn, Algo::Lzbitmap] {
            assert_eq!(compress_chunk(&[], algo), None, "{algo:?} should refuse empty input");
        }
    }

    // Stresses the scratch-buffer reuse path (compress_chunk_with_scratch).
    #[test]
    fn maximally_repetitive_data_compresses_and_roundtrips() {
        for algo in [Algo::Zlib(9), Algo::Zlib(1), Algo::Lzfse, Algo::CrushLzfse(3), Algo::Lzvn, Algo::Lzbitmap] {
            let data = vec![0x41u8; 65536]; // one repeated byte, full chunk size
            let compressed = compress_chunk(&data, algo).expect("must compress trivially");
            // Ratio-based, not a fixed byte bar: LZVN's byte-oriented format
            // pays real per-token overhead even on one repeated byte.
            assert!(
                compressed.len() * 100 < data.len(),
                "{algo:?} compressed a single repeated byte to {} bytes, expected >100x compression",
                compressed.len()
            );
            let back = decompress_chunk(&compressed, algo, data.len()).expect("must decompress");
            assert_eq!(back, data);
        }
    }

    // The `cap = input.len() - 1` boundary in compress_chunk_with_scratch:
    // cap=0 for 1 byte, cap=1 for 2 bytes.
    #[test]
    fn single_byte_input_never_compresses() {
        // cap = input.len() - 1 = 0, so this short-circuits before calling
        // into libcompression/libdeflate at all.
        for algo in [Algo::Zlib(9), Algo::Zlib(1), Algo::Lzfse, Algo::CrushLzfse(3), Algo::Lzvn, Algo::Lzbitmap] {
            assert_eq!(compress_chunk(&[0x41], algo), None, "{algo:?} should refuse 1-byte input");
        }
    }

    #[test]
    fn two_byte_repetitive_input_roundtrips_if_it_shrinks() {
        // cap = 1: only a 1-byte result counts as shrunk. Rare, but if
        // `compress_chunk` returns `Some` here it must still be correct.
        for algo in [Algo::Zlib(9), Algo::Zlib(1), Algo::Lzfse, Algo::CrushLzfse(3), Algo::Lzvn, Algo::Lzbitmap] {
            let data = [0x41u8, 0x41];
            if let Some(compressed) = compress_chunk(&data, algo) {
                assert_eq!(compressed.len(), 1);
                let back = decompress_chunk(&compressed, algo, data.len()).expect("must decompress");
                assert_eq!(back, data);
            }
        }
    }

    // Models a corrupted/tampered decmpfs header disagreeing with its
    // payload.
    #[test]
    fn decompress_chunk_rejects_mismatched_uncompressed_len() {
        for algo in [Algo::Zlib(9), Algo::Zlib(1), Algo::Lzfse, Algo::CrushLzfse(3), Algo::Lzvn, Algo::Lzbitmap] {
            // CrushLzfse caps input at 65536 bytes; other algos use the
            // larger compressible_data() to stress beyond one chunk.
            let data = if matches!(algo, Algo::CrushLzfse(_)) { compressible_data_one_chunk() } else { compressible_data() };
            let compressed = compress_chunk(&data, algo).expect("should compress");

            assert!(
                decompress_chunk(&compressed, algo, data.len() - 1).is_none(),
                "{algo:?}: claimed length one byte too small must be rejected"
            );
            assert!(
                decompress_chunk(&compressed, algo, data.len() + 1).is_none(),
                "{algo:?}: claimed length one byte too large must be rejected"
            );
            assert!(
                decompress_chunk(&compressed, algo, 0).is_none(),
                "{algo:?}: claimed length of zero against real compressed data must be rejected"
            );
        }
    }

    #[test]
    fn decompress_chunk_rejects_garbage_bytes() {
        // Must fail cleanly, never panic or read out of bounds.
        let garbage = vec![0xDEu8, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
        for algo in [Algo::Zlib(9), Algo::Zlib(1), Algo::Lzfse, Algo::CrushLzfse(3), Algo::Lzvn, Algo::Lzbitmap] {
            assert_eq!(decompress_chunk(&garbage, algo, 65536), None, "{algo:?} must reject garbage input");
        }
    }
}

#[cfg(test)]
mod os_version_tests {
    use super::*;

    #[test]
    fn parses_the_version_shapes_macos_actually_reports() {
        assert_eq!(parse_os_version("27.0"), Some((27, 0)));
        assert_eq!(parse_os_version("10.11.6"), Some((10, 11)), "the patch component is ignored");
        assert_eq!(parse_os_version("27"), Some((27, 0)), "a bare major means minor 0");
        assert_eq!(parse_os_version(" 12.0 "), Some((12, 0)));
        assert_eq!(parse_os_version(""), None);
        assert_eq!(parse_os_version("sonoma"), None);
        assert_eq!(parse_os_version("27.x"), None, "a garbage minor is not silently 0");
    }

    #[test]
    fn version_ordering_is_the_comparison_we_rely_on() {
        assert!(parse_os_version("10.11").unwrap() < parse_os_version("12.0").unwrap());
        assert!(parse_os_version("12.0").unwrap() < parse_os_version("27.0").unwrap());
        // The old 10.x scale compares on the minor, not lexically.
        assert!(parse_os_version("10.6").unwrap() < parse_os_version("10.11").unwrap());
    }

    #[test]
    fn os_version_reads_a_real_version_from_the_kernel() {
        let v = os_version();
        // decmpfs itself is 10.6, so anything running this test is at least
        // that. Catches both a failed sysctl silently reading as (0, 0) and
        // a parse that lost the major.
        assert!(v >= (10, 6), "implausible OS version {v:?}");
        // Cross-check against the value `sw_vers` reports, which is the
        // same field by a different route.
        let sw = std::process::Command::new("sw_vers").arg("-productVersion").output().expect("sw_vers");
        let reported = parse_os_version(std::str::from_utf8(&sw.stdout).unwrap()).expect("sw_vers version");
        assert_eq!(v, reported, "kern.osproductversion disagrees with sw_vers");
    }

    #[test]
    fn the_floor_is_per_decmpfs_type_not_per_encoder() {
        // Same on-disk type => same floor, whichever encoder produced it.
        assert_eq!(min_os_version(Algo::Lzfse), min_os_version(Algo::CrushLzfse(6)));
        assert_eq!(min_os_version(Algo::Zlib(9)), min_os_version(Algo::Zlib(ZLIB_DEFAULT_LEVEL)));
        // And the level carried by a variant never changes its floor.
        assert_eq!(min_os_version(Algo::CrushLzfse(-2)), min_os_version(Algo::CrushLzfse(10)));
        assert_eq!(min_os_version(Algo::Lzvn), min_os_version(Algo::CrushLzvn(8)));
        assert_eq!(min_os_version(Algo::Lzbitmap), min_os_version(Algo::CrushLzbitmap(7)));
        assert_eq!(min_os_version(Algo::Lz4), min_os_version(Algo::CrushLz4(6)));
        // The floors must be ordered as the formats actually shipped, since
        // that ordering is what makes the check meaningful at all.
        assert!(min_os_version(Algo::Zlib(9)) < min_os_version(Algo::Lzvn));
        assert!(min_os_version(Algo::Lzvn) < min_os_version(Algo::Lzfse));
        assert!(min_os_version(Algo::Lzfse) < min_os_version(Algo::Lzbitmap));
        assert!(min_os_version(Algo::Lzbitmap) < min_os_version(Algo::Lz4));
    }

    #[test]
    fn everything_we_ship_today_is_supported_on_a_modern_system() {
        // Every pre-LZ4 format predates any macOS that can run this, so the
        // check must not exclude any of them - a regression here would mean
        // the version gate silently disabled a working algorithm.
        for algo in all_algos() {
            if min_os_version(algo) > (12, 0) {
                continue; // LZ4 is the one floor a supported machine can fail
            }
            assert!(is_supported(algo), "{algo:?} should be supported on {:?}", os_version());
        }
        let supported = supported_algos();
        assert!(supported.contains(&Algo::Lzfse));
        // Everything but LZ4's two encoders is available on any machine that
        // can run this at all; those two depend on the running OS. Derived
        // from `all_algos` rather than hardcoded, so adding or removing an
        // encoder doesn't make this assertion a liar.
        let lz4_encoders = all_algos().into_iter().filter(|&a| min_os_version(a) == (27, 0)).count();
        let expected = if os_version() >= (27, 0) { all_algos().len() } else { all_algos().len() - lz4_encoders };
        assert_eq!(supported.len(), expected, "unexpected inventory on {:?}: {supported:?}", os_version());
    }
}

#[cfg(test)]
mod crush_encoder_tests {
    use super::*;

    fn compressible(n: usize) -> Vec<u8> {
        b"The quick brown fox jumps over the lazy dog. ".iter().copied().cycle().take(n).collect()
    }

    fn incompressible(n: usize) -> Vec<u8> {
        let mut x: u32 = 0x2545_F491;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x & 0xff) as u8
            })
            .collect()
    }

    /// The four crush encoders at their defaults, plus the Apple encoder for
    /// each format, so a failure names which pairing broke.
    fn every_encoder() -> Vec<Algo> {
        all_algos().into_iter().filter(|&a| is_supported(a)).collect()
    }

    #[test]
    fn every_encoder_shrinks_compressible_input_and_survives_the_system_decoder() {
        // Small enough that LZBITMAP/LZ4 would reject an `input.len() - 1`
        // buffer despite shrinking, pinning the `crush_encode` fix.
        let data = compressible(2250);
        for algo in every_encoder() {
            if algo == Algo::Stored {
                continue; // never compresses, by definition
            }
            let packed = compress_chunk(&data, algo)
                .unwrap_or_else(|| panic!("{algo:?} failed to shrink 2250 bytes of repeated text"));
            assert!(packed.len() < data.len(), "{algo:?}: {} not smaller than {}", packed.len(), data.len());
            let back = decompress_chunk(&packed, algo, data.len())
                .unwrap_or_else(|| panic!("{algo:?}: system decoder rejected our own output"));
            assert_eq!(back, data, "{algo:?}: round-trip mismatch");
        }
    }

    #[test]
    fn every_encoder_declines_incompressible_input_rather_than_growing() {
        // The contract compress_chunk owes: `None`, never output >= input.
        // Each codec's internal stored fallback would otherwise "succeed".
        let data = incompressible(8192);
        for algo in every_encoder() {
            if algo == Algo::Stored {
                continue;
            }
            if let Some(packed) = compress_chunk(&data, algo) {
                assert!(packed.len() < data.len(), "{algo:?} returned {} bytes for {} of noise", packed.len(), data.len());
            }
        }
    }

    #[test]
    fn crush_and_apple_encoders_produce_mutually_decodable_output() {
        // Both encoders must round-trip under both the system decoder and
        // the independent crush decoder, rather than routing both checks
        // through decompress_chunk's system-only decode path.
        for data in [compressible(2250), compressible(40_000), compressible(65_536)] {
            for (apple, crush) in [
                (Algo::Lzfse, Algo::CrushLzfse(CRUSHLZFSE_DEFAULT_LEVEL)),
                (Algo::Lzvn, Algo::CrushLzvn(CRUSHLZVN_DEFAULT_LEVEL)),
                (Algo::Lzbitmap, Algo::CrushLzbitmap(CRUSHLZBITMAP_DEFAULT_LEVEL)),
                (Algo::Lz4, Algo::CrushLz4(CRUSHLZ4_DEFAULT_LEVEL)),
            ] {
                if !is_supported(apple) {
                    continue;
                }
                for encoder in [apple, crush] {
                    let packed = compress_chunk(&data, encoder).expect("encoder");
                    assert_eq!(decompress_chunk(&packed, apple, data.len()).as_deref(), Some(&data[..]),
                        "{encoder:?} output failed system decoding at {} bytes", data.len());
                    let back = match crush {
                        Algo::CrushLzfse(_) => crushlzfse::decompress(&packed).expect("crush LZFSE decoder"),
                        Algo::CrushLzvn(_) => crushlzfse::lzvn::decompress(&packed).expect("crush LZVN decoder"),
                        Algo::CrushLzbitmap(_) => lzbitmap::decompress(&packed).expect("crush LZBITMAP decoder"),
                        Algo::CrushLz4(_) => crushlz4::decompress(&packed).expect("crush LZ4 decoder"),
                        _ => unreachable!(),
                    };
                    assert_eq!(back, data, "{encoder:?} output failed crush decoding at {} bytes", data.len());
                }
            }
        }
    }

    #[test]
    fn one_scratch_serves_every_crush_encoder_in_turn() {
        // `EncodeScratch` holds all four regions at once and a race hands the
        // same one to every codec; reuse must not change any codec's output.
        let data = compressible(30_000);
        let mut scratch = EncodeScratch::default();
        let crush = [
            Algo::CrushLzfse(CRUSHLZFSE_DEFAULT_LEVEL),
            Algo::CrushLzvn(CRUSHLZVN_DEFAULT_LEVEL),
            Algo::CrushLzbitmap(CRUSHLZBITMAP_DEFAULT_LEVEL),
            Algo::CrushLz4(CRUSHLZ4_DEFAULT_LEVEL),
        ];
        // Each algo runs twice, against the same shared scratch, compared to
        // a compress_chunk call that uses a fresh one each time.
        for algo in crush.iter().chain(crush.iter()).copied() {
            let shared = compress_chunk_with_scratch(&data, algo, &mut scratch).expect("shared scratch");
            let fresh = compress_chunk(&data, algo).expect("fresh scratch");
            assert_eq!(shared, fresh, "{algo:?} output changed under a reused scratch");
        }
    }
}
