//! The decmpfs container format itself - independent of libcompression,
//! independent of the filesystem calls that write it. Pure byte-layout logic;
//! the xattr header matches XNU's open-source `bsd/sys/decmpfs.h`.

use crate::algo::Algo;

pub const MAGIC: u32 = 0x636d_7066;
pub const HEADER_LEN: usize = 16;
pub const CHUNK_SIZE: usize = 65536;
pub const MAX_XATTR_TOTAL: usize = 3802;
/// Payload room after the 16-byte header. For type 9 (Stored), one of these
/// bytes is the mandatory 0xCC sentinel, so real plaintext capacity is one
/// less than for the other inline types (7/11/13), which have no sentinel.
pub const MAX_INLINE_PAYLOAD: usize = MAX_XATTR_TOTAL - HEADER_LEN; // 3786

pub fn max_inline_payload_for(algo: Algo) -> usize {
    if algo == Algo::Stored {
        MAX_INLINE_PAYLOAD - 1 // 3785: one byte is the sentinel
    } else {
        MAX_INLINE_PAYLOAD
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub compression_type: u32,
    pub uncompressed_size: u64,
}

impl Header {
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&self.compression_type.to_le_bytes());
        buf[8..16].copy_from_slice(&self.uncompressed_size.to_le_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_LEN {
            return None;
        }
        let magic = u32::from_le_bytes(buf[0..4].try_into().ok()?);
        if magic != MAGIC {
            return None;
        }
        let compression_type = u32::from_le_bytes(buf[4..8].try_into().ok()?);
        let uncompressed_size = u64::from_le_bytes(buf[8..16].try_into().ok()?);
        Some(Header { compression_type, uncompressed_size })
    }
}

/// Inline (xattr-only) decmpfs type for `algo`.
pub fn xattr_type(algo: Algo) -> u32 {
    match algo {
        Algo::Zlib(_) => 3,
        Algo::Lzvn | Algo::CrushLzvn(_) => 7,
        Algo::Stored => 9,
        Algo::Lzfse | Algo::CrushLzfse(_) => 11,
        Algo::Lzbitmap | Algo::CrushLzbitmap(_) => 13,
        Algo::Lz4 | Algo::CrushLz4(_) => 15,
    }
}

/// Resource-fork (64KB-chunked) type for `algo`, if one exists. ZLIB (type 4)
/// uses a different on-disk layout than the standard chunk table every other
/// type here uses (see `build_resource_fork_zlib`/`parse_chunk_table_zlib`),
/// determined by inspecting files written by macOS and checking variations
/// against the kernel decoder.
pub fn rsrc_type(algo: Algo) -> Option<u32> {
    match algo {
        Algo::Zlib(_) => Some(4),
        Algo::Lzvn | Algo::CrushLzvn(_) => Some(8),
        Algo::Stored => Some(10),
        Algo::Lzfse | Algo::CrushLzfse(_) => Some(12),
        Algo::Lzbitmap | Algo::CrushLzbitmap(_) => Some(14),
        Algo::Lz4 | Algo::CrushLz4(_) => Some(16),
    }
}

/// Whether `algo` writes/reads the type 3/4 ZLIB container. Call sites that
/// branch on the ZLIB on-disk layout should use this rather than matching
/// the variant directly, so it stays correct if another DEFLATE encoder
/// ever shares the container.
pub fn uses_zlib_container(algo: Algo) -> bool {
    matches!(algo, Algo::Zlib(_))
}

/// Inverse of `xattr_type`/`rsrc_type`: which algorithm (if any) a decmpfs
/// header's `compression_type` field corresponds to, for decode-path
/// dispatch only (never re-encoding). Two things this list is deliberate
/// about:
/// - `Zlib` gets a nominal level, since the level isn't stored on disk.
/// - `Lzfse`, never `CrushLzfse`: type 11/12 never records which encoder
///   produced a file, so there's nothing else to recover.
pub fn algo_for_type(t: u32) -> Option<Algo> {
    [Algo::Zlib(0), Algo::Lzvn, Algo::Stored, Algo::Lzfse, Algo::Lzbitmap, Algo::Lz4]
        .into_iter()
        .find(|&a| xattr_type(a) == t || rsrc_type(a) == Some(t))
}

/// Per-chunk stored-sentinel byte for the chunked (rsrc) formats: the first
/// byte of a chunk's on-disk data marking "this chunk is raw, not
/// compressed." Safe by construction of each algorithm's bitstream framing
/// (e.g. 0x06 is LZVN's own end-of-stream opcode, which real compressed
/// output can never start with). Type 10 (Stored) uses this on every chunk.
pub fn chunk_stored_sentinel(algo: Algo) -> u8 {
    match algo {
        Algo::Lzvn | Algo::CrushLzvn(_) => 0x06,
        // 0xFF is safe for LZ4 too: Apple's frame always opens with a `bv4`
        // magic (`bv41`/`bv4-`/`bv4$`), never 0xFF.
        Algo::Lzfse
        | Algo::CrushLzfse(_)
        | Algo::Lzbitmap
        | Algo::CrushLzbitmap(_)
        | Algo::Lz4
        | Algo::CrushLz4(_)
        | Algo::Zlib(_) => 0xFF,
        Algo::Stored => 0xCC,
    }
}

/// Builds an inline decmpfs xattr payload (header + payload) for types
/// 3/7/9/11/13. `payload` is the algorithm's raw output for non-Stored algos,
/// or the raw plaintext itself for Stored (this function adds the 0xCC
/// prefix). Caller must ensure `payload.len() <= max_inline_payload_for(algo)`.
pub fn build_inline(algo: Algo, uncompressed_size: u64, payload: &[u8]) -> Vec<u8> {
    let header = Header { compression_type: xattr_type(algo), uncompressed_size };
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len() + 1);
    out.extend_from_slice(&header.to_bytes());
    if algo == Algo::Stored {
        out.push(0xCC);
    }
    out.extend_from_slice(payload);
    out
}

/// Parses an inline decmpfs xattr payload back into raw plaintext bytes
/// (decompressing if necessary). `algo` must match the header's declared type.
pub fn parse_inline(algo: Algo, xattr_value: &[u8]) -> Option<Vec<u8>> {
    let header = Header::from_bytes(xattr_value)?;
    // The kernel refuses inline files larger than one chunk.
    if header.compression_type != xattr_type(algo) || header.uncompressed_size > CHUNK_SIZE as u64 {
        return None;
    }
    let payload = &xattr_value[HEADER_LEN..];
    if algo == Algo::Stored {
        if payload.first() != Some(&0xCC) || (payload.len() - 1) as u64 != header.uncompressed_size {
            return None;
        }
        return Some(payload[1..].to_vec());
    }
    crate::algo::decompress_chunk(payload, algo, header.uncompressed_size as usize)
}

/// One chunk's final on-disk bytes, already resolved to either real
/// compressed output or the sentinel+raw stored fallback.
pub struct ChunkOutput {
    pub bytes: Vec<u8>,
}

/// Resolves a chunk to its on-disk form. `compressed` is `compress_chunk`'s
/// result for this chunk, taken by value rather than copied. `None` (or
/// Stored) always falls back to the sentinel+raw form.
pub fn encode_chunk(algo: Algo, uncompressed: &[u8], compressed: Option<Vec<u8>>) -> ChunkOutput {
    match compressed {
        Some(bytes) if algo != Algo::Stored => ChunkOutput { bytes },
        _ => {
            let mut bytes = Vec::with_capacity(uncompressed.len() + 1);
            bytes.push(chunk_stored_sentinel(algo));
            bytes.extend_from_slice(uncompressed);
            ChunkOutput { bytes }
        }
    }
}

/// Decodes one chunk's on-disk bytes back to `uncompressed_len` plaintext bytes.
pub fn decode_chunk(algo: Algo, raw: &[u8], uncompressed_len: usize) -> Option<Vec<u8>> {
    if raw.is_empty() {
        return if uncompressed_len == 0 { Some(Vec::new()) } else { None };
    }
    let sentinel = chunk_stored_sentinel(algo);
    if raw[0] == sentinel {
        let plain = &raw[1..];
        return if plain.len() == uncompressed_len {
            Some(plain.to_vec())
        } else {
            None
        };
    }
    crate::algo::decompress_chunk(raw, algo, uncompressed_len)
}

/// Computes each chunk's cumulative end offset into the resource fork,
/// starting from `table_size`. Split out from `build_resource_fork` so the
/// overflow boundary can be tested with synthetic sizes instead of
/// allocating multi-gigabyte buffers.
///
/// Panics (in every build profile - a hard format limit, not an internal
/// invariant) if the cumulative offset would exceed `u32::MAX`: the on-disk
/// chunk table stores offsets as 32-bit fields, so truncating via `as u32`
/// would wrap into a corrupt table instead of failing loudly.
fn chunk_end_offsets(table_size: usize, chunk_sizes: &[usize]) -> Vec<u32> {
    let mut offset = table_size;
    chunk_sizes
        .iter()
        .map(|&len| {
            offset += len;
            u32::try_from(offset)
                .expect("resource fork exceeds 4GiB - decmpfs chunk table offsets are 32-bit")
        })
        .collect()
}

/// Builds the full `com.apple.ResourceFork` blob: chunk table + chunk data.
pub fn build_resource_fork(chunks: &[ChunkOutput]) -> Vec<u8> {
    let table_size = (chunks.len() + 1) * 4;
    let sizes: Vec<usize> = chunks.iter().map(|c| c.bytes.len()).collect();
    let offsets = chunk_end_offsets(table_size, &sizes);
    let data_len: usize = sizes.iter().sum();
    let mut out = Vec::with_capacity(table_size + data_len);
    out.extend_from_slice(
        &u32::try_from(table_size)
            .expect("chunk table too large - too many chunks")
            .to_le_bytes(),
    );
    for end in &offsets {
        out.extend_from_slice(&end.to_le_bytes());
    }
    for c in chunks {
        out.extend_from_slice(&c.bytes);
    }
    out
}

/// Parses a resource-fork blob's chunk table into (start, end) byte ranges
/// into the blob, one per chunk.
pub fn parse_chunk_table(rsrc: &[u8]) -> Option<Vec<(usize, usize)>> {
    if rsrc.len() < 4 {
        return None;
    }
    let table_size = u32::from_le_bytes(rsrc[0..4].try_into().ok()?) as usize;
    if table_size < 4 || table_size > rsrc.len() || !table_size.is_multiple_of(4) {
        return None;
    }
    let num_chunks = table_size / 4 - 1;
    let mut ranges = Vec::with_capacity(num_chunks);
    let mut start = table_size;
    for i in 0..num_chunks {
        let off = 4 + i * 4;
        let end = u32::from_le_bytes(rsrc[off..off + 4].try_into().ok()?) as usize;
        if end < start || end > rsrc.len() {
            return None;
        }
        ranges.push((start, end));
        start = end;
    }
    // The kernel rejects a fork that runs past its last chunk, so match it.
    if start != rsrc.len() {
        return None;
    }
    Some(ranges)
}

/// decmpfs type 4 (ZLIB resource fork): offset from the resource fork's start
/// to the block-descriptor block. Real macOS-written files always use
/// exactly 256 (240 zero bytes after the 16-byte header), and that value is
/// load-bearing: any other offset makes the real kernel decompressor fail
/// the read with `EINVAL`. The padding bytes' content is cosmetic; written
/// as zero to match real macOS output.
pub const ZLIB_RSRC_DESC_OFFSET: u32 = 256;

/// decmpfs type 4 footer, appended after a ZLIB resource fork's compressed
/// block data. Reverse-engineered from real macOS-written files since this
/// layout isn't documented precisely enough to implement from spec text
/// alone. Checked byte-for-byte on read: flipping any bit, or omitting it,
/// makes the kernel decompressor fail with `EINVAL`, so it must be written
/// verbatim. By contrast the header's `footer_off`/`desc_size` fields and
/// the descriptor block's "compressed data size" can be garbage and still
/// read fine, so the kernel most likely locates this footer by its fixed
/// 50-byte length from the end, not via `footer_off`.
///
/// All fields big-endian except the one noted. Byte layout:
///   `[0..24)`  zero
///   `[24..26)` `0x001C` (28)   - unknown meaning, constant across every observed file
///   `[26..28)` `0x0032` (50)   - this footer's own length
///   `[28..30)` zero
///   `[30..34)` `"cmpf"` (ASCII - i.e. `MAGIC.to_be_bytes()`)
///   `[34..38)` `0x0000000A` (10) - unknown meaning, constant across every observed file
///   `[38..46)` `0x00000000_FFFF0100` stored little-endian - the one LE field in the footer
///   `[46..50)` zero
pub const ZLIB_RSRC_FOOTER: [u8; 50] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0..24
    0x00, 0x1c, // 24..26
    0x00, 0x32, // 26..28
    0x00, 0x00, // 28..30
    0x63, 0x6d, 0x70, 0x66, // 30..34 "cmpf"
    0x00, 0x00, 0x00, 0x0a, // 34..38
    0x00, 0x01, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, // 38..46 (LE u64 0xFFFF0100)
    0, 0, 0, 0, // 46..50
];

/// Combined size (bytes) of everything a chunked resource fork needs beyond
/// the raw chunk data itself. `algo`-dependent, since ZLIB (type 4) uses a
/// different layout (see `ZLIB_RSRC_DESC_OFFSET`/`ZLIB_RSRC_FOOTER`) from
/// every other chunked type's flat LE offset table. Single source of truth
/// so footprint predictions agree with the real writers.
pub fn rsrc_footprint_overhead(algo: Algo, num_chunks: usize) -> u64 {
    if uses_zlib_container(algo) {
        ZLIB_RSRC_DESC_OFFSET as u64 + 8 + (num_chunks as u64) * 8 + ZLIB_RSRC_FOOTER.len() as u64
    } else {
        (num_chunks as u64 + 1) * 4
    }
}

/// Builds the full `com.apple.ResourceFork` blob for `algo`, dispatching to
/// the ZLIB (type 4) layout or the standard LE chunk table as appropriate.
/// The single place that branch lives, so callers don't repeat it.
pub fn build_resource_fork_for(algo: Algo, chunks: &[ChunkOutput]) -> Vec<u8> {
    if uses_zlib_container(algo) {
        build_resource_fork_zlib(chunks)
    } else {
        build_resource_fork(chunks)
    }
}

/// Builds the full ZLIB (type 4) `com.apple.ResourceFork` blob: big-endian
/// header, mixed-endian block-descriptor table, chunk data, then the fixed
/// footer. See `ZLIB_RSRC_DESC_OFFSET`/`ZLIB_RSRC_FOOTER` for how this layout
/// was determined. Companion to `build_resource_fork` (the standard LE
/// format every other chunked type uses).
pub fn build_resource_fork_zlib(chunks: &[ChunkOutput]) -> Vec<u8> {
    let n = chunks.len();
    let desc_off = ZLIB_RSRC_DESC_OFFSET as usize;
    let tuples_start = desc_off + 8;
    let data_start = tuples_start + n * 8;
    let data_total: usize = chunks.iter().map(|c| c.bytes.len()).sum();
    let desc_block_len = 8 + n * 8 + data_total;
    let footer_off = desc_off + desc_block_len;

    let overflow = "resource fork exceeds 4GiB - decmpfs chunk table offsets are 32-bit";
    let desc_off_u32 = u32::try_from(desc_off).expect(overflow);
    let footer_off_u32 = u32::try_from(footer_off).expect(overflow);
    let desc_block_len_u32 = u32::try_from(desc_block_len).expect(overflow);
    let comp_data_size = desc_block_len_u32 - 4;

    let mut out = Vec::with_capacity(footer_off + ZLIB_RSRC_FOOTER.len());
    out.extend_from_slice(&desc_off_u32.to_be_bytes());
    out.extend_from_slice(&footer_off_u32.to_be_bytes());
    out.extend_from_slice(&desc_block_len_u32.to_be_bytes());
    out.extend_from_slice(&(ZLIB_RSRC_FOOTER.len() as u32).to_be_bytes());
    out.resize(desc_off, 0); // zero padding between the header and desc_off - see ZLIB_RSRC_DESC_OFFSET
    out.extend_from_slice(&comp_data_size.to_be_bytes());
    out.extend_from_slice(&(n as u32).to_le_bytes());

    let base = desc_off + 4;
    let mut offset = data_start;
    for c in chunks {
        out.extend_from_slice(&u32::try_from(offset - base).expect(overflow).to_le_bytes());
        out.extend_from_slice(&u32::try_from(c.bytes.len()).expect(overflow).to_le_bytes());
        offset += c.bytes.len();
    }
    for c in chunks {
        out.extend_from_slice(&c.bytes);
    }
    out.extend_from_slice(&ZLIB_RSRC_FOOTER);
    out
}

/// Parses a ZLIB (type 4) resource-fork blob's block-descriptor table into
/// (start, end) byte ranges, one per chunk. Companion to `parse_chunk_table`
/// (the standard LE format). Ignores `footer_off`/`desc_size`/`footer_size`
/// and the footer itself: only `desc_off`, the tuple count, and the tuples
/// are load-bearing for decoding (see `ZLIB_RSRC_FOOTER`). Every
/// offset/length is validated against `rsrc`'s actual bounds, since this is
/// untrusted on-disk input.
pub fn parse_chunk_table_zlib(rsrc: &[u8]) -> Option<Vec<(usize, usize)>> {
    if rsrc.len() < 16 {
        return None;
    }
    let desc_off = u32::from_be_bytes(rsrc[0..4].try_into().ok()?) as usize;
    if desc_off < 16 || desc_off + 8 > rsrc.len() {
        return None;
    }
    let num_tuples = u32::from_le_bytes(rsrc[desc_off + 4..desc_off + 8].try_into().ok()?) as usize;
    let tuples_start = desc_off + 8;
    let tuples_len = num_tuples.checked_mul(8)?;
    let data_region_start = tuples_start.checked_add(tuples_len)?;
    if data_region_start > rsrc.len() {
        return None;
    }
    let base = desc_off + 4;
    let mut ranges = Vec::with_capacity(num_tuples);
    for i in 0..num_tuples {
        let off = tuples_start + i * 8;
        let rel = u32::from_le_bytes(rsrc[off..off + 4].try_into().ok()?) as usize;
        let size = u32::from_le_bytes(rsrc[off + 4..off + 8].try_into().ok()?) as usize;
        let start = base.checked_add(rel)?;
        let end = start.checked_add(size)?;
        if start < data_region_start || end > rsrc.len() {
            return None;
        }
        ranges.push((start, end));
    }
    Some(ranges)
}

/// Number of 64KB chunks (last one possibly shorter) for a file of `size` bytes.
pub fn chunk_count(size: u64) -> usize {
    if size == 0 {
        0
    } else {
        ((size - 1) / CHUNK_SIZE as u64 + 1) as usize
    }
}

/// Uncompressed length of chunk `index` (0-based) for a file of `total_size` bytes.
///
/// Callers must ensure `index` is in range for `total_size` (i.e. came from
/// `chunk_count(total_size)`, not a separately-sourced count that might
/// disagree - see `engine::decompress_bytes`). An out-of-range `index` would
/// underflow the subtraction below; the assert turns that into a loud
/// failure instead of a silent wraparound.
pub fn chunk_len(total_size: u64, index: usize) -> usize {
    let start = index as u64 * CHUNK_SIZE as u64;
    debug_assert!(
        start < total_size,
        "chunk_len: index {index} out of range for total_size {total_size} bytes"
    );
    let remaining = total_size - start;
    remaining.min(CHUNK_SIZE as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = Header { compression_type: 12, uncompressed_size: 274_480 };
        let bytes = h.to_bytes();
        assert_eq!(Header::from_bytes(&bytes), Some(h));
    }

    #[test]
    fn header_rejects_bad_magic() {
        let mut bytes = Header { compression_type: 8, uncompressed_size: 100 }.to_bytes();
        bytes[0] ^= 0xFF;
        assert_eq!(Header::from_bytes(&bytes), None);
    }

    #[test]
    fn inline_type9_roundtrip() {
        let data = b"hello world, this is small".to_vec();
        let payload = data.clone(); // Stored: payload is raw plaintext
        let xattr = build_inline(Algo::Stored, data.len() as u64, &payload);
        assert_eq!(xattr[16], 0xCC);
        let back = parse_inline(Algo::Stored, &xattr).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn inline_lzfse_roundtrip() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
        let compressed = crate::algo::compress_chunk(&data, Algo::Lzfse).unwrap();
        let xattr = build_inline(Algo::Lzfse, data.len() as u64, &compressed);
        let back = parse_inline(Algo::Lzfse, &xattr).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn chunk_table_roundtrip() {
        let chunks = vec![
            ChunkOutput { bytes: vec![1, 2, 3, 4, 5] },
            ChunkOutput { bytes: vec![9, 9] },
            ChunkOutput { bytes: (0..10u8).collect() },
        ];
        let rsrc = build_resource_fork(&chunks);
        let ranges = parse_chunk_table(&rsrc).unwrap();
        assert_eq!(ranges.len(), 3);
        for (i, (start, end)) in ranges.iter().enumerate() {
            assert_eq!(&rsrc[*start..*end], chunks[i].bytes.as_slice());
        }
    }

    #[test]
    fn example_from_spec_single_chunk() {
        // A macOS-written LZVN file: 8360 bytes -> 4581-byte rsrc, type 8.
        // table_size=8 (1 chunk), chunk_ends[0]=4581.
        let chunk = ChunkOutput { bytes: vec![0u8; 4573] };
        let rsrc = build_resource_fork(&[chunk]);
        assert_eq!(u32::from_le_bytes(rsrc[0..4].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(rsrc[4..8].try_into().unwrap()), 4581);
        assert_eq!(rsrc.len(), 4581);
    }

    // --- type 4 (ZLIB resource fork), see `ZLIB_RSRC_DESC_OFFSET`/
    // `ZLIB_RSRC_FOOTER` for how this layout was determined.

    #[test]
    fn zlib_rsrc_roundtrip() {
        let chunks = vec![
            ChunkOutput { bytes: vec![1, 2, 3, 4, 5] },
            ChunkOutput { bytes: vec![9, 9] },
            ChunkOutput { bytes: (0..10u8).collect() },
        ];
        let rsrc = build_resource_fork_zlib(&chunks);
        let ranges = parse_chunk_table_zlib(&rsrc).unwrap();
        assert_eq!(ranges.len(), 3);
        for (i, (start, end)) in ranges.iter().enumerate() {
            assert_eq!(&rsrc[*start..*end], chunks[i].bytes.as_slice());
        }
    }

    #[test]
    fn zlib_rsrc_header_fields_match_real_macos_formula() {
        // Checks the field relationships (footer_off = desc_off + desc_size,
        // comp_data_size = desc_size - 4, etc) that a real afsctool-written
        // file satisfies also hold for our own writer's output.
        let chunks: Vec<ChunkOutput> =
            [11278usize, 11254, 11290, 803].iter().map(|&n| ChunkOutput { bytes: vec![0x78; n] }).collect();
        let rsrc = build_resource_fork_zlib(&chunks);
        let desc_off = u32::from_be_bytes(rsrc[0..4].try_into().unwrap());
        let footer_off = u32::from_be_bytes(rsrc[4..8].try_into().unwrap());
        let desc_size = u32::from_be_bytes(rsrc[8..12].try_into().unwrap());
        let footer_size = u32::from_be_bytes(rsrc[12..16].try_into().unwrap());
        assert_eq!(desc_off, ZLIB_RSRC_DESC_OFFSET);
        assert_eq!(footer_size, ZLIB_RSRC_FOOTER.len() as u32);
        assert_eq!(footer_off, desc_off + desc_size);
        assert_eq!(rsrc.len(), footer_off as usize + footer_size as usize);

        let comp_data_size = u32::from_be_bytes(
            rsrc[desc_off as usize..desc_off as usize + 4].try_into().unwrap(),
        );
        assert_eq!(comp_data_size, desc_size - 4);
        let num_tuples =
            u32::from_le_bytes(rsrc[desc_off as usize + 4..desc_off as usize + 8].try_into().unwrap());
        assert_eq!(num_tuples, 4);
        assert_eq!(&rsrc[footer_off as usize..], &ZLIB_RSRC_FOOTER);
    }

    #[test]
    fn zlib_rsrc_parses_real_macos_padded_layout() {
        // Real macOS/afsctool-written files pad desc_off out to 256, unlike
        // our own writer; the parser must follow whatever offset is
        // actually in the header field, not assume our own writer's value.
        let mut rsrc = vec![0u8; 256];
        rsrc[0..4].copy_from_slice(&256u32.to_be_bytes()); // desc_off
        rsrc.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // comp_data_size: cosmetic, unchecked
        rsrc.extend_from_slice(&1u32.to_le_bytes()); // num_tuples
        let chunk_data = b"hello zlib chunk";
        let rel_offset = 272u32 - 260; // base = desc_off+4 = 260; data starts right after the 1 tuple at 272
        rsrc.extend_from_slice(&rel_offset.to_le_bytes());
        rsrc.extend_from_slice(&(chunk_data.len() as u32).to_le_bytes());
        rsrc.extend_from_slice(chunk_data);

        let ranges = parse_chunk_table_zlib(&rsrc).unwrap();
        assert_eq!(ranges.len(), 1);
        let (start, end) = ranges[0];
        assert_eq!(&rsrc[start..end], chunk_data);
    }

    #[test]
    fn zlib_rsrc_encode_decode_chunk_uses_0xff_sentinel() {
        assert_eq!(chunk_stored_sentinel(Algo::Zlib(9)), 0xFF);
        let mut data = vec![0u8; 200];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i * 37 % 251) as u8; // incompressible -> stored fallback
        }
        let compressed = crate::algo::compress_chunk(&data, Algo::Zlib(9));
        let chunk = encode_chunk(Algo::Zlib(9), &data, compressed);
        assert_eq!(chunk.bytes[0], 0xFF);
        let back = decode_chunk(Algo::Zlib(9), &chunk.bytes, data.len()).unwrap();
        assert_eq!(back, data);
    }

    // --- adversarial: malformed/corrupted parse_chunk_table_zlib input,
    // mirroring parse_chunk_table's own adversarial suite.

    #[test]
    fn parse_chunk_table_zlib_rejects_too_short_for_header() {
        assert_eq!(parse_chunk_table_zlib(&[]), None);
        assert_eq!(parse_chunk_table_zlib(&[0u8; 15]), None);
    }

    #[test]
    fn parse_chunk_table_zlib_rejects_desc_off_below_header() {
        let mut rsrc = vec![0u8; 32];
        rsrc[0..4].copy_from_slice(&8u32.to_be_bytes()); // inside the 16-byte header itself
        assert_eq!(parse_chunk_table_zlib(&rsrc), None);
    }

    #[test]
    fn parse_chunk_table_zlib_rejects_desc_off_past_blob_end() {
        let mut rsrc = vec![0u8; 32];
        rsrc[0..4].copy_from_slice(&1000u32.to_be_bytes());
        assert_eq!(parse_chunk_table_zlib(&rsrc), None);
    }

    #[test]
    fn parse_chunk_table_zlib_rejects_num_tuples_overrunning_blob() {
        let mut rsrc = vec![0u8; 24];
        rsrc[0..4].copy_from_slice(&16u32.to_be_bytes()); // desc_off = 16
        rsrc[20..24].copy_from_slice(&1_000_000u32.to_le_bytes()); // way more tuples than fit
        assert_eq!(parse_chunk_table_zlib(&rsrc), None);
    }

    #[test]
    fn parse_chunk_table_zlib_rejects_tuple_pointing_past_blob_end() {
        let mut rsrc = vec![0u8; 32];
        rsrc[0..4].copy_from_slice(&16u32.to_be_bytes()); // desc_off = 16
        rsrc[20..24].copy_from_slice(&1u32.to_le_bytes()); // num_tuples = 1
        rsrc[24..28].copy_from_slice(&0u32.to_le_bytes()); // rel offset 0 -> abs 20
        rsrc[28..32].copy_from_slice(&1_000_000u32.to_le_bytes()); // size way past blob end
        assert_eq!(parse_chunk_table_zlib(&rsrc), None);
    }

    #[test]
    fn rsrc_footprint_overhead_matches_real_writer_output() {
        let chunks: Vec<ChunkOutput> = (0..3).map(|_| ChunkOutput { bytes: vec![0u8; 100] }).collect();
        let zlib_rsrc = build_resource_fork_zlib(&chunks);
        assert_eq!(
            rsrc_footprint_overhead(Algo::Zlib(9), chunks.len()),
            zlib_rsrc.len() as u64 - chunks.iter().map(|c| c.bytes.len() as u64).sum::<u64>()
        );

        let le_rsrc = build_resource_fork(&chunks);
        assert_eq!(
            rsrc_footprint_overhead(Algo::Lzfse, chunks.len()),
            le_rsrc.len() as u64 - chunks.iter().map(|c| c.bytes.len() as u64).sum::<u64>()
        );
    }

    #[test]
    fn chunk_count_and_len() {
        assert_eq!(chunk_count(0), 0);
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(CHUNK_SIZE as u64), 1);
        assert_eq!(chunk_count(CHUNK_SIZE as u64 + 1), 2);
        assert_eq!(chunk_count(274_480), 5); // matches the 5-chunk example in the spec

        assert_eq!(chunk_len(CHUNK_SIZE as u64 + 100, 0), CHUNK_SIZE);
        assert_eq!(chunk_len(CHUNK_SIZE as u64 + 100, 1), 100);
    }

    #[test]
    fn encode_decode_chunk_stored_fallback() {
        // Incompressible data -> compress_chunk returns None -> sentinel fallback.
        let mut data = vec![0u8; 200];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i * 37 % 251) as u8;
        }
        let compressed = crate::algo::compress_chunk(&data, Algo::Lzvn);
        let chunk = encode_chunk(Algo::Lzvn, &data, compressed);
        assert_eq!(chunk.bytes[0], chunk_stored_sentinel(Algo::Lzvn));
        let back = decode_chunk(Algo::Lzvn, &chunk.bytes, data.len()).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn encode_decode_chunk_real_compression() {
        let data = vec![b'x'; 65536];
        let compressed = crate::algo::compress_chunk(&data, Algo::Lzfse);
        assert!(compressed.is_some());
        let chunk = encode_chunk(Algo::Lzfse, &data, compressed);
        assert_ne!(chunk.bytes[0], chunk_stored_sentinel(Algo::Lzfse));
        let back = decode_chunk(Algo::Lzfse, &chunk.bytes, data.len()).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn type10_every_chunk_is_stored() {
        let data = vec![b'z'; 65536];
        let identity = crate::algo::compress_chunk(&data, Algo::Stored);
        let chunk = encode_chunk(Algo::Stored, &data, identity);
        assert_eq!(chunk.bytes[0], 0xCC);
        assert_eq!(chunk.bytes.len(), data.len() + 1);
    }

    #[test]
    fn zlib_rsrc_type_is_4() {
        assert_eq!(rsrc_type(Algo::Zlib(9)), Some(4));
        assert_eq!(rsrc_type(Algo::Lzfse), Some(12));
        assert_eq!(algo_for_type(4), Some(Algo::Zlib(0)));
    }

    // --- The zlib container (type 3/4) never records which encoder, or
    // which level, produced its bytes.

    #[test]
    fn zlib_level_never_reaches_the_on_disk_type() {
        for (a, b) in [(Algo::Zlib(1), Algo::Zlib(12)), (Algo::Zlib(6), Algo::Zlib(9))] {
            assert_eq!(xattr_type(a), xattr_type(b));
            assert_eq!(rsrc_type(a), rsrc_type(b));
            assert_eq!(chunk_stored_sentinel(a), chunk_stored_sentinel(b));
            assert!(uses_zlib_container(a) && uses_zlib_container(b));
        }
        // Read back through algo_for_type as a nominal Zlib: decmpfs records
        // the type, never the level that produced it.
        assert_eq!(algo_for_type(xattr_type(Algo::Zlib(12))), Some(Algo::Zlib(0)));
    }

    #[test]
    fn zlib_rsrc_roundtrips_through_the_zlib_container() {
        let data = vec![0u8; 200];
        let compressed = crate::algo::compress_chunk(&data, Algo::Zlib(12));
        let chunk = encode_chunk(Algo::Zlib(12), &data, compressed);
        let rsrc = build_resource_fork_zlib(&[chunk]);
        let ranges = parse_chunk_table_zlib(&rsrc).unwrap();
        assert_eq!(ranges.len(), 1);
        let (start, end) = ranges[0];
        let back = decode_chunk(Algo::Zlib(12), &rsrc[start..end], data.len()).unwrap();
        assert_eq!(back, data);
    }

    // --- CrushLzfse shares Lzfse's on-disk container (type 11/12) end to
    // end: same xattr/rsrc type numbers, same 0xFF stored-sentinel, same
    // standard (non-ZLIB) chunk-table layout: it's purely an alternate
    // encoder for the same format.

    #[test]
    fn crushlzfse_uses_same_decmpfs_types_as_lzfse() {
        assert_eq!(xattr_type(Algo::CrushLzfse(3)), xattr_type(Algo::Lzfse));
        assert_eq!(rsrc_type(Algo::CrushLzfse(3)), rsrc_type(Algo::Lzfse));
        assert_eq!(chunk_stored_sentinel(Algo::CrushLzfse(3)), chunk_stored_sentinel(Algo::Lzfse));
        assert!(!uses_zlib_container(Algo::CrushLzfse(3)));
        // Reads back as a nominal Lzfse: decmpfs never records which
        // encoder produced the type 11/12 bytes.
        assert_eq!(algo_for_type(xattr_type(Algo::CrushLzfse(3))), Some(Algo::Lzfse));
    }

    #[test]
    fn crushlzfse_rsrc_roundtrips_through_the_standard_container() {
        let data = vec![b'x'; 65536]; // one full chunk, within CrushLzfse's optimal-level cap
        let compressed = crate::algo::compress_chunk(&data, Algo::CrushLzfse(3));
        let chunk = encode_chunk(Algo::CrushLzfse(3), &data, compressed);
        let rsrc = build_resource_fork_for(Algo::CrushLzfse(3), &[chunk]);
        let ranges = parse_chunk_table(&rsrc).unwrap();
        assert_eq!(ranges.len(), 1);
        let (start, end) = ranges[0];
        let back = decode_chunk(Algo::CrushLzfse(3), &rsrc[start..end], data.len()).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn max_inline_payload_accounts_for_stored_sentinel() {
        assert_eq!(max_inline_payload_for(Algo::Stored), 3785);
        assert_eq!(max_inline_payload_for(Algo::Lzfse), 3786);
    }

    // --- adversarial: resource-fork offset overflow ---
    // Simulated with synthetic sizes rather than real multi-gigabyte buffers
    // - the point being tested is the arithmetic/format limit, not actual
    // allocation.

    #[test]
    #[should_panic(expected = "exceeds 4GiB")]
    fn chunk_end_offsets_panics_instead_of_wrapping_past_u32_max() {
        chunk_end_offsets(4, &[u32::MAX as usize - 2, 100]);
    }

    #[test]
    fn chunk_end_offsets_exactly_at_limit_does_not_panic() {
        let offsets = chunk_end_offsets(4, &[u32::MAX as usize - 4]);
        assert_eq!(offsets, vec![u32::MAX]);
    }

    #[test]
    fn chunk_end_offsets_one_under_limit_does_not_panic() {
        let offsets = chunk_end_offsets(4, &[u32::MAX as usize - 104]);
        assert_eq!(offsets, vec![u32::MAX - 100]);
    }

    // --- adversarial: malformed/corrupted parse_chunk_table input ---
    // These simulate what a corrupted, hand-crafted, or crash-truncated
    // com.apple.ResourceFork xattr could contain; every case must return
    // None cleanly, never panic or index out of bounds.

    #[test]
    fn parse_chunk_table_rejects_too_short_to_hold_table_size() {
        assert_eq!(parse_chunk_table(&[]), None);
        assert_eq!(parse_chunk_table(&[1, 2, 3]), None);
    }

    #[test]
    fn parse_chunk_table_rejects_table_size_not_multiple_of_four() {
        let mut rsrc = vec![0u8; 20];
        rsrc[0..4].copy_from_slice(&6u32.to_le_bytes()); // not a multiple of 4
        assert_eq!(parse_chunk_table(&rsrc), None);
    }

    #[test]
    fn parse_chunk_table_rejects_table_size_below_minimum() {
        let mut rsrc = vec![0u8; 20];
        rsrc[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(parse_chunk_table(&rsrc), None);
    }

    #[test]
    fn parse_chunk_table_rejects_table_size_exceeding_blob_length() {
        let mut rsrc = vec![0u8; 20];
        rsrc[0..4].copy_from_slice(&1000u32.to_le_bytes()); // way past rsrc.len()
        assert_eq!(parse_chunk_table(&rsrc), None);
    }

    #[test]
    fn parse_chunk_table_rejects_reversed_chunk_end() {
        // table_size=8 (1 chunk), but the chunk's declared end (4) is before
        // its start (table_size=8) - a corrupted/hand-crafted table.
        let mut rsrc = vec![0u8; 8];
        rsrc[0..4].copy_from_slice(&8u32.to_le_bytes());
        rsrc[4..8].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(parse_chunk_table(&rsrc), None);
    }

    #[test]
    fn parse_chunk_table_rejects_end_beyond_blob_length() {
        let mut rsrc = vec![0u8; 8];
        rsrc[0..4].copy_from_slice(&8u32.to_le_bytes());
        rsrc[4..8].copy_from_slice(&9_000_000u32.to_le_bytes()); // past rsrc.len()
        assert_eq!(parse_chunk_table(&rsrc), None);
    }

    #[test]
    fn parse_chunk_table_accepts_zero_length_chunk() {
        // Degenerate but not malformed: a chunk whose end equals its start.
        let mut rsrc = vec![0u8; 8];
        rsrc[0..4].copy_from_slice(&8u32.to_le_bytes());
        rsrc[4..8].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(parse_chunk_table(&rsrc), Some(vec![(8, 8)]));
    }

    // --- adversarial: Header::from_bytes ---

    #[test]
    fn header_from_bytes_rejects_truncated_buffer() {
        assert_eq!(Header::from_bytes(&[]), None);
        assert_eq!(Header::from_bytes(&[0u8; 15]), None); // one byte short
    }

    #[test]
    fn header_from_bytes_ignores_trailing_bytes() {
        let h = Header { compression_type: 11, uncompressed_size: 12345 };
        let mut bytes = h.to_bytes().to_vec();
        bytes.extend_from_slice(b"trailing garbage, e.g. a truncated payload");
        assert_eq!(Header::from_bytes(&bytes), Some(h));
    }

    // --- adversarial: chunk_len boundaries ---

    #[test]
    fn chunk_len_last_of_exact_multiple_is_full_chunk() {
        assert_eq!(chunk_len(CHUNK_SIZE as u64 * 3, 2), CHUNK_SIZE);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "out of range")]
    fn chunk_len_panics_on_out_of_range_index() {
        // total_size implies exactly 1 chunk; index 1 is one past the end.
        chunk_len(100, 1);
    }
}
