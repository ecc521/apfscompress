//! Splits file data into 64KB decmpfs chunks and compresses them, using
//! rayon for both cross-file and within-file parallelism, in one global pool.

use crate::algo::{self, Algo};
use crate::decmpfs::{self, ChunkOutput};
use rayon::prelude::*;

/// (start, end) byte ranges into a `total_size`-byte source, one per 64KB
/// chunk (last one possibly shorter).
pub fn chunk_ranges(total_size: u64) -> Vec<(usize, usize)> {
    let count = decmpfs::chunk_count(total_size);
    let ranges: Vec<(usize, usize)> = (0..count)
        .map(|i| {
            let start = i * decmpfs::CHUNK_SIZE;
            let end = start + decmpfs::chunk_len(total_size, i);
            (start, end)
        })
        .collect();
    debug_assert_eq!(
        ranges.last().map_or(0, |&(_, end)| end) as u64,
        total_size,
        "chunk_ranges: last range doesn't reach total_size - every caller assumes full coverage"
    );
    ranges
}

/// Compresses every chunk of `data` with a single `algo`, in parallel,
/// preserving chunk order. Each chunk independently falls back to the
/// stored-sentinel form if `algo` doesn't shrink it.
pub fn compress_chunks(data: &[u8], algo: Algo) -> Vec<ChunkOutput> {
    let ranges = chunk_ranges(data.len() as u64);
    ranges
        .par_iter()
        .map(|&(start, end)| {
            let slice = &data[start..end];
            let compressed = algo::compress_chunk(slice, algo);
            decmpfs::encode_chunk(algo, slice, compressed)
        })
        .collect()
}

/// Compresses every chunk of `data` with a single `algo` sequentially (no
/// rayon) - a deterministic-ordering counterpart to `compress_chunks`, used
/// by tests that assert parallel and sequential results agree.
#[cfg(test)]
pub fn compress_chunks_sequential(data: &[u8], algo: Algo) -> Vec<ChunkOutput> {
    chunk_ranges(data.len() as u64)
        .iter()
        .map(|&(start, end)| {
            let slice = &data[start..end];
            let compressed = algo::compress_chunk(slice, algo);
            decmpfs::encode_chunk(algo, slice, compressed)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compressible_file(n_chunks: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n_chunks * decmpfs::CHUNK_SIZE);
        for i in 0..n_chunks {
            // vary content per chunk, staying highly compressible
            let byte = (b'a' + (i % 5) as u8) as char;
            v.extend(std::iter::repeat_n(byte as u8, decmpfs::CHUNK_SIZE));
        }
        v
    }

    #[test]
    fn chunk_ranges_cover_whole_file_no_gaps_no_overlap() {
        let total = decmpfs::CHUNK_SIZE as u64 * 3 + 1234;
        let ranges = chunk_ranges(total);
        assert_eq!(ranges.len(), 4);
        assert_eq!(ranges[0], (0, decmpfs::CHUNK_SIZE));
        assert_eq!(ranges[3].1 - ranges[3].0, 1234);
        // contiguous, no gaps
        for w in ranges.windows(2) {
            assert_eq!(w[0].1, w[1].0);
        }
        assert_eq!(ranges.last().unwrap().1, total as usize);
    }

    #[test]
    fn parallel_and_sequential_agree() {
        let data = compressible_file(6);
        let par = compress_chunks(&data, Algo::Lzfse);
        let seq = compress_chunks_sequential(&data, Algo::Lzfse);
        assert_eq!(par.len(), seq.len());
        for (a, b) in par.iter().zip(seq.iter()) {
            assert_eq!(a.bytes, b.bytes);
        }
    }

    #[test]
    fn multi_chunk_roundtrip_via_decmpfs() {
        let data = compressible_file(4);
        let chunks = compress_chunks(&data, Algo::Lzfse);
        let rsrc = decmpfs::build_resource_fork(&chunks);
        let ranges = decmpfs::parse_chunk_table(&rsrc).unwrap();
        assert_eq!(ranges.len(), chunks.len());

        let mut reconstructed = Vec::with_capacity(data.len());
        for (i, (start, end)) in ranges.iter().enumerate() {
            let uncompressed_len = decmpfs::chunk_len(data.len() as u64, i);
            let plain =
                decmpfs::decode_chunk(Algo::Lzfse, &rsrc[*start..*end], uncompressed_len).unwrap();
            reconstructed.extend_from_slice(&plain);
        }
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn last_chunk_shorter_than_64kb_roundtrips() {
        // Lzvn, not Zlib: Zlib is inline-only (no rsrc_type, see decmpfs.rs)
        // and a real engine would never chunk with it.
        let mut data = compressible_file(2);
        data.truncate(decmpfs::CHUNK_SIZE + 777);
        let chunks = compress_chunks(&data, Algo::Lzvn);
        assert_eq!(chunks.len(), 2);
        let rsrc = decmpfs::build_resource_fork(&chunks);
        let ranges = decmpfs::parse_chunk_table(&rsrc).unwrap();
        let last_len = decmpfs::chunk_len(data.len() as u64, 1);
        assert_eq!(last_len, 777);
        let plain = decmpfs::decode_chunk(
            Algo::Lzvn,
            &rsrc[ranges[1].0..ranges[1].1],
            last_len,
        )
        .unwrap();
        assert_eq!(plain, &data[decmpfs::CHUNK_SIZE..]);
    }

    // Zero-byte input and exact chunk-size boundaries.

    #[test]
    fn zero_byte_input_produces_no_chunks() {
        assert_eq!(chunk_ranges(0), Vec::new());
        assert_eq!(compress_chunks(&[], Algo::Lzfse).len(), 0);
        assert_eq!(compress_chunks_sequential(&[], Algo::Lzfse).len(), 0);
    }

    #[test]
    fn exact_multiple_of_chunk_size_has_no_short_final_chunk() {
        // Exactly 2 full chunks, no remainder: the boundary between a full
        // last chunk and a trailing partial one.
        let data = compressible_file(2);
        assert_eq!(data.len(), decmpfs::CHUNK_SIZE * 2);
        let ranges = chunk_ranges(data.len() as u64);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], (0, decmpfs::CHUNK_SIZE));
        assert_eq!(ranges[1], (decmpfs::CHUNK_SIZE, decmpfs::CHUNK_SIZE * 2));

        let chunks = compress_chunks(&data, Algo::Lzfse);
        let rsrc = decmpfs::build_resource_fork(&chunks);
        let parsed = decmpfs::parse_chunk_table(&rsrc).unwrap();
        assert_eq!(parsed.len(), 2);
    }
}
