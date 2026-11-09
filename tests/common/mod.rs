//! Seeded input generation shared by the decmpfs test suites.

use apfscompress::algo::Algo;
use apfscompress::decmpfs::{CHUNK_SIZE, MAX_INLINE_PAYLOAD};

pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    pub fn range(&mut self, lo: i64, hi: i64) -> i64 {
        lo + self.below((hi - lo + 1) as u64) as i64
    }
}

/// File sizes, weighted towards the points where our framing changes shape.
pub fn pick_size(r: &mut Rng) -> usize {
    let c = CHUNK_SIZE as i64;
    let jitter = r.range(-2, 2);
    let size = match r.below(8) {
        0 => r.range(0, 64),
        1 => MAX_INLINE_PAYLOAD as i64 + r.range(-64, 64),
        2 => r.range(1, 8) * c + jitter,
        3 => c + jitter,
        4 => r.range(0, c),
        5 => r.range(c, 4 * c),
        6 => r.range(4 * c, 24 * c),
        _ => r.range(0, 3 * MAX_INLINE_PAYLOAD as i64),
    };
    size.max(0) as usize
}

/// Content as a run of segments with different entropy, so that within one
/// file some chunks compress and others fall back to stored.
pub fn fill(r: &mut Rng, size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        let max_len = if r.below(4) == 0 { CHUNK_SIZE as u64 * 2 } else { 4096 };
        let len = (1 + r.below(max_len) as usize).min(size - out.len());
        match r.below(6) {
            0 => out.extend(std::iter::repeat_n(r.next() as u8, len)),
            1 => {
                let text = b"the quick brown fox jumps over the lazy dog; ";
                out.extend(text.iter().cycle().skip(r.below(text.len() as u64) as usize).take(len));
            }
            2 => out.extend((0..len).map(|_| r.next() as u8)),
            3 => {
                // Fixed-stride records with small per-record changes, the
                // shape LZBITMAP is built for.
                let stride = 4 + r.below(60) as usize;
                let base: Vec<u8> = (0..stride).map(|_| r.next() as u8).collect();
                for i in 0..len {
                    let b = base[i % stride];
                    out.push(if r.below(16) == 0 { b.wrapping_add(i as u8) } else { b });
                }
            }
            4 => {
                let alphabet = 2 + r.below(14);
                out.extend((0..len).map(|_| (r.below(alphabet) as u8).wrapping_mul(17)));
            }
            _ => {
                // Copy of earlier content, at any distance.
                if out.is_empty() {
                    continue;
                }
                let from = r.below(out.len() as u64) as usize;
                for i in 0..len {
                    out.push(out[from + i % (out.len() - from)]);
                }
            }
        }
    }
    out.truncate(size);
    out
}

pub fn pick_algo(r: &mut Rng) -> Algo {
    let crush = |r: &mut Rng| r.range(-2, 10) as i32;
    match r.below(10) {
        0 => Algo::Lzfse,
        1 => Algo::CrushLzfse(crush(r)),
        2 => Algo::Zlib(r.range(1, 12) as u8),
        3 => Algo::Lzvn,
        4 => Algo::CrushLzvn(crush(r)),
        5 => Algo::Lzbitmap,
        6 => Algo::CrushLzbitmap(crush(r)),
        7 => Algo::Lz4,
        8 => Algo::CrushLz4(crush(r)),
        _ => Algo::Stored,
    }
}
