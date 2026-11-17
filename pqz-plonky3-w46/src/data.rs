//! Synthetic workload: the SAME generator as `bench/pqz-proof-w30/src/data.rs` (splitmix64, same draw order),
//! re-implemented here on plain `u64` so that this crate does not depend on winterfell. The tests cross-check it
//! word by word against the w30 `Workload::synthetic` (read-only path dev-dependency).
//!
//! Raw word (8 values, identical to w30):
//!   header word of block g : [e, g, m_B, pid, seq_start_g, 0, 0, 1]
//!   record word            : [pid, e, seq, id, v, b, tag, 0]       (v < 2^32, b < 2^20, tag < 2^64-2^32+1)
//! The last value is the header flag h.

pub const DOM_CHAIN: u64 = 0x5051_5a43; // "PQZC", as in w30
pub const MAX_ATTR: u64 = 1u64 << 32;
/// Goldilocks modulus (w30 draws `tag = next % F::MODULUS` with this modulus, for every config here).
pub const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;

pub type RawWord = [u64; 8];

pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        // splitmix64 (same as w30)
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[derive(Clone, Debug)]
pub struct Workload {
    pub n_blocks: usize,
    pub block_size: usize,
    pub epoch: u64,
    pub pid: u64,
    pub seq_start: u64,
    /// header + record words, in stream order (n_blocks * (block_size + 1) words)
    pub words: Vec<RawWord>,
}

pub fn header_word(e: u64, g: u64, m_b: u64, pid: u64, seq_start_g: u64) -> RawWord {
    [e, g, m_b, pid, seq_start_g, 0, 0, 1]
}

impl Workload {
    /// `n_records` must be a multiple of `block_size`. Same draw order as w30:
    /// per record `v = next & (2^32-1)`, `b = next & (2^20-1)`, `tag = next % GOLDILOCKS_P`.
    pub fn synthetic(n_records: usize, block_size: usize, seed: u64) -> Self {
        assert!(block_size > 0 && n_records > 0 && n_records % block_size == 0);
        let n_blocks = n_records / block_size;
        let (epoch, pid, seq_start) = (1u64, 7u64, 1u64);
        let mut rng = Rng::new(seed);
        let mut words = Vec::with_capacity(n_blocks * (block_size + 1));
        let mut seq = seq_start;
        for g in 0..n_blocks {
            words.push(header_word(epoch, g as u64, block_size as u64, pid, seq));
            for _ in 0..block_size {
                let v = rng.next_u64() & (MAX_ATTR - 1);
                let b = rng.next_u64() & ((1 << 20) - 1);
                let tag = rng.next_u64() % GOLDILOCKS_P;
                words.push([pid, epoch, seq, seq, v, b, tag, 0]);
                seq += 1;
            }
        }
        Workload { n_blocks, block_size, epoch, pid, seq_start, words }
    }
    pub fn n_records(&self) -> usize {
        self.n_blocks * self.block_size
    }
    pub fn n_words(&self) -> usize {
        self.words.len()
    }
    /// Reference result of "v >= theta": (count, sum of b over matches). Plain integer code, independent of any
    /// circuit or field (same rule as w30 `reference_result`).
    pub fn reference_result(&self, theta: u64) -> (u64, u64) {
        let (mut cnt, mut sum) = (0u64, 0u64);
        for w in &self.words {
            if w[7] == 0 && w[4] >= theta {
                cnt += 1;
                sum += w[5];
            }
        }
        (cnt, sum)
    }
    /// Same, but the integer sum is split in the C2 limbs: (count, sum of b_lo, sum of b_hi) with b = b_lo + 2^10 b_hi.
    pub fn reference_result_limbs(&self, theta: u64) -> (u64, u64, u64) {
        let (mut cnt, mut slo, mut shi) = (0u64, 0u64, 0u64);
        for w in &self.words {
            if w[7] == 0 && w[4] >= theta {
                cnt += 1;
                slo += w[5] & 0x3FF;
                shi += w[5] >> 10;
            }
        }
        (cnt, slo, shi)
    }
}

/// Words of config C1 (Goldilocks): the raw word unchanged (8 values per word, as in w30).
pub fn map_c1(w: &RawWord) -> Vec<u64> {
    w.to_vec()
}

/// Words of config C2 (KoalaBear, p = 2^31 - 2^24 + 1): 12 values per word.
///   [pid, e, seq, id, v_lo, v_hi, b_lo, b_hi, tag0, tag1, tag2, h]
/// v = v_lo + 2^16 v_hi (16-bit limbs, both range-checked in the AIR); b = b_lo + 2^10 b_hi (10-bit limbs, not range
/// checked, as b is not range checked in w30); tag = tag0 + 2^22 tag1 + 2^43 tag2 (22/21/21 bits, not proven, as in w30).
/// pid, e, seq, id are below 2^31 - 2^24 for all workloads here (seq <= 2^24), checked below.
/// Header word [e, g, m_B, pid, seq_start_g, 0, 0, 1] becomes [e, g, m_B, pid, seq_start_g, 0 x6, 1].
pub fn map_c2(w: &RawWord) -> Vec<u64> {
    const P: u64 = 2_130_706_433;
    if w[7] == 1 {
        for &x in &w[..5] {
            assert!(x < P);
        }
        return vec![w[0], w[1], w[2], w[3], w[4], 0, 0, 0, 0, 0, 0, 1];
    }
    for &x in &w[..4] {
        assert!(x < P);
    }
    let (v, b, tag) = (w[4], w[5], w[6]);
    assert!(v < (1u64 << 32) && b < (1u64 << 20));
    vec![
        w[0],
        w[1],
        w[2],
        w[3],
        v & 0xFFFF,
        v >> 16,
        b & 0x3FF,
        b >> 10,
        tag & ((1 << 22) - 1),
        (tag >> 22) & ((1 << 21) - 1),
        tag >> 43,
        0,
    ]
}
