//! Deterministic synthetic workload and reference (non-circuit) hash chain.
//!
//! Stream of 8-element words absorbed by one Rescue sponge (rate 8, capacity 4):
//!   header word of block g : [e, g, m_B, pid, seq_start_g, 0, 0, 1]
//!   record word            : [pid, e, seq, id, v, b, tag, 0]
//! The last element is the header flag (1 = header, 0 = record); it is part of the absorbed data, so the
//! commitment binds which words are headers.
//! v (search attribute) and b (aggregation attribute) are generated below 2^32 and 2^20.
//! `tag` stands for the protected-search / HE representation of the record: random field element, NOT derived
//! from anything and NOT proven (see DESIGN.md, "not proven").

use crate::rescue::{perm, F, W};
use winterfell::math::{FieldElement, StarkField};

pub const DOM_CHAIN: u64 = 0x5051_5a43; // "PQZC"
pub const MAX_ATTR: u64 = 1u64 << 32;

pub type Word = [F; 8];

pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        // splitmix64
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
    pub words: Vec<Word>,
}

impl Workload {
    /// `n_records` must be a multiple of `block_size`.
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
                let tag = rng.next_u64() % F::MODULUS;
                words.push([
                    F::new(pid),
                    F::new(epoch),
                    F::new(seq),
                    F::new(seq), // id
                    F::new(v),
                    F::new(b),
                    F::new(tag),
                    F::ZERO,
                ]);
                seq += 1;
            }
        }
        Workload { n_blocks, block_size, epoch, pid, seq_start, words }
    }
    pub fn n_records(&self) -> usize {
        self.n_blocks * self.block_size
    }
    pub fn n_groups(&self) -> usize {
        self.words.len()
    }
    pub fn header0(&self) -> Word {
        self.words[0]
    }
    /// Reference commitment (library permutation, no circuit).
    pub fn commitment(&self) -> [F; 4] {
        chain_digest(&self.words)
    }
    /// Reference result of "v >= theta": (count, sum of b over matches). Independent of the circuit code.
    pub fn reference_result(&self, theta: u64) -> (u64, u64) {
        let (mut cnt, mut sum) = (0u64, 0u64);
        for w in &self.words {
            if w[7] == F::ZERO && w[4].as_int() >= theta {
                cnt += 1;
                sum += w[5].as_int();
            }
        }
        (cnt, sum)
    }
}

pub fn header_word(e: u64, g: u64, m_b: u64, pid: u64, seq_start_g: u64) -> Word {
    [
        F::new(e),
        F::new(g),
        F::new(m_b),
        F::new(pid),
        F::new(seq_start_g),
        F::ZERO,
        F::ZERO,
        F::ONE,
    ]
}

/// Padding word, treated like a header with no content.
pub fn pad_word() -> Word {
    [F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ONE]
}

pub fn cap_init(n_groups: usize) -> [F; 4] {
    [F::new(DOM_CHAIN), F::new(n_groups as u64), F::ZERO, F::ZERO]
}

pub fn chain_digest(words: &[Word]) -> [F; 4] {
    let mut s = [F::ZERO; W];
    let c = cap_init(words.len());
    s[..4].copy_from_slice(&c);
    for w in words {
        for j in 0..8 {
            s[4 + j] += w[j];
        }
        perm(&mut s);
    }
    [s[4], s[5], s[6], s[7]]
}

pub fn pow2_len(rows: usize) -> usize {
    rows.next_power_of_two().max(32)
}
