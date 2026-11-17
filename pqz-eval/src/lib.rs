#![forbid(unsafe_code)]

//! PQZ-Audit evaluation prototype, Stage A.
//!
//! Stage A covers the data generator, the protected log (Phases 1-2), the
//! protected-search primitives, the BFV aggregation pool and the benchmark
//! harness. Proofs, the ledger and threshold decryption are Stage B/C.

pub mod bench;
pub mod eapat;
pub mod r#gen;
pub mod he;
pub mod search;

use sha3::{Digest, Sha3_256};

/// Domain of attribute `a` (and `c`, `d`): `0..A_DOMAIN`.
pub const A_DOMAIN: u32 = 1000;
/// Domain of attribute `b`: `0..B_DOMAIN`.
pub const B_DOMAIN: u32 = 1 << B_BITS;
/// Number of bits of attribute `b`.
pub const B_BITS: u32 = 20;
/// Fixed predicate parameter `x`.
pub const X: u32 = 7;
/// Fixed predicate parameter `y` (`2^19`).
pub const Y: u32 = 1 << 19;
/// Fixed predicate parameter `z`.
pub const Z: u32 = 500;
/// Fixed predicate parameter `w`.
pub const W: u32 = 3;
/// Default block size used by the experiments.
pub const DEFAULT_MB: usize = 500;

/// A log record. `ts == id` in the generated data, so ordering by `id` is
/// ordering by timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub id: u64,
    pub ts: u64,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
}

/// The four predicates of the paper, with the fixed parameters `x,y,z,w`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Predicate {
    P1,
    P2,
    P3,
    P4,
}

impl Predicate {
    pub const ALL: [Predicate; 4] = [Predicate::P1, Predicate::P2, Predicate::P3, Predicate::P4];

    pub fn name(self) -> &'static str {
        match self {
            Predicate::P1 => "P1",
            Predicate::P2 => "P2",
            Predicate::P3 => "P3",
            Predicate::P4 => "P4",
        }
    }

    /// Plaintext evaluation, used by `trad_scan` and by the correctness gate.
    pub fn matches(self, r: &Record) -> bool {
        match self {
            Predicate::P1 => r.a == X,
            Predicate::P2 => r.a == X && r.b >= Y,
            Predicate::P3 => (r.a == X && r.b >= Y) || r.c == Z,
            Predicate::P4 => (r.a == X && r.b >= Y) && (r.c < Z || r.d == W),
        }
    }
}

/// Physical placement of the records that satisfy the predicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// The satisfying records form one contiguous id range at a seeded offset.
    Clustered,
    /// The satisfying records are at uniformly random distinct ids.
    Scattered,
}

impl Layout {
    pub fn name(self) -> &'static str {
        match self {
            Layout::Clustered => "clustered",
            Layout::Scattered => "scattered",
        }
    }
}

/// SHA3-256 of a byte string.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let out = Sha3_256::digest(data);
    let mut h = [0u8; 32];
    h.copy_from_slice(&out);
    h
}

/// SHA3-256 over the concatenation of `parts`, without building the
/// concatenation in memory.
pub fn sha3_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// A deterministic 32-byte key derived from a seed and a label. This is a
/// plain hash-based KDF used only to derive evaluation keys; the record keys
/// themselves use HKDF (see `eapat`).
pub fn derive_key(seed: u64, label: &[u8]) -> [u8; 32] {
    sha3_parts(&[&seed.to_le_bytes(), label])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(a: u32, b: u32, c: u32, d: u32) -> Record {
        Record {
            id: 1,
            ts: 1,
            a,
            b,
            c,
            d,
        }
    }

    #[test]
    fn predicate_truth_table() {
        let hit = rec(X, Y, 0, W);
        assert!(Predicate::ALL.iter().all(|p| p.matches(&hit)));

        // a != x and c != z: all four are false.
        let miss = rec(X + 1, B_DOMAIN - 1, Z + 1, W);
        assert!(Predicate::ALL.iter().all(|p| !p.matches(&miss)));

        // P3 alone would be true if c == z, so the generator must never emit it
        // for a non-hit.
        let c_z = rec(X + 1, 0, Z, 0);
        assert!(!Predicate::P1.matches(&c_z));
        assert!(Predicate::P3.matches(&c_z));
    }

    #[test]
    fn hash_parts_equals_concatenation() {
        assert_eq!(
            sha3_parts(&[b"ab", b"cd"]),
            sha3_256(b"abcd"),
            "incremental hashing must match one-shot hashing"
        );
    }
}
