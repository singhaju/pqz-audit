//! Protected search: keyed-hash tags, block Bloom summaries (BPS) and
//! record-level evaluation (RPS).
//!
//! This is the provisional construction from SPEC.md. It leaks the search
//! pattern and which blocks match; it is not a "secure" searchable encryption
//! scheme. The block summary has false positives (bounded by the Bloom sizing),
//! never false negatives.

use std::collections::BTreeSet;

use crate::{B_BITS, B_DOMAIN, Predicate, Record, W, Y, Z, sha3_parts};

/// A keyed tag. 16 bytes is enough to make accidental collisions negligible.
pub type Tag = [u8; 16];

pub const ATTR_A: u8 = 1;
pub const ATTR_B: u8 = 2;
pub const ATTR_C: u8 = 3;
pub const ATTR_D: u8 = 4;

/// Key for the keyed-hash tags (`k_s` in the paper).
#[derive(Clone)]
pub struct TagKey([u8; 32]);

impl TagKey {
    pub fn from_seed(seed: u64) -> Self {
        TagKey(crate::derive_key(seed, b"pqz-tag-key"))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        TagKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Equality tag: `SHA3(k_s || attr || 0x00 || value_le)[..16]`.
pub fn eq_tag(key: &TagKey, attr: u8, value: u32) -> Tag {
    let h = sha3_parts(&[&key.0, &[attr, 0x00], &value.to_le_bytes()]);
    let mut t = [0u8; 16];
    t.copy_from_slice(&h[..16]);
    t
}

/// Prefix tag for the top `level` bits of a 20-bit value.
///
/// Layout: `SHA3(k_s || attr || 0x01 || level || packed_prefix)[..16]`, with the
/// prefix packed most-significant bit first.
pub fn prefix_tag(key: &TagKey, attr: u8, level: u8, value: u32) -> Tag {
    debug_assert!(level <= B_BITS as u8);
    debug_assert!(value < B_DOMAIN);
    let nbytes = (level as usize).div_ceil(8);
    let mut packed = [0u8; 3];
    for i in 0..level as usize {
        let bit = (value >> (B_BITS as usize - 1 - i)) & 1;
        packed[i / 8] |= (bit as u8) << (7 - (i % 8));
    }
    let h = sha3_parts(&[&key.0, &[attr, 0x01, level], &packed[..nbytes]]);
    let mut t = [0u8; 16];
    t.copy_from_slice(&h[..16]);
    t
}

/// All 21 prefix tags of a 20-bit value (levels 0..=20).
pub fn prefix_tags(key: &TagKey, attr: u8, value: u32) -> Vec<Tag> {
    (0..=B_BITS as u8)
        .map(|l| prefix_tag(key, attr, l, value))
        .collect()
}

/// Dyadic cover of `[lo, hi)` in the 20-bit domain, as `(level, prefix)`.
pub fn dyadic_cover(lo: u32, hi: u32) -> Vec<(u8, u32)> {
    assert!(lo <= hi && hi <= B_DOMAIN);
    let mut out = Vec::new();
    let mut cur = lo;
    while cur < hi {
        let max_k = if cur == 0 {
            B_BITS
        } else {
            cur.trailing_zeros().min(B_BITS)
        };
        let mut k = max_k;
        while k > 0 && (1u32 << k) > hi - cur {
            k -= 1;
        }
        let level = (B_BITS - k) as u8;
        out.push((level, cur >> k));
        cur += 1u32 << k;
    }
    out
}

/// Tags of the dyadic intervals covering `[lo, hi)`.
pub fn range_tags(key: &TagKey, attr: u8, lo: u32, hi: u32) -> Vec<Tag> {
    dyadic_cover(lo, hi)
        .into_iter()
        .map(|(level, prefix)| prefix_tag(key, attr, level, prefix << (B_BITS - level as u32)))
        .collect()
}

/// The tags stored for one record: equality tags for a, c, d and prefix tags
/// for b and c (45 tags). Sorted so `rps_eval` can binary-search.
pub fn tags_for_record(r: &Record, key: &TagKey) -> Vec<Tag> {
    let mut tags = Vec::with_capacity(45);
    tags.push(eq_tag(key, ATTR_A, r.a));
    tags.extend(prefix_tags(key, ATTR_B, r.b));
    tags.push(eq_tag(key, ATTR_C, r.c));
    tags.extend(prefix_tags(key, ATTR_C, r.c));
    tags.push(eq_tag(key, ATTR_D, r.d));
    tags.sort_unstable();
    tags
}

/// Boolean query formula over tag leaves.
#[derive(Clone, Debug)]
pub enum Formula {
    Leaf(Vec<Tag>),
    And(Box<Formula>, Box<Formula>),
    Or(Box<Formula>, Box<Formula>),
}

impl Formula {
    pub fn leaf(tags: Vec<Tag>) -> Self {
        Formula::Leaf(tags)
    }

    pub fn and(a: Formula, b: Formula) -> Self {
        Formula::And(Box::new(a), Box::new(b))
    }

    pub fn or(a: Formula, b: Formula) -> Self {
        Formula::Or(Box::new(a), Box::new(b))
    }

    /// Distinct tags in the trapdoor, sorted.
    pub fn trapdoor_tags(&self) -> Vec<Tag> {
        let mut set = BTreeSet::new();
        self.collect_tags(&mut set);
        set.into_iter().collect()
    }

    pub fn tag_count(&self) -> usize {
        self.trapdoor_tags().len()
    }

    fn collect_tags(&self, set: &mut BTreeSet<Tag>) {
        match self {
            Formula::Leaf(tags) => {
                for t in tags {
                    set.insert(*t);
                }
            }
            Formula::And(a, b) | Formula::Or(a, b) => {
                a.collect_tags(set);
                b.collect_tags(set);
            }
        }
    }
}

/// Build the trapdoor formula for a paper predicate.
pub fn formula_for(p: Predicate, key: &TagKey) -> Formula {
    let a_x = || Formula::leaf(vec![eq_tag(key, ATTR_A, crate::x())]);
    let b_ge_y = || Formula::leaf(range_tags(key, ATTR_B, Y, B_DOMAIN));
    match p {
        Predicate::P1 => a_x(),
        Predicate::P2 => Formula::and(a_x(), b_ge_y()),
        Predicate::P3 => Formula::or(
            Formula::and(a_x(), b_ge_y()),
            Formula::leaf(vec![eq_tag(key, ATTR_C, Z)]),
        ),
        Predicate::P4 => Formula::and(
            Formula::and(a_x(), b_ge_y()),
            Formula::or(
                Formula::leaf(range_tags(key, ATTR_C, 0, Z)),
                Formula::leaf(vec![eq_tag(key, ATTR_D, W)]),
            ),
        ),
    }
}

/// Record-level evaluation. Exact (no false positives); `record_tags` must be
/// sorted (as returned by [`tags_for_record`]).
pub fn rps_eval(record_tags: &[Tag], f: &Formula) -> bool {
    match f {
        Formula::Leaf(tags) => tags
            .iter()
            .any(|t| record_tags.binary_search(t).is_ok()),
        Formula::And(a, b) => rps_eval(record_tags, a) && rps_eval(record_tags, b),
        Formula::Or(a, b) => rps_eval(record_tags, a) || rps_eval(record_tags, b),
    }
}

/// Per-block Bloom filter over all tags of its records.
#[derive(Clone)]
pub struct Bloom {
    bits: Vec<u64>,
    nbits: usize,
    k: usize,
}

impl Bloom {
    /// Build a Bloom filter targeting `fp_rate` for `m` inserted tags.
    pub fn with_fp_rate(m: usize, fp_rate: f64) -> Self {
        assert!(m > 0);
        assert!(fp_rate > 0.0 && fp_rate < 1.0);
        let ln2 = std::f64::consts::LN_2;
        let nbits = ((m as f64) * (-fp_rate.ln()) / (ln2 * ln2)).ceil() as usize;
        let nbits = nbits.max(64);
        let k = (((nbits as f64) / (m as f64)) * ln2).round() as usize;
        let k = k.clamp(1, 8);
        Bloom {
            bits: vec![0u64; nbits.div_ceil(64)],
            nbits,
            k,
        }
    }

    /// A filter sized for a block of `record_count` records (45 tags each).
    pub fn for_block(record_count: usize) -> Self {
        Self::with_fp_rate(record_count * 45, 0.01)
    }

    fn hashes(tag: &Tag) -> (u64, u64) {
        let h1 = u64::from_le_bytes(tag[..8].try_into().expect("8 bytes"));
        let h2 = u64::from_le_bytes(tag[8..].try_into().expect("8 bytes")) | 1;
        (h1, h2)
    }

    fn index(&self, h1: u64, h2: u64, i: usize) -> usize {
        (h1.wrapping_add((i as u64).wrapping_mul(h2)) % self.nbits as u64) as usize
    }

    pub fn insert(&mut self, tag: &Tag) {
        let (h1, h2) = Self::hashes(tag);
        for i in 0..self.k {
            let idx = self.index(h1, h2, i);
            self.bits[idx / 64] |= 1u64 << (idx % 64);
        }
    }

    pub fn contains(&self, tag: &Tag) -> bool {
        let (h1, h2) = Self::hashes(tag);
        (0..self.k).all(|i| {
            let idx = self.index(h1, h2, i);
            self.bits[idx / 64] & (1u64 << (idx % 64)) != 0
        })
    }

    pub fn nbits(&self) -> usize {
        self.nbits
    }

    pub fn k(&self) -> usize {
        self.k
    }

    pub fn bytes(&self) -> usize {
        self.bits.len() * 8
    }

    /// Heap bytes owned by the bit vector (not the `Bloom` struct itself,
    /// which is stored inline in a `Block`).
    pub fn heap_bytes(&self) -> usize {
        self.bits.capacity() * std::mem::size_of::<u64>()
    }

    /// Digest committed in the block header. Includes the parameters so two
    /// different filters cannot share a digest.
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(16 + self.bits.len() * 8);
        bytes.extend_from_slice(&(self.nbits as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.k as u64).to_le_bytes());
        for w in &self.bits {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        crate::sha3_parts(&[b"pqz-bloom", &bytes])
    }

    pub fn build<'a>(record_count: usize, tags: impl Iterator<Item = &'a Tag>) -> Self {
        let mut b = Self::for_block(record_count);
        for t in tags {
            b.insert(t);
        }
        b
    }
}

/// Block-level evaluation. Conservative: a record that matches is always in a
/// block whose summary evaluates true (no false negatives).
pub fn bps_eval(bloom: &Bloom, f: &Formula) -> bool {
    match f {
        Formula::Leaf(tags) => tags.iter().any(|t| bloom.contains(t)),
        Formula::And(a, b) => bps_eval(bloom, a) && bps_eval(bloom, b),
        Formula::Or(a, b) => bps_eval(bloom, a) || bps_eval(bloom, b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::X;
    use crate::r#gen::r#gen;
    use crate::{A_DOMAIN, B_DOMAIN, Layout};

    #[test]
    fn record_has_45_sorted_tags() {
        let key = TagKey::from_seed(1);
        let r = Record {
            id: 0,
            ts: 0,
            a: 3,
            b: 123456,
            c: 900,
            d: 4,
        };
        let tags = tags_for_record(&r, &key);
        assert_eq!(tags.len(), 45);
        assert!(tags.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn dyadic_cover_is_exact_and_bounded() {
        for (lo, hi) in [(0, 500), (Y, B_DOMAIN), (0, 1), (12345, 54321), (0, B_DOMAIN)] {
            let cover = dyadic_cover(lo, hi);
            let mut sum = 0u32;
            for (level, _prefix) in &cover {
                let size = 1u32 << (B_BITS - *level as u32);
                sum += size;
            }
            assert_eq!(sum, hi - lo, "cover of [{lo},{hi})");
            assert!(cover.len() <= 2 * B_BITS as usize);
        }
        assert_eq!(dyadic_cover(Y, B_DOMAIN), vec![(1, 1)]);
    }

    #[test]
    fn rps_is_exact_for_all_predicates() {
        let key = TagKey::from_seed(9);
        for layout in [Layout::Clustered, Layout::Scattered] {
            let records = r#gen(500, 20, layout, 77);
            for p in Predicate::ALL {
                let f = formula_for(p, &key);
                for r in &records {
                    let tags = tags_for_record(r, &key);
                    assert_eq!(
                        rps_eval(&tags, &f),
                        p.matches(r),
                        "predicate {p:?} record {r:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn bps_has_no_false_negatives() {
        let key = TagKey::from_seed(10);
        for layout in [Layout::Clustered, Layout::Scattered] {
            let records = r#gen(1000, 40, layout, 123);
            let tags: Vec<Vec<Tag>> = records.iter().map(|r| tags_for_record(r, &key)).collect();
            for chunk in 0..2 {
                let lo = chunk * 500;
                let block_tags = &tags[lo..lo + 500];
                let bloom = Bloom::build(block_tags.len(), block_tags.iter().flatten());
                for p in Predicate::ALL {
                    let f = formula_for(p, &key);
                    for (i, r) in records[lo..lo + 500].iter().enumerate() {
                        if p.matches(r) {
                            assert!(
                                bps_eval(&bloom, &f),
                                "false negative: {p:?} at {i} ({layout:?})"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn bps_false_positive_rate_is_measured() {
        let key = TagKey::from_seed(11);
        // A small block leaves most of the 1000-value domain absent, so the
        // probes are genuinely false.
        let records = r#gen(50, 0, Layout::Clustered, 5);
        let tags: Vec<Vec<Tag>> = records.iter().map(|r| tags_for_record(r, &key)).collect();
        let bloom = Bloom::build(tags.len(), tags.iter().flatten());
        let present: BTreeSet<u32> = records.iter().map(|r| r.a).collect();

        let mut probes = 0usize;
        let mut fp = 0usize;
        for a in 0..A_DOMAIN {
            if a == X || present.contains(&a) {
                continue;
            }
            let f = Formula::leaf(vec![eq_tag(&key, ATTR_A, a)]);
            probes += 1;
            if bps_eval(&bloom, &f) {
                fp += 1;
            }
        }
        let rate = fp as f64 / probes as f64;
        println!(
            "BPS measured false-positive rate (P1, 1% target, {probes} absent values): {rate:.4}"
        );
        assert!(rate < 0.03, "false-positive rate too high: {rate}");
    }

    #[test]
    fn bps_double_hash_false_positive_rate_below_1_5_percent() {
        const BLOCK_RECORDS: usize = 500;
        const SEEDS: u64 = 10;
        let mut probes = 0usize;
        let mut fp = 0usize;
        for s in 0..SEEDS {
            let seed = 0x5eed_0000_0000_0000u64 + s;
            let key = TagKey::from_seed(seed);
            let records = r#gen(BLOCK_RECORDS, 0, Layout::Clustered, seed);
            let tags: Vec<Vec<Tag>> = records.iter().map(|r| tags_for_record(r, &key)).collect();
            let bloom = Bloom::build(tags.len(), tags.iter().flatten());
            let present: BTreeSet<u32> = records.iter().map(|r| r.a).collect();
            for a in 0..A_DOMAIN {
                if a == X || present.contains(&a) {
                    continue;
                }
                let f = Formula::leaf(vec![eq_tag(&key, ATTR_A, a)]);
                probes += 1;
                if bps_eval(&bloom, &f) {
                    fp += 1;
                }
            }
        }
        let rate = fp as f64 / probes as f64;
        println!(
            "BPS measured average false-positive rate (double hashing, {SEEDS} seeds x {BLOCK_RECORDS} records, {probes} absent probes): {rate:.4}"
        );
        assert!(rate < 0.015, "average false-positive rate too high: {rate}");
    }

    #[test]
    fn formula_tag_counts() {
        let key = TagKey::from_seed(3);
        assert_eq!(formula_for(Predicate::P1, &key).tag_count(), 1);
        assert_eq!(formula_for(Predicate::P2, &key).tag_count(), 2);
        assert_eq!(formula_for(Predicate::P3, &key).tag_count(), 3);
        let p4 = formula_for(Predicate::P4, &key).tag_count();
        assert!(p4 > 3, "P4 has a range leaf: {p4}");
        assert!(p4 <= 1 + 1 + 2 * B_BITS as usize + 1);
    }

    #[test]
    fn bloom_parameters_are_sane() {
        let b = Bloom::for_block(500);
        assert!(b.k() >= 1 && b.k() <= 8);
        assert!(b.nbits() > 500 * 45 * 8);
        assert!(b.bytes() >= 20_000);
    }
}
