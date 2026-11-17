//! Deterministic synthetic data generator.
//!
//! Every non-hit has `a != X` and `c != Z`, which makes P1..P4 false on exactly
//! the same set: all four predicates are true if and only if the record is a
//! hit. Hits also have `b >= Y`, `c < Z` and `d == W`.

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{Rng, SeedableRng};

use crate::{A_DOMAIN, B_DOMAIN, Layout, Record, W, X, Y, Z};

/// Generate `n` records, of which exactly `sigma_count` satisfy P1..P4.
///
/// Records are ordered by `ts == id`. `layout` decides where the hits are.
pub fn r#gen(n: usize, sigma_count: usize, layout: Layout, seed: u64) -> Vec<Record> {
    assert!(sigma_count <= n, "sigma_count must not exceed n");
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let mut records: Vec<Record> = (0..n)
        .map(|i| {
            let id = i as u64;
            Record {
                id,
                ts: id,
                a: non_hit_excluding(&mut rng, A_DOMAIN, X),
                b: rng.next_u32() & (B_DOMAIN - 1),
                c: non_hit_excluding(&mut rng, A_DOMAIN, Z),
                d: uniform_below(&mut rng, A_DOMAIN),
            }
        })
        .collect();

    let hit_ids = match layout {
        Layout::Clustered => {
            let offset = uniform_below(&mut rng, (n - sigma_count + 1) as u32) as usize;
            (offset..offset + sigma_count).collect::<Vec<_>>()
        }
        Layout::Scattered => {
            let mut ids: Vec<usize> = (0..n).collect();
            for i in 0..sigma_count {
                let j = i + uniform_below(&mut rng, (n - i) as u32) as usize;
                ids.swap(i, j);
            }
            ids.truncate(sigma_count);
            ids
        }
    };

    for idx in hit_ids {
        let r = &mut records[idx];
        r.a = X;
        // B_DOMAIN - Y is a power of two (2^19), so masking is unbiased.
        let span = B_DOMAIN - Y;
        r.b = Y + (rng.next_u32() & (span - 1));
        r.c = uniform_below(&mut rng, Z);
        r.d = W;
    }

    records
}

/// Uniform in `0..bound` by rejection (no modulo bias).
fn uniform_below(rng: &mut ChaCha20Rng, bound: u32) -> u32 {
    assert!(bound > 0);
    let limit = u32::MAX - (u32::MAX % bound);
    loop {
        let x = rng.next_u32();
        if x < limit {
            return x % bound;
        }
    }
}

/// Uniform in `0..domain` after removing `forbidden`.
fn non_hit_excluding(rng: &mut ChaCha20Rng, domain: u32, forbidden: u32) -> u32 {
    let v = uniform_below(rng, domain - 1);
    if v >= forbidden { v + 1 } else { v }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{B_BITS, Predicate};

    #[test]
    fn exact_hit_count_every_predicate_and_layout() {
        let n = 5000;
        let sigma = 50;
        for layout in [Layout::Clustered, Layout::Scattered] {
            let records = r#gen(n, sigma, layout, 0x5eed);
            assert_eq!(records.len(), n);
            for (i, r) in records.iter().enumerate() {
                assert_eq!(r.id, i as u64);
                assert_eq!(r.ts, r.id);
            }
            for p in Predicate::ALL {
                let count = records.iter().filter(|r| p.matches(r)).count();
                assert_eq!(count, sigma, "layout={layout:?} predicate={p:?}");
            }
        }
    }

    #[test]
    fn hits_are_where_the_layout_says() {
        let n = 400;
        let sigma = 17;
        let recs = r#gen(n, sigma, Layout::Clustered, 11);
        let hits: Vec<usize> = recs
            .iter()
            .enumerate()
            .filter(|(_, r)| Predicate::P4.matches(r))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits.len(), sigma);
        assert!(hits.windows(2).all(|w| w[1] == w[0] + 1));

        let recs = r#gen(n, sigma, Layout::Scattered, 11);
        let mut hits: Vec<usize> = recs
            .iter()
            .enumerate()
            .filter(|(_, r)| Predicate::P4.matches(r))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits.len(), sigma);
        hits.sort_unstable();
        hits.dedup();
        assert_eq!(hits.len(), sigma, "scattered hits must be distinct");
    }

    #[test]
    fn edge_cases() {
        assert_eq!(r#gen(10, 0, Layout::Clustered, 1).len(), 10);
        assert_eq!(
            r#gen(10, 10, Layout::Clustered, 1)
                .iter()
                .filter(|r| Predicate::P1.matches(r))
                .count(),
            10
        );
        assert_eq!(
            r#gen(10, 10, Layout::Scattered, 1)
                .iter()
                .filter(|r| Predicate::P1.matches(r))
                .count(),
            10
        );
    }

    #[test]
    fn same_seed_same_data() {
        let a = r#gen(100, 5, Layout::Scattered, 42);
        let b = r#gen(100, 5, Layout::Scattered, 42);
        assert_eq!(a, b);
        let c = r#gen(100, 5, Layout::Scattered, 43);
        assert_ne!(a, c);
    }

    #[test]
    fn b_domain_is_20_bits() {
        let recs = r#gen(200, 0, Layout::Clustered, 7);
        assert!(recs.iter().all(|r| r.b < B_DOMAIN));
        assert_eq!(B_BITS, 20);
    }
}
