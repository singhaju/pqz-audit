//! w29 (NEW file): the fixed split rule for linked chunks (plan `journal2/UPGRADE-w29-plan.md`, section 1).
//!
//! Rule: whole blocks; a chunk of `b` blocks has `b * (block_size + 1)` words of 8 rows, padded to a power of two
//! (`data::pow2_len`, minimum 32); minimise the TOTAL padded rows over all splits into 1..=`max_chunks` contiguous chunks;
//! a tie in the total goes to FEWER chunks; among splits with the same total and the same number of chunks the
//! dynamic programme below takes the first one it finds (loop order: number of chunks c ascending, blocks b ascending,
//! size k of the LAST chunk ascending, strict `<`, so the smallest k wins a tie at every step of the reconstruction).
//! The result is returned sorted in DECREASING chunk size (the order of the chunks in the stream; any order is valid, this one is fixed).
//! This is the same programme as `best_split` in `scripts/pilot_driver.py` (w25 pilot), ported 1:1.

use crate::data::pow2_len;
use crate::rescue::GROUP;

/// Padded rows of a chunk of `blocks` whole blocks.
pub fn chunk_rows(blocks: usize, block_size: usize) -> usize {
    pow2_len(blocks * (block_size + 1) * GROUP)
}

/// Total padded rows of a split.
pub fn split_rows(split: &[usize], block_size: usize) -> usize {
    split.iter().map(|&b| chunk_rows(b, block_size)).sum()
}

/// Blocks per chunk, in stream order (decreasing size). Panics if `n_blocks == 0`, `block_size == 0` or `max_chunks == 0`.
pub fn plan_split(n_blocks: usize, block_size: usize, max_chunks: usize) -> Vec<usize> {
    assert!(n_blocks > 0 && block_size > 0 && max_chunks > 0);
    const INF: u64 = u64::MAX / 4;
    let mut f = vec![vec![INF; n_blocks + 1]; max_chunks + 1];
    let mut arg = vec![vec![0usize; n_blocks + 1]; max_chunks + 1];
    f[0][0] = 0;
    for c in 1..=max_chunks {
        for b in 1..=n_blocks {
            for k in 1..=b {
                let prev = f[c - 1][b - k];
                if prev >= INF {
                    continue;
                }
                let v = prev + chunk_rows(k, block_size) as u64;
                if v < f[c][b] {
                    f[c][b] = v;
                    arg[c][b] = k;
                }
            }
        }
    }
    // fewest chunks among equal totals: min over (total, c)
    let c_best = (1..=max_chunks).min_by_key(|&c| (f[c][n_blocks], c)).unwrap();
    assert!(f[c_best][n_blocks] < INF);
    let mut parts = Vec::new();
    let (mut b, mut c) = (n_blocks, c_best);
    while c > 0 {
        let k = arg[c][b];
        parts.push(k);
        b -= k;
        c -= 1;
    }
    parts.sort_unstable_by(|a, b| b.cmp(a));
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brute(n: usize, bs: usize, maxc: usize) -> (usize, usize) {
        // exhaustive over all compositions (ordered), returns (min total rows, fewest chunks reaching it)
        fn rec(left: usize, c_left: usize, bs: usize, used: usize, best: &mut Vec<(usize, usize)>, acc: usize) {
            if left == 0 {
                best.push((acc, used));
                return;
            }
            if c_left == 0 {
                return;
            }
            for k in 1..=left {
                rec(left - k, c_left - 1, bs, used + 1, best, acc + chunk_rows(k, bs));
            }
        }
        let mut v = Vec::new();
        rec(n, maxc, bs, 0, &mut v, 0);
        *v.iter().min().unwrap()
    }

    #[test]
    fn split_matches_brute_force_small() {
        for bs in [3usize, 5, 9, 500] {
            for n in 1..=18 {
                let s = plan_split(n, bs, 4);
                assert_eq!(s.iter().sum::<usize>(), n);
                assert!(s.len() <= 4 && s.iter().all(|&x| x > 0));
                let (tot, c) = brute(n, bs, 4);
                assert_eq!(split_rows(&s, bs), tot, "n={n} bs={bs} split={s:?}");
                assert_eq!(s.len(), c, "tie must go to fewer chunks: n={n} bs={bs} split={s:?}");
                assert!(s.windows(2).all(|w| w[0] >= w[1]));
            }
        }
    }

    #[test]
    fn one_block_is_one_chunk() {
        assert_eq!(plan_split(1, 7, 4), vec![1]);
    }

    #[test]
    fn max_chunks_one_is_single() {
        assert_eq!(plan_split(37, 500, 1), vec![37]);
    }
}
