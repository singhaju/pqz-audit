//! w36 (S1): parallel sponge rows from stored checkpoints.
//!
//! The sponge of the one-proof AIRs (R_Exec `air.rs`, R_RC `rc.rs`) and of the chunk / run AIRs (`chunk.rs`, `run.rs`) is a
//! sequential chain of Poseidon2 permutations: row r absorbs word r into the state left by row r-1. `sponge_rows` /
//! `sponge_rows_from` run that chain on one thread. Given the full sponge state before row r0 (a "checkpoint", the state the
//! CSP stores at ingest, w35 design D1) the rows r0.. can be filled independently of the rows before r0. This module fills
//! the segments between consecutive checkpoints with rayon.
//!
//! A checkpoint is `(row, state)`: `state` is the full sponge state BEFORE row `row` absorbs its word (= the output of the
//! permutation of row `row - 1`; for row 0 the IV / start state). The first checkpoint must be row 0. The parallel path produces
//! the same `ins` (permutation inputs) as the sequential one if and only if the checkpoints are honest; a wrong checkpoint gives a
//! wrong trace, which the (unchanged) verifier rejects, so the prover has nothing to gain by lying about them.
//!
//! No AIR constraint and no verifier code is touched by this module.

use p3_field::PrimeField64;
use p3_maybe_rayon::prelude::*;
use p3_symmetric::Permutation;

/// Default spacing of the checkpoints, in rows (= words). 1024 rows is about 4 ms of Poseidon2 on one core, so a 131072-row
/// trace gives 128 segments, enough to balance 22-32 threads. (4096 gives only 32 segments: measured, see CHANGES-w36.md.)
pub const CKPT_K: usize = 1024;

/// (row index, full sponge state before that row absorbs its word), canonical u64 values.
pub type Ckpt<const W: usize> = (usize, [u64; W]);

#[inline]
fn absorb<F: PrimeField64, const W: usize>(s: &mut [F; W], words: &[Vec<u64>], pad: &[u64], wlen: usize, r: usize) {
    let wk = if r < words.len() { &words[r] } else { pad };
    for j in 0..wlen {
        s[j] += F::from_u64(wk[j]);
    }
}

/// Ingest-side helper: one sequential pass over the sponge from `start`, keeping the state before every `k`-th row
/// (rows 0, k, 2k, ... < n_rows). Pad rows (r >= words.len()) absorb `pad`. Nothing else is stored, so it is cheaper than
/// `sponge_rows` (no input / output vectors).
pub fn checkpoints<F: PrimeField64, const W: usize, P: Permutation<[F; W]>>(
    perm: &P,
    start: &[u64; W],
    words: &[Vec<u64>],
    wlen: usize,
    pad: &[u64],
    n_rows: usize,
    k: usize,
) -> Vec<Ckpt<W>> {
    assert!(k >= 1 && n_rows >= words.len());
    let mut s = [F::ZERO; W];
    for j in 0..W {
        s[j] = F::from_u64(start[j]);
    }
    let mut v = Vec::with_capacity(n_rows / k + 1);
    for r in 0..n_rows {
        if r % k == 0 {
            let mut c = [0u64; W];
            for j in 0..W {
                c[j] = s[j].as_canonical_u64();
            }
            v.push((r, c));
        }
        absorb(&mut s, words, pad, wlen, r);
        perm.permute_mut(&mut s);
    }
    v
}

/// The permutation inputs of all `n_rows` rows (what `sponge_rows` returns as `ins`), computed segment by segment in parallel.
/// Segment i = rows `ckpts[i].0 .. ckpts[i+1].0` (the last one runs to `n_rows`).
pub fn ins_par<F: PrimeField64, const W: usize, P: Permutation<[F; W]>>(
    perm: &P,
    words: &[Vec<u64>],
    wlen: usize,
    pad: &[u64],
    n_rows: usize,
    ckpts: &[Ckpt<W>],
) -> Vec<[F; W]> {
    assert!(n_rows >= words.len());
    assert!(!ckpts.is_empty() && ckpts[0].0 == 0, "the first checkpoint must be row 0");
    let mut ins = vec![[F::ZERO; W]; n_rows];
    let mut segs: Vec<(usize, [u64; W], &mut [[F; W]])> = Vec::with_capacity(ckpts.len());
    let mut rest: &mut [[F; W]] = &mut ins;
    for (i, &(r0, st)) in ckpts.iter().enumerate() {
        let r1 = if i + 1 < ckpts.len() { ckpts[i + 1].0 } else { n_rows };
        assert!(r0 < r1 && r1 <= n_rows, "checkpoint rows must be strictly increasing and below n_rows");
        let (seg, tail) = rest.split_at_mut(r1 - r0);
        rest = tail;
        segs.push((r0, st, seg));
    }
    segs.into_par_iter().for_each(|(r0, st, seg)| {
        let mut s = [F::ZERO; W];
        for j in 0..W {
            s[j] = F::from_u64(st[j]);
        }
        for (i, out) in seg.iter_mut().enumerate() {
            absorb(&mut s, words, pad, wlen, r0 + i);
            *out = s;
            perm.permute_mut(&mut s);
        }
    });
    ins
}
