//! w38 (P2, P2r): R_Exec AIR for the PACKED stream format ("two records per absorbed word").
//!
//! Stream of one block g (B = block_size records, m_g = B):
//!   header word   [e, g, m_g, pid, seq_start, hd_lo, hd_hi, 1]          (unchanged, absorbed alone)
//!   record words  [id_a, v_a, b_a, tau_a, id_b, v_b, b_b, tau_b]         (ceil(B/2) words; if B is odd the last word has half b = 0)
//! One row = one absorbed word = one Poseidon2 permutation (as w36 MODE 0). Rows per block: 1 + ceil(B/2).
//! The old record word [pid, e, seq, id, v, b, tau, 0] is gone: pid, e are in the header, seq = seq_start + position.
//!
//! Row kinds are NOT read from a hashed flag: they are decided by an in-AIR countdown.
//!   hdr, va, vb  boolean columns. Exactly one of {hdr, va, pad} is 1 (pad = rows after n_words-1; pad = seen - last).
//!   va = 1 : record row (half a is a real record);  vb = 1 : half b is a real record (vb <= va).
//!   rem          records still to absorb AFTER this row. Header row: rem = w[2] = B (public block size).
//!                Record row: rem = rem_prev - 1 - vb.  (va*(1-vb)*rem = 0: a row with an empty half b is the last of its block.)
//!   zr, rinv     is-zero gadget for rem.  Next row is a header iff zr (unless it is a pad row).  Last real row: zr = 1.
//! So a header row is followed by exactly ceil(B/2) record rows, all with vb = 1 except possibly the last (only if B is odd);
//! the first row is a header; the last real row closes a block. An empty half b must hold the all-zero half word (enforced).
//! Predicate gadgets: for each half, m bit and 32 bits of d (d = v - theta if m else theta - 1 - v), and (P2 only) 32 bits of v.
//! P2r (`range_v = false`): the 32 bits of v are dropped. v < 2^32 is then NOT checked by this AIR; it must be checked by the chunk
//! (R_RC) proof of the same stream, which is NOT built yet (see CHANGES-w38.md).
//! cnt, sum: cnt' = cnt + m_a' + m_b', sum' = sum + m_a' b_a' + m_b' b_b'. b is not range-checked (same as MODE 0), no b in {0,1} shortcut.
//! Public values: the layout of MODE 0 (`Layout::new(0, ..)`): digest, n_words (packed), theta, count, sum, n_blocks, block_size, ctx.
//! All constraints have degree <= 3 (as w36).

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{generate_trace_rows, Poseidon2Air, Poseidon2Cols, RoundConstants};
use p3_symmetric::Permutation;
use p3_uni_stark::{prove, verify, SubAirBuilder};

use crate::air::{native_digest, sponge_checkpoints, sponge_ins_par, ExecPublic, Layout, MIN_ROWS};
use crate::data::{RawWord, Workload, DOM_CHAIN};
use crate::psponge::Ckpt;
use crate::variants::{c1, FriOpts};

/// Packed words of a raw stream (header + record words of `data.rs`, block size `block_size`): headers unchanged, records two per word.
pub fn pack_raw(raw: &[RawWord], block_size: usize) -> Vec<Vec<u64>> {
    assert!(block_size >= 1 && raw.len() % (block_size + 1) == 0);
    let mut out = Vec::new();
    for blk in raw.chunks(block_size + 1) {
        assert_eq!(blk[0][7], 1, "block must start with a header word");
        out.push(blk[0].to_vec());
        for pair in blk[1..].chunks(2) {
            assert!(pair.iter().all(|r| r[7] == 0));
            let mut w = vec![pair[0][3], pair[0][4], pair[0][5], pair[0][6], 0, 0, 0, 0];
            if pair.len() == 2 {
                w[4..8].copy_from_slice(&[pair[1][3], pair[1][4], pair[1][5], pair[1][6]]);
            }
            out.push(w);
        }
    }
    out
}
pub fn pack_workload(w: &Workload) -> Vec<Vec<u64>> {
    pack_raw(&w.words, w.block_size)
}
/// Rows (= absorbed words) per block in the packed format.
pub fn rows_per_block(block_size: usize) -> usize {
    1 + (block_size + 1) / 2
}
/// Number of packed words of the statement.
pub fn pair_n_words(n_blocks: usize, block_size: usize) -> usize {
    n_blocks * rows_per_block(block_size)
}

#[derive(Clone, Debug)]
pub struct PLayout {
    pub range_v: bool,
    pub p: usize,
    pub c_word: usize,
    pub c_ma: usize,
    pub c_mb: usize,
    pub c_cnt: usize,
    pub c_sum: usize,
    pub c_idx: usize,
    pub c_inv: usize,
    pub c_last: usize,
    pub c_seen: usize,
    pub c_hdr: usize,
    pub c_va: usize,
    pub c_vb: usize,
    pub c_rem: usize,
    pub c_zr: usize,
    pub c_rinv: usize,
    pub c_bda: usize,
    pub c_bdb: usize,
    pub c_bva: usize,
    pub c_bvb: usize,
    pub width: usize,
}

impl PLayout {
    pub fn new(p: usize, range_v: bool) -> Self {
        let c_word = p;
        let mut c = c_word + 8;
        let mut take = |n: usize| {
            let s = c;
            c += n;
            s
        };
        let c_ma = take(1);
        let c_mb = take(1);
        let c_cnt = take(1);
        let c_sum = take(1);
        let c_idx = take(1);
        let c_inv = take(1);
        let c_last = take(1);
        let c_seen = take(1);
        let c_hdr = take(1);
        let c_va = take(1);
        let c_vb = take(1);
        let c_rem = take(1);
        let c_zr = take(1);
        let c_rinv = take(1);
        let c_bda = take(32);
        let c_bdb = take(32);
        let (c_bva, c_bvb) = if range_v { (take(32), take(32)) } else { (usize::MAX, usize::MAX) };
        PLayout {
            range_v, p, c_word, c_ma, c_mb, c_cnt, c_sum, c_idx, c_inv, c_last, c_seen, c_hdr, c_va, c_vb, c_rem, c_zr, c_rinv,
            c_bda, c_bdb, c_bva, c_bvb, width: c,
        }
    }
}

/// Row kind of the honest or a hand-made (test) structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kind {
    pub hdr: bool,
    pub va: bool,
    pub vb: bool,
}

/// Honest row kinds for `n_blocks` blocks of `block_size` records.
pub fn honest_kinds(n_blocks: usize, block_size: usize) -> Vec<Kind> {
    let mut k = Vec::with_capacity(pair_n_words(n_blocks, block_size));
    for _ in 0..n_blocks {
        k.push(Kind { hdr: true, va: false, vb: false });
        let nrec = (block_size + 1) / 2;
        for j in 0..nrec {
            let vb = 2 * j + 1 < block_size;
            k.push(Kind { hdr: false, va: true, vb });
        }
    }
    k
}

pub struct PairAir<
    F: PrimeCharacteristicRing,
    LL,
    const W: usize,
    const SBOX: u64,
    const REG: usize,
    const HF: usize,
    const PR: usize,
> {
    pub p2: Poseidon2Air<F, LL, W, SBOX, REG, HF, PR>,
    pub consts: RoundConstants<F, W, HF, PR>,
    pub lay: PLayout,
    /// public-value layout (= MODE 0 `Layout`)
    pub lay0: Layout,
    pub theta: u64,
    /// number of packed words (AIR constant, also a public value)
    pub n_words: u64,
}

impl<F: PrimeCharacteristicRing + Sync + Clone, LL, const W: usize, const SBOX: u64, const REG: usize, const HF: usize, const PR: usize>
    PairAir<F, LL, W, SBOX, REG, HF, PR>
{
    pub fn new(consts: RoundConstants<F, W, HF, PR>, theta: u64, n_words: u64, range_v: bool) -> Self {
        assert!(W == 12);
        assert!(theta >= 1 && theta < (1u64 << 32));
        let p = p3_poseidon2_air::num_cols::<W, SBOX, REG, HF, PR>();
        PairAir {
            p2: Poseidon2Air::new(consts.clone()),
            consts,
            lay: PLayout::new(p, range_v),
            lay0: Layout::new(0, W, p),
            theta,
            n_words,
        }
    }
}

impl<F: PrimeCharacteristicRing + Sync + Clone, LL: Sync, const W: usize, const SBOX: u64, const REG: usize, const HF: usize, const PR: usize>
    BaseAir<F> for PairAir<F, LL, W, SBOX, REG, HF, PR>
{
    fn width(&self) -> usize {
        self.lay.width
    }
    fn num_public_values(&self) -> usize {
        self.lay0.n_pv
    }
}

impl<
        AB: AirBuilder<F = F>,
        F: Field,
        LL: GenericPoseidon2LinearLayers<W> + Sync,
        const W: usize,
        const SBOX: u64,
        const REG: usize,
        const HF: usize,
        const PR: usize,
    > Air<AB> for PairAir<F, LL, W, SBOX, REG, HF, PR>
{
    fn eval(&self, builder: &mut AB) {
        let (l, l0) = (&self.lay, &self.lay0);
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let pv: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let c = |x: u64| -> AB::Expr { AB::Expr::from_u64(x) };
        let one = || -> AB::Expr { AB::Expr::ONE };
        let rate = l0.rate;

        // (1) Poseidon2 permutation of the row
        {
            let mut sub =
                SubAirBuilder::<AB, Poseidon2Air<F, LL, W, SBOX, REG, HF, PR>, AB::Var>::new(builder, 0..l.p);
            self.p2.eval(&mut sub);
        }
        let p2l: &Poseidon2Cols<AB::Var, W, SBOX, REG, HF, PR> = local[..l.p].borrow();
        let p2n: &Poseidon2Cols<AB::Var, W, SBOX, REG, HF, PR> = next[..l.p].borrow();
        let out = |i: usize| -> AB::Expr { p2l.ending_full_rounds[HF - 1].post[i].into() };
        let wd = |i: usize| -> AB::Expr { local[l.c_word + i].into() };
        let wd_next = |i: usize| -> AB::Expr { next[l.c_word + i].into() };
        let col = |i: usize| -> AB::Expr { local[i].into() };
        let col_next = |i: usize| -> AB::Expr { next[i].into() };

        // (2) sponge (word length 8 = rate)
        {
            let mut b = builder.when_first_row();
            for j in 0..rate {
                b.assert_zero(Into::<AB::Expr>::into(p2l.inputs[j]) - wd(j));
            }
            b.assert_zero(Into::<AB::Expr>::into(p2l.inputs[rate]) - c(DOM_CHAIN));
            b.assert_zero(Into::<AB::Expr>::into(p2l.inputs[rate + 1]) - c(self.n_words));
            for j in rate + 2..W {
                b.assert_zero(p2l.inputs[j]);
            }
        }
        {
            let mut b = builder.when_transition();
            for j in 0..rate {
                b.assert_zero(Into::<AB::Expr>::into(p2n.inputs[j]) - out(j) - wd_next(j));
            }
            for j in rate..W {
                b.assert_zero(Into::<AB::Expr>::into(p2n.inputs[j]) - out(j));
            }
        }

        // (3) row kinds and countdown
        let (hdr, va, vb) = (col(l.c_hdr), col(l.c_va), col(l.c_vb));
        let (ma, mb) = (col(l.c_ma), col(l.c_mb));
        let (idx, last, inv, seen) = (col(l.c_idx), col(l.c_last), col(l.c_inv), col(l.c_seen));
        let (rem, zr, rinv) = (col(l.c_rem), col(l.c_zr), col(l.c_rinv));
        let pad = seen.clone() - last.clone();
        let pad_next = col_next(l.c_seen) - col_next(l.c_last);
        for x in [&hdr, &va, &vb, &ma, &mb] {
            builder.assert_zero(x.clone() * (x.clone() - one()));
        }
        builder.assert_zero(hdr.clone() + va.clone() + pad.clone() - one());
        builder.assert_zero(vb.clone() * (one() - va.clone()));
        builder.assert_zero(ma.clone() * (one() - va.clone()));
        builder.assert_zero(mb.clone() * (one() - vb.clone()));
        // header row: flag slot, m_g = public block size, countdown load
        let bsz: AB::Expr = pv[l0.pv_bsize].into();
        builder.assert_zero(hdr.clone() * (wd(7) - one()));
        builder.assert_zero(hdr.clone() * (wd(2) - bsz));
        builder.assert_zero(hdr.clone() * (rem.clone() - wd(2)));
        // record row: an empty half b is the last row of the block, and holds the all-zero half word
        let short = va.clone() * (one() - vb.clone());
        builder.assert_zero(short.clone() * rem.clone());
        for i in 4..8 {
            builder.assert_zero(short.clone() * wd(i));
        }
        // zero test of rem
        builder.assert_zero(rem.clone() * rinv.clone() - (one() - zr.clone()));
        builder.assert_zero(zr.clone() * rem.clone());
        {
            let mut b = builder.when_first_row();
            b.assert_zero(hdr.clone() - one());
        }
        {
            let mut b = builder.when_transition();
            // next row is a header iff the block is complete (pad rows are outside the structure)
            b.assert_zero((one() - pad_next) * (col_next(l.c_hdr) - zr.clone()));
            // record row: rem = rem_prev - 1 - vb
            b.assert_zero(col_next(l.c_va) * (col_next(l.c_rem) - rem.clone() + one() + col_next(l.c_vb)));
        }

        // (4) predicate gadgets, per half
        let pow = |base: usize| -> AB::Expr {
            let mut acc = AB::Expr::ZERO;
            for k in 0..32 {
                acc += col(base + k) * c(1u64 << k);
            }
            acc
        };
        for i in 0..32 {
            for base in [l.c_bda, l.c_bdb] {
                let x = col(base + i);
                builder.assert_zero(x.clone() * (x - one()));
            }
            if l.range_v {
                for base in [l.c_bva, l.c_bvb] {
                    let x = col(base + i);
                    builder.assert_zero(x.clone() * (x - one()));
                }
            }
        }
        let halves = [(va.clone(), ma.clone(), 1usize, l.c_bda, l.c_bva), (vb.clone(), mb.clone(), 5usize, l.c_bdb, l.c_bvb)];
        for (valid, m, vi, bd, bv) in halves {
            let v = wd(vi);
            let dd = m.clone() * (v.clone() - c(self.theta)) + (one() - m.clone()) * (c(self.theta - 1) - v.clone());
            builder.assert_zero(valid.clone() * (pow(bd) - dd));
            if l.range_v {
                builder.assert_zero(valid * (pow(bv) - v));
            }
        }

        // (5) running count and sum (inclusive of the current row)
        {
            let mut b = builder.when_first_row();
            b.assert_zero(col(l.c_cnt) - ma.clone() - mb.clone());
            b.assert_zero(col(l.c_sum) - ma.clone() * wd(2) - mb.clone() * wd(6));
        }
        {
            let mut b = builder.when_transition();
            b.assert_zero(col_next(l.c_cnt) - col(l.c_cnt) - col_next(l.c_ma) - col_next(l.c_mb));
            b.assert_zero(
                col_next(l.c_sum) - col(l.c_sum) - col_next(l.c_ma) * wd_next(2) - col_next(l.c_mb) * wd_next(6),
            );
        }

        // (6) row counter and "row n_words-1" selector
        let diff = idx.clone() - c(self.n_words - 1);
        builder.assert_zero(diff.clone() * last.clone());
        builder.assert_zero(diff * inv - (one() - last.clone()));
        {
            let mut b = builder.when_first_row();
            b.assert_zero(idx.clone());
            b.assert_zero(seen.clone() - last.clone());
        }
        {
            let mut b = builder.when_transition();
            b.assert_zero(col_next(l.c_idx) - idx - one());
            b.assert_zero(col_next(l.c_seen) - seen.clone() - col_next(l.c_last));
        }
        builder.when_last_row().assert_zero(seen - one());

        // (7) boundary values at row n_words-1: the last block is complete, digest, count, sum
        {
            let mut b = builder.when(last);
            b.assert_zero(zr - one());
            for j in 0..l0.dig {
                let pj: AB::Expr = pv[l0.pv_digest + j].into();
                b.assert_zero(out(j) - pj);
            }
            let pc: AB::Expr = pv[l0.pv_count].into();
            b.assert_zero(col(l.c_cnt) - pc);
            let ps: AB::Expr = pv[l0.pv_sum].into();
            b.assert_zero(col(l.c_sum) - ps);
        }
    }
}

impl<
        F: PrimeField64,
        LL: GenericPoseidon2LinearLayers<W> + Sync,
        const W: usize,
        const SBOX: u64,
        const REG: usize,
        const HF: usize,
        const PR: usize,
    > PairAir<F, LL, W, SBOX, REG, HF, PR>
{
    fn n_rows_for(&self, words: &[Vec<u64>]) -> usize {
        words.len().next_power_of_two().max(MIN_ROWS)
    }

    /// Honest witness of the statement's structure (kinds by position: block size = `block_size`, n_blocks derived from n_words).
    pub fn build_trace<P: Permutation<[F; W]>>(&self, perm: &P, words: &[Vec<u64>], block_size: usize) -> RowMajorMatrix<F> {
        let n_rows = self.n_rows_for(words);
        let (ins, _) = crate::air::sponge_rows::<F, W, P>(&self.lay0, perm, words, n_rows);
        self.build_trace_ins(words, ins, &kinds_by_position(words.len(), block_size))
    }
    pub fn build_trace_par<P: Permutation<[F; W]>>(&self, perm: &P, words: &[Vec<u64>], block_size: usize, ckpts: &[Ckpt<W>]) -> RowMajorMatrix<F> {
        let n_rows = self.n_rows_for(words);
        let ins = sponge_ins_par::<F, W, P>(&self.lay0, perm, words, n_rows, ckpts);
        self.build_trace_ins(words, ins, &kinds_by_position(words.len(), block_size))
    }
    /// Witness with hand-made row kinds (tests: a dishonest prover chooses its own hdr / va / vb columns).
    pub fn build_trace_kinds<P: Permutation<[F; W]>>(&self, perm: &P, words: &[Vec<u64>], kinds: &[Kind]) -> RowMajorMatrix<F> {
        let n_rows = self.n_rows_for(words);
        let (ins, _) = crate::air::sponge_rows::<F, W, P>(&self.lay0, perm, words, n_rows);
        self.build_trace_ins(words, ins, kinds)
    }

    fn build_trace_ins(&self, words: &[Vec<u64>], ins: Vec<[F; W]>, kinds: &[Kind]) -> RowMajorMatrix<F> {
        let l = &self.lay;
        let n_words = words.len();
        let n_rows = self.n_rows_for(words);
        assert_eq!(kinds.len(), n_words);
        let p2 = generate_trace_rows::<F, LL, W, SBOX, REG, HF, PR>(ins, &self.consts, 0);
        assert_eq!(p2.width, l.p);
        let mut vals = vec![F::ZERO; n_rows * l.width];
        let (mut cnt, mut sum) = (0u64, 0u64);
        let theta = self.theta;
        let mut pad = vec![0u64; 8];
        pad[7] = 1;
        let mut rem = F::ZERO;
        let bits = |x: u64, row: &mut [F], base: usize| {
            for i in 0..32 {
                row[base + i] = F::from_u64((x >> i) & 1);
            }
        };
        for k in 0..n_rows {
            let row = &mut vals[k * l.width..(k + 1) * l.width];
            row[..l.p].copy_from_slice(&p2.values[k * l.p..(k + 1) * l.p]);
            let wk = if k < n_words { &words[k] } else { &pad };
            for j in 0..8 {
                row[l.c_word + j] = F::from_u64(wk[j]);
            }
            let kind = if k < n_words { kinds[k] } else { Kind { hdr: false, va: false, vb: false } };
            let (mut ma, mut mb) = (0u64, 0u64);
            if k >= n_words {
                rem = F::ZERO;
            } else if kind.hdr {
                rem = F::from_u64(wk[2]);
            } else if kind.va {
                rem = rem - F::ONE - F::from_bool(kind.vb);
            }
            if kind.va {
                let (v, b) = (wk[1], wk[2]);
                ma = (v >= theta) as u64;
                let d = if ma == 1 { v.wrapping_sub(theta) } else { (theta - 1).wrapping_sub(v) };
                bits(d, row, l.c_bda);
                if l.range_v {
                    bits(v, row, l.c_bva);
                }
                if ma == 1 {
                    cnt += 1;
                    sum += b;
                }
            }
            if kind.vb {
                let (v, b) = (wk[5], wk[6]);
                mb = (v >= theta) as u64;
                let d = if mb == 1 { v.wrapping_sub(theta) } else { (theta - 1).wrapping_sub(v) };
                bits(d, row, l.c_bdb);
                if l.range_v {
                    bits(v, row, l.c_bvb);
                }
                if mb == 1 {
                    cnt += 1;
                    sum += b;
                }
            }
            row[l.c_ma] = F::from_u64(ma);
            row[l.c_mb] = F::from_u64(mb);
            row[l.c_cnt] = F::from_u64(cnt);
            row[l.c_sum] = F::from_u64(sum);
            row[l.c_hdr] = F::from_bool(kind.hdr);
            row[l.c_va] = F::from_bool(kind.va);
            row[l.c_vb] = F::from_bool(kind.vb);
            row[l.c_rem] = rem;
            let z = rem == F::ZERO;
            row[l.c_zr] = F::from_bool(z);
            row[l.c_rinv] = if z { F::ZERO } else { rem.inverse() };
            row[l.c_idx] = F::from_u64(k as u64);
            let diff = F::from_u64(k as u64) - F::from_u64(self.n_words - 1);
            let is_last = k as u64 == self.n_words - 1;
            row[l.c_last] = F::from_bool(is_last);
            row[l.c_inv] = if is_last { F::ZERO } else { diff.inverse() };
            row[l.c_seen] = F::from_bool(k as u64 >= self.n_words - 1);
        }
        RowMajorMatrix::new(vals, l.width)
    }
}

pub fn kinds_by_position(n_words: usize, block_size: usize) -> Vec<Kind> {
    let rpb = rows_per_block(block_size);
    let nrec = (block_size + 1) / 2;
    (0..n_words)
        .map(|k| {
            let pos = k % rpb;
            if pos == 0 {
                Kind { hdr: true, va: false, vb: false }
            } else {
                Kind { hdr: false, va: true, vb: !(pos == nrec && block_size % 2 == 1) }
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------------------------------
// Goldilocks (C1) wrappers
// ---------------------------------------------------------------------------------------------------------------------

pub type PAir = PairAir<c1::Val, crate::rel::LL, { c1::W }, { c1::SBOX }, { c1::REG }, { c1::HF }, { c1::PR }>;

/// Packed-format variant: P2 (v range-checked in the Exec AIR) or P2r (v range check dropped).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fmt {
    P2,
    P2r,
}
impl Fmt {
    pub fn range_v(self) -> bool {
        self == Fmt::P2
    }
}

pub fn pair_air(theta: u64, n_words: u64, f: Fmt) -> PAir {
    PAir::new(c1::consts(), theta, n_words, f.range_v())
}
pub fn pair_n_rows(n_words: usize) -> usize {
    n_words.next_power_of_two().max(MIN_ROWS)
}
pub fn pair_width(f: Fmt) -> usize {
    pair_air(1 << 31, 2, f).lay.width
}

/// Honest public statement: digest from the native sponge over the PACKED words, count/sum from the integer reference.
pub fn pair_public(w: &Workload, theta: u64, ctx: [u64; 4]) -> ExecPublic {
    let lay0 = Layout::new(0, 12, 0);
    let digest = native_digest::<c1::Val, 12, _>(&lay0, &c1::perm(), &pack_workload(w));
    let (count, s) = w.reference_result(theta);
    ExecPublic { digest, n_blocks: w.n_blocks, block_size: w.block_size, theta, count, sum: vec![s], ctx }
}
/// Public values vector (n_words = packed word count).
pub fn pair_values(p: &ExecPublic) -> Vec<c1::Val> {
    let mut v: Vec<c1::Val> = p.digest.iter().map(|&x| c1::Val::from_u64(x)).collect();
    v.push(c1::Val::from_u64(pair_n_words(p.n_blocks, p.block_size) as u64));
    v.push(c1::Val::from_u64(p.theta));
    v.push(c1::Val::from_u64(p.count));
    v.extend(p.sum.iter().map(|&x| c1::Val::from_u64(x)));
    v.push(c1::Val::from_u64(p.n_blocks as u64));
    v.push(c1::Val::from_u64(p.block_size as u64));
    v.extend(p.ctx.iter().map(|&x| c1::Val::from_u64(x)));
    v
}
fn check_public(p: &ExecPublic) -> Result<(), String> {
    if p.block_size == 0 || p.n_blocks == 0 || p.theta < 1 || p.theta >= (1u64 << 32) || p.sum.len() != 1 || p.digest.len() != 4 {
        return Err("malformed statement".into());
    }
    Ok(())
}

/// Prover from packed words (they may differ from the data behind `p`: rejection tests).
pub fn prove_pair_words(o: &FriOpts, words: &[Vec<u64>], p: &ExecPublic, f: Fmt) -> Result<c1::P, String> {
    check_public(p)?;
    let a = pair_air(p.theta, pair_n_words(p.n_blocks, p.block_size) as u64, f);
    let trace = a.build_trace(&c1::perm(), words, p.block_size);
    prove(&c1::config(o), &a, trace, &pair_values(p)).map_err(|e| format!("{e:?}"))
}
pub fn prove_pair(o: &FriOpts, w: &Workload, p: &ExecPublic, f: Fmt) -> Result<c1::P, String> {
    prove_pair_words(o, &pack_workload(w), p, f)
}
pub fn prove_pair_kinds(o: &FriOpts, words: &[Vec<u64>], kinds: &[Kind], p: &ExecPublic, f: Fmt) -> Result<c1::P, String> {
    check_public(p)?;
    let a = pair_air(p.theta, pair_n_words(p.n_blocks, p.block_size) as u64, f);
    let trace = a.build_trace_kinds(&c1::perm(), words, kinds);
    prove(&c1::config(o), &a, trace, &pair_values(p)).map_err(|e| format!("{e:?}"))
}
pub fn verify_pair_raw(o: &FriOpts, proof: &c1::P, p: &ExecPublic, f: Fmt) -> Result<(), String> {
    check_public(p)?;
    let a = pair_air(p.theta, pair_n_words(p.n_blocks, p.block_size) as u64, f);
    verify(&c1::config(o), &a, proof, &pair_values(p)).map_err(|e| format!("{e:?}"))
}
/// Guarded verifier (a panic on malformed input is a rejection).
pub fn verify_pair(o: &FriOpts, proof: &c1::P, p: &ExecPublic, f: Fmt) -> Result<(), String> {
    crate::rel::guard(|| verify_pair_raw(o, proof, p, f))
}

pub fn pair_checkpoints(words: &[Vec<u64>], n_rows: usize, k: usize) -> Vec<Ckpt<12>> {
    let lay0 = Layout::new(0, 12, 0);
    sponge_checkpoints::<c1::Val, 12, _>(&lay0, &c1::perm(), words, n_rows, k)
}
