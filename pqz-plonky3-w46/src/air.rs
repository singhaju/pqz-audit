//! Plonky3 AIR for R_Exec (mirror of `bench/pqz-proof-w30/src/exec.rs`), see README.md for the constraint table.
//!
//! ONE row = ONE absorbed word = ONE full Poseidon2 permutation (w30: 8 rows per word, one Rescue round per row).
//!
//! Column layout (all columns of one row):
//!   [ 0 .. P )            Poseidon2 AIR columns (`p3_poseidon2_air::Poseidon2Cols`): inputs, all round states
//!   word                  the absorbed word, WLEN values (MODE 0: 8 as in w30; MODE 1: 12, limb encoding, see data.rs)
//!   m                     predicate bit (m = 1 iff v >= theta), 0 on header / padding words
//!   cnt                   running count of matches (inclusive of this row)
//!   sum (NSUM = 1 | 2)    running sum of b over matches (MODE 1: sum of b_lo and sum of b_hi, two columns)
//!   idx                   row counter 0,1,2,...
//!   inv, last, seen       is-zero gadget for "idx == n_words - 1" and a "row n_words-1 exists" flag
//!   [br]                  MODE 1 only: borrow bit of the limb subtraction for d
//!   bd[32]                bits of d (LSB first; MODE 1: bd[0..16] = low limb of d, bd[16..32] = high limb)
//!   bv[32]                bits of v (LSB first; MODE 1: bv[0..16] = v_lo, bv[16..32] = v_hi)

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{generate_trace_rows, Poseidon2Air, Poseidon2Cols, RoundConstants};
use p3_symmetric::Permutation;
use p3_uni_stark::SubAirBuilder;

use crate::data::DOM_CHAIN;
use crate::psponge::{checkpoints, ins_par, Ckpt};

/// Smallest trace height: FRI needs log_height > log_final_poly_len + log_blowup (5 + 3), so 2^6 rows.
pub const MIN_ROWS: usize = 64;

#[derive(Clone, Debug)]
pub struct Layout {
    pub mode: usize,
    pub w: usize,
    pub rate: usize,
    pub cap: usize,
    pub dig: usize,
    pub p: usize,
    pub wlen: usize,
    pub c_word: usize,
    pub c_m: usize,
    pub c_cnt: usize,
    pub c_sum: usize,
    pub nsum: usize,
    pub c_idx: usize,
    pub c_inv: usize,
    pub c_last: usize,
    pub c_seen: usize,
    pub c_br: usize,
    pub c_bd: usize,
    pub c_bv: usize,
    pub width: usize,
    // public value indices
    pub pv_digest: usize,
    pub pv_nwords: usize,
    pub pv_theta: usize,
    pub pv_count: usize,
    pub pv_sum: usize,
    pub pv_nblocks: usize,
    pub pv_bsize: usize,
    pub pv_ctx: usize,
    pub n_pv: usize,
}

impl Layout {
    pub fn new(mode: usize, w: usize, p: usize) -> Self {
        assert!(mode <= 1);
        let rate = w / 3 * 2;
        let cap = w / 3;
        let wlen = if mode == 0 { 8 } else { 12 };
        assert!(wlen <= rate);
        let nsum = if mode == 0 { 1 } else { 2 };
        let c_word = p;
        let c_m = c_word + wlen;
        let c_cnt = c_m + 1;
        let c_sum = c_cnt + 1;
        let c_idx = c_sum + nsum;
        let c_inv = c_idx + 1;
        let c_last = c_inv + 1;
        let c_seen = c_last + 1;
        let (c_br, c_bd) = if mode == 1 { (c_seen + 1, c_seen + 2) } else { (usize::MAX, c_seen + 1) };
        let c_bv = c_bd + 32;
        let width = c_bv + 32;
        let ntheta = if mode == 0 { 1 } else { 2 };
        let pv_digest = 0;
        let pv_nwords = pv_digest + cap;
        let pv_theta = pv_nwords + 1;
        let pv_count = pv_theta + ntheta;
        let pv_sum = pv_count + 1;
        let pv_nblocks = pv_sum + nsum;
        let pv_bsize = pv_nblocks + 1;
        let pv_ctx = pv_bsize + 1;
        let n_pv = pv_ctx + 4;
        Layout {
            mode, w, rate, cap, dig: cap, p, wlen, c_word, c_m, c_cnt, c_sum, nsum, c_idx, c_inv, c_last, c_seen, c_br,
            c_bd, c_bv, width, pv_digest, pv_nwords, pv_theta, pv_count, pv_sum, pv_nblocks, pv_bsize, pv_ctx, n_pv,
        }
    }
    /// index of the header flag inside the word
    pub fn h(&self) -> usize {
        self.wlen - 1
    }
}

/// Public inputs of one R_Exec statement (w30 `ExecPublic`), with field elements as canonical u64.
#[derive(Clone, Debug)]
pub struct ExecPublic {
    /// sponge digest: `cap` field elements (4 for C1, 8 for C2)
    pub digest: Vec<u64>,
    pub n_blocks: usize,
    pub block_size: usize,
    pub theta: u64,
    pub count: u64,
    /// C1: [sum]; C2: [sum of b_lo, sum of b_hi] (integer sum = sum_lo + 2^10 sum_hi)
    pub sum: Vec<u64>,
    pub ctx: [u64; 4],
}

impl ExecPublic {
    pub fn n_words(&self) -> usize {
        self.n_blocks * (self.block_size + 1)
    }
    /// integer sum of b over the matches
    pub fn sum_int(&self) -> u64 {
        if self.sum.len() == 1 {
            self.sum[0]
        } else {
            self.sum[0] + (self.sum[1] << 10)
        }
    }
    /// Flat public-value vector in the order of `Layout` (n_words is derived, never free).
    pub fn to_values<F: PrimeField64>(&self, lay: &Layout) -> Vec<F> {
        assert_eq!(self.digest.len(), lay.cap);
        assert_eq!(self.sum.len(), lay.nsum);
        assert!(self.theta >= 1 && self.theta < (1u64 << 32), "theta must be in [1, 2^32)");
        let mut v: Vec<F> = self.digest.iter().map(|&x| F::from_u64(x)).collect();
        v.push(F::from_u64(self.n_words() as u64));
        if lay.mode == 0 {
            v.push(F::from_u64(self.theta));
        } else {
            v.push(F::from_u64(self.theta & 0xFFFF));
            v.push(F::from_u64(self.theta >> 16));
        }
        v.push(F::from_u64(self.count));
        v.extend(self.sum.iter().map(|&x| F::from_u64(x)));
        v.push(F::from_u64(self.n_blocks as u64));
        v.push(F::from_u64(self.block_size as u64));
        v.extend(self.ctx.iter().map(|&x| F::from_u64(x)));
        assert_eq!(v.len(), lay.n_pv);
        v
    }
}

pub struct ExecAir<
    F: PrimeCharacteristicRing,
    LL,
    const W: usize,
    const SBOX: u64,
    const REG: usize,
    const HF: usize,
    const PR: usize,
    const MODE: usize,
> {
    pub p2: Poseidon2Air<F, LL, W, SBOX, REG, HF, PR>,
    pub consts: RoundConstants<F, W, HF, PR>,
    pub lay: Layout,
    /// predicate parameter (AIR constant, also a public value in the transcript, as in w30)
    pub theta: u64,
    /// number of absorbed words n_blocks*(block_size+1) (AIR constant, also a public value)
    pub n_words: u64,
}

impl<
        F: PrimeCharacteristicRing + Sync + Clone,
        LL,
        const W: usize,
        const SBOX: u64,
        const REG: usize,
        const HF: usize,
        const PR: usize,
        const MODE: usize,
    > ExecAir<F, LL, W, SBOX, REG, HF, PR, MODE>
{
    pub fn new(consts: RoundConstants<F, W, HF, PR>, theta: u64, n_words: u64) -> Self {
        assert!(theta >= 1 && theta < (1u64 << 32));
        let p = p3_poseidon2_air::num_cols::<W, SBOX, REG, HF, PR>();
        ExecAir {
            p2: Poseidon2Air::new(consts.clone()),
            consts,
            lay: Layout::new(MODE, W, p),
            theta,
            n_words,
        }
    }
}

impl<
        F: PrimeCharacteristicRing + Sync + Clone,
        LL: Sync,
        const W: usize,
        const SBOX: u64,
        const REG: usize,
        const HF: usize,
        const PR: usize,
        const MODE: usize,
    > BaseAir<F> for ExecAir<F, LL, W, SBOX, REG, HF, PR, MODE>
{
    fn width(&self) -> usize {
        self.lay.width
    }
    fn num_public_values(&self) -> usize {
        self.lay.n_pv
    }
    // main_next_row_columns: default (all columns), as the AIR reads next-row cells of many columns.
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
        const MODE: usize,
    > Air<AB> for ExecAir<F, LL, W, SBOX, REG, HF, PR, MODE>
{
    fn eval(&self, builder: &mut AB) {
        let lay = &self.lay;
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let pv: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let c = |x: u64| -> AB::Expr { AB::Expr::from_u64(x) };
        let one = || -> AB::Expr { AB::Expr::ONE };
        let (rate, cap, dig, wlen) = (lay.rate, lay.cap, lay.dig, lay.wlen);

        // ---- (1) Poseidon2 permutation of this row: the p3-poseidon2-air constraints on columns 0..P
        {
            let mut sub = SubAirBuilder::<AB, Poseidon2Air<F, LL, W, SBOX, REG, HF, PR>, AB::Var>::new(
                builder,
                0..lay.p,
            );
            self.p2.eval(&mut sub);
        }
        let p2l: &Poseidon2Cols<AB::Var, W, SBOX, REG, HF, PR> = local[..lay.p].borrow();
        let p2n: &Poseidon2Cols<AB::Var, W, SBOX, REG, HF, PR> = next[..lay.p].borrow();
        let out = |i: usize| -> AB::Expr { p2l.ending_full_rounds[HF - 1].post[i].into() };

        let wd = |i: usize| -> AB::Expr { local[lay.c_word + i].into() };
        let wd_next = |i: usize| -> AB::Expr { next[lay.c_word + i].into() };
        let col = |i: usize| -> AB::Expr { local[i].into() };
        let col_next = |i: usize| -> AB::Expr { next[i].into() };

        // ---- (2) sponge: first row input = [word0, 0.., cap_init], transition input = previous output + word
        {
            let mut b = builder.when_first_row();
            for j in 0..wlen {
                b.assert_zero(Into::<AB::Expr>::into(p2l.inputs[j]) - wd(j));
            }
            for j in wlen..rate {
                b.assert_zero(p2l.inputs[j]);
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
                let add = if j < wlen { wd_next(j) } else { AB::Expr::ZERO };
                b.assert_zero(Into::<AB::Expr>::into(p2n.inputs[j]) - out(j) - add);
            }
            for j in rate..W {
                b.assert_zero(Into::<AB::Expr>::into(p2n.inputs[j]) - out(j));
            }
        }

        // ---- (3) predicate bit, header flag, range checks (every row)
        let h = wd(lay.h());
        let m = col(lay.c_m);
        builder.assert_zero(h.clone() * (h.clone() - one()));
        builder.assert_zero(m.clone() * (m.clone() - one()));
        builder.assert_zero(h.clone() * m.clone());
        for i in 0..64 {
            let x = col(lay.c_bd + i);
            builder.assert_zero(x.clone() * (x - one()));
        }
        let not_h = one() - h.clone();
        let pow = |bits: std::ops::Range<usize>, base: usize| -> AB::Expr {
            let mut acc = AB::Expr::ZERO;
            for (k, i) in bits.enumerate() {
                acc += col(base + i) * c(1u64 << k);
            }
            acc
        };
        if MODE == 0 {
            // v = word[4]; d = m*(v-theta) + (1-m)*(theta-1-v); 32-bit decompositions of d and v
            let v = wd(4);
            let dd = m.clone() * (v.clone() - c(self.theta)) + (one() - m.clone()) * (c(self.theta - 1) - v.clone());
            builder.assert_zero(not_h.clone() * (pow(0..32, lay.c_bd) - dd));
            builder.assert_zero(not_h.clone() * (pow(0..32, lay.c_bv) - v));
        } else {
            let (vlo, vhi) = (wd(4), wd(5));
            let (tlo, thi) = (self.theta & 0xFFFF, self.theta >> 16);
            let (ulo, uhi) = ((self.theta - 1) & 0xFFFF, (self.theta - 1) >> 16);
            let br = col(lay.c_br);
            builder.assert_zero(br.clone() * (br.clone() - one()));
            let a_lo = m.clone() * (vlo.clone() - c(tlo)) + (one() - m.clone()) * (c(ulo) - vlo.clone());
            let a_hi = m.clone() * (vhi.clone() - c(thi)) + (one() - m.clone()) * (c(uhi) - vhi.clone());
            // d_lo = a_lo + 2^16 br ; d_hi = a_hi - br ; d_lo, d_hi in [0, 2^16): d = d_lo + 2^16 d_hi = v-theta | theta-1-v
            builder.assert_zero(not_h.clone() * (pow(0..16, lay.c_bd) - a_lo - br.clone() * c(1 << 16)));
            builder.assert_zero(not_h.clone() * (pow(16..32, lay.c_bd) - a_hi + br.clone()));
            builder.assert_zero(not_h.clone() * (pow(0..16, lay.c_bv) - vlo));
            builder.assert_zero(not_h.clone() * (pow(16..32, lay.c_bv) - vhi));
        }

        // ---- (4) running count and sum (inclusive of the current row)
        let b_cols: Vec<usize> = if MODE == 0 { vec![5] } else { vec![6, 7] }; // word index of b (limbs)
        {
            let mut b = builder.when_first_row();
            b.assert_zero(col(lay.c_cnt) - m.clone());
            for (k, &bi) in b_cols.iter().enumerate() {
                b.assert_zero(col(lay.c_sum + k) - m.clone() * wd(bi));
            }
        }
        {
            let mut b = builder.when_transition();
            b.assert_zero(col_next(lay.c_cnt) - col(lay.c_cnt) - col_next(lay.c_m));
            for (k, &bi) in b_cols.iter().enumerate() {
                b.assert_zero(col_next(lay.c_sum + k) - col(lay.c_sum + k) - col_next(lay.c_m) * wd_next(bi));
            }
        }

        // ---- (5) row counter and "this is row n_words-1" selector
        let idx = col(lay.c_idx);
        let last = col(lay.c_last);
        let inv = col(lay.c_inv);
        let seen = col(lay.c_seen);
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
            b.assert_zero(col_next(lay.c_idx) - idx - one());
            b.assert_zero(col_next(lay.c_seen) - seen.clone() - col_next(lay.c_last));
        }
        builder.when_last_row().assert_zero(seen - one());

        // ---- (6) boundary values at row n_words-1: digest, count, sum
        {
            let mut b = builder.when(last);
            for j in 0..dig {
                let pj: AB::Expr = pv[lay.pv_digest + j].into();
                b.assert_zero(out(j) - pj);
            }
            let pc: AB::Expr = pv[lay.pv_count].into();
            b.assert_zero(col(lay.c_cnt) - pc);
            for k in 0..lay.nsum {
                let ps: AB::Expr = pv[lay.pv_sum + k].into();
                b.assert_zero(col(lay.c_sum + k) - ps);
            }
        }
        let _ = cap;
    }
}

/// Native sponge (reference permutation, no circuit): returns the per-row permutation inputs and outputs for the
/// padded word list. `words.len() == n_words`; the stream is padded with pad words up to `n_rows`.
pub fn sponge_rows<F: PrimeField64, const W: usize, P: Permutation<[F; W]>>(
    lay: &Layout,
    perm: &P,
    words: &[Vec<u64>],
    n_rows: usize,
) -> (Vec<[F; W]>, Vec<[F; W]>) {
    let n_words = words.len();
    assert!(n_rows >= n_words);
    let mut s = [F::ZERO; W];
    s[lay.rate] = F::from_u64(DOM_CHAIN);
    s[lay.rate + 1] = F::from_u64(n_words as u64);
    let mut ins = Vec::with_capacity(n_rows);
    let mut outs = Vec::with_capacity(n_rows);
    let mut pad = vec![0u64; lay.wlen];
    pad[lay.h()] = 1;
    for k in 0..n_rows {
        let wk = if k < n_words { &words[k] } else { &pad };
        for j in 0..lay.wlen {
            s[j] += F::from_u64(wk[j]);
        }
        ins.push(s);
        perm.permute_mut(&mut s);
        outs.push(s);
    }
    (ins, outs)
}

/// IV of the one-proof sponge (rate part 0, capacity: DOM_CHAIN, n_words) as canonical u64 values.
pub fn sponge_iv<const W: usize>(lay: &Layout, n_words: usize) -> [u64; W] {
    let mut s = [0u64; W];
    s[lay.rate] = DOM_CHAIN;
    s[lay.rate + 1] = n_words as u64;
    s
}

fn pad_word(lay: &Layout) -> Vec<u64> {
    let mut pad = vec![0u64; lay.wlen];
    pad[lay.h()] = 1;
    pad
}

/// w36 (S1) ingest-side helper: the sponge states before rows 0, k, 2k, ... (< `n_rows`) of the one-proof stream `words`
/// (same chain as `sponge_rows`; `n_rows` = the padded trace height). See `psponge.rs`.
pub fn sponge_checkpoints<F: PrimeField64, const W: usize, P: Permutation<[F; W]>>(
    lay: &Layout,
    perm: &P,
    words: &[Vec<u64>],
    n_rows: usize,
    k: usize,
) -> Vec<Ckpt<W>> {
    checkpoints::<F, W, P>(perm, &sponge_iv::<W>(lay, words.len()), words, lay.wlen, &pad_word(lay), n_rows, k)
}

/// w36 (S1): the `ins` of `sponge_rows` (permutation inputs of all `n_rows` rows), filled in parallel from the checkpoints.
pub fn sponge_ins_par<F: PrimeField64, const W: usize, P: Permutation<[F; W]>>(
    lay: &Layout,
    perm: &P,
    words: &[Vec<u64>],
    n_rows: usize,
    ckpts: &[Ckpt<W>],
) -> Vec<[F; W]> {
    ins_par::<F, W, P>(perm, words, lay.wlen, &pad_word(lay), n_rows, ckpts)
}

/// Digest of the real stream (output of the permutation of row n_words-1, first `dig` rate elements).
pub fn native_digest<F: PrimeField64, const W: usize, P: Permutation<[F; W]>>(
    lay: &Layout,
    perm: &P,
    words: &[Vec<u64>],
) -> Vec<u64> {
    let (_, outs) = sponge_rows::<F, W, P>(lay, perm, words, words.len());
    (0..lay.dig).map(|j| outs[words.len() - 1][j].as_canonical_u64()).collect()
}

impl<
        F: PrimeField64,
        LL: GenericPoseidon2LinearLayers<W> + Sync,
        const W: usize,
        const SBOX: u64,
        const REG: usize,
        const HF: usize,
        const PR: usize,
        const MODE: usize,
    > ExecAir<F, LL, W, SBOX, REG, HF, PR, MODE>
{
    /// Witness generation. `words` are the (already mapped, see data.rs) absorbed words of the prover.
    /// Honest witness for whatever words are given (so a changed record gives a trace that is internally consistent
    /// but whose digest differs from the public one).
    pub fn build_trace<P: Permutation<[F; W]>>(&self, perm: &P, words: &[Vec<u64>]) -> RowMajorMatrix<F> {
        let n_rows = words.len().next_power_of_two().max(MIN_ROWS);
        let (ins, _outs) = sponge_rows::<F, W, P>(&self.lay, perm, words, n_rows);
        self.build_trace_ins(words, ins)
    }

    /// w36 (S1): same trace as `build_trace`, with the sponge rows filled in parallel from stored checkpoints
    /// (`sponge_checkpoints`, spacing any k >= 1).
    pub fn build_trace_par<P: Permutation<[F; W]>>(&self, perm: &P, words: &[Vec<u64>], ckpts: &[Ckpt<W>]) -> RowMajorMatrix<F> {
        let n_rows = words.len().next_power_of_two().max(MIN_ROWS);
        let ins = sponge_ins_par::<F, W, P>(&self.lay, perm, words, n_rows, ckpts);
        self.build_trace_ins(words, ins)
    }

    /// The rest of the witness, given the permutation inputs `ins` of every row (unchanged w35 code).
    fn build_trace_ins(&self, words: &[Vec<u64>], ins: Vec<[F; W]>) -> RowMajorMatrix<F> {
        let lay = &self.lay;
        let n_words = words.len();
        // stage C: no length assertion here: a dishonest prover may hold a stream of another length than the AIR's n_words;
        // the trace is then simply invalid (honest behaviour is unchanged)
        let n_rows = n_words.next_power_of_two().max(MIN_ROWS);
        let p2 = generate_trace_rows::<F, LL, W, SBOX, REG, HF, PR>(ins, &self.consts, 0);
        assert_eq!(p2.width, lay.p);
        let mut vals = vec![F::ZERO; n_rows * lay.width];
        let (mut cnt, mut s0, mut s1) = (0u64, 0u64, 0u64);
        let theta = self.theta;
        let mut pad = vec![0u64; lay.wlen];
        pad[lay.h()] = 1;
        for k in 0..n_rows {
            let row = &mut vals[k * lay.width..(k + 1) * lay.width];
            row[..lay.p].copy_from_slice(&p2.values[k * lay.p..(k + 1) * lay.p]);
            let wk = if k < n_words { &words[k] } else { &pad };
            for j in 0..lay.wlen {
                row[lay.c_word + j] = F::from_u64(wk[j]);
            }
            let is_header = wk[lay.h()] == 1;
            let (mut m, mut bd, mut bv, mut br) = (0u64, [0u64; 32], [0u64; 32], 0u64);
            if !is_header {
                if MODE == 0 {
                    let v = wk[4];
                    m = (v >= theta) as u64;
                    let d = if m == 1 { v.wrapping_sub(theta) } else { (theta - 1).wrapping_sub(v) };
                    for i in 0..32 {
                        bd[i] = (d >> i) & 1;
                        bv[i] = (v >> i) & 1;
                    }
                    if m == 1 {
                        cnt += 1;
                        s0 += wk[5];
                    }
                } else {
                    let (vlo, vhi) = (wk[4] as i64, wk[5] as i64);
                    let v = vlo + (vhi << 16);
                    m = (v as u64 >= theta) as u64;
                    let (tlo, thi) = ((theta & 0xFFFF) as i64, (theta >> 16) as i64);
                    let (ulo, uhi) = (((theta - 1) & 0xFFFF) as i64, ((theta - 1) >> 16) as i64);
                    let (alo, ahi) = if m == 1 { (vlo - tlo, vhi - thi) } else { (ulo - vlo, uhi - vhi) };
                    let b = (alo < 0) as i64;
                    let (dlo, dhi) = (alo + (b << 16), ahi - b);
                    br = b as u64;
                    for i in 0..16 {
                        bd[i] = ((dlo >> i) & 1) as u64;
                        bd[16 + i] = ((dhi >> i) & 1) as u64;
                        bv[i] = ((vlo >> i) & 1) as u64;
                        bv[16 + i] = ((vhi >> i) & 1) as u64;
                    }
                    if m == 1 {
                        cnt += 1;
                        s0 += wk[6];
                        s1 += wk[7];
                    }
                }
            }
            row[lay.c_m] = F::from_u64(m);
            row[lay.c_cnt] = F::from_u64(cnt);
            row[lay.c_sum] = F::from_u64(s0);
            if lay.nsum == 2 {
                row[lay.c_sum + 1] = F::from_u64(s1);
            }
            row[lay.c_idx] = F::from_u64(k as u64);
            let diff = F::from_u64(k as u64) - F::from_u64(self.n_words - 1);
            let is_last = k as u64 == self.n_words - 1;
            row[lay.c_last] = F::from_bool(is_last);
            row[lay.c_inv] = if is_last { F::ZERO } else { diff.inverse() };
            row[lay.c_seen] = F::from_bool(k as u64 >= self.n_words - 1);
            if lay.c_br != usize::MAX {
                row[lay.c_br] = F::from_u64(br);
            }
            for i in 0..32 {
                row[lay.c_bd + i] = F::from_u64(bd[i]);
                row[lay.c_bv + i] = F::from_u64(bv[i]);
            }
        }
        RowMajorMatrix::new(vals, lay.width)
    }
}
