//! Stage C: Plonky3 AIR for R_RC (mirror of `bench/pqz-proof-w30/src/rc.rs`), see README.md for the constraint table.
//!
//! Same layout idea as R_Exec (air.rs): ONE row = ONE absorbed word = ONE full Poseidon2 permutation, so row k of this
//! trace is group k of the w30 trace (w30: 8 Rescue rows per word). The carried values K, cnt, mb, hdr of row k are the
//! values AFTER word k (inclusive), which are the w30 values of group k. The w30 link-row constraints of group k -> k+1
//! become the transition constraints of row k -> k+1, using the word of row k+1.
//!
//! Column layout:
//!   [ 0 .. P )     Poseidon2 AIR columns (`p3_poseidon2_air::Poseidon2Cols`)
//!   word[8]        the absorbed word of this row (w30 format, flag = word[7])
//!   K[3]           carried (pid, epoch, seq) of the current block
//!   cnt            records since the last header
//!   mb             record count announced by the current header (block_size; 0 for padding words)
//!   hdr            number of real headers so far
//!   idx, inv, last, seen    row counter and the "row n_words-1" selector (as in R_Exec)
//!
//! Public values (flat order): digest[4], n_words (derived, not free), n_blocks, block_size, header0[8].
//! Every constraint has degree <= 3 (the quotient degree is the same as for R_Exec).

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{generate_trace_rows, Poseidon2Air, Poseidon2Cols, RoundConstants};
use p3_symmetric::Permutation;
use p3_uni_stark::SubAirBuilder;

use crate::air::{sponge_checkpoints, sponge_ins_par, sponge_rows, Layout, MIN_ROWS};
use crate::psponge::Ckpt;
use crate::data::DOM_CHAIN;

pub const WLEN: usize = 8;
pub const RATE: usize = 8;

#[derive(Clone, Debug)]
pub struct RcLayout {
    pub w: usize,
    pub p: usize,
    pub c_word: usize,
    pub c_k: usize,
    pub c_cnt: usize,
    pub c_mb: usize,
    pub c_hdr: usize,
    pub c_idx: usize,
    pub c_inv: usize,
    pub c_last: usize,
    pub c_seen: usize,
    pub width: usize,
    pub pv_digest: usize,
    pub pv_nwords: usize,
    pub pv_nblocks: usize,
    pub pv_bsize: usize,
    pub pv_header0: usize,
    pub n_pv: usize,
}

impl RcLayout {
    pub fn new(w: usize, p: usize) -> Self {
        assert_eq!(w, 12, "R_RC is written for Poseidon2 width 12 (rate 8, capacity 4)");
        let c_word = p;
        let c_k = c_word + WLEN;
        let c_cnt = c_k + 3;
        let c_mb = c_cnt + 1;
        let c_hdr = c_mb + 1;
        let c_idx = c_hdr + 1;
        let c_inv = c_idx + 1;
        let c_last = c_inv + 1;
        let c_seen = c_last + 1;
        let width = c_seen + 1;
        RcLayout {
            w, p, c_word, c_k, c_cnt, c_mb, c_hdr, c_idx, c_inv, c_last, c_seen, width,
            pv_digest: 0, pv_nwords: 4, pv_nblocks: 5, pv_bsize: 6, pv_header0: 7, n_pv: 15,
        }
    }
}

/// Public inputs of one R_RC statement (w30 `RcPublic`), field elements as canonical u64.
#[derive(Clone, Debug)]
pub struct RcPublic {
    pub digest: Vec<u64>,
    pub n_blocks: usize,
    pub block_size: usize,
    pub header0: [u64; 8],
}

impl RcPublic {
    pub fn n_words(&self) -> usize {
        self.n_blocks * (self.block_size + 1)
    }
    pub fn to_values<F: PrimeField64>(&self, lay: &RcLayout) -> Vec<F> {
        assert_eq!(self.digest.len(), 4);
        let mut v: Vec<F> = self.digest.iter().map(|&x| F::from_u64(x)).collect();
        v.push(F::from_u64(self.n_words() as u64));
        v.push(F::from_u64(self.n_blocks as u64));
        v.push(F::from_u64(self.block_size as u64));
        v.extend(self.header0.iter().map(|&x| F::from_u64(x)));
        assert_eq!(v.len(), lay.n_pv);
        v
    }
}

pub struct RcAir<
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
    pub lay: RcLayout,
    /// block size (AIR constant, also a public value)
    pub block_size: u64,
    /// number of absorbed words (AIR constant, also a public value)
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
    > RcAir<F, LL, W, SBOX, REG, HF, PR>
{
    pub fn new(consts: RoundConstants<F, W, HF, PR>, block_size: u64, n_words: u64) -> Self {
        assert!(block_size >= 1 && n_words >= 1);
        let p = p3_poseidon2_air::num_cols::<W, SBOX, REG, HF, PR>();
        RcAir { p2: Poseidon2Air::new(consts.clone()), consts, lay: RcLayout::new(W, p), block_size, n_words }
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
    > BaseAir<F> for RcAir<F, LL, W, SBOX, REG, HF, PR>
{
    fn width(&self) -> usize {
        self.lay.width
    }
    fn num_public_values(&self) -> usize {
        self.lay.n_pv
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
    > Air<AB> for RcAir<F, LL, W, SBOX, REG, HF, PR>
{
    fn eval(&self, builder: &mut AB) {
        let lay = &self.lay;
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let pv: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let c = |x: u64| -> AB::Expr { AB::Expr::from_u64(x) };
        let one = || -> AB::Expr { AB::Expr::ONE };
        let bs_f = F::from_u64(self.block_size);
        let inv_bs = bs_f.inverse();

        // ---- (R1) Poseidon2 permutation of this row
        {
            let mut sub =
                SubAirBuilder::<AB, Poseidon2Air<F, LL, W, SBOX, REG, HF, PR>, AB::Var>::new(builder, 0..lay.p);
            self.p2.eval(&mut sub);
        }
        let p2l: &Poseidon2Cols<AB::Var, W, SBOX, REG, HF, PR> = local[..lay.p].borrow();
        let p2n: &Poseidon2Cols<AB::Var, W, SBOX, REG, HF, PR> = next[..lay.p].borrow();
        let out = |i: usize| -> AB::Expr { p2l.ending_full_rounds[HF - 1].post[i].into() };
        let wd = |i: usize| -> AB::Expr { local[lay.c_word + i].into() };
        let wdn = |i: usize| -> AB::Expr { next[lay.c_word + i].into() };
        let col = |i: usize| -> AB::Expr { local[i].into() };
        let coln = |i: usize| -> AB::Expr { next[i].into() };
        let pvx = |i: usize| -> AB::Expr { pv[i].into() };
        let bs_pv = pvx(lay.pv_bsize);

        // ---- (R2) sponge: row 0 input = [word0 | cap_init], transition input = previous output + next word
        {
            let mut b = builder.when_first_row();
            for j in 0..RATE {
                b.assert_zero(Into::<AB::Expr>::into(p2l.inputs[j]) - wd(j));
            }
            b.assert_zero(Into::<AB::Expr>::into(p2l.inputs[RATE]) - c(DOM_CHAIN));
            b.assert_zero(Into::<AB::Expr>::into(p2l.inputs[RATE + 1]) - c(self.n_words));
            for j in RATE + 2..W {
                b.assert_zero(p2l.inputs[j]);
            }
        }
        {
            let mut b = builder.when_transition();
            for j in 0..RATE {
                b.assert_zero(Into::<AB::Expr>::into(p2n.inputs[j]) - out(j) - wdn(j));
            }
            for j in RATE..W {
                b.assert_zero(Into::<AB::Expr>::into(p2n.inputs[j]) - out(j));
            }
        }

        // ---- (R3) row 0: the word is the public header0 and is a header of block_size records; K, cnt, mb, hdr start values
        {
            let mut b = builder.when_first_row();
            for j in 0..8 {
                b.assert_zero(wd(j) - pvx(lay.pv_header0 + j));
            }
            b.assert_zero(wd(7) - one()); // header flag (w30: bound through header0 only)
            b.assert_zero(wd(2) - bs_pv.clone()); // m_B of the first header = block_size (w30: asserted by get_assertions)
            b.assert_zero(col(lay.c_k) - wd(3));
            b.assert_zero(col(lay.c_k + 1) - wd(0));
            b.assert_zero(col(lay.c_k + 2) - wd(4) + one());
            b.assert_zero(col(lay.c_cnt));
            b.assert_zero(col(lay.c_mb) - bs_pv.clone());
            b.assert_zero(col(lay.c_hdr) - one());
        }

        // ---- (R4) per-row: flag boolean; a header announces m_B in {0, block_size} (m_B = mb of this row on a header row)
        let f = wd(7);
        let mb = col(lay.c_mb);
        builder.assert_zero(f.clone() * (f.clone() - one()));
        builder.assert_zero(f.clone() * mb.clone() * (mb.clone() - bs_pv.clone()));

        // ---- (R5) transition row k -> k+1 (w30 link row of group k), x = word of row k+1, nf = its flag
        {
            let nf = wdn(7);
            let not_nf = one() - nf.clone();
            let (k0, k1, k2) = (col(lay.c_k), col(lay.c_k + 1), col(lay.c_k + 2));
            let (cnt, hdr) = (col(lay.c_cnt), col(lay.c_hdr));
            let mut b = builder.when_transition();
            // record: pid == K0, epoch == K1, seq == K2 + 1
            b.assert_zero(not_nf.clone() * (wdn(0) - k0.clone()));
            b.assert_zero(not_nf.clone() * (wdn(1) - k1.clone()));
            b.assert_zero(not_nf.clone() * (wdn(2) - k2.clone() - one()));
            // K updates
            b.assert_zero(coln(lay.c_k) - (nf.clone() * wdn(3) + not_nf.clone() * k0));
            b.assert_zero(coln(lay.c_k + 1) - (nf.clone() * wdn(0) + not_nf.clone() * k1));
            b.assert_zero(coln(lay.c_k + 2) - (nf.clone() * (wdn(4) - one()) + not_nf.clone() * wdn(2)));
            // a header only follows a complete block
            b.assert_zero(nf.clone() * (cnt.clone() - mb.clone()));
            // counters
            b.assert_zero(coln(lay.c_cnt) - not_nf.clone() * (cnt + one()));
            b.assert_zero(coln(lay.c_mb) - (nf.clone() * wdn(2) + not_nf * mb));
            b.assert_zero(coln(lay.c_hdr) - hdr - nf * wdn(2) * AB::Expr::from(inv_bs));
        }

        // ---- (R6) row counter and "this is row n_words-1" selector (as R_Exec)
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
            b.assert_zero(coln(lay.c_idx) - idx - one());
            b.assert_zero(coln(lay.c_seen) - seen.clone() - coln(lay.c_last));
        }
        builder.when_last_row().assert_zero(seen - one());

        // ---- (R7) at row n_words-1: digest, cnt = mb = block_size, hdr = n_blocks
        {
            let mut b = builder.when(last);
            for j in 0..4 {
                b.assert_zero(out(j) - pvx(lay.pv_digest + j));
            }
            b.assert_zero(col(lay.c_cnt) - bs_pv.clone());
            b.assert_zero(col(lay.c_mb) - bs_pv);
            b.assert_zero(col(lay.c_hdr) - pvx(lay.pv_nblocks));
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
    > RcAir<F, LL, W, SBOX, REG, HF, PR>
{
    /// Witness generation for whatever words are given (a changed stream gives an internally consistent Poseidon2 part
    /// and carried values computed by the honest update rule, so the first violated constraint is the one the change breaks).
    pub fn build_trace<P: Permutation<[F; W]>>(&self, perm: &P, words: &[Vec<u64>]) -> RowMajorMatrix<F> {
        let n_rows = words.len().next_power_of_two().max(MIN_ROWS);
        let el = Layout::new(0, W, self.lay.p);
        let (ins, _outs) = sponge_rows::<F, W, P>(&el, perm, words, n_rows);
        self.build_trace_ins(words, ins)
    }

    /// w36 (S1): the layout used for the sponge (as in `build_trace`) and its checkpoints (ingest-side helper).
    pub fn sponge_checkpoints<P: Permutation<[F; W]>>(&self, perm: &P, words: &[Vec<u64>], k: usize) -> Vec<Ckpt<W>> {
        let n_rows = words.len().next_power_of_two().max(MIN_ROWS);
        sponge_checkpoints::<F, W, P>(&Layout::new(0, W, self.lay.p), perm, words, n_rows, k)
    }

    /// w36 (S1): same trace as `build_trace`, sponge rows filled in parallel from stored checkpoints.
    pub fn build_trace_par<P: Permutation<[F; W]>>(&self, perm: &P, words: &[Vec<u64>], ckpts: &[Ckpt<W>]) -> RowMajorMatrix<F> {
        let n_rows = words.len().next_power_of_two().max(MIN_ROWS);
        let el = Layout::new(0, W, self.lay.p);
        let ins = sponge_ins_par::<F, W, P>(&el, perm, words, n_rows, ckpts);
        self.build_trace_ins(words, ins)
    }

    /// The rest of the witness, given the permutation inputs `ins` of every row (unchanged w35 code).
    fn build_trace_ins(&self, words: &[Vec<u64>], ins: Vec<[F; W]>) -> RowMajorMatrix<F> {
        let lay = &self.lay;
        let n_words = words.len();
        // the stream length may differ from the AIR's n_words (a dishonest prover): the trace is then simply invalid
        let n_rows = n_words.next_power_of_two().max(MIN_ROWS);
        let p2 = generate_trace_rows::<F, LL, W, SBOX, REG, HF, PR>(ins, &self.consts, 0);
        assert_eq!(p2.width, lay.p);
        let mut vals = vec![F::ZERO; n_rows * lay.width];
        let mut pad = vec![0u64; WLEN];
        pad[7] = 1;
        let inv_bs = F::from_u64(self.block_size).inverse();
        let wf = |x: &Vec<u64>, j: usize| F::from_u64(x[j]);
        // after word 0
        let x0 = &words[0];
        let mut k = [wf(x0, 3), wf(x0, 0), wf(x0, 4) - F::ONE];
        let (mut cnt, mut mb, mut hdr) = (F::ZERO, wf(x0, 2), F::ONE);
        for r in 0..n_rows {
            let x = if r < n_words { &words[r] } else { &pad };
            if r > 0 {
                if x[7] == 1 {
                    k = [wf(x, 3), wf(x, 0), wf(x, 4) - F::ONE];
                    cnt = F::ZERO;
                    mb = wf(x, 2);
                    hdr += wf(x, 2) * inv_bs;
                } else {
                    k = [k[0], k[1], wf(x, 2)];
                    cnt += F::ONE;
                }
            }
            let row = &mut vals[r * lay.width..(r + 1) * lay.width];
            row[..lay.p].copy_from_slice(&p2.values[r * lay.p..(r + 1) * lay.p]);
            for j in 0..WLEN {
                row[lay.c_word + j] = wf(x, j);
            }
            row[lay.c_k..lay.c_k + 3].copy_from_slice(&k);
            row[lay.c_cnt] = cnt;
            row[lay.c_mb] = mb;
            row[lay.c_hdr] = hdr;
            row[lay.c_idx] = F::from_u64(r as u64);
            let is_last = r as u64 == self.n_words - 1;
            row[lay.c_last] = F::from_bool(is_last);
            row[lay.c_inv] =
                if is_last { F::ZERO } else { (F::from_u64(r as u64) - F::from_u64(self.n_words - 1)).inverse() };
            row[lay.c_seen] = F::from_bool(r as u64 >= self.n_words - 1);
        }
        RowMajorMatrix::new(vals, lay.width)
    }
}
