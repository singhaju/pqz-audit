//! w46: R_Exec over a RUN of whole blocks of the PACKED stream format (two records per absorbed word), from a public start
//! state `s_in` to a public end state `s_out`.
//!
//! PRunAir = the P2r constraints of `pair.rs` (row kinds by countdown, predicate bits of d per half, no bits of v) with the
//! boundary of `run.rs` (sponge from the public state `s_in`, public `hdr_first`, all 12 output elements = `s_out`).
//! Public values (42, same order as `run.rs` `RunLayout`): s_in[12], s_out[12], hdr_first[8], n_blocks, block_size,
//! n_words (PACKED count), theta, count, sum, ctx[4]. ctx is a public value only (checked natively by the requester).
//!
//! SOUNDNESS DEPENDENCY (P2r): this AIR does NOT check v < 2^32 or b < 2^20. Those range checks are made by the packed chunk (R_RC)
//! proofs of the same stream (`pchunk.rs`). The run is bound to that stream through s_in / s_out, which must be sponge states
//! anchored by the chunk proofs (chunk-end states). Used alone, a run proof accepts a word with v = 2^32 + 5 as a match.
//! Likewise the record grammar inside a block (ids / seq) is checked by the chunk proofs, not by this AIR; and the public sum is a field
//! sum, equal to the integer sum only while n_records * 2^20 < p (about 2^44 records).
//!
//! Constraint table (degree in brackets); one row = one absorbed word = one Poseidon2 permutation:
//!   R1  Poseidon2 permutation of the row [3]
//!   R2  row 0 inputs = s_in (+ word in the rate); transitions: inputs' = out + word' (rate), = out (capacity) [1]
//!   G0  row 0: word = hdr_first (8 slots), hdr = 1 [1]
//!   G1  hdr, va, vb, ma, mb boolean [2]; hdr + va + pad = 1 [1]; vb(1-va) = 0, ma(1-va) = 0, mb(1-vb) = 0 [2]
//!   G2  header row: w7 = 1, w2 = public block_size, rem = w2 [2]
//!   G3  short row (va, not vb): rem = 0 and half b = 0 (4 slots) [3]
//!   G4  zero test: rem*rinv = 1 - zr, zr*rem = 0 [2]
//!   G5  transition: (1 - pad')(hdr' - zr) = 0 (next row is a header iff block complete) [2];
//!       va' (rem' - rem + 1 + vb') = 0 [2]
//!   E3  per half: bits of d boolean [2]; va (resp. vb) * (sum 2^k bit_k - d) = 0, d = m (v - theta) + (1 - m)(theta - 1 - v) [3]
//!   E4  cnt = ma + mb, sum = ma w2 + mb w6 in row 0; transition cnt' = cnt + ma' + mb', sum' = sum + ma' w2' + mb' w6' [3]
//!   E5  idx, last = [idx == n_words - 1] (n_words an AIR constant), seen [2]
//!   E6  at last: out[0..12] = s_out, cnt = count, sum = sum, zr = 1 [2]
//! Trace: `prove_run*` build the trace SEQUENTIALLY (as `run.rs` `plain::prove_run`); `build_trace_par` (checkpoints) and
//! `prove_run_bytes_par` are provided for multi-threaded trace building.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{generate_trace_rows, Poseidon2Air, Poseidon2Cols, RoundConstants};
use p3_symmetric::Permutation;
use p3_uni_stark::SubAirBuilder;

use crate::air::MIN_ROWS;
use crate::chunk::{sponge_ins_par_from, sponge_rows_from, State, RATE, STATE, WLEN};
use crate::pair::{kinds_by_position, pair_n_words, Kind, PLayout};
use crate::psponge::Ckpt;

pub use crate::run::RunPublic;

/// Packed word count of the run statement (NOT `p.n_words()`, which is the old one-record-per-word count).
pub fn prun_n_words(p: &RunPublic) -> usize {
    pair_n_words(p.n_blocks, p.block_size)
}

/// Columns (as `pair.rs` P2r) and public-value indices (as `run.rs`).
#[derive(Clone, Debug)]
pub struct PRunLayout {
    pub cols: PLayout,
    pub pv_s_in: usize,
    pub pv_s_out: usize,
    pub pv_hdr_first: usize,
    pub pv_nblocks: usize,
    pub pv_bsize: usize,
    pub pv_nwords: usize,
    pub pv_theta: usize,
    pub pv_count: usize,
    pub pv_sum: usize,
    pub pv_ctx: usize,
    pub n_pv: usize,
}

impl PRunLayout {
    pub fn new(p: usize) -> Self {
        PRunLayout {
            cols: PLayout::new(p, false),
            pv_s_in: 0,
            pv_s_out: 12,
            pv_hdr_first: 24,
            pv_nblocks: 32,
            pv_bsize: 33,
            pv_nwords: 34,
            pv_theta: 35,
            pv_count: 36,
            pv_sum: 37,
            pv_ctx: 38,
            n_pv: 42,
        }
    }
}

/// 42 public values; n_words = packed count.
pub fn prun_values<F: PrimeField64>(p: &RunPublic) -> Vec<F> {
    assert!(p.theta >= 1 && p.theta < (1u64 << 32), "theta must be in [1, 2^32)");
    let mut v: Vec<F> = Vec::with_capacity(42);
    v.extend(p.s_in.iter().map(|&x| F::from_u64(x)));
    v.extend(p.s_out.iter().map(|&x| F::from_u64(x)));
    v.extend(p.hdr_first.iter().map(|&x| F::from_u64(x)));
    v.push(F::from_u64(p.n_blocks as u64));
    v.push(F::from_u64(p.block_size as u64));
    v.push(F::from_u64(prun_n_words(p) as u64));
    v.push(F::from_u64(p.theta));
    v.push(F::from_u64(p.count));
    v.push(F::from_u64(p.sum));
    v.extend(p.ctx.iter().map(|&x| F::from_u64(x)));
    assert_eq!(v.len(), 42);
    v
}

pub struct PRunAir<
    F: PrimeCharacteristicRing,
    LL,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> {
    pub p2: Poseidon2Air<F, LL, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    pub consts: RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    pub lay: PRunLayout,
    pub theta: u64,
    /// number of PACKED words of the run (AIR constant)
    pub n_words: u64,
    /// prover-side minimum trace height (the verifier reads the height from the proof); the hiding PCS needs more
    pub min_rows: usize,
}

impl<F: PrimeCharacteristicRing + Sync + Clone, LL, const W: usize, const SBOX: u64, const REG: usize, const HF: usize, const PR: usize>
    PRunAir<F, LL, W, SBOX, REG, HF, PR>
{
    pub fn new(consts: RoundConstants<F, W, HF, PR>, theta: u64, n_words: u64, min_rows: usize) -> Self {
        assert!(W == 12);
        assert!(theta >= 1 && theta < (1u64 << 32) && n_words >= 1);
        let p = p3_poseidon2_air::num_cols::<W, SBOX, REG, HF, PR>();
        PRunAir { p2: Poseidon2Air::new(consts.clone()), consts, lay: PRunLayout::new(p), theta, n_words, min_rows: min_rows.max(MIN_ROWS) }
    }
}

impl<F: PrimeCharacteristicRing + Sync + Clone, LL: Sync, const W: usize, const SBOX: u64, const REG: usize, const HF: usize, const PR: usize>
    BaseAir<F> for PRunAir<F, LL, W, SBOX, REG, HF, PR>
{
    fn width(&self) -> usize {
        self.lay.cols.width
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
    > Air<AB> for PRunAir<F, LL, W, SBOX, REG, HF, PR>
{
    fn eval(&self, builder: &mut AB) {
        let (pl, l) = (&self.lay, &self.lay.cols);
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let pv: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let c = |x: u64| -> AB::Expr { AB::Expr::from_u64(x) };
        let one = || -> AB::Expr { AB::Expr::ONE };
        let pvx = |i: usize| -> AB::Expr { pv[i].into() };

        // R1
        {
            let mut sub = SubAirBuilder::<AB, Poseidon2Air<F, LL, W, SBOX, REG, HF, PR>, AB::Var>::new(builder, 0..l.p);
            self.p2.eval(&mut sub);
        }
        let p2l: &Poseidon2Cols<AB::Var, W, SBOX, REG, HF, PR> = local[..l.p].borrow();
        let p2n: &Poseidon2Cols<AB::Var, W, SBOX, REG, HF, PR> = next[..l.p].borrow();
        let out = |i: usize| -> AB::Expr { p2l.ending_full_rounds[HF - 1].post[i].into() };
        let wd = |i: usize| -> AB::Expr { local[l.c_word + i].into() };
        let wd_next = |i: usize| -> AB::Expr { next[l.c_word + i].into() };
        let col = |i: usize| -> AB::Expr { local[i].into() };
        let col_next = |i: usize| -> AB::Expr { next[i].into() };

        // R2: sponge from the public start state
        {
            let mut b = builder.when_first_row();
            for j in 0..RATE {
                b.assert_zero(Into::<AB::Expr>::into(p2l.inputs[j]) - wd(j) - pvx(pl.pv_s_in + j));
            }
            for j in RATE..W {
                b.assert_zero(Into::<AB::Expr>::into(p2l.inputs[j]) - pvx(pl.pv_s_in + j));
            }
        }
        {
            let mut b = builder.when_transition();
            for j in 0..RATE {
                b.assert_zero(Into::<AB::Expr>::into(p2n.inputs[j]) - out(j) - wd_next(j));
            }
            for j in RATE..W {
                b.assert_zero(Into::<AB::Expr>::into(p2n.inputs[j]) - out(j));
            }
        }

        // row kinds and countdown (pair.rs)
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
        let bsz = pvx(pl.pv_bsize);
        builder.assert_zero(hdr.clone() * (wd(7) - one()));
        builder.assert_zero(hdr.clone() * (wd(2) - bsz));
        builder.assert_zero(hdr.clone() * (rem.clone() - wd(2)));
        let short = va.clone() * (one() - vb.clone());
        builder.assert_zero(short.clone() * rem.clone());
        for i in 4..8 {
            builder.assert_zero(short.clone() * wd(i));
        }
        builder.assert_zero(rem.clone() * rinv.clone() - (one() - zr.clone()));
        builder.assert_zero(zr.clone() * rem.clone());
        // G0: first row = the public header
        {
            let mut b = builder.when_first_row();
            b.assert_zero(hdr.clone() - one());
            for j in 0..8 {
                b.assert_zero(wd(j) - pvx(pl.pv_hdr_first + j));
            }
        }
        {
            let mut b = builder.when_transition();
            b.assert_zero((one() - pad_next) * (col_next(l.c_hdr) - zr.clone()));
            b.assert_zero(col_next(l.c_va) * (col_next(l.c_rem) - rem.clone() + one() + col_next(l.c_vb)));
        }

        // predicate gadgets (P2r: no bits of v)
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
        }
        let halves = [(va.clone(), ma.clone(), 1usize, l.c_bda), (vb.clone(), mb.clone(), 5usize, l.c_bdb)];
        for (valid, m, vi, bd) in halves {
            let v = wd(vi);
            let dd = m.clone() * (v.clone() - c(self.theta)) + (one() - m.clone()) * (c(self.theta - 1) - v.clone());
            builder.assert_zero(valid * (pow(bd) - dd));
        }

        // running count and sum from 0
        {
            let mut b = builder.when_first_row();
            b.assert_zero(col(l.c_cnt) - ma.clone() - mb.clone());
            b.assert_zero(col(l.c_sum) - ma.clone() * wd(2) - mb.clone() * wd(6));
        }
        {
            let mut b = builder.when_transition();
            b.assert_zero(col_next(l.c_cnt) - col(l.c_cnt) - col_next(l.c_ma) - col_next(l.c_mb));
            b.assert_zero(col_next(l.c_sum) - col(l.c_sum) - col_next(l.c_ma) * wd_next(2) - col_next(l.c_mb) * wd_next(6));
        }

        // row counter and `last`
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

        // E6: boundary at row n_words - 1
        {
            let mut b = builder.when(last);
            b.assert_zero(zr - one());
            for j in 0..W {
                b.assert_zero(out(j) - pvx(pl.pv_s_out + j));
            }
            b.assert_zero(col(l.c_cnt) - pvx(pl.pv_count));
            b.assert_zero(col(l.c_sum) - pvx(pl.pv_sum));
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
    > PRunAir<F, LL, W, SBOX, REG, HF, PR>
{
    pub fn n_rows_for(&self, words: &[Vec<u64>]) -> usize {
        words.len().next_power_of_two().max(self.min_rows)
    }

    /// Witness for the honest structure (kinds by position, `block_size`), sponge from `start`, sequential.
    pub fn build_trace<P: Permutation<[F; W]>>(&self, perm: &P, words: &[Vec<u64>], start: &State, block_size: usize) -> RowMajorMatrix<F> {
        assert_eq!(W, STATE);
        let (ins, _) = sponge_rows_from::<F, W, P>(perm, start, words, self.n_rows_for(words));
        self.build_trace_ins(words, ins, &kinds_by_position(words.len(), block_size))
    }
    /// Same trace, permutation inputs filled in parallel from checkpoints (`chunk::sponge_checkpoints_from`, first = row 0 = `start`).
    pub fn build_trace_par<P: Permutation<[F; W]>>(&self, perm: &P, words: &[Vec<u64>], block_size: usize, ckpts: &[Ckpt<W>]) -> RowMajorMatrix<F> {
        assert_eq!(W, STATE);
        let ins = sponge_ins_par_from::<F, W, P>(perm, words, self.n_rows_for(words), ckpts);
        self.build_trace_ins(words, ins, &kinds_by_position(words.len(), block_size))
    }
    /// Witness with hand-made row kinds (tests).
    pub fn build_trace_kinds<P: Permutation<[F; W]>>(&self, perm: &P, words: &[Vec<u64>], start: &State, kinds: &[Kind]) -> RowMajorMatrix<F> {
        let (ins, _) = sponge_rows_from::<F, W, P>(perm, start, words, self.n_rows_for(words));
        self.build_trace_ins(words, ins, kinds)
    }

    fn build_trace_ins(&self, words: &[Vec<u64>], ins: Vec<[F; W]>, kinds: &[Kind]) -> RowMajorMatrix<F> {
        let l = &self.lay.cols;
        let n_words = words.len();
        let n_rows = self.n_rows_for(words);
        assert_eq!(kinds.len(), n_words);
        let p2 = generate_trace_rows::<F, LL, W, SBOX, REG, HF, PR>(ins, &self.consts, 0);
        assert_eq!(p2.width, l.p);
        let mut vals = vec![F::ZERO; n_rows * l.width];
        let (mut cnt, mut sum) = (0u64, 0u64);
        let theta = self.theta;
        let mut pad = vec![0u64; WLEN];
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
            for j in 0..WLEN {
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
            let is_last = k as u64 == self.n_words - 1;
            row[l.c_last] = F::from_bool(is_last);
            row[l.c_inv] = if is_last { F::ZERO } else { (F::from_u64(k as u64) - F::from_u64(self.n_words - 1)).inverse() };
            row[l.c_seen] = F::from_bool(k as u64 >= self.n_words - 1);
        }
        RowMajorMatrix::new(vals, l.width)
    }
}

macro_rules! prun_mod {
    ($m:ident, $base:ident, $min_rows:expr) => {
        pub mod $m {
            use super::*;
            use crate::rel::{guard, LL};
            use crate::variants::FriOpts;
            pub use crate::variants::$base::{config, consts, from_bytes, perm, to_bytes, Val, HF, P, PR, REG, SBOX, W};
            use p3_uni_stark::{prove, verify};
            use std::time::Instant;

            pub type PRunA = PRunAir<Val, LL, W, { SBOX }, REG, { HF }, { PR }>;

            /// Prover-side minimum trace height of this module.
            pub const MIN_TRACE_ROWS: usize = $min_rows;

            pub fn run_air(p: &RunPublic) -> Result<PRunA, String> {
                if p.block_size == 0 || p.block_size > (1 << 20) || p.n_blocks == 0 || p.n_blocks > crate::chunk::MAX_CHUNK_BLOCKS * 64 {
                    return Err("run statement out of range".into());
                }
                if p.theta == 0 || p.theta >= (1u64 << 32) {
                    return Err("theta out of range".into());
                }
                Ok(PRunA::new(consts(), p.theta, prun_n_words(p) as u64, MIN_TRACE_ROWS))
            }

            /// Prove a run over PACKED `words` (header first). The trace starts at `p.s_in` (sequential trace).
            pub fn prove_run(o: &FriOpts, words: &[Vec<u64>], p: &RunPublic) -> Result<P, String> {
                if words.is_empty() {
                    return Err("empty run".into());
                }
                let a = run_air(p)?;
                let trace = a.build_trace(&perm(), words, &p.s_in, p.block_size);
                let pv = prun_values::<Val>(p);
                prove(&config(o), &a, trace, &pv).map_err(|e| format!("{e:?}"))
            }

            /// Prove with timing: (proof bytes, trace seconds, prove seconds, rows). `par`: trace built from checkpoints in parallel.
            fn prove_timed(o: &FriOpts, words: &[Vec<u64>], p: &RunPublic, par: bool) -> Result<(Vec<u8>, f64, f64, usize), String> {
                if words.is_empty() {
                    return Err("empty run".into());
                }
                let a = run_air(p)?;
                let t0 = Instant::now();
                let n_rows = a.n_rows_for(words);
                let trace = if par {
                    let ck = crate::chunk::sponge_checkpoints_from::<Val, W, _>(&perm(), &p.s_in, words, n_rows, crate::psponge::CKPT_K);
                    a.build_trace_par(&perm(), words, p.block_size, &ck)
                } else {
                    a.build_trace(&perm(), words, &p.s_in, p.block_size)
                };
                let trace_s = t0.elapsed().as_secs_f64();
                let pv = prun_values::<Val>(p);
                let t1 = Instant::now();
                let proof = prove(&config(o), &a, trace, &pv).map_err(|e| format!("{e:?}"))?;
                let prove_s = t1.elapsed().as_secs_f64();
                Ok((to_bytes(&proof), trace_s, prove_s, n_rows))
            }
            pub fn prove_run_bytes(o: &FriOpts, words: &[Vec<u64>], p: &RunPublic) -> Result<(Vec<u8>, f64, f64, usize), String> {
                prove_timed(o, words, p, false)
            }
            /// Same, with the trace built in parallel from sponge checkpoints (checkpoint time counted in trace_s).
            pub fn prove_run_bytes_par(o: &FriOpts, words: &[Vec<u64>], p: &RunPublic) -> Result<(Vec<u8>, f64, f64, usize), String> {
                prove_timed(o, words, p, true)
            }

            pub fn verify_run(o: &FriOpts, proof: &P, p: &RunPublic) -> Result<(), String> {
                guard(|| {
                    let a = run_air(p)?;
                    let pv = prun_values::<Val>(p);
                    verify(&config(o), &a, proof, &pv).map_err(|e| format!("{e:?}"))
                })
            }
            pub fn verify_run_bytes(o: &FriOpts, bytes: &[u8], p: &RunPublic) -> Result<(), String> {
                let proof = from_bytes(bytes)?;
                verify_run(o, &proof, p)
            }

            /// Honest statement of a run over PACKED words: s_out from the native sponge, (count, sum) from the packed row kinds.
            pub fn honest_public(words: &[Vec<u64>], s_in: &State, block_size: usize, theta: u64, ctx: [u64; 4]) -> RunPublic {
                let s_out = crate::chunk::state_after::<Val, W, _>(&perm(), s_in, words);
                let (mut count, mut sum) = (0u64, 0u64);
                for (w, k) in words.iter().zip(kinds_by_position(words.len(), block_size)) {
                    if k.va && w[1] >= theta {
                        count += 1;
                        sum += w[2];
                    }
                    if k.vb && w[5] >= theta {
                        count += 1;
                        sum += w[6];
                    }
                }
                let rpb = crate::pair::rows_per_block(block_size);
                assert!(words.len() % rpb == 0, "words must be whole blocks");
                let mut hdr_first = [0u64; 8];
                hdr_first.copy_from_slice(&words[0][..8]);
                RunPublic { s_in: *s_in, s_out, hdr_first, n_blocks: words.len() / rpb, block_size, theta, count, sum, ctx }
            }

            pub fn run_rows(n_words: usize) -> usize {
                n_words.next_power_of_two().max(MIN_TRACE_ROWS.max(MIN_ROWS))
            }
        }
    };
}

prun_mod!(plain, c1, 64);
// hiding PCS: fast1 (126 queries) needs 512 rows ("HidingBudgetExceeded" at 256; see rel.rs), so every zk run is padded to >= 512 rows
prun_mod!(zk, c1zk, 512);
