//! w35 D4: R_Exec over a RUN of whole blocks, from a public start state to a public end state.
//!
//! The statement is the w30 `exec_link` statement with an arbitrary start: the run's words absorb from `s_in` (full 12-element state,
//! sigma after the chunk before the run, or the IV) to `s_out` (sigma after the last chunk of the run). The run's count and sum start at 0.
//! Public values (42): s_in[12], s_out[12], hdr_first[8], n_blocks, block_size, n_words, theta, count, sum, ctx[4].
//!
//! Constraints (one row = one absorbed word = one Poseidon2 permutation; all selectors as in `air.rs` / `chunk.rs`):
//!   R1  Poseidon2 permutation per row;
//!   R2  sponge from the public state: row 0 inputs = s_in + word0 (rate), s_in (capacity); transition inputs' = out + word';
//!   G3-G5  STREAM GRAMMAR (the R_RC rules of `rc.rs` R3-R5, inside the run): row 0 is the header `hdr_first` of a block of block_size
//!       records; flag boolean; header m_B in {0, block_size}; a header only after a complete block; (pid, e) constant and seq+1 inside
//!       a block; running block counter hdr from 1; at the last word: cnt_g = mb = block_size and hdr = n_blocks;
//!   E3  predicate bit m, header flag h = word[7], range checks (bits of d and v), as `air.rs` MODE 0;
//!   E4  running count and sum from 0 (m * b), inclusive of the current row;
//!   E5  row counter, `last` = [idx == n_words - 1];
//!   E6  at `last`: ALL 12 output state elements = s_out, count = pub count, sum = pub sum.
//! ctx (= C_Q) is a public value of the proof statement (checked natively against the Auth statement, as in w33); theta and n_words are
//! also AIR constants built by the verifier from its own statement.

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
use crate::psponge::Ckpt;

#[derive(Clone, Debug)]
pub struct RunLayout {
    pub p: usize,
    pub c_word: usize,
    pub c_k: usize,
    pub c_cntg: usize,
    pub c_mb: usize,
    pub c_hdr: usize,
    pub c_m: usize,
    pub c_cnt: usize,
    pub c_sum: usize,
    pub c_idx: usize,
    pub c_inv: usize,
    pub c_last: usize,
    pub c_seen: usize,
    pub c_bd: usize,
    pub c_bv: usize,
    pub width: usize,
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

impl RunLayout {
    pub fn new(p: usize) -> Self {
        let c_word = p;
        let c_k = c_word + WLEN;
        let c_cntg = c_k + 3;
        let c_mb = c_cntg + 1;
        let c_hdr = c_mb + 1;
        let c_m = c_hdr + 1;
        let c_cnt = c_m + 1;
        let c_sum = c_cnt + 1;
        let c_idx = c_sum + 1;
        let c_inv = c_idx + 1;
        let c_last = c_inv + 1;
        let c_seen = c_last + 1;
        let c_bd = c_seen + 1;
        let c_bv = c_bd + 32;
        let width = c_bv + 32;
        RunLayout {
            p, c_word, c_k, c_cntg, c_mb, c_hdr, c_m, c_cnt, c_sum, c_idx, c_inv, c_last, c_seen, c_bd, c_bv, width,
            pv_s_in: 0, pv_s_out: 12, pv_hdr_first: 24, pv_nblocks: 32, pv_bsize: 33, pv_nwords: 34, pv_theta: 35, pv_count: 36,
            pv_sum: 37, pv_ctx: 38, n_pv: 42,
        }
    }
}

/// Public statement of one run proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunPublic {
    pub s_in: State,
    pub s_out: State,
    pub hdr_first: [u64; 8],
    pub n_blocks: usize,
    pub block_size: usize,
    pub theta: u64,
    pub count: u64,
    pub sum: u64,
    pub ctx: [u64; 4],
}

impl RunPublic {
    pub fn n_words(&self) -> usize {
        self.n_blocks * (self.block_size + 1)
    }
    pub fn to_values<F: PrimeField64>(&self, lay: &RunLayout) -> Vec<F> {
        assert!(self.theta >= 1 && self.theta < (1u64 << 32), "theta must be in [1, 2^32)");
        let mut v: Vec<F> = Vec::with_capacity(lay.n_pv);
        v.extend(self.s_in.iter().map(|&x| F::from_u64(x)));
        v.extend(self.s_out.iter().map(|&x| F::from_u64(x)));
        v.extend(self.hdr_first.iter().map(|&x| F::from_u64(x)));
        v.push(F::from_u64(self.n_blocks as u64));
        v.push(F::from_u64(self.block_size as u64));
        v.push(F::from_u64(self.n_words() as u64));
        v.push(F::from_u64(self.theta));
        v.push(F::from_u64(self.count));
        v.push(F::from_u64(self.sum));
        v.extend(self.ctx.iter().map(|&x| F::from_u64(x)));
        assert_eq!(v.len(), lay.n_pv);
        v
    }
}

pub struct RunAir<
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
    pub lay: RunLayout,
    pub theta: u64,
    pub block_size: u64,
    pub n_words: u64,
}

impl<F: PrimeCharacteristicRing + Sync + Clone, LL, const W: usize, const SBOX: u64, const REG: usize, const HF: usize, const PR: usize>
    RunAir<F, LL, W, SBOX, REG, HF, PR>
{
    pub fn new(consts: RoundConstants<F, W, HF, PR>, theta: u64, block_size: u64, n_words: u64) -> Self {
        assert!(theta >= 1 && theta < (1u64 << 32) && block_size >= 1 && n_words >= 1);
        let p = p3_poseidon2_air::num_cols::<W, SBOX, REG, HF, PR>();
        RunAir { p2: Poseidon2Air::new(consts.clone()), consts, lay: RunLayout::new(p), theta, block_size, n_words }
    }
}

impl<F: PrimeCharacteristicRing + Sync + Clone, LL: Sync, const W: usize, const SBOX: u64, const REG: usize, const HF: usize, const PR: usize>
    BaseAir<F> for RunAir<F, LL, W, SBOX, REG, HF, PR>
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
    > Air<AB> for RunAir<F, LL, W, SBOX, REG, HF, PR>
{
    fn eval(&self, builder: &mut AB) {
        let lay = &self.lay;
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let pv: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let c = |x: u64| -> AB::Expr { AB::Expr::from_u64(x) };
        let one = || -> AB::Expr { AB::Expr::ONE };
        let inv_bs = F::from_u64(self.block_size).inverse();

        // ---- R1
        {
            let mut sub = SubAirBuilder::<AB, Poseidon2Air<F, LL, W, SBOX, REG, HF, PR>, AB::Var>::new(builder, 0..lay.p);
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

        // ---- R2: sponge from the public start state
        {
            let mut b = builder.when_first_row();
            for j in 0..RATE {
                b.assert_zero(Into::<AB::Expr>::into(p2l.inputs[j]) - wd(j) - pvx(lay.pv_s_in + j));
            }
            for j in RATE..W {
                b.assert_zero(Into::<AB::Expr>::into(p2l.inputs[j]) - pvx(lay.pv_s_in + j));
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

        // ---- G3: row 0 = the public header of the first block
        {
            let mut b = builder.when_first_row();
            for j in 0..8 {
                b.assert_zero(wd(j) - pvx(lay.pv_hdr_first + j));
            }
            b.assert_zero(wd(7) - one());
            b.assert_zero(wd(2) - bs_pv.clone());
            b.assert_zero(col(lay.c_k) - wd(3));
            b.assert_zero(col(lay.c_k + 1) - wd(0));
            b.assert_zero(col(lay.c_k + 2) - wd(4) + one());
            b.assert_zero(col(lay.c_cntg));
            b.assert_zero(col(lay.c_mb) - bs_pv.clone());
            b.assert_zero(col(lay.c_hdr) - one());
        }
        // ---- G4: flag boolean, header announces m_B in {0, block_size}
        let f = wd(7);
        let mb = col(lay.c_mb);
        builder.assert_zero(f.clone() * (f.clone() - one()));
        builder.assert_zero(f.clone() * mb.clone() * (mb.clone() - bs_pv.clone()));
        // ---- G5: transition
        {
            let nf = wdn(7);
            let not_nf = one() - nf.clone();
            let (k0, k1, k2) = (col(lay.c_k), col(lay.c_k + 1), col(lay.c_k + 2));
            let (cg, hdr) = (col(lay.c_cntg), col(lay.c_hdr));
            let mut b = builder.when_transition();
            b.assert_zero(not_nf.clone() * (wdn(0) - k0.clone()));
            b.assert_zero(not_nf.clone() * (wdn(1) - k1.clone()));
            b.assert_zero(not_nf.clone() * (wdn(2) - k2.clone() - one()));
            b.assert_zero(coln(lay.c_k) - (nf.clone() * wdn(3) + not_nf.clone() * k0));
            b.assert_zero(coln(lay.c_k + 1) - (nf.clone() * wdn(0) + not_nf.clone() * k1));
            b.assert_zero(coln(lay.c_k + 2) - (nf.clone() * (wdn(4) - one()) + not_nf.clone() * wdn(2)));
            b.assert_zero(nf.clone() * (cg.clone() - mb.clone()));
            b.assert_zero(coln(lay.c_cntg) - not_nf.clone() * (cg + one()));
            b.assert_zero(coln(lay.c_mb) - (nf.clone() * wdn(2) + not_nf * mb));
            b.assert_zero(coln(lay.c_hdr) - hdr - nf * wdn(2) * AB::Expr::from(inv_bs));
        }

        // ---- E3: predicate bit and range checks (as air.rs MODE 0)
        let h = wd(7);
        let m = col(lay.c_m);
        builder.assert_zero(m.clone() * (m.clone() - one()));
        builder.assert_zero(h.clone() * m.clone());
        for i in 0..64 {
            let x = col(lay.c_bd + i);
            builder.assert_zero(x.clone() * (x - one()));
        }
        let not_h = one() - h;
        let pow = |base: usize| -> AB::Expr {
            let mut acc = AB::Expr::ZERO;
            for k in 0..32 {
                acc += col(base + k) * c(1u64 << k);
            }
            acc
        };
        {
            let v = wd(4);
            let dd = m.clone() * (v.clone() - c(self.theta)) + (one() - m.clone()) * (c(self.theta - 1) - v.clone());
            builder.assert_zero(not_h.clone() * (pow(lay.c_bd) - dd));
            builder.assert_zero(not_h * (pow(lay.c_bv) - v));
        }
        // ---- E4: running count and sum from 0
        {
            let mut b = builder.when_first_row();
            b.assert_zero(col(lay.c_cnt) - m.clone());
            b.assert_zero(col(lay.c_sum) - m.clone() * wd(5));
        }
        {
            let mut b = builder.when_transition();
            b.assert_zero(coln(lay.c_cnt) - col(lay.c_cnt) - coln(lay.c_m));
            b.assert_zero(coln(lay.c_sum) - col(lay.c_sum) - coln(lay.c_m) * wdn(5));
        }
        // ---- E5: row counter and `last`
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
        // ---- E6: boundary values at row n_words - 1
        {
            let mut b = builder.when(last);
            for j in 0..W {
                b.assert_zero(out(j) - pvx(lay.pv_s_out + j));
            }
            b.assert_zero(col(lay.c_cntg) - bs_pv.clone());
            b.assert_zero(col(lay.c_mb) - bs_pv);
            b.assert_zero(col(lay.c_hdr) - pvx(lay.pv_nblocks));
            b.assert_zero(col(lay.c_cnt) - pvx(lay.pv_count));
            b.assert_zero(col(lay.c_sum) - pvx(lay.pv_sum));
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
    > RunAir<F, LL, W, SBOX, REG, HF, PR>
{
    /// Witness for whatever words are given, absorbed from `start`.
    pub fn build_trace<P: Permutation<[F; W]>>(&self, perm: &P, words: &[Vec<u64>], start: &State) -> RowMajorMatrix<F> {
        assert_eq!(W, STATE);
        let n_rows = words.len().next_power_of_two().max(MIN_ROWS);
        let (ins, _outs) = sponge_rows_from::<F, W, P>(perm, start, words, n_rows);
        self.build_trace_ins(words, ins)
    }

    /// w36 (S1): same trace as `build_trace`, sponge rows filled in parallel from stored checkpoints
    /// (`chunk::sponge_checkpoints_from`; the first checkpoint is row 0 = `start`).
    pub fn build_trace_par<P: Permutation<[F; W]>>(&self, perm: &P, words: &[Vec<u64>], ckpts: &[Ckpt<W>]) -> RowMajorMatrix<F> {
        assert_eq!(W, STATE);
        let n_rows = words.len().next_power_of_two().max(MIN_ROWS);
        let ins = sponge_ins_par_from::<F, W, P>(perm, words, n_rows, ckpts);
        self.build_trace_ins(words, ins)
    }

    /// The rest of the witness, given the permutation inputs `ins` of every row (unchanged w35 code).
    fn build_trace_ins(&self, words: &[Vec<u64>], ins: Vec<[F; W]>) -> RowMajorMatrix<F> {
        let lay = &self.lay;
        let n_words = words.len();
        let n_rows = n_words.next_power_of_two().max(MIN_ROWS);
        let p2 = generate_trace_rows::<F, LL, W, SBOX, REG, HF, PR>(ins, &self.consts, 0);
        assert_eq!(p2.width, lay.p);
        let mut vals = vec![F::ZERO; n_rows * lay.width];
        let mut pad = vec![0u64; WLEN];
        pad[7] = 1;
        let inv_bs = F::from_u64(self.block_size).inverse();
        let wf = |x: &Vec<u64>, j: usize| F::from_u64(x[j]);
        let x0 = &words[0];
        let mut k = [wf(x0, 3), wf(x0, 0), wf(x0, 4) - F::ONE];
        let (mut cg, mut mb, mut hdr) = (F::ZERO, wf(x0, 2), F::ONE);
        let theta = self.theta;
        let (mut cnt, mut sum) = (0u64, 0u64);
        for r in 0..n_rows {
            let x = if r < n_words { &words[r] } else { &pad };
            if r > 0 {
                if x[7] == 1 {
                    k = [wf(x, 3), wf(x, 0), wf(x, 4) - F::ONE];
                    cg = F::ZERO;
                    mb = wf(x, 2);
                    hdr += wf(x, 2) * inv_bs;
                } else {
                    k = [k[0], k[1], wf(x, 2)];
                    cg += F::ONE;
                }
            }
            let (mut m, mut bd, mut bv) = (0u64, [0u64; 32], [0u64; 32]);
            if x[7] == 0 {
                let v = x[4];
                m = (v >= theta) as u64;
                let d = if m == 1 { v.wrapping_sub(theta) } else { (theta - 1).wrapping_sub(v) };
                for i in 0..32 {
                    bd[i] = (d >> i) & 1;
                    bv[i] = (v >> i) & 1;
                }
                if m == 1 {
                    cnt += 1;
                    sum += x[5];
                }
            }
            let row = &mut vals[r * lay.width..(r + 1) * lay.width];
            row[..lay.p].copy_from_slice(&p2.values[r * lay.p..(r + 1) * lay.p]);
            for j in 0..WLEN {
                row[lay.c_word + j] = wf(x, j);
            }
            row[lay.c_k..lay.c_k + 3].copy_from_slice(&k);
            row[lay.c_cntg] = cg;
            row[lay.c_mb] = mb;
            row[lay.c_hdr] = hdr;
            row[lay.c_m] = F::from_u64(m);
            row[lay.c_cnt] = F::from_u64(cnt);
            row[lay.c_sum] = F::from_u64(sum);
            row[lay.c_idx] = F::from_u64(r as u64);
            let is_last = r as u64 == self.n_words - 1;
            row[lay.c_last] = F::from_bool(is_last);
            row[lay.c_inv] = if is_last { F::ZERO } else { (F::from_u64(r as u64) - F::from_u64(self.n_words - 1)).inverse() };
            row[lay.c_seen] = F::from_bool(r as u64 >= self.n_words - 1);
            for i in 0..32 {
                row[lay.c_bd + i] = F::from_u64(bd[i]);
                row[lay.c_bv + i] = F::from_u64(bv[i]);
            }
        }
        RowMajorMatrix::new(vals, lay.width)
    }
}

/// C1 prove / verify wrappers.
pub mod plain {
    use super::*;
    use crate::rel::{guard, LL};
    use crate::variants::FriOpts;
    pub use crate::variants::c1::{config, consts, from_bytes, perm, to_bytes, Val, HF, P, PR, REG, SBOX, W};
    use p3_uni_stark::{prove, verify};

    pub type RunA = RunAir<Val, LL, W, { SBOX }, REG, { HF }, { PR }>;

    pub fn run_air(p: &RunPublic) -> Result<RunA, String> {
        if p.block_size == 0 || p.block_size > (1 << 20) || p.n_blocks == 0 || p.n_blocks > crate::chunk::MAX_CHUNK_BLOCKS * 64 {
            return Err("run statement out of range".into());
        }
        if p.theta == 0 || p.theta >= (1u64 << 32) {
            return Err("theta out of range".into());
        }
        Ok(RunA::new(consts(), p.theta, p.block_size as u64, p.n_words() as u64))
    }

    /// Prove a run over `words` (header first). The trace starts at `p.s_in`.
    pub fn prove_run(o: &FriOpts, words: &[Vec<u64>], p: &RunPublic) -> Result<P, String> {
        if words.is_empty() {
            return Err("empty run".into());
        }
        let a = run_air(p)?;
        let trace = a.build_trace(&perm(), words, &p.s_in);
        let pv = p.to_values::<Val>(&a.lay);
        prove(&config(o), &a, trace, &pv).map_err(|e| format!("{e:?}"))
    }

    pub fn verify_run(o: &FriOpts, proof: &P, p: &RunPublic) -> Result<(), String> {
        guard(|| {
            let a = run_air(p)?;
            let pv = p.to_values::<Val>(&a.lay);
            verify(&config(o), &a, proof, &pv).map_err(|e| format!("{e:?}"))
        })
    }

    /// Honest statement of a run: `s_out` from the native sponge, (count, sum) from plain integer code over the words.
    pub fn honest_public(words: &[Vec<u64>], s_in: &State, block_size: usize, theta: u64, ctx: [u64; 4]) -> RunPublic {
        let s_out = crate::chunk::state_after::<Val, W, _>(&perm(), s_in, words);
        let (mut count, mut sum) = (0u64, 0u64);
        for w in words {
            if w[7] == 0 && w[4] >= theta {
                count += 1;
                sum += w[5];
            }
        }
        let mut hdr_first = [0u64; 8];
        hdr_first.copy_from_slice(&words[0][..8]);
        RunPublic { s_in: *s_in, s_out, hdr_first, n_blocks: words.len() / (block_size + 1), block_size, theta, count, sum, ctx }
    }

    pub fn run_rows(n_words: usize) -> usize {
        n_words.next_power_of_two().max(MIN_ROWS)
    }
}
