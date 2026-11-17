//! R_Exec (predicate execution over the retained records): see DESIGN.md section 3.
//!
//! Columns: 0..12 state S | 12..20 R (word absorbed by the next group) | 20 m | 21 accD | 22 accV |
//!          23..27 bd (4 bits of d) | 27..31 bv (4 bits of v) | 31 cnt | 32 sum.
//! For every record word w (v = w[4], b = w[5]) the circuit checks v < 2^32 and the predicate bit m
//! (m = 1 iff v >= theta) by decomposing d = m*(v-theta) + (1-m)*(theta-1-v) into 32 bits, 4 bits per row.

use crate::chain::{chain_periodic, fill_chain, C_R, C_S};
use crate::data::{cap_init, pow2_len, Workload};
use crate::prove::{default_options, prove_trace, verify_proof};
use crate::rescue::{round_constraints, F, GROUP, W};
use winterfell::{
    math::{FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, Proof, ProofOptions, TraceInfo, TraceTable,
    TransitionConstraintDegree,
};

pub const WIDTH: usize = 33;
const C_M: usize = 20;
const C_ACCD: usize = 21;
const C_ACCV: usize = 22;
const C_BD: usize = 23;
const C_BV: usize = 27;
const C_CNT: usize = 31;
const C_SUM: usize = 32;

#[derive(Clone, Debug)]
pub struct ExecPublic {
    /// commitment to the stream (headers + records), computed by the log side
    pub digest: [F; 4],
    pub n_blocks: usize,
    pub block_size: usize,
    /// predicate parameter: match iff v >= theta (public in this prototype, theta < 2^32)
    pub theta: u64,
    /// claimed result
    pub count: u64,
    pub sum: u64,
    /// execution context C_Q; bound only through the Fiat-Shamir transcript, see DESIGN.md
    pub ctx: [F; 4],
}

impl ExecPublic {
    pub fn n_groups(&self) -> usize {
        self.n_blocks * (self.block_size + 1)
    }
}

impl ToElements<F> for ExecPublic {
    fn to_elements(&self) -> Vec<F> {
        let mut v = self.digest.to_vec();
        v.push(F::new(self.n_blocks as u64));
        v.push(F::new(self.block_size as u64));
        v.push(F::new(self.theta));
        v.push(F::new(self.count));
        v.push(F::new(self.sum));
        v.extend_from_slice(&self.ctx);
        v
    }
}

pub struct ExecAir {
    context: AirContext<F>,
    p: ExecPublic,
}

#[inline(always)]
fn chunk<E: FieldElement>(b: &[E]) -> E {
    let two = E::ONE + E::ONE;
    let four = two + two;
    let eight = four + four;
    eight * b[0] + four * b[1] + two * b[2] + b[3]
}

impl Air for ExecAir {
    type BaseField = F;
    type PublicInputs = ExecPublic;

    fn new(trace_info: TraceInfo, p: ExecPublic, options: ProofOptions) -> Self {
        assert_eq!(WIDTH, trace_info.width());
        assert!(p.theta < (1u64 << 32), "theta must be below 2^32");
        let c8 = || vec![GROUP];
        let wc = |base| TransitionConstraintDegree::with_cycles(base, c8());
        let mut d = Vec::new();
        for _ in 0..W {
            d.push(wc(7)); // Rescue round
        }
        for _ in 0..W {
            d.push(wc(1)); // link: absorb
        }
        d.push(wc(2)); // header flag boolean
        d.push(wc(2)); // m boolean
        d.push(wc(2)); // header => m = 0
        d.push(wc(3)); // d decomposition
        d.push(wc(2)); // v decomposition
        d.push(wc(1)); // cnt link
        d.push(wc(2)); // sum link
        d.push(wc(1)); // accD reset
        d.push(wc(1)); // accV reset
        d.push(wc(1)); // cnt hold
        d.push(wc(1)); // sum hold
        d.push(wc(1)); // accD update
        d.push(wc(1)); // accV update
        for _ in 0..8 {
            d.push(TransitionConstraintDegree::new(2)); // bits boolean
        }
        // row 0: cap 4 + accD, accV, cnt, sum; last row: digest 4 + cnt + sum
        let n_assert = 4 + 4 + 4 + 2;
        ExecAir { context: AirContext::new(trace_info, d, n_assert, options), p }
    }

    fn evaluate_transition<E: FieldElement + From<F>>(
        &self,
        frame: &EvaluationFrame<E>,
        pv: &[E],
        out: &mut [E],
    ) {
        let cur = frame.current();
        let next = frame.next();
        let (fr, fl) = (pv[0], pv[1]);
        let ark1 = &pv[2..2 + W];
        let ark2 = &pv[2 + W..2 + 2 * W];
        round_constraints(&cur[..W], &next[..W], ark1, ark2, fr, &mut out[..W]);
        for j in 0..4 {
            out[W + j] = fl * (next[j] - cur[j]);
        }
        for j in 0..8 {
            out[W + 4 + j] = fl * (next[4 + j] - cur[4 + j] - cur[C_R + j]);
        }
        let one = E::ONE;
        let sixteen = E::from(F::new(16));
        let theta = E::from(F::new(self.p.theta));
        let r = &cur[C_R..C_R + 8];
        let (v, b, h) = (r[4], r[5], r[7]);
        let m = cur[C_M];
        let dd = m * (v - theta) + (one - m) * (theta - one - v);
        let cd = chunk(&cur[C_BD..C_BD + 4]);
        let cv = chunk(&cur[C_BV..C_BV + 4]);
        let o = 2 * W;
        out[o] = fl * h * (h - one);
        out[o + 1] = fl * m * (m - one);
        out[o + 2] = fl * h * m;
        out[o + 3] = fl * (one - h) * (sixteen * cur[C_ACCD] + cd - dd);
        out[o + 4] = fl * (one - h) * (sixteen * cur[C_ACCV] + cv - v);
        out[o + 5] = fl * (next[C_CNT] - cur[C_CNT] - m);
        out[o + 6] = fl * (next[C_SUM] - cur[C_SUM] - m * b);
        out[o + 7] = fl * next[C_ACCD];
        out[o + 8] = fl * next[C_ACCV];
        out[o + 9] = fr * (next[C_CNT] - cur[C_CNT]);
        out[o + 10] = fr * (next[C_SUM] - cur[C_SUM]);
        out[o + 11] = fr * (next[C_ACCD] - sixteen * cur[C_ACCD] - cd);
        out[o + 12] = fr * (next[C_ACCV] - sixteen * cur[C_ACCV] - cv);
        for i in 0..4 {
            out[o + 13 + i] = cur[C_BD + i] * (cur[C_BD + i] - one);
            out[o + 17 + i] = cur[C_BV + i] * (cur[C_BV + i] - one);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<F>> {
        let n = self.trace_length();
        let mut a = Vec::new();
        let cap = cap_init(self.p.n_groups());
        for j in 0..4 {
            a.push(Assertion::single(C_S + j, 0, cap[j]));
        }
        for c in [C_ACCD, C_ACCV, C_CNT, C_SUM] {
            a.push(Assertion::single(c, 0, F::ZERO));
        }
        let last = self.p.n_groups() * GROUP - 1;
        assert!(last < n);
        for j in 0..4 {
            a.push(Assertion::single(C_S + 4 + j, last, self.p.digest[j]));
        }
        a.push(Assertion::single(C_CNT, last, F::new(self.p.count)));
        a.push(Assertion::single(C_SUM, last, F::new(self.p.sum)));
        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<F>> {
        chain_periodic()
    }

    fn context(&self) -> &AirContext<F> {
        &self.context
    }
}

/// Public input of an honest execution (result computed by the reference code, not by the circuit).
pub fn exec_public(w: &Workload, theta: u64, ctx: [F; 4]) -> ExecPublic {
    let (count, sum) = w.reference_result(theta);
    ExecPublic {
        digest: w.commitment(),
        n_blocks: w.n_blocks,
        block_size: w.block_size,
        theta,
        count,
        sum,
        ctx,
    }
}

pub fn build_exec_trace(w: &Workload, theta: u64) -> TraceTable<F> {
    let n = pow2_len(w.n_groups() * GROUP);
    let mut cols = vec![vec![F::ZERO; n]; WIDTH];
    let words = fill_chain(&mut cols, w, n);
    let ng = n / GROUP;
    let (mut cnt, mut sum) = (0u64, 0u64);
    for k in 0..ng {
        // contribution of word k enters at the link row before group k
        if k > 0 {
            let x = &words[k];
            if x[7] == F::ZERO && x[4].as_int() >= theta {
                cnt += 1;
                sum += x[5].as_int();
            }
        }
        // data for the word absorbed next (k+1)
        let (mut m, mut dval, mut vval) = (0u64, 0u64, 0u64);
        if k + 1 < ng {
            let x = &words[k + 1];
            if x[7] == F::ZERO {
                let v = x[4].as_int();
                vval = v;
                m = (v >= theta) as u64;
                // low 32 bits only: an out-of-range value (not produced by Workload) would fail the check
                dval = if m == 1 { v.wrapping_sub(theta) } else { theta.wrapping_sub(1).wrapping_sub(v) };
            }
        }
        let (mut accd, mut accv) = (0u64, 0u64);
        for r in 0..GROUP {
            let row = k * GROUP + r;
            cols[C_M][row] = F::new(m);
            cols[C_ACCD][row] = F::new(accd);
            cols[C_ACCV][row] = F::new(accv);
            cols[C_CNT][row] = F::new(cnt);
            cols[C_SUM][row] = F::new(sum);
            let (mut cd, mut cv) = (0u64, 0u64);
            for i in 0..4 {
                let sh = 31 - 4 * r - i;
                let bd = (dval >> sh) & 1;
                let bv = (vval >> sh) & 1;
                cols[C_BD + i][row] = F::new(bd);
                cols[C_BV + i][row] = F::new(bv);
                cd = 2 * cd + bd;
                cv = 2 * cv + bv;
            }
            accd = 16 * accd + cd;
            accv = 16 * accv + cv;
        }
    }
    TraceTable::init(cols)
}

pub fn prove_exec_with(
    w: &Workload,
    theta: u64,
    ctx: [F; 4],
    options: ProofOptions,
) -> Result<(Proof, ExecPublic), String> {
    let p = exec_public(w, theta, ctx);
    let trace = build_exec_trace(w, theta);
    let proof = prove_trace::<ExecAir>(trace, p.clone(), options)?;
    Ok((proof, p))
}

/// Honest prover with the crate's default options.
pub fn prove_exec(w: &Workload, theta: u64, ctx: [F; 4]) -> Result<(Proof, ExecPublic), String> {
    prove_exec_with(w, theta, ctx, default_options())
}

/// Verifier; `min_bits` = least conjectured security (library estimate) the verifier accepts.
pub fn verify_exec(proof: Proof, p: ExecPublic, min_bits: u32) -> Result<(), String> {
    verify_proof::<ExecAir>(proof, p, min_bits)
}
