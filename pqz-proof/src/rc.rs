//! R_RC (batched record commitment): see DESIGN.md section 1.

use crate::chain::{chain_periodic, fill_chain, C_R, C_S};
use crate::data::{cap_init, pow2_len, Word, Workload};
use crate::prove::{default_options, prove_trace, verify_proof};
use crate::rescue::{round_constraints, F, GROUP, W};
use winterfell::{
    math::{FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, Proof, ProofOptions, TraceInfo, TraceTable,
    TransitionConstraintDegree,
};

pub const WIDTH: usize = 26;
const C_K: usize = 20; // carried (pid, e, seq)
const C_CNT: usize = 23; // records since the last header
const C_MB: usize = 24; // record count claimed by the current header (block_size, or 0 for padding)
const C_HDR: usize = 25; // number of real headers so far

#[derive(Clone, Debug)]
pub struct RcPublic {
    pub digest: [F; 4],
    pub n_blocks: usize,
    pub block_size: usize,
    pub header0: Word,
}

impl RcPublic {
    pub fn n_groups(&self) -> usize {
        self.n_blocks * (self.block_size + 1)
    }
}

impl ToElements<F> for RcPublic {
    fn to_elements(&self) -> Vec<F> {
        let mut v = self.digest.to_vec();
        v.push(F::new(self.n_blocks as u64));
        v.push(F::new(self.block_size as u64));
        v.extend_from_slice(&self.header0);
        v
    }
}

pub struct RcAir {
    context: AirContext<F>,
    p: RcPublic,
}

impl Air for RcAir {
    type BaseField = F;
    type PublicInputs = RcPublic;

    fn new(trace_info: TraceInfo, p: RcPublic, options: ProofOptions) -> Self {
        assert_eq!(WIDTH, trace_info.width());
        let c8 = || vec![GROUP];
        let mut d = Vec::new();
        for _ in 0..W {
            d.push(TransitionConstraintDegree::with_cycles(7, c8()));
        }
        for _ in 0..W {
            d.push(TransitionConstraintDegree::with_cycles(1, c8())); // link: absorb
        }
        for _ in 0..7 {
            d.push(TransitionConstraintDegree::with_cycles(2, c8())); // flag bool, 3 record checks, 3 K updates
        }
        for _ in 0..3 {
            d.push(TransitionConstraintDegree::with_cycles(1, c8())); // K hold
        }
        d.push(TransitionConstraintDegree::with_cycles(3, c8())); // header m_b in {0, block_size}
        d.push(TransitionConstraintDegree::with_cycles(2, c8())); // block closes with cnt == mb
        d.push(TransitionConstraintDegree::with_cycles(2, c8())); // cnt update
        d.push(TransitionConstraintDegree::with_cycles(2, c8())); // mb update
        d.push(TransitionConstraintDegree::with_cycles(2, c8())); // hdr update
        for _ in 0..3 {
            d.push(TransitionConstraintDegree::with_cycles(1, c8())); // cnt, mb, hdr hold
        }
        // cap 4 + header0 rate 8 + K0 3 + final digest 4 + (cnt, mb, hdr) at row 0 and at the last row
        let n_assert = 4 + 8 + 3 + 4 + 6;
        RcAir { context: AirContext::new(trace_info, d, n_assert, options), p }
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
        // link: capacity kept, rate += R
        for j in 0..4 {
            out[W + j] = fl * (next[j] - cur[j]);
        }
        for j in 0..8 {
            out[W + 4 + j] = fl * (next[4 + j] - cur[4 + j] - cur[C_R + j]);
        }
        let r = &cur[C_R..C_R + 8];
        let f = r[7]; // header flag of the word absorbed next
        let one = E::ONE;
        let k = &cur[C_K..C_K + 3];
        let base = 2 * W;
        out[base] = fl * f * (f - one);
        out[base + 1] = fl * (one - f) * (r[0] - k[0]); // record pid == header pid
        out[base + 2] = fl * (one - f) * (r[1] - k[1]); // record epoch == header epoch
        out[base + 3] = fl * (one - f) * (r[2] - k[2] - one); // seq = previous seq + 1
        out[base + 4] = fl * (next[C_K] - (f * r[3] + (one - f) * k[0]));
        out[base + 5] = fl * (next[C_K + 1] - (f * r[0] + (one - f) * k[1]));
        out[base + 6] = fl * (next[C_K + 2] - (f * (r[4] - one) + (one - f) * r[2]));
        for i in 0..3 {
            out[base + 7 + i] = fr * (next[C_K + i] - cur[C_K + i]);
        }
        // block structure: every real header announces block_size records (padding announces 0); a header may
        // only follow a block that has exactly mb records; the number of real headers is counted
        let bs = E::from(F::new(self.p.block_size as u64));
        let inv_bs = E::from(F::new(self.p.block_size as u64).inv());
        let nb = base + 10;
        let (cnt, mb, hdr) = (cur[C_CNT], cur[C_MB], cur[C_HDR]);
        out[nb] = fl * f * r[2] * (r[2] - bs);
        out[nb + 1] = fl * f * (cnt - mb);
        out[nb + 2] = fl * (next[C_CNT] - (one - f) * (cnt + one));
        out[nb + 3] = fl * (next[C_MB] - (f * r[2] + (one - f) * mb));
        out[nb + 4] = fl * (next[C_HDR] - hdr - f * r[2] * inv_bs);
        out[nb + 5] = fr * (next[C_CNT] - cnt);
        out[nb + 6] = fr * (next[C_MB] - mb);
        out[nb + 7] = fr * (next[C_HDR] - hdr);
    }

    fn get_assertions(&self) -> Vec<Assertion<F>> {
        let n = self.trace_length();
        let mut a = Vec::new();
        let cap = cap_init(self.p.n_groups());
        for j in 0..4 {
            a.push(Assertion::single(C_S + j, 0, cap[j]));
        }
        for j in 0..8 {
            a.push(Assertion::single(C_S + 4 + j, 0, self.p.header0[j]));
        }
        let h = &self.p.header0;
        a.push(Assertion::single(C_K, 0, h[3]));
        a.push(Assertion::single(C_K + 1, 0, h[0]));
        a.push(Assertion::single(C_K + 2, 0, h[4] - F::ONE));
        let last = self.p.n_groups() * GROUP - 1;
        assert!(last < n);
        for j in 0..4 {
            a.push(Assertion::single(C_S + 4 + j, last, self.p.digest[j]));
        }
        let bs = F::new(self.p.block_size as u64);
        assert_eq!(self.p.header0[2], bs, "header0 must announce block_size records");
        a.push(Assertion::single(C_CNT, 0, F::ZERO));
        a.push(Assertion::single(C_MB, 0, bs));
        a.push(Assertion::single(C_HDR, 0, F::ONE));
        a.push(Assertion::single(C_CNT, last, bs));
        a.push(Assertion::single(C_MB, last, bs));
        a.push(Assertion::single(C_HDR, last, F::new(self.p.n_blocks as u64)));
        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<F>> {
        chain_periodic()
    }

    fn context(&self) -> &AirContext<F> {
        &self.context
    }
}

pub fn rc_public(w: &Workload) -> RcPublic {
    RcPublic {
        digest: w.commitment(),
        n_blocks: w.n_blocks,
        block_size: w.block_size,
        header0: w.header0(),
    }
}

pub fn build_rc_trace(w: &Workload) -> TraceTable<F> {
    let n = pow2_len(w.n_groups() * GROUP);
    let mut cols = vec![vec![F::ZERO; n]; WIDTH];
    let words = fill_chain(&mut cols, w, n);
    let h = words[0];
    let mut k = [h[3], h[0], h[4] - F::ONE];
    let bs = F::new(w.block_size as u64);
    let (mut cnt, mut mb, mut hdr) = (F::ZERO, h[2], F::ONE);
    for g in 0..n / GROUP {
        let x = words[g];
        if g > 0 {
            if x[7] == F::ONE {
                k = [x[3], x[0], x[4] - F::ONE];
                cnt = F::ZERO;
                mb = x[2];
                hdr += x[2] / bs;
            } else {
                k = [k[0], k[1], x[2]];
                cnt += F::ONE;
            }
        }
        for r in 0..GROUP {
            for i in 0..3 {
                cols[C_K + i][g * GROUP + r] = k[i];
            }
            cols[C_CNT][g * GROUP + r] = cnt;
            cols[C_MB][g * GROUP + r] = mb;
            cols[C_HDR][g * GROUP + r] = hdr;
        }
    }
    TraceTable::init(cols)
}

/// Prove R_RC for a workload (honest prover). Returns proof and public input.
pub fn prove_rc(w: &Workload, options: ProofOptions) -> Result<(Proof, RcPublic), String> {
    let p = rc_public(w);
    let trace = build_rc_trace(w);
    let proof = prove_trace::<RcAir>(trace, p.clone(), options)?;
    Ok((proof, p))
}

pub fn verify_rc(proof: Proof, p: RcPublic, min_bits: u32) -> Result<(), String> {
    verify_proof::<RcAir>(proof, p, min_bits)
}

pub fn options() -> ProofOptions {
    default_options()
}
