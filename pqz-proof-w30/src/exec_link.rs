//! w29 (NEW file): R_Exec over LINKED chunks. See `journal2/UPGRADE-w29-plan.md` section 1 ("Linking").
//!
//! `ExecChunkAir` is the AIR of `exec.rs` (same 33 columns, same transition constraints, same periodic columns, same
//! degrees; the evaluation function is a copy of `ExecAir::evaluate_transition`) for ONE chunk of whole blocks. Only the boundary
//! assertions differ, because the chunk starts from a PUBLIC sponge state and ends in a PUBLIC state:
//!
//!   row 0, chunk 0   : capacity = cap_init(TOTAL word count of the stream); nothing on the rate (as in exec.rs today).
//!   row 0, chunk i>0 : capacity = s_in[0..4];  rate S[4..12] = s_in[4..12] + hdr_first (the first word of the chunk is a block
//!                      header, absorbed by the AIR from public values; this replaces the absorb link of the single trace).
//!   row 0, always    : accD = accV = 0, cnt = cnt_in, sum = sum_in.
//!   last real row (n_blocks_chunk * (block_size + 1) * 8 - 1):
//!                      not last chunk: full state S[0..12] = s_out; last chunk: S[4..8] = digest (as in exec.rs);
//!                      cnt = cnt_out, sum = sum_out.
//!
//! What the verifier must check outside the AIR is in `verify_exec_chunked` (and `chain_link::check_links`).

use crate::chain::{chain_periodic, C_S};
use crate::chain_link::{check_links, check_same_options, fill_chain_from, initial_state, reference_chunks, ChunkRef, LinkView, State, MAX_ACC};
use crate::data::{cap_init, pow2_len, Word, Workload};
use crate::prove::{prove_trace, verify_proof};
use crate::rescue::{round_constraints, F, GROUP, W};
use winterfell::{
    math::{FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, Proof, ProofOptions, TraceInfo, TraceTable,
    TransitionConstraintDegree,
};

pub const WIDTH: usize = 33;
const C_R: usize = 12;
const C_M: usize = 20;
const C_ACCD: usize = 21;
const C_ACCV: usize = 22;
const C_BD: usize = 23;
const C_BV: usize = 27;
const C_CNT: usize = 31;
const C_SUM: usize = 32;

/// Public input of one chunk. Every field is in `to_elements`, hence in the Fiat-Shamir transcript.
#[derive(Clone, Debug)]
pub struct ExecChunkPublic {
    /// word count of the WHOLE stream, n_blocks * (block_size + 1) (capacity of the sponge of chunk 0)
    pub total_groups: usize,
    pub chunk_index: usize,
    pub n_blocks_chunk: usize,
    pub block_size: usize,
    /// predicate parameter: match iff v >= theta (theta < 2^32)
    pub theta: u64,
    /// execution context, bound only through the transcript (as in exec.rs)
    pub ctx: [F; 4],
    /// sponge state before the first word of the chunk is absorbed (None for chunk 0)
    pub s_in: Option<State>,
    /// the header word of the first block of the chunk
    pub hdr_first: Word,
    pub cnt_in: u64,
    pub sum_in: u64,
    /// sponge state after the last word of the chunk (last chunk: only elements 4..8 = digest are used, the rest must be 0)
    pub s_out: State,
    pub cnt_out: u64,
    pub sum_out: u64,
    pub is_last: bool,
}

impl ExecChunkPublic {
    /// number of real words (= permutations) of this chunk
    pub fn n_groups(&self) -> usize {
        self.n_blocks_chunk * (self.block_size + 1)
    }
}

impl ToElements<F> for ExecChunkPublic {
    fn to_elements(&self) -> Vec<F> {
        let mut v = vec![
            F::new(self.total_groups as u64),
            F::new(self.chunk_index as u64),
            F::new(self.n_blocks_chunk as u64),
            F::new(self.block_size as u64),
            F::new(self.theta),
        ];
        v.extend_from_slice(&self.ctx);
        v.push(F::new(self.s_in.is_some() as u64));
        v.extend_from_slice(&self.s_in.unwrap_or([F::ZERO; W]));
        v.extend_from_slice(&self.hdr_first);
        v.push(F::new(self.cnt_in));
        v.push(F::new(self.sum_in));
        v.extend_from_slice(&self.s_out);
        v.push(F::new(self.cnt_out));
        v.push(F::new(self.sum_out));
        v.push(F::new(self.is_last as u64));
        v
    }
}

pub struct ExecChunkAir {
    context: AirContext<F>,
    p: ExecChunkPublic,
}

#[inline(always)]
fn chunk4<E: FieldElement>(b: &[E]) -> E {
    let two = E::ONE + E::ONE;
    let four = two + two;
    let eight = four + four;
    eight * b[0] + four * b[1] + two * b[2] + b[3]
}

fn n_assertions(p: &ExecChunkPublic) -> usize {
    // row 0: capacity 4 (+ rate 8 for chunk > 0) + accD, accV, cnt, sum; last row: 12 or 4 state elements + cnt + sum
    4 + if p.s_in.is_some() { 8 } else { 0 } + 4 + if p.is_last { 4 } else { 12 } + 2
}

impl Air for ExecChunkAir {
    type BaseField = F;
    type PublicInputs = ExecChunkPublic;

    fn new(trace_info: TraceInfo, p: ExecChunkPublic, options: ProofOptions) -> Self {
        assert_eq!(WIDTH, trace_info.width());
        assert!(p.theta < (1u64 << 32), "theta must be below 2^32");
        assert!(p.n_blocks_chunk > 0 && p.block_size > 0, "empty chunk");
        assert_eq!(p.s_in.is_some(), p.chunk_index > 0, "s_in is present exactly for chunk_index > 0");
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
        let n_assert = n_assertions(&p);
        ExecChunkAir { context: AirContext::new(trace_info, d, n_assert, options), p }
    }

    // identical to ExecAir::evaluate_transition (exec.rs)
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
        let cd = chunk4(&cur[C_BD..C_BD + 4]);
        let cv = chunk4(&cur[C_BV..C_BV + 4]);
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
        let p = &self.p;
        let n = self.trace_length();
        let mut a = Vec::new();
        // row 0
        let cap = match &p.s_in {
            None => cap_init(p.total_groups),
            Some(s) => [s[0], s[1], s[2], s[3]],
        };
        for j in 0..4 {
            a.push(Assertion::single(C_S + j, 0, cap[j]));
        }
        if let Some(s) = &p.s_in {
            for j in 0..8 {
                a.push(Assertion::single(C_S + 4 + j, 0, s[4 + j] + p.hdr_first[j]));
            }
        }
        a.push(Assertion::single(C_ACCD, 0, F::ZERO));
        a.push(Assertion::single(C_ACCV, 0, F::ZERO));
        a.push(Assertion::single(C_CNT, 0, F::new(p.cnt_in)));
        a.push(Assertion::single(C_SUM, 0, F::new(p.sum_in)));
        // last real row
        let last = p.n_groups() * GROUP - 1;
        assert!(last < n);
        if p.is_last {
            for j in 0..4 {
                a.push(Assertion::single(C_S + 4 + j, last, p.s_out[4 + j]));
            }
        } else {
            for j in 0..W {
                a.push(Assertion::single(C_S + j, last, p.s_out[j]));
            }
        }
        a.push(Assertion::single(C_CNT, last, F::new(p.cnt_out)));
        a.push(Assertion::single(C_SUM, last, F::new(p.sum_out)));
        debug_assert_eq!(a.len(), n_assertions(p));
        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<F>> {
        chain_periodic()
    }

    fn context(&self) -> &AirContext<F> {
        &self.context
    }
}

/// Trace of one chunk: `words` are the chunk's words (a whole number of blocks), `start` the sponge state before `words[0]` is
/// absorbed, (`cnt_in`, `sum_in`) the accumulators before the chunk. The loop is a copy of `exec::build_exec_trace` with the
/// start values as parameters (the original is tied to a whole `Workload`). Padding words after the chunk are `pad_word()`.
pub fn build_exec_chunk_trace(words: &[Word], start: State, cnt_in: u64, sum_in: u64, theta: u64) -> TraceTable<F> {
    let n = pow2_len(words.len() * GROUP);
    let mut cols = vec![vec![F::ZERO; n]; WIDTH];
    let words = fill_chain_from(&mut cols, words, n, start);
    let ng = n / GROUP;
    let (mut cnt, mut sum) = (cnt_in, sum_in);
    for k in 0..ng {
        // contribution of word k enters at the link row before group k (word 0 is a header: no contribution)
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

/// One chunk of an honest split: public input, the chunk's words and the sponge state it starts from.
#[derive(Clone, Debug)]
pub struct ExecChunkInstance {
    pub public: ExecChunkPublic,
    pub words: Vec<Word>,
    pub start: State,
}

impl ExecChunkInstance {
    pub fn build_trace(&self) -> TraceTable<F> {
        build_exec_chunk_trace(&self.words, self.start, self.public.cnt_in, self.public.sum_in, self.public.theta)
    }
    pub fn prove_trace(&self, trace: TraceTable<F>, options: ProofOptions) -> Result<Proof, String> {
        prove_trace::<ExecChunkAir>(trace, self.public.clone(), options)
    }
    pub fn prove(&self, options: ProofOptions) -> Result<Proof, String> {
        self.prove_trace(self.build_trace(), options)
    }
}

fn public_from_ref(r: &ChunkRef, total_groups: usize, block_size: usize, theta: u64, ctx: [F; 4]) -> ExecChunkPublic {
    let mut s_out = r.s_out;
    if r.is_last {
        // only the digest (elements 4..8) is public for the last chunk
        s_out = [F::ZERO; W];
        s_out[4..8].copy_from_slice(&r.s_out[4..8]);
    }
    ExecChunkPublic {
        total_groups,
        chunk_index: r.chunk_index,
        n_blocks_chunk: r.n_blocks,
        block_size,
        theta,
        ctx,
        s_in: r.s_in,
        hdr_first: r.hdr_first,
        cnt_in: r.cnt_in,
        sum_in: r.sum_in,
        s_out,
        cnt_out: r.cnt_out,
        sum_out: r.sum_out,
        is_last: r.is_last,
    }
}

/// Instances of an honest split. All public values come from the reference sponge (`rescue::perm`) and the reference
/// predicate rule, not from a trace.
pub fn exec_chunk_instances(w: &Workload, theta: u64, ctx: [F; 4], split: &[usize]) -> Vec<ExecChunkInstance> {
    let total = w.n_groups();
    reference_chunks(w, theta, split)
        .iter()
        .map(|r| ExecChunkInstance {
            public: public_from_ref(r, total, w.block_size, theta, ctx),
            words: w.words[r.first_word..r.first_word + r.n_words].to_vec(),
            start: r.s_in.unwrap_or_else(|| initial_state(total)),
        })
        .collect()
}

/// Honest prover: one proof per chunk, proved one after the other. `split` = blocks per chunk (e.g. `split::plan_split`).
pub fn prove_exec_chunked(
    w: &Workload,
    theta: u64,
    ctx: [F; 4],
    options: ProofOptions,
    split: &[usize],
) -> Result<Vec<(Proof, ExecChunkPublic)>, String> {
    exec_chunk_instances(w, theta, ctx, split)
        .into_iter()
        .map(|inst| {
            let proof = inst.prove(options.clone())?;
            Ok((proof, inst.public))
        })
        .collect()
}

/// Verifier of a chunked R_Exec. `digest`, `n_blocks`, `block_size`, `theta`, `ctx`, `claimed_count`, `claimed_sum` are the
/// verifier's statement; the chunk public inputs are taken as given (not recomputed from any workload) and checked against it:
///   * the common chain checks of `chain_link::check_links` (chunk_index 0..k-1, total_groups, sum of n_blocks_chunk = n_blocks,
///     S_out_i = S_in_{i+1}, hdr_first flag 1 and m_b = block_size, is_last, digest of the last chunk = D);
///   * theta and ctx equal to the statement in every chunk; theta < 2^32;
///   * cnt_in_0 = sum_in_0 = 0; cnt_out_i = cnt_in_{i+1}, sum_out_i = sum_in_{i+1}; last (cnt_out, sum_out) = claimed;
///   * all values below p (no aliasing), all proofs with the same options;
/// then every chunk proof is verified (strict: only `default_options()`, see `prove::verify_proof`).
#[allow(clippy::too_many_arguments)]
pub fn verify_exec_chunked(
    proofs: Vec<(Proof, ExecChunkPublic)>,
    digest: [F; 4],
    n_blocks: usize,
    block_size: usize,
    theta: u64,
    ctx: [F; 4],
    claimed_count: u64,
    claimed_sum: u64,
) -> Result<(), String> {
    {
        let views: Vec<LinkView> = proofs
            .iter()
            .map(|(_, p)| LinkView {
                chunk_index: p.chunk_index,
                total_groups: p.total_groups,
                n_blocks_chunk: p.n_blocks_chunk,
                block_size: p.block_size,
                s_in: &p.s_in,
                hdr_first: &p.hdr_first,
                s_out: &p.s_out,
                is_last: p.is_last,
            })
            .collect();
        check_links(&views, n_blocks, block_size, &digest)?;
    }
    if theta >= (1u64 << 32) {
        return Err("link: theta must be below 2^32".into());
    }
    for (i, (_, p)) in proofs.iter().enumerate() {
        if p.theta != theta {
            return Err(format!("link: chunk {i} theta differs from the statement"));
        }
        if p.ctx != ctx {
            return Err(format!("link: chunk {i} ctx differs from the statement"));
        }
        if [p.cnt_in, p.sum_in, p.cnt_out, p.sum_out].iter().any(|&x| x > MAX_ACC) {
            return Err(format!("link: chunk {i} count/sum not below p"));
        }
    }
    let k = proofs.len();
    if proofs[0].1.cnt_in != 0 || proofs[0].1.sum_in != 0 {
        return Err("link: cnt_in and sum_in of chunk 0 must be 0".into());
    }
    for i in 0..k - 1 {
        if proofs[i].1.cnt_out != proofs[i + 1].1.cnt_in {
            return Err(format!("link: cnt_out of chunk {i} != cnt_in of chunk {}", i + 1));
        }
        if proofs[i].1.sum_out != proofs[i + 1].1.sum_in {
            return Err(format!("link: sum_out of chunk {i} != sum_in of chunk {}", i + 1));
        }
    }
    if proofs[k - 1].1.cnt_out != claimed_count || proofs[k - 1].1.sum_out != claimed_sum {
        return Err("link: final count/sum differ from the claimed result".into());
    }
    {
        let refs: Vec<&Proof> = proofs.iter().map(|(pr, _)| pr).collect();
        check_same_options(&refs)?;
    }
    for (i, (proof, p)) in proofs.into_iter().enumerate() {
        verify_proof::<ExecChunkAir>(proof, p).map_err(|e| format!("chunk {i}: {e}"))?;
    }
    Ok(())
}
