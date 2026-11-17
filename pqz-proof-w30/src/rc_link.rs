//! w29 (NEW file): R_RC over LINKED chunks. See `journal2/UPGRADE-w29-plan.md` section 1 ("Linking").
//!
//! `RcChunkAir` is the AIR of `rc.rs` (same 26 columns, same transition constraints, same periodic columns, same degrees; the
//! evaluation function is a copy of `RcAir::evaluate_transition`) for ONE chunk of whole blocks. Only the boundary
//! assertions differ:
//!
//!   row 0, chunk 0   : exactly as rc.rs today: capacity = cap_init(total word count), rate = hdr_first (= header0),
//!                      K = (hdr_first[3], hdr_first[0], hdr_first[4] - 1), cnt = 0, mb = block_size, hdr = 1.
//!   row 0, chunk i>0 : capacity = s_in[0..4], rate = s_in[4..12] + hdr_first, K = (hdr_first[3], hdr_first[0], hdr_first[4] - 1),
//!                      cnt = 0, mb = block_size, hdr = hdr_before + 1 (the same updates the single trace performs on a header).
//!   last real row (n_blocks_chunk * (block_size + 1) * 8 - 1):
//!                      cnt = block_size, mb = block_size, hdr = hdr_before + n_blocks_chunk;
//!                      S = s_out (all 12) if not last, S[4..8] = digest if last.
//!
//! The verifier checks (`verify_rc_chunked`, `chain_link::check_links`) replace the constraints of the single trace that fire on
//! the link rows between chunks.

use crate::chain::{chain_periodic, C_S};
use crate::chain_link::{check_links, check_same_options, fill_chain_from, initial_state, reference_chunks, ChunkRef, LinkView, State};
use crate::data::{cap_init, pow2_len, Word, Workload};
use crate::prove::{prove_trace, verify_proof};
use crate::rescue::{round_constraints, F, GROUP, W};
use winterfell::{
    math::{FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, Proof, ProofOptions, TraceInfo, TraceTable,
    TransitionConstraintDegree,
};

pub const WIDTH: usize = 26;
const C_R: usize = 12;
const C_K: usize = 20; // carried (pid, e, seq)
const C_CNT: usize = 23;
const C_MB: usize = 24;
const C_HDR: usize = 25;

#[derive(Clone, Debug)]
pub struct RcChunkPublic {
    /// word count of the WHOLE stream, n_blocks * (block_size + 1)
    pub total_groups: usize,
    pub chunk_index: usize,
    pub n_blocks_chunk: usize,
    pub block_size: usize,
    /// number of real block headers before this chunk (sum of n_blocks_chunk of the earlier chunks)
    pub hdr_before: usize,
    /// sponge state before the first word of the chunk is absorbed (None for chunk 0)
    pub s_in: Option<State>,
    /// header word of the first block of the chunk (chunk 0: header0)
    pub hdr_first: Word,
    /// sponge state after the last word (last chunk: only elements 4..8 = digest are used, the rest must be 0)
    pub s_out: State,
    pub is_last: bool,
}

impl RcChunkPublic {
    pub fn n_groups(&self) -> usize {
        self.n_blocks_chunk * (self.block_size + 1)
    }
}

impl ToElements<F> for RcChunkPublic {
    fn to_elements(&self) -> Vec<F> {
        let mut v = vec![
            F::new(self.total_groups as u64),
            F::new(self.chunk_index as u64),
            F::new(self.n_blocks_chunk as u64),
            F::new(self.block_size as u64),
            F::new(self.hdr_before as u64),
            F::new(self.s_in.is_some() as u64),
        ];
        v.extend_from_slice(&self.s_in.unwrap_or([F::ZERO; W]));
        v.extend_from_slice(&self.hdr_first);
        v.extend_from_slice(&self.s_out);
        v.push(F::new(self.is_last as u64));
        v
    }
}

pub struct RcChunkAir {
    context: AirContext<F>,
    p: RcChunkPublic,
}

fn n_assertions(p: &RcChunkPublic) -> usize {
    // row 0: capacity 4 + rate 8 + K 3 + (cnt, mb, hdr) 3; last row: 12 or 4 state elements + (cnt, mb, hdr) 3
    4 + 8 + 3 + 3 + if p.is_last { 4 } else { 12 } + 3
}

impl Air for RcChunkAir {
    type BaseField = F;
    type PublicInputs = RcChunkPublic;

    fn new(trace_info: TraceInfo, p: RcChunkPublic, options: ProofOptions) -> Self {
        assert_eq!(WIDTH, trace_info.width());
        assert!(p.n_blocks_chunk > 0 && p.block_size > 0, "empty chunk");
        assert_eq!(p.s_in.is_some(), p.chunk_index > 0, "s_in is present exactly for chunk_index > 0");
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
        let n_assert = n_assertions(&p);
        RcChunkAir { context: AirContext::new(trace_info, d, n_assert, options), p }
    }

    // identical to RcAir::evaluate_transition (rc.rs)
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
        let r = &cur[C_R..C_R + 8];
        let f = r[7];
        let one = E::ONE;
        let k = &cur[C_K..C_K + 3];
        let base = 2 * W;
        out[base] = fl * f * (f - one);
        out[base + 1] = fl * (one - f) * (r[0] - k[0]);
        out[base + 2] = fl * (one - f) * (r[1] - k[1]);
        out[base + 3] = fl * (one - f) * (r[2] - k[2] - one);
        out[base + 4] = fl * (next[C_K] - (f * r[3] + (one - f) * k[0]));
        out[base + 5] = fl * (next[C_K + 1] - (f * r[0] + (one - f) * k[1]));
        out[base + 6] = fl * (next[C_K + 2] - (f * (r[4] - one) + (one - f) * r[2]));
        for i in 0..3 {
            out[base + 7 + i] = fr * (next[C_K + i] - cur[C_K + i]);
        }
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
        let p = &self.p;
        let n = self.trace_length();
        let mut a = Vec::new();
        let bs = F::new(p.block_size as u64);
        assert_eq!(p.hdr_first[2], bs, "hdr_first must announce block_size records");
        let (cap, rate_in) = match &p.s_in {
            None => (cap_init(p.total_groups), [F::ZERO; 8]),
            Some(s) => ([s[0], s[1], s[2], s[3]], [s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11]]),
        };
        for j in 0..4 {
            a.push(Assertion::single(C_S + j, 0, cap[j]));
        }
        for j in 0..8 {
            a.push(Assertion::single(C_S + 4 + j, 0, rate_in[j] + p.hdr_first[j]));
        }
        let h = &p.hdr_first;
        a.push(Assertion::single(C_K, 0, h[3]));
        a.push(Assertion::single(C_K + 1, 0, h[0]));
        a.push(Assertion::single(C_K + 2, 0, h[4] - F::ONE));
        a.push(Assertion::single(C_CNT, 0, F::ZERO));
        a.push(Assertion::single(C_MB, 0, bs));
        a.push(Assertion::single(C_HDR, 0, F::new(p.hdr_before as u64 + 1)));
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
        a.push(Assertion::single(C_CNT, last, bs));
        a.push(Assertion::single(C_MB, last, bs));
        a.push(Assertion::single(C_HDR, last, F::new((p.hdr_before + p.n_blocks_chunk) as u64)));
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

/// Trace of one chunk (copy of `rc::build_rc_trace` with the start values as parameters; the original is tied to a whole
/// `Workload`). `start` = sponge state before `words[0]` is absorbed; `hdr_before` = real headers before the chunk.
pub fn build_rc_chunk_trace(words: &[Word], start: State, block_size: usize, hdr_before: usize) -> TraceTable<F> {
    let n = pow2_len(words.len() * GROUP);
    let mut cols = vec![vec![F::ZERO; n]; WIDTH];
    let words = fill_chain_from(&mut cols, words, n, start);
    let h = words[0];
    let mut k = [h[3], h[0], h[4] - F::ONE];
    let bs = F::new(block_size as u64);
    let (mut cnt, mut mb, mut hdr) = (F::ZERO, h[2], F::new(hdr_before as u64 + 1));
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

#[derive(Clone, Debug)]
pub struct RcChunkInstance {
    pub public: RcChunkPublic,
    pub words: Vec<Word>,
    pub start: State,
}

impl RcChunkInstance {
    pub fn build_trace(&self) -> TraceTable<F> {
        build_rc_chunk_trace(&self.words, self.start, self.public.block_size, self.public.hdr_before)
    }
    pub fn prove_trace(&self, trace: TraceTable<F>, options: ProofOptions) -> Result<Proof, String> {
        prove_trace::<RcChunkAir>(trace, self.public.clone(), options)
    }
    pub fn prove(&self, options: ProofOptions) -> Result<Proof, String> {
        self.prove_trace(self.build_trace(), options)
    }
}

fn public_from_ref(r: &ChunkRef, total_groups: usize, block_size: usize) -> RcChunkPublic {
    let mut s_out = r.s_out;
    if r.is_last {
        s_out = [F::ZERO; W];
        s_out[4..8].copy_from_slice(&r.s_out[4..8]);
    }
    RcChunkPublic {
        total_groups,
        chunk_index: r.chunk_index,
        n_blocks_chunk: r.n_blocks,
        block_size,
        hdr_before: r.hdr_before,
        s_in: r.s_in,
        hdr_first: r.hdr_first,
        s_out,
        is_last: r.is_last,
    }
}

/// Instances of an honest split; public values from the reference sponge (`rescue::perm`), not from a trace.
pub fn rc_chunk_instances(w: &Workload, split: &[usize]) -> Vec<RcChunkInstance> {
    let total = w.n_groups();
    // theta is irrelevant for R_RC; 0 only feeds the (unused) count/sum of the shared reference routine
    reference_chunks(w, 0, split)
        .iter()
        .map(|r| RcChunkInstance {
            public: public_from_ref(r, total, w.block_size),
            words: w.words[r.first_word..r.first_word + r.n_words].to_vec(),
            start: r.s_in.unwrap_or_else(|| initial_state(total)),
        })
        .collect()
}

pub fn prove_rc_chunked(w: &Workload, options: ProofOptions, split: &[usize]) -> Result<Vec<(Proof, RcChunkPublic)>, String> {
    rc_chunk_instances(w, split)
        .into_iter()
        .map(|inst| {
            let proof = inst.prove(options.clone())?;
            Ok((proof, inst.public))
        })
        .collect()
}

/// Verifier of a chunked R_RC. `digest`, `n_blocks`, `block_size`, `header0` are the verifier's statement (as `RcPublic`); the
/// chunk public inputs are taken as given. Checks: `chain_link::check_links` (chunk_index, total_groups, sum of n_blocks_chunk =
/// n_blocks, S_out_i = S_in_{i+1}, hdr_first flag 1 and m_b = block_size, is_last, digest of the last chunk = D), plus
/// hdr_before_i = sum of the earlier n_blocks_chunk, hdr_first of chunk 0 = header0, same proof options; then every proof.
pub fn verify_rc_chunked(
    proofs: Vec<(Proof, RcChunkPublic)>,
    digest: [F; 4],
    n_blocks: usize,
    block_size: usize,
    header0: Word,
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
    if proofs[0].1.hdr_first != header0 {
        return Err("link: hdr_first of chunk 0 != header0".into());
    }
    let mut before = 0usize;
    for (i, (_, p)) in proofs.iter().enumerate() {
        if p.hdr_before != before {
            return Err(format!("link: chunk {i} hdr_before {} != sum of earlier n_blocks_chunk {before}", p.hdr_before));
        }
        before += p.n_blocks_chunk;
    }
    {
        let refs: Vec<&Proof> = proofs.iter().map(|(pr, _)| pr).collect();
        check_same_options(&refs)?;
    }
    for (i, (proof, p)) in proofs.into_iter().enumerate() {
        verify_proof::<RcChunkAir>(proof, p).map_err(|e| format!("chunk {i}: {e}"))?;
    }
    Ok(())
}
