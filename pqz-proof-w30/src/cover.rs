//! R_Cover (BlockCover + PruneValid over the block summaries): see DESIGN.md section 7.
//!
//! One block = 16 rows = 2 Rescue permutations of each of two sponges.
//!   sponge 1 (columns 0..12, R1 12..20): words H_1, S_1, H_2, S_2, ... (H_g = [DOM_HDR, g, 0..], S_g = 8 summary words)
//!   sponge 2 (columns 20..32, R2 32..40): words 0, [f_1,0..], 0, [f_2,0..], ...
//! Group 2(g-1) (rows 16(g-1)..+8, "header group") absorbs S_g and [f_g,0..] at its link row; its rows 0..6 are the k = 7 probe rows.
//! Group 2g-1 ("summary group") absorbs H_{g+1} and the zero word.

use crate::chain::chain_periodic;
use crate::data::{chain_digest, pow2_len, Rng, Word};
use crate::prove::{default_options, prove_trace, verify_proof};
use crate::rescue::{perm, perm_states, round_constraints, F, GROUP, W};
use winterfell::{
    math::{FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, Proof, ProofOptions, TraceInfo, TraceTable,
    TransitionConstraintDegree,
};

pub const K: usize = 7; // probed positions per block (fixed in the AIR)
pub const SW: usize = 8; // summary words per block (W of the task text; `rescue::W` is the Rescue state width)
pub const WORD_BITS: usize = 32;
pub const POSITIONS: usize = SW * WORD_BITS; // 256 Bloom bits per block
pub const BLOCK_ROWS: usize = 2 * GROUP; // 16
pub const DOM_HDR: u64 = 0x5051_5a48; // "PQZH"
pub const DOM_FLAGS: u64 = 0x5051_5a46; // "PQZF"

pub const WIDTH: usize = 123;
const C_S1: usize = 0;
const C_R1: usize = 12;
const C_S2: usize = 20;
const C_R2: usize = 32;
const C_P: usize = 40; // 7 probe positions, constant
const C_F: usize = 47; // flag of the current block
const C_C: usize = 48; // retained blocks before this block
const C_CI: usize = 49; // C + F
const C_GG: usize = 50; // block counter
const C_SEL: usize = 51; // 8
const C_OH: usize = 59; // 32
const C_B: usize = 91; // 32
const N_CONSTRAINTS: usize = 161;
const N_ASSERT: usize = 36;

// ---------------------------------------------------------------------------------------------
// Instance (witness) and public input
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct CoverInstance {
    pub g: usize,
    /// summaries[b] = the SW words of block b+1 (each below 2^32)
    pub summaries: Vec<[u64; SW]>,
    /// flags[b] = true if block b+1 is retained
    pub flags: Vec<bool>,
    /// the k probed bit positions (0..POSITIONS), the same for all blocks
    pub positions: [usize; K],
}

impl CoverInstance {
    /// Honest instance: `r` retained blocks spread evenly over the G blocks. Retained blocks have all probed bits set
    /// (a true match); pruned blocks have all probed bits clear; other bits are random with density about 1/4.
    pub fn honest(g: usize, r: usize, seed: u64) -> Self {
        assert!(g >= 1 && r <= g);
        let mut rng = Rng::new(seed);
        let mut positions = [0usize; K];
        let mut i = 0;
        while i < K {
            let p = (rng.next_u64() % POSITIONS as u64) as usize;
            if !positions[..i].contains(&p) {
                positions[i] = p;
                i += 1;
            }
        }
        let flags: Vec<bool> = (0..g).map(|b| ((b + 1) * r) / g > (b * r) / g).collect();
        let mut summaries = Vec::with_capacity(g);
        for b in 0..g {
            let mut s = [0u64; SW];
            for w in s.iter_mut() {
                *w = rng.next_u64() & rng.next_u64() & 0xffff_ffff;
            }
            for &p in &positions {
                let (wi, t) = (p / WORD_BITS, p % WORD_BITS);
                if flags[b] {
                    s[wi] |= 1u64 << t;
                } else {
                    s[wi] &= !(1u64 << t);
                }
            }
            summaries.push(s);
        }
        CoverInstance { g, summaries, flags, positions }
    }
    pub fn retained(&self) -> usize {
        self.flags.iter().filter(|&&f| f).count()
    }
}

#[derive(Clone, Debug)]
pub struct CoverPublic {
    pub d_s: [F; 4],
    pub d_flags: [F; 4],
    pub g: usize,
    pub k: usize,
    pub r: usize,
}

impl ToElements<F> for CoverPublic {
    fn to_elements(&self) -> Vec<F> {
        let mut v = self.d_s.to_vec();
        v.extend_from_slice(&self.d_flags);
        v.push(F::new(self.g as u64));
        v.push(F::new(self.k as u64));
        v.push(F::new(self.r as u64));
        v
    }
}

pub fn header_word(g: u64) -> Word {
    let mut w = [F::ZERO; 8];
    w[0] = F::new(DOM_HDR);
    w[1] = F::new(g);
    w
}

fn summary_word(s: &[u64; SW]) -> Word {
    let mut w = [F::ZERO; 8];
    for j in 0..SW {
        w[j] = F::new(s[j]);
    }
    w
}

/// The 2G words of the summary chain: H_1, S_1, ..., H_G, S_G.
pub fn summary_chain_words(inst: &CoverInstance) -> Vec<Word> {
    let mut v = Vec::with_capacity(2 * inst.g);
    for b in 0..inst.g {
        v.push(header_word(b as u64 + 1));
        v.push(summary_word(&inst.summaries[b]));
    }
    v
}

/// The 2G words of the flag chain: 0, [f_1,0..], ..., 0, [f_G,0..].
pub fn flag_chain_words(flags: &[bool]) -> Vec<Word> {
    let mut v = Vec::with_capacity(2 * flags.len());
    for &f in flags {
        v.push([F::ZERO; 8]);
        let mut w = [F::ZERO; 8];
        w[0] = F::new(f as u64);
        v.push(w);
    }
    v
}

/// Reference flag digest (library permutation, no circuit).
pub fn flag_digest(flags: &[bool]) -> [F; 4] {
    let words = flag_chain_words(flags);
    let mut s = [F::ZERO; W];
    s[0] = F::new(DOM_FLAGS);
    s[1] = F::new(words.len() as u64);
    for w in &words {
        for j in 0..8 {
            s[4 + j] += w[j];
        }
        perm(&mut s);
    }
    [s[4], s[5], s[6], s[7]]
}

pub fn summary_digest(inst: &CoverInstance) -> [F; 4] {
    chain_digest(&summary_chain_words(inst))
}

pub fn cover_public(inst: &CoverInstance) -> CoverPublic {
    CoverPublic {
        d_s: summary_digest(inst),
        d_flags: flag_digest(&inst.flags),
        g: inst.g,
        k: K,
        r: inst.retained(),
    }
}

// ---------------------------------------------------------------------------------------------
// AIR
// ---------------------------------------------------------------------------------------------

pub struct CoverAir {
    context: AirContext<F>,
    p: CoverPublic,
}

fn degrees() -> Vec<TransitionConstraintDegree> {
    let c8 = || vec![GROUP];
    let c16 = || vec![BLOCK_ROWS];
    let mut d = Vec::new();
    for _ in 0..2 {
        for _ in 0..W {
            d.push(TransitionConstraintDegree::with_cycles(7, c8())); // Rescue round
        }
        for _ in 0..W {
            d.push(TransitionConstraintDegree::with_cycles(1, c8())); // link
        }
    }
    for _ in 0..8 {
        d.push(TransitionConstraintDegree::with_cycles(1, c8())); // R1 hold inside a group
    }
    for _ in 0..7 {
        d.push(TransitionConstraintDegree::new(1)); // R2[1..8] = 0
    }
    d.push(TransitionConstraintDegree::with_cycles(1, c16())); // R2[0] = hdr * F
    for _ in 0..8 {
        d.push(TransitionConstraintDegree::with_cycles(1, c16())); // header word of the next block
    }
    d.push(TransitionConstraintDegree::new(2)); // F boolean
    d.push(TransitionConstraintDegree::with_cycles(1, c16())); // F hold
    d.push(TransitionConstraintDegree::new(1)); // GG step
    d.push(TransitionConstraintDegree::with_cycles(1, c16())); // C update
    d.push(TransitionConstraintDegree::new(1)); // CI = C + F
    for _ in 0..K {
        d.push(TransitionConstraintDegree::new(1)); // P hold
    }
    for _ in 0..SW {
        d.push(TransitionConstraintDegree::with_cycles(2, c16())); // sel boolean
    }
    d.push(TransitionConstraintDegree::with_cycles(1, c16())); // sel sums to 1
    for _ in 0..WORD_BITS {
        d.push(TransitionConstraintDegree::with_cycles(2, c16())); // oh boolean
    }
    d.push(TransitionConstraintDegree::with_cycles(1, c16())); // oh sums to 1
    for _ in 0..WORD_BITS {
        d.push(TransitionConstraintDegree::with_cycles(2, c16())); // bits boolean
    }
    d.push(TransitionConstraintDegree::with_cycles(1, c16())); // position tie
    d.push(TransitionConstraintDegree::with_cycles(2, c16())); // selected word = sum 2^t bits_t
    d.push(TransitionConstraintDegree::with_cycles(3, c16())); // PruneValid
    assert_eq!(d.len(), N_CONSTRAINTS);
    d
}

impl Air for CoverAir {
    type BaseField = F;
    type PublicInputs = CoverPublic;

    fn new(trace_info: TraceInfo, p: CoverPublic, options: ProofOptions) -> Self {
        assert_eq!(WIDTH, trace_info.width());
        assert_eq!(p.k, K, "this AIR is built for k = {K} probes");
        assert!(p.g >= 1, "G must be at least 1");
        CoverAir { context: AirContext::new(trace_info, degrees(), N_ASSERT, options), p }
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
        let (hdr, odd, bend, nend, prow) = (pv[26], pv[27], pv[28], pv[29], pv[30]);
        let psel = &pv[31..31 + K];
        let one = E::ONE;
        let mut o = 0;

        // two Rescue sponges: round constraints and link rows
        for (cs, cr) in [(C_S1, C_R1), (C_S2, C_R2)] {
            round_constraints(&cur[cs..cs + W], &next[cs..cs + W], ark1, ark2, fr, &mut out[o..o + W]);
            o += W;
            for j in 0..4 {
                out[o + j] = fl * (next[cs + j] - cur[cs + j]);
            }
            for j in 0..8 {
                out[o + 4 + j] = fl * (next[cs + 4 + j] - cur[cs + 4 + j] - cur[cr + j]);
            }
            o += W;
        }
        // R1 constant inside a group (the summary shown at the probe rows is the one absorbed at the link row)
        for j in 0..8 {
            out[o + j] = fr * (next[C_R1 + j] - cur[C_R1 + j]);
        }
        o += 8;
        // flag word: R2 = [hdr * F, 0, ..., 0]
        for j in 1..8 {
            out[o + j - 1] = cur[C_R2 + j];
        }
        o += 7;
        out[o] = cur[C_R2] - hdr * cur[C_F];
        o += 1;
        // summary group absorbs H_{g+1} = [DOM_HDR, GG + 1, 0, ...]
        out[o] = odd * (cur[C_R1] - E::from(F::new(DOM_HDR)));
        out[o + 1] = odd * (cur[C_R1 + 1] - cur[C_GG] - one);
        for j in 2..8 {
            out[o + j] = odd * cur[C_R1 + j];
        }
        o += 8;
        // flag, counters
        let f = cur[C_F];
        out[o] = f * (f - one);
        out[o + 1] = nend * (next[C_F] - f);
        out[o + 2] = next[C_GG] - cur[C_GG] - bend;
        out[o + 3] = next[C_C] - cur[C_C] - bend * (cur[C_CI] - cur[C_C]);
        out[o + 4] = cur[C_CI] - cur[C_C] - f;
        o += 5;
        for j in 0..K {
            out[o + j] = next[C_P + j] - cur[C_P + j];
        }
        o += K;
        // probe rows
        let sel = &cur[C_SEL..C_SEL + SW];
        let oh = &cur[C_OH..C_OH + WORD_BITS];
        let bits = &cur[C_B..C_B + WORD_BITS];
        let mut sum_sel = E::ZERO;
        for i in 0..SW {
            out[o + i] = prow * sel[i] * (sel[i] - one);
            sum_sel += sel[i];
        }
        o += SW;
        out[o] = prow * (sum_sel - one);
        o += 1;
        let mut sum_oh = E::ZERO;
        for t in 0..WORD_BITS {
            out[o + t] = prow * oh[t] * (oh[t] - one);
            sum_oh += oh[t];
        }
        o += WORD_BITS;
        out[o] = prow * (sum_oh - one);
        o += 1;
        for t in 0..WORD_BITS {
            out[o + t] = prow * bits[t] * (bits[t] - one);
        }
        o += WORD_BITS;
        // position tie: P_j = 32 * word index + bit index on probe row j
        let mut lhs = E::ZERO;
        for j in 0..K {
            lhs += psel[j] * cur[C_P + j];
        }
        let mut pos = E::ZERO;
        for i in 0..SW {
            pos += E::from(F::new((WORD_BITS * i) as u64)) * sel[i];
        }
        for t in 0..WORD_BITS {
            pos += E::from(F::new(t as u64)) * oh[t];
        }
        out[o] = lhs - prow * pos;
        o += 1;
        // selected word = sum 2^t bits_t
        let mut ws = E::ZERO;
        for i in 0..SW {
            ws += sel[i] * cur[C_R1 + i];
        }
        let mut bs = E::ZERO;
        let mut pw = F::ONE;
        let two = F::new(2);
        let mut ob = E::ZERO;
        for t in 0..WORD_BITS {
            bs += E::from(pw) * bits[t];
            pw = pw * two;
            ob += oh[t] * bits[t];
        }
        out[o] = prow * (ws - bs);
        o += 1;
        // PruneValid: pruned block => probed bit is 0
        out[o] = prow * (one - f) * ob;
        o += 1;
        debug_assert_eq!(o, N_CONSTRAINTS);
    }

    fn get_assertions(&self) -> Vec<Assertion<F>> {
        let n = self.trace_length();
        let g = self.p.g;
        let last = BLOCK_ROWS * g - 1;
        assert!(last < n, "trace too short for G");
        let mut a = Vec::new();
        let cap1 = [F::new(crate::data::DOM_CHAIN), F::new(2 * g as u64), F::ZERO, F::ZERO];
        let cap2 = [F::new(DOM_FLAGS), F::new(2 * g as u64), F::ZERO, F::ZERO];
        let h1 = header_word(1);
        for j in 0..4 {
            a.push(Assertion::single(C_S1 + j, 0, cap1[j]));
            a.push(Assertion::single(C_S2 + j, 0, cap2[j]));
        }
        for j in 0..8 {
            a.push(Assertion::single(C_S1 + 4 + j, 0, h1[j]));
            a.push(Assertion::single(C_S2 + 4 + j, 0, F::ZERO));
        }
        a.push(Assertion::single(C_C, 0, F::ZERO));
        a.push(Assertion::single(C_GG, 0, F::ONE));
        for j in 0..4 {
            a.push(Assertion::single(C_S1 + 4 + j, last, self.p.d_s[j]));
            a.push(Assertion::single(C_S2 + 4 + j, last, self.p.d_flags[j]));
        }
        a.push(Assertion::single(C_GG, last, F::new(g as u64)));
        a.push(Assertion::single(C_CI, last, F::new(self.p.r as u64)));
        assert_eq!(a.len(), N_ASSERT);
        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<F>> {
        let mut cols = chain_periodic();
        let col = |f: &dyn Fn(usize) -> bool| -> Vec<F> {
            (0..BLOCK_ROWS).map(|r| if f(r) { F::ONE } else { F::ZERO }).collect()
        };
        cols.push(col(&|r| r < GROUP)); // hdr
        cols.push(col(&|r| r >= GROUP)); // odd
        cols.push(col(&|r| r == BLOCK_ROWS - 1)); // bend
        cols.push(col(&|r| r != BLOCK_ROWS - 1)); // nend
        cols.push(col(&|r| r < K)); // prow
        for j in 0..K {
            cols.push(col(&|r| r == j));
        }
        cols
    }

    fn context(&self) -> &AirContext<F> {
        &self.context
    }
}

// ---------------------------------------------------------------------------------------------
// Trace builder and prover
// ---------------------------------------------------------------------------------------------

/// Fill one sponge: columns `cs..cs+12` (state) and `cr..cr+8` (next word), `words` has length n/8 + 1.
fn fill_sponge(cols: &mut [Vec<F>], cs: usize, cr: usize, cap: [F; 4], words: &[Word], n: usize) {
    let ng = n / GROUP;
    assert_eq!(words.len(), ng + 1);
    let mut s = [F::ZERO; W];
    s[..4].copy_from_slice(&cap);
    for j in 0..8 {
        s[4 + j] += words[0][j];
    }
    for k in 0..ng {
        let states = perm_states(s);
        for r in 0..GROUP {
            let row = k * GROUP + r;
            for j in 0..W {
                cols[cs + j][row] = states[r][j];
            }
            for j in 0..8 {
                cols[cr + j][row] = words[k + 1][j];
            }
        }
        s = states[GROUP - 1];
        for j in 0..8 {
            s[4 + j] += words[k + 1][j];
        }
    }
}

pub fn build_cover_trace(inst: &CoverInstance) -> TraceTable<F> {
    build_cover_trace_forged(inst, &summary_chain_words(inst), None)
}

/// Trace builder with two hooks for tests of forged witnesses: `chain_words` replaces the 2G words absorbed by sponge 1,
/// and `probe_view = Some((block index from 0, words))` shows other summary words at the probe rows (rows 0..6) of that block
/// than those absorbed at its link row.
pub fn build_cover_trace_forged(
    inst: &CoverInstance,
    chain_words: &[Word],
    probe_view: Option<(usize, [u64; SW])>,
) -> TraceTable<F> {
    let g = inst.g;
    assert_eq!(chain_words.len(), 2 * g);
    assert_eq!(inst.summaries.len(), g);
    assert_eq!(inst.flags.len(), g);
    let n = pow2_len(BLOCK_ROWS * g);
    let nb = n / BLOCK_ROWS;
    let ng = n / GROUP;
    let flag_of = |b: usize| if b < g { inst.flags[b] } else { true };
    // words with the virtual (padding) blocks after block G
    let mut w1 = chain_words.to_vec();
    for idx in 2 * g..=ng {
        w1.push(if idx % 2 == 0 { header_word((idx / 2 + 1) as u64) } else { [F::ZERO; 8] });
    }
    let mut w2 = Vec::with_capacity(ng + 1);
    for idx in 0..=ng {
        let mut w = [F::ZERO; 8];
        if idx % 2 == 1 {
            w[0] = F::new(flag_of((idx - 1) / 2) as u64);
        }
        w2.push(w);
    }
    let mut cols = vec![vec![F::ZERO; n]; WIDTH];
    let cap1 = [F::new(crate::data::DOM_CHAIN), F::new(2 * g as u64), F::ZERO, F::ZERO];
    let cap2 = [F::new(DOM_FLAGS), F::new(2 * g as u64), F::ZERO, F::ZERO];
    fill_sponge(&mut cols, C_S1, C_R1, cap1, &w1, n);
    fill_sponge(&mut cols, C_S2, C_R2, cap2, &w2, n);
    let zero_s = [0u64; SW];
    let mut c_before = 0u64;
    for b in 0..nb {
        let f = flag_of(b);
        let ci = c_before + f as u64;
        let s_real = if b < g { inst.summaries[b] } else { zero_s };
        let view = match probe_view {
            Some((vb, v)) if vb == b => v,
            _ => s_real,
        };
        for r in 0..BLOCK_ROWS {
            let row = BLOCK_ROWS * b + r;
            for j in 0..K {
                cols[C_P + j][row] = F::new(inst.positions[j] as u64);
            }
            cols[C_F][row] = F::new(f as u64);
            cols[C_C][row] = F::new(c_before);
            cols[C_CI][row] = F::new(ci);
            cols[C_GG][row] = F::new(b as u64 + 1);
            if r < K {
                let pos = inst.positions[r];
                let (wi, t) = (pos / WORD_BITS, pos % WORD_BITS);
                cols[C_SEL + wi][row] = F::ONE;
                cols[C_OH + t][row] = F::ONE;
                let word = view[wi];
                for i in 0..WORD_BITS {
                    cols[C_B + i][row] = F::new((word >> i) & 1);
                }
                if probe_view.map(|(vb, _)| vb == b).unwrap_or(false) {
                    for j in 0..SW {
                        cols[C_R1 + j][row] = F::new(view[j]);
                    }
                }
            }
        }
        c_before = ci;
    }
    TraceTable::init(cols)
}

pub fn prove_cover(inst: &CoverInstance, options: ProofOptions) -> Result<(Proof, CoverPublic), String> {
    let p = cover_public(inst);
    let trace = build_cover_trace(inst);
    let proof = prove_trace::<CoverAir>(trace, p.clone(), options)?;
    Ok((proof, p))
}

pub fn verify_cover(proof: Proof, p: CoverPublic) -> Result<(), String> {
    verify_proof::<CoverAir>(proof, p)
}

pub fn options() -> ProofOptions {
    default_options()
}
