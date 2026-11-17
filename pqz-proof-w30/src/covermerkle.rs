//! R_CoverM (block coverage with Merkle-opened probes over real-size Bloom summaries): see DESIGN.md section 8.
//!
//! One block = 1024 rows = 128 groups of 8 rows (one Rescue permutation per group, ONE shared state bank `S`).
//!   group 0   chain sponge, header word H_g = [DOM_HDR, g, 0..]           (S = CH + word, then CH = S after the group)
//!   group 1   chain sponge, root word   W_g = [M_g, 0, 0, 0, 0]
//!   group 2   flag sponge, zero word
//!   group 3   flag sponge, [f_g, 0..]
//!   probe j (j = 0..6), base d = 3 + 14 j:
//!     group d      decomposition of the limb into 32 bits (columns BD, ACC; the group itself belongs to the previous role)
//!     group d + 1  leaf permutation  [DOM_MLEAF,0,0,0 | limb,0..]        (link row of group d sets the state)
//!     group d + 2 .. d + 14  the 13 merges [DOM_MERGE,0,0,0 | left | right]  (link rows set the state; direction = bit i of the leaf index)
//!   the output digest of the last merge (group d + 14, which is also the decomposition group of the next probe) equals M_g.
//!   groups 102..127: padding (no round constraint; the holds still apply).
//! Columns: 0..12 S | 12..24 CH | 24..36 FH | 36..40 M | 40..44 SIB | 44..48 BD | 48 ACC | 49 F | 50 C | 51 GG | 52 PR.

use crate::auth::DOM_MERGE;
use crate::cover::{flag_digest, header_word, DOM_FLAGS, DOM_HDR, K};
use crate::data::{chain_digest, Rng, Word, DOM_CHAIN};
use crate::prove::{default_options, prove_trace, verify_proof};
use crate::rescue::{ark_periodic, perm, perm_states, round_constraints, F, GROUP, W};
use winterfell::{
    math::{FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, Proof, ProofOptions, TraceInfo, TraceTable,
    TransitionConstraintDegree,
};

pub const DEPTH: usize = 13;
pub const LEAVES: usize = 1 << DEPTH; // 8192
pub const LIMBS: usize = 6740; // real limbs of 32 bits per block summary (3,370 words of 64 bits)
pub const LIMB_BITS: usize = 32;
pub const NBITS: usize = LIMBS * LIMB_BITS; // 215,680 Bloom bits
pub const BLOCK_ROWS: usize = 1024;
pub const ACTIVE_GROUPS: usize = 4 + K * (DEPTH + 1); // 102
pub const DOM_MLEAF: u64 = 0x5051_5a45; // "PQZE"

pub const WIDTH: usize = 53;
pub const C_S: usize = 0;
pub const C_CH: usize = 12;
pub const C_FH: usize = 24;
pub const C_M: usize = 36;
pub const C_SIB: usize = 40;
pub const C_BD: usize = 44;
pub const C_ACC: usize = 48;
pub const C_F: usize = 49;
pub const C_C: usize = 50;
pub const C_GG: usize = 51;
pub const C_PR: usize = 52;
const N_CONSTRAINTS: usize = 81;
const N_ASSERT: usize = 36;
const N_PERIODIC: usize = 45;

fn dec_group(j: usize) -> usize {
    3 + (DEPTH + 1) * j
}

// ---------------------------------------------------------------------------------------------
// Merkle tree (reference code, library permutation; the 2-to-1 compression is the one of R_Auth)
// ---------------------------------------------------------------------------------------------

pub fn leaf_digest(limb: u64) -> [F; 4] {
    let mut s = [F::ZERO; W];
    s[0] = F::new(DOM_MLEAF);
    s[4] = F::new(limb);
    perm(&mut s);
    [s[4], s[5], s[6], s[7]]
}

pub fn merge_digest(left: [F; 4], right: [F; 4]) -> [F; 4] {
    let mut s = [F::ZERO; W];
    s[0] = F::new(DOM_MERGE);
    s[4..8].copy_from_slice(&left);
    s[8..12].copy_from_slice(&right);
    perm(&mut s);
    [s[4], s[5], s[6], s[7]]
}

/// Root from a leaf digest, the leaf index and the siblings (bit i of the index = 1: the node is the right child).
pub fn fold_path(leaf: [F; 4], index: usize, sibs: &[[F; 4]]) -> [F; 4] {
    let mut cur = leaf;
    for (i, sib) in sibs.iter().enumerate() {
        cur = if (index >> i) & 1 == 1 { merge_digest(*sib, cur) } else { merge_digest(cur, *sib) };
    }
    cur
}

/// Complete Merkle tree over `LEAVES` leaves (limbs padded with zero limbs).
pub struct Tree {
    pub limbs: Vec<u64>,
    /// levels[0] = leaf digests, levels[DEPTH] = [root]
    pub levels: Vec<Vec<[F; 4]>>,
}

impl Tree {
    pub fn build(limbs: &[u64]) -> Tree {
        assert!(limbs.len() <= LEAVES);
        let mut l = limbs.to_vec();
        l.resize(LEAVES, 0);
        let zero = leaf_digest(0);
        let mut lvl0 = Vec::with_capacity(LEAVES);
        for (i, &x) in l.iter().enumerate() {
            lvl0.push(if i >= limbs.len() { zero } else { leaf_digest(x) });
        }
        let mut levels = vec![lvl0];
        for d in 0..DEPTH {
            let prev = &levels[d];
            let next: Vec<[F; 4]> = (0..prev.len() / 2).map(|i| merge_digest(prev[2 * i], prev[2 * i + 1])).collect();
            levels.push(next);
        }
        Tree { limbs: l, levels }
    }
    pub fn root(&self) -> [F; 4] {
        self.levels[DEPTH][0]
    }
}

/// A tree with one leaf replaced (only the 14 nodes on that leaf's path are recomputed; everything else is read from the base tree).
pub struct Patched<'a> {
    t: &'a Tree,
    m: usize,
    val: u64,
    path: Vec<[F; 4]>,
}

impl<'a> Patched<'a> {
    pub fn none(t: &'a Tree) -> Self {
        Patched { t, m: usize::MAX, val: 0, path: Vec::new() }
    }
    pub fn new(t: &'a Tree, m: usize, val: u64) -> Self {
        let mut path = Vec::with_capacity(DEPTH + 1);
        let mut cur = leaf_digest(val);
        path.push(cur);
        for l in 0..DEPTH {
            let sib = t.levels[l][(m >> l) ^ 1];
            cur = if (m >> l) & 1 == 1 { merge_digest(sib, cur) } else { merge_digest(cur, sib) };
            path.push(cur);
        }
        Patched { t, m, val, path }
    }
    fn node(&self, level: usize, i: usize) -> [F; 4] {
        if self.m != usize::MAX && i == (self.m >> level) {
            self.path[level]
        } else {
            self.t.levels[level][i]
        }
    }
    fn limb(&self, i: usize) -> u64 {
        if i == self.m {
            self.val
        } else {
            self.t.limbs[i]
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Witness and public input
// ---------------------------------------------------------------------------------------------

/// Leaf indices (= limb indices) of the k probed bit positions.
pub fn leaf_indices(positions: &[usize; K]) -> [usize; K] {
    let mut r = [0usize; K];
    for j in 0..K {
        r[j] = positions[j] / LIMB_BITS;
    }
    r
}

#[derive(Clone, Debug)]
pub struct BlockWitness {
    pub root: [F; 4],
    /// true = retained
    pub flag: bool,
    pub limbs: [u64; K],
    pub sibs: [[[F; 4]; DEPTH]; K],
}

impl BlockWitness {
    /// Honest openings of the leaves `leaf_idx[j]` of the view (the leaf indices are normally `leaf_indices(positions)`).
    pub fn open(view: &Patched, leaf_idx: &[usize; K], flag: bool) -> Self {
        let mut limbs = [0u64; K];
        let mut sibs = [[[F::ZERO; 4]; DEPTH]; K];
        for j in 0..K {
            limbs[j] = view.limb(leaf_idx[j]);
            for i in 0..DEPTH {
                sibs[j][i] = view.node(i, (leaf_idx[j] >> i) ^ 1);
            }
        }
        BlockWitness { root: view.node(DEPTH, 0), flag, limbs, sibs }
    }
    /// Build the whole tree of a summary (LIMBS limbs) and open the probes. Cost: about 15,000 permutations.
    pub fn from_limbs(limbs: &[u64], positions: &[usize; K], flag: bool) -> Self {
        let t = Tree::build(limbs);
        Self::open(&Patched::none(&t), &leaf_indices(positions), flag)
    }
    pub fn probed_bit(&self, positions: &[usize; K], j: usize) -> bool {
        (self.limbs[j] >> (positions[j] % LIMB_BITS)) & 1 == 1
    }
}

/// Random 6,740-limb summary with the k probed bits set as given (synthetic content; not a Bloom filter of anything).
pub fn synth_limbs(rng: &mut Rng, positions: &[usize; K], bits: &[bool; K]) -> Vec<u64> {
    let mut l: Vec<u64> = (0..LIMBS).map(|_| rng.next_u64() & 0xffff_ffff).collect();
    for j in 0..K {
        let (wi, t) = (positions[j] / LIMB_BITS, positions[j] % LIMB_BITS);
        if bits[j] {
            l[wi] |= 1u64 << t;
        } else {
            l[wi] &= !(1u64 << t);
        }
    }
    l
}

pub fn random_positions(rng: &mut Rng) -> [usize; K] {
    let mut positions = [0usize; K];
    let mut i = 0;
    while i < K {
        let p = (rng.next_u64() % NBITS as u64) as usize;
        if !positions[..i].contains(&p) {
            positions[i] = p;
            i += 1;
        }
    }
    positions
}

#[derive(Clone, Debug)]
pub struct CoverMInstance {
    pub g: usize,
    pub blocks: Vec<BlockWitness>,
    /// the k probed bit positions, the same for all blocks
    pub positions: [usize; K],
    /// witness of the virtual blocks after block G (a valid dummy block, flag 1)
    pub pad: BlockWitness,
}

impl CoverMInstance {
    /// Honest instance: `r` retained blocks spread evenly over the G blocks. Retained blocks have all k probed bits 1; pruned blocks have a
    /// random pattern with at least one 0 (so the paper's rule holds, the all-zero rule of R_Cover would not). To keep the cost of building
    /// G trees small, 2 retained and 4 pruned template trees are built, and every block replaces one fixed non-probed limb by its block
    /// number (roots all distinct, 14 nodes recomputed per block). See DESIGN.md section 8.
    pub fn honest(g: usize, r: usize, seed: u64) -> Self {
        assert!(g >= 1 && r <= g);
        let mut rng = Rng::new(seed);
        let positions = random_positions(&mut rng);
        let lidx = leaf_indices(&positions);
        let mut templates_ret = Vec::new();
        for _ in 0..2 {
            let l = synth_limbs(&mut rng, &positions, &[true; K]);
            templates_ret.push(Tree::build(&l));
        }
        let mut templates_pru = Vec::new();
        for t in 0..4 {
            let mut bits = [true; K];
            // template 0: exactly one 0 (the paper's minimal pruned case); others: each bit 1 with probability 1/2, at least one 0
            let z = (rng.next_u64() % K as u64) as usize;
            bits[z] = false;
            if t > 0 {
                for b in bits.iter_mut() {
                    *b = rng.next_u64() & 1 == 1;
                }
                bits[z] = false;
            }
            let l = synth_limbs(&mut rng, &positions, &bits);
            templates_pru.push(Tree::build(&l));
        }
        // block-specific leaf: the highest real limb that is not probed
        let mut m = LIMBS - 1;
        while lidx.contains(&m) {
            m -= 1;
        }
        let flag_of = |b: usize| ((b + 1) * r) / g > (b * r) / g;
        let mut blocks = Vec::with_capacity(g);
        for b in 0..g {
            let f = flag_of(b);
            let t = if f { &templates_ret[b % templates_ret.len()] } else { &templates_pru[b % templates_pru.len()] };
            let view = Patched::new(t, m, (b + 1) as u64);
            blocks.push(BlockWitness::open(&view, &lidx, f));
        }
        let pad_tree = &templates_ret[0];
        let pad_view = Patched::new(pad_tree, m, 0xffff_fff0);
        let pad = BlockWitness::open(&pad_view, &lidx, true);
        CoverMInstance { g, blocks, positions, pad }
    }
    pub fn flags(&self) -> Vec<bool> {
        self.blocks.iter().map(|b| b.flag).collect()
    }
    pub fn retained(&self) -> usize {
        self.blocks.iter().filter(|b| b.flag).count()
    }
}

#[derive(Clone, Debug)]
pub struct CoverMPublic {
    pub d_s: [F; 4],
    pub d_flags: [F; 4],
    pub g: usize,
    pub k: usize,
    pub r: usize,
    pub positions: [usize; K],
}

impl ToElements<F> for CoverMPublic {
    fn to_elements(&self) -> Vec<F> {
        let mut v = self.d_s.to_vec();
        v.extend_from_slice(&self.d_flags);
        v.push(F::new(self.g as u64));
        v.push(F::new(self.k as u64));
        v.push(F::new(self.r as u64));
        for &p in &self.positions {
            v.push(F::new(p as u64));
        }
        v
    }
}

/// Hooks for tests of forged witnesses.
#[derive(Clone, Debug, Default)]
pub struct Forge {
    /// (block index from 0, g value): this value is absorbed in the header word of that block instead of the true block index
    pub header_override: Option<(usize, u64)>,
}

pub fn root_word(m: &[F; 4]) -> Word {
    let mut w = [F::ZERO; 8];
    w[..4].copy_from_slice(m);
    w
}

/// The 2G words of the chain: H_1, W_1, ..., H_G, W_G.
pub fn chain_words(inst: &CoverMInstance, forge: &Forge) -> Vec<Word> {
    let mut v = Vec::with_capacity(2 * inst.g);
    for b in 0..inst.g {
        let idx = match forge.header_override {
            Some((fb, val)) if fb == b => val,
            _ => b as u64 + 1,
        };
        v.push(header_word(idx));
        v.push(root_word(&inst.blocks[b].root));
    }
    v
}

pub fn summary_digest(inst: &CoverMInstance) -> [F; 4] {
    chain_digest(&chain_words(inst, &Forge::default()))
}

pub fn covermerkle_public(inst: &CoverMInstance) -> CoverMPublic {
    CoverMPublic {
        d_s: summary_digest(inst),
        d_flags: flag_digest(&inst.flags()),
        g: inst.g,
        k: K,
        r: inst.retained(),
        positions: inst.positions,
    }
}

pub fn trace_len(g: usize) -> usize {
    (BLOCK_ROWS * (g + 1)).next_power_of_two().max(2 * BLOCK_ROWS)
}

// ---------------------------------------------------------------------------------------------
// Geometry fixed by the public positions
// ---------------------------------------------------------------------------------------------

struct Geo {
    dir: [[bool; DEPTH]; K],
    pr_row: [usize; K],
    pr_col: [usize; K],
}

impl Geo {
    fn new(positions: &[usize; K]) -> Geo {
        let mut dir = [[false; DEPTH]; K];
        let mut pr_row = [0usize; K];
        let mut pr_col = [0usize; K];
        for j in 0..K {
            let p = positions[j];
            assert!(p < NBITS, "position out of range");
            let (limb, t) = (p / LIMB_BITS, p % LIMB_BITS);
            for i in 0..DEPTH {
                dir[j][i] = (limb >> i) & 1 == 1;
            }
            // chunks are taken MSB first: row rho holds bits 31-4rho .. 28-4rho in columns 0..3
            let from_msb = LIMB_BITS - 1 - t;
            pr_row[j] = GROUP * dec_group(j) + from_msb / 4;
            pr_col[j] = from_msb % 4;
        }
        Geo { dir, pr_row, pr_col }
    }
}

// ---------------------------------------------------------------------------------------------
// AIR
// ---------------------------------------------------------------------------------------------

pub struct CoverMAir {
    context: AirContext<F>,
    p: CoverMPublic,
    geo: Geo,
}

fn degrees() -> Vec<TransitionConstraintDegree> {
    let c = || vec![BLOCK_ROWS];
    let mut d = Vec::new();
    for _ in 0..W {
        d.push(TransitionConstraintDegree::with_cycles(7, c())); // Rescue round (selector period 1024)
    }
    for _ in 0..2 * W {
        d.push(TransitionConstraintDegree::with_cycles(1, c())); // CH and FH: hold / copy from S
    }
    for _ in 0..W {
        d.push(TransitionConstraintDegree::with_cycles(1, c())); // sponge input at row 0 of the chain groups
    }
    for _ in 0..W {
        d.push(TransitionConstraintDegree::with_cycles(1, c())); // leaf and merge links
    }
    for _ in 0..4 {
        d.push(TransitionConstraintDegree::with_cycles(1, c())); // digest of the last merge = M
    }
    d.push(TransitionConstraintDegree::with_cycles(1, c())); // ACC update
    d.push(TransitionConstraintDegree::with_cycles(1, c())); // ACC reset
    for _ in 0..4 {
        d.push(TransitionConstraintDegree::new(2)); // BD boolean
    }
    d.push(TransitionConstraintDegree::with_cycles(2, c())); // PR update
    d.push(TransitionConstraintDegree::with_cycles(1, c())); // PR start
    d.push(TransitionConstraintDegree::with_cycles(2, c())); // PR end: (1 - F) * PR = 0
    d.push(TransitionConstraintDegree::new(2)); // F boolean
    d.push(TransitionConstraintDegree::with_cycles(1, c())); // F hold
    d.push(TransitionConstraintDegree::with_cycles(1, c())); // C update
    d.push(TransitionConstraintDegree::with_cycles(1, c())); // GG step
    for _ in 0..4 {
        d.push(TransitionConstraintDegree::with_cycles(1, c())); // M hold
    }
    assert_eq!(d.len(), N_CONSTRAINTS);
    d
}

impl Air for CoverMAir {
    type BaseField = F;
    type PublicInputs = CoverMPublic;

    fn new(trace_info: TraceInfo, p: CoverMPublic, options: ProofOptions) -> Self {
        assert_eq!(WIDTH, trace_info.width());
        assert_eq!(p.k, K, "this AIR is built for k = {K} probes");
        assert!(p.g >= 1, "G must be at least 1");
        assert!(trace_info.length() > BLOCK_ROWS * p.g, "trace too short for G");
        let geo = Geo::new(&p.positions);
        CoverMAir { context: AirContext::new(trace_info, degrees(), if p.g == 1 { N_ASSERT - 1 } else { N_ASSERT }, options), p, geo }
    }

    fn evaluate_transition<E: FieldElement + From<F>>(
        &self,
        frame: &EvaluationFrame<E>,
        pv: &[E],
        out: &mut [E],
    ) {
        let cur = frame.current();
        let next = frame.next();
        let fr = pv[0];
        let ark1 = &pv[1..1 + W];
        let ark2 = &pv[1 + W..1 + 2 * W];
        let (in0, in1, in2, in3) = (pv[25], pv[26], pv[27], pv[28]);
        let (s_leaf, s_d0, s_d1, s_root) = (pv[29], pv[30], pv[31], pv[32]);
        let (s_dec, s_dec0, s_hold) = (pv[33], pv[34], pv[35]);
        let pk = &pv[36..40];
        let (r0, bend, nend, u_ch, u_fh) = (pv[40], pv[41], pv[42], pv[43], pv[44]);
        let one = E::ONE;
        let two = one + one;
        let four = two + two;
        let eight = four + four;
        let sixteen = eight + eight;
        let mut o = 0;

        // Rescue rounds on the shared state
        round_constraints(&cur[C_S..C_S + W], &next[C_S..C_S + W], ark1, ark2, fr, &mut out[o..o + W]);
        o += W;
        // saved sponge states: hold, and copy the group output after the last row of a chain group
        for j in 0..W {
            out[o + j] = next[C_CH + j] - cur[C_CH + j] - u_ch * (cur[C_S + j] - cur[C_CH + j]);
        }
        o += W;
        for j in 0..W {
            out[o + j] = next[C_FH + j] - cur[C_FH + j] - u_fh * (cur[C_S + j] - cur[C_FH + j]);
        }
        o += W;
        // sponge input at row 0 of groups 0..3: S = saved state + word
        for j in 0..W {
            let w0 = if j == 4 {
                E::from(F::new(DOM_HDR))
            } else if j == 5 {
                cur[C_GG]
            } else {
                E::ZERO
            };
            let w1 = if (4..8).contains(&j) { cur[C_M + j - 4] } else { E::ZERO };
            let w3 = if j == 4 { cur[C_F] } else { E::ZERO };
            let s = cur[C_S + j];
            let (ch, fh) = (cur[C_CH + j], cur[C_FH + j]);
            out[o + j] = in0 * (s - ch - w0) + in1 * (s - ch - w1) + in2 * (s - fh) + in3 * (s - fh - w3);
        }
        o += W;
        // leaf and merge links (row 7 of the previous group -> row 0 of the leaf / merge group)
        let chunk = eight * cur[C_BD] + four * cur[C_BD + 1] + two * cur[C_BD + 2] + cur[C_BD + 3];
        let limb = sixteen * cur[C_ACC] + chunk;
        let s_mrg = s_d0 + s_d1;
        out[o] = s_leaf * (next[C_S] - E::from(F::new(DOM_MLEAF))) + s_mrg * (next[C_S] - E::from(F::new(DOM_MERGE)));
        for j in 1..4 {
            out[o + j] = (s_leaf + s_mrg) * next[C_S + j];
        }
        for j in 4..8 {
            let leaf_w = if j == 4 { limb } else { E::ZERO };
            out[o + j] = s_leaf * (next[C_S + j] - leaf_w)
                + s_d0 * (next[C_S + j] - cur[C_S + j])
                + s_d1 * (next[C_S + j] - cur[C_SIB + j - 4]);
        }
        for j in 8..12 {
            out[o + j] = s_leaf * next[C_S + j]
                + s_d0 * (next[C_S + j] - cur[C_SIB + j - 8])
                + s_d1 * (next[C_S + j] - cur[C_S + 4 + j - 8]);
        }
        o += W;
        // the root of the path is the block root
        for i in 0..4 {
            out[o + i] = s_root * (cur[C_S + 4 + i] - cur[C_M + i]);
        }
        o += 4;
        // 32-bit decomposition of the limb (4 bits per row, MSB first)
        out[o] = s_dec * (next[C_ACC] - sixteen * cur[C_ACC] - chunk);
        out[o + 1] = s_dec0 * cur[C_ACC];
        o += 2;
        for i in 0..4 {
            out[o + i] = cur[C_BD + i] * (cur[C_BD + i] - one);
        }
        o += 4;
        // PruneValid: running product of the probed bits; a pruned block needs the product to be 0
        let f = cur[C_F];
        let pr = cur[C_PR];
        let mut upd = s_hold * (next[C_PR] - pr);
        for k in 0..4 {
            upd += pk[k] * (next[C_PR] - pr * cur[C_BD + k]);
        }
        out[o] = upd;
        out[o + 1] = r0 * (pr - one);
        out[o + 2] = bend * (one - f) * pr;
        o += 3;
        // flag, counters, root hold
        out[o] = f * (f - one);
        out[o + 1] = nend * (next[C_F] - f);
        out[o + 2] = next[C_C] - cur[C_C] - bend * f;
        out[o + 3] = next[C_GG] - cur[C_GG] - bend;
        o += 4;
        for i in 0..4 {
            out[o + i] = nend * (next[C_M + i] - cur[C_M + i]);
        }
        o += 4;
        debug_assert_eq!(o, N_CONSTRAINTS);
    }

    fn get_assertions(&self) -> Vec<Assertion<F>> {
        let g = self.p.g;
        let first_g = BLOCK_ROWS * (g - 1);
        let after_g = BLOCK_ROWS * g;
        assert!(after_g < self.trace_length(), "trace too short for G");
        let mut a = Vec::with_capacity(N_ASSERT);
        let cap1 = [F::new(DOM_CHAIN), F::new(2 * g as u64), F::ZERO, F::ZERO];
        let cap2 = [F::new(DOM_FLAGS), F::new(2 * g as u64), F::ZERO, F::ZERO];
        for j in 0..W {
            a.push(Assertion::single(C_CH + j, 0, if j < 4 { cap1[j] } else { F::ZERO }));
            a.push(Assertion::single(C_FH + j, 0, if j < 4 { cap2[j] } else { F::ZERO }));
        }
        a.push(Assertion::single(C_C, 0, F::ZERO));
        a.push(Assertion::single(C_GG, 0, F::ONE));
        // chain digest: saved chain state after group 1 of block G (visible from row 16 of the block)
        for j in 0..4 {
            a.push(Assertion::single(C_CH + 4 + j, first_g + 2 * GROUP, self.p.d_s[j]));
            a.push(Assertion::single(C_FH + 4 + j, first_g + 4 * GROUP, self.p.d_flags[j]));
        }
        // for G = 1 this assertion is the same one as GG = 1 at row 0 (winterfell refuses duplicates), so it is left out
        if first_g != 0 {
            a.push(Assertion::single(C_GG, first_g, F::new(g as u64)));
        }
        a.push(Assertion::single(C_C, after_g, F::new(self.p.r as u64)));
        assert_eq!(a.len(), if first_g != 0 { N_ASSERT } else { N_ASSERT - 1 });
        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<F>> {
        let geo = &self.geo;
        let col = |f: &dyn Fn(usize) -> bool| -> Vec<F> {
            (0..BLOCK_ROWS).map(|r| if f(r) { F::ONE } else { F::ZERO }).collect()
        };
        let grp = |r: usize| r / GROUP;
        let rho = |r: usize| r % GROUP;
        let mut cols: Vec<Vec<F>> = Vec::with_capacity(N_PERIODIC);
        cols.push(col(&|r| grp(r) < ACTIVE_GROUPS && rho(r) < GROUP - 1)); // 0 fr
        cols.extend(ark_periodic()); // 1..25
        cols.push(col(&|r| r == 0)); // 25 in0
        cols.push(col(&|r| r == GROUP)); // 26 in1
        cols.push(col(&|r| r == 2 * GROUP)); // 27 in2
        cols.push(col(&|r| r == 3 * GROUP)); // 28 in3
        // 29 s_leaf: row 7 of a decomposition group
        cols.push(col(&|r| rho(r) == GROUP - 1 && (0..K).any(|j| grp(r) == dec_group(j))));
        // 30 s_d0 / 31 s_d1: row 7 of group 4 + 14 j + i (the group before merge i), direction = bit i of the leaf index
        let merge_link = |r: usize, want: bool| -> bool {
            if rho(r) != GROUP - 1 {
                return false;
            }
            (0..K).any(|j| (0..DEPTH).any(|i| grp(r) == dec_group(j) + 1 + i && geo.dir[j][i] == want))
        };
        cols.push(col(&|r| merge_link(r, false)));
        cols.push(col(&|r| merge_link(r, true)));
        // 32 s_root: row 7 of the last merge group of each probe
        cols.push(col(&|r| rho(r) == GROUP - 1 && (0..K).any(|j| grp(r) == dec_group(j) + DEPTH + 1)));
        // 33 s_dec: rows 0..6 of a decomposition group; 34 s_dec0: row 0
        cols.push(col(&|r| rho(r) < GROUP - 1 && (0..K).any(|j| grp(r) == dec_group(j))));
        cols.push(col(&|r| rho(r) == 0 && (0..K).any(|j| grp(r) == dec_group(j))));
        // 35 s_hold: PR holds on every row except the probe rows and the last row of the block
        cols.push(col(&|r| r != BLOCK_ROWS - 1 && !geo.pr_row.contains(&r)));
        // 36..40 pk: probe row whose probed bit sits in BD column k
        for k in 0..4 {
            cols.push(col(&|r| (0..K).any(|j| geo.pr_row[j] == r && geo.pr_col[j] == k)));
        }
        cols.push(col(&|r| r == 0)); // 40 r0
        cols.push(col(&|r| r == BLOCK_ROWS - 1)); // 41 bend
        cols.push(col(&|r| r != BLOCK_ROWS - 1)); // 42 nend
        cols.push(col(&|r| r == GROUP - 1 || r == 2 * GROUP - 1)); // 43 u_ch
        cols.push(col(&|r| r == 3 * GROUP - 1 || r == 4 * GROUP - 1)); // 44 u_fh
        assert_eq!(cols.len(), N_PERIODIC);
        cols
    }

    fn context(&self) -> &AirContext<F> {
        &self.context
    }
}

// ---------------------------------------------------------------------------------------------
// Trace builder and prover
// ---------------------------------------------------------------------------------------------

fn put_states(cols: &mut [Vec<F>], row0: usize, st: &[[F; W]; GROUP]) {
    for r in 0..GROUP {
        for j in 0..W {
            cols[C_S + j][row0 + r] = st[r][j];
        }
    }
}

pub fn build_trace(inst: &CoverMInstance) -> TraceTable<F> {
    build_trace_forged(inst, &Forge::default())
}

pub fn build_trace_forged(inst: &CoverMInstance, forge: &Forge) -> TraceTable<F> {
    let g = inst.g;
    assert_eq!(inst.blocks.len(), g);
    let n = trace_len(g);
    let nb = n / BLOCK_ROWS;
    let geo = Geo::new(&inst.positions);
    let mut cols = vec![vec![F::ZERO; n]; WIDTH];
    let mut ch = [F::ZERO; W];
    ch[0] = F::new(DOM_CHAIN);
    ch[1] = F::new(2 * g as u64);
    let mut fh = [F::ZERO; W];
    fh[0] = F::new(DOM_FLAGS);
    fh[1] = F::new(2 * g as u64);
    let mut c_before = 0u64;
    for b in 0..nb {
        let w = if b < g { &inst.blocks[b] } else { &inst.pad };
        let flag = if b < g { w.flag } else { true };
        let base = b * BLOCK_ROWS;
        let hidx = match forge.header_override {
            Some((fb, val)) if fb == b => val,
            _ => b as u64 + 1,
        };
        // groups 0..3: the two sponges
        let ch0 = ch;
        let mut s = ch;
        s[4] += F::new(DOM_HDR);
        s[5] += F::new(hidx);
        let st0 = perm_states(s);
        put_states(&mut cols, base, &st0);
        let ch1 = st0[GROUP - 1];
        let mut s = ch1;
        for i in 0..4 {
            s[4 + i] += w.root[i];
        }
        let st1 = perm_states(s);
        put_states(&mut cols, base + GROUP, &st1);
        let ch2 = st1[GROUP - 1];
        let fh0 = fh;
        let st2 = perm_states(fh0);
        put_states(&mut cols, base + 2 * GROUP, &st2);
        let fh2 = st2[GROUP - 1];
        let mut s = fh2;
        s[4] += F::new(flag as u64);
        let st3 = perm_states(s);
        put_states(&mut cols, base + 3 * GROUP, &st3);
        let fh3 = st3[GROUP - 1];
        for j in 0..W {
            cols[C_CH + j][base..base + GROUP].fill(ch0[j]);
            cols[C_CH + j][base + GROUP..base + 2 * GROUP].fill(ch1[j]);
            cols[C_CH + j][base + 2 * GROUP..base + BLOCK_ROWS].fill(ch2[j]);
            cols[C_FH + j][base..base + 3 * GROUP].fill(fh0[j]);
            cols[C_FH + j][base + 3 * GROUP..base + 4 * GROUP].fill(fh2[j]);
            cols[C_FH + j][base + 4 * GROUP..base + BLOCK_ROWS].fill(fh3[j]);
        }
        ch = ch2;
        fh = fh3;
        // probes
        for j in 0..K {
            let d = dec_group(j);
            let limb = w.limbs[j];
            assert!(limb < (1u64 << LIMB_BITS), "limb must be below 2^32");
            // decomposition group
            let mut acc = 0u64;
            for r in 0..GROUP {
                let row = base + GROUP * d + r;
                cols[C_ACC][row] = F::new(acc);
                let mut chunk = 0u64;
                for k in 0..4 {
                    let bit = (limb >> (31 - 4 * r - k)) & 1;
                    cols[C_BD + k][row] = F::new(bit);
                    chunk = 2 * chunk + bit;
                }
                acc = 16 * acc + chunk;
            }
            // leaf group
            let mut s = [F::ZERO; W];
            s[0] = F::new(DOM_MLEAF);
            s[4] = F::new(limb);
            let st = perm_states(s);
            put_states(&mut cols, base + GROUP * (d + 1), &st);
            let mut dg = [st[GROUP - 1][4], st[GROUP - 1][5], st[GROUP - 1][6], st[GROUP - 1][7]];
            // merges
            for i in 0..DEPTH {
                let sib = w.sibs[j][i];
                let link_row = base + GROUP * (d + 1 + i) + GROUP - 1;
                for q in 0..4 {
                    cols[C_SIB + q][link_row] = sib[q];
                }
                let (l, r) = if geo.dir[j][i] { (sib, dg) } else { (dg, sib) };
                let mut s = [F::ZERO; W];
                s[0] = F::new(DOM_MERGE);
                s[4..8].copy_from_slice(&l);
                s[8..12].copy_from_slice(&r);
                let st = perm_states(s);
                put_states(&mut cols, base + GROUP * (d + 2 + i), &st);
                dg = [st[GROUP - 1][4], st[GROUP - 1][5], st[GROUP - 1][6], st[GROUP - 1][7]];
            }
        }
        // constant columns of the block and the running product
        let ci = c_before + flag as u64;
        for r in 0..BLOCK_ROWS {
            cols[C_F][base + r] = F::new(flag as u64);
            cols[C_C][base + r] = F::new(c_before);
            cols[C_GG][base + r] = F::new(b as u64 + 1);
            for i in 0..4 {
                cols[C_M + i][base + r] = w.root[i];
            }
        }
        let mut pr = F::ONE;
        for r in 0..BLOCK_ROWS {
            cols[C_PR][base + r] = pr;
            if let Some(j) = (0..K).find(|&j| geo.pr_row[j] == r) {
                pr = pr * cols[C_BD + geo.pr_col[j]][base + r];
            }
        }
        c_before = ci;
    }
    TraceTable::init(cols)
}

pub fn prove_covermerkle(inst: &CoverMInstance, options: ProofOptions) -> Result<(Proof, CoverMPublic), String> {
    let p = covermerkle_public(inst);
    let trace = build_trace(inst);
    let proof = prove_trace::<CoverMAir>(trace, p.clone(), options)?;
    Ok((proof, p))
}

pub fn verify_covermerkle(proof: Proof, p: CoverMPublic) -> Result<(), String> {
    verify_proof::<CoverMAir>(proof, p)
}

pub fn options() -> ProofOptions {
    default_options()
}
