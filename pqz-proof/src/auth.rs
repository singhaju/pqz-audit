//! R_Auth (authorization and canonical-state binding): see DESIGN.md section 2.
//!
//! Layout (groups of 8 rows; d = Merkle depth of the policy tree):
//!   g0          leaf hash, part 1: capacity [DOM_LEAF,0,0,0], rate = P0..P7
//!   g1          leaf hash, part 2: rate[0..4] += P8..P11            (link of g0)
//!   g2..g(d+1)  Merkle merges with private sibling SIB and direction bit D   (links of g1..g(d))
//!   g(d+2)      B_Q hash part 1 (all inputs public, asserted)
//!   g(d+3)      B_Q hash part 2: rate += [R_pol, Omega]            (link of g(d+2))
//!   g(d+4+i)    nine 32-bit range checks (i = 0..8), one inequality per group
//!   rest        padding (all selectors 0)
//! Columns: 0..12 S | 12..24 P (policy leaf, held constant) | 24 D | 25..29 SIB | 29..33 bd | 33 acc.
//! P0 = UID, P1 = v_a, P2..P9 = (S_lo,S_hi,E_lo,E_hi,T_lo,T_hi,P_lo,P_hi), P10 = level_a, P11 = blinding.

use crate::data::{Rng, MAX_ATTR};
use crate::prove::{default_options, prove_trace, verify_proof};
use crate::rescue::{ark_periodic, perm, perm_states, round_constraints, F, GROUP, W};
use winterfell::{
    math::{FieldElement, StarkField, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, Proof, ProofOptions, TraceInfo, TraceTable,
    TransitionConstraintDegree,
};

pub const WIDTH: usize = 34;
const C_P: usize = 12;
const C_D: usize = 24;
const C_SIB: usize = 25;
const C_BD: usize = 29;
const C_ACC: usize = 33;

pub const DOM_LEAF: u64 = 0x5051_5a4c; // "PQZL"
pub const DOM_MERGE: u64 = 0x5051_5a4d; // "PQZM"
pub const DOM_BIND: u64 = 0x5051_5a42; // "PQZB"

const N_RANGE: usize = 9;

/// Policy leaf, private witness (UID and v_a are also public).
#[derive(Clone, Debug)]
pub struct PolicyLeaf {
    pub uid: u64,
    pub v_a: u64,
    pub s: (u64, u64),
    pub e: (u64, u64),
    pub t: (u64, u64),
    pub p: (u64, u64),
    pub level: u64,
    pub blind: u64,
}

impl PolicyLeaf {
    pub fn to_p(&self) -> [F; 12] {
        [
            F::new(self.uid),
            F::new(self.v_a),
            F::new(self.s.0),
            F::new(self.s.1),
            F::new(self.e.0),
            F::new(self.e.1),
            F::new(self.t.0),
            F::new(self.t.1),
            F::new(self.p.0),
            F::new(self.p.1),
            F::new(self.level),
            F::new(self.blind),
        ]
    }
}

/// The audit request's scope, public.
#[derive(Clone, Debug)]
pub struct ScopeQ {
    pub s: (u64, u64),
    pub e: (u64, u64),
    pub t: (u64, u64),
    pub p: u64,
    pub level: u64,
}

#[derive(Clone, Debug)]
pub struct AuthPublic {
    pub depth: usize,
    pub r_pol: [F; 4],
    pub b_q: [F; 4],
    pub d_q: [F; 4],
    pub omega: [F; 4],
    pub uid: u64,
    pub v_a: u64,
    pub v_auth: u64,
    pub scope: ScopeQ,
}

impl ToElements<F> for AuthPublic {
    fn to_elements(&self) -> Vec<F> {
        let mut v = vec![F::new(self.depth as u64)];
        v.extend_from_slice(&self.r_pol);
        v.extend_from_slice(&self.b_q);
        v.extend_from_slice(&self.d_q);
        v.extend_from_slice(&self.omega);
        for x in [
            self.uid, self.v_a, self.v_auth, self.scope.s.0, self.scope.s.1, self.scope.e.0,
            self.scope.e.1, self.scope.t.0, self.scope.t.1, self.scope.p, self.scope.level,
        ] {
            v.push(F::new(x));
        }
        v
    }
}

/// Range checks: (P index, sign, public value). diff = sign * (P - pub) must be in [0, 2^32).
fn range_list(sc: &ScopeQ) -> [(usize, bool, u64); N_RANGE] {
    // sign true = +1
    [
        (2, false, sc.s.0),  // S_lo <= q_lo   : q_lo - P2
        (3, true, sc.s.1),   // q_hi <= S_hi   : P3 - q_hi
        (4, false, sc.e.0),
        (5, true, sc.e.1),
        (6, false, sc.t.0),
        (7, true, sc.t.1),
        (8, false, sc.p),    // P_lo <= p
        (9, true, sc.p),     // p <= P_hi
        (10, true, sc.level), // level_Q <= level_a
    ]
}

fn signed(sign: bool, x: F) -> F {
    if sign {
        x
    } else {
        -x
    }
}

pub struct AuthAir {
    context: AirContext<F>,
    p: AuthPublic,
}

impl AuthAir {
    fn n_hash_groups(&self) -> usize {
        self.p.depth + 4
    }
    fn first_range_group(&self) -> usize {
        self.p.depth + 4
    }
}

pub fn n_groups_auth(depth: usize) -> usize {
    depth + 4 + N_RANGE
}

pub fn auth_rows(depth: usize) -> usize {
    (n_groups_auth(depth) * GROUP).next_power_of_two().max(32)
}

impl Air for AuthAir {
    type BaseField = F;
    type PublicInputs = AuthPublic;

    fn new(trace_info: TraceInfo, p: AuthPublic, options: ProofOptions) -> Self {
        assert_eq!(WIDTH, trace_info.width());
        assert_eq!(trace_info.length(), auth_rows(p.depth));
        let n = trace_info.length();
        let cn = || vec![n];
        let wc = |base| TransitionConstraintDegree::with_cycles(base, cn());
        let mut d = Vec::new();
        for _ in 0..W {
            d.push(wc(7)); // Rescue round (selector is full length)
        }
        for _ in 0..12 {
            d.push(TransitionConstraintDegree::new(1)); // P held constant
        }
        for _ in 0..8 {
            d.push(wc(1)); // leaf rate = P0..P7 at row 0
        }
        for _ in 0..12 {
            d.push(wc(1)); // absorb P8..P11
        }
        for _ in 0..4 {
            d.push(wc(1)); // merge: capacity reset
        }
        for _ in 0..8 {
            d.push(wc(2)); // merge: ordered children
        }
        d.push(wc(2)); // D boolean on merge links
        for _ in 0..12 {
            d.push(wc(1)); // absorb public words for B_Q
        }
        d.push(wc(1)); // range: acc update
        d.push(wc(1)); // range: final check
        d.push(wc(1)); // range: acc reset
        for _ in 0..4 {
            d.push(TransitionConstraintDegree::new(2)); // bits boolean
        }
        let n_assert = 4 + 2 + 4 + 4 + 8 + 4 + 1;
        AuthAir { context: AirContext::new(trace_info, d, n_assert, options), p }
    }

    fn evaluate_transition<E: FieldElement + From<F>>(
        &self,
        frame: &EvaluationFrame<E>,
        pv: &[E],
        out: &mut [E],
    ) {
        // periodic: 0 hash_round, 1 sel_leaf0, 2 sel_absleaf, 3 sel_merge, 4 sel_absb, 5 sel_rround,
        // 6 sel_rlink, 7..16 psel (P2..P10), 16 pubterm, 17..41 ark
        let cur = frame.current();
        let next = frame.next();
        let ark1 = &pv[17..17 + W];
        let ark2 = &pv[17 + W..17 + 2 * W];
        round_constraints(&cur[..W], &next[..W], ark1, ark2, pv[0], &mut out[..W]);
        let one = E::ONE;
        let mut o = W;
        for j in 0..12 {
            out[o + j] = next[C_P + j] - cur[C_P + j];
        }
        o += 12;
        for j in 0..8 {
            out[o + j] = pv[1] * (cur[4 + j] - cur[C_P + j]);
        }
        o += 8;
        // absorb leaf part 2
        for j in 0..4 {
            out[o + j] = pv[2] * (next[j] - cur[j]);
        }
        for j in 0..4 {
            out[o + 4 + j] = pv[2] * (next[4 + j] - cur[4 + j] - cur[C_P + 8 + j]);
        }
        for j in 0..4 {
            out[o + 8 + j] = pv[2] * (next[8 + j] - cur[8 + j]);
        }
        o += 12;
        // merge: cap = [DOM_MERGE,0,0,0], rate = (left, right) with left = D ? sib : digest
        let dir = cur[C_D];
        out[o] = pv[3] * (next[0] - E::from(F::new(DOM_MERGE)));
        for j in 1..4 {
            out[o + j] = pv[3] * next[j];
        }
        for j in 0..4 {
            let dg = cur[4 + j];
            let sb = cur[C_SIB + j];
            out[o + 4 + j] = pv[3] * (next[4 + j] - (dg + dir * (sb - dg)));
            out[o + 8 + j] = pv[3] * (next[8 + j] - (sb + dir * (dg - sb)));
        }
        o += 12;
        out[o] = pv[3] * dir * (dir - one);
        o += 1;
        // absorb B_Q part 2: cap kept, rate[0..4] += R_pol, rate[4..8] += Omega
        for j in 0..4 {
            out[o + j] = pv[4] * (next[j] - cur[j]);
        }
        for j in 0..4 {
            out[o + 4 + j] = pv[4] * (next[4 + j] - cur[4 + j] - E::from(self.p.r_pol[j]));
        }
        for j in 0..4 {
            out[o + 8 + j] = pv[4] * (next[8 + j] - cur[8 + j] - E::from(self.p.omega[j]));
        }
        o += 12;
        // range checks
        let sixteen = E::from(F::new(16));
        let two = one + one;
        let four = two + two;
        let eight = four + four;
        let b = &cur[C_BD..C_BD + 4];
        let chunk = eight * b[0] + four * b[1] + two * b[2] + b[3];
        out[o] = pv[5] * (next[C_ACC] - sixteen * cur[C_ACC] - chunk);
        let mut sel_p = E::ZERO;
        for i in 0..9 {
            sel_p += pv[7 + i] * cur[C_P + 2 + i];
        }
        out[o + 1] = pv[6] * (sixteen * cur[C_ACC] + chunk) - sel_p + pv[16];
        out[o + 2] = pv[6] * next[C_ACC];
        o += 3;
        for i in 0..4 {
            out[o + i] = b[i] * (b[i] - one);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<F>> {
        let d = self.p.depth;
        let mut a = Vec::new();
        for j in 0..4 {
            a.push(Assertion::single(j, 0, if j == 0 { F::new(DOM_LEAF) } else { F::ZERO }));
        }
        a.push(Assertion::single(C_P, 0, F::new(self.p.uid)));
        a.push(Assertion::single(C_P + 1, 0, F::new(self.p.v_a)));
        let merge_end = (d + 2) * GROUP - 1;
        for j in 0..4 {
            a.push(Assertion::single(4 + j, merge_end, self.p.r_pol[j]));
        }
        let b1 = (d + 2) * GROUP;
        for j in 0..4 {
            a.push(Assertion::single(j, b1, if j == 0 { F::new(DOM_BIND) } else { F::ZERO }));
        }
        let b_in = [
            self.p.d_q[0], self.p.d_q[1], self.p.d_q[2], self.p.d_q[3],
            F::new(self.p.uid), F::new(self.p.v_a), F::new(self.p.v_auth), F::ZERO,
        ];
        for j in 0..8 {
            a.push(Assertion::single(4 + j, b1, b_in[j]));
        }
        let b_end = (d + 4) * GROUP - 1;
        for j in 0..4 {
            a.push(Assertion::single(4 + j, b_end, self.p.b_q[j]));
        }
        a.push(Assertion::single(C_ACC, (d + 4) * GROUP, F::ZERO));
        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<F>> {
        let d = self.p.depth;
        let n = self.trace_length();
        let mut hash_round = vec![F::ZERO; n];
        let mut sel_leaf0 = vec![F::ZERO; n];
        let mut sel_absleaf = vec![F::ZERO; n];
        let mut sel_merge = vec![F::ZERO; n];
        let mut sel_absb = vec![F::ZERO; n];
        let mut sel_rround = vec![F::ZERO; n];
        let mut sel_rlink = vec![F::ZERO; n];
        let mut psel = vec![vec![F::ZERO; n]; 9];
        let mut pubterm = vec![F::ZERO; n];
        for g in 0..self.n_hash_groups() {
            for r in 0..GROUP - 1 {
                hash_round[g * GROUP + r] = F::ONE;
            }
        }
        sel_leaf0[0] = F::ONE;
        sel_absleaf[GROUP - 1] = F::ONE;
        for g in 1..=d {
            sel_merge[g * GROUP + GROUP - 1] = F::ONE;
        }
        sel_absb[(d + 2) * GROUP + GROUP - 1] = F::ONE;
        let rl = range_list(&self.p.scope);
        for (i, (pidx, sign, pubv)) in rl.iter().enumerate() {
            let g = self.first_range_group() + i;
            for r in 0..GROUP - 1 {
                sel_rround[g * GROUP + r] = F::ONE;
            }
            let row = g * GROUP + GROUP - 1;
            sel_rlink[row] = F::ONE;
            let sg = signed(*sign, F::ONE);
            psel[pidx - 2][row] = sg;
            pubterm[row] = sg * F::new(*pubv);
        }
        let mut cols = vec![
            hash_round, sel_leaf0, sel_absleaf, sel_merge, sel_absb, sel_rround, sel_rlink,
        ];
        cols.extend(psel);
        cols.push(pubterm);
        cols.extend(ark_periodic());
        cols
    }

    fn context(&self) -> &AirContext<F> {
        &self.context
    }
}

// ---------------------------------------------------------------------------------------------
// Reference code (library permutation) and honest instance construction
// ---------------------------------------------------------------------------------------------

fn leaf_hash(p: &[F; 12]) -> [F; 4] {
    let mut s = [F::ZERO; W];
    s[0] = F::new(DOM_LEAF);
    s[4..12].copy_from_slice(&p[..8]);
    perm(&mut s);
    for j in 0..4 {
        s[4 + j] += p[8 + j];
    }
    perm(&mut s);
    [s[4], s[5], s[6], s[7]]
}

fn merge_hash(left: [F; 4], right: [F; 4]) -> [F; 4] {
    let mut s = [F::ZERO; W];
    s[0] = F::new(DOM_MERGE);
    s[4..8].copy_from_slice(&left);
    s[8..12].copy_from_slice(&right);
    perm(&mut s);
    [s[4], s[5], s[6], s[7]]
}

pub fn bind_hash(d_q: [F; 4], uid: u64, v_a: u64, v_auth: u64, r_pol: [F; 4], omega: [F; 4]) -> [F; 4] {
    let mut s = [F::ZERO; W];
    s[0] = F::new(DOM_BIND);
    s[4..8].copy_from_slice(&d_q);
    s[8] = F::new(uid);
    s[9] = F::new(v_a);
    s[10] = F::new(v_auth);
    perm(&mut s);
    for j in 0..4 {
        s[4 + j] += r_pol[j];
        s[8 + j] += omega[j];
    }
    perm(&mut s);
    [s[4], s[5], s[6], s[7]]
}

/// Private witness of R_Auth.
#[derive(Clone, Debug)]
pub struct AuthWitness {
    pub leaf: PolicyLeaf,
    pub index: u64,
    pub siblings: Vec<[F; 4]>,
}

fn rand_digest(rng: &mut Rng) -> [F; 4] {
    let mut d = [F::ZERO; 4];
    for x in d.iter_mut() {
        *x = F::new(rng.next_u64() % F::MODULUS);
    }
    d
}

/// Honest instance: a policy leaf that covers `scope`, a depth-`depth` Merkle path with pseudo-random siblings
/// (the other leaves of the policy tree are not materialised; membership is proven for whatever the siblings are).
pub fn honest_auth_instance(depth: usize, seed: u64) -> (AuthPublic, AuthWitness) {
    let mut rng = Rng::new(seed);
    let scope = ScopeQ { s: (1000, 2000), e: (3, 5), t: (100, 900), p: 4, level: 2 };
    let leaf = PolicyLeaf {
        uid: 42,
        v_a: 3,
        s: (500, 4000),
        e: (1, 8),
        t: (0, 5000),
        p: (0, 7),
        level: 3,
        blind: rng.next_u64() % F::MODULUS,
    };
    let index = rng.next_u64() & ((1u64 << depth) - 1);
    let siblings: Vec<[F; 4]> = (0..depth).map(|_| rand_digest(&mut rng)).collect();
    let r_pol = root_of(&leaf, index, &siblings);
    let d_q = rand_digest(&mut rng);
    let omega = rand_digest(&mut rng);
    let v_auth = 9;
    let b_q = bind_hash(d_q, leaf.uid, leaf.v_a, v_auth, r_pol, omega);
    let pubin = AuthPublic { depth, r_pol, b_q, d_q, omega, uid: leaf.uid, v_a: leaf.v_a, v_auth, scope };
    (pubin, AuthWitness { leaf, index, siblings })
}

pub fn root_of(leaf: &PolicyLeaf, index: u64, siblings: &[[F; 4]]) -> [F; 4] {
    let mut cur = leaf_hash(&leaf.to_p());
    for (i, sib) in siblings.iter().enumerate() {
        let bit = (index >> i) & 1 == 1;
        cur = if bit { merge_hash(*sib, cur) } else { merge_hash(cur, *sib) };
    }
    cur
}

pub fn build_auth_trace(p: &AuthPublic, w: &AuthWitness) -> TraceTable<F> {
    let d = p.depth;
    assert_eq!(w.siblings.len(), d);
    let n = auth_rows(d);
    let mut cols = vec![vec![F::ZERO; n]; WIDTH];
    let pv = w.leaf.to_p();
    // P held constant
    for j in 0..12 {
        for row in 0..n {
            cols[C_P + j][row] = pv[j];
        }
    }
    let put = |cols: &mut Vec<Vec<F>>, g: usize, s0: [F; W]| -> [F; W] {
        let st = perm_states(s0);
        for r in 0..GROUP {
            for j in 0..W {
                cols[j][g * GROUP + r] = st[r][j];
            }
        }
        st[GROUP - 1]
    };
    // g0
    let mut s = [F::ZERO; W];
    s[0] = F::new(DOM_LEAF);
    s[4..12].copy_from_slice(&pv[..8]);
    let mut out = put(&mut cols, 0, s);
    // g1
    let mut s1 = out;
    for j in 0..4 {
        s1[4 + j] += pv[8 + j];
    }
    out = put(&mut cols, 1, s1);
    // merges: group g (2..=d+1) built from output of group g-1, with D/SIB set on row 7 of group g-1
    for i in 0..d {
        let g = 2 + i;
        let bit = (w.index >> i) & 1 == 1;
        let sib = w.siblings[i];
        let row7 = (g - 1) * GROUP + GROUP - 1;
        cols[C_D][row7] = if bit { F::ONE } else { F::ZERO };
        for j in 0..4 {
            cols[C_SIB + j][row7] = sib[j];
        }
        let dg = [out[4], out[5], out[6], out[7]];
        let (l, r) = if bit { (sib, dg) } else { (dg, sib) };
        let mut sm = [F::ZERO; W];
        sm[0] = F::new(DOM_MERGE);
        sm[4..8].copy_from_slice(&l);
        sm[8..12].copy_from_slice(&r);
        out = put(&mut cols, g, sm);
    }
    // B_Q part 1 (fresh)
    let mut sb = [F::ZERO; W];
    sb[0] = F::new(DOM_BIND);
    sb[4..8].copy_from_slice(&p.d_q);
    sb[8] = F::new(p.uid);
    sb[9] = F::new(p.v_a);
    sb[10] = F::new(p.v_auth);
    let mut out2 = put(&mut cols, d + 2, sb);
    for j in 0..4 {
        out2[4 + j] += p.r_pol[j];
        out2[8 + j] += p.omega[j];
    }
    put(&mut cols, d + 3, out2);
    // range groups
    let rl = range_list(&p.scope);
    for (i, (pidx, sign, pubv)) in rl.iter().enumerate() {
        let g = d + 4 + i;
        let diff = signed(*sign, pv[*pidx] - F::new(*pubv)).as_int();
        let mut acc = 0u64;
        for r in 0..GROUP {
            let row = g * GROUP + r;
            cols[C_ACC][row] = F::new(acc);
            let mut ch = 0u64;
            for k in 0..4 {
                let bit = (diff >> (31 - 4 * r - k)) & 1; // low 32 bits only; wrong diff => constraint fails
                cols[C_BD + k][row] = F::new(bit);
                ch = 2 * ch + bit;
            }
            acc = 16 * acc + ch;
        }
    }
    TraceTable::init(cols)
}

pub fn prove_auth_with(
    p: &AuthPublic,
    w: &AuthWitness,
    options: ProofOptions,
) -> Result<Proof, String> {
    assert!(
        [p.scope.s.0, p.scope.s.1, p.scope.e.0, p.scope.e.1, p.scope.t.0, p.scope.t.1, p.scope.p, p.scope.level]
            .iter()
            .all(|&x| x < MAX_ATTR)
    );
    prove_trace::<AuthAir>(build_auth_trace(p, w), p.clone(), options)
}

pub fn prove_auth(p: &AuthPublic, w: &AuthWitness) -> Result<Proof, String> {
    prove_auth_with(p, w, default_options())
}

pub fn verify_auth(proof: Proof, p: AuthPublic, min_bits: u32) -> Result<(), String> {
    verify_proof::<AuthAir>(proof, p, min_bits)
}
