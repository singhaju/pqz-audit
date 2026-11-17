//! Stage C: Plonky3 AIR for R_Auth (mirror of `bench/pqz-proof-w30/src/auth.rs`), see README.md for the constraint table.
//!
//! ONE row = ONE Poseidon2 permutation (w30: groups of 8 Rescue rows). Row roles (d = Merkle depth, d >= 1):
//!   row 0          leaf hash, part 1: rate = P0..P7, capacity [DOM_LEAF,0,0,0]
//!   row 1          leaf hash, part 2: input = previous output, rate[0..4] += P8..P11
//!   rows 2..d+1    Merkle merges: rate = (left, right) with left = D ? sib : dg, right = D ? dg : sib, cap [DOM_MERGE,0,0,0]
//!   row d+2        B_Q hash, part 1: rate = (d_q, uid, v_a, v_auth, 0), capacity [DOM_BIND,0,0,0]
//!   row d+3        B_Q hash, part 2: input = previous output, rate[0..4] += r_pol, rate[4..8] += omega
//!   rows d+4..d+12 nine 32-bit range checks, one inequality per row
//!   rest           padding (all flags 0, Poseidon2 input zero)
//! Sponge convention (same as R_Exec/R_RC): rate = state[0..8], capacity = state[8..12], digest = output[0..4].
//!
//! Columns: [0..P) Poseidon2 | P[12] (policy leaf, held constant) | dg[4] (previous row's output[0..4]) | D | sib[4] |
//!   bd[32] (bits of the range-check difference) | idx | invb1 | f_l1 f_l2 f_m f_b1 f_b2 f_r[9] (row-role flags) | seen.
//! Public values (28): depth, r_pol[4], b_q[4], d_q[4], omega[4], uid, v_a, v_auth, s.0 s.1 e.0 e.1 t.0 t.1, p, level.
//! Every constraint has degree <= 3.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{generate_trace_rows, Poseidon2Air, Poseidon2Cols, RoundConstants};
use p3_symmetric::Permutation;
use p3_uni_stark::SubAirBuilder;

use crate::air::MIN_ROWS;
use crate::data::{Rng, GOLDILOCKS_P, MAX_ATTR};

pub const DOM_LEAF: u64 = 0x5051_5a4c; // "PQZL" (as w30)
pub const DOM_MERGE: u64 = 0x5051_5a4d; // "PQZM"
pub const DOM_BIND: u64 = 0x5051_5a42; // "PQZB"
pub const N_RANGE: usize = 9;

/// public value indices
pub const PV_DEPTH: usize = 0;
pub const PV_RPOL: usize = 1;
pub const PV_BQ: usize = 5;
pub const PV_DQ: usize = 9;
pub const PV_OMEGA: usize = 13;
pub const PV_UID: usize = 17;
pub const PV_VA: usize = 18;
pub const PV_VAUTH: usize = 19;
pub const PV_S0: usize = 20;
pub const PV_LEVEL: usize = 27;
pub const N_PV: usize = 28;

/// (index into P, sign is +, public value index): diff = sign * (P - pub) must be in [0, 2^32) (w30 `range_list`).
pub const RANGES: [(usize, bool, usize); N_RANGE] = [
    (2, false, 20),
    (3, true, 21),
    (4, false, 22),
    (5, true, 23),
    (6, false, 24),
    (7, true, 25),
    (8, false, 26),
    (9, true, 26),
    (10, true, 27),
];

#[derive(Clone, Debug)]
pub struct AuthLayout {
    pub w: usize,
    pub p: usize,
    pub depth: usize,
    pub c_p: usize,
    pub c_dg: usize,
    pub c_d: usize,
    pub c_sib: usize,
    pub c_bd: usize,
    pub c_idx: usize,
    pub c_invb1: usize,
    pub c_fl1: usize,
    pub c_fl2: usize,
    pub c_fm: usize,
    pub c_fb1: usize,
    pub c_fb2: usize,
    pub c_fr: usize,
    pub c_seen: usize,
    pub width: usize,
}

impl AuthLayout {
    pub fn new(w: usize, p: usize, depth: usize) -> Self {
        assert_eq!(w, 12, "R_Auth is written for Poseidon2 width 12");
        assert!(depth >= 1 && depth <= 60);
        let c_p = p;
        let c_dg = c_p + 12;
        let c_d = c_dg + 4;
        let c_sib = c_d + 1;
        let c_bd = c_sib + 4;
        let c_idx = c_bd + 32;
        let c_invb1 = c_idx + 1;
        let c_fl1 = c_invb1 + 1;
        let c_fl2 = c_fl1 + 1;
        let c_fm = c_fl2 + 1;
        let c_fb1 = c_fm + 1;
        let c_fb2 = c_fb1 + 1;
        let c_fr = c_fb2 + 1;
        let c_seen = c_fr + N_RANGE;
        AuthLayout { w, p, depth, c_p, c_dg, c_d, c_sib, c_bd, c_idx, c_invb1, c_fl1, c_fl2, c_fm, c_fb1, c_fb2, c_fr, c_seen, width: c_seen + 1 }
    }
    /// trace height for depth d (w30 `auth_rows`)
    pub fn rows(depth: usize) -> usize {
        (depth + 4 + N_RANGE).next_power_of_two().max(MIN_ROWS)
    }
}

/// The audit request's scope, public (w30 `ScopeQ`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeQ {
    pub s: (u64, u64),
    pub e: (u64, u64),
    pub t: (u64, u64),
    pub p: u64,
    pub level: u64,
}

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
    pub fn to_p(&self) -> [u64; 12] {
        [
            self.uid, self.v_a, self.s.0, self.s.1, self.e.0, self.e.1, self.t.0, self.t.1, self.p.0, self.p.1, self.level,
            self.blind,
        ]
    }
}

#[derive(Clone, Debug)]
pub struct AuthPublic {
    pub depth: usize,
    pub r_pol: [u64; 4],
    pub b_q: [u64; 4],
    pub d_q: [u64; 4],
    pub omega: [u64; 4],
    pub uid: u64,
    pub v_a: u64,
    pub v_auth: u64,
    pub scope: ScopeQ,
}

impl AuthPublic {
    pub fn to_values<F: PrimeField64>(&self) -> Vec<F> {
        let mut v = vec![F::from_u64(self.depth as u64)];
        for a in [&self.r_pol, &self.b_q, &self.d_q, &self.omega] {
            v.extend(a.iter().map(|&x| F::from_u64(x)));
        }
        for x in [
            self.uid, self.v_a, self.v_auth, self.scope.s.0, self.scope.s.1, self.scope.e.0, self.scope.e.1, self.scope.t.0,
            self.scope.t.1, self.scope.p, self.scope.level,
        ] {
            v.push(F::from_u64(x));
        }
        assert_eq!(v.len(), N_PV);
        v
    }
}

/// Private witness of R_Auth.
#[derive(Clone, Debug)]
pub struct AuthWitness {
    pub leaf: PolicyLeaf,
    pub index: u64,
    pub siblings: Vec<[u64; 4]>,
}

pub struct AuthAir<
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
    pub lay: AuthLayout,
    /// prover-side minimum trace height (the verifier takes the height from the proof; hiding mode needs a taller trace)
    pub min_rows: usize,
}

impl<
        F: PrimeCharacteristicRing + Sync + Clone,
        LL,
        const W: usize,
        const SBOX: u64,
        const REG: usize,
        const HF: usize,
        const PR: usize,
    > AuthAir<F, LL, W, SBOX, REG, HF, PR>
{
    pub fn new(consts: RoundConstants<F, W, HF, PR>, depth: usize) -> Self {
        let p = p3_poseidon2_air::num_cols::<W, SBOX, REG, HF, PR>();
        AuthAir { p2: Poseidon2Air::new(consts.clone()), consts, lay: AuthLayout::new(W, p, depth), min_rows: MIN_ROWS }
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
    > BaseAir<F> for AuthAir<F, LL, W, SBOX, REG, HF, PR>
{
    fn width(&self) -> usize {
        self.lay.width
    }
    fn num_public_values(&self) -> usize {
        N_PV
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
    > Air<AB> for AuthAir<F, LL, W, SBOX, REG, HF, PR>
{
    fn eval(&self, builder: &mut AB) {
        let lay = &self.lay;
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let pv: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let c = |x: u64| -> AB::Expr { AB::Expr::from_u64(x) };
        let one = || -> AB::Expr { AB::Expr::ONE };
        let d = lay.depth as u64;

        // ---- (A1) Poseidon2 permutation of this row
        {
            let mut sub =
                SubAirBuilder::<AB, Poseidon2Air<F, LL, W, SBOX, REG, HF, PR>, AB::Var>::new(builder, 0..lay.p);
            self.p2.eval(&mut sub);
        }
        let p2l: &Poseidon2Cols<AB::Var, W, SBOX, REG, HF, PR> = local[..lay.p].borrow();
        let p2n: &Poseidon2Cols<AB::Var, W, SBOX, REG, HF, PR> = next[..lay.p].borrow();
        let out = |i: usize| -> AB::Expr { p2l.ending_full_rounds[HF - 1].post[i].into() };
        let inp = |i: usize| -> AB::Expr { p2l.inputs[i].into() };
        let inpn = |i: usize| -> AB::Expr { p2n.inputs[i].into() };
        let col = |i: usize| -> AB::Expr { local[i].into() };
        let coln = |i: usize| -> AB::Expr { next[i].into() };
        let pvx = |i: usize| -> AB::Expr { pv[i].into() };
        let pc = |i: usize| -> AB::Expr { col(lay.c_p + i) };

        let (fl1, fl2, fm, fb1, fb2) = (col(lay.c_fl1), col(lay.c_fl2), col(lay.c_fm), col(lay.c_fb1), col(lay.c_fb2));
        let fr = |i: usize| -> AB::Expr { col(lay.c_fr + i) };
        let frn = |i: usize| -> AB::Expr { coln(lay.c_fr + i) };

        // ---- (A2) row-role flags: first row, recurrences, "row d+2" pinned by the counter
        {
            let mut b = builder.when_first_row();
            b.assert_zero(fl1.clone() - one());
            b.assert_zero(fl2.clone());
            b.assert_zero(fm.clone());
            b.assert_zero(fb1.clone());
            b.assert_zero(fb2.clone());
            for i in 0..N_RANGE {
                b.assert_zero(fr(i));
            }
            b.assert_zero(col(lay.c_seen) - fr(N_RANGE - 1));
            b.assert_zero(col(lay.c_idx));
            b.assert_zero(pc(0) - pvx(PV_UID));
            b.assert_zero(pc(1) - pvx(PV_VA));
        }
        {
            let mut b = builder.when_transition();
            b.assert_zero(coln(lay.c_fl1));
            b.assert_zero(coln(lay.c_fl2) - fl1.clone());
            b.assert_zero(coln(lay.c_fm) - fm.clone() - fl2.clone() + coln(lay.c_fb1));
            b.assert_zero(coln(lay.c_fb2) - fb1.clone());
            b.assert_zero(frn(0) - fb2.clone());
            for i in 1..N_RANGE {
                b.assert_zero(frn(i) - fr(i - 1));
            }
            b.assert_zero(coln(lay.c_idx) - col(lay.c_idx) - one());
            b.assert_zero(coln(lay.c_seen) - col(lay.c_seen) - frn(N_RANGE - 1));
            for i in 0..12 {
                b.assert_zero(coln(lay.c_p + i) - pc(i)); // policy leaf held constant
            }
            for j in 0..4 {
                b.assert_zero(coln(lay.c_dg + j) - out(j)); // dg = previous row's digest
            }
        }
        builder.when_last_row().assert_zero(col(lay.c_seen) - one());
        {
            // f_b1 = 1 iff idx == d + 2
            let diff = col(lay.c_idx) - c(d + 2);
            builder.assert_zero(fb1.clone() * diff.clone());
            builder.assert_zero(diff * col(lay.c_invb1) - (one() - fb1.clone()));
        }

        // ---- (A3) hash chain
        {
            // leaf part 1 (row 0): rate = P0..P7, capacity [DOM_LEAF, 0, 0, 0]
            let mut b = builder.when_first_row();
            for j in 0..8 {
                b.assert_zero(inp(j) - pc(j));
            }
            b.assert_zero(inp(8) - c(DOM_LEAF));
            for j in 9..12 {
                b.assert_zero(inp(j));
            }
        }
        {
            // leaf part 2 (next row is row 1) and B_Q part 2 (next row is row d+3): previous output plus absorbed words
            let (fl2n, fb2n) = (coln(lay.c_fl2), coln(lay.c_fb2));
            let mut b = builder.when_transition();
            for j in 0..12 {
                let add1 = if j < 4 { pc(8 + j) } else { AB::Expr::ZERO };
                b.assert_zero(fl2n.clone() * (inpn(j) - out(j) - add1));
                let add2 = if j < 4 {
                    pvx(PV_RPOL + j)
                } else if j < 8 {
                    pvx(PV_OMEGA + j - 4)
                } else {
                    AB::Expr::ZERO
                };
                b.assert_zero(fb2n.clone() * (inpn(j) - out(j) - add2));
            }
        }
        {
            // merges (rows 2..d+1): left = D ? sib : dg, right = D ? dg : sib, capacity [DOM_MERGE, 0, 0, 0]
            let dir = col(lay.c_d);
            builder.assert_zero(fm.clone() * dir.clone() * (dir.clone() - one()));
            for j in 0..4 {
                let dg = col(lay.c_dg + j);
                let sb = col(lay.c_sib + j);
                builder.assert_zero(fm.clone() * (inp(j) - (dg.clone() + dir.clone() * (sb.clone() - dg.clone()))));
                builder.assert_zero(fm.clone() * (inp(4 + j) - (sb.clone() + dir.clone() * (dg - sb))));
            }
            builder.assert_zero(fm.clone() * (inp(8) - c(DOM_MERGE)));
            for j in 9..12 {
                builder.assert_zero(fm.clone() * inp(j));
            }
        }
        {
            // Merkle root (digest of row d+1 = dg of row d+2) and B_Q part 1 (row d+2): all inputs public
            for j in 0..4 {
                builder.assert_zero(fb1.clone() * (col(lay.c_dg + j) - pvx(PV_RPOL + j)));
                builder.assert_zero(fb1.clone() * (inp(j) - pvx(PV_DQ + j)));
            }
            builder.assert_zero(fb1.clone() * (inp(4) - pvx(PV_UID)));
            builder.assert_zero(fb1.clone() * (inp(5) - pvx(PV_VA)));
            builder.assert_zero(fb1.clone() * (inp(6) - pvx(PV_VAUTH)));
            builder.assert_zero(fb1.clone() * inp(7));
            builder.assert_zero(fb1.clone() * (inp(8) - c(DOM_BIND)));
            for j in 9..12 {
                builder.assert_zero(fb1.clone() * inp(j));
            }
            // B_Q = digest of row d+3
            for j in 0..4 {
                builder.assert_zero(fb2.clone() * (out(j) - pvx(PV_BQ + j)));
            }
        }

        // ---- (A4) range checks: bits boolean on every row, one inequality per range row
        for k in 0..32 {
            let x = col(lay.c_bd + k);
            builder.assert_zero(x.clone() * (x - one()));
        }
        let mut sum = AB::Expr::ZERO;
        for k in 0..32 {
            sum += col(lay.c_bd + k) * c(1u64 << k);
        }
        for (i, &(pi, plus, pvi)) in RANGES.iter().enumerate() {
            let diff = if plus { pc(pi) - pvx(pvi) } else { pvx(pvi) - pc(pi) };
            builder.assert_zero(fr(i) * (sum.clone() - diff));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Native side (reference hashes), generic over the permutation
// ---------------------------------------------------------------------------------------------

fn f<F: PrimeField64>(x: u64) -> F {
    F::from_u64(x)
}
fn digest_of<F: PrimeField64>(s: &[F; 12]) -> [u64; 4] {
    [0, 1, 2, 3].map(|j| s[j].as_canonical_u64())
}

pub fn leaf_hash<F: PrimeField64, P: Permutation<[F; 12]>>(perm: &P, p: &[u64; 12]) -> [u64; 4] {
    let mut s = [F::ZERO; 12];
    for j in 0..8 {
        s[j] = f(p[j]);
    }
    s[8] = f(DOM_LEAF);
    perm.permute_mut(&mut s);
    for j in 0..4 {
        s[j] += f::<F>(p[8 + j]);
    }
    perm.permute_mut(&mut s);
    digest_of(&s)
}

pub fn merge_hash<F: PrimeField64, P: Permutation<[F; 12]>>(perm: &P, left: [u64; 4], right: [u64; 4]) -> [u64; 4] {
    let mut s = [F::ZERO; 12];
    for j in 0..4 {
        s[j] = f(left[j]);
        s[4 + j] = f(right[j]);
    }
    s[8] = f(DOM_MERGE);
    perm.permute_mut(&mut s);
    digest_of(&s)
}

pub fn bind_hash<F: PrimeField64, P: Permutation<[F; 12]>>(
    perm: &P,
    d_q: [u64; 4],
    uid: u64,
    v_a: u64,
    v_auth: u64,
    r_pol: [u64; 4],
    omega: [u64; 4],
) -> [u64; 4] {
    let mut s = [F::ZERO; 12];
    for j in 0..4 {
        s[j] = f(d_q[j]);
    }
    s[4] = f(uid);
    s[5] = f(v_a);
    s[6] = f(v_auth);
    s[8] = f(DOM_BIND);
    perm.permute_mut(&mut s);
    for j in 0..4 {
        s[j] += f::<F>(r_pol[j]);
        s[4 + j] += f::<F>(omega[j]);
    }
    perm.permute_mut(&mut s);
    digest_of(&s)
}

pub fn root_of<F: PrimeField64, P: Permutation<[F; 12]>>(
    perm: &P,
    leaf: &PolicyLeaf,
    index: u64,
    siblings: &[[u64; 4]],
) -> [u64; 4] {
    let mut cur = leaf_hash::<F, P>(perm, &leaf.to_p());
    for (i, sib) in siblings.iter().enumerate() {
        let bit = (index >> i) & 1 == 1;
        cur = if bit { merge_hash::<F, P>(perm, *sib, cur) } else { merge_hash::<F, P>(perm, cur, *sib) };
    }
    cur
}

fn rand_digest(rng: &mut Rng) -> [u64; 4] {
    [0; 4].map(|_| rng.next_u64() % GOLDILOCKS_P)
}

/// Honest instance (same constants and draw order as w30 `honest_auth_instance`): a policy leaf that covers the scope,
/// a depth-`depth` Merkle path with pseudo-random siblings.
pub fn honest_auth_instance<F: PrimeField64, P: Permutation<[F; 12]>>(
    perm: &P,
    depth: usize,
    seed: u64,
) -> (AuthPublic, AuthWitness) {
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
        blind: rng.next_u64() % GOLDILOCKS_P,
    };
    let index = rng.next_u64() & ((1u64 << depth) - 1);
    let siblings: Vec<[u64; 4]> = (0..depth).map(|_| rand_digest(&mut rng)).collect();
    let r_pol = root_of::<F, P>(perm, &leaf, index, &siblings);
    let d_q = rand_digest(&mut rng);
    let omega = rand_digest(&mut rng);
    let v_auth = 9;
    let b_q = bind_hash::<F, P>(perm, d_q, leaf.uid, leaf.v_a, v_auth, r_pol, omega);
    let pubin = AuthPublic { depth, r_pol, b_q, d_q, omega, uid: leaf.uid, v_a: leaf.v_a, v_auth, scope };
    (pubin, AuthWitness { leaf, index, siblings })
}

impl<
        F: PrimeField64,
        LL: GenericPoseidon2LinearLayers<W> + Sync,
        const W: usize,
        const SBOX: u64,
        const REG: usize,
        const HF: usize,
        const PR: usize,
    > AuthAir<F, LL, W, SBOX, REG, HF, PR>
{
    /// Witness generation (honest for whatever witness is given; a wrong witness violates the constraint it breaks).
    /// Errors (like w30): a scope value of 2^32 or more is refused by the prover.
    pub fn build_trace<P: Permutation<[F; W]>>(
        &self,
        perm: &P,
        p: &AuthPublic,
        w: &AuthWitness,
    ) -> Result<RowMajorMatrix<F>, String> {
        let lay = &self.lay;
        let d = lay.depth;
        if p.depth != d || w.siblings.len() != d {
            return Err("depth mismatch".into());
        }
        let sc = &p.scope;
        if ![sc.s.0, sc.s.1, sc.e.0, sc.e.1, sc.t.0, sc.t.1, sc.p, sc.level].iter().all(|&x| x < MAX_ATTR) {
            return Err("scope value >= 2^32".into());
        }
        let n_rows = (d + 4 + N_RANGE).next_power_of_two().max(self.min_rows);
        let pv = w.leaf.to_p();
        let fe = |x: u64| F::from_u64(x);
        // permutation inputs per row
        let mut ins: Vec<[F; W]> = vec![[F::ZERO; W]; n_rows];
        let mut dirs = vec![0u64; n_rows];
        let mut sibs = vec![[0u64; 4]; n_rows];
        let step = |s: &[F; W]| -> [F; W] {
            let mut t = *s;
            perm.permute_mut(&mut t);
            t
        };
        let mut s = [F::ZERO; W];
        for j in 0..8 {
            s[j] = fe(pv[j]);
        }
        s[8] = fe(DOM_LEAF);
        ins[0] = s;
        let mut o = step(&ins[0]);
        let mut s1 = o;
        for j in 0..4 {
            s1[j] += fe(pv[8 + j]);
        }
        ins[1] = s1;
        o = step(&ins[1]);
        for i in 0..d {
            let r = 2 + i;
            let bit = (w.index >> i) & 1 == 1;
            let sib = w.siblings[i];
            dirs[r] = bit as u64;
            sibs[r] = sib;
            let dg = [o[0], o[1], o[2], o[3]];
            let mut sm = [F::ZERO; W];
            for j in 0..4 {
                let (l, rr) = if bit { (fe(sib[j]), dg[j]) } else { (dg[j], fe(sib[j])) };
                sm[j] = l;
                sm[4 + j] = rr;
            }
            sm[8] = fe(DOM_MERGE);
            ins[r] = sm;
            o = step(&ins[r]);
        }
        let mut sb = [F::ZERO; W];
        for j in 0..4 {
            sb[j] = fe(p.d_q[j]);
        }
        sb[4] = fe(p.uid);
        sb[5] = fe(p.v_a);
        sb[6] = fe(p.v_auth);
        sb[8] = fe(DOM_BIND);
        ins[d + 2] = sb;
        o = step(&ins[d + 2]);
        let mut sb2 = o;
        for j in 0..4 {
            sb2[j] += fe(p.r_pol[j]);
            sb2[4 + j] += fe(p.omega[j]);
        }
        ins[d + 3] = sb2;

        let p2 = generate_trace_rows::<F, LL, W, SBOX, REG, HF, PR>(ins.clone(), &self.consts, 0);
        assert_eq!(p2.width, lay.p);
        let pubvals = p.to_values::<F>();
        let mut vals = vec![F::ZERO; n_rows * lay.width];
        let mut prev_out = [F::ZERO; 4];
        for r in 0..n_rows {
            let row = &mut vals[r * lay.width..(r + 1) * lay.width];
            row[..lay.p].copy_from_slice(&p2.values[r * lay.p..(r + 1) * lay.p]);
            for j in 0..12 {
                row[lay.c_p + j] = fe(pv[j]);
            }
            for j in 0..4 {
                row[lay.c_dg + j] = prev_out[j];
            }
            row[lay.c_d] = fe(dirs[r]);
            for j in 0..4 {
                row[lay.c_sib + j] = fe(sibs[r][j]);
            }
            row[lay.c_idx] = F::from_u64(r as u64);
            let diff = F::from_u64(r as u64) - F::from_u64(d as u64 + 2);
            let is_b1 = r == d + 2;
            row[lay.c_invb1] = if is_b1 { F::ZERO } else { diff.inverse() };
            row[lay.c_fl1] = F::from_bool(r == 0);
            row[lay.c_fl2] = F::from_bool(r == 1);
            row[lay.c_fm] = F::from_bool(r >= 2 && r < d + 2);
            row[lay.c_fb1] = F::from_bool(is_b1);
            row[lay.c_fb2] = F::from_bool(r == d + 3);
            for i in 0..N_RANGE {
                row[lay.c_fr + i] = F::from_bool(r == d + 4 + i);
            }
            row[lay.c_seen] = F::from_bool(r >= d + 4 + N_RANGE - 1);
            if r >= d + 4 && r < d + 4 + N_RANGE {
                let (pi, plus, pvi) = RANGES[r - d - 4];
                let diffv = if plus { F::from_u64(pv[pi]) - pubvals[pvi] } else { pubvals[pvi] - F::from_u64(pv[pi]) };
                let x = diffv.as_canonical_u64();
                for k in 0..32 {
                    row[lay.c_bd + k] = F::from_u64((x >> k) & 1);
                }
            }
            // digest of this row for the dg column of the next row (rows before n_rows-1 only are used)
            let outp = step(&ins[r]);
            prev_out = [outp[0], outp[1], outp[2], outp[3]];
        }
        Ok(RowMajorMatrix::new(vals, lay.width))
    }
}
