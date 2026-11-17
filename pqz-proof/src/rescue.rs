//! Shared Rescue-Prime (winter-crypto `Rp64_256`, 12 elements, 7 rounds, alpha = 7) AIR gadget.
//!
//! One permutation occupies 8 trace rows (a "group"): row 0 holds the input state, row r+1 the state after
//! round r (r = 0..6), so row 7 holds the permutation output. The transition row r -> r+1 (r < 7) enforces one
//! round; the transition row 7 -> next group's row 0 (the "link row") is protocol specific.
//!
//! Round relation (same as `Rp64_256::apply_round`):  mid = MDS * cur^7 + ARK1[r];  next = MDS * mid^(1/7) + ARK2[r].
//! Written without the inverse S-box:  (INV_MDS * (next - ARK2[r]))^7 = MDS * cur^7 + ARK1[r]   (degree 7).

use winterfell::crypto::hashers::Rp64_256;
use winterfell::math::{fields::f64::BaseElement, FieldElement};

pub type F = BaseElement;
pub const W: usize = Rp64_256::STATE_WIDTH; // 12
pub const GROUP: usize = 8; // rows per permutation
pub const ROUNDS: usize = Rp64_256::NUM_ROUNDS; // 7

/// Apply the full permutation (reference, library code).
pub fn perm(state: &mut [F; W]) {
    Rp64_256::apply_permutation(state);
}

/// The 8 states of one permutation: states[0] = input, states[r+1] = after round r.
pub fn perm_states(input: [F; W]) -> [[F; W]; GROUP] {
    let mut out = [[F::ZERO; W]; GROUP];
    let mut s = input;
    out[0] = s;
    for r in 0..ROUNDS {
        Rp64_256::apply_round(&mut s, r);
        out[r + 1] = s;
    }
    out
}

/// Periodic columns (period 8): ARK1[0..12], ARK2[0..12]; row 7 entries are 0 (unused, constraint switched off).
pub fn ark_periodic() -> Vec<Vec<F>> {
    let mut cols = Vec::with_capacity(2 * W);
    for j in 0..W {
        let mut c = vec![F::ZERO; GROUP];
        for r in 0..ROUNDS {
            c[r] = Rp64_256::ARK1[r][j];
        }
        cols.push(c);
    }
    for j in 0..W {
        let mut c = vec![F::ZERO; GROUP];
        for r in 0..ROUNDS {
            c[r] = Rp64_256::ARK2[r][j];
        }
        cols.push(c);
    }
    cols
}

#[inline(always)]
fn pow7<E: FieldElement>(x: E) -> E {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x2 * x
}

/// out[i] = flag * ( (INV_MDS*(next-ark2))_i ^7 - (MDS*cur^7 + ark1)_i ),  i = 0..12.
pub fn round_constraints<E: FieldElement + From<F>>(
    cur: &[E],
    next: &[E],
    ark1: &[E],
    ark2: &[E],
    flag: E,
    out: &mut [E],
) {
    let mut c7 = [E::ZERO; W];
    let mut d = [E::ZERO; W];
    for j in 0..W {
        c7[j] = pow7(cur[j]);
        d[j] = next[j] - ark2[j];
    }
    for i in 0..W {
        let mut y = E::ZERO;
        let mut mid = ark1[i];
        for j in 0..W {
            y += E::from(Rp64_256::INV_MDS[i][j]) * d[j];
            mid += E::from(Rp64_256::MDS[i][j]) * c7[j];
        }
        out[i] = flag * (pow7(y) - mid);
    }
}
