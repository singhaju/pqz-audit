//! Common layout of the two chain-based relations (R_RC and R_Exec):
//! columns 0..12 = Rescue state S, columns 12..20 = R (the 8-element word absorbed by the NEXT group, read on
//! the link row only). Periodic columns: [fr, fl, ark1 x12, ark2 x12] (period 8).

use crate::data::{cap_init, pad_word, Word};
use crate::rescue::{ark_periodic, perm_states, F, GROUP, W};
use crate::data::Workload;
use winterfell::math::FieldElement;

pub const C_S: usize = 0;
pub const C_R: usize = 12;

pub fn chain_periodic() -> Vec<Vec<F>> {
    let mut fr = vec![F::ONE; GROUP];
    fr[GROUP - 1] = F::ZERO;
    let mut fl = vec![F::ZERO; GROUP];
    fl[GROUP - 1] = F::ONE;
    let mut cols = vec![fr, fl];
    cols.extend(ark_periodic());
    cols
}

/// Fill columns S and R for `n` rows (n = multiple of 8). Returns the extended word list (real + padding words).
pub fn fill_chain(cols: &mut [Vec<F>], w: &Workload, n: usize) -> Vec<Word> {
    let n_groups_total = n / GROUP;
    assert!(w.n_groups() <= n_groups_total);
    let mut words = w.words.clone();
    words.resize(n_groups_total, pad_word());
    let cap = cap_init(w.n_groups());
    let mut s = [F::ZERO; W];
    s[..4].copy_from_slice(&cap);
    for k in 0..n_groups_total {
        for j in 0..8 {
            s[4 + j] += words[k][j];
        }
        let states = perm_states(s);
        let next_word = if k + 1 < n_groups_total { words[k + 1] } else { pad_word() };
        for r in 0..GROUP {
            let row = k * GROUP + r;
            for j in 0..W {
                cols[C_S + j][row] = states[r][j];
            }
            for j in 0..8 {
                cols[C_R + j][row] = next_word[j];
            }
        }
        s = states[GROUP - 1];
    }
    words
}
