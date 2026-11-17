//! Stage C: prove / verify wrappers for R_RC and R_Auth, plain (`c1`) and hiding / zero-knowledge (`c1zk`) mode.
//! R_Exec uses `c1::prove_with` / `c1zk::prove_with` from variants.rs (unchanged since stage B).
//! The verifier builds its own AIR and its own FRI parameters (`FriOpts` of the caller), so a proof made with other
//! FRI parameters (fewer queries, less grinding, other blowup) is rejected: the same rule as w30 Phase 7.

use p3_uni_stark::{prove, verify};

use crate::air::{native_digest, Layout};
use crate::auth::{AuthAir, AuthPublic, AuthWitness};
use crate::rc::{RcAir, RcPublic};
use crate::variants::FriOpts;

pub type LL = p3_goldilocks::GenericPoseidon2LinearLayersGoldilocks;

/// Largest Merkle depth the verifier accepts (the public value `depth` is the verifier's own input).
pub const MAX_DEPTH: usize = 40;

/// Run a verifier call; a panic inside it (malformed proof) is reported as a rejection, as the w30 verifier does
/// (`rejected: verifier panicked on malformed input`).
pub fn guard(f: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => Err("rejected: verifier panicked on malformed input".into()),
    }
}

macro_rules! rel {
    ($m:ident, $base:ident, $minrows:literal, $minrows_hi:literal, $minrows_xhi:literal) => {
        pub mod $m {
            use super::*;
            pub use crate::variants::$base::{config, consts, from_bytes, perm, to_bytes, Val, P, SC, HF, PR, REG, SBOX, W};

            pub type RcA = RcAir<Val, LL, W, { SBOX }, REG, { HF }, { PR }>;
            pub type AuthA = AuthAir<Val, LL, W, { SBOX }, REG, { HF }, { PR }>;

            pub fn rc_air(block_size: u64, n_words: u64) -> RcA {
                RcA::new(consts(), block_size, n_words)
            }
            pub fn auth_air(depth: usize) -> AuthA {
                let mut a = AuthA::new(consts(), depth);
                a.min_rows = $minrows;
                a
            }
            /// Prover-side R_Auth AIR for the options `o`. w34: more queries than the default (`fri=hi`) need a larger minimum height
            /// in hiding mode (the verifier reads the height from the proof, so `auth_air` is still the verifier's AIR).
            /// Default options: identical to `auth_air`.
            pub fn auth_air_for(o: &FriOpts, depth: usize) -> AuthA {
                let mut a = auth_air(depth);
                if o.num_queries > FriOpts::default().num_queries {
                    a.min_rows = $minrows_hi;
                }
                // w36: fast1 (126 queries) needs 512 rows in hiding mode (`HidingBudgetExceeded` at 256 rows); plain mode is unaffected
                if o.num_queries > crate::variants::HI_NUM_QUERIES {
                    a.min_rows = $minrows_xhi;
                }
                a
            }
            /// Honest public statement of R_RC for a word stream (digest from the native sponge, no circuit code).
            pub fn rc_public(words: &[Vec<u64>], block_size: usize) -> RcPublic {
                let el = Layout::new(0, 12, 0);
                let digest = native_digest::<Val, 12, _>(&el, &perm(), words);
                let mut header0 = [0u64; 8];
                header0.copy_from_slice(&words[0][..8]);
                RcPublic { digest, n_blocks: words.len() / (block_size + 1), block_size, header0 }
            }
            /// Number of trace rows of R_RC.
            pub fn rc_rows(n_words: usize) -> usize {
                n_words.next_power_of_two().max(crate::air::MIN_ROWS)
            }
            pub fn prove_rc(o: &FriOpts, words: &[Vec<u64>], p: &RcPublic) -> Result<P, String> {
                if p.block_size == 0 || p.n_words() == 0 {
                    return Err("empty statement".into());
                }
                let a = rc_air(p.block_size as u64, p.n_words() as u64);
                let trace = a.build_trace(&perm(), words);
                let pv = p.to_values::<Val>(&a.lay);
                prove(&config(o), &a, trace, &pv).map_err(|e| format!("{e:?}"))
            }
            pub fn verify_rc(o: &FriOpts, proof: &P, p: &RcPublic) -> Result<(), String> {
                guard(|| verify_rc_raw(o, proof, p))
            }
            pub fn verify_rc_raw(o: &FriOpts, proof: &P, p: &RcPublic) -> Result<(), String> {
                if p.block_size == 0 || p.n_words() == 0 {
                    return Err("empty statement".into());
                }
                let a = rc_air(p.block_size as u64, p.n_words() as u64);
                let pv = p.to_values::<Val>(&a.lay);
                verify(&config(o), &a, proof, &pv).map_err(|e| format!("{e:?}"))
            }
            pub fn prove_auth(o: &FriOpts, p: &AuthPublic, w: &AuthWitness) -> Result<P, String> {
                if p.depth < 1 || p.depth > MAX_DEPTH {
                    return Err("depth out of range".into());
                }
                let a = auth_air_for(o, p.depth);
                let trace = a.build_trace(&perm(), p, w)?;
                let pv = p.to_values::<Val>();
                prove(&config(o), &a, trace, &pv).map_err(|e| format!("{e:?}"))
            }
            pub fn verify_auth(o: &FriOpts, proof: &P, p: &AuthPublic) -> Result<(), String> {
                guard(|| verify_auth_raw(o, proof, p))
            }
            pub fn verify_auth_raw(o: &FriOpts, proof: &P, p: &AuthPublic) -> Result<(), String> {
                if p.depth < 1 || p.depth > MAX_DEPTH {
                    return Err("depth out of range".into());
                }
                let a = auth_air(p.depth);
                let pv = p.to_values::<Val>();
                verify(&config(o), &a, proof, &pv).map_err(|e| format!("{e:?}"))
            }
            /// R_Exec (stage B code in variants.rs), guarded verifier.
            pub fn verify_exec(o: &FriOpts, proof: &P, p: &crate::air::ExecPublic) -> Result<(), String> {
                guard(|| crate::variants::$base::verify_with(o, proof, p))
            }
            pub fn prove_exec(o: &FriOpts, w: &crate::data::Workload, p: &crate::air::ExecPublic) -> Result<P, String> {
                crate::variants::$base::prove_with(o, w, p)
            }
            pub fn auth_rows(depth: usize) -> usize {
                crate::auth::AuthLayout::rows(depth)
            }
            pub fn rc_width() -> usize {
                rc_air(1, 1).lay.width
            }
            pub fn auth_width() -> usize {
                auth_air(1).lay.width
            }
        }
    };
}

// prover-side minimum height of the R_Auth trace: 64 (plain); the hiding PCS needs 128 rows or more
// (`HidingBudgetExceeded` at 64 rows with 40 queries).
rel!(plain, c1, 64, 64, 64);
// w34: with fri=hi (102 queries) the hiding PCS needs 256 rows for R_Auth (`HidingBudgetExceeded` at 128 rows)
// w36: fast1 (126 queries) needs 512 rows for R_Auth in hiding mode (`HidingBudgetExceeded` at 256 rows)
rel!(zk, c1zk, 128, 256, 512);
