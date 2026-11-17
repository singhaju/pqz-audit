//! w33 SPIKE (laptop only, decision only): Plonky3 0.8.0 prover for the PQZ-Audit R_Exec relation.
//! Mirror of `bench/pqz-proof-w30/src/exec.rs`; see README.md for the constraint table.

pub mod air;
pub mod auth;
pub mod chunk;
pub mod data;
pub mod psponge;
pub mod rc;
pub mod rel;
pub mod request;
pub mod run;
pub mod security;
pub mod variants;

pub use variants::{c1, c1r0, c1zk, c2, FriOpts};
