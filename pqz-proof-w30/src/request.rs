//! Request-level checks that tie the Auth proof and the Exec proof of ONE request together (w30 lead fix e443, after the attack
//! finding A1 of `bench/pqz-attack-w30/REPORT-w30.md`).
//!
//! Paper (journal2/pqz-audit-journal-work26.tex, eq. execution-context): C_Q = H("PQZA-EXEC" || B_Q || Auth_Q || RID_Q).
//! Mapping in this prototype (the Auth AIR has no Auth_Q or RID_Q object):
//!   * B_Q   = `AuthPublic::b_q`  (4 elements)
//!   * Auth_Q = `AuthPublic::d_q` (4 elements; the digest the Auth statement carries for the authorisation state)
//!   * RID_Q = a `u64`; 0 for a routine request (paper: bottom), the request id of the privileged operation otherwise.
//! H = native Rescue Prime sponge (`rescue::perm`, Rp64_256, 12 elements, rate 8, capacity 4), the same permutation the crate
//! uses natively for `data::chain_digest`. Fixed-length sponge: capacity = [11, 0, 0, 0] (11 = number of absorbed elements),
//! message (11 elements, in this order) = tag0, tag1, b_q[0..4], d_q[0..4], rid; the message is added into the rate (state[4..12])
//! 8 elements per permutation, the last block is zero padded (the length is bound by the capacity); output = state[4..8].
//! The tag "PQZA-EXEC" (9 ASCII bytes) is absorbed as two elements: tag0 = u64::from_le_bytes(b"PQZA-EXE"), tag1 = b"C" (= 0x43).
//! `ExecPublic::ctx` (also every chunk's `ctx` in the chunked form) MUST equal this value; the Exec AIR only binds ctx through
//! the Fiat-Shamir transcript, so this check, done by the verifier, is what links the two proofs.

use crate::auth::{verify_auth, AuthPublic};
use crate::exec::{verify_exec, ExecPublic};
use crate::exec_link::{verify_exec_chunked, ExecChunkPublic};
use crate::rescue::{perm, F, W};
use winterfell::Proof;

const TAG0: u64 = u64::from_le_bytes(*b"PQZA-EXE");
const TAG1: u64 = b'C' as u64;
const MSG_LEN: usize = 11;

/// C_Q = H("PQZA-EXEC" || B_Q || Auth_Q || RID_Q), see the module comment for the mapping and the sponge.
pub fn exec_context(b_q: [F; 4], d_q: [F; 4], rid: u64) -> [F; 4] {
    let mut msg = [F::new(0); MSG_LEN];
    msg[0] = F::new(TAG0);
    msg[1] = F::new(TAG1);
    msg[2..6].copy_from_slice(&b_q);
    msg[6..10].copy_from_slice(&d_q);
    msg[10] = F::new(rid);
    let mut s = [F::new(0); W];
    s[0] = F::new(MSG_LEN as u64);
    for block in msg.chunks(8) {
        for (j, x) in block.iter().enumerate() {
            s[4 + j] += *x;
        }
        perm(&mut s);
    }
    [s[4], s[5], s[6], s[7]]
}

/// The Exec statement of a chunked request (the verifier's own statement, as the arguments of `verify_exec_chunked`).
#[derive(Clone, Debug)]
pub struct ExecChunkedStatement {
    pub digest: [F; 4],
    pub n_blocks: usize,
    pub block_size: usize,
    pub theta: u64,
    pub ctx: [F; 4],
    pub count: u64,
    pub sum: u64,
}

fn check_ctx(auth_pub: &AuthPublic, exec_ctx: &[F; 4], rid: u64) -> Result<(), String> {
    let want = exec_context(auth_pub.b_q, auth_pub.d_q, rid);
    if &want != exec_ctx {
        return Err("link: Exec ctx != exec_context(B_Q, Auth_Q, RID_Q) of the Auth statement".into());
    }
    Ok(())
}

/// Request verifier, single Exec proof: checks `exec_pub.ctx == exec_context(auth_pub.b_q, auth_pub.d_q, rid)`, then verifies the
/// Auth proof and the Exec proof (both strict, see `prove::verify_proof`).
pub fn verify_request(
    auth_proof: Proof,
    auth_pub: AuthPublic,
    exec_proof: Proof,
    exec_pub: ExecPublic,
    rid: u64,
) -> Result<(), String> {
    check_ctx(&auth_pub, &exec_pub.ctx, rid)?;
    verify_auth(auth_proof, auth_pub).map_err(|e| format!("auth: {e}"))?;
    verify_exec(exec_proof, exec_pub).map_err(|e| format!("exec: {e}"))
}

/// Request verifier, chunked Exec: checks `stmt.ctx == exec_context(...)`, then verifies the Auth proof and the chunked Exec proofs
/// (`verify_exec_chunked`, which also requires every chunk's ctx to equal `stmt.ctx`).
pub fn verify_request_chunked(
    auth_proof: Proof,
    auth_pub: AuthPublic,
    exec_proofs: Vec<(Proof, ExecChunkPublic)>,
    stmt: &ExecChunkedStatement,
    rid: u64,
) -> Result<(), String> {
    check_ctx(&auth_pub, &stmt.ctx, rid)?;
    verify_auth(auth_proof, auth_pub).map_err(|e| format!("auth: {e}"))?;
    verify_exec_chunked(
        exec_proofs,
        stmt.digest,
        stmt.n_blocks,
        stmt.block_size,
        stmt.theta,
        stmt.ctx,
        stmt.count,
        stmt.sum,
    )
    .map_err(|e| format!("exec: {e}"))
}
