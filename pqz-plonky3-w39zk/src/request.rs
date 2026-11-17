//! Request-level link between the Auth proof and the Exec proof (mirror of `bench/pqz-proof-w30/src/request.rs`).
//!
//! C_Q = H("PQZA-EXEC" || B_Q || Auth_Q || RID_Q) with H = fixed-length Poseidon2 sponge (width 12, rate 8, capacity 4):
//! capacity = [11, 0, 0, 0] at state[8..12] (11 = absorbed elements; w30 Rescue had it at state[0..4]), the 11-element
//! message (tag0, tag1, b_q[4], d_q[4], rid) is added into state[0..8] 8 elements per permutation, last block zero
//! padded, output = state[0..4]. tag0 = u64::from_le_bytes(b"PQZA-EXE"), tag1 = b'C'.
//! `verify_request` checks the Exec statement's ctx against the C_Q recomputed from the Auth statement FIRST, then verifies
//! both proofs with the verifier's own fixed FriOpts (as w30 Phase 7).

use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use p3_symmetric::Permutation;

use crate::air::ExecPublic;
use crate::auth::AuthPublic;
use crate::rc::RcPublic;
use crate::variants::{c1, FriOpts};

const TAG0: u64 = u64::from_le_bytes(*b"PQZA-EXE");
const TAG1: u64 = b'C' as u64;
const MSG_LEN: usize = 11;

pub fn exec_context<P: Permutation<[Goldilocks; 12]>>(perm: &P, b_q: [u64; 4], d_q: [u64; 4], rid: u64) -> [u64; 4] {
    let mut msg = [0u64; MSG_LEN];
    msg[0] = TAG0;
    msg[1] = TAG1;
    msg[2..6].copy_from_slice(&b_q);
    msg[6..10].copy_from_slice(&d_q);
    msg[10] = rid;
    let mut s = [Goldilocks::new(0); 12];
    s[8] = Goldilocks::new(MSG_LEN as u64);
    for block in msg.chunks(8) {
        for (j, x) in block.iter().enumerate() {
            s[j] += <Goldilocks as p3_field::PrimeCharacteristicRing>::from_u64(*x);
        }
        perm.permute_mut(&mut s);
    }
    [0, 1, 2, 3].map(|j| s[j].as_canonical_u64())
}

pub fn check_ctx(auth_pub: &AuthPublic, exec_ctx: &[u64; 4], rid: u64) -> Result<(), String> {
    let want = exec_context(&c1::perm(), auth_pub.b_q, auth_pub.d_q, rid);
    if &want != exec_ctx {
        return Err("link: Exec ctx != exec_context(B_Q, Auth_Q, RID_Q) of the Auth statement".into());
    }
    Ok(())
}

/// w34 native verifier checks that need no proof (verifier-only; no AIR is changed).
/// `link`: C1, the R_RC digest, `n_blocks` and `block_size` equal those of the R_Exec statement ("link: ").
/// `scope`: C2, the query scope is not inverted (start <= end for the ranges s, e, t) ("scope: ").
/// `NativeChecks::ON` is the only value the production verifiers (`verify_request`, `verify_bundle`, `pchild3`, `pverify3`) use;
/// `NativeChecks::OFF` exists ONLY for the attack crate `bench/pqz-attack-w33`, to show that the two checks matter. The C_Q link
/// (`check_ctx`, w33 stage C) is not switchable and always runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeChecks {
    pub link: bool,
    pub scope: bool,
}

impl NativeChecks {
    pub const ON: NativeChecks = NativeChecks { link: true, scope: true };
    pub const OFF: NativeChecks = NativeChecks { link: false, scope: false };
}

/// C2: the three ranges of the query scope in `AuthPublic.scope` (`auth.rs` `ScopeQ`: s = (start, end) of the S range,
/// e = (start, end) of the epoch range, t = (start, end) of the time range; public values PV_S0..PV_S0+5 = 20..25) must satisfy start <= end.
/// The Auth AIR only proves `leaf.lo <= start` and `end <= leaf.hi` (`RANGES`), so start > end passes it.
pub fn check_scope(a: &AuthPublic) -> Result<(), String> {
    let sc = &a.scope;
    for (name, r) in [("s", sc.s), ("e", sc.e), ("t", sc.t)] {
        if r.0 > r.1 {
            return Err(format!("scope: inverted range {name} (start {} > end {})", r.0, r.1));
        }
    }
    Ok(())
}

/// C1: the R_RC statement must describe the same stream as the R_Exec statement (same sponge digest, same block count and size).
/// Honest statements satisfy this by construction: both digests are `native_digest(Layout, perm, mapped words)` of the same words.
pub fn check_stream_link(exec_pub: &ExecPublic, rc_pub: &RcPublic) -> Result<(), String> {
    if exec_pub.digest != rc_pub.digest {
        return Err("link: R_RC digest != R_Exec digest".into());
    }
    if exec_pub.n_blocks != rc_pub.n_blocks {
        return Err(format!("link: n_blocks differ (exec {} vs rc {})", exec_pub.n_blocks, rc_pub.n_blocks));
    }
    if exec_pub.block_size != rc_pub.block_size {
        return Err(format!("link: block_size differ (exec {} vs rc {})", exec_pub.block_size, rc_pub.block_size));
    }
    Ok(())
}

/// Every native (proof-free) check of a bundle, in the order of `verify_bundle_with`: stream link, C_Q link, scope.
/// Used by `verify_bundle_with` and by the timing children (`pchild3`, `pverify3`, which call their own plain / zk proof verifiers).
pub fn native_bundle_checks(
    nc: NativeChecks,
    auth_pub: &AuthPublic,
    exec_pub: &ExecPublic,
    rc_pub: &RcPublic,
    rid: u64,
) -> Result<(), String> {
    if nc.link {
        check_stream_link(exec_pub, rc_pub)?;
    }
    native_request_checks(nc, auth_pub, exec_pub, rid)
}

/// Native checks of a request (Auth + Exec): C_Q link (always), then the scope order (if `nc.scope`).
pub fn native_request_checks(nc: NativeChecks, auth_pub: &AuthPublic, exec_pub: &ExecPublic, rid: u64) -> Result<(), String> {
    check_ctx(auth_pub, &exec_pub.ctx, rid)?;
    if nc.scope {
        check_scope(auth_pub)?;
    }
    Ok(())
}

/// Request verifier: ctx link first, then the scope order (w34), then the Auth proof, then the Exec proof (errors prefixed "auth: " / "exec: ").
pub fn verify_request(
    o: &FriOpts,
    auth_proof: &c1::P,
    auth_pub: &AuthPublic,
    exec_proof: &c1::P,
    exec_pub: &ExecPublic,
    rid: u64,
) -> Result<(), String> {
    verify_request_with(NativeChecks::ON, o, auth_proof, auth_pub, exec_proof, exec_pub, rid)
}

/// As `verify_request` with the w34 native checks selectable (attack crate only; see `NativeChecks`).
pub fn verify_request_with(
    nc: NativeChecks,
    o: &FriOpts,
    auth_proof: &c1::P,
    auth_pub: &AuthPublic,
    exec_proof: &c1::P,
    exec_pub: &ExecPublic,
    rid: u64,
) -> Result<(), String> {
    native_request_checks(nc, auth_pub, exec_pub, rid)?;
    crate::rel::plain::verify_auth(o, auth_proof, auth_pub).map_err(|e| format!("auth: {e}"))?;
    crate::rel::plain::verify_exec(o, exec_proof, exec_pub).map_err(|e| format!("exec: {e}"))
}

/// Bundle verifier: the w34 native checks (stream link, C_Q link, scope) BEFORE any proof, then Auth, Exec and the R_RC proof of the stored stream.
pub fn verify_bundle(
    o: &FriOpts,
    auth_proof: &c1::P,
    auth_pub: &AuthPublic,
    exec_proof: &c1::P,
    exec_pub: &ExecPublic,
    rc_proof: &c1::P,
    rc_pub: &RcPublic,
    rid: u64,
) -> Result<(), String> {
    verify_bundle_with(NativeChecks::ON, o, auth_proof, auth_pub, exec_proof, exec_pub, rc_proof, rc_pub, rid)
}

/// As `verify_bundle` with the w34 native checks selectable (attack crate only; see `NativeChecks`).
pub fn verify_bundle_with(
    nc: NativeChecks,
    o: &FriOpts,
    auth_proof: &c1::P,
    auth_pub: &AuthPublic,
    exec_proof: &c1::P,
    exec_pub: &ExecPublic,
    rc_proof: &c1::P,
    rc_pub: &RcPublic,
    rid: u64,
) -> Result<(), String> {
    native_bundle_checks(nc, auth_pub, exec_pub, rc_pub, rid)?;
    crate::rel::plain::verify_auth(o, auth_proof, auth_pub).map_err(|e| format!("auth: {e}"))?;
    crate::rel::plain::verify_exec(o, exec_proof, exec_pub).map_err(|e| format!("exec: {e}"))?;
    crate::rel::plain::verify_rc(o, rc_proof, rc_pub).map_err(|e| format!("rc: {e}"))
}
