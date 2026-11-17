//! Honest proofs verify; tampered public input, tampered trace value and wrong record count are rejected.
//! Run with `cargo test --release` (the release prover does not validate the trace, so a bad trace
//! yields a proof that the verifier must reject; in a debug build the prover panics, also treated as rejection).

use pqz_proof::auth::*;
use pqz_proof::data::Workload;
use pqz_proof::exec::*;
use pqz_proof::prove::*;
use pqz_proof::rc::*;
use pqz_proof::rescue::F;
use winterfell::math::FieldElement;
use winterfell::Trace;

const MIN_BITS: u32 = 80;

fn ctx() -> [F; 4] {
    [F::new(11), F::new(22), F::new(33), F::new(44)]
}

fn wl() -> Workload {
    Workload::synthetic(40, 8, 1)
}

fn rejected_or_unprovable<T>(r: Result<T, String>) -> bool {
    r.is_err()
}

// ---------------- R_RC ----------------

#[test]
fn rc_honest_verifies() {
    let (proof, p) = prove_rc(&wl(), options()).unwrap();
    verify_rc(proof, p, MIN_BITS).unwrap();
}

#[test]
fn rc_tampered_digest_rejected() {
    let (proof, mut p) = prove_rc(&wl(), options()).unwrap();
    p.digest[0] += F::ONE;
    assert!(verify_rc(proof, p, MIN_BITS).is_err());
}

#[test]
fn rc_tampered_header_rejected() {
    let (proof, mut p) = prove_rc(&wl(), options()).unwrap();
    p.header0[1] += F::ONE;
    assert!(verify_rc(proof, p, MIN_BITS).is_err());
}

#[test]
fn rc_wrong_record_count_rejected() {
    let (proof, mut p) = prove_rc(&wl(), options()).unwrap();
    p.n_blocks += 1;
    assert!(verify_rc(proof, p, MIN_BITS).is_err());
    // fewer blocks than committed
    let (proof, mut p) = prove_rc(&wl(), options()).unwrap();
    p.n_blocks -= 1;
    assert!(verify_rc(proof, p, MIN_BITS).is_err());
}

#[test]
fn rc_dropped_block_with_original_public_rejected() {
    // prover drops the last block but claims the digest and count of the full set
    let w = wl();
    let p = rc_public(&w);
    let mut short = w.clone();
    let k = short.block_size + 1;
    short.words.truncate(short.words.len() - k);
    short.n_blocks -= 1;
    let trace = build_rc_trace(&short);
    let r = prove_trace::<RcAir>(trace, p.clone(), options());
    match r {
        Err(_) => eprintln!("path: prover refused"),
        Ok(proof) => {
            let r = verify_rc(proof, p, MIN_BITS);
            eprintln!("path: verifier said {:?}", r);
            assert!(r.is_err());
        }
    }
}

#[test]
fn rc_tampered_trace_rejected() {
    let w = wl();
    let p = rc_public(&w);
    let mut trace = build_rc_trace(&w);
    // change one record value in the absorbed rate columns of some middle group (link row 8*5 + 7; the R columns are only constrained on link rows)
    let v = trace.get(12 + 4, 8 * 5 + 7);
    trace.set(12 + 4, 8 * 5 + 7, v + F::ONE);
    match prove_trace::<RcAir>(trace, p.clone(), options()) {
        Err(_) => eprintln!("path: prover refused"),
        Ok(proof) => {
            let r = verify_rc(proof, p, MIN_BITS);
            eprintln!("path: verifier said {:?}", r);
            assert!(r.is_err());
        }
    }
}

#[test]
fn rc_record_with_wrong_pid_rejected() {
    // a record whose pid differs from its header: honest digest of the altered stream, but the AIR must refuse it
    let mut w = wl();
    w.words[3][0] += F::ONE; // pid of a record
    let p = rc_public(&w); // digest matches the altered stream
    let trace = build_rc_trace(&w);
    match prove_trace::<RcAir>(trace, p.clone(), options()) {
        Err(_) => eprintln!("path: prover refused"),
        Ok(proof) => {
            let r = verify_rc(proof, p, MIN_BITS);
            eprintln!("path: verifier said {:?}", r);
            assert!(r.is_err());
        }
    }
}

#[test]
fn rc_merged_blocks_rejected() {
    // delete the header of block 1 (two blocks become one) and add a padding word at the end, so the stream keeps its
    // length, pid/epoch and sequence numbers stay consistent, and only the block structure is wrong
    use pqz_proof::data::pad_word;
    let mut w = wl();
    let k = w.block_size + 1;
    w.words.remove(k);
    w.words.push(pad_word());
    let p = rc_public(&w);
    let trace = build_rc_trace(&w);
    match prove_trace::<RcAir>(trace, p.clone(), options()) {
        Err(_) => eprintln!("path: prover refused"),
        Ok(proof) => {
            let r = verify_rc(proof, p, MIN_BITS);
            eprintln!("path: verifier said {:?}", r);
            assert!(r.is_err());
        }
    }
}

// ---------------- R_Exec ----------------

const THETA: u64 = 1 << 30;

#[test]
fn exec_honest_verifies() {
    let (proof, p) = prove_exec(&wl(), THETA, ctx()).unwrap();
    assert!(p.count > 0 && (p.count as usize) < wl().n_records(), "theta should split the data");
    verify_exec(proof, p, MIN_BITS).unwrap();
}

#[test]
fn exec_tampered_public_rejected() {
    for which in 0..6 {
        let (proof, mut p) = prove_exec(&wl(), THETA, ctx()).unwrap();
        match which {
            0 => p.count += 1,
            1 => p.sum += 1,
            2 => p.digest[2] += F::ONE,
            3 => p.theta += 1,
            4 => p.ctx[0] += F::ONE,
            _ => p.n_blocks += 1,
        }
        assert!(verify_exec(proof, p, MIN_BITS).is_err(), "case {which} accepted");
    }
}

#[test]
fn exec_wrong_claimed_result_unprovable() {
    // prover claims a wrong count with a correct trace
    let w = wl();
    let mut p = exec_public(&w, THETA, ctx());
    p.count += 1;
    let trace = build_exec_trace(&w, THETA);
    match prove_trace::<ExecAir>(trace, p.clone(), options()) {
        Err(_) => eprintln!("path: prover refused"),
        Ok(proof) => {
            let r = verify_exec(proof, p, MIN_BITS);
            eprintln!("path: verifier said {:?}", r);
            assert!(r.is_err());
        }
    }
}

#[test]
fn exec_tampered_trace_rejected() {
    // flip the match flag m of one record to count a record below theta
    let w = wl();
    let p = exec_public(&w, THETA, ctx());
    let mut trace = build_exec_trace(&w, THETA);
    // find a row where m = 0 on a record group (first round row after a record link) and set it to 1
    let mut done = false;
    for g in 1..w.n_groups() {
        if w.words[g][7] == F::ZERO && w.words[g][4].as_int() < THETA {
            // data for word g is placed in group g-1
            for r in 0..8 {
                trace.set(20, (g - 1) * 8 + r, F::ONE);
            }
            done = true;
            break;
        }
    }
    assert!(done);
    match prove_trace::<ExecAir>(trace, p.clone(), options()) {
        Err(_) => eprintln!("path: prover refused"),
        Ok(proof) => {
            let r = verify_exec(proof, p, MIN_BITS);
            eprintln!("path: verifier said {:?}", r);
            assert!(r.is_err());
        }
    }
}

#[test]
fn exec_wrong_record_count_rejected() {
    let w = wl();
    let mut short = w.clone();
    let k = short.block_size + 1;
    short.words.truncate(short.words.len() - k);
    short.n_blocks -= 1;
    // claim the full data set's digest and the full set's result
    let p = exec_public(&w, THETA, ctx());
    let trace = build_exec_trace(&short, THETA);
    match prove_trace::<ExecAir>(trace, p.clone(), options()) {
        Err(_) => eprintln!("path: prover refused"),
        Ok(proof) => {
            let r = verify_exec(proof, p, MIN_BITS);
            eprintln!("path: verifier said {:?}", r);
            assert!(r.is_err());
        }
    }
}

#[test]
fn exec_security_floor_enforced() {
    let (proof, p) = prove_exec(&wl(), THETA, ctx()).unwrap();
    assert!(verify_exec(proof, p, 400).is_err());
}

// ---------------- R_Auth ----------------

#[test]
fn auth_honest_verifies() {
    let (p, w) = honest_auth_instance(8, 5);
    let proof = prove_auth(&p, &w).unwrap();
    verify_auth(proof, p, MIN_BITS).unwrap();
}

#[test]
fn auth_tampered_public_rejected() {
    for which in 0..6 {
        let (p0, w) = honest_auth_instance(8, 5);
        let proof = prove_auth(&p0, &w).unwrap();
        let mut p = p0.clone();
        match which {
            0 => p.r_pol[0] += F::ONE,
            1 => p.b_q[1] += F::ONE,
            2 => p.d_q[2] += F::ONE,
            3 => p.v_auth += 1,
            4 => p.scope.p += 1,
            _ => p.uid += 1,
        }
        assert!(verify_auth(proof, p, MIN_BITS).is_err(), "case {which} accepted");
    }
}

#[test]
fn auth_scope_outside_policy_rejected() {
    // policy allows epochs 1..8, request asks for epoch up to 9
    let (mut p, w) = honest_auth_instance(8, 5);
    p.scope.e.1 = 9;
    // b_q and r_pol do not depend on the scope, so the public input stays consistent
    match prove_auth(&p, &w) {
        Err(_) => eprintln!("path: prover refused"),
        Ok(proof) => {
            let r = verify_auth(proof, p, MIN_BITS);
            eprintln!("path: verifier said {:?}", r);
            assert!(r.is_err());
        }
    }
}

#[test]
fn auth_level_too_low_rejected() {
    let (mut p, w) = honest_auth_instance(8, 5);
    p.scope.level = 4; // policy level is 3
    match prove_auth(&p, &w) {
        Err(_) => eprintln!("path: prover refused"),
        Ok(proof) => {
            let r = verify_auth(proof, p, MIN_BITS);
            eprintln!("path: verifier said {:?}", r);
            assert!(r.is_err());
        }
    }
}

#[test]
fn auth_wrong_membership_rejected() {
    // sibling changed: path no longer leads to r_pol
    let (p, mut w) = honest_auth_instance(8, 5);
    w.siblings[3][0] += F::ONE;
    match prove_auth(&p, &w) {
        Err(_) => eprintln!("path: prover refused"),
        Ok(proof) => {
            let r = verify_auth(proof, p, MIN_BITS);
            eprintln!("path: verifier said {:?}", r);
            assert!(r.is_err());
        }
    }
}

#[test]
fn auth_tampered_trace_rejected() {
    let (p, w) = honest_auth_instance(8, 5);
    let mut trace = build_auth_trace(&p, &w);
    let v = trace.get(12 + 3, 5); // policy word held in the P columns
    for row in 0..trace.length() {
        trace.set(12 + 3, row, v + F::ONE);
    }
    match prove_trace::<AuthAir>(trace, p.clone(), options()) {
        Err(_) => eprintln!("path: prover refused"),
        Ok(proof) => {
            let r = verify_auth(proof, p, MIN_BITS);
            eprintln!("path: verifier said {:?}", r);
            assert!(r.is_err());
        }
    }
}

#[allow(dead_code)]
fn _unused() {
    let _ = rejected_or_unprovable::<()>;
}
