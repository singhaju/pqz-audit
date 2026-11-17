//! Lead fix e443 (after the attack finding of bench/pqz-attack-w30): (1) strict proof options in every verifier;
//! (2) the request pair check binds the Exec ctx to the Auth statement: ctx = exec_context(B_Q, Auth_Q, RID_Q).
//! Run with `cargo test --release` (and `--features blake3`).

use pqz_proof::auth::*;
use pqz_proof::data::Workload;
use pqz_proof::exec::*;
use pqz_proof::exec_link::*;
use pqz_proof::prove::*;
use pqz_proof::rc::*;
use pqz_proof::rc_link::*;
use pqz_proof::request::*;
use pqz_proof::rescue::F;
use winterfell::Proof;

const RID: u64 = 0;
const THETA: u64 = 1 << 31;

fn auth_inst(depth: usize, seed: u64) -> (AuthPublic, Proof) {
    let (p, w) = honest_auth_instance(depth, seed);
    let proof = prove_auth(&p, &w).unwrap();
    (p, proof)
}

fn wl(seed: u64) -> Workload {
    Workload::synthetic(32, 4, seed) // 8 blocks of 4 records
}

fn ctx_for(a: &AuthPublic) -> [F; 4] {
    exec_context(a.b_q, a.d_q, RID)
}

fn exec_for(w: &Workload, ctx: [F; 4]) -> (Proof, ExecPublic) {
    prove_exec(w, THETA, ctx).unwrap()
}

fn chunked_for(w: &Workload, ctx: [F; 4], split: &[usize]) -> (Vec<(Proof, ExecChunkPublic)>, ExecChunkedStatement) {
    let proofs = prove_exec_chunked(w, THETA, ctx, default_options(), split).unwrap();
    let (count, sum) = w.reference_result(THETA);
    let st = ExecChunkedStatement {
        digest: w.commitment(),
        n_blocks: w.n_blocks,
        block_size: w.block_size,
        theta: THETA,
        ctx,
        count,
        sum,
    };
    (proofs, st)
}

fn bump(c: [F; 4], i: usize) -> [F; 4] {
    let mut d = c;
    d[i] += F::new(1);
    d
}

fn is_binding_error(r: &Result<(), String>) -> bool {
    matches!(r, Err(e) if e.contains("exec_context"))
}

// ---------------- exec_context ----------------

#[test]
fn exec_context_is_deterministic_and_depends_on_every_input() {
    let (a, _) = auth_inst(6, 1);
    let base = exec_context(a.b_q, a.d_q, 0);
    assert_eq!(base, exec_context(a.b_q, a.d_q, 0));
    for i in 0..4 {
        assert_ne!(base, exec_context(bump(a.b_q, i), a.d_q, 0), "b_q[{i}] ignored");
        assert_ne!(base, exec_context(a.b_q, bump(a.d_q, i), 0), "d_q[{i}] ignored");
    }
    assert_ne!(base, exec_context(a.b_q, a.d_q, 1), "rid ignored");
    assert_ne!(exec_context(a.b_q, a.d_q, 0), exec_context(a.d_q, a.b_q, 0), "b_q and d_q are not interchangeable");
}

// ---------------- honest pair accepted ----------------

#[test]
fn pair_honest_single_accepted() {
    for depth in [6, 10] {
        let (a, ap) = auth_inst(depth, 7);
        let (ep, e) = exec_for(&wl(1), ctx_for(&a));
        verify_request(ap, a, ep, e, RID).unwrap();
    }
}

#[test]
fn pair_honest_chunked_accepted() {
    let (a, _) = auth_inst(6, 7);
    for split in [vec![8], vec![4, 4], vec![3, 3, 2]] {
        let (_, ap) = auth_inst(6, 7);
        let (proofs, st) = chunked_for(&wl(1), ctx_for(&a), &split);
        verify_request_chunked(ap, a.clone(), proofs, &st, RID).unwrap();
    }
}

#[test]
fn pair_privileged_rid_accepted_and_rid_mismatch_rejected() {
    let (a, ap) = auth_inst(6, 7);
    let (ep, e) = exec_for(&wl(1), exec_context(a.b_q, a.d_q, 99));
    assert!(is_binding_error(&verify_request(ap, a.clone(), ep, e.clone(), RID))); // verifier says routine, ctx is for rid 99
    let (_, ap2) = auth_inst(6, 7);
    let (ep2, e2) = exec_for(&wl(1), exec_context(a.b_q, a.d_q, 99));
    verify_request(ap2, a, ep2, e2, 99).unwrap();
}

// ---------------- Auth of request 1 + Exec of request 2 ----------------

#[test]
fn auth_of_request_1_with_exec_of_request_2_rejected_single() {
    let (a1, ap1) = auth_inst(6, 7);
    let (a2, ap2) = auth_inst(6, 8);
    assert_ne!(ctx_for(&a1), ctx_for(&a2));
    let (ep1, e1) = exec_for(&wl(1), ctx_for(&a1));
    let (ep2, e2) = exec_for(&wl(2), ctx_for(&a2));
    // both requests are honest on their own
    verify_request(ap1, a1.clone(), ep1, e1.clone(), RID).unwrap();
    verify_request(ap2, a2.clone(), ep2, e2.clone(), RID).unwrap();
    // mix (proofs must be re-made: Proof is consumed)
    let (_, ap1) = auth_inst(6, 7);
    let (ep2, e2) = exec_for(&wl(2), ctx_for(&a2));
    let r = verify_request(ap1, a1.clone(), ep2, e2, RID);
    assert!(is_binding_error(&r), "{r:?}");
    let (_, ap2) = auth_inst(6, 8);
    let (ep1, e1) = exec_for(&wl(1), ctx_for(&a1));
    let r = verify_request(ap2, a2, ep1, e1, RID);
    assert!(is_binding_error(&r), "{r:?}");
}

#[test]
fn auth_of_request_1_with_exec_of_request_2_rejected_chunked() {
    let (a1, _) = auth_inst(6, 7);
    let (a2, _) = auth_inst(6, 8);
    let (_, ap1) = auth_inst(6, 7);
    let (proofs2, st2) = chunked_for(&wl(2), ctx_for(&a2), &[4, 4]);
    let r = verify_request_chunked(ap1, a1.clone(), proofs2, &st2, RID);
    assert!(is_binding_error(&r), "{r:?}");
    // same, the honest pair control
    let (_, ap1) = auth_inst(6, 7);
    let (proofs1, st1) = chunked_for(&wl(1), ctx_for(&a1), &[4, 4]);
    verify_request_chunked(ap1, a1, proofs1, &st1, RID).unwrap();
}

#[test]
fn same_workload_other_auth_is_rejected() {
    // Exec of the same workload, but made for request 2's ctx: still rejected against request 1
    let (a1, ap1) = auth_inst(6, 7);
    let (a2, _) = auth_inst(6, 8);
    let (ep, e) = exec_for(&wl(1), ctx_for(&a2));
    assert!(is_binding_error(&verify_request(ap1, a1, ep, e, RID)));
}

// ---------------- ctx off by one element ----------------

#[test]
fn ctx_off_by_one_element_rejected_single() {
    let (a, _) = auth_inst(6, 7);
    let good = ctx_for(&a);
    for i in 0..4 {
        // (1) the Exec proof is honestly made for the wrong ctx (a valid proof of a different statement)
        let (_, ap) = auth_inst(6, 7);
        let (ep, e) = exec_for(&wl(1), bump(good, i));
        let r = verify_request(ap, a.clone(), ep, e, RID);
        assert!(is_binding_error(&r), "element {i}: {r:?}");
        // (2) honest proof for the right ctx, the public ctx changed afterwards
        let (_, ap) = auth_inst(6, 7);
        let (ep, mut e) = exec_for(&wl(1), good);
        e.ctx = bump(good, i);
        let r = verify_request(ap, a.clone(), ep, e, RID);
        assert!(is_binding_error(&r), "element {i} (tampered public): {r:?}");
    }
}

#[test]
fn ctx_off_by_one_element_rejected_chunked() {
    let (a, _) = auth_inst(6, 7);
    let good = ctx_for(&a);
    for i in 0..4 {
        // statement ctx wrong (chunks made for it)
        let (_, ap) = auth_inst(6, 7);
        let (proofs, st) = chunked_for(&wl(1), bump(good, i), &[4, 4]);
        let r = verify_request_chunked(ap, a.clone(), proofs, &st, RID);
        assert!(is_binding_error(&r), "element {i}: {r:?}");
        // statement ctx right, one chunk's ctx off by one (honest chunk proofs for it elsewhere): the chunked verifier's link check
        let (_, ap) = auth_inst(6, 7);
        let (mut proofs, st) = chunked_for(&wl(1), good, &[4, 4]);
        proofs[1].1.ctx = bump(good, i);
        let r = verify_request_chunked(ap, a.clone(), proofs, &st, RID);
        assert!(r.is_err() && !is_binding_error(&r), "element {i} (chunk): {r:?}");
        assert!(r.unwrap_err().contains("ctx differs"));
    }
}

// ---------------- weaker options (30 and 35 queries, other options) ----------------

fn weak(q: usize) -> winterfell::ProofOptions {
    options_with(q, 8, 16)
}

#[test]
fn weak_options_rejected_by_every_verifier() {
    let w = wl(3);
    let (cnt, sum) = w.reference_result(THETA);
    for q in [30usize, 35] {
        // R_Exec single
        let (p, e) = prove_exec_with(&w, THETA, [F::new(1); 4], weak(q)).unwrap();
        assert!(proof_is_valid_with_floor::<ExecAir>(&p, &e), "control q={q}");
        let r = verify_exec(p, e);
        assert!(r.as_ref().unwrap_err().contains("UnacceptableProofOptions"), "exec q={q}: {r:?}");
        // R_RC single
        let (p, rp) = prove_rc(&w, weak(q)).unwrap();
        assert!(verify_rc(p, rp).unwrap_err().contains("UnacceptableProofOptions"), "rc q={q}");
        // R_Auth
        let (ap, aw) = honest_auth_instance(6, 5);
        let p = prove_auth_with(&ap, &aw, weak(q)).unwrap();
        assert!(verify_auth(p, ap).unwrap_err().contains("UnacceptableProofOptions"), "auth q={q}");
        // chunked Exec / RC (all chunks equally weak: the old verifier accepted this)
        let proofs = prove_exec_chunked(&w, THETA, [F::new(1); 4], weak(q), &[4, 4]).unwrap();
        let r = verify_exec_chunked(proofs, w.commitment(), w.n_blocks, w.block_size, THETA, [F::new(1); 4], cnt, sum);
        assert!(r.unwrap_err().contains("UnacceptableProofOptions"), "exec chunked q={q}");
        let proofs = prove_rc_chunked(&w, weak(q), &[4, 4]).unwrap();
        let r = verify_rc_chunked(proofs, w.commitment(), w.n_blocks, w.block_size, w.header0());
        assert!(r.unwrap_err().contains("UnacceptableProofOptions"), "rc chunked q={q}");
        // pair: weak Exec with a correctly bound ctx, single and chunked
        let (a, _) = auth_inst(6, 7);
        let (_, ap) = auth_inst(6, 7);
        let (p, e) = prove_exec_with(&w, THETA, ctx_for(&a), weak(q)).unwrap();
        let r = verify_request(ap, a.clone(), p, e, RID);
        assert!(r.unwrap_err().contains("UnacceptableProofOptions"), "pair single q={q}");
        let (_, ap) = auth_inst(6, 7);
        let proofs = prove_exec_chunked(&w, THETA, ctx_for(&a), weak(q), &[4, 4]).unwrap();
        let st = ExecChunkedStatement {
            digest: w.commitment(),
            n_blocks: w.n_blocks,
            block_size: w.block_size,
            theta: THETA,
            ctx: ctx_for(&a),
            count: cnt,
            sum,
        };
        let r = verify_request_chunked(ap, a, proofs, &st, RID);
        assert!(r.unwrap_err().contains("UnacceptableProofOptions"), "pair chunked q={q}");
    }
}

/// control: the same proof IS valid under the weak (min-bits) rule, so the strict verifier is what rejects it
fn proof_is_valid_with_floor<A>(p: &Proof, e: &A::PublicInputs) -> bool
where
    A: winterfell::Air<BaseField = F> + 'static,
    A::PublicInputs: Clone,
{
    verify_proof_min_bits::<A>(p.clone(), e.clone(), 80).is_ok()
}

#[test]
fn other_blowup_or_grinding_rejected_even_with_more_security() {
    let w = wl(3);
    for o in [options_with(40, 8, 15), options_with(40, 16, 16), options_with(41, 8, 16)] {
        let (p, e) = prove_exec_with(&w, THETA, [F::new(1); 4], o.clone()).unwrap();
        assert!(proof_is_valid_with_floor::<ExecAir>(&p, &e), "control {o:?}");
        assert!(verify_exec(p, e).unwrap_err().contains("UnacceptableProofOptions"), "{o:?}");
    }
}

#[test]
fn default_options_still_accepted_by_strict_and_min_bits_verifier() {
    let w = wl(3);
    let (p, e) = prove_exec(&w, THETA, [F::new(1); 4]).unwrap();
    assert!(verify_proof_min_bits::<ExecAir>(p.clone(), e.clone(), 80).is_ok());
    assert!(verify_proof_min_bits::<ExecAir>(p.clone(), e.clone(), 400).is_err()); // the old floor rule still works
    verify_exec(p, e).unwrap();
}

#[cfg(not(debug_assertions))]
#[test]
fn weak_options_rejected_by_cover_verifiers() {
    use pqz_proof::cover::*;
    use pqz_proof::covermerkle::*;
    for q in [30usize, 35] {
        let i = CoverInstance::honest(10, 4, 5);
        let (p, pu) = prove_cover(&i, weak(q)).unwrap();
        assert!(verify_cover(p, pu).unwrap_err().contains("UnacceptableProofOptions"), "cover q={q}");
        let i = CoverMInstance::honest(10, 4, 5);
        let (p, pu) = prove_covermerkle(&i, weak(q)).unwrap();
        assert!(verify_covermerkle(p, pu).unwrap_err().contains("UnacceptableProofOptions"), "covermerkle q={q}");
    }
}
