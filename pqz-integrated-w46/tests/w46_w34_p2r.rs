//! w46: w34 whole-stream arm in the packed format P2r. Release mode: `cargo test --release`.
use pqz_eval::eapat::EpochKeys;
use pqz_eval::r#gen::r#gen;
use pqz_eval::Layout;
use pqz_integrated_w46::*;

const N: usize = 2000;
const SEED: u64 = DEFAULT_SEED;

struct Fx {
    auth: AuthProof,
    exec: ExecProof,
    rc: PRcProof,
}

fn fx(layout: Layout, seed: u64) -> Fx {
    let records = r#gen(N, N / 100, layout, seed);
    let keys = EpochKeys::from_seed(seed);
    let (formula, _t) = predicate_formula(&keys);
    let log = build_log(&records, &keys);
    let (rc, _) = prove_rc_stage_p(&log.wl).expect("rc prove");
    verify_rc_stage_p(&rc).expect("rc verify");
    let mut lc = ledger_setup(seed);
    let (_st, omega) = commit_epoch(&mut lc, log.r_e, N as u64, (N / BLOCK) as u64).expect("anchor");
    let (auth, _) = auth_stage(&omega, 1, "P1: A = x", seed).expect("auth");
    let so = search(&log, &formula);
    let (exec_wl, claim, _used) = exec_input(&log, &so, ExecStream::Whole);
    let ctx = pqz_plonky3_w36::request::exec_context(&pqz_plonky3_w36::c1::perm(), auth.stmt.b_q, auth.stmt.d_q, RID);
    let (exec, _) = prove_exec_stage_p(&exec_wl, ctx, claim).expect("exec prove");
    Fx { auth, exec, rc }
}

#[test]
fn p2r_whole_honest_both_layouts() {
    for l in [Layout::Clustered, Layout::Scattered] {
        let f = fx(l, SEED);
        let (_t, k) = verify_requester_p(&f.auth, &f.exec, &f.rc).expect("requester");
        assert_eq!(k, LinkKind::Full);
    }
}

#[test]
fn p2r_run_one_whole_matches_old_result() {
    let s = setting_of("P3").unwrap();
    for l in [Layout::Clustered, Layout::Scattered] {
        let old = run_one_with_fmt(N, l, &s, SEED, ExecStream::Whole, WFmt::Old).expect("old");
        let new = run_one_with_fmt(N, l, &s, SEED, ExecStream::Whole, WFmt::P2r).expect("p2r");
        assert_eq!(old.n_sel, new.n_sel);
        assert_eq!(new.fmt, WFmt::P2r);
        assert!(new.p6b_s > 0.0 && new.total_s > 0.0);
    }
}

#[test]
fn p2r_retained_is_exit_2() {
    let s = setting_of("P3").unwrap();
    let e = run_one_with_fmt(N, Layout::Clustered, &s, SEED, ExecStream::Retained, WFmt::P2r).err().expect("must fail");
    assert_eq!(e.code, 2);
}

/// Exec statement of another stream (digest differs) against this stream's RC chunk: the stream link rejects.
#[test]
fn p2r_foreign_exec_digest_rejected_by_link() {
    let a = fx(Layout::Clustered, SEED);
    let b = fx(Layout::Clustered, SEED + 1);
    verify_requester_p(&b.auth, &b.exec, &b.rc).expect("B with B");
    assert_ne!(a.rc.stmt.s_out, b.rc.stmt.s_out);
    let err = verify_requester_p(&b.auth, &b.exec, &a.rc).err().expect("accepted");
    assert!(err.msg.contains("link"), "reason: {}", err.msg);
    // the same by the native check alone
    assert!(pqz_plonky3_w36::prequest::check_stream_link_p(&b.exec.stmt, std::slice::from_ref(&a.rc.stmt)).is_err());
}

/// Tampered chunk statement / lists (check_sealed + alpha/beta/acc) and tampered exec statement are rejected.
#[test]
fn p2r_tampered_statements_rejected() {
    let f = fx(Layout::Scattered, SEED);
    // exec: n_blocks, block_size, digest, count, theta
    let mut e = ExecProof { bytes: f.exec.bytes.clone(), stmt: f.exec.stmt.clone() };
    e.stmt.n_blocks += 1;
    assert!(verify_requester_p(&f.auth, &e, &f.rc).is_err(), "n_blocks");
    let mut e = ExecProof { bytes: f.exec.bytes.clone(), stmt: f.exec.stmt.clone() };
    e.stmt.digest[0] ^= 1;
    assert!(verify_requester_p(&f.auth, &e, &f.rc).is_err(), "digest");
    let mut e = ExecProof { bytes: f.exec.bytes.clone(), stmt: f.exec.stmt.clone() };
    e.stmt.theta ^= 1;
    assert!(verify_requester_p(&f.auth, &e, &f.rc).is_err(), "theta");
    let mut e = ExecProof { bytes: f.exec.bytes.clone(), stmt: f.exec.stmt.clone() };
    e.stmt.count += 1;
    assert!(verify_requester_p(&f.auth, &e, &f.rc).is_err(), "count");
    // exec proof bytes
    let mut e = ExecProof { bytes: f.exec.bytes.clone(), stmt: f.exec.stmt.clone() };
    let m = e.bytes.len() / 2;
    e.bytes[m] ^= 1;
    assert!(verify_requester_p(&f.auth, &e, &f.rc).is_err(), "exec bytes");
    // rc: lists (sealed), statement digest, chunk proof bytes
    let mk = |f: &Fx| PRcProof { bytes: f.rc.bytes.clone(), stmt: f.rc.stmt.clone(), lists: f.rc.lists.clone() };
    let mut r = mk(&f);
    r.lists.tags[0] ^= 1;
    assert!(verify_requester_p(&f.auth, &f.exec, &r).is_err(), "list tag (check_sealed / acc)");
    let mut r = mk(&f);
    r.lists.hdrs[0][0] ^= 1;
    assert!(verify_requester_p(&f.auth, &f.exec, &r).is_err(), "list hdr");
    let mut r = mk(&f);
    r.stmt.s_out[0] ^= 1;
    assert!(verify_requester_p(&f.auth, &f.exec, &r).is_err(), "rc digest");
    let mut r = mk(&f);
    let m = r.bytes.len() / 2;
    r.bytes[m] ^= 1;
    assert!(verify_rc_stage_p(&r).is_err(), "rc proof bytes");
}
