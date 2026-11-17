//! Release-mode tests only (the Plonky3 prover panics on an invalid trace in debug builds): `cargo test --release --offline`.
//! Small N (2000 = 4 blocks of 500). Each test runs the same pieces `run_one_with` runs, so the gates and verifiers are exercised for real.
//! Port of tests/w30.rs: the linked-mode (S2) variants are dropped (one proof per relation only), the winterfell field is u64.
//! New in w34: honest end-to-end, tampered proofs, mismatched streams, the stream link (full and subset), the C_Q link.

use pqz_eval::eapat::EpochKeys;
use pqz_eval::r#gen::r#gen;
use pqz_eval::{Layout, Record};
use pqz_integrated_w46::*;
use pqz_plonky3_w36::data::{Workload, GOLDILOCKS_P};

const N: usize = 2000;
const SEED: u64 = DEFAULT_SEED;

fn setting() -> Setting {
    setting_of("P3").expect("P3")
}

struct Fix {
    records: Vec<Record>,
    log: Log,
    so: SearchOut,
    lc: LedgerCtx,
    rc: RcProof,
    omega: [u8; 32],
    auth: AuthProof,
    exec_wl: Workload,
    exec_used: Vec<bool>,
    claim: (u64, u64),
    exec: ExecProof,
    es: ExecStream,
}

fn fixture_seed(layout: Layout, es: ExecStream, seed: u64) -> Fix {
    let records = r#gen(N, N / 100, layout, seed);
    let keys = EpochKeys::from_seed(seed);
    let (formula, _t) = predicate_formula(&keys);
    let log = build_log(&records, &keys);
    let (rc, _) = prove_rc_stage(&log.wl).expect("rc prove");
    verify_rc_stage(&rc).expect("rc verify");
    let mut lc = ledger_setup(seed);
    let (_st, omega) = commit_epoch(&mut lc, log.r_e, N as u64, (N / BLOCK) as u64).expect("anchor");
    let (auth, _) = auth_stage(&omega, 1, "P1: A = x", seed).expect("auth");
    let so = search(&log, &formula);
    assert!(so.flags.iter().any(|&f| f));
    let (exec_wl, claim, exec_used) = exec_input(&log, &so, es);
    let ctx = exec_ctx(&auth);
    let (exec, _) = prove_exec_stage(&exec_wl, ctx, claim).expect("exec prove");
    Fix { records, log, so, lc, rc, omega, auth, exec_wl, exec_used, claim, exec, es }
}

fn fixture(layout: Layout, es: ExecStream) -> Fix {
    fixture_seed(layout, es, SEED)
}

fn exec_ctx(a: &AuthProof) -> [u64; 4] {
    pqz_plonky3_w36::request::exec_context(&pqz_plonky3_w36::c1::perm(), a.stmt.b_q, a.stmt.d_q, RID)
}

fn gate_with(f: &Fix, link: LinkKind) -> Res<()> {
    gates(&GateInput {
        records: &f.records,
        log: &f.log,
        search: &f.so,
        exec_wl: &f.exec_wl,
        exec_used: &f.exec_used,
        claim: f.claim,
        rc: &f.rc,
        exec: &f.exec,
        link,
        exec_stream: f.es,
    })
}

fn gate(f: &Fix) -> Res<()> {
    gate_with(f, LinkKind::of(&f.exec.stmt, &f.rc.stmt))
}

fn honest(layout: Layout, es: ExecStream) {
    let f = fixture(layout, es);
    let (_tm, link) = verify_requester(&f.auth, &f.exec, &f.rc.stmt).expect("requester verifies");
    // whole stream, or every block retained: the full link; otherwise the subset link
    let all = f.exec.stmt.n_blocks == f.rc.stmt.n_blocks;
    assert_eq!(link, if all { LinkKind::Full } else { LinkKind::Subset });
    if es == ExecStream::Whole {
        assert_eq!(link, LinkKind::Full);
    }
    gate(&f).expect("gates");
    ledger_read_gate(&f.lc, &f.omega).expect("ledger read");
    assert_eq!(f.claim.0 as usize, N / 100);
}

#[test]
fn honest_clustered_retained() {
    honest(Layout::Clustered, ExecStream::Retained);
}
#[test]
fn honest_scattered_retained() {
    honest(Layout::Scattered, ExecStream::Retained);
}
#[test]
fn honest_clustered_whole() {
    honest(Layout::Clustered, ExecStream::Whole);
}
#[test]
fn honest_scattered_whole() {
    honest(Layout::Scattered, ExecStream::Whole);
}

#[test]
fn run_one_end_to_end_all_variants() {
    for es in [ExecStream::Retained, ExecStream::Whole] {
        for l in [Layout::Clustered, Layout::Scattered] {
            let o = run_one_with(N, l, &setting(), SEED, es).expect("run_one");
            assert_eq!(o.n_sel, N / 100);
            assert!(o.total_s > 0.0 && o.p3b_s > 0.0 && o.p6b_s > 0.0);
            let sum = o.p3a_s + o.p3b_s + o.p4a_s + o.p4b_s + o.p5_s + o.p6a_s + o.p6b_s + o.p7_s;
            assert!((sum - o.total_s).abs() < 1e-9);
            assert!(o.p7_native_s > 0.0 && o.p7_native_s < o.p7_s);
            assert_eq!(o.exec_stream, Some(es));
            if es == ExecStream::Whole {
                assert_eq!(o.link_kind, Some(LinkKind::Full));
            }
        }
    }
}

/// NEW (L5): an honest end-to-end run at small n passes every stage, the verifiers and all the gates (run_one runs the gates itself).
#[test]
fn e2e_honest_run_passes_the_gates() {
    let o = run_one(N, Layout::Clustered, &setting(), SEED).expect("honest run must pass the gates");
    assert_eq!(o.n, N);
    assert_eq!(o.g, N / BLOCK);
    assert_eq!(o.n_sel, N / 100);
    assert!(o.r >= 1 && o.r <= o.g);
    assert_eq!(o.rc.chunks, 1);
    assert_eq!(o.exec.chunks, 1);
    // the security estimates are those of FriOpts::std() (conjectured, proven unique decoding, proven list decoding)
    assert!(o.rc.conj >= 100 && o.exec.conj >= 100 && o.auth.conj >= 100, "conjectured bits {} {} {}", o.rc.conj, o.exec.conj, o.auth.conj);
    assert!(o.hwm_reset_ok);
}

#[test]
fn wrong_claimed_result_is_rejected() {
    let f = fixture(Layout::Clustered, ExecStream::Retained);
    let mut bad = f.exec.stmt.clone();
    bad.sum[0] += 1;
    assert!(verify_exec_stage(&f.exec, &bad).is_err(), "wrong sum accepted");
    let mut bad = f.exec.stmt.clone();
    bad.count += 1;
    assert!(verify_exec_stage(&f.exec, &bad).is_err(), "wrong count accepted");
    let mut bad = f.exec.stmt.clone();
    bad.theta += 1;
    assert!(verify_exec_stage(&f.exec, &bad).is_err(), "wrong theta accepted");
    // the prover cannot make a proof for a wrong claim either
    let (wl, claim, _) = exec_input(&f.log, &f.so, ExecStream::Retained);
    let r = prove_exec_stage(&wl, exec_ctx(&f.auth), (claim.0 + 1, claim.1));
    let accepted = match r {
        Err(_) => false,
        Ok((p, _)) => verify_exec_stage(&p, &p.stmt).is_ok(),
    };
    assert!(!accepted, "a proof for a wrong claimed count was accepted");
    // and a requester that asked for another theta refuses the statement before any proof check
    let mut other_theta = ExecProof { bytes: f.exec.bytes.clone(), stmt: f.exec.stmt.clone() };
    other_theta.stmt.theta += 1;
    assert!(verify_requester(&f.auth, &other_theta, &f.rc.stmt).is_err());
}

#[test]
fn exec_context_is_bound_to_the_auth_statement() {
    let f = fixture(Layout::Clustered, ExecStream::Retained);
    // (1) the native C_Q link: an Exec statement with another ctx is refused by the requester
    let mut e = ExecProof { bytes: f.exec.bytes.clone(), stmt: f.exec.stmt.clone() };
    e.stmt.ctx = [0; 4];
    assert!(verify_requester(&f.auth, &e, &f.rc.stmt).is_err(), "a different C_Q was accepted by the requester");
    // (2) the proof itself binds ctx as a public value: the unchanged proof does not verify against another ctx
    assert!(verify_exec_stage(&f.exec, &e.stmt).is_err(), "the Exec proof verified against a different ctx");
    // (3) the old w30 ctx (= B_Q itself) is not C_Q any more
    let mut e2 = ExecProof { bytes: f.exec.bytes.clone(), stmt: f.exec.stmt.clone() };
    e2.stmt.ctx = f.auth.stmt.b_q;
    assert!(verify_requester(&f.auth, &e2, &f.rc.stmt).is_err(), "ctx = B_Q accepted");
}

#[test]
fn tampered_auth_statement_is_rejected() {
    let f = fixture(Layout::Clustered, ExecStream::Retained);
    let mut a = AuthProof { bytes: f.auth.bytes.clone(), stmt: f.auth.stmt.clone() };
    a.stmt.omega[0] = (a.stmt.omega[0] + 1) % GOLDILOCKS_P;
    assert!(verify_auth_stage(&a).is_err(), "Auth with a changed Omega accepted");
    let mut a = AuthProof { bytes: f.auth.bytes.clone(), stmt: f.auth.stmt.clone() };
    a.stmt.d_q[0] = (a.stmt.d_q[0] + 1) % GOLDILOCKS_P;
    assert!(verify_auth_stage(&a).is_err(), "Auth with a changed d_Q accepted");
}

/// NEW (L5): a tampered proof is rejected, for each of the three relations, at several byte positions.
#[test]
fn tampered_proof_bytes_are_rejected() {
    let f = fixture(Layout::Clustered, ExecStream::Retained);
    // sanity: the untouched proofs pass
    verify_rc_stage(&f.rc).expect("rc");
    verify_auth_stage(&f.auth).expect("auth");
    verify_exec_stage(&f.exec, &f.exec.stmt).expect("exec");
    for &pos in &[0usize, 20, 100, 1000, 5000, 20000, 40000] {
        let mut rc = RcProof { bytes: f.rc.bytes.clone(), stmt: f.rc.stmt.clone() };
        let p = pos.min(rc.bytes.len() - 1);
        rc.bytes[p] ^= 0x01;
        assert!(verify_rc_stage(&rc).is_err(), "R_RC proof with byte {p} flipped accepted");
        let mut au = AuthProof { bytes: f.auth.bytes.clone(), stmt: f.auth.stmt.clone() };
        let p = pos.min(au.bytes.len() - 1);
        au.bytes[p] ^= 0x01;
        assert!(verify_auth_stage(&au).is_err(), "R_Auth proof with byte {p} flipped accepted");
        let mut ex = ExecProof { bytes: f.exec.bytes.clone(), stmt: f.exec.stmt.clone() };
        let p = pos.min(ex.bytes.len() - 1);
        ex.bytes[p] ^= 0x01;
        assert!(verify_exec_stage(&ex, &ex.stmt).is_err(), "R_Exec proof with byte {p} flipped accepted");
        assert!(verify_requester(&f.auth, &ex, &f.rc.stmt).is_err(), "requester accepted a tampered R_Exec proof");
    }
    // the last byte, a truncated proof and an empty proof
    let mut ex = ExecProof { bytes: f.exec.bytes.clone(), stmt: f.exec.stmt.clone() };
    let l = ex.bytes.len();
    ex.bytes[l - 1] ^= 0x80;
    assert!(verify_exec_stage(&ex, &ex.stmt).is_err());
    ex.bytes.truncate(l / 2);
    assert!(verify_exec_stage(&ex, &ex.stmt).is_err());
    ex.bytes.clear();
    assert!(verify_exec_stage(&ex, &ex.stmt).is_err());
    // an R_RC proof is not an R_Exec proof (swapped proofs)
    let swapped = ExecProof { bytes: f.rc.bytes.clone(), stmt: f.exec.stmt.clone() };
    assert!(verify_exec_stage(&swapped, &swapped.stmt).is_err());
}

/// NEW (L5): a mismatched stream, R_RC of one log + R_Exec of another, is rejected by the requester's stream link (and by the gates).
#[test]
fn mismatched_stream_is_rejected() {
    let a = fixture_seed(Layout::Clustered, ExecStream::Whole, SEED);
    let b = fixture_seed(Layout::Clustered, ExecStream::Whole, SEED + 1);
    // both honest on their own
    verify_requester(&a.auth, &a.exec, &a.rc.stmt).expect("A with A");
    verify_requester(&b.auth, &b.exec, &b.rc.stmt).expect("B with B");
    assert_ne!(a.rc.stmt.digest, b.rc.stmt.digest, "the two logs must differ");
    // R_RC of A + R_Exec of B (the ctx of B's exec belongs to B's Auth, so use B's Auth: the only failing check is the stream link)
    let err = verify_requester(&b.auth, &b.exec, &a.rc.stmt).err().expect("mismatched stream accepted");
    assert!(err.msg.contains("link: R_RC digest != R_Exec digest"), "unexpected rejection reason: {}", err.msg);
    // the proofs themselves are valid, so only the link catches it
    verify_rc_stage(&a.rc).expect("A rc proof");
    verify_exec_stage(&b.exec, &b.exec.stmt).expect("B exec proof");
    // the gates also see it: A's gate input with B's Exec proof
    let mut g = fixture(Layout::Clustered, ExecStream::Whole);
    g.exec = ExecProof { bytes: b.exec.bytes.clone(), stmt: b.exec.stmt.clone() };
    assert!(gate(&g).is_err(), "gates missed a foreign Exec proof");
    // the same, with a stream of the same length but one changed word in the Exec words
    let mut w = a.exec_wl.clone();
    w.words[3][4] ^= 1;
    let (ex, _) = prove_exec_stage(&w, exec_ctx(&a.auth), a.claim).expect("prove");
    assert!(verify_requester(&a.auth, &ex, &a.rc.stmt).is_err(), "a stream with a changed word was linked to the RC digest");
}

/// What the subset link does and does not give (CHANGES-w34.md, "deviation"): with the retained-blocks stream the requester can only check
/// block size and block count, NOT that the retained words are blocks of the R_RC stream. The gates (which hold the log) catch that.
#[test]
fn subset_link_is_weaker_and_the_gates_cover_it() {
    let f = fixture(Layout::Clustered, ExecStream::Retained);
    assert!(f.exec.stmt.n_blocks < f.rc.stmt.n_blocks, "clustered N=2000 seed {SEED:#x}: expected fewer retained blocks than blocks");
    let (_t, link) = verify_requester(&f.auth, &f.exec, &f.rc.stmt).expect("honest subset");
    assert_eq!(link, LinkKind::Subset);
    // checks that still bite on a subset
    let mut bs = ExecProof { bytes: f.exec.bytes.clone(), stmt: f.exec.stmt.clone() };
    bs.stmt.block_size += 1;
    assert!(requester_native_checks(&f.auth.stmt, &bs.stmt, &f.rc.stmt).is_err(), "block_size mismatch accepted");
    let mut nb = f.exec.stmt.clone();
    nb.n_blocks = f.rc.stmt.n_blocks + 1;
    assert!(requester_native_checks(&f.auth.stmt, &nb, &f.rc.stmt).is_err(), "more blocks than the epoch accepted");
    nb.n_blocks = 0;
    assert!(requester_native_checks(&f.auth.stmt, &nb, &f.rc.stmt).is_err(), "zero blocks accepted");
    // a foreign subset (other log, same size) passes the requester's native link ...
    let g = fixture_seed(Layout::Clustered, ExecStream::Retained, SEED + 1);
    assert!(g.exec.stmt.n_blocks < f.rc.stmt.n_blocks);
    {
        let r = verify_requester(&g.auth, &g.exec, &f.rc.stmt);
        assert!(r.is_ok(), "subset link is expected to accept a foreign subset (documented gap): {:?}", r.err().map(|e| e.msg));
        // ... and the gates catch it
        let mut h = fixture(Layout::Clustered, ExecStream::Retained);
        h.exec = ExecProof { bytes: g.exec.bytes.clone(), stmt: g.exec.stmt.clone() };
        h.exec_wl = g.exec_wl.clone();
        h.exec_used = g.exec_used.clone();
        h.claim = g.claim;
        assert!(gate(&h).is_err(), "gates missed a foreign subset");
    }
}

#[test]
fn dropped_hit_block_in_exec_stream_is_caught_by_the_gates() {
    let mut f = fixture(Layout::Scattered, ExecStream::Retained);
    // a malicious CSP drops one retained block that holds a hit, and claims the result of what is left
    let flags = f.so.flags.clone();
    let hit = (0..flags.len()).find(|&b| flags[b] && f.so.sel.iter().any(|&id| id as usize / BLOCK == b)).expect("a hit block");
    let mut so2 = SearchOut { flags: flags.clone(), sel: f.so.sel.clone(), bps_s: 0.0, rps_s: 0.0 };
    so2.flags[hit] = false;
    so2.sel.retain(|&id| id as usize / BLOCK != hit);
    let (wl, claim, used) = exec_input(&f.log, &so2, ExecStream::Retained);
    if wl.n_blocks == 0 {
        return;
    }
    let (ex, _) = prove_exec_stage(&wl, exec_ctx(&f.auth), claim).expect("exec prove");
    // the Exec verifier accepts (it proves the statement about THESE words only) ...
    verify_exec_stage(&ex, &ex.stmt).expect("exec proof of the smaller stream verifies");
    // ... the gates do not, because the search/plaintext reference has more matches
    f.so = so2;
    f.exec_wl = wl;
    f.exec_used = used;
    f.claim = claim;
    f.exec = ex;
    assert!(gate(&f).is_err(), "gates missed a dropped hit block");
}

#[test]
fn exec_stream_with_a_changed_word_is_caught_by_the_gates() {
    let mut f = fixture(Layout::Clustered, ExecStream::Retained);
    // change the b of one selected record inside the Exec stream and prove that stream with the matching (wrong) sum
    let i = f.exec_wl.words.iter().position(|w| w[7] == 0 && w[4] >= THETA).expect("a matching word");
    f.exec_wl.words[i][5] += 1;
    let claim = (f.claim.0, f.claim.1 + 1);
    let (ex, _) = prove_exec_stage(&f.exec_wl, exec_ctx(&f.auth), claim).expect("prove");
    f.claim = claim;
    f.exec = ex;
    assert!(gate(&f).is_err(), "a changed word in the Exec stream passed the gates");
}

#[test]
fn rc_and_exec_digests_follow_the_stream() {
    let f = fixture(Layout::Clustered, ExecStream::Retained);
    assert_eq!(ref_chain_digest(&f.log.wl.words), f.rc.stmt.digest);
    assert_eq!(ref_chain_digest(&f.exec_wl.words), f.exec.stmt.digest);
    let mut w = f.log.wl.words.clone();
    w[1][4] += 1;
    assert_ne!(ref_chain_digest(&w), f.rc.stmt.digest);
    // the reference chain agrees with w33's own native digest (two independent sponge implementations)
    use pqz_plonky3_w36::air::native_digest;
    use pqz_plonky3_w36::c1;
    assert_eq!(native_digest::<c1::Val, 12, _>(&c1::lay(), &c1::perm(), &c1::words(&f.log.wl)), ref_chain_digest(&f.log.wl.words));
}

#[test]
fn descriptor_tags_and_ids_tie_search_to_stream() {
    let f = fixture(Layout::Scattered, ExecStream::Retained);
    for (i, r) in f.records.iter().enumerate() {
        let w = &f.log.wl.words[(i / BLOCK) * (BLOCK + 1) + 1 + i % BLOCK];
        assert_eq!(w[3], r.id);
        assert_eq!(w[6], u64::from_le_bytes(f.log.descriptors[i][..8].try_into().unwrap()) % GOLDILOCKS_P);
    }
    let mut ids: Vec<u64> = f.exec_wl.words.iter().filter(|w| w[7] == 0 && w[4] >= THETA).map(|w| w[3]).collect();
    ids.sort_unstable();
    assert_eq!(ids, f.so.sel);
    // a changed descriptor tag in the stream is caught by the gates
    let mut f2 = fixture(Layout::Scattered, ExecStream::Retained);
    f2.log.wl.words[1][6] += 1;
    assert!(gate(&f2).is_err());
}

#[test]
fn ledger_anchor_accepted_and_omega_checked() {
    let f = fixture(Layout::Clustered, ExecStream::Retained);
    ledger_read_gate(&f.lc, &f.omega).expect("light-client read");
    let mut bad = f.omega;
    bad[0] ^= 1;
    assert!(ledger_read_gate(&f.lc, &bad).is_err(), "a wrong Omega was accepted");
    // the Auth statement carries the same Omega (8 bytes LE mod p per element)
    assert_eq!(f.auth.stmt.omega, f4(&f.omega));
    // the chain advances: a second anchor becomes epoch 2 and leaves State[1] (and its Omega) unchanged
    let mut lc = f.lc;
    commit_epoch(&mut lc, f.log.r_e, N as u64, (N / BLOCK) as u64).expect("second anchor = epoch 2");
    ledger_read_gate(&lc, &f.omega).expect("State[1] unchanged");
}

#[test]
fn statements_are_built_from_the_driver_log() {
    // the R_RC statement: block size BLOCK = 500, one header word per block, G blocks, header0 = the first header of the log
    let f = fixture(Layout::Clustered, ExecStream::Retained);
    assert_eq!(f.rc.stmt.block_size, BLOCK);
    assert_eq!(f.rc.stmt.n_blocks, N / BLOCK);
    assert_eq!(f.rc.stmt.n_words(), f.log.wl.words.len());
    assert_eq!(f.rc.stmt.header0, f.log.wl.words[0]);
    // the R_Exec statement: theta = THETA, count/sum = the search claim, ctx = C_Q
    assert_eq!(f.exec.stmt.block_size, BLOCK);
    assert_eq!(f.exec.stmt.theta, THETA);
    assert_eq!((f.exec.stmt.count, f.exec.stmt.sum_int()), f.claim);
    assert_eq!(f.exec.stmt.ctx, exec_ctx(&f.auth));
    assert_eq!(f.exec.stmt.n_words(), f.exec_wl.words.len());
}

#[test]
fn bad_arguments() {
    assert_eq!(run_one(1234, Layout::Clustered, &setting(), SEED).err().map(|e| e.code), Some(2));
    assert!(setting_of("S9").is_err());
    // the w30 settings are not offered by this driver
    assert_eq!(setting_of("S0").err().map(|e| e.code), Some(2));
    assert_eq!(setting_of("S2").err().map(|e| e.code), Some(2));
    assert!(setting_of("P3").is_ok());
}

/// L5 evidence: count and sum at n = 2000, seed DEFAULT_SEED, clustered. Printed (`--nocapture`) so they can be compared with the w30 run of the
/// same seed (both drivers gate the claim against the plain reference over the same generated records, `pqz_eval::gen`).
#[test]
fn count_and_sum_at_n2000_match_the_plain_reference() {
    let f = fixture(Layout::Clustered, ExecStream::Retained);
    let plain_count = f.records.iter().filter(|r| pqz_eval::Predicate::P1.matches(r)).count() as u64;
    let plain_sum: u64 = f.records.iter().filter(|r| pqz_eval::Predicate::P1.matches(r)).map(|r| r.b as u64).sum();
    eprintln!("L5 count={} sum={} (claim count={} sum={}; stmt count={} sum={})", plain_count, plain_sum, f.claim.0, f.claim.1, f.exec.stmt.count, f.exec.stmt.sum_int());
    assert_eq!(f.claim, (plain_count, plain_sum));
    assert_eq!((f.exec.stmt.count, f.exec.stmt.sum_int()), (plain_count, plain_sum));
}
