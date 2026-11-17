//! w36 (S2): the speed presets `fast2` (log_blowup 2) and `fast1` (log_blowup 1), same tests for each preset (and for `std`, as the reference):
//!   honest proofs of every relation verify (plain and ZK; R_Exec, one-proof R_RC, R_Auth, chunk, run),
//!   the AIRs are unchanged, so tampered statements, flipped proof bytes and wrong options are rejected by the unchanged verifier,
//!   the query counts of the presets are exactly the smallest values of the fixed rule (re-derived here from `security.rs`).

use pqz_plonky3_w46::auth::honest_auth_instance;
use pqz_plonky3_w46::chunk::plain as ch;
use pqz_plonky3_w46::data::Workload;
use pqz_plonky3_w46::rel::{plain, zk};
use pqz_plonky3_w46::run::plain as rn;
use pqz_plonky3_w46::security::estimate;
use pqz_plonky3_w46::variants::{FAST1_NUM_QUERIES, FAST2_NUM_QUERIES};
use pqz_plonky3_w46::{c1, c1zk, FriOpts};
use std::panic::{catch_unwind, AssertUnwindSafe};

const THETA: u64 = 1 << 31;
const CTX: [u64; 4] = [1, 2, 3, 4];

fn presets() -> Vec<(&'static str, FriOpts)> {
    vec![("std", FriOpts::std()), ("fast2", FriOpts::fast2()), ("fast1", FriOpts::fast1())]
}

/// true iff verification was refused (an error or a panic inside the verifier both count as a rejection)
fn refused<T>(f: impl FnOnce() -> Result<T, String>) -> bool {
    match catch_unwind(AssertUnwindSafe(f)) {
        Err(_) | Ok(Err(_)) => true,
        Ok(Ok(_)) => false,
    }
}

#[test]
fn presets_have_the_documented_parameters() {
    let (f2, f1, s) = (FriOpts::fast2(), FriOpts::fast1(), FriOpts::std());
    for (o, lb, q) in [(&f2, 2usize, FAST2_NUM_QUERIES), (&f1, 1, FAST1_NUM_QUERIES)] {
        assert_eq!((o.log_blowup, o.num_queries), (lb, q));
        assert_eq!((o.query_pow_bits, o.log_final_poly_len, o.max_log_arity), (s.query_pow_bits, s.log_final_poly_len, s.max_log_arity));
    }
    assert_eq!((FAST2_NUM_QUERIES, FAST1_NUM_QUERIES), (61, 126));
    assert_eq!(FriOpts::preset("fast2").unwrap().num_queries, 61);
    assert_eq!(FriOpts::preset("fast1").unwrap().num_queries, 126);
    assert!(FriOpts::preset("fast3").is_none());
}

/// The fixed S2 rule: smallest q with conj >= 127, udr >= 49 and ldr >= std at every N for exec, rc, auth (plain heights, block 100).
#[test]
fn preset_query_counts_are_the_smallest_of_the_rule() {
    let grid = [1000usize, 2000, 5000, 10000, 20000, 50000, 100000];
    let heights = |n: usize| [c1::n_rows((n / 100) * 101), plain::auth_rows(10)];
    let passes = |lb: usize, q: usize| -> bool {
        let o = FriOpts { log_blowup: lb, num_queries: q, ..FriOpts::default() };
        grid.iter().all(|&n| {
            heights(n).iter().all(|&h| {
                let (s, t) = (estimate(&c1::sec_input(&o, h)), estimate(&c1::sec_input(&FriOpts::std(), h)));
                s.conjectured >= 127 && s.proven_unique_decoding >= 49 && s.proven_list_decoding >= t.proven_list_decoding
            })
        })
    };
    for (lb, q) in [(2usize, FAST2_NUM_QUERIES), (1, FAST1_NUM_QUERIES)] {
        assert!(passes(lb, q), "log_blowup {lb}: q={q} does not meet the rule");
        assert!(!passes(lb, q - 1), "log_blowup {lb}: q={} already meets the rule", q - 1);
    }
}

#[test]
fn honest_plain_all_relations_every_preset() {
    for (name, o) in presets() {
        // R_Exec and one-proof R_RC
        let w = Workload::synthetic(1000, 100, 1);
        let words = c1::words(&w);
        let epub = c1::public_for(&w, THETA, CTX);
        let pe = plain::prove_exec(&o, &w, &epub).expect("prove exec");
        plain::verify_exec(&o, &plain::from_bytes(&plain::to_bytes(&pe)).unwrap(), &epub).expect("verify exec");
        let rpub = plain::rc_public(&words, 100);
        let pr = plain::prove_rc(&o, &words, &rpub).expect("prove rc");
        plain::verify_rc(&o, &pr, &rpub).expect("verify rc");
        // R_Auth
        let (apub, awit) = honest_auth_instance::<c1::Val, _>(&c1::perm(), 10, 1);
        let pa = plain::prove_auth(&o, &apub, &awit).expect("prove auth");
        plain::verify_auth(&o, &pa, &apub).expect("verify auth");
        // chunk and run (w35), from a stored (non-IV) start state
        let w8 = Workload::synthetic(13 * 8, 8, 7);
        let words8 = c1::words(&w8);
        let (pubs, _) = ch::honest_publics(&words8, 8, 4);
        let mut fb = 0;
        for p in &pubs {
            let cw = &words8[fb * 9..(fb + p.n_blocks_chunk) * 9];
            let pc = ch::prove_chunk(&o, cw, p).expect("prove chunk");
            ch::verify_chunk(&o, &pc, p).expect("verify chunk");
            let rp = rn::honest_public(cw, &p.s_in, 8, THETA, CTX);
            let prn = rn::prove_run(&o, cw, &rp).expect("prove run");
            rn::verify_run(&o, &prn, &rp).expect("verify run");
            fb += p.n_blocks_chunk;
        }
        println!("{name}: honest plain exec/rc/auth/chunk/run verify; exec {} B, rc {} B, auth {} B", plain::to_bytes(&pe).len(), plain::to_bytes(&pr).len(), plain::to_bytes(&pa).len());
    }
}

#[test]
fn honest_zk_every_preset() {
    for (name, o) in presets() {
        let w = Workload::synthetic(1000, 100, 1);
        let words = c1zk::words(&w);
        let epub = c1zk::public_for(&w, THETA, CTX);
        let pe = zk::prove_exec(&o, &w, &epub).expect("prove exec zk");
        zk::verify_exec(&o, &pe, &epub).expect("verify exec zk");
        let rpub = zk::rc_public(&words, 100);
        let pr = zk::prove_rc(&o, &words, &rpub).expect("prove rc zk");
        zk::verify_rc(&o, &pr, &rpub).expect("verify rc zk");
        let (apub, awit) = honest_auth_instance::<c1zk::Val, _>(&c1zk::perm(), 10, 1);
        let pa = zk::prove_auth(&o, &apub, &awit).expect("prove auth zk");
        zk::verify_auth(&o, &pa, &apub).expect("verify auth zk");
        println!("{name}: honest zk exec/rc/auth verify");
    }
}

#[test]
fn rejections_every_preset() {
    for (name, o) in presets() {
        let w = Workload::synthetic(1000, 100, 1);
        let words = c1::words(&w);
        let epub = c1::public_for(&w, THETA, CTX);
        let pe = plain::prove_exec(&o, &w, &epub).unwrap();
        let rpub = plain::rc_public(&words, 100);
        let pr = plain::prove_rc(&o, &words, &rpub).unwrap();
        let (apub, awit) = honest_auth_instance::<c1::Val, _>(&c1::perm(), 10, 1);
        let pa = plain::prove_auth(&o, &apub, &awit).unwrap();

        // tampered public statements
        let mut e = epub.clone();
        e.count += 1;
        assert!(refused(|| plain::verify_exec(&o, &pe, &e)), "{name}: wrong count accepted");
        let mut e = epub.clone();
        e.sum[0] += 1;
        assert!(refused(|| plain::verify_exec(&o, &pe, &e)), "{name}: wrong sum accepted");
        let mut e = epub.clone();
        e.digest[0] = (e.digest[0] + 1) % pqz_plonky3_w46::data::GOLDILOCKS_P;
        assert!(refused(|| plain::verify_exec(&o, &pe, &e)), "{name}: wrong digest accepted");
        let mut e = epub.clone();
        e.ctx[0] += 1;
        assert!(refused(|| plain::verify_exec(&o, &pe, &e)), "{name}: wrong ctx accepted");
        let mut r = rpub.clone();
        r.digest[1] = (r.digest[1] + 1) % pqz_plonky3_w46::data::GOLDILOCKS_P;
        assert!(refused(|| plain::verify_rc(&o, &pr, &r)), "{name}: wrong rc digest accepted");
        let mut a = apub.clone();
        a.d_q[0] += 1;
        assert!(refused(|| plain::verify_auth(&o, &pa, &a)), "{name}: wrong auth statement accepted");

        // one changed record: honest proof of the changed data does not verify against the statement of the original data
        let mut w2 = w.clone();
        let mut r_ = 1;
        while w2.words[r_][7] == 1 {
            r_ += 1;
        }
        w2.words[r_][4] ^= 1;
        let bad = catch_unwind(AssertUnwindSafe(|| plain::prove_exec(&o, &w2, &epub)));
        if let Ok(Ok(pb)) = bad {
            assert!(refused(|| plain::verify_exec(&o, &pb, &epub)), "{name}: proof over changed data accepted");
        }

        // flipped proof bytes (10 positions)
        let bytes = plain::to_bytes(&pe);
        for t in 0..10usize {
            let pos = (t * 7919 + 13) % bytes.len();
            let mut b = bytes.clone();
            b[pos] ^= 0x40;
            let ok = refused(|| plain::from_bytes(&b).and_then(|p| plain::verify_exec(&o, &p, &epub)));
            assert!(ok, "{name}: proof with byte {pos} flipped accepted");
        }

        // fewer queries than the preset, same everything else: rejected by the preset's verifier
        let weak = FriOpts { num_queries: o.num_queries / 2, ..o.clone() };
        let pw = plain::prove_exec(&weak, &w, &epub).unwrap();
        plain::verify_exec(&weak, &pw, &epub).expect("weak proof verifies under its own options");
        assert!(refused(|| plain::verify_exec(&o, &pw, &epub)), "{name}: proof with fewer queries accepted");
    }
    // a proof under one preset is rejected under every other preset
    let w = Workload::synthetic(1000, 100, 1);
    let epub = c1::public_for(&w, THETA, CTX);
    let ps = presets();
    for (n1, o1) in &ps {
        let p = plain::prove_exec(o1, &w, &epub).unwrap();
        for (n2, o2) in &ps {
            if n1 != n2 {
                assert!(refused(|| plain::verify_exec(o2, &p, &epub)), "proof made with {n1} accepted by the {n2} verifier");
            }
        }
    }
}

/// Same (count, sum) and digest under every preset (the preset changes only the proof system parameters).
#[test]
fn statements_do_not_depend_on_the_preset() {
    let w = Workload::synthetic(1000, 100, 1);
    let epub = c1::public_for(&w, THETA, CTX);
    let (c, s) = w.reference_result(THETA);
    assert_eq!((epub.count, epub.sum_int()), (c, s));
    for (_, o) in presets() {
        // the statement is an input of the verifier; the proof verifies against exactly this statement under each preset
        let p = plain::prove_exec(&o, &w, &epub).unwrap();
        plain::verify_exec(&o, &p, &epub).unwrap();
    }
}
