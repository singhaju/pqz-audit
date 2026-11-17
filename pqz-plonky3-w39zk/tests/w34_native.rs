//! w34: native verifier checks (C1 digest link, C2 scope order), the `fri=hi` preset (C3) and honest proofs under both presets.
//! Run in release mode: `cargo test --release`.
use pqz_plonky3_w38::auth::{honest_auth_instance, AuthPublic, AuthWitness};
use pqz_plonky3_w38::data::Workload;
use pqz_plonky3_w38::rel::{plain, zk};
use pqz_plonky3_w38::request::{
    check_scope, check_stream_link, exec_context, native_bundle_checks, verify_bundle, verify_bundle_with, NativeChecks,
};
use pqz_plonky3_w38::security::estimate;
use pqz_plonky3_w38::{c1, c1zk, FriOpts};

const RID: u64 = 1;
const THETA: u64 = 1 << 31;

struct Bundle {
    apub: AuthPublic,
    epub: pqz_plonky3_w38::air::ExecPublic,
    rpub: pqz_plonky3_w38::rc::RcPublic,
    pa: c1::P,
    pe: c1::P,
    pr: c1::P,
}

fn make(o: &FriOpts, n: usize, seed: u64, apub: AuthPublic, awit: &AuthWitness) -> Bundle {
    let w = Workload::synthetic(n, 100, seed);
    let ctx = exec_context(&c1::perm(), apub.b_q, apub.d_q, RID);
    let epub = c1::public_for(&w, THETA, ctx);
    let rpub = plain::rc_public(&c1::words(&w), 100);
    let pe = plain::prove_exec(o, &w, &epub).unwrap();
    let pr = plain::prove_rc(o, &c1::words(&w), &rpub).unwrap();
    let pa = plain::prove_auth(o, &apub, awit).unwrap();
    Bundle { apub, epub, rpub, pa, pe, pr }
}

/// C1: the honest R_Exec digest and the honest R_RC digest of one stream are the same number by construction
/// (`variants::c1::public_for` and `rel::plain::rc_public` both call `air::native_digest` with the same permutation, the same
/// `Layout` fields rate/cap/dig/wlen and the same mapped words `c1::words`).
#[test]
fn digests_equal_by_construction() {
    for (n, bs, seed) in [(100usize, 100usize, 1u64), (1000, 100, 1), (1000, 100, 9), (500, 50, 3), (5000, 100, 2), (20000, 100, 5), (2000, 20, 4)] {
        let w = Workload::synthetic(n, bs, seed);
        let e = c1::public_for(&w, THETA, [1, 2, 3, 4]);
        let r = plain::rc_public(&c1::words(&w), bs);
        assert_eq!(e.digest, r.digest, "n={n} bs={bs}");
        assert_eq!((e.n_blocks, e.block_size), (r.n_blocks, r.block_size));
        check_stream_link(&e, &r).unwrap();
        // zk mode shares the same functions
        let rz = zk::rc_public(&c1zk::words(&w), bs);
        assert_eq!(c1zk::public_for(&w, THETA, [1, 2, 3, 4]).digest, rz.digest);
        assert_eq!(rz.digest, r.digest);
    }
    // layouts of the two native digests: the fields that enter the sponge are equal
    let le = c1::lay();
    let lr = pqz_plonky3_w38::air::Layout::new(0, 12, 0);
    assert_eq!((le.rate, le.cap, le.dig, le.wlen), (lr.rate, lr.cap, lr.dig, lr.wlen));
}

#[test]
fn stream_link_rejects() {
    let w = Workload::synthetic(1000, 100, 1);
    let e = c1::public_for(&w, THETA, [1, 2, 3, 4]);
    let r = plain::rc_public(&c1::words(&w), 100);
    let mut r1 = r.clone();
    r1.digest[0] ^= 1;
    assert!(check_stream_link(&e, &r1).unwrap_err().starts_with("link: "));
    let mut r2 = r.clone();
    r2.n_blocks += 1;
    assert!(check_stream_link(&e, &r2).unwrap_err().starts_with("link: "));
    let mut r3 = r.clone();
    r3.block_size += 1;
    assert!(check_stream_link(&e, &r3).unwrap_err().starts_with("link: "));
    // another stream of the same shape
    let w2 = Workload::synthetic(1000, 100, 2);
    let r4 = plain::rc_public(&c1::words(&w2), 100);
    assert!(check_stream_link(&e, &r4).unwrap_err().starts_with("link: "));
}

#[test]
fn scope_order_check() {
    let (a, _) = honest_auth_instance::<c1::Val, _>(&c1::perm(), 10, 1);
    check_scope(&a).unwrap();
    for which in 0..3 {
        let mut b = a.clone();
        let r = match which {
            0 => &mut b.scope.s,
            1 => &mut b.scope.e,
            _ => &mut b.scope.t,
        };
        std::mem::swap(&mut r.0, &mut r.1);
        assert!(r.0 > r.1);
        assert!(check_scope(&b).unwrap_err().starts_with("scope: "), "range {which}");
        // equal start and end is allowed
        let mut c = a.clone();
        let rr = match which {
            0 => &mut c.scope.s,
            1 => &mut c.scope.e,
            _ => &mut c.scope.t,
        };
        rr.1 = rr.0;
        check_scope(&c).unwrap();
    }
}

#[test]
fn checks_on_off_with_real_proofs() {
    let o = FriOpts::from_env();
    let (apub, awit) = honest_auth_instance::<c1::Val, _>(&c1::perm(), 10, 1);
    let b = make(&o, 1000, 1, apub.clone(), &awit);
    // honest: accepted with checks on and off, and by the plain `verify_bundle`
    verify_bundle(&o, &b.pa, &b.apub, &b.pe, &b.epub, &b.pr, &b.rpub, RID).unwrap();
    verify_bundle_with(NativeChecks::OFF, &o, &b.pa, &b.apub, &b.pe, &b.epub, &b.pr, &b.rpub, RID).unwrap();
    native_bundle_checks(NativeChecks::ON, &b.apub, &b.epub, &b.rpub, RID).unwrap();

    // stream mismatch: honest R_RC of stream A, honest R_Exec of stream B
    let wb = Workload::synthetic(1000, 100, 77);
    let epub_b = c1::public_for(&wb, THETA, b.epub.ctx);
    let pe_b = plain::prove_exec(&o, &wb, &epub_b).unwrap();
    plain::verify_exec(&o, &pe_b, &epub_b).unwrap();
    let on = verify_bundle(&o, &b.pa, &b.apub, &pe_b, &epub_b, &b.pr, &b.rpub, RID);
    assert!(on.as_ref().unwrap_err().starts_with("link: "), "{on:?}");
    let off = verify_bundle_with(NativeChecks::OFF, &o, &b.pa, &b.apub, &pe_b, &epub_b, &b.pr, &b.rpub, RID);
    assert!(off.is_ok(), "expected the unchecked verifier to accept: {off:?}");

    // inverted scope: honest proofs of a statement with start > end (inside the policy leaf: s = (500, 4000))
    let mut inv = apub.clone();
    inv.scope.s = (2000, 1000);
    let pa_inv = plain::prove_auth(&o, &inv, &awit).expect("the prover can prove an inverted scope");
    let on = verify_bundle(&o, &pa_inv, &inv, &b.pe, &b.epub, &b.pr, &b.rpub, RID);
    assert!(on.as_ref().unwrap_err().starts_with("scope: "), "{on:?}");
    let off = verify_bundle_with(NativeChecks::OFF, &o, &pa_inv, &inv, &b.pe, &b.epub, &b.pr, &b.rpub, RID);
    assert!(off.is_ok(), "expected the unchecked verifier to accept: {off:?}");
}

/// C3: HI_NUM_QUERIES is the smallest value with proven unique decoding >= 100 for every relation and every N of the grid.
#[test]
fn hi_preset_is_minimal() {
    let grid = [1000usize, 2000, 5000, 10000, 20000, 50000, 100000];
    let min_udr = |q: usize| -> u32 {
        let o = FriOpts { num_queries: q, ..FriOpts::default() };
        let mut m = u32::MAX;
        for n in grid {
            let rows = c1::n_rows((n / 100) * 101);
            m = m.min(estimate(&c1::sec_input(&o, rows)).proven_unique_decoding);
        }
        m.min(estimate(&c1::sec_input(&o, plain::auth_rows(10))).proven_unique_decoding)
    };
    let hi = FriOpts::hi();
    assert_eq!((hi.log_blowup, hi.query_pow_bits, hi.log_final_poly_len, hi.max_log_arity), (3, 16, 5, 3));
    assert!(min_udr(hi.num_queries) >= 100);
    assert!(min_udr(hi.num_queries - 1) < 100);
    let s = FriOpts::std();
    assert_eq!(s.num_queries, 40);
    assert_eq!(min_udr(40), 49);
}

#[test]
fn honest_hi_plain_and_zk() {
    let o = FriOpts::hi();
    let w = Workload::synthetic(1000, 100, 1);
    let words = c1::words(&w);
    let (apub, awit) = honest_auth_instance::<c1::Val, _>(&c1::perm(), 10, 1);
    // plain
    let b = make(&o, 1000, 1, apub.clone(), &awit);
    verify_bundle(&o, &b.pa, &b.apub, &b.pe, &b.epub, &b.pr, &b.rpub, RID).unwrap();
    // a proof made with `hi` must NOT verify under `std` (the verifier uses its own options)
    assert!(plain::verify_rc(&FriOpts::std(), &b.pr, &b.rpub).is_err());
    // zk
    let rpub = zk::rc_public(&words, 100);
    let pr = zk::prove_rc(&o, &words, &rpub).unwrap();
    zk::verify_rc(&o, &pr, &rpub).unwrap();
    let epub = c1zk::public_for(&w, THETA, [1, 2, 3, 4]);
    let pe = zk::prove_exec(&o, &w, &epub).unwrap();
    zk::verify_exec(&o, &pe, &epub).unwrap();
    let a = zk::auth_air_for(&o, 10);
    let trace = a.build_trace(&c1zk::perm(), &apub, &awit).unwrap();
    let pv = apub.to_values::<c1zk::Val>();
    let pa = p3_uni_stark::prove(&c1zk::config(&o), &a, trace, &pv).unwrap();
    zk::verify_auth(&o, &pa, &apub).unwrap();
}
