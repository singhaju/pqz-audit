//! Stage C: honest proofs of R_RC and R_Auth verify (plain and ZK), release build.
use pqz_plonky3_w36::auth::honest_auth_instance;
use pqz_plonky3_w36::data::Workload;
use pqz_plonky3_w36::rel::{plain, zk};
use pqz_plonky3_w36::{c1, FriOpts};

#[test]
fn rc_honest_plain() {
    let o = FriOpts::from_env();
    for (n, bs) in [(1000usize, 100usize), (200, 100), (5000, 100)] {
        let w = Workload::synthetic(n, bs, 1);
        let words = c1::words(&w);
        let p = plain::rc_public(&words, bs);
        let proof = plain::prove_rc(&o, &words, &p).expect("prove");
        let b = plain::to_bytes(&proof);
        let pr = plain::from_bytes(&b).unwrap();
        plain::verify_rc(&o, &pr, &p).expect("verify");
        eprintln!("rc n={n} bytes={}", b.len());
    }
}

#[test]
fn auth_honest_plain() {
    let o = FriOpts::from_env();
    for depth in [1usize, 5, 10, 20] {
        let (p, w) = honest_auth_instance::<c1::Val, _>(&c1::perm(), depth, 7);
        let proof = plain::prove_auth(&o, &p, &w).expect("prove");
        plain::verify_auth(&o, &proof, &p).expect("verify");
    }
}

#[test]
fn honest_zk() {
    let o = FriOpts::from_env();
    let w = Workload::synthetic(1000, 100, 1);
    let words = c1::words(&w);
    let p = zk::rc_public(&words, 100);
    let proof = zk::prove_rc(&o, &words, &p).expect("prove");
    zk::verify_rc(&o, &proof, &p).expect("verify");
    let (pa, wa) = honest_auth_instance::<c1::Val, _>(&c1::perm(), 10, 7);
    let proof = zk::prove_auth(&o, &pa, &wa).expect("prove");
    zk::verify_auth(&o, &proof, &pa).expect("verify");
}
