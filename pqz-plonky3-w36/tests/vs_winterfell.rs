//! Same data, same result as winterfell (w30). Method: the w30 library crate is a read-only path dev-dependency.
//!  (1) our generator (src/data.rs) equals w30 `Workload::synthetic` word by word;
//!  (2) w30 `prove_exec` + `verify_exec` (a real winterfell proof of R_Exec) give (count, sum); ours must be equal;
//!  (3) our Plonky3 proofs (C1, C1 with 0 registers, C2) verify and carry the same count and integer sum.
//! Run with `cargo test --release` (the debug build runs a constraint checker that panics on bad traces).

use pqz_plonky3_w36::data::Workload;
use pqz_plonky3_w36::{c1, c1r0, c2, FriOpts};
use pqz_proof::data::Workload as W30;
use pqz_proof::exec::{prove_exec, verify_exec};
use pqz_proof::rescue::F as F30;

const THETA: u64 = 1 << 31;

fn check_generator(n: usize) {
    let a = Workload::synthetic(n, 100, 1);
    let b = W30::synthetic(n, 100, 1);
    assert_eq!(a.words.len(), b.words.len());
    for (i, (x, y)) in a.words.iter().zip(b.words.iter()).enumerate() {
        for j in 0..8 {
            assert_eq!(x[j], y[j].as_int(), "word {i} elem {j}");
        }
    }
    let (c, s) = a.reference_result(THETA);
    let (c30, s30) = b.reference_result(THETA);
    assert_eq!((c, s), (c30, s30));
}

fn winterfell_result(n: usize) -> (u64, u64) {
    let w = W30::synthetic(n, 100, 1);
    let ctx = [F30::new(1), F30::new(2), F30::new(3), F30::new(4)];
    let (proof, p) = prove_exec(&w, THETA, ctx).expect("winterfell prove");
    verify_exec(proof, p.clone()).expect("winterfell verify");
    (p.count, p.sum)
}

macro_rules! plonky3_matches {
    ($m:ident, $n:expr, $wcount:expr, $wsum:expr) => {{
        let o = FriOpts::from_env();
        let w = Workload::synthetic($n, 100, 1);
        let p = $m::public_for(&w, THETA, [1, 2, 3, 4]);
        let proof = $m::prove_with(&o, &w, &p).expect("plonky3 prove");
        $m::verify_with(&o, &proof, &p).expect("plonky3 verify");
        assert_eq!(p.count, $wcount, "{} count", $m::LABEL);
        assert_eq!(p.sum_int(), $wsum, "{} sum", $m::LABEL);
        println!("{} n={} count={} sum={} (winterfell: {} {}) proof_bytes={}", $m::LABEL, $n, p.count, p.sum_int(), $wcount, $wsum, $m::to_bytes(&proof).len());
    }};
}

#[test]
fn generator_equals_w30_1e3() {
    check_generator(1000);
}
#[test]
fn generator_equals_w30_1e4() {
    check_generator(10_000);
}

#[test]
fn same_result_as_winterfell_1e3() {
    let (wc, ws) = winterfell_result(1000);
    plonky3_matches!(c1, 1000, wc, ws);
    plonky3_matches!(c1r0, 1000, wc, ws);
    plonky3_matches!(c2, 1000, wc, ws);
}

#[test]
fn same_result_as_winterfell_1e4() {
    let (wc, ws) = winterfell_result(10_000);
    plonky3_matches!(c1, 10_000, wc, ws);
    plonky3_matches!(c2, 10_000, wc, ws);
}
