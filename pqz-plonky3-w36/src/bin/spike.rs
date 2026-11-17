//! Smoke driver: one prove + verify per call. NOT a measurement driver.
//! usage: spike <c1|c1r0|c2> <n_records>

use pqz_plonky3_w36::data::Workload;
use pqz_plonky3_w36::{c1, c1r0, c2, FriOpts};
use std::time::Instant;

macro_rules! run {
    ($m:ident, $n:expr) => {{
        let o = FriOpts::default();
        let w = Workload::synthetic($n, 100, 1);
        let p = $m::public_for(&w, 1u64 << 31, [1, 2, 3, 4]);
        let t = Instant::now();
        let proof = $m::prove_with(&o, &w, &p).expect("prove");
        let t_prove = t.elapsed();
        let bytes = $m::to_bytes(&proof);
        let t = Instant::now();
        $m::verify_with(&o, &proof, &p).expect("verify");
        let t_verify = t.elapsed();
        println!(
            "{} n={} rows={} width={} count={} sum_int={} prove_s={:.3} verify_ms={:.2} proof_bytes={}",
            $m::LABEL,
            $n,
            $m::n_rows(p.n_words()),
            $m::lay().width,
            p.count,
            p.sum_int(),
            t_prove.as_secs_f64(),
            t_verify.as_secs_f64() * 1e3,
            bytes.len()
        );
    }};
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let n: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(1000);
    match a.get(1).map(|s| s.as_str()) {
        Some("c1") => run!(c1, n),
        Some("c1r0") => run!(c1r0, n),
        Some("c2") => run!(c2, n),
        _ => eprintln!("usage: spike <c1|c1r0|c2> <n_records>"),
    }
}
