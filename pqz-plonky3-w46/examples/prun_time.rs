//! LAPTOP SMOKE (informational only, never a benchmark): old run.rs (one record per word) vs prun (packed) over ALL blocks of one stream.
//! usage: prun_time [n=100000] [block=500] [fri=fast1]   (use taskset -c 1 for 1 thread)
use pqz_plonky3_w46::chunk::iv_state;
use pqz_plonky3_w46::data::Workload;
use pqz_plonky3_w46::pair::pack_workload;
use pqz_plonky3_w46::{run, prun, FriOpts};
use std::time::Instant;
fn arg(a: &[String], k: &str) -> Option<String> { a.iter().find_map(|x| x.strip_prefix(&format!("{k}=")).map(|s| s.to_string())) }
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let n: usize = arg(&a, "n").and_then(|s| s.parse().ok()).unwrap_or(100_000);
    let b: usize = arg(&a, "block").and_then(|s| s.parse().ok()).unwrap_or(500);
    let o = FriOpts::preset(&arg(&a, "fri").unwrap_or_else(|| "fast1".into())).expect("fri");
    let theta = 1u64 << 31;
    let wl = Workload::synthetic(n, b, 1);
    println!("LAPTOP SMOKE n={n} block={b} threads={}", std::thread::available_parallelism().map(|x| x.get()).unwrap_or(0));
    let old_words: Vec<Vec<u64>> = wl.words.iter().map(|w| w.to_vec()).collect();
    let op = run::plain::honest_public(&old_words, &iv_state(old_words.len() as u64), b, theta, [1, 2, 3, 4]);
    let t = Instant::now();
    let pr = run::plain::prove_run(&o, &old_words, &op).expect("old prove");
    let s = t.elapsed().as_secs_f64();
    let bytes = run::plain::to_bytes(&pr).len();
    let width = run::plain::run_air(&op).unwrap().lay.width;
    println!("old run.rs : rows={} width={} prove_s={:.3} proof_bytes={}", run::plain::run_rows(op.n_words()), width, s, bytes);
    let pw = pack_workload(&wl);
    let pp = prun::plain::honest_public(&pw, &iv_state(pw.len() as u64), b, theta, [1, 2, 3, 4]);
    let pwidth = prun::plain::run_air(&pp).unwrap().lay.cols.width;
    let (by, ts, ps, rows) = prun::plain::prove_run_bytes(&o, &pw, &pp).expect("prun prove");
    prun::plain::verify_run_bytes(&o, &by, &pp).expect("verify");
    println!("prun (seq trace): rows={rows} width={pwidth} trace_s={ts:.3} prove_s={ps:.3} proof_bytes={}", by.len());
    let (by2, ts2, ps2, _) = prun::plain::prove_run_bytes_par(&o, &pw, &pp).expect("prun par");
    println!("prun (par trace): trace_s={ts2:.3} prove_s={ps2:.3} proof_bytes={}", by2.len());
}
