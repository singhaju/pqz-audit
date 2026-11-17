//! Stage B measurement child (same protocol as the w30 child, `bench/pqz-proof-w30/src/bin/w30.rs`):
//! ONE fresh process per measurement point. It prepares the workload and the public statement outside any timer,
//! prints a READY line, performs ONE measured run per line "run" on stdin, prints a ROW line and then IDLE; exits on "quit".
//!
//! usage: pchild <c1|c1r0|c2|c1zk> n=N [block=100]
//!
//! ROW,<label>,<n>,<rows>,<width>,<count>,<sum_int>,<trace_s>,<prove_s>,<verify_s>,<proof_bytes>,<conj>,<udr>,<ldr>,<vmrss_kb>,<threads>
//!   trace_s  = words mapping + witness (trace) generation
//!   prove_s  = `p3_uni_stark::prove` (includes the FRI/Merkle commitments, Blake3)
//!   full     = trace_s + prove_s  (the gate metric "trace generation + prove")
//!   verify_s = proof bytes -> parse -> `verify` (as the w30 child: verification from bytes)
//! Untimed: Workload generation, native sponge digest (public statement), serialization of the proof for the size.

use pqz_plonky3_w36::data::Workload;
use pqz_plonky3_w36::{c1, c1r0, c1zk, c2, FriOpts};
use std::io::{BufRead, Write};
use std::time::Instant;

fn arg(args: &[String], key: &str) -> Option<String> {
    args.iter().find_map(|a| a.strip_prefix(&format!("{key}=")).map(|s| s.to_string()))
}

fn status_kb(key: &str) -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for l in s.lines() {
        if let Some(r) = l.strip_prefix(key) {
            return r.trim().trim_end_matches("kB").trim().parse().unwrap_or(0);
        }
    }
    0
}

fn emit(line: String) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}

macro_rules! child {
    ($m:ident, $n:expr, $block:expr) => {{
        let o = FriOpts::default();
        let w = Workload::synthetic($n, $block, 1);
        let p = $m::public_for(&w, 1u64 << 31, [1, 2, 3, 4]);
        let rows = $m::n_rows(p.n_words());
        let sec = pqz_plonky3_w36::security::estimate(&$m::sec_input(&o, rows));
        emit(format!(
            "READY,{},{},rows={},width={},queries={},log_blowup={},pow={}",
            $m::LABEL.replace(',', ";"),
            $n,
            rows,
            $m::lay().width,
            o.num_queries,
            o.log_blowup,
            o.query_pow_bits
        ));
        let stdin = std::io::stdin();
        for l in stdin.lock().lines().map_while(Result::ok) {
            match l.trim() {
                "run" => {
                    let t0 = Instant::now();
                    let a = $m::air(p.theta, p.n_words() as u64);
                    let trace = a.build_trace(&$m::perm(), &$m::words(&w));
                    let pv = p.to_values::<$m::Val>(&a.lay);
                    let trace_s = t0.elapsed().as_secs_f64();
                    let t1 = Instant::now();
                    let proof = match p3_uni_stark::prove(&$m::config(&o), &a, trace, &pv) {
                        Ok(x) => x,
                        Err(e) => {
                            eprintln!("prove failed: {e:?}");
                            std::process::exit(4);
                        }
                    };
                    let prove_s = t1.elapsed().as_secs_f64();
                    let bytes = $m::to_bytes(&proof);
                    drop(proof);
                    let t2 = Instant::now();
                    let parsed = $m::from_bytes(&bytes).expect("parse");
                    $m::verify_with(&o, &parsed, &p).expect("honest proof must verify");
                    let verify_s = t2.elapsed().as_secs_f64();
                    emit(format!(
                        "ROW,{},{},{},{},{},{},{:.6},{:.6},{:.6},{},{},{},{},{},{}",
                        $m::LABEL.replace(',', ";"),
                        $n,
                        rows,
                        $m::lay().width,
                        p.count,
                        p.sum_int(),
                        trace_s,
                        prove_s,
                        verify_s,
                        bytes.len(),
                        sec.conjectured,
                        sec.proven_unique_decoding,
                        sec.proven_list_decoding,
                        status_kb("VmRSS:"),
                        std::env::var("RAYON_NUM_THREADS").unwrap_or_default()
                    ));
                    emit("IDLE".to_string());
                }
                "quit" => break,
                _ => {}
            }
        }
    }};
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let n: usize = arg(&a, "n").and_then(|s| s.parse().ok()).expect("n=N");
    let block: usize = arg(&a, "block").and_then(|s| s.parse().ok()).unwrap_or(100);
    match a.get(1).map(|s| s.as_str()) {
        Some("c1") => child!(c1, n, block),
        Some("c1r0") => child!(c1r0, n, block),
        Some("c2") => child!(c2, n, block),
        Some("c1zk") => child!(c1zk, n, block),
        _ => eprintln!("usage: pchild <c1|c1r0|c2|c1zk> n=N [block=100]"),
    }
}
