//! pilot (w25, NEW file in the copy): child programs for the interleaved laptop pilot. Written for `scripts/pilot_driver.py`.
//!
//! Every child is ONE fresh process for ONE measurement point. It prepares its instance (outside any timer), prints a READY line,
//! and then performs ONE measured run each time it reads the line "run" on stdin (so the driver can interleave the points
//! round-robin and still keep one process per point). It exits on "quit" or end of input.
//!
//!   pilot child prove  rel=exec|rc n=N [block=100]            one trace build + prove + parse/verify per "run" (like proofbench `scale`)
//!   pilot child bundle [n=1000] [depth=10]                    parse + verify of the rc + auth + exec proofs per "run" (like proofbench `q` bundle, q = 1, same proof)
//!   pilot child chunks rel=exec|rc block=B blocks=a,b,c       each chunk = independent proof over a whole blocks of B records, one after the other;
//!                                                             chunks are NOT linked to each other (same as src/bin/chunked.rs)
//!   pilot secsweep rel=exec|rc|auth n=N [block=100] [depth=10] blowup=B qmin=Q1 qmax=Q2 [grind=16]
//!                                                             prints the library's three estimates for each number of queries
//!
//! The commitment hash comes from the cargo feature `blake3`; queries, blowup, grinding from PQZ_QUERIES, PQZ_BLOWUP, PQZ_GRIND
//! (see src/prove.rs). Prove/verify code is the crate's own (same calls as proofbench.rs); only the loop around it is new.

use pqz_proof::auth::{build_auth_trace, honest_auth_instance, AuthAir, AuthPublic, AuthWitness};
use pqz_proof::data::Workload;
use pqz_proof::exec::{build_exec_trace, exec_public, ExecAir, ExecPublic};
use pqz_proof::prove::{default_options, options_with, prove_trace, security_of, verify_proof_min_bits, HASH_NAME};
use pqz_proof::rc::{build_rc_trace, rc_public, RcAir, RcPublic};
use pqz_proof::rescue::F;
use std::io::{BufRead, Write};
use std::time::Instant;
use winterfell::{Proof, Trace};

const MIN_BITS: u32 = 80;
const THETA: u64 = 1 << 31;

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

#[derive(Clone)]
enum Stmt {
    Rc(RcPublic),
    Exec(ExecPublic),
    Auth(AuthPublic),
}

impl Stmt {
    fn verify_bytes(&self, bytes: &[u8]) -> Result<(), String> {
        let proof = Proof::from_bytes(bytes).map_err(|e| format!("parse: {e:?}"))?;
        match self {
            Stmt::Rc(p) => verify_proof_min_bits::<RcAir>(proof, p.clone(), MIN_BITS),
            Stmt::Exec(p) => verify_proof_min_bits::<ExecAir>(proof, p.clone(), MIN_BITS),
            Stmt::Auth(p) => verify_proof_min_bits::<AuthAir>(proof, p.clone(), MIN_BITS),
        }
    }
}

enum Prepared {
    Rc(Workload, RcPublic),
    Exec(Workload, ExecPublic),
    Auth(AuthPublic, AuthWitness),
}

fn prepare(rel: &str, n: usize, block: usize, depth: usize, seed: u64) -> Prepared {
    match rel {
        "rc" => {
            let w = Workload::synthetic(n, block.min(n), seed);
            let p = rc_public(&w);
            Prepared::Rc(w, p)
        }
        "exec" => {
            let w = Workload::synthetic(n, block.min(n), seed);
            let ctx = [F::new(seed), F::new(2), F::new(3), F::new(4)];
            let p = exec_public(&w, THETA, ctx);
            Prepared::Exec(w, p)
        }
        "auth" => {
            let (p, w) = honest_auth_instance(depth, seed);
            Prepared::Auth(p, w)
        }
        _ => panic!("unknown relation {rel}"),
    }
}

struct Made {
    stmt: Stmt,
    proof: Proof,
    trace_rows: usize,
    trace_s: f64,
    prove_s: f64,
}

fn prove_prepared(pr: &Prepared, opts: winterfell::ProofOptions) -> Result<Made, String> {
    let t0 = Instant::now();
    let (trace, stmt) = match pr {
        Prepared::Rc(w, p) => (build_rc_trace(w), Stmt::Rc(p.clone())),
        Prepared::Exec(w, p) => (build_exec_trace(w, THETA), Stmt::Exec(p.clone())),
        Prepared::Auth(p, w) => (build_auth_trace(p, w), Stmt::Auth(p.clone())),
    };
    let trace_s = t0.elapsed().as_secs_f64();
    let trace_rows = trace.length();
    let t1 = Instant::now();
    let proof = match &stmt {
        Stmt::Rc(p) => prove_trace::<RcAir>(trace, p.clone(), opts)?,
        Stmt::Exec(p) => prove_trace::<ExecAir>(trace, p.clone(), opts)?,
        Stmt::Auth(p) => prove_trace::<AuthAir>(trace, p.clone(), opts)?,
    };
    let prove_s = t1.elapsed().as_secs_f64();
    Ok(Made { stmt, proof, trace_rows, trace_s, prove_s })
}

fn opts_line() -> String {
    let o = default_options();
    format!("{},{},{},{}", HASH_NAME, o.num_queries(), o.blowup_factor(), o.grinding_factor())
}

extern "C" {
    fn malloc_trim(pad: usize) -> i32;
}

/// Calls `run` once for every line "run" read on stdin. With the environment variable PILOT_TRIM=1 the allocator is asked to
/// give freed memory back to the system after each run (outside the timers), so that idle children of a large point
/// do not hold gigabytes each; the next run then pays the page faults again (all points alike).
fn serve<G: FnMut()>(mut run: G) {
    let trim = std::env::var("PILOT_TRIM").map(|v| v == "1").unwrap_or(false);
    let stdin = std::io::stdin();
    for l in stdin.lock().lines().map_while(Result::ok) {
        match l.trim() {
            "run" => {
                run();
                if trim {
                    unsafe {
                        malloc_trim(0);
                    }
                }
                // the driver waits for this line before it starts the next child, so that nothing of this child runs during another timing
                emit("IDLE".to_string());
            }
            "quit" => break,
            _ => {}
        }
    }
}

fn emit(line: String) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}

// ------------------------------------------------------------------------------------------------

fn child_prove(args: &[String]) {
    let rel = arg(args, "rel").unwrap();
    let n: usize = arg(args, "n").unwrap().parse().unwrap();
    let block: usize = arg(args, "block").map(|s| s.parse().unwrap()).unwrap_or(100);
    assert!(rel == "exec" || rel == "rc");
    let pr = prepare(&rel, n, block, 0, 1);
    emit(format!("READY,prove,{rel},{n},{block},{}", opts_line()));
    serve(|| {
        let made = match prove_prepared(&pr, default_options()) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("prove failed: {e}");
                std::process::exit(4);
            }
        };
        let sec = security_of(&made.proof);
        let bytes = made.proof.to_bytes();
        let t = Instant::now();
        made.stmt.verify_bytes(&bytes).expect("honest proof must verify");
        let verify_s = t.elapsed().as_secs_f64();
        emit(format!(
            "ROW,prove,{rel},{n},{block},{},{},{:.6},{:.6},{:.6},{},{},{},{},{}",
            opts_line(),
            made.trace_rows,
            made.trace_s,
            made.prove_s,
            verify_s,
            bytes.len(),
            sec.conjectured_bits,
            sec.proven_unique_decoding_bits,
            sec.proven_list_decoding_bits,
            status_kb("VmRSS:")
        ));
    });
}

fn child_bundle(args: &[String]) {
    let n: usize = arg(args, "n").map(|s| s.parse().unwrap()).unwrap_or(1000);
    let depth: usize = arg(args, "depth").map(|s| s.parse().unwrap()).unwrap_or(10);
    // same instances as proofbench `q bundle same`: seed 1000, blocks of 100, R_Auth depth 10
    let mut items: Vec<(Stmt, Vec<u8>)> = Vec::new();
    let (mut conj, mut udr, mut ldr) = (u32::MAX, u32::MAX, u32::MAX);
    let mut sizes: Vec<usize> = Vec::new();
    for rel in ["rc", "auth", "exec"] {
        let pr = prepare(rel, n, 100, depth, 1000);
        let m = prove_prepared(&pr, default_options()).expect("prove");
        let sec = security_of(&m.proof);
        conj = conj.min(sec.conjectured_bits);
        udr = udr.min(sec.proven_unique_decoding_bits);
        ldr = ldr.min(sec.proven_list_decoding_bits);
        let bytes = m.proof.to_bytes();
        sizes.push(bytes.len());
        items.push((m.stmt, bytes));
    }
    let total_bytes: usize = sizes.iter().sum();
    emit(format!(
        "READY,bundle,{n},{depth},{},{},{},{},{},{},{},{}",
        opts_line(), total_bytes, sizes[0], sizes[1], sizes[2], conj, udr, ldr
    ));
    serve(|| {
        let mut t = [0f64; 3];
        let t_all = Instant::now();
        for (i, (stmt, bytes)) in items.iter().enumerate() {
            let t0 = Instant::now();
            stmt.verify_bytes(bytes).expect("honest proof must verify");
            t[i] = t0.elapsed().as_secs_f64();
        }
        let total = t_all.elapsed().as_secs_f64();
        emit(format!(
            "ROW,bundle,{n},{depth},{},{:.6},{:.6},{:.6},{:.6},{},{},{},{},{},{},{}",
            opts_line(), total, t[0], t[1], t[2], total_bytes, sizes[0], sizes[1], sizes[2], conj, udr, ldr
        ));
    });
}

fn child_chunks(args: &[String]) {
    let rel = arg(args, "rel").unwrap_or_else(|| "exec".into());
    let block: usize = arg(args, "block").map(|s| s.parse().unwrap()).unwrap_or(500);
    let blocks: Vec<usize> = arg(args, "blocks").unwrap().split(',').map(|s| s.parse().unwrap()).collect();
    assert!(rel == "exec" || rel == "rc");
    let label = blocks.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("+");
    let preps: Vec<Prepared> =
        blocks.iter().enumerate().map(|(i, &b)| prepare(&rel, b * block, block, 0, (i + 1) as u64)).collect();
    emit(format!("READY,chunks,{rel},{block},{label},{},{}", blocks.len(), opts_line()));
    serve(|| {
        let mut mades: Vec<Made> = Vec::with_capacity(preps.len());
        let mut bytes_v: Vec<Vec<u8>> = Vec::with_capacity(preps.len());
        let t_all = Instant::now();
        for pr in &preps {
            let m = match prove_prepared(pr, default_options()) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("prove failed: {e}");
                    std::process::exit(4);
                }
            };
            bytes_v.push(m.proof.to_bytes());
            mades.push(m);
        }
        // wall-clock interval around the loop: trace build + prove + proof serialisation (as in src/bin/chunked.rs)
        let prove_total = t_all.elapsed().as_secs_f64();
        let (mut conj, mut udr, mut ldr) = (u32::MAX, u32::MAX, u32::MAX);
        for m in &mades {
            let sec = security_of(&m.proof);
            conj = conj.min(sec.conjectured_bits);
            udr = udr.min(sec.proven_unique_decoding_bits);
            ldr = ldr.min(sec.proven_list_decoding_bits);
        }
        let t_v = Instant::now();
        for (m, b) in mades.iter().zip(bytes_v.iter()) {
            m.stmt.verify_bytes(b).expect("honest proof must verify");
        }
        let verify_total = t_v.elapsed().as_secs_f64();
        let rows: usize = mades.iter().map(|m| m.trace_rows).sum();
        let rows_each = mades.iter().map(|m| m.trace_rows.to_string()).collect::<Vec<_>>().join("+");
        let trace_s: f64 = mades.iter().map(|m| m.trace_s).sum();
        let prove_s: f64 = mades.iter().map(|m| m.prove_s).sum();
        let bytes: usize = bytes_v.iter().map(|b| b.len()).sum();
        emit(format!(
            "ROW,chunks,{rel},{block},{label},{},{},{rows},{rows_each},{trace_s:.6},{prove_s:.6},{prove_total:.6},{verify_total:.6},{bytes},{conj},{udr},{ldr},{}",
            blocks.len(),
            opts_line(),
            status_kb("VmRSS:")
        ));
    });
}

fn secsweep(args: &[String]) {
    let rel = arg(args, "rel").unwrap_or_else(|| "exec".into());
    let n: usize = arg(args, "n").map(|s| s.parse().unwrap()).unwrap_or(1000);
    let block: usize = arg(args, "block").map(|s| s.parse().unwrap()).unwrap_or(100);
    let depth: usize = arg(args, "depth").map(|s| s.parse().unwrap()).unwrap_or(10);
    let blowup: usize = arg(args, "blowup").unwrap().parse().unwrap();
    let qmin: usize = arg(args, "qmin").unwrap().parse().unwrap();
    let qmax: usize = arg(args, "qmax").unwrap().parse().unwrap();
    let grind: u32 = arg(args, "grind").map(|s| s.parse().unwrap()).unwrap_or(16);
    let pr = prepare(&rel, n, block, depth, 1);
    println!("SEC_HEADER,hash,rel,n,trace_rows,queries,blowup,grind,conj_bits,udr_bits,ldr_bits,proof_bytes,prove_s,verify_ok");
    for q in qmin..=qmax {
        let m = prove_prepared(&pr, options_with(q, blowup, grind)).expect("prove");
        let sec = security_of(&m.proof);
        let bytes = m.proof.to_bytes();
        let ok = m.stmt.verify_bytes(&bytes).is_ok();
        println!(
            "SEC,{HASH_NAME},{rel},{},{},{q},{blowup},{grind},{},{},{},{},{:.4},{}",
            if rel == "auth" { depth } else { n },
            m.trace_rows,
            sec.conjectured_bits,
            sec.proven_unique_decoding_bits,
            sec.proven_list_decoding_bits,
            bytes.len(),
            m.prove_s,
            ok as u8
        );
        let _ = std::io::stdout().flush();
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(|s| s.as_str()) {
        Some("child") => match a.get(1).map(|s| s.as_str()) {
            Some("prove") => child_prove(&a[2..]),
            Some("bundle") => child_bundle(&a[2..]),
            Some("chunks") => child_chunks(&a[2..]),
            _ => panic!("bad child kind"),
        },
        Some("secsweep") => secsweep(&a[1..]),
        _ => {
            eprintln!("usage: pilot child prove|bundle|chunks key=value ... | pilot secsweep key=value ...");
            std::process::exit(2);
        }
    }
}
