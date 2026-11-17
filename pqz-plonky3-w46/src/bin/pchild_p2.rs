//! w38 measurement child for the packed formats (P2, P2r). Same protocol and ROW line as `pchild3 exec`:
//! prepares the workload outside any timer, prints READY, one measured run per "run" line, then ROW and IDLE; "quit" exits.
//! usage: pchild_p2 n=N [block=100] [fmt=p2|p2r] [fri=std|hi|fast2|fast1] [trace=seq|par] [ckpt_k=1024]
//! ROW,<label>,<n>,<rows>,<width>,<count>,<sum>,<trace_s>,<prove_s>,<verify_s>,<bytes>,<conj>,<udr>,<ldr>,<vmrss_kb>,<threads>
//! trace_s = packing (word mapping) + witness generation; prove_s = `p3_uni_stark::prove`; verify_s = bytes -> parse -> verify.
//! The checkpoints of trace=par are made in the untimed preparation (as in pchild3).
use p3_matrix::Matrix;
use pqz_plonky3_w46::data::Workload;
use pqz_plonky3_w46::pair::*;
use pqz_plonky3_w46::psponge::CKPT_K;
use pqz_plonky3_w46::security::estimate;
use pqz_plonky3_w46::{c1, FriOpts};
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

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let n: usize = arg(&a, "n").and_then(|s| s.parse().ok()).expect("n=N");
    let block: usize = arg(&a, "block").and_then(|s| s.parse().ok()).unwrap_or(100);
    let f = match arg(&a, "fmt").as_deref().unwrap_or("p2") {
        "p2" => Fmt::P2,
        "p2r" => Fmt::P2r,
        x => {
            eprintln!("fmt must be p2 or p2r, got {x}");
            std::process::exit(2);
        }
    };
    let fri = arg(&a, "fri").unwrap_or_else(|| "fast1".into());
    let o = FriOpts::preset(&fri).expect("fri=std|hi|fast2|fast1");
    let par_k = match arg(&a, "trace").as_deref() {
        None | Some("seq") => None,
        Some("par") => Some(arg(&a, "ckpt_k").and_then(|s| s.parse().ok()).unwrap_or(CKPT_K)),
        Some(x) => {
            eprintln!("trace must be seq or par, got {x}");
            std::process::exit(2);
        }
    };
    const THETA: u64 = 1u64 << 31;
    let wl = Workload::synthetic(n, block, 1);
    let p = pair_public(&wl, THETA, [1, 2, 3, 4]);
    let nw = pair_n_words(p.n_blocks, p.block_size);
    let ck = par_k.map(|k| pair_checkpoints(&pack_workload(&wl), pair_n_rows(nw), k));
    let label = format!("pair-{}-{}", if f == Fmt::P2 { "p2" } else { "p2r" }, fri);
    emit(format!(
        "READY,{label},{n},rows_exec={},n_words={nw},queries={},log_blowup={},pow={},trace={},ckpts={}",
        pair_n_rows(nw), o.num_queries, o.log_blowup, o.query_pow_bits,
        if par_k.is_some() { "par" } else { "seq" },
        ck.as_ref().map(|c| c.len()).unwrap_or(0)
    ));
    let stdin = std::io::stdin();
    for l in stdin.lock().lines().map_while(Result::ok) {
        match l.trim() {
            "run" => {
                let t0 = Instant::now();
                let words = pack_workload(&wl);
                let a = pair_air(p.theta, nw as u64, f);
                let trace = match &ck {
                    Some(c) => a.build_trace_par(&c1::perm(), &words, p.block_size, c),
                    None => a.build_trace(&c1::perm(), &words, p.block_size),
                };
                let pv = pair_values(&p);
                let trace_s = t0.elapsed().as_secs_f64();
                let rows = trace.height();
                let t1 = Instant::now();
                let proof = match p3_uni_stark::prove(&c1::config(&o), &a, trace, &pv) {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("prove failed: {e:?}");
                        std::process::exit(4);
                    }
                };
                let prove_s = t1.elapsed().as_secs_f64();
                let bytes = c1::to_bytes(&proof);
                drop(proof);
                let t2 = Instant::now();
                let parsed = c1::from_bytes(&bytes).expect("parse");
                verify_pair(&o, &parsed, &p, f).expect("honest proof must verify");
                let verify_s = t2.elapsed().as_secs_f64();
                let s = estimate(&c1::sec_input(&o, rows));
                emit(format!(
                    "ROW,{label},{n},{rows},{},{},{},{trace_s:.6},{prove_s:.6},{verify_s:.6},{},{},{},{},{},{}",
                    pair_width(f), p.count, p.sum[0], bytes.len(), s.conjectured, s.proven_unique_decoding, s.proven_list_decoding,
                    status_kb("VmRSS:"), std::env::var("RAYON_NUM_THREADS").unwrap_or_default()
                ));
                emit("IDLE".to_string());
            }
            "quit" => break,
            _ => {}
        }
    }
}
