//! Stage C measurement child (same protocol as `pchild`, stage B, and the w30 child): ONE fresh process per measurement
//! point. It prepares the workload and the public statements outside any timer, prints a READY line, performs ONE measured
//! run per line "run" on stdin, prints SUB lines (bundle only), a ROW line and then IDLE; exits on "quit".
//!
//! usage: pchild3 <exec|rc|auth|bundle|rcsep> n=N [block=100] [mode=plain|zk] [depth=10] [fri=std|hi|fast2|fast1] [trace=seq|par] [ckpt_k=1024]
//!   w36: fri=fast2 / fri=fast1 are the speed presets (`FriOpts::fast2` / `fast1`, variants.rs; label suffix -fast2 / -fast1).
//!   w36 (S1): trace=par (exec, rc, bundle) builds the trace with the parallel sponge from stored checkpoints (`build_trace_par`);
//!   trace=seq (default) is the w35 sequential `build_trace`. The checkpoints are made in the UNTIMED preparation (they model the
//!   sponge states the CSP stored at ingest) and the helper is timed on its own: the READY line carries `trace=`, `ckpt_k=`,
//!   `ckpt_exec_s=` and `ckpt_rc_s=` (seconds of the sequential helper over the whole padded stream, 0 for trace=seq). Not part of trace_s.
//!   fri=std (default) = the stage C options (40 queries); fri=hi = the w34 high-security preset (`FriOpts::hi`, variants.rs).
//!   The verifier inside the child uses the same preset (its own FriOpts), as before.
//!   exec   = R_Exec (same code path as pchild c1 / c1zk)
//!   rc     = R_RC (one proof over the whole stream)
//!   auth   = R_Auth (depth 10, seed 1; independent of N)
//!   bundle = R_Exec + R_RC + R_Auth, proved one after the other in this process (no aggregation), verified together:
//!            C_Q link (`request::check_ctx`) first, then the three proofs (same body as `request::verify_bundle`).
//!
//!   rcsep  = (w34 E3) G = n/block SEPARATE R_RC proofs, each its own statement and proof over ONE block of `block` records + header
//!            (workload of `block` records, block_size = block, seed 1000+g), proven and verified one after the other in this process.
//!            n must be a multiple of block (else exit 2). ROW fields: rows/width = sums over the G proofs (width = per-proof width),
//!            count = G (the number of proofs; sum_int = 0), trace_s / prove_s / verify_s / bytes = TOTALS over the G proofs
//!            (verify_s = sum of the G timed "bytes -> parse -> verify"), conj/udr/ldr = the estimate (equal for all G, one block each).
//!            Compare: `pchild3 rc n=N block=500` is the batched form (one proof over all N records).
//!            usage: pchild3 rcsep n=N block=500 [mode=plain|zk] [fri=std|hi]   (label rcsep-<mode>[-hi], n field = N)
//!
//! ROW,<label>,<n>,<rows>,<width>,<count>,<sum_int>,<trace_s>,<prove_s>,<verify_s>,<proof_bytes>,<conj>,<udr>,<ldr>,<vmrss_kb>,<threads>
//!   trace_s  = words mapping + witness (trace) generation;  prove_s = `p3_uni_stark::prove`
//!   full     = trace_s + prove_s;  verify_s = proof bytes -> parse -> verify (bundle: three proofs + the C_Q link check)
//!   bundle: trace_s, prove_s, verify_s, bytes, rows, width are SUMS over the three relations; conj/udr/ldr are the minimum.
//!   SUB,<rel>,<rows>,<width>,<trace_s>,<prove_s>,<verify_s>,<bytes>,<conj>,<udr>,<ldr>   one line per relation (bundle only;
//!   the per-relation verify time in a SUB line is measured after the bundle verify timer, for information only)
//! Untimed: workload generation, native sponge digests (public statements), the honest Auth instance, proof serialisation.

use pqz_plonky3_w46::auth::{honest_auth_instance, AuthPublic, AuthWitness};
use pqz_plonky3_w46::data::Workload;
use pqz_plonky3_w46::rc::RcPublic;
use pqz_plonky3_w46::rel::{plain, zk};
use pqz_plonky3_w46::request::{exec_context, native_bundle_checks, NativeChecks};
use pqz_plonky3_w46::security::estimate;
use pqz_plonky3_w46::psponge::CKPT_K;
use pqz_plonky3_w46::variants::{FAST1_NUM_QUERIES, FAST2_NUM_QUERIES, HI_NUM_QUERIES};
use pqz_plonky3_w46::{c1, c1zk, FriOpts};
use p3_matrix::Matrix;
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

/// Label suffix of the FRI preset (by query count, as the w34 `-hi` suffix; the three presets differ in num_queries).
fn fri_suffix(o: &FriOpts) -> &'static str {
    match (o.log_blowup, o.num_queries) {
        (_, q) if q == HI_NUM_QUERIES => "-hi",
        (2, q) if q == FAST2_NUM_QUERIES => "-fast2",
        (1, q) if q == FAST1_NUM_QUERIES => "-fast1",
        _ => "",
    }
}

/// w36 (S1): `trace=par` -> Some(checkpoint spacing), `trace=seq` (default) -> None.
fn par_trace_k() -> Option<usize> {
    let a: Vec<String> = std::env::args().collect();
    match arg(&a, "trace").as_deref() {
        None | Some("seq") => None,
        Some("par") => Some(arg(&a, "ckpt_k").and_then(|s| s.parse().ok()).unwrap_or(CKPT_K)),
        Some(x) => {
            eprintln!("trace must be seq or par, got {x}");
            std::process::exit(2);
        }
    }
}

fn emit(line: String) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}

/// Result of one relation: timings, bytes, rows, width, security (conj, udr, ldr).
struct One {
    rows: usize,
    width: usize,
    trace_s: f64,
    prove_s: f64,
    verify_s: f64,
    bytes: usize,
    sec: (u32, u32, u32),
}

const RID: u64 = 1;
const THETA: u64 = 1u64 << 31;

macro_rules! child {
    ($rel:expr, $n:expr, $block:expr, $depth:expr, $plain:ident, $base:ident, $mode:expr, $fri:expr) => {{
        let o: FriOpts = $fri;
        let rel: &str = $rel;
        let n: usize = $n;
        let block: usize = $block;
        let depth: usize = $depth;
        // ---- untimed preparation
        let wl = if rel != "auth" { Some(Workload::synthetic(n, block, 1)) } else { None };
        let (apub, awit): (Option<AuthPublic>, Option<AuthWitness>) = if rel == "auth" || rel == "bundle" {
            let (p, w) = honest_auth_instance::<$base::Val, _>(&$base::perm(), depth, 1);
            (Some(p), Some(w))
        } else {
            (None, None)
        };
        // exec statement: ctx = exec_context(B_Q, D_Q, RID) of the Auth statement in the bundle, a fixed value otherwise
        let epub = if rel == "exec" || rel == "bundle" {
            let ctx = match &apub {
                Some(a) => exec_context(&$base::perm(), a.b_q, a.d_q, RID),
                None => [1, 2, 3, 4],
            };
            Some($base::public_for(wl.as_ref().unwrap(), THETA, ctx))
        } else {
            None
        };
        let rpub: Option<RcPublic> = if rel == "rc" || rel == "bundle" {
            Some($plain::rc_public(&$base::words(wl.as_ref().unwrap()), block))
        } else {
            None
        };
        let label = format!("{rel}-{}{}", $mode, fri_suffix(&o));
        // w36 (S1): checkpoints for trace=par, made here (untimed preparation = the sponge states stored at ingest); the helper is timed on its own
        let par_k = par_trace_k();
        let (mut ckpt_exec_s, mut ckpt_rc_s) = (0.0f64, 0.0f64);
        let ck_exec = match par_k {
            Some(k) if rel == "exec" || rel == "bundle" => {
                let p = epub.as_ref().unwrap();
                let a = $base::air(p.theta, p.n_words() as u64);
                let words = $base::words(wl.as_ref().unwrap());
                let n_rows = $base::n_rows(words.len());
                let t = Instant::now();
                let c = pqz_plonky3_w46::air::sponge_checkpoints::<$base::Val, { $base::W }, _>(&a.lay, &$base::perm(), &words, n_rows, k);
                ckpt_exec_s = t.elapsed().as_secs_f64();
                Some(c)
            }
            _ => None,
        };
        let ck_rc = match par_k {
            Some(k) if rel == "rc" || rel == "bundle" => {
                let p = rpub.as_ref().unwrap();
                let a = $plain::rc_air(p.block_size as u64, p.n_words() as u64);
                let words = $base::words(wl.as_ref().unwrap());
                let t = Instant::now();
                let c = a.sponge_checkpoints(&$base::perm(), &words, k);
                ckpt_rc_s = t.elapsed().as_secs_f64();
                Some(c)
            }
            _ => None,
        };
        let rows_exec = epub.as_ref().map(|p| $base::n_rows(p.n_words())).unwrap_or(0);
        let rows_rc = rpub.as_ref().map(|p| $plain::rc_rows(p.n_words())).unwrap_or(0);
        let rows_auth = if apub.is_some() { $plain::auth_rows(depth) } else { 0 };
        emit(format!(
            "READY,{label},{n},rows_exec={rows_exec},rows_rc={rows_rc},rows_auth(before min)={rows_auth},queries={},log_blowup={},pow={},trace={},ckpt_k={},ckpt_exec_s={ckpt_exec_s:.6},ckpt_rc_s={ckpt_rc_s:.6},ckpts_exec={},ckpts_rc={}",
            o.num_queries, o.log_blowup, o.query_pow_bits,
            if par_k.is_some() { "par" } else { "seq" },
            par_k.unwrap_or(0),
            ck_exec.as_ref().map(|c| c.len()).unwrap_or(0),
            ck_rc.as_ref().map(|c| c.len()).unwrap_or(0)
        ));

        // ---- the three measured steps (each: trace, prove, serialise [untimed], and for a single relation parse + verify)
        let run_exec = |bytes_keep: &mut Option<Vec<u8>>| -> One {
            let p = epub.as_ref().unwrap();
            let t0 = Instant::now();
            let a = $base::air(p.theta, p.n_words() as u64);
            let trace = match &ck_exec {
                Some(ck) => a.build_trace_par(&$base::perm(), &$base::words(wl.as_ref().unwrap()), ck),
                None => a.build_trace(&$base::perm(), &$base::words(wl.as_ref().unwrap())),
            };
            let pv = p.to_values::<$base::Val>(&a.lay);
            let trace_s = t0.elapsed().as_secs_f64();
            let rows = trace.height();
            let t1 = Instant::now();
            let proof = match p3_uni_stark::prove(&$base::config(&o), &a, trace, &pv) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("prove failed (exec): {e:?}");
                    std::process::exit(4);
                }
            };
            let prove_s = t1.elapsed().as_secs_f64();
            let bytes = $base::to_bytes(&proof);
            drop(proof);
            let mut verify_s = 0.0;
            if rel == "exec" {
                let t2 = Instant::now();
                let parsed = $base::from_bytes(&bytes).expect("parse");
                $plain::verify_exec(&o, &parsed, p).expect("honest exec proof must verify");
                verify_s = t2.elapsed().as_secs_f64();
            }
            let s = estimate(&$base::sec_input(&o, rows));
            let len = bytes.len();
            *bytes_keep = Some(bytes);
            One { rows, width: $base::lay().width, trace_s, prove_s, verify_s, bytes: len, sec: (s.conjectured, s.proven_unique_decoding, s.proven_list_decoding) }
        };
        let run_rc = |bytes_keep: &mut Option<Vec<u8>>| -> One {
            let p = rpub.as_ref().unwrap();
            let t0 = Instant::now();
            let a = $plain::rc_air(p.block_size as u64, p.n_words() as u64);
            let trace = match &ck_rc {
                Some(ck) => a.build_trace_par(&$base::perm(), &$base::words(wl.as_ref().unwrap()), ck),
                None => a.build_trace(&$base::perm(), &$base::words(wl.as_ref().unwrap())),
            };
            let pv = p.to_values::<$base::Val>(&a.lay);
            let trace_s = t0.elapsed().as_secs_f64();
            let rows = trace.height();
            let t1 = Instant::now();
            let proof = match p3_uni_stark::prove(&$base::config(&o), &a, trace, &pv) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("prove failed (rc): {e:?}");
                    std::process::exit(4);
                }
            };
            let prove_s = t1.elapsed().as_secs_f64();
            let bytes = $base::to_bytes(&proof);
            drop(proof);
            let mut verify_s = 0.0;
            if rel == "rc" {
                let t2 = Instant::now();
                let parsed = $base::from_bytes(&bytes).expect("parse");
                $plain::verify_rc(&o, &parsed, p).expect("honest rc proof must verify");
                verify_s = t2.elapsed().as_secs_f64();
            }
            let s = estimate(&$base::sec_input(&o, rows));
            let len = bytes.len();
            *bytes_keep = Some(bytes);
            One { rows, width: $plain::rc_width(), trace_s, prove_s, verify_s, bytes: len, sec: (s.conjectured, s.proven_unique_decoding, s.proven_list_decoding) }
        };
        let run_auth = |bytes_keep: &mut Option<Vec<u8>>| -> One {
            let p = apub.as_ref().unwrap();
            let w = awit.as_ref().unwrap();
            let t0 = Instant::now();
            let a = $plain::auth_air_for(&o, p.depth);
            let trace = a.build_trace(&$base::perm(), p, w).expect("trace");
            let pv = p.to_values::<$base::Val>();
            let trace_s = t0.elapsed().as_secs_f64();
            let rows = trace.height();
            let t1 = Instant::now();
            let proof = match p3_uni_stark::prove(&$base::config(&o), &a, trace, &pv) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("prove failed (auth): {e:?}");
                    std::process::exit(4);
                }
            };
            let prove_s = t1.elapsed().as_secs_f64();
            let bytes = $base::to_bytes(&proof);
            drop(proof);
            let mut verify_s = 0.0;
            if rel == "auth" {
                let t2 = Instant::now();
                let parsed = $base::from_bytes(&bytes).expect("parse");
                $plain::verify_auth(&o, &parsed, p).expect("honest auth proof must verify");
                verify_s = t2.elapsed().as_secs_f64();
            }
            let s = estimate(&$base::sec_input(&o, rows));
            let len = bytes.len();
            *bytes_keep = Some(bytes);
            One { rows, width: $plain::auth_width(), trace_s, prove_s, verify_s, bytes: len, sec: (s.conjectured, s.proven_unique_decoding, s.proven_list_decoding) }
        };

        let stdin = std::io::stdin();
        for l in stdin.lock().lines().map_while(Result::ok) {
            match l.trim() {
                "run" => {
                    let (mut be, mut br, mut ba) = (None, None, None);
                    let mut parts: Vec<(&str, One)> = Vec::new();
                    match rel {
                        "exec" => parts.push(("exec", run_exec(&mut be))),
                        "rc" => parts.push(("rc", run_rc(&mut br))),
                        "auth" => parts.push(("auth", run_auth(&mut ba))),
                        "bundle" => {
                            parts.push(("exec", run_exec(&mut be)));
                            parts.push(("rc", run_rc(&mut br)));
                            parts.push(("auth", run_auth(&mut ba)));
                        }
                        _ => unreachable!(),
                    }
                    if rel == "bundle" {
                        // bundle verification: bytes -> parse -> native checks (w34: stream link, C_Q link, scope), Auth, Exec, RC (body of request::verify_bundle)
                        let t2 = Instant::now();
                        let pa = $base::from_bytes(ba.as_ref().unwrap()).expect("parse auth");
                        let pe = $base::from_bytes(be.as_ref().unwrap()).expect("parse exec");
                        let pr = $base::from_bytes(br.as_ref().unwrap()).expect("parse rc");
                        native_bundle_checks(NativeChecks::ON, apub.as_ref().unwrap(), epub.as_ref().unwrap(), rpub.as_ref().unwrap(), RID).expect("native checks");
                        $plain::verify_auth(&o, &pa, apub.as_ref().unwrap()).expect("honest auth proof must verify");
                        $plain::verify_exec(&o, &pe, epub.as_ref().unwrap()).expect("honest exec proof must verify");
                        $plain::verify_rc(&o, &pr, rpub.as_ref().unwrap()).expect("honest rc proof must verify");
                        let vb = t2.elapsed().as_secs_f64();
                        // per-relation verify time (SUB lines), after the bundle timer, for information only
                        let tv = Instant::now();
                        $plain::verify_exec(&o, &pe, epub.as_ref().unwrap()).unwrap();
                        parts[0].1.verify_s = tv.elapsed().as_secs_f64();
                        let tv = Instant::now();
                        $plain::verify_rc(&o, &pr, rpub.as_ref().unwrap()).unwrap();
                        parts[1].1.verify_s = tv.elapsed().as_secs_f64();
                        let tv = Instant::now();
                        $plain::verify_auth(&o, &pa, apub.as_ref().unwrap()).unwrap();
                        parts[2].1.verify_s = tv.elapsed().as_secs_f64();
                        for (name, p) in &parts {
                            emit(format!(
                                "SUB,{name},{},{},{:.6},{:.6},{:.6},{},{},{},{}",
                                p.rows, p.width, p.trace_s, p.prove_s, p.verify_s, p.bytes, p.sec.0, p.sec.1, p.sec.2
                            ));
                        }
                        let rows: usize = parts.iter().map(|x| x.1.rows).sum();
                        let width: usize = parts.iter().map(|x| x.1.width).sum();
                        let tr: f64 = parts.iter().map(|x| x.1.trace_s).sum();
                        let pr_: f64 = parts.iter().map(|x| x.1.prove_s).sum();
                        let by: usize = parts.iter().map(|x| x.1.bytes).sum();
                        let c = parts.iter().map(|x| x.1.sec.0).min().unwrap();
                        let u = parts.iter().map(|x| x.1.sec.1).min().unwrap();
                        let ld = parts.iter().map(|x| x.1.sec.2).min().unwrap();
                        let ep = epub.as_ref().unwrap();
                        emit(format!(
                            "ROW,{label},{n},{rows},{width},{},{},{:.6},{:.6},{:.6},{by},{c},{u},{ld},{},{}",
                            ep.count,
                            ep.sum_int(),
                            tr,
                            pr_,
                            vb,
                            status_kb("VmRSS:"),
                            std::env::var("RAYON_NUM_THREADS").unwrap_or_default()
                        ));
                    } else {
                        let p = &parts[0].1;
                        let (count, sum) = match &epub {
                            Some(e) => (e.count, e.sum_int()),
                            None => (0, 0),
                        };
                        emit(format!(
                            "ROW,{label},{n},{},{},{count},{sum},{:.6},{:.6},{:.6},{},{},{},{},{},{}",
                            p.rows,
                            p.width,
                            p.trace_s,
                            p.prove_s,
                            p.verify_s,
                            p.bytes,
                            p.sec.0,
                            p.sec.1,
                            p.sec.2,
                            status_kb("VmRSS:"),
                            std::env::var("RAYON_NUM_THREADS").unwrap_or_default()
                        ));
                    }
                    emit("IDLE".to_string());
                }
                "quit" => break,
                _ => {}
            }
        }
    }};
}

/// w34 E3: G separate one-block R_RC proofs, one measured run per "run" line.
macro_rules! child_rcsep {
    ($n:expr, $block:expr, $plain:ident, $base:ident, $mode:expr, $fri:expr) => {{
        let o: FriOpts = $fri;
        let (n, block): (usize, usize) = ($n, $block);
        let g = n / block;
        // ---- untimed preparation: G workloads of one block each and their R_RC statements
        let wls: Vec<Workload> = (0..g).map(|i| Workload::synthetic(block, block, 1000 + i as u64)).collect();
        let pubs: Vec<RcPublic> = wls.iter().map(|w| $plain::rc_public(&$base::words(w), block)).collect();
        let label = format!("rcsep-{}{}", $mode, fri_suffix(&o));
        let rows_one = $plain::rc_rows(pubs[0].n_words());
        emit(format!(
            "READY,{label},{n},G={g},rows_rc_each={rows_one},queries={},log_blowup={},pow={}",
            o.num_queries, o.log_blowup, o.query_pow_bits
        ));
        let stdin = std::io::stdin();
        for l in stdin.lock().lines().map_while(Result::ok) {
            match l.trim() {
                "run" => {
                    let (mut trace_s, mut prove_s, mut verify_s) = (0f64, 0f64, 0f64);
                    let (mut bytes, mut rows) = (0usize, 0usize);
                    let mut sec = (0u32, 0u32, 0u32);
                    for (w, p) in wls.iter().zip(pubs.iter()) {
                        let t0 = Instant::now();
                        let a = $plain::rc_air(p.block_size as u64, p.n_words() as u64);
                        let trace = a.build_trace(&$base::perm(), &$base::words(w));
                        let pv = p.to_values::<$base::Val>(&a.lay);
                        trace_s += t0.elapsed().as_secs_f64();
                        let r = trace.height();
                        let t1 = Instant::now();
                        let proof = match p3_uni_stark::prove(&$base::config(&o), &a, trace, &pv) {
                            Ok(x) => x,
                            Err(e) => {
                                eprintln!("prove failed (rcsep): {e:?}");
                                std::process::exit(4);
                            }
                        };
                        prove_s += t1.elapsed().as_secs_f64();
                        let b = $base::to_bytes(&proof);
                        drop(proof);
                        let t2 = Instant::now();
                        let parsed = $base::from_bytes(&b).expect("parse");
                        $plain::verify_rc(&o, &parsed, p).expect("honest rc proof must verify");
                        verify_s += t2.elapsed().as_secs_f64();
                        let s = estimate(&$base::sec_input(&o, r));
                        sec = (s.conjectured, s.proven_unique_decoding, s.proven_list_decoding);
                        bytes += b.len();
                        rows += r;
                    }
                    emit(format!(
                        "ROW,{label},{n},{rows},{},{g},0,{trace_s:.6},{prove_s:.6},{verify_s:.6},{bytes},{},{},{},{},{}",
                        $plain::rc_width(),
                        sec.0,
                        sec.1,
                        sec.2,
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

/// w38 stage 3: packed format (`fmt=p2|p2r`): plain mode, trace=seq only. exec = packed Exec (P2 / P2r), rc = packed chunk proofs of the whole stream
/// (`chunk=C` blocks per chunk, default: one chunk with all blocks = the single R_RC), auth = as before, bundle = Auth + Exec + chunks.
/// Same ROW / SUB protocol as the default path; label `<rel>-<fmt>-plain<-fri>`.
fn packed_child(rel: &str, n: usize, block: usize, depth: usize, o: FriOpts, f: pqz_plonky3_w46::pair::Fmt, chunk_blocks: usize) {
    use pqz_plonky3_w46::pair::*;
    use pqz_plonky3_w46::pchunk::plain as pc;
    use pqz_plonky3_w46::prequest::verify_bundle_p;
    let wl = if rel != "auth" { Some(Workload::synthetic(n, block, 1)) } else { None };
    let (apub, awit) = if rel == "auth" || rel == "bundle" {
        let (p, w) = honest_auth_instance::<c1::Val, _>(&c1::perm(), depth, 1);
        (Some(p), Some(w))
    } else {
        (None, None)
    };
    let epub = if rel == "exec" || rel == "bundle" {
        let ctx = match &apub {
            Some(a) => exec_context(&c1::perm(), a.b_q, a.d_q, RID),
            None => [1, 2, 3, 4],
        };
        Some(pair_public(wl.as_ref().unwrap(), THETA, ctx))
    } else {
        None
    };
    let (cpubs, clists) = if rel == "rc" || rel == "bundle" {
        let w = wl.as_ref().unwrap();
        let c = if chunk_blocks == 0 { w.n_blocks } else { chunk_blocks };
        pc::honest_publics(&pack_workload(w), block, c)
    } else {
        (vec![], vec![])
    };
    let fl = match f { Fmt::P2 => "p2", Fmt::P2r => "p2r" };
    let label = format!("{rel}-{fl}-plain{}", fri_suffix(&o));
    let rpw = rows_per_block(block);
    // trace=par: checkpoints in the UNTIMED preparation (sponge states stored at ingest), as in the old format
    let par_k = par_trace_k();
    let mut ckpt_exec_s = 0.0f64;
    let mut ckpt_rc_s = 0.0f64;
    let ck_exec = match par_k {
        Some(k) if rel == "exec" || rel == "bundle" => {
            let p = epub.as_ref().unwrap();
            let words = pack_workload(wl.as_ref().unwrap());
            let t = Instant::now();
            let c = pair_checkpoints(&words, pair_n_rows(pair_n_words(p.n_blocks, p.block_size)), k);
            ckpt_exec_s = t.elapsed().as_secs_f64();
            Some(c)
        }
        _ => None,
    };
    let ck_rc: Option<Vec<Vec<pqz_plonky3_w46::psponge::Ckpt<12>>>> = match par_k {
        Some(k) if rel == "rc" || rel == "bundle" => {
            let words = pack_workload(wl.as_ref().unwrap());
            let t = Instant::now();
            let mut first = 0usize;
            let mut v = Vec::new();
            for p in &cpubs {
                let cw = &words[first * rpw..(first + p.n_blocks_chunk) * rpw];
                first += p.n_blocks_chunk;
                let n_rows = cw.len().next_power_of_two().max(pqz_plonky3_w46::air::MIN_ROWS);
                v.push(pqz_plonky3_w46::chunk::sponge_checkpoints_from::<c1::Val, 12, _>(&c1::perm(), &p.s_in, cw, n_rows, k));
            }
            ckpt_rc_s = t.elapsed().as_secs_f64();
            Some(v)
        }
        _ => None,
    };
    emit(format!(
        "READY,{label},{n},rows_exec={},chunks={},queries={},log_blowup={},pow={},trace={},ckpt_k={},ckpt_exec_s={ckpt_exec_s:.6},ckpt_rc_s={ckpt_rc_s:.6}",
        epub.as_ref().map(|p| pair_n_rows(pair_n_words(p.n_blocks, p.block_size))).unwrap_or(0),
        cpubs.len(), o.num_queries, o.log_blowup, o.query_pow_bits,
        if par_k.is_some() { "par" } else { "seq" }, par_k.unwrap_or(0)
    ));
    let run_exec = |keep: &mut Option<Vec<u8>>| -> One {
        let p = epub.as_ref().unwrap();
        let t0 = Instant::now();
        let words = pack_workload(wl.as_ref().unwrap());
        let a = pair_air(p.theta, pair_n_words(p.n_blocks, p.block_size) as u64, f);
        let trace = match &ck_exec {
            Some(ck) => a.build_trace_par(&c1::perm(), &words, p.block_size, ck),
            None => a.build_trace(&c1::perm(), &words, p.block_size),
        };
        let pv = pair_values(p);
        let trace_s = t0.elapsed().as_secs_f64();
        let rows = trace.height();
        let t1 = Instant::now();
        let proof = p3_uni_stark::prove(&c1::config(&o), &a, trace, &pv).unwrap_or_else(|e| {
            eprintln!("prove failed (exec): {e:?}");
            std::process::exit(4)
        });
        let prove_s = t1.elapsed().as_secs_f64();
        let bytes = c1::to_bytes(&proof);
        drop(proof);
        let mut verify_s = 0.0;
        if rel == "exec" {
            let t2 = Instant::now();
            let parsed = c1::from_bytes(&bytes).expect("parse");
            verify_pair(&o, &parsed, p, f).expect("honest exec proof must verify");
            verify_s = t2.elapsed().as_secs_f64();
        }
        let s = estimate(&c1::sec_input(&o, rows));
        let len = bytes.len();
        *keep = Some(bytes);
        One { rows, width: pair_width(f), trace_s, prove_s, verify_s, bytes: len, sec: (s.conjectured, s.proven_unique_decoding, s.proven_list_decoding) }
    };
    let run_rc = |keep: &mut Vec<Vec<u8>>| -> One {
        let t0 = Instant::now();
        let words = pack_workload(wl.as_ref().unwrap());
        let mut jobs = Vec::new();
        let mut first = 0usize;
        for (ci, p) in cpubs.iter().enumerate() {
            let a = pc::chunk_air(p).unwrap();
            let cw = &words[first * rpw..(first + p.n_blocks_chunk) * rpw];
            first += p.n_blocks_chunk;
            let trace = match &ck_rc {
                Some(ck) => a.build_trace_par(&c1::perm(), cw, &p.alpha, &p.beta, p.hdr_before as u64, &ck[ci]),
                None => a.build_trace(&c1::perm(), cw, &p.s_in, &p.alpha, &p.beta, p.hdr_before as u64),
            };
            jobs.push((trace, pc::values(p)));
        }
        let trace_s = t0.elapsed().as_secs_f64();
        let rows: usize = jobs.iter().map(|j| j.0.height()).sum();
        let last_rows = jobs[0].0.height();
        let t1 = Instant::now();
        let mut bytes: Vec<Vec<u8>> = Vec::new();
        for ((trace, pv), p) in jobs.into_iter().zip(&cpubs) {
            let a = pc::chunk_air(p).unwrap();
            let proof = p3_uni_stark::prove(&c1::config(&o), &a, trace, &pv).unwrap_or_else(|e| {
                eprintln!("prove failed (rc): {e:?}");
                std::process::exit(4)
            });
            bytes.push(c1::to_bytes(&proof));
        }
        let prove_s = t1.elapsed().as_secs_f64();
        let mut verify_s = 0.0;
        if rel == "rc" {
            let t2 = Instant::now();
            for (b, p) in bytes.iter().zip(&cpubs) {
                let parsed = c1::from_bytes(b).expect("parse");
                pc::verify_chunk(&o, &parsed, p).expect("honest chunk proof must verify");
            }
            verify_s = t2.elapsed().as_secs_f64();
        }
        let s = estimate(&c1::sec_input(&o, last_rows));
        let len: usize = bytes.iter().map(|b| b.len()).sum();
        *keep = bytes;
        One { rows, width: pc::chunk_width(), trace_s, prove_s, verify_s, bytes: len, sec: (s.conjectured, s.proven_unique_decoding, s.proven_list_decoding) }
    };
    let run_auth = |keep: &mut Option<Vec<u8>>| -> One {
        let (p, w) = (apub.as_ref().unwrap(), awit.as_ref().unwrap());
        let t0 = Instant::now();
        let a = plain::auth_air_for(&o, p.depth);
        let trace = a.build_trace(&c1::perm(), p, w).expect("trace");
        let pv = p.to_values::<c1::Val>();
        let trace_s = t0.elapsed().as_secs_f64();
        let rows = trace.height();
        let t1 = Instant::now();
        let proof = p3_uni_stark::prove(&c1::config(&o), &a, trace, &pv).unwrap_or_else(|e| {
            eprintln!("prove failed (auth): {e:?}");
            std::process::exit(4)
        });
        let prove_s = t1.elapsed().as_secs_f64();
        let bytes = c1::to_bytes(&proof);
        drop(proof);
        let mut verify_s = 0.0;
        if rel == "auth" {
            let t2 = Instant::now();
            let parsed = c1::from_bytes(&bytes).expect("parse");
            plain::verify_auth(&o, &parsed, p).expect("honest auth proof must verify");
            verify_s = t2.elapsed().as_secs_f64();
        }
        let s = estimate(&c1::sec_input(&o, rows));
        let len = bytes.len();
        *keep = Some(bytes);
        One { rows, width: plain::auth_width(), trace_s, prove_s, verify_s, bytes: len, sec: (s.conjectured, s.proven_unique_decoding, s.proven_list_decoding) }
    };
    let stdin = std::io::stdin();
    for l in stdin.lock().lines().map_while(Result::ok) {
        match l.trim() {
            "run" => {
                let (mut be, mut br, mut ba) = (None, Vec::new(), None);
                let mut parts: Vec<(&str, One)> = Vec::new();
                match rel {
                    "exec" => parts.push(("exec", run_exec(&mut be))),
                    "rc" => parts.push(("rc", run_rc(&mut br))),
                    "auth" => parts.push(("auth", run_auth(&mut ba))),
                    _ => {
                        parts.push(("exec", run_exec(&mut be)));
                        parts.push(("rc", run_rc(&mut br)));
                        parts.push(("auth", run_auth(&mut ba)));
                    }
                }
                let mut vb = 0.0;
                if rel == "bundle" {
                    let t2 = Instant::now();
                    let pa = c1::from_bytes(ba.as_ref().unwrap()).expect("parse auth");
                    let pe = c1::from_bytes(be.as_ref().unwrap()).expect("parse exec");
                    let prs: Vec<c1::P> = br.iter().map(|b| c1::from_bytes(b).expect("parse rc")).collect();
                    verify_bundle_p(NativeChecks::ON, &o, f, &pa, apub.as_ref().unwrap(), &pe, epub.as_ref().unwrap(), &prs, &cpubs, &clists, RID)
                        .expect("honest bundle must verify");
                    vb = t2.elapsed().as_secs_f64();
                    for (name, p) in &parts {
                        emit(format!("SUB,{name},{},{},{:.6},{:.6},{:.6},{},{},{},{}", p.rows, p.width, p.trace_s, p.prove_s, p.verify_s, p.bytes, p.sec.0, p.sec.1, p.sec.2));
                    }
                }
                let rows: usize = parts.iter().map(|x| x.1.rows).sum();
                let width: usize = parts.iter().map(|x| x.1.width).sum();
                let tr: f64 = parts.iter().map(|x| x.1.trace_s).sum();
                let pr_: f64 = parts.iter().map(|x| x.1.prove_s).sum();
                let by: usize = parts.iter().map(|x| x.1.bytes).sum();
                let ver = if rel == "bundle" { vb } else { parts[0].1.verify_s };
                let c = parts.iter().map(|x| x.1.sec.0).min().unwrap();
                let u = parts.iter().map(|x| x.1.sec.1).min().unwrap();
                let ld = parts.iter().map(|x| x.1.sec.2).min().unwrap();
                let (count, sum) = epub.as_ref().map(|e| (e.count, e.sum[0])).unwrap_or((0, 0));
                emit(format!(
                    "ROW,{label},{n},{rows},{width},{count},{sum},{tr:.6},{pr_:.6},{ver:.6},{by},{c},{u},{ld},{},{}",
                    status_kb("VmRSS:"),
                    std::env::var("RAYON_NUM_THREADS").unwrap_or_default()
                ));
                emit("IDLE".to_string());
            }
            "quit" => break,
            _ => {}
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let rel = a.get(1).cloned().unwrap_or_default();
    let n: usize = arg(&a, "n").and_then(|s| s.parse().ok()).expect("n=N");
    let block: usize = arg(&a, "block").and_then(|s| s.parse().ok()).unwrap_or(100);
    let depth: usize = arg(&a, "depth").and_then(|s| s.parse().ok()).unwrap_or(10);
    let mode = arg(&a, "mode").unwrap_or_else(|| "plain".into());
    if !["exec", "rc", "auth", "bundle", "rcsep"].contains(&rel.as_str()) {
        eprintln!("usage: pchild3 <exec|rc|auth|bundle|rcsep> n=N [block=100] [mode=plain|zk] [depth=10] [fri=std|hi|fast2|fast1] [trace=seq|par] [ckpt_k=1024]");
        return;
    }
    if rel == "rcsep" && (block == 0 || n == 0 || n % block != 0) {
        eprintln!("rcsep: n must be a positive multiple of block (n={n}, block={block})");
        std::process::exit(2);
    }
    let fri = arg(&a, "fri").unwrap_or_else(|| "std".into());
    let Some(fo) = FriOpts::preset(&fri) else {
        eprintln!("fri must be std, hi, fast2 or fast1");
        return;
    };
    // w38 stage 3: `fmt=p2|p2r` selects the packed format (plain mode); the default (no fmt) is the old format, unchanged
    match arg(&a, "fmt").as_deref() {
        None | Some("old") => {}
        Some(x @ ("p2" | "p2r")) => {
            if mode != "plain" || rel == "rcsep" {
                eprintln!("fmt={x}: plain mode, rel exec|rc|auth|bundle only");
                std::process::exit(2);
            }
            let f = if x == "p2" { pqz_plonky3_w46::pair::Fmt::P2 } else { pqz_plonky3_w46::pair::Fmt::P2r };
            let cb: usize = arg(&a, "chunk").and_then(|s| s.parse().ok()).unwrap_or(0);
            packed_child(rel.as_str(), n, block, depth, fo.clone(), f, cb);
            return;
        }
        Some(x) => {
            eprintln!("fmt must be old, p2 or p2r, got {x}");
            std::process::exit(2);
        }
    }
    if rel == "rcsep" {
        match mode.as_str() {
            "plain" => child_rcsep!(n, block, plain, c1, "plain", fo.clone()),
            "zk" => child_rcsep!(n, block, zk, c1zk, "zk", fo.clone()),
            _ => eprintln!("mode must be plain or zk"),
        }
        return;
    }
    match mode.as_str() {
        "plain" => child!(rel.as_str(), n, block, depth, plain, c1, "plain", fo.clone()),
        "zk" => child!(rel.as_str(), n, block, depth, zk, c1zk, "zk", fo.clone()),
        _ => eprintln!("mode must be plain or zk"),
    }
}
