//! w34 (C4) verify-only child: prepare and prove ONCE (untimed, same code paths as `pchild3`), then `reps` timed verifications.
//! One timed verification = proof bytes -> parse -> verify. Bundle: three parses, the native checks (w34: stream link,
//! C_Q link, scope; `request::native_bundle_checks`) and the three proof verifications (same body as `request::verify_bundle`,
//! with the plain or zk verifiers). The verifier uses its own `FriOpts` (the same preset as the prover, as in `pchild3`).
//!
//! `request` (w34 E2) = the request verification of the paper (T_PQV, no R_RC): parse Auth + Exec, `request::native_request_checks`
//! (C_Q link + scope order; no RC, no stream link), verify Auth, verify Exec (same body as `request::verify_request` with all checks on).
//!
//! usage: pverify3 <exec|rc|auth|bundle|request> n=N [block=100] [mode=plain|zk] [fri=std|hi|fast2|fast1] [reps=25] [depth=10]
//! output (stdout), one line per timed rep, then DONE:
//!   VER,<label>,<n>,<rep>,<verify_s>,<bytes>,<conj>,<udr>,<ldr>,<threads>
//!   label = <rel>-<mode> (plus "-hi" for fri=hi); rep = 1..reps; bytes = total proof bytes (bundle: sum of the three);
//!   conj/udr/ldr = estimator bits (bundle: minimum over the three relations); threads = RAYON_NUM_THREADS (empty if unset).
//! Untimed: workload, statements, honest Auth instance, trace, proving, serialisation. An honest proof that fails to verify exits with code 5.

use pqz_plonky3_w36::auth::honest_auth_instance;
use pqz_plonky3_w36::data::Workload;
use pqz_plonky3_w36::rel::{plain, zk};
use pqz_plonky3_w36::request::{exec_context, native_bundle_checks, native_request_checks, NativeChecks};
use pqz_plonky3_w36::security::estimate;
use pqz_plonky3_w36::{c1, c1zk, FriOpts};
use p3_matrix::Matrix;
use std::io::Write;
use std::time::Instant;

fn arg(args: &[String], key: &str) -> Option<String> {
    args.iter().find_map(|a| a.strip_prefix(&format!("{key}=")).map(|s| s.to_string()))
}

const RID: u64 = 1;
const THETA: u64 = 1u64 << 31;

macro_rules! go {
    ($rel:expr, $n:expr, $block:expr, $depth:expr, $reps:expr, $plain:ident, $base:ident, $mode:expr, $fri:expr) => {{
        let o: FriOpts = $fri;
        let rel: &str = $rel;
        let (n, block, depth, reps): (usize, usize, usize, usize) = ($n, $block, $depth, $reps);
        // ---- untimed preparation (same as pchild3)
        let wl = if rel != "auth" { Some(Workload::synthetic(n, block, 1)) } else { None };
        let (apub, awit) = if rel == "auth" || rel == "bundle" || rel == "request" {
            let (p, w) = honest_auth_instance::<$base::Val, _>(&$base::perm(), depth, 1);
            (Some(p), Some(w))
        } else {
            (None, None)
        };
        let epub = if rel == "exec" || rel == "bundle" || rel == "request" {
            let ctx = match &apub {
                Some(a) => exec_context(&$base::perm(), a.b_q, a.d_q, RID),
                None => [1, 2, 3, 4],
            };
            Some($base::public_for(wl.as_ref().unwrap(), THETA, ctx))
        } else {
            None
        };
        let rpub = if rel == "rc" || rel == "bundle" { Some($plain::rc_public(&$base::words(wl.as_ref().unwrap()), block)) } else { None };
        let label = format!("{rel}-{}{}", $mode, match (o.log_blowup, o.num_queries) { (_, q) if q == FriOpts::hi().num_queries => "-hi", (2, q) if q == FriOpts::fast2().num_queries => "-fast2", (1, q) if q == FriOpts::fast1().num_queries => "-fast1", _ => "" });
        let mut sec: Vec<(u32, u32, u32)> = Vec::new();
        let mut est = |rows: usize| {
            let s = estimate(&$base::sec_input(&o, rows));
            sec.push((s.conjectured, s.proven_unique_decoding, s.proven_list_decoding));
        };

        // ---- prove once, untimed (each relation as in pchild3: trace, prove, serialise)
        let mut be: Option<Vec<u8>> = None;
        let mut br: Option<Vec<u8>> = None;
        let mut ba: Option<Vec<u8>> = None;
        if let Some(p) = epub.as_ref() {
            let a = $base::air(p.theta, p.n_words() as u64);
            let trace = a.build_trace(&$base::perm(), &$base::words(wl.as_ref().unwrap()));
            let pv = p.to_values::<$base::Val>(&a.lay);
            let rows = trace.height();
            let proof = p3_uni_stark::prove(&$base::config(&o), &a, trace, &pv).unwrap_or_else(|e| {
                eprintln!("prove failed (exec): {e:?}");
                std::process::exit(4)
            });
            be = Some($base::to_bytes(&proof));
            est(rows);
        }
        if let Some(p) = rpub.as_ref() {
            let a = $plain::rc_air(p.block_size as u64, p.n_words() as u64);
            let trace = a.build_trace(&$base::perm(), &$base::words(wl.as_ref().unwrap()));
            let pv = p.to_values::<$base::Val>(&a.lay);
            let rows = trace.height();
            let proof = p3_uni_stark::prove(&$base::config(&o), &a, trace, &pv).unwrap_or_else(|e| {
                eprintln!("prove failed (rc): {e:?}");
                std::process::exit(4)
            });
            br = Some($base::to_bytes(&proof));
            est(rows);
        }
        if let Some(p) = apub.as_ref() {
            let w = awit.as_ref().unwrap();
            let a = $plain::auth_air_for(&o, p.depth);
            let trace = a.build_trace(&$base::perm(), p, w).expect("trace");
            let pv = p.to_values::<$base::Val>();
            let rows = trace.height();
            let proof = p3_uni_stark::prove(&$base::config(&o), &a, trace, &pv).unwrap_or_else(|e| {
                eprintln!("prove failed (auth): {e:?}");
                std::process::exit(4)
            });
            ba = Some($base::to_bytes(&proof));
            est(rows);
        }
        let bytes: usize = [&be, &br, &ba].iter().map(|x| x.as_ref().map(|v| v.len()).unwrap_or(0)).sum();
        let c = sec.iter().map(|x| x.0).min().unwrap();
        let u = sec.iter().map(|x| x.1).min().unwrap();
        let ld = sec.iter().map(|x| x.2).min().unwrap();
        let threads = std::env::var("RAYON_NUM_THREADS").unwrap_or_default();
        eprintln!("prepared {label} n={n}: proof bytes {bytes}, reps {reps}");

        // ---- timed verifications: bytes -> parse -> verify
        for rep in 1..=reps {
            let t = Instant::now();
            let res: Result<(), String> = (|| {
                match rel {
                    "exec" => {
                        let p = $base::from_bytes(be.as_ref().unwrap())?;
                        $plain::verify_exec(&o, &p, epub.as_ref().unwrap())
                    }
                    "rc" => {
                        let p = $base::from_bytes(br.as_ref().unwrap())?;
                        $plain::verify_rc(&o, &p, rpub.as_ref().unwrap())
                    }
                    "auth" => {
                        let p = $base::from_bytes(ba.as_ref().unwrap())?;
                        $plain::verify_auth(&o, &p, apub.as_ref().unwrap())
                    }
                    "request" => {
                        let pa = $base::from_bytes(ba.as_ref().unwrap())?;
                        let pe = $base::from_bytes(be.as_ref().unwrap())?;
                        native_request_checks(NativeChecks::ON, apub.as_ref().unwrap(), epub.as_ref().unwrap(), RID)?;
                        $plain::verify_auth(&o, &pa, apub.as_ref().unwrap()).map_err(|e| format!("auth: {e}"))?;
                        $plain::verify_exec(&o, &pe, epub.as_ref().unwrap()).map_err(|e| format!("exec: {e}"))
                    }
                    _ => {
                        let pa = $base::from_bytes(ba.as_ref().unwrap())?;
                        let pe = $base::from_bytes(be.as_ref().unwrap())?;
                        let pr = $base::from_bytes(br.as_ref().unwrap())?;
                        native_bundle_checks(NativeChecks::ON, apub.as_ref().unwrap(), epub.as_ref().unwrap(), rpub.as_ref().unwrap(), RID)?;
                        $plain::verify_auth(&o, &pa, apub.as_ref().unwrap()).map_err(|e| format!("auth: {e}"))?;
                        $plain::verify_exec(&o, &pe, epub.as_ref().unwrap()).map_err(|e| format!("exec: {e}"))?;
                        $plain::verify_rc(&o, &pr, rpub.as_ref().unwrap()).map_err(|e| format!("rc: {e}"))
                    }
                }
            })();
            let dt = t.elapsed().as_secs_f64();
            if let Err(e) = res {
                eprintln!("honest {rel} proof rejected: {e}");
                std::process::exit(5);
            }
            println!("VER,{label},{n},{rep},{dt:.6},{bytes},{c},{u},{ld},{threads}");
            let _ = std::io::stdout().flush();
        }
        println!("DONE");
    }};
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let rel = a.get(1).cloned().unwrap_or_default();
    let usage = "usage: pverify3 <exec|rc|auth|bundle|request> n=N [block=100] [mode=plain|zk] [fri=std|hi|fast2|fast1] [reps=25] [depth=10]";
    if !["exec", "rc", "auth", "bundle", "request"].contains(&rel.as_str()) {
        eprintln!("{usage}");
        std::process::exit(2);
    }
    let Some(n) = arg(&a, "n").and_then(|s| s.parse::<usize>().ok()) else {
        eprintln!("{usage}");
        std::process::exit(2);
    };
    let block: usize = arg(&a, "block").and_then(|s| s.parse().ok()).unwrap_or(100);
    let depth: usize = arg(&a, "depth").and_then(|s| s.parse().ok()).unwrap_or(10);
    let reps: usize = arg(&a, "reps").and_then(|s| s.parse().ok()).unwrap_or(25);
    let mode = arg(&a, "mode").unwrap_or_else(|| "plain".into());
    let fri = arg(&a, "fri").unwrap_or_else(|| "std".into());
    let Some(fo) = FriOpts::preset(&fri) else {
        eprintln!("fri must be std, hi, fast2 or fast1");
        std::process::exit(2);
    };
    match mode.as_str() {
        "plain" => go!(rel.as_str(), n, block, depth, reps, plain, c1, "plain", fo.clone()),
        "zk" => go!(rel.as_str(), n, block, depth, reps, zk, c1zk, "zk", fo.clone()),
        _ => {
            eprintln!("mode must be plain or zk");
            std::process::exit(2);
        }
    }
}
