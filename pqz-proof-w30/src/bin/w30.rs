//! w30 (copy of `w29.rs` of pqz-proof-w29 plus the parallel-chunks mode). Written for `scripts/w30_driver.py`.
//! NEW in w30: `child prove ... mode=linked --parallel-chunks [threads=N]`: boundary values of all chunks first (native), then ALL chunk
//! proofs at the same time, one rayon ThreadPool per chunk (threads split in proportion to padded rows, `par_link::split_threads`).
//! Timed value of that mode (column prove_s) = wall-clock from the start of the boundary computation to the last chunk proof done
//! (boundary values + copying the chunk words + pool creation + trace build + proving; NOT serialisation / verification).
//! Row mode column: `linked-par`. Two trailing columns were added to every prove ROW: `bound_s` and `threads`.
//!   * sequential rows (single / linked): bound_s = time of the boundary computation measured at start-up, outside every timer, minimum of 3
//!     (single: 0); threads = number of threads of the global pool.
//!   * parallel rows: trace_s = the LONGEST per-chunk trace build, bound_s = boundary time of this run (inside prove_s), threads = "a+b+c".
//! Sequential modes are the w29 code, unchanged.
//!
//! (text of w29.rs follows)
//! w29 (NEW file): child programs for the w29 laptop matrix (linked chunks vs single proof). Written for `scripts/w29_driver.py`.
//! Same child protocol as `pilot.rs` (w25): ONE fresh process per measurement point; it prepares its instance outside any timer,
//! prints a READY line, performs ONE measured run per line "run" on stdin, prints a ROW line and then IDLE; exits on "quit".
//!
//!   w29 child prove  rel=exec|rc n=N [block=500] mode=single|linked
//!        single: one trace build + one proof. linked: plan_split (<= 4 chunks, whole blocks), then for each chunk one trace build +
//!        one proof, one after the other (public chain values come from the reference sponge, outside the timers).
//!        trace_s = sum of the trace builds, prove_s = sum of the proofs (proving only, no trace); both are printed.
//!        After the timers: serialise, parse + verify (not timed in the prove numbers; verify_s is printed for information).
//!   w29 child verify kind=bundle3|pair2|rc1|execchunk|execsingle [n=..] [block=..] [depth=10]
//!        bundle3 = rc + auth + exec (single proofs), pair2 = auth + exec, rc1 = rc alone (n=1000, block=100, seed 1000 as pilot `bundle`);
//!        execchunk / execsingle = R_Exec at n (default 50000), block (default 500), seed 1: parse + verify of the proofs per "run"
//!        (execchunk: parse every chunk proof + verify_exec_chunked incl. the link checks).
//!
//! The commitment hash comes from the cargo feature `blake3` (HASH_NAME is printed in every line); the proof options are
//! `prove::default_options()` (40 queries, blowup 8, grind 16; PQZ_* variables are NOT read by the driver).

use pqz_proof::auth::{build_auth_trace, honest_auth_instance, AuthAir, AuthPublic, AuthWitness};
use pqz_proof::data::Workload;
use pqz_proof::exec::{build_exec_trace, exec_public, ExecAir, ExecPublic};
use pqz_proof::exec_link::{exec_chunk_instances, verify_exec_chunked, ExecChunkPublic};
use pqz_proof::prove::{default_options, prove_trace, security_of, verify_proof, HASH_NAME};
use pqz_proof::rc::{build_rc_trace, rc_public, RcAir, RcPublic};
use pqz_proof::rc_link::{rc_chunk_instances, verify_rc_chunked, RcChunkPublic};
use pqz_proof::par_link::{prove_exec_chunked_parallel, prove_rc_chunked_parallel, total_threads};
use pqz_proof::request::{exec_context, verify_request};
use pqz_proof::rescue::F;
use pqz_proof::split::plan_split;
use std::io::{BufRead, Write};
use std::time::Instant;
use winterfell::{Proof, Trace};

const THETA: u64 = 1 << 31;
const MAX_CHUNKS: usize = 4;

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

fn opts_line() -> String {
    let o = default_options();
    format!("{},{},{},{}", HASH_NAME, o.num_queries(), o.blowup_factor(), o.grinding_factor())
}

extern "C" {
    fn malloc_trim(pad: usize) -> i32;
}

fn emit(line: String) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}

/// Calls `run` once per line "run" on stdin; with PILOT_TRIM=1 the allocator gives freed memory back after each run (outside the timers).
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
                emit("IDLE".to_string());
            }
            "quit" => break,
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// single-proof statements (as pilot.rs)

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
            Stmt::Rc(p) => verify_proof::<RcAir>(proof, p.clone()),
            Stmt::Exec(p) => verify_proof::<ExecAir>(proof, p.clone()),
            Stmt::Auth(p) => verify_proof::<AuthAir>(proof, p.clone()),
        }
    }
}

enum Prepared {
    Rc(Workload, RcPublic),
    Exec(Workload, ExecPublic),
    Auth(AuthPublic, AuthWitness),
}

fn make_workload(n: usize, block: usize, seed: u64) -> Workload {
    Workload::synthetic(n, block.min(n), seed)
}

fn ctx_of(seed: u64) -> [F; 4] {
    [F::new(seed), F::new(2), F::new(3), F::new(4)]
}

/// `exec_ctx`: Some(ctx) for an Exec statement that belongs to an Auth statement (ctx = exec_context(...) of that Auth statement,
/// lead fix e443); None = stand-alone Exec statement (ctx_of(seed), as before).
fn prepare(rel: &str, n: usize, block: usize, depth: usize, seed: u64, exec_ctx: Option<[F; 4]>) -> Prepared {
    match rel {
        "rc" => {
            let w = make_workload(n, block, seed);
            let p = rc_public(&w);
            Prepared::Rc(w, p)
        }
        "exec" => {
            let w = make_workload(n, block, seed);
            let p = exec_public(&w, THETA, exec_ctx.unwrap_or_else(|| ctx_of(seed)));
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

fn prove_prepared(pr: &Prepared) -> Result<Made, String> {
    let opts = default_options();
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

// ---------------------------------------------------------------------------------------------------------------
// linked chunks

/// Chunked prove of either relation. Returns (trace_s, prove_s, rows each, serialised proofs, min security bits (conj, udr, ldr)).
/// Chunk public inputs are made by `*_chunk_instances` (reference sponge) before this is called; only trace building and proving are timed.
enum ChunkInst {
    Exec(Vec<pqz_proof::exec_link::ExecChunkInstance>),
    Rc(Vec<pqz_proof::rc_link::RcChunkInstance>),
}

struct ChunkedMade {
    trace_s: f64,
    prove_s: f64,
    rows_each: Vec<usize>,
    bytes: Vec<Vec<u8>>,
    conj: u32,
    udr: u32,
    ldr: u32,
}

fn prove_chunks(inst: &ChunkInst) -> Result<ChunkedMade, String> {
    let (mut trace_s, mut prove_s) = (0f64, 0f64);
    let mut rows_each = Vec::new();
    let mut bytes = Vec::new();
    let (mut conj, mut udr, mut ldr) = (u32::MAX, u32::MAX, u32::MAX);
    let mut note = |proof: &Proof| {
        let sec = security_of(proof);
        conj = conj.min(sec.conjectured_bits);
        udr = udr.min(sec.proven_unique_decoding_bits);
        ldr = ldr.min(sec.proven_list_decoding_bits);
    };
    match inst {
        ChunkInst::Exec(v) => {
            for c in v {
                let t0 = Instant::now();
                let trace = c.build_trace();
                trace_s += t0.elapsed().as_secs_f64();
                rows_each.push(trace.length());
                let t1 = Instant::now();
                let proof = c.prove_trace(trace, default_options())?;
                prove_s += t1.elapsed().as_secs_f64();
                note(&proof);
                bytes.push(proof.to_bytes());
            }
        }
        ChunkInst::Rc(v) => {
            for c in v {
                let t0 = Instant::now();
                let trace = c.build_trace();
                trace_s += t0.elapsed().as_secs_f64();
                rows_each.push(trace.length());
                let t1 = Instant::now();
                let proof = c.prove_trace(trace, default_options())?;
                prove_s += t1.elapsed().as_secs_f64();
                note(&proof);
                bytes.push(proof.to_bytes());
            }
        }
    }
    Ok(ChunkedMade { trace_s, prove_s, rows_each, bytes, conj, udr, ldr })
}

fn parse_all(bytes: &[Vec<u8>]) -> Result<Vec<Proof>, String> {
    bytes.iter().map(|b| Proof::from_bytes(b).map_err(|e| format!("parse: {e:?}"))).collect()
}

fn verify_exec_chunk_bytes(bytes: &[Vec<u8>], pubs: &[ExecChunkPublic], w: &Workload, st: &ExecPublic) -> Result<(), String> {
    let proofs = parse_all(bytes)?;
    let v: Vec<(Proof, ExecChunkPublic)> = proofs.into_iter().zip(pubs.iter().cloned()).collect();
    verify_exec_chunked(v, st.digest, w.n_blocks, w.block_size, st.theta, st.ctx, st.count, st.sum)
}

fn verify_rc_chunk_bytes(bytes: &[Vec<u8>], pubs: &[RcChunkPublic], st: &RcPublic) -> Result<(), String> {
    let proofs = parse_all(bytes)?;
    let v: Vec<(Proof, RcChunkPublic)> = proofs.into_iter().zip(pubs.iter().cloned()).collect();
    verify_rc_chunked(v, st.digest, st.n_blocks, st.block_size, st.header0)
}

/// Routine request: RID_Q = 0 (paper: bottom).
const RID_ROUTINE: u64 = 0;

/// Pair verification of one request (parse both proofs, then `verify_request`: ctx binding, Auth proof, Exec proof).
fn verify_pair_bytes(auth: &Stmt, auth_bytes: &[u8], exec: &Stmt, exec_bytes: &[u8]) -> Result<(), String> {
    let (Stmt::Auth(ap), Stmt::Exec(ep)) = (auth, exec) else { return Err("pair: wrong statement kinds".into()) };
    let aproof = Proof::from_bytes(auth_bytes).map_err(|e| format!("parse: {e:?}"))?;
    let eproof = Proof::from_bytes(exec_bytes).map_err(|e| format!("parse: {e:?}"))?;
    verify_request(aproof, ap.clone(), eproof, ep.clone(), RID_ROUTINE)
}

fn join_usize(v: &[usize]) -> String {
    v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("+")
}

// ---------------------------------------------------------------------------------------------------------------

fn child_prove(args: &[String]) {
    let rel = arg(args, "rel").unwrap();
    let n: usize = arg(args, "n").unwrap().parse().unwrap();
    let block: usize = arg(args, "block").map(|s| s.parse().unwrap()).unwrap_or(500);
    let mode = arg(args, "mode").unwrap_or_else(|| "single".into());
    assert!(rel == "exec" || rel == "rc");
    assert!(mode == "single" || mode == "linked");
    let parallel = args.iter().any(|a| a == "--parallel-chunks");
    assert!(!(parallel && mode == "single"), "--parallel-chunks needs mode=linked");
    let threads: usize = arg(args, "threads").map(|s| s.parse().unwrap()).unwrap_or_else(total_threads);
    if mode == "single" {
        let pr = prepare(&rel, n, block, 0, 1, None);
        emit(format!("READY,prove,{rel},{n},{block},single,{}", opts_line()));
        serve(|| {
            let made = match prove_prepared(&pr) {
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
                "ROW,prove,{rel},{n},{block},single,{},1,{},{},{:.6},{:.6},{:.6},{},{},{},{},{},0.000000,{}",
                opts_line(),
                made.trace_rows,
                made.trace_rows,
                made.trace_s,
                made.prove_s,
                verify_s,
                bytes.len(),
                sec.conjectured_bits,
                sec.proven_unique_decoding_bits,
                sec.proven_list_decoding_bits,
                status_kb("VmRSS:"),
                total_threads()
            ));
        });
    } else if parallel {
        child_prove_parallel(&rel, n, block, threads);
    } else {
        let w = make_workload(n, block, 1);
        let split = plan_split(w.n_blocks, w.block_size, MAX_CHUNKS);
        let label = join_usize(&split);
        // w30: boundary-computation time (information, outside every timer; minimum of 3)
        let bound_s = (0..3)
            .map(|_| {
                let t = Instant::now();
                if rel == "exec" {
                    std::hint::black_box(exec_chunk_instances(&w, THETA, ctx_of(1), &split));
                } else {
                    std::hint::black_box(rc_chunk_instances(&w, &split));
                }
                t.elapsed().as_secs_f64()
            })
            .fold(f64::MAX, f64::min);
        let (inst, exec_st, rc_st, exec_pubs, rc_pubs);
        if rel == "exec" {
            let i = exec_chunk_instances(&w, THETA, ctx_of(1), &split);
            exec_pubs = i.iter().map(|c| c.public.clone()).collect::<Vec<_>>();
            rc_pubs = Vec::new();
            exec_st = Some(exec_public(&w, THETA, ctx_of(1)));
            rc_st = None;
            inst = ChunkInst::Exec(i);
        } else {
            let i = rc_chunk_instances(&w, &split);
            rc_pubs = i.iter().map(|c| c.public.clone()).collect::<Vec<_>>();
            exec_pubs = Vec::new();
            rc_st = Some(rc_public(&w));
            exec_st = None;
            inst = ChunkInst::Rc(i);
        }
        emit(format!("READY,prove,{rel},{n},{block},linked,{},{label}", opts_line()));
        serve(|| {
            let made = match prove_chunks(&inst) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("prove failed: {e}");
                    std::process::exit(4);
                }
            };
            let t = Instant::now();
            if let Some(st) = &exec_st {
                verify_exec_chunk_bytes(&made.bytes, &exec_pubs, &w, st).expect("honest chunked proof must verify");
            } else {
                verify_rc_chunk_bytes(&made.bytes, &rc_pubs, rc_st.as_ref().unwrap()).expect("honest chunked proof must verify");
            }
            let verify_s = t.elapsed().as_secs_f64();
            let rows: usize = made.rows_each.iter().sum();
            let bytes: usize = made.bytes.iter().map(|b| b.len()).sum();
            emit(format!(
                "ROW,prove,{rel},{n},{block},linked,{},{},{rows},{},{:.6},{:.6},{:.6},{bytes},{},{},{},{},{bound_s:.6},{}",
                opts_line(),
                made.rows_each.len(),
                join_usize(&made.rows_each),
                made.trace_s,
                made.prove_s,
                verify_s,
                made.conj,
                made.udr,
                made.ldr,
                status_kb("VmRSS:"),
                total_threads()
            ));
        });
    }
}

/// w30: parallel chunks. The statement and the workload are prepared outside the timer; one run = boundary values + all chunk proofs at the
/// same time (see the header). Verification (after the timer) uses the publics returned by the run itself.
fn child_prove_parallel(rel: &str, n: usize, block: usize, threads: usize) {
    let w = make_workload(n, block, 1);
    let split = plan_split(w.n_blocks, w.block_size, MAX_CHUNKS);
    let label = join_usize(&split);
    let exec_st = if rel == "exec" { Some(exec_public(&w, THETA, ctx_of(1))) } else { None };
    let rc_st = if rel == "rc" { Some(rc_public(&w)) } else { None };
    emit(format!("READY,prove,{rel},{n},{block},linked-par,{},{label},threads={threads}", opts_line()));
    serve(|| {
        // ---- timed region = ParStats::wall_s (inside the call) ----
        let (bytes, stats, verify_s, sec) = if let Some(st) = &exec_st {
            let (proofs, stats) = match prove_exec_chunked_parallel(&w, THETA, ctx_of(1), default_options(), &split, threads) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("prove failed: {e}");
                    std::process::exit(4);
                }
            };
            let sec: Vec<_> = proofs.iter().map(|(p, _)| security_of(p)).collect();
            let bytes: Vec<Vec<u8>> = proofs.iter().map(|(p, _)| p.to_bytes()).collect();
            let pubs: Vec<ExecChunkPublic> = proofs.iter().map(|(_, p)| p.clone()).collect();
            let t = Instant::now();
            verify_exec_chunk_bytes(&bytes, &pubs, &w, st).expect("honest parallel chunked proof must verify");
            (bytes, stats, t.elapsed().as_secs_f64(), sec)
        } else {
            let (proofs, stats) = match prove_rc_chunked_parallel(&w, default_options(), &split, threads) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("prove failed: {e}");
                    std::process::exit(4);
                }
            };
            let sec: Vec<_> = proofs.iter().map(|(p, _)| security_of(p)).collect();
            let bytes: Vec<Vec<u8>> = proofs.iter().map(|(p, _)| p.to_bytes()).collect();
            let pubs: Vec<RcChunkPublic> = proofs.iter().map(|(_, p)| p.clone()).collect();
            let t = Instant::now();
            verify_rc_chunk_bytes(&bytes, &pubs, rc_st.as_ref().unwrap()).expect("honest parallel chunked proof must verify");
            (bytes, stats, t.elapsed().as_secs_f64(), sec)
        };
        let conj = sec.iter().map(|s| s.conjectured_bits).min().unwrap();
        let udr = sec.iter().map(|s| s.proven_unique_decoding_bits).min().unwrap();
        let ldr = sec.iter().map(|s| s.proven_list_decoding_bits).min().unwrap();
        let rows: usize = stats.rows.iter().sum();
        let nbytes: usize = bytes.iter().map(|b| b.len()).sum();
        let trace_max = stats.trace_s.iter().cloned().fold(0.0, f64::max);
        emit(format!(
            "ROW,prove,{rel},{n},{block},linked-par,{},{},{rows},{},{:.6},{:.6},{:.6},{nbytes},{conj},{udr},{ldr},{},{:.6},{}",
            opts_line(),
            stats.rows.len(),
            join_usize(&stats.rows),
            trace_max,
            stats.wall_s,
            verify_s,
            status_kb("VmRSS:"),
            stats.boundary_s,
            join_usize(&stats.threads)
        ));
    });
}

fn child_verify(args: &[String]) {
    let kind = arg(args, "kind").unwrap();
    match kind.as_str() {
        "bundle3" | "pair2" | "rc1" => {
            let n: usize = arg(args, "n").map(|s| s.parse().unwrap()).unwrap_or(1000);
            let block: usize = arg(args, "block").map(|s| s.parse().unwrap()).unwrap_or(100);
            let depth: usize = arg(args, "depth").map(|s| s.parse().unwrap()).unwrap_or(10);
            let rels: Vec<&str> = match kind.as_str() {
                "bundle3" => vec!["rc", "auth", "exec"],
                "pair2" => vec!["auth", "exec"],
                _ => vec!["rc"],
            };
            let mut items: Vec<(Stmt, Vec<u8>)> = Vec::new();
            let (mut conj, mut udr, mut ldr) = (u32::MAX, u32::MAX, u32::MAX);
            let mut sizes: Vec<usize> = Vec::new();
            let mut auth_ctx: Option<[F; 4]> = None;
            for rel in &rels {
                let pr = prepare(rel, n, block, depth, 1000, if *rel == "exec" { auth_ctx } else { None });
                if let Prepared::Auth(p, _) = &pr {
                    auth_ctx = Some(exec_context(p.b_q, p.d_q, RID_ROUTINE));
                }
                let m = prove_prepared(&pr).expect("prove");
                let sec = security_of(&m.proof);
                conj = conj.min(sec.conjectured_bits);
                udr = udr.min(sec.proven_unique_decoding_bits);
                ldr = ldr.min(sec.proven_list_decoding_bits);
                let bytes = m.proof.to_bytes();
                sizes.push(bytes.len());
                items.push((m.stmt, bytes));
            }
            let total_bytes: usize = sizes.iter().sum();
            let sizes_s = join_usize(&sizes);
            emit(format!("READY,verify,{kind},{n},{block},{},{total_bytes},{sizes_s},{conj},{udr},{ldr}", opts_line()));
            serve(|| {
                let t_all = Instant::now();
                // rc proofs alone; Auth + Exec together through verify_request (ctx binding INSIDE the timer)
                for (stmt, bytes) in items.iter() {
                    if let Stmt::Rc(_) = stmt {
                        stmt.verify_bytes(bytes).expect("honest proof must verify");
                    }
                }
                let a = items.iter().find(|(s, _)| matches!(s, Stmt::Auth(_)));
                let e = items.iter().find(|(s, _)| matches!(s, Stmt::Exec(_)));
                if let (Some((sa, ba)), Some((se, be))) = (a, e) {
                    verify_pair_bytes(sa, ba, se, be).expect("honest request (Auth + Exec) must verify");
                }
                let total = t_all.elapsed().as_secs_f64();
                emit(format!(
                    "ROW,verify,{kind},{n},{block},{},{},{total:.6},{total_bytes},{sizes_s},{conj},{udr},{ldr}",
                    opts_line(),
                    rels.len()
                ));
            });
        }
        "execsingle" => {
            let n: usize = arg(args, "n").map(|s| s.parse().unwrap()).unwrap_or(50000);
            let block: usize = arg(args, "block").map(|s| s.parse().unwrap()).unwrap_or(500);
            let pr = prepare("exec", n, block, 0, 1, None);
            let m = prove_prepared(&pr).expect("prove");
            let sec = security_of(&m.proof);
            let bytes = m.proof.to_bytes();
            let (conj, udr, ldr) = (sec.conjectured_bits, sec.proven_unique_decoding_bits, sec.proven_list_decoding_bits);
            emit(format!("READY,verify,{kind},{n},{block},{},{},{},{conj},{udr},{ldr}", opts_line(), bytes.len(), bytes.len()));
            serve(|| {
                let t0 = Instant::now();
                m.stmt.verify_bytes(&bytes).expect("honest proof must verify");
                let total = t0.elapsed().as_secs_f64();
                emit(format!(
                    "ROW,verify,{kind},{n},{block},{},1,{total:.6},{},{},{conj},{udr},{ldr}",
                    opts_line(),
                    bytes.len(),
                    bytes.len()
                ));
            });
        }
        "execchunk" => {
            let n: usize = arg(args, "n").map(|s| s.parse().unwrap()).unwrap_or(50000);
            let block: usize = arg(args, "block").map(|s| s.parse().unwrap()).unwrap_or(500);
            let w = make_workload(n, block, 1);
            let split = plan_split(w.n_blocks, w.block_size, MAX_CHUNKS);
            let st = exec_public(&w, THETA, ctx_of(1));
            let inst = exec_chunk_instances(&w, THETA, ctx_of(1), &split);
            let pubs: Vec<ExecChunkPublic> = inst.iter().map(|c| c.public.clone()).collect();
            let made = prove_chunks(&ChunkInst::Exec(inst)).expect("prove");
            let sizes: Vec<usize> = made.bytes.iter().map(|b| b.len()).collect();
            let total_bytes: usize = sizes.iter().sum();
            let sizes_s = join_usize(&sizes);
            let split_s = join_usize(&split);
            emit(format!(
                "READY,verify,{kind},{n},{block},{},{total_bytes},{sizes_s},{},{},{},{split_s}",
                opts_line(),
                made.conj,
                made.udr,
                made.ldr
            ));
            serve(|| {
                let t0 = Instant::now();
                verify_exec_chunk_bytes(&made.bytes, &pubs, &w, &st).expect("honest chunked proof must verify");
                let total = t0.elapsed().as_secs_f64();
                emit(format!(
                    "ROW,verify,{kind},{n},{block},{},{},{total:.6},{total_bytes},{sizes_s},{},{},{}",
                    opts_line(),
                    sizes.len(),
                    made.conj,
                    made.udr,
                    made.ldr
                ));
            });
        }
        _ => panic!("unknown verify kind {kind}"),
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match (a.first().map(|s| s.as_str()), a.get(1).map(|s| s.as_str())) {
        (Some("child"), Some("prove")) => child_prove(&a[2..]),
        (Some("child"), Some("verify")) => child_verify(&a[2..]),
        _ => {
            eprintln!("usage: w30 child prove|verify key=value ...");
            std::process::exit(2);
        }
    }
}
