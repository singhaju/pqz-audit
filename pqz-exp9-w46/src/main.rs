//! Experiment 9 harness, PQZ side (w36). One process = one run (the steps script starts a fresh process for every run).
//!
//!   export <n> <layout> <outdir>      write the ZKSQL table (id,a,v,b CSV) and the reference (count, sum_b) of the SAME records
//!   child whole|cover n=N layout=clustered|scattered preset=std|fast2|fast1 zk=0|1 [vreps=25] [chunk=4] [gap=1] [run=I]
//!                                     prints ONE line "ROW key=value ..." (status=ok) or "ROW status=FAILED ..." and exits non-zero
//!
//! WHOLE : one R_Exec proof over all N records (as w34 `ExecStream::Whole`). Per-query numbers: claim scan, R_Exec public/trace/prove, requester.
//! COVER : block cover. Ingest (log, chunk proofs, AA check, Bloom filters, ledger anchor) is timed separately (`ingest_*`) and never enters a
//!         per-query number. Per query: BPS + run plan + Bloom openings of the pruned blocks, R_Exec run proofs (public/trace/prove), requester.
//! `auth_s` (the R_Auth proof, a per-request cost) is reported separately in both modes; it is always plain (no zk), see README "Disclosures".
//!
//! The proof stack (w35 or w36) is named only in Cargo.toml (`pqz_int`, `pqz_p3`). The FRI preset is chosen by
//! the driver itself (`apply_preset`); only the per-query proofs use it, see the comment there.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::time::Instant;

use p3_matrix::Matrix;
use pqz_eval::eapat::EpochKeys;
use pqz_eval::r#gen::r#gen;
use pqz_eval::{Layout, Predicate};
use pqz_int::w35::{
    aa_finalize_fmt, openings_for_blocks, plan_runs, requester_bytes, requester_native35_fmt, verify_requester35_fmt, AaChecks, Anchor, CspResponse,
    ReqChecks, RunClaim, World35,
};
use pqz_int::WFmt;
use pqz_int::{
    auth_stage, build_log, commit_epoch, ledger_setup, opts, predicate_formula, requester_native_checks, search, sys, verify_auth_stage, BLOCK,
    DEFAULT_SEED, EPOCH, RID, THETA,
};
use pqz_p3::air::{native_digest, ExecPublic};
use pqz_p3::request::{check_ctx, check_scope, exec_context};
use pqz_p3::run::{RunAir, RunPublic};
use pqz_p3::{c1, FriOpts};

type Row = BTreeMap<String, String>;

fn set(r: &mut Row, k: &str, v: impl ToString) {
    r.insert(k.to_string(), v.to_string());
}
fn setf(r: &mut Row, k: &str, v: f64) {
    r.insert(k.to_string(), format!("{v:.6}"));
}
fn print_row(r: &Row) {
    let mut s = String::from("ROW");
    for (k, v) in r {
        let v: String = v.chars().map(|c| if c.is_whitespace() { '_' } else { c }).collect();
        s.push_str(&format!(" {k}={v}"));
    }
    println!("{s}");
    let _ = std::io::stdout().flush();
}

fn arg(args: &[String], k: &str) -> Option<String> {
    args.iter().find_map(|a| a.strip_prefix(&format!("{k}=")).map(|s| s.to_string()))
}
fn layout_of(s: &str) -> Option<Layout> {
    match s {
        "clustered" => Some(Layout::Clustered),
        "scattered" => Some(Layout::Scattered),
        _ => None,
    }
}

struct Fail(i32, String);
type R<T> = Result<T, Fail>;
fn f<E: std::fmt::Display>(code: i32) -> impl Fn(E) -> Fail {
    move |e| Fail(code, e.to_string())
}

// ------------------------------------------------------------------------------------------------------------------------------------
// presets
// ------------------------------------------------------------------------------------------------------------------------------------

/// (log_blowup, num_queries) each preset must give (w36 `FriOpts::std/fast2/fast1`, FAST2_NUM_QUERIES 61, FAST1_NUM_QUERIES 126).
fn expected_preset(name: &str) -> Option<(usize, usize)> {
    match name {
        "std" => Some((3, 40)),
        "fast2" => Some((2, 61)),
        "fast1" => Some((1, 126)),
        _ => None,
    }
}

/// The one place that selects a preset. The driver builds the options itself (same values as w36 `FriOpts::fast2/fast1`; the w35 stack has
/// no such functions) and uses them for the per-query proofs (R_Exec whole, R_Exec runs) and their verification. The ingest chunk proofs and
/// R_Auth go through `pqz_int::opts()` of the library (std) and are not changed by the preset: ingest is not a per-query number, and R_Auth is
/// reported separately (README, Disclosures). The library requester gate (`verify_requester35`) uses `opts()` too and is therefore run only for std.
fn apply_preset(name: &str) -> R<FriOpts> {
    let (lb, q) = expected_preset(name).ok_or_else(|| Fail(2, format!("unknown preset {name}")))?;
    let o = FriOpts { log_blowup: lb, num_queries: q, ..FriOpts::default() };
    if name == "std" {
        let l = opts();
        if l.log_blowup != o.log_blowup || l.num_queries != o.num_queries || l.query_pow_bits != o.query_pow_bits {
            return Err(Fail(3, "std preset differs from pqz_int::opts()".into()));
        }
    }
    Ok(o)
}

// ------------------------------------------------------------------------------------------------------------------------------------
// proof modules: plain (c1) and hiding (c1zk). Same code, other PCS.
// ------------------------------------------------------------------------------------------------------------------------------------

macro_rules! proofmod {
    ($m:ident, $base:path) => {
        mod $m {
            use super::*;
            use $base as b;
            use pqz_p3::rel::{guard, LL};
            use b::{HF, PR, REG, SBOX, W};

            pub type RunA = RunAir<b::Val, LL, W, { SBOX }, REG, { HF }, { PR }>;

            fn run_air(p: &RunPublic) -> Result<RunA, String> {
                if p.block_size == 0 || p.n_blocks == 0 || p.theta == 0 || p.theta >= (1u64 << 32) {
                    return Err("run statement out of range".into());
                }
                Ok(RunA::new(b::consts(), p.theta, p.block_size as u64, p.n_words() as u64))
            }
            /// (proof bytes, trace_s, prove_s incl. serialisation, rows)
            pub fn prove_run(o: &FriOpts, words: &[Vec<u64>], p: &RunPublic) -> Result<(Vec<u8>, f64, f64, usize), String> {
                let a = run_air(p)?;
                let t = Instant::now();
                let trace = a.build_trace(&b::perm(), words, &p.s_in);
                let pv = p.to_values::<b::Val>(&a.lay);
                let trace_s = t.elapsed().as_secs_f64();
                let rows = trace.height();
                let t = Instant::now();
                let proof = p3_uni_stark::prove(&b::config(o), &a, trace, &pv).map_err(|e| format!("{e:?}"))?;
                let bytes = b::to_bytes(&proof);
                Ok((bytes, trace_s, t.elapsed().as_secs_f64(), rows))
            }
            pub fn verify_run(o: &FriOpts, bytes: &[u8], p: &RunPublic) -> Result<(), String> {
                let proof = b::from_bytes(bytes)?;
                guard(|| {
                    let a = run_air(p)?;
                    let pv = p.to_values::<b::Val>(&a.lay);
                    p3_uni_stark::verify(&b::config(o), &a, &proof, &pv).map_err(|e| format!("{e:?}"))
                })
            }
            /// R_Exec over all words: (stmt, bytes, pub_s, trace_s, prove_s, rows)
            pub fn prove_exec(o: &FriOpts, wl: &pqz_p3::data::Workload, ctx: [u64; 4], claim: (u64, u64)) -> Result<(ExecPublic, Vec<u8>, f64, f64, f64, usize), String> {
                let t = Instant::now();
                let words = b::words(wl);
                let digest = native_digest::<b::Val, 12, _>(&b::lay(), &b::perm(), &words);
                let stmt = ExecPublic { digest, n_blocks: wl.n_blocks, block_size: wl.block_size, theta: THETA, count: claim.0, sum: vec![claim.1], ctx };
                let pub_s = t.elapsed().as_secs_f64();
                let t = Instant::now();
                let a = b::air(THETA, stmt.n_words() as u64);
                let trace = a.build_trace(&b::perm(), &words);
                let pv = stmt.to_values::<b::Val>(&a.lay);
                let trace_s = t.elapsed().as_secs_f64();
                let rows = trace.height();
                let t = Instant::now();
                let proof = p3_uni_stark::prove(&b::config(o), &a, trace, &pv).map_err(|e| format!("{e:?}"))?;
                let bytes = b::to_bytes(&proof);
                Ok((stmt, bytes, pub_s, trace_s, t.elapsed().as_secs_f64(), rows))
            }
            pub fn verify_exec(o: &FriOpts, bytes: &[u8], stmt: &ExecPublic) -> Result<(), String> {
                let proof = b::from_bytes(bytes)?;
                guard(|| b::verify_with(o, &proof, stmt))
            }
        }
    };
}
proofmod!(pm_plain, pqz_p3::variants::c1);
proofmod!(pm_zk, pqz_p3::variants::c1zk);

/// w46: packed P2r whole-mode R_Exec (pqz-plonky3-w46 `pair`, Fmt::P2r), plain or hiding PCS. The Exec statement digest is over the PACKED words;
/// it is linked to the packed R_RC statement (ONE pchunk chunk with all blocks, computed at prepare time) by `prequest::native_bundle_checks_p`
/// (= `check_stream_link_p` + `check_sealed` lists + C_Q link + scope), run in the per-query requester check together with the theta check.
mod p2r {
    use super::*;
    use pqz_p3::air::ExecPublic as PubB;
    use pqz_p3::pair::{pack_workload, pair_air, pair_n_words, pair_public, pair_values, Fmt};
    use pqz_p3::{c1zk as c1zkb, FriOpts as FoB};

    pub fn opts_b(name: &str) -> Result<FoB, String> {
        FoB::preset(name).ok_or_else(|| format!("unknown preset {name} (p2r)"))
    }
    /// (stmt, bytes, pub_s, trace_s, prove_s, rows)
    pub fn prove_exec(o: &FoB, wl: &pqz_p3::data::Workload, ctx: [u64; 4], zk: bool) -> Result<(PubB, Vec<u8>, f64, f64, f64, usize), String> {
        let t = Instant::now();
        let packed = pack_workload(wl);
        let stmt = pair_public(wl, THETA, ctx);
        let pub_s = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let air = pair_air(stmt.theta, pair_n_words(stmt.n_blocks, stmt.block_size) as u64, Fmt::P2r);
        let trace = air.build_trace(&c1::perm(), &packed, stmt.block_size);
        let pv = pair_values(&stmt);
        let trace_s = t.elapsed().as_secs_f64();
        let rows = trace.height();
        let t = Instant::now();
        let bytes = if zk {
            let p = p3_uni_stark::prove(&c1zkb::config(o), &air, trace, &pv).map_err(|e| format!("{e:?}"))?;
            c1zkb::to_bytes(&p)
        } else {
            let p = p3_uni_stark::prove(&c1::config(o), &air, trace, &pv).map_err(|e| format!("{e:?}"))?;
            c1::to_bytes(&p)
        };
        Ok((stmt, bytes, pub_s, trace_s, t.elapsed().as_secs_f64(), rows))
    }
    pub fn verify_exec(o: &FoB, bytes: &[u8], stmt: &PubB, zk: bool) -> Result<(), String> {
        let air = pair_air(stmt.theta, pair_n_words(stmt.n_blocks, stmt.block_size) as u64, Fmt::P2r);
        let pv = pair_values(stmt);
        pqz_p3::rel::guard(|| {
            if zk {
                let p = c1zkb::from_bytes(bytes)?;
                p3_uni_stark::verify(&c1zkb::config(o), &air, &p, &pv).map_err(|e| format!("{e:?}"))
            } else {
                let p = c1::from_bytes(bytes)?;
                p3_uni_stark::verify(&c1::config(o), &air, &p, &pv).map_err(|e| format!("{e:?}"))
            }
        })
    }
    /// Packed R_RC statement of the whole stream (prepare time): one chunk holding all blocks, honest publics + lists.
    pub fn rc_statement(wl: &pqz_p3::data::Workload) -> (Vec<pqz_p3::chunk::RcChunkPublic>, Vec<pqz_p3::chunk::ChunkLists>, Vec<Vec<u64>>) {
        let packed = pack_workload(wl);
        let (pubs, lists) = pqz_p3::pchunk::plain::honest_publics(&packed, wl.block_size, wl.n_blocks);
        (pubs, lists, packed)
    }
    /// requester native checks of P2r whole: theta, then `native_bundle_checks_p` (stream link, lists, C_Q link, scope)
    pub fn native_checks(auth: &pqz_p3::auth::AuthPublic, stmt: &PubB, rc: &[pqz_p3::chunk::RcChunkPublic], lists: &[pqz_p3::chunk::ChunkLists]) -> Result<(), String> {
        if stmt.theta != THETA {
            return Err(format!("exec theta {} != requested theta {}", stmt.theta, THETA));
        }
        pqz_p3::prequest::native_bundle_checks_p(pqz_p3::request::NativeChecks::ON, auth, stmt, rc, lists, RID)
    }
}

fn prove_run(zk: bool, o: &FriOpts, w: &[Vec<u64>], p: &RunPublic) -> Result<(Vec<u8>, f64, f64, usize), String> {
    if zk {
        pm_zk::prove_run(o, w, p)
    } else {
        pm_plain::prove_run(o, w, p)
    }
}
fn verify_run(zk: bool, o: &FriOpts, b: &[u8], p: &RunPublic) -> Result<(), String> {
    if zk {
        pm_zk::verify_run(o, b, p)
    } else {
        pm_plain::verify_run(o, b, p)
    }
}

fn prove_run_f(wf: WFmt, zk: bool, o: &FriOpts, w: &[Vec<u64>], p: &RunPublic) -> Result<(Vec<u8>, f64, f64, usize), String> {
    match (wf, zk) {
        (WFmt::Old, _) => prove_run(zk, o, w, p),
        (WFmt::P2r, false) => pqz_p3::prun::plain::prove_run_bytes_par(o, w, p),
        (WFmt::P2r, true) => pqz_p3::prun::zk::prove_run_bytes_par(o, w, p),
    }
}
fn verify_run_f(wf: WFmt, zk: bool, o: &FriOpts, b: &[u8], p: &RunPublic) -> Result<(), String> {
    match (wf, zk) {
        (WFmt::Old, _) => verify_run(zk, o, b, p),
        (WFmt::P2r, false) => pqz_p3::prun::plain::verify_run_bytes(o, b, p),
        (WFmt::P2r, true) => pqz_p3::prun::zk::verify_run_bytes(o, b, p),
    }
}

// ------------------------------------------------------------------------------------------------------------------------------------
// helpers
// ------------------------------------------------------------------------------------------------------------------------------------

fn med(v: &mut Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if v.is_empty() {
        0.0
    } else if v.len() % 2 == 1 {
        v[v.len() / 2]
    } else {
        (v[v.len() / 2 - 1] + v[v.len() / 2]) / 2.0
    }
}
fn pct(v: &mut Vec<f64>, p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if v.is_empty() {
        return 0.0;
    }
    let i = ((v.len() as f64 - 1.0) * p).ceil() as usize;
    v[i.min(v.len() - 1)]
}

fn reference(records: &[pqz_eval::Record]) -> (u64, u64) {
    let mut t = (0u64, 0u64);
    for r in records {
        if Predicate::P1.matches(r) {
            t.0 += 1;
            t.1 += r.b as u64;
        }
    }
    t
}

fn common(r: &mut Row, mode: &str, n: usize, layout: &str, preset: &str, zk: bool, run: &str, o: &FriOpts) {
    set(r, "stack", std::any::type_name::<pqz_int::RunError>().split("::").next().unwrap_or("?"));
    set(r, "exp", "exp9");
    set(r, "mode", mode);
    set(r, "n", n);
    set(r, "layout", layout);
    set(r, "preset", preset);
    set(r, "zk", zk as u8);
    set(r, "run", run);
    set(r, "seed", DEFAULT_SEED);
    set(r, "block", BLOCK);
    set(r, "sigma", n / 100);
    set(r, "log_blowup", o.log_blowup);
    set(r, "num_queries", o.num_queries);
    set(r, "preset_scope", "exec_and_run_proofs_only;ingest_and_auth_use_library_std");
    set(r, "rayon_threads_env", std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "unset".into()));
    let aff = fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:").map(|s| s.trim().to_string()))
        .unwrap_or_default();
    set(r, "cpus_allowed", aff);
    set(r, "loadavg1_start", sys::loadavg1());
}

// ------------------------------------------------------------------------------------------------------------------------------------
// WHOLE
// ------------------------------------------------------------------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn whole(n: usize, layout_s: &str, layout: Layout, preset: &str, zk: bool, vreps: usize, run: &str, fmt: &str, rcgate: bool) -> R<Row> {
    let p2r_fmt = fmt == "p2r";
    let o = apply_preset(preset)?;
    let wall = Instant::now();
    let seed = DEFAULT_SEED;
    let records = r#gen(n, n / 100, layout, seed);
    let refv = reference(&records);
    let keys = EpochKeys::from_seed(seed);
    let (_formula, _t) = predicate_formula(&keys);
    let mut lc = ledger_setup(seed);
    // prepare (not a per-query number): log with tags and Bloom filters, R_RC statement from the native sponge, ledger anchor
    let t = Instant::now();
    let log = build_log(&records, &keys);
    let prep_log_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    // old: R_RC statement over the one-record-per-word stream. p2r: the PACKED R_RC statement, ONE pchunk chunk with all blocks (honest publics + lists)
    let (rc_stmt, rc_p_pubs, rc_p_lists, rc_p_words) = if p2r_fmt {
        let (pubs, lists, packed) = p2r::rc_statement(&log.wl);
        if pubs.len() != 1 {
            return Err(Fail(6, "p2r R_RC: expected one chunk for the whole stream".into()));
        }
        (None, pubs, lists, packed)
    } else {
        let words_all = c1::words(&log.wl);
        (Some(pqz_p3::rel::plain::rc_public(&words_all, BLOCK)), Vec::new(), Vec::new(), Vec::new())
    };
    let (_led, omega) = commit_epoch(&mut lc, log.r_e, n as u64, (n / BLOCK) as u64).map_err(|e| Fail(e.code, e.msg))?;
    let prep_stmt_s = t.elapsed().as_secs_f64();
    // untimed R_RC gate (rcgate=1): prove and verify the packed RC chunk once with the library options; never in a per-query number
    let mut rcgate_res: Option<(bool, usize, f64)> = None;
    if p2r_fmt && rcgate {
        let t = Instant::now();
        let pr = pqz_p3::pchunk::plain::prove_chunk(&opts(), &rc_p_words, &rc_p_pubs[0]).map_err(|e| Fail(4, format!("R_RC (p2r) prove failed: {e}")))?;
        let bytes = c1::to_bytes(&pr);
        let ps = t.elapsed().as_secs_f64();
        let ok = pqz_p3::pchunk::plain::verify_chunk(&opts(), &pr, &rc_p_pubs[0]).is_ok();
        if !ok {
            return Err(Fail(5, "R_RC (p2r) verifier rejected the honest chunk".into()));
        }
        rcgate_res = Some((ok, bytes.len(), ps));
    }
    drop(rc_p_words);
    sys::reset_hwm();
    // per request: R_Auth (separate)
    let t = Instant::now();
    let (auth, auth_st) = auth_stage(&omega, 1, "P1: A = x", seed).map_err(|e| Fail(e.code, e.msg))?;
    let auth_s = t.elapsed().as_secs_f64();
    let ctx = exec_context(&c1::perm(), auth.stmt.b_q, auth.stmt.d_q, RID);
    // per query: claim = plain scan of the words (count, sum of b over words with v >= theta, slot 7 == 0)
    let t = Instant::now();
    let mut claim = (0u64, 0u64);
    for w in &log.wl.words {
        if w[7] == 0 && w[4] >= THETA {
            claim.0 += 1;
            claim.1 += w[5];
        }
    }
    let claim_s = t.elapsed().as_secs_f64();
    let (stmt_count, stmt_sum, bytes_len, pub_s, trace_s, prove_s, rows, peak_prove_kb);
    let mut tot = Vec::new();
    let mut ex = Vec::new();
    let mut nat = Vec::new();
    let mut au = Vec::new();
    if p2r_fmt {
        let ob = p2r::opts_b(preset).map_err(|e| Fail(2, e))?;
        let pr = p2r::prove_exec(&ob, &log.wl, ctx, zk).map_err(|e| Fail(4, format!("R_Exec (p2r) prove failed: {e}")))?;
        let (stmt, bytes, a1, a2, a3, a4) = pr;
        (stmt_count, stmt_sum, bytes_len, pub_s, trace_s, prove_s, rows) = (stmt.count, stmt.sum[0], bytes.len(), a1, a2, a3, a4);
        peak_prove_kb = sys::status_kb("VmHWM:");
        for _ in 0..vreps.max(1) {
            let t = Instant::now();
            p2r::native_checks(&auth.stmt, &stmt, &rc_p_pubs, &rc_p_lists).map_err(|e| Fail(5, format!("requester native check rejected: {e}")))?;
            let n_s = t.elapsed().as_secs_f64();
            let t1 = Instant::now();
            verify_auth_stage(&auth).map_err(|e| Fail(e.code, e.msg))?;
            let a_s = t1.elapsed().as_secs_f64();
            let t2 = Instant::now();
            p2r::verify_exec(&ob, &bytes, &stmt, zk).map_err(|e| Fail(5, format!("R_Exec (p2r) verifier rejected: {e}")))?;
            let e_s = t2.elapsed().as_secs_f64();
            tot.push(t.elapsed().as_secs_f64() * 1e3);
            nat.push(n_s * 1e3);
            au.push(a_s * 1e3);
            ex.push(e_s * 1e3);
        }
    } else {
        let pr = if zk { pm_zk::prove_exec(&o, &log.wl, ctx, claim) } else { pm_plain::prove_exec(&o, &log.wl, ctx, claim) };
        let (stmt, bytes, a1, a2, a3, a4) = pr.map_err(|e| Fail(4, format!("R_Exec prove failed: {e}")))?;
        (stmt_count, stmt_sum, bytes_len, pub_s, trace_s, prove_s, rows) = (stmt.count, stmt.sum[0], bytes.len(), a1, a2, a3, a4);
        peak_prove_kb = sys::status_kb("VmHWM:");
        for _ in 0..vreps.max(1) {
            let t = Instant::now();
            requester_native_checks(&auth.stmt, &stmt, rc_stmt.as_ref().expect("old rc stmt")).map_err(|e| Fail(5, format!("requester native check rejected: {e}")))?;
            let n_s = t.elapsed().as_secs_f64();
            let t1 = Instant::now();
            verify_auth_stage(&auth).map_err(|e| Fail(e.code, e.msg))?;
            let a_s = t1.elapsed().as_secs_f64();
            let t2 = Instant::now();
            let vr = if zk { pm_zk::verify_exec(&o, &bytes, &stmt) } else { pm_plain::verify_exec(&o, &bytes, &stmt) };
            vr.map_err(|e| Fail(5, format!("R_Exec verifier rejected: {e}")))?;
            let e_s = t2.elapsed().as_secs_f64();
            tot.push(t.elapsed().as_secs_f64() * 1e3);
            nat.push(n_s * 1e3);
            au.push(a_s * 1e3);
            ex.push(e_s * 1e3);
        }
    }
    let result = (stmt_count, stmt_sum);
    if result != refv {
        return Err(Fail(6, format!("gate: result {result:?} != plain reference {refv:?}")));
    }
    let mut r = Row::new();
    common(&mut r, "whole", n, layout_s, preset, zk, run, &o);
    set(&mut r, "result_count", result.0);
    set(&mut r, "result_sum", result.1);
    set(&mut r, "ref_count", refv.0);
    set(&mut r, "ref_sum", refv.1);
    set(&mut r, "retained_blocks", n / BLOCK);
    set(&mut r, "blocks_total", n / BLOCK);
    set(&mut r, "runs", 1);
    setf(&mut r, "openings_s", 0.0);
    setf(&mut r, "bps_s", 0.0);
    setf(&mut r, "plan_s", 0.0);
    setf(&mut r, "claim_s", claim_s);
    setf(&mut r, "exec_pub_s", pub_s);
    setf(&mut r, "exec_trace_s", trace_s);
    setf(&mut r, "exec_prove_s", prove_s);
    set(&mut r, "exec_rows", rows);
    set(&mut r, "fmt", if p2r_fmt { "p2r" } else { "old" });
    set(&mut r, "rcgate", rcgate as u8);
    if let Some((ok, by, ps)) = rcgate_res {
        set(&mut r, "rcgate_ok", ok as u8);
        set(&mut r, "rcgate_bytes", by);
        setf(&mut r, "rcgate_prove_s", ps);
    }
    setf(&mut r, "auth_s", auth_s);
    set(&mut r, "auth_rows", auth_st.rows);
    // headline per-query prove time: everything the prover does for the query except the R_Auth proof; `prove_incl_auth_s` adds it
    let q = claim_s + pub_s + trace_s + prove_s;
    setf(&mut r, "prove_s", q);
    setf(&mut r, "prove_incl_auth_s", q + auth_s);
    set(&mut r, "bytes_exec", bytes_len);
    set(&mut r, "bytes_auth", auth.bytes.len());
    set(&mut r, "bytes_requester", bytes_len + auth.bytes.len());
    set(&mut r, "vreps", tot.len());
    setf(&mut r, "verify_ms_med", med(&mut tot.clone()));
    setf(&mut r, "verify_ms_min", tot.iter().cloned().fold(f64::MAX, f64::min));
    setf(&mut r, "verify_ms_p90", pct(&mut tot.clone(), 0.9));
    setf(&mut r, "verify_native_ms_med", med(&mut nat));
    setf(&mut r, "verify_auth_ms_med", med(&mut au));
    setf(&mut r, "verify_exec_ms_med", med(&mut ex));
    setf(&mut r, "ingest_log_s", prep_log_s);
    setf(&mut r, "ingest_stmt_ledger_s", prep_stmt_s);
    set(&mut r, "peak_rss_prove_kb", peak_prove_kb);
    set(&mut r, "peak_rss_process_kb", sys::status_kb("VmHWM:"));
    setf(&mut r, "wall_s", wall.elapsed().as_secs_f64());
    set(&mut r, "loadavg1_end", sys::loadavg1());
    set(&mut r, "status", "ok");
    Ok(r)
}

// ------------------------------------------------------------------------------------------------------------------------------------
// COVER
// ------------------------------------------------------------------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn cover(n: usize, layout_s: &str, layout: Layout, preset: &str, zk: bool, vreps: usize, chunk: usize, gap: usize, run: &str, fmt: &str) -> R<Row> {
    let wf = WFmt::parse(fmt).ok_or_else(|| Fail(2, format!("unknown fmt {fmt}")))?;
    let o = apply_preset(preset)?;
    let wall = Instant::now();
    let seed = DEFAULT_SEED;
    let g_blocks = n / BLOCK;
    let records = r#gen(n, n / 100, layout, seed);
    let refv = reference(&records);
    let keys = EpochKeys::from_seed(seed);
    let (formula, _t) = predicate_formula(&keys);
    let mut lc = ledger_setup(seed);

    // ---------------- ingest (separate; never in a per-query number) ----------------
    let t = Instant::now();
    let log = build_log(&records, &keys);
    let ing_log_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let w = World35::prepare_fmt(log, chunk, wf);
    let ing_prepare_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let (proofs, rc_st) = w.prove_chunks().map_err(|e| Fail(e.code, e.msg))?;
    let ing_chunk_prove_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let aa = aa_finalize_fmt(&proofs, &w.blocks, &w.material(), AaChecks::ON, wf).map_err(|e| Fail(5, e))?;
    let ing_aa_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let (_led, omega) = commit_epoch(&mut lc, aa.r_e, aa.n_e, aa.g_e).map_err(|e| Fail(e.code, e.msg))?;
    let ing_ledger_s = t.elapsed().as_secs_f64();
    let peak_ingest_kb = sys::status_kb("VmHWM:");
    let hwm_ok = sys::reset_hwm();

    // ---------------- per request: R_Auth (separate) ----------------
    let t = Instant::now();
    let (auth, auth_st) = auth_stage(&omega, 1, "P1: A = x", seed).map_err(|e| Fail(e.code, e.msg))?;
    let auth_s = t.elapsed().as_secs_f64();
    let ctx = exec_context(&c1::perm(), auth.stmt.b_q, auth.stmt.d_q, RID);

    // ---------------- per query, CSP side ----------------
    // BPS over the block summaries (the protected search without the exact RPS, which the cover protocol does not need: the run proofs give the result)
    let t = Instant::now();
    let flags: Vec<bool> = std::hint::black_box(w.log.blooms.iter().map(|b| pqz_eval::search::bps_eval(b, &formula)).collect());
    let bps_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let ranges = plan_runs(&flags, &w.plan, gap);
    let plan_s = t.elapsed().as_secs_f64();
    let mut covered = vec![false; w.g];
    for &(ca, cb) in &ranges {
        for b in w.plan[ca].first_block..w.plan[cb].first_block + w.plan[cb].n_blocks {
            covered[b] = true;
        }
    }
    let t = Instant::now();
    let openings = openings_for_blocks(&w.blooms, &formula, (0..w.g).filter(|&i| !covered[i]))
        .map_err(|e| Fail(6, format!("CSP cannot open zero bits for a block outside the runs: {e}")))?;
    let openings_s = t.elapsed().as_secs_f64();
    let retained = flags.iter().filter(|&&x| x).count();
    let blocks_proven = covered.iter().filter(|&&c| c).count();
    // run proofs
    let (mut pub_s, mut trace_s, mut prove_s, mut rows) = (0.0, 0.0, 0.0, 0usize);
    let mut runs: Vec<RunClaim> = Vec::new();
    for &(ca, cb) in &ranges {
        let first0 = w.plan[ca].first_block;
        let end0 = w.plan[cb].first_block + w.plan[cb].n_blocks;
        let words = w.block_words(first0, end0 - first0);
        let t = Instant::now();
        let stmt = if wf == WFmt::P2r {
            if zk {
                pqz_p3::prun::zk::honest_public(words, &w.pubs[ca].s_in, BLOCK, THETA, ctx)
            } else {
                pqz_p3::prun::plain::honest_public(words, &w.pubs[ca].s_in, BLOCK, THETA, ctx)
            }
        } else {
            pqz_p3::run::plain::honest_public(words, &w.pubs[ca].s_in, BLOCK, THETA, ctx)
        };
        pub_s += t.elapsed().as_secs_f64();
        let (bytes, tr, pr, rw) = prove_run_f(wf, zk, &o, words, &stmt).map_err(|e| Fail(4, format!("run {ca}..{cb} prove failed: {e}")))?;
        trace_s += tr;
        prove_s += pr;
        rows += rw;
        runs.push(RunClaim { first: first0 + 1, last: end0, stmt, proof: bytes });
    }
    let claim: (u64, u64) = (runs.iter().map(|r| r.stmt.count).sum(), runs.iter().map(|r| r.stmt.sum).sum());
    let n_openings: usize = openings.iter().map(|(_, v)| v.len()).sum();
    let resp = CspResponse { blocks: w.blocks.clone(), runs, openings, claim };
    let peak_prove_kb = sys::status_kb("VmHWM:");

    // ---------------- requester, vreps times ----------------
    let a_e = lc.chain.epoch(EPOCH).a.clone();
    let an = Anchor { r_e: a_e.r_e, n_e: a_e.n_e, g_e: a_e.g_e };
    let mut tot = Vec::new();
    let mut nat = Vec::new();
    let mut au = Vec::new();
    let mut rn = Vec::new();
    let mut result = (0u64, 0u64);
    for _ in 0..vreps.max(1) {
        let t = Instant::now();
        result = requester_native35_fmt(&an, &formula, &resp, ReqChecks::ON, wf).map_err(|e| Fail(5, format!("requester native check rejected: {e}")))?;
        for (k, r) in resp.runs.iter().enumerate() {
            check_ctx(&auth.stmt, &r.stmt.ctx, RID).map_err(|e| Fail(5, format!("run {k}: {e}")))?;
            if r.stmt.theta != THETA {
                return Err(Fail(5, format!("run {k}: theta {} != requested {THETA}", r.stmt.theta)));
            }
        }
        check_scope(&auth.stmt).map_err(|e| Fail(5, format!("requester native check rejected: {e}")))?;
        let n_s = t.elapsed().as_secs_f64();
        let t1 = Instant::now();
        verify_auth_stage(&auth).map_err(|e| Fail(e.code, e.msg))?;
        let a_s = t1.elapsed().as_secs_f64();
        let t2 = Instant::now();
        for (k, r) in resp.runs.iter().enumerate() {
            verify_run_f(wf, zk, &o, &r.proof, &r.stmt).map_err(|e| Fail(5, format!("run {k}: R_Exec verifier rejected: {e}")))?;
        }
        let r_s = t2.elapsed().as_secs_f64();
        tot.push(t.elapsed().as_secs_f64() * 1e3);
        nat.push(n_s * 1e3);
        au.push(a_s * 1e3);
        rn.push(r_s * 1e3);
    }
    // gates (outside every timer)
    if result != refv {
        return Err(Fail(6, format!("gate: requester result {result:?} != plain reference {refv:?}")));
    }
    if !zk && preset == "std" {
        // the library requester (w35 `verify_requester35`) must accept the same response and give the same result
        let (_tm, res2) = verify_requester35_fmt(&an, &formula, &auth, &resp, ReqChecks::ON, wf).map_err(|e| Fail(e.code, e.msg))?;
        if res2 != result {
            return Err(Fail(6, format!("gate: library requester result {res2:?} != harness requester result {result:?}")));
        }
    }
    let so = search(&w.log, &formula);
    if !so.sel.iter().all(|id| covered[*id as usize / BLOCK]) {
        return Err(Fail(6, "gate: a selected record lies in a block outside the runs".to_string()));
    }
    let bytes_req = requester_bytes(&resp, &auth);

    let mut r = Row::new();
    common(&mut r, "cover", n, layout_s, preset, zk, run, &o);
    set(&mut r, "fmt", wf.name());
    set(&mut r, "chunk", chunk);
    set(&mut r, "gap_merge", gap);
    set(&mut r, "result_count", result.0);
    set(&mut r, "result_sum", result.1);
    set(&mut r, "ref_count", refv.0);
    set(&mut r, "ref_sum", refv.1);
    set(&mut r, "retained_blocks", retained);
    set(&mut r, "blocks_proven", blocks_proven);
    set(&mut r, "blocks_total", g_blocks);
    set(&mut r, "runs", ranges.len());
    set(&mut r, "n_openings", n_openings);
    setf(&mut r, "bps_s", bps_s);
    setf(&mut r, "plan_s", plan_s);
    setf(&mut r, "openings_s", openings_s);
    setf(&mut r, "claim_s", 0.0);
    setf(&mut r, "exec_pub_s", pub_s);
    setf(&mut r, "exec_trace_s", trace_s);
    setf(&mut r, "exec_prove_s", prove_s);
    set(&mut r, "exec_rows", rows);
    setf(&mut r, "auth_s", auth_s);
    set(&mut r, "auth_rows", auth_st.rows);
    let q = bps_s + plan_s + openings_s + pub_s + trace_s + prove_s;
    setf(&mut r, "prove_s", q);
    setf(&mut r, "prove_incl_auth_s", q + auth_s);
    set(&mut r, "bytes_exec", resp.runs_bytes());
    set(&mut r, "bytes_openings", resp.openings_bytes());
    set(&mut r, "bytes_blocklist", resp.block_list_bytes());
    set(&mut r, "bytes_auth", auth.bytes.len());
    set(&mut r, "bytes_requester", bytes_req);
    set(&mut r, "vreps", tot.len());
    setf(&mut r, "verify_ms_med", med(&mut tot.clone()));
    setf(&mut r, "verify_ms_min", tot.iter().cloned().fold(f64::MAX, f64::min));
    setf(&mut r, "verify_ms_p90", pct(&mut tot.clone(), 0.9));
    setf(&mut r, "verify_native_ms_med", med(&mut nat));
    setf(&mut r, "verify_auth_ms_med", med(&mut au));
    setf(&mut r, "verify_exec_ms_med", med(&mut rn));
    setf(&mut r, "ingest_log_s", ing_log_s);
    setf(&mut r, "ingest_prepare_s", ing_prepare_s);
    setf(&mut r, "ingest_chunk_prove_s", ing_chunk_prove_s);
    setf(&mut r, "ingest_aa_s", ing_aa_s);
    setf(&mut r, "ingest_ledger_s", ing_ledger_s);
    setf(&mut r, "ingest_total_s", ing_log_s + ing_prepare_s + ing_chunk_prove_s + ing_aa_s + ing_ledger_s);
    set(&mut r, "ingest_chunk_proof_bytes", rc_st.bytes);
    set(&mut r, "peak_rss_ingest_kb", peak_ingest_kb);
    set(&mut r, "peak_rss_prove_kb", peak_prove_kb);
    set(&mut r, "peak_rss_process_kb", sys::status_kb("VmHWM:").max(peak_ingest_kb));
    set(&mut r, "hwm_reset_ok", hwm_ok as u8);
    setf(&mut r, "wall_s", wall.elapsed().as_secs_f64());
    set(&mut r, "loadavg1_end", sys::loadavg1());
    set(&mut r, "status", "ok");
    Ok(r)
}

// ------------------------------------------------------------------------------------------------------------------------------------
// export
// ------------------------------------------------------------------------------------------------------------------------------------

fn export(n: usize, layout_s: &str, layout: Layout, out: &str) -> R<()> {
    if n == 0 || n % BLOCK != 0 {
        return Err(Fail(2, format!("N = {n} must be a positive multiple of {BLOCK}")));
    }
    fs::create_dir_all(out).map_err(f(2))?;
    let records = r#gen(n, n / 100, layout, DEFAULT_SEED);
    let refv = reference(&records);
    let path = format!("{out}/auditlog_n{n}_{layout_s}.csv");
    let mut w = std::io::BufWriter::new(fs::File::create(&path).map_err(f(2))?);
    // columns: id, a (the attribute of P1), v (what the R_Exec circuit tests: THETA if a == 7 else 0, the same function as `pqz_int::v_of`), b (what R_Exec sums)
    for r in &records {
        writeln!(w, "{},{},{},{}", r.id, r.a, pqz_int::v_of(r), r.b).map_err(f(2))?;
    }
    w.flush().map_err(f(2))?;
    let line = format!("{n} {layout_s} {} {} {} {}\n", refv.0, refv.1, n / 100, THETA);
    let mut ref_all = fs::OpenOptions::new().create(true).append(true).open(format!("{out}/reference.tsv")).map_err(f(2))?;
    ref_all.write_all(line.as_bytes()).map_err(f(2))?;
    println!("EXPORT n={n} layout={layout_s} count={} sum_b={} sigma={} theta={THETA} file={path}", refv.0, refv.1, n / 100);
    Ok(())
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let cmd = a.first().cloned().unwrap_or_default();
    let code = match cmd.as_str() {
        "export" => {
            let (Some(n), Some(l), Some(out)) = (a.get(1).and_then(|x| x.parse::<usize>().ok()), a.get(2), a.get(3)) else {
                eprintln!("usage: export <n> <clustered|scattered> <outdir>");
                std::process::exit(2);
            };
            let Some(layout) = layout_of(l) else {
                eprintln!("unknown layout");
                std::process::exit(2);
            };
            match export(n, l, layout, out) {
                Ok(()) => 0,
                Err(Fail(c, m)) => {
                    eprintln!("export failed: {m}");
                    c
                }
            }
        }
        "child" => {
            let rest = &a[2.min(a.len())..];
            let mode = a.get(1).cloned().unwrap_or_default();
            let n = arg(rest, "n").and_then(|x| x.parse::<usize>().ok()).unwrap_or(0);
            let layout_s = arg(rest, "layout").unwrap_or_default();
            let preset = arg(rest, "preset").unwrap_or_else(|| "std".into());
            let zk = arg(rest, "zk").map(|x| x == "1").unwrap_or(false);
            let vreps = arg(rest, "vreps").and_then(|x| x.parse().ok()).unwrap_or(25usize);
            let chunk = arg(rest, "chunk").and_then(|x| x.parse().ok()).unwrap_or(4usize);
            let gap = arg(rest, "gap").and_then(|x| x.parse().ok()).unwrap_or(1usize);
            let run = arg(rest, "run").unwrap_or_else(|| "0".into());
            let fmt = arg(rest, "fmt").unwrap_or_else(|| "old".into());
            if fmt != "old" && fmt != "p2r" {
                eprintln!("fmt must be old or p2r");
                std::process::exit(2);
            }
            let rcgate = arg(rest, "rcgate").map(|x| x == "1").unwrap_or(false);
            let Some(layout) = layout_of(&layout_s) else {
                eprintln!("child needs layout=clustered|scattered");
                std::process::exit(2);
            };
            if n == 0 || n % BLOCK != 0 || chunk == 0 {
                eprintln!("n must be a positive multiple of {BLOCK}; chunk >= 1");
                std::process::exit(2);
            }
            let res = match mode.as_str() {
                "whole" => whole(n, &layout_s, layout, &preset, zk, vreps, &run, &fmt, rcgate),
                "cover" => cover(n, &layout_s, layout, &preset, zk, vreps, chunk, gap, &run, &fmt),
                _ => Err(Fail(2, "mode must be whole or cover".into())),
            };
            match res {
                Ok(r) => {
                    print_row(&r);
                    0
                }
                Err(Fail(c, m)) => {
                    let mut r = Row::new();
                    set(&mut r, "exp", "exp9");
                    set(&mut r, "mode", &mode);
                    set(&mut r, "n", n);
                    set(&mut r, "layout", &layout_s);
                    set(&mut r, "preset", &preset);
                    set(&mut r, "zk", zk as u8);
                    set(&mut r, "run", &run);
                    set(&mut r, "rayon_threads_env", std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "unset".into()));
                    set(&mut r, "status", "FAILED");
                    set(&mut r, "code", c);
                    set(&mut r, "msg", m);
                    print_row(&r);
                    c
                }
            }
        }
        _ => {
            eprintln!("usage: pqz-exp9-w36 export <n> <layout> <outdir> | child whole|cover n=.. layout=.. preset=.. zk=0|1 [vreps= chunk= gap= run= fmt=old|p2r rcgate=0|1]");
            2
        }
    };
    std::process::exit(code);
}
