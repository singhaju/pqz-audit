//! proofbench: measures prove time, verify time, proof size and peak RSS of the three PROVISIONAL STARK relations.
//!
//! Driver:  proofbench smoke|full [--out DIR] [--threads N] [--only scale|q] [--sizes N1,N2,...] [--with-auth]
//!          --sizes replaces the N_Q points of rc and exec (multiples of 100, <= 1e5, ascending); the auth points are then skipped
//!          unless --with-auth is given. Without --sizes nothing changes.
//! Child:   proofbench child <kind> key=value ...      (one fresh process per measurement point, so that the
//!          peak RSS of a point is not polluted by earlier points; the driver collects the ROW lines).
//!
//! Run rule (per point): the first run is a probe. If it takes < 60 s: 3 warm-up runs (the probe is the first
//! one) then 30 timed runs ("30+3"). Otherwise: 5 runs in total, no warm-up (the cold probe is run 1) ("5").
//! `smoke` uses the quick rule (1 warm-up + 3 runs, tagged "quick") and is only for checking that things work.
//!
//! Exp 6 ablation: proofbench ablation --out DIR [--threads N] [--quick]  (see driver_ablation; child kind `ablation`).
//!
//! Safety stops of the driver: a point is killed if no row arrives for 600 s (a run over 10 min) or if the
//! machine's MemAvailable drops below 1.5 GiB (this machine is shared). Larger N_Q of the same relation are then
//! skipped and the event is written to failures.txt. N_Q above 1e5 is refused.

use pqz_proof::auth::{honest_auth_instance, build_auth_trace, AuthAir, AuthPublic};
use pqz_proof::data::Workload;
use pqz_proof::exec::{build_exec_trace, exec_public, ExecAir, ExecPublic};
use pqz_proof::prove::{default_options, prove_trace, security_of, verify_proof};
use pqz_proof::rc::{build_rc_trace, rc_public, RcAir, RcPublic};
use pqz_proof::rescue::F;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use winterfell::Proof;

const MIN_BITS: u32 = 80;
const BLOCK_SIZE: usize = 100;
const THETA: u64 = 1 << 31; // about half of the records match (v is uniform in [0, 2^32))
const MAX_NQ: usize = 100_000;
const Q_LIST: [usize; 6] = [1, 10, 25, 50, 100, 200];
const Q_LIST_QUICK: [usize; 3] = [1, 10, 25];
const AUTH_DEPTHS: [usize; 2] = [10, 20];
const Q_N: usize = 1000;
const Q_AUTH_DEPTH: usize = 10;
const WATCHDOG_S: u64 = 600;
// Exp 6 ablation ("w/o Batched RC"): blocks of 500 records, G blocks.
const ABL_BLOCK: usize = 500;
const ABL_G: [usize; 4] = [1, 4, 16, 64];
const ABL_G_QUICK: [usize; 2] = [1, 4];
const MIN_AVAIL_KB: u64 = 1_500_000;

const HEADER: &str = "experiment,rel,n_records,block_size,depth,q,mode,run,warmup,rule,trace_rows,trace_s,prove_s,verify_s,\
total_verify_s,proof_bytes,prove_peak_rss_kb,verify_rss_baseline_kb,verify_peak_rss_kb,conj_bits,udr_bits,ldr_bits,loadavg1,hwm_reset_ok";

// ------------------------------------------------------------------------------------------------
// /proc helpers
// ------------------------------------------------------------------------------------------------

fn status_kb(key: &str) -> u64 {
    let s = fs::read_to_string("/proc/self/status").unwrap_or_default();
    for l in s.lines() {
        if let Some(r) = l.strip_prefix(key) {
            return r.trim().trim_end_matches("kB").trim().parse().unwrap_or(0);
        }
    }
    0
}

fn reset_hwm() -> bool {
    fs::write("/proc/self/clear_refs", "5").is_ok()
}

fn loadavg1() -> String {
    fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(|x| x.to_string()))
        .unwrap_or_default()
}

fn mem_available_kb() -> u64 {
    let s = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    for l in s.lines() {
        if let Some(r) = l.strip_prefix("MemAvailable:") {
            return r.trim().trim_end_matches("kB").trim().parse().unwrap_or(0);
        }
    }
    0
}

// ------------------------------------------------------------------------------------------------
// One instance of a relation: prove and verify
// ------------------------------------------------------------------------------------------------

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
            Stmt::Rc(p) => verify_proof::<RcAir>(proof, p.clone(), MIN_BITS),
            Stmt::Exec(p) => verify_proof::<ExecAir>(proof, p.clone(), MIN_BITS),
            Stmt::Auth(p) => verify_proof::<AuthAir>(proof, p.clone(), MIN_BITS),
        }
    }
}

struct Made {
    stmt: Stmt,
    bytes: Vec<u8>,
    trace_rows: usize,
    trace_s: f64,
    prove_s: f64,
    conj: u32,
    udr: u32,
    ldr: u32,
}

/// Instance data prepared outside the timed region (workload generation and public-input computation).
enum Prepared {
    Rc(Workload, RcPublic),
    Exec(Workload, ExecPublic),
    Auth(AuthPublic, pqz_proof::auth::AuthWitness),
}

fn prepare(rel: &str, n: usize, depth: usize, seed: u64) -> Prepared {
    match rel {
        "rc" => {
            let w = Workload::synthetic(n, BLOCK_SIZE.min(n), seed);
            let p = rc_public(&w);
            Prepared::Rc(w, p)
        }
        "exec" => {
            let w = Workload::synthetic(n, BLOCK_SIZE.min(n), seed);
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

/// Builds the trace (timed as trace_s), proves (timed as prove_s). Consumes nothing: the trace is rebuilt per call.
fn prove_prepared(pr: &Prepared) -> Result<Made, String> {
    let opts = default_options();
    let t0 = Instant::now();
    let (trace, stmt) = match pr {
        Prepared::Rc(w, p) => (build_rc_trace(w), Stmt::Rc(p.clone())),
        Prepared::Exec(w, p) => (build_exec_trace(w, THETA), Stmt::Exec(p.clone())),
        Prepared::Auth(p, w) => (build_auth_trace(p, w), Stmt::Auth(p.clone())),
    };
    let trace_s = t0.elapsed().as_secs_f64();
    use winterfell::Trace;
    let trace_rows = trace.length();
    let t1 = Instant::now();
    let proof = match &stmt {
        Stmt::Rc(p) => prove_trace::<RcAir>(trace, p.clone(), opts)?,
        Stmt::Exec(p) => prove_trace::<ExecAir>(trace, p.clone(), opts)?,
        Stmt::Auth(p) => prove_trace::<AuthAir>(trace, p.clone(), opts)?,
    };
    let prove_s = t1.elapsed().as_secs_f64();
    let sec = security_of(&proof);
    let bytes = proof.to_bytes();
    Ok(Made {
        stmt,
        bytes,
        trace_rows,
        trace_s,
        prove_s,
        conj: sec.conjectured_bits,
        udr: sec.proven_unique_decoding_bits,
        ldr: sec.proven_list_decoding_bits,
    })
}

// ------------------------------------------------------------------------------------------------
// Row output and run rule
// ------------------------------------------------------------------------------------------------

#[derive(Default, Clone)]
struct Row {
    experiment: String,
    rel: String,
    n_records: String,
    block_size: String,
    depth: String,
    q: String,
    mode: String,
    run: usize,
    warmup: bool,
    rule: String,
    trace_rows: String,
    trace_s: String,
    prove_s: String,
    verify_s: String,
    total_verify_s: String,
    proof_bytes: String,
    prove_peak_rss_kb: String,
    verify_rss_baseline_kb: String,
    verify_peak_rss_kb: String,
    conj: String,
    udr: String,
    ldr: String,
    hwm_ok: bool,
}

impl Row {
    fn line(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.experiment, self.rel, self.n_records, self.block_size, self.depth, self.q, self.mode,
            self.run, self.warmup as u8, self.rule, self.trace_rows, self.trace_s, self.prove_s,
            self.verify_s, self.total_verify_s, self.proof_bytes, self.prove_peak_rss_kb,
            self.verify_rss_baseline_kb, self.verify_peak_rss_kb, self.conj, self.udr, self.ldr,
            loadavg1(), self.hwm_ok as u8
        )
    }
}

fn emit(r: &Row) {
    println!("ROW,{}", r.line());
    let _ = std::io::stdout().flush();
}

struct Rule {
    quick: bool,
}

/// `once(run_index, warmup_flag, rule_label) -> (Row, run_seconds)`. Applies the run rule and emits all rows.
fn apply_rule<G: FnMut(&str) -> (Row, f64)>(rule: &Rule, mut once: G) {
    // probe run = warm-up 1 (or run 1 of the slow rule)
    let (mut row, secs) = once("probe");
    let slow = secs >= 60.0;
    if rule.quick {
        row.rule = "quick(1 warmup+3)".into();
        row.warmup = true;
        row.run = 0;
        emit(&row);
        for i in 1..=3 {
            let (mut r, _) = once("quick");
            r.rule = "quick(1 warmup+3)".into();
            r.run = i;
            r.warmup = false;
            emit(&r);
        }
        return;
    }
    if slow {
        row.rule = "5 runs (first run >= 60 s; no warm-up, cold first run counted)".into();
        row.warmup = false;
        row.run = 1;
        emit(&row);
        for i in 2..=5 {
            let (mut r, _) = once("slow");
            r.rule = "5 runs (first run >= 60 s; no warm-up, cold first run counted)".into();
            r.run = i;
            r.warmup = false;
            emit(&r);
        }
    } else {
        let label = "30 runs + 3 warm-up (first run < 60 s)";
        row.rule = label.into();
        row.warmup = true;
        row.run = 0;
        emit(&row);
        for i in 1..3 {
            let (mut r, _) = once("warm");
            r.rule = label.into();
            r.warmup = true;
            r.run = i;
            emit(&r);
        }
        for i in 1..=30 {
            let (mut r, _) = once("run");
            r.rule = label.into();
            r.run = i;
            r.warmup = false;
            emit(&r);
        }
    }
}

// ------------------------------------------------------------------------------------------------
// Child kinds
// ------------------------------------------------------------------------------------------------

fn arg(args: &[String], key: &str) -> Option<String> {
    args.iter().find_map(|a| a.strip_prefix(&format!("{key}=")).map(|s| s.to_string()))
}

fn child_scale(args: &[String]) {
    let rel = arg(args, "rel").unwrap();
    let n: usize = arg(args, "n").map(|s| s.parse().unwrap()).unwrap_or(0);
    let depth: usize = arg(args, "depth").map(|s| s.parse().unwrap()).unwrap_or(0);
    let quick = arg(args, "quick").is_some();
    if rel != "auth" {
        assert!(n <= MAX_NQ, "N_Q above 1e5 is not allowed");
    }
    let pr = prepare(&rel, n, depth, 1);
    let rule = Rule { quick };
    apply_rule(&rule, |_| {
        let hwm_ok = reset_hwm();
        let made = match prove_prepared(&pr) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("prove failed: {e}");
                std::process::exit(4);
            }
        };
        let prove_rss = status_kb("VmHWM:");
        let base = status_kb("VmRSS:");
        reset_hwm();
        let t = Instant::now();
        made.stmt.verify_bytes(&made.bytes).expect("honest proof must verify");
        let verify_s = t.elapsed().as_secs_f64();
        let vrss = status_kb("VmHWM:");
        let row = Row {
            experiment: "scale".into(),
            rel: rel.clone(),
            n_records: if rel == "auth" { String::new() } else { n.to_string() },
            block_size: if rel == "auth" { String::new() } else { BLOCK_SIZE.min(n).to_string() },
            depth: if rel == "auth" { depth.to_string() } else { String::new() },
            trace_rows: made.trace_rows.to_string(),
            trace_s: format!("{:.6}", made.trace_s),
            prove_s: format!("{:.6}", made.prove_s),
            verify_s: format!("{:.6}", verify_s),
            proof_bytes: made.bytes.len().to_string(),
            prove_peak_rss_kb: prove_rss.to_string(),
            verify_rss_baseline_kb: base.to_string(),
            verify_peak_rss_kb: vrss.to_string(),
            conj: made.conj.to_string(),
            udr: made.udr.to_string(),
            ldr: made.ldr.to_string(),
            hwm_ok,
            ..Default::default()
        };
        let secs = made.trace_s + made.prove_s + verify_s;
        (row, secs)
    });
}

/// q-verification experiments at fixed size. Same proof q times, and q distinct proofs.
/// rel in rc | auth | exec | bundle (bundle = one query verifies the rc, auth and exec proofs together).
fn child_q(args: &[String]) {
    let rel = arg(args, "rel").unwrap();
    let mode = arg(args, "mode").unwrap(); // same | distinct
    let quick = arg(args, "quick").is_some();
    let qs: Vec<usize> = if quick { Q_LIST_QUICK.to_vec() } else { Q_LIST.to_vec() };
    let qmax = *qs.iter().max().unwrap();
    let rels: Vec<&str> = if rel == "bundle" { vec!["rc", "auth", "exec"] } else { vec![rel.as_str()] };
    let n_instances = if mode == "same" { 1 } else { qmax };
    // instances[i][j] = (statement, proof bytes) of relation j for query i
    let mut inst: Vec<Vec<(Stmt, Vec<u8>)>> = Vec::new();
    for i in 0..n_instances {
        let mut one = Vec::new();
        for r in &rels {
            let pr = prepare(r, Q_N, Q_AUTH_DEPTH, 1000 + i as u64);
            let m = prove_prepared(&pr).expect("prove");
            one.push((m.stmt, m.bytes));
        }
        inst.push(one);
    }
    let proof_bytes: usize = inst[0].iter().map(|x| x.1.len()).sum();
    eprintln!("q-experiment {rel}/{mode}: {} instance(s) ready, bundle bytes {proof_bytes}", inst.len());
    for &q in &qs {
        let rule = Rule { quick };
        apply_rule(&rule, |_| {
            let hwm_ok = reset_hwm();
            let base = status_kb("VmRSS:");
            let t = Instant::now();
            for k in 0..q {
                let one = if mode == "same" { &inst[0] } else { &inst[k] };
                for (stmt, bytes) in one {
                    stmt.verify_bytes(bytes).expect("honest proof must verify");
                }
            }
            let total = t.elapsed().as_secs_f64();
            let vrss = status_kb("VmHWM:");
            let row = Row {
                experiment: "q".into(),
                rel: rel.clone(),
                n_records: if rel == "auth" { String::new() } else { Q_N.to_string() },
                block_size: if rel == "auth" { String::new() } else { BLOCK_SIZE.min(Q_N).to_string() },
                depth: if rel == "rc" || rel == "exec" { String::new() } else { Q_AUTH_DEPTH.to_string() },
                q: q.to_string(),
                mode: mode.clone(),
                verify_s: format!("{:.6}", total / q as f64),
                total_verify_s: format!("{:.6}", total),
                proof_bytes: proof_bytes.to_string(),
                verify_rss_baseline_kb: base.to_string(),
                verify_peak_rss_kb: vrss.to_string(),
                hwm_ok,
                ..Default::default()
            };
            (row, total)
        });
    }
}

// ------------------------------------------------------------------------------------------------
// Exp 6 ablation: one batched R_RC proof over G*500 records versus G separate R_RC proofs of 500 records
// ------------------------------------------------------------------------------------------------

fn prepare_rc(n: usize, block: usize, seed: u64) -> Prepared {
    let w = Workload::synthetic(n, block, seed);
    let p = rc_public(&w);
    Prepared::Rc(w, p)
}

/// Run rule of the ablation: quick = 1 warm-up + 2 runs; otherwise 3 warm-up + 30 timed runs (fixed, no probe rule).
fn apply_rule_abl<G: FnMut() -> (Row, f64)>(quick: bool, g_blocks: usize, mut once: G) {
    let (n_warm, n_run, label) = if quick {
        (1usize, 2usize, "ablation quick(1 warmup+2)")
    } else {
        (3usize, 30usize, "30 runs + 3 warm-up")
    };
    for i in 0..n_warm {
        let (mut r, _) = once();
        r.rule = label.into();
        r.warmup = true;
        r.run = i;
        emit_abl(&r, g_blocks);
    }
    for i in 1..=n_run {
        let (mut r, _) = once();
        r.rule = label.into();
        r.warmup = false;
        r.run = i;
        emit_abl(&r, g_blocks);
    }
}

fn emit_abl(r: &Row, g_blocks: usize) {
    println!("ROW,{},{}", r.line(), g_blocks);
    let _ = std::io::stdout().flush();
}

/// Child of the ablation. series=batched: ONE proof over g*500 records (g blocks). series=per_block: g proofs, each over one
/// block of 500 records, proved and verified one after the other in this process. Times, sizes and trace rows are sums over the
/// g proofs. Every proof must verify; otherwise the child exits with code 5 and the driver writes failures.txt.
fn child_ablation(args: &[String]) {
    let series = arg(args, "series").unwrap();
    let g: usize = arg(args, "g").unwrap().parse().unwrap();
    let quick = arg(args, "quick").is_some();
    assert!(series == "batched" || series == "per_block", "series must be batched or per_block");
    assert!((1..=64).contains(&g), "G must be in 1..=64");
    let preps: Vec<Prepared> = if series == "batched" {
        vec![prepare_rc(g * ABL_BLOCK, ABL_BLOCK, 1)]
    } else {
        (0..g).map(|i| prepare_rc(ABL_BLOCK, ABL_BLOCK, 1 + i as u64)).collect()
    };
    apply_rule_abl(quick, g, || {
        let hwm_ok = reset_hwm();
        let mut mades: Vec<Made> = Vec::with_capacity(preps.len());
        for pr in &preps {
            match prove_prepared(pr) {
                Ok(m) => mades.push(m),
                Err(e) => {
                    eprintln!("prove failed: {e}");
                    std::process::exit(4);
                }
            }
        }
        let prove_rss = status_kb("VmHWM:");
        let base = status_kb("VmRSS:");
        reset_hwm();
        let t = Instant::now();
        for m in &mades {
            if let Err(e) = m.stmt.verify_bytes(&m.bytes) {
                eprintln!("verify failed ({series}, G={g}): {e}");
                std::process::exit(5);
            }
        }
        let verify_s = t.elapsed().as_secs_f64();
        let vrss = status_kb("VmHWM:");
        let trace_s: f64 = mades.iter().map(|m| m.trace_s).sum();
        let prove_s: f64 = mades.iter().map(|m| m.prove_s).sum();
        let bytes: usize = mades.iter().map(|m| m.bytes.len()).sum();
        let rows: usize = mades.iter().map(|m| m.trace_rows).sum();
        let row = Row {
            experiment: "ablation".into(),
            rel: "rc".into(),
            n_records: (g * ABL_BLOCK).to_string(),
            block_size: ABL_BLOCK.to_string(),
            mode: series.clone(),
            trace_rows: rows.to_string(),
            trace_s: format!("{:.6}", trace_s),
            prove_s: format!("{:.6}", prove_s),
            verify_s: format!("{:.6}", verify_s),
            proof_bytes: bytes.to_string(),
            prove_peak_rss_kb: prove_rss.to_string(),
            verify_rss_baseline_kb: base.to_string(),
            verify_peak_rss_kb: vrss.to_string(),
            conj: mades[0].conj.to_string(),
            udr: mades[0].udr.to_string(),
            ldr: mades[0].ldr.to_string(),
            hwm_ok,
            ..Default::default()
        };
        (row, trace_s + prove_s + verify_s)
    });
}

// ------------------------------------------------------------------------------------------------
// Driver
// ------------------------------------------------------------------------------------------------

struct Driver {
    out: std::path::PathBuf,
    threads: Option<usize>,
    quick: bool,
    csv: File,
    failures: File,
}

#[allow(dead_code)]
enum PointResult {
    Ok,
    Failed(String),
}

impl Driver {
    fn run_point(&mut self, desc: &str, child_args: &[String]) -> PointResult {
        eprintln!("[driver] point: {desc}");
        let exe = std::env::current_exe().unwrap();
        let mut cmd = Command::new(exe);
        cmd.arg("child").args(child_args);
        if self.quick {
            cmd.arg("quick=1");
        }
        if let Some(t) = self.threads {
            cmd.env("RAYON_NUM_THREADS", t.to_string());
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
        let mut child = cmd.spawn().expect("spawn child");
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            for l in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        let mut last = Instant::now();
        let mut rows = 0usize;
        loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(l) => {
                    if let Some(r) = l.strip_prefix("ROW,") {
                        writeln!(self.csv, "{r}").unwrap();
                        self.csv.flush().unwrap();
                        rows += 1;
                        last = Instant::now();
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            if last.elapsed().as_secs() > WATCHDOG_S {
                let _ = child.kill();
                let _ = child.wait();
                return self.fail(desc, format!("no result for {WATCHDOG_S} s (a run exceeds 10 min); child killed after {rows} rows"));
            }
            let avail = mem_available_kb();
            if avail < MIN_AVAIL_KB {
                let _ = child.kill();
                let _ = child.wait();
                return self.fail(desc, format!("MemAvailable fell to {avail} kB (< {MIN_AVAIL_KB} kB guard); child killed after {rows} rows"));
            }
        }
        let st = child.wait().unwrap();
        if st.success() {
            PointResult::Ok
        } else {
            use std::os::unix::process::ExitStatusExt;
            self.fail(desc, format!("child exited abnormally: code {:?}, signal {:?} (signal 9 usually means out of memory); {rows} rows were written", st.code(), st.signal()))
        }
    }

    fn fail(&mut self, desc: &str, why: String) -> PointResult {
        let msg = format!("FAILED {desc}: {why}");
        eprintln!("[driver] {msg}");
        writeln!(self.failures, "{msg}").unwrap();
        PointResult::Failed(why)
    }
}

fn cmd_out(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unavailable".into())
}

fn write_env(out: &std::path::Path, threads: Option<usize>, mode: &str) {
    let cpu = fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("model name"))
        .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
        .unwrap_or_default();
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0);
    let memtotal = fs::read_to_string("/proc/meminfo")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("MemTotal"))
        .unwrap_or("")
        .to_string();
    let lock = cmd_out("sha256sum", &["Cargo.lock"]);
    let s = format!(
        "mode: {mode}\ncpu: {cpu}\nlogical_cores: {cores}\n{memtotal}\nkernel: {}\nrustc: {}\ncargo: {}\n\
Cargo.lock sha256: {}\nwinterfell: 0.13.1 (pinned =0.13.1)\nconcurrent feature: {}\nthreads: {}\n\
loadavg at start: {}\nMemAvailable at start (kB): {}\nproof options: {:?}\nhash for commitments: Sha3_256 (winterfell DefaultRandomCoin, MerkleTree)\n\
in-circuit hash: Rescue Prime Rp64_256 (algebraic; see DESIGN.md)\nblock size: {BLOCK_SIZE}\ntheta: {THETA}\n\
min_bits accepted by the verifier (library conjectured estimate): {MIN_BITS}\n",
        cmd_out("uname", &["-sr"]),
        cmd_out("rustc", &["--version"]),
        cmd_out("cargo", &["--version"]),
        lock,
        cfg!(feature = "concurrent"),
        threads.map(|t| t.to_string()).unwrap_or_else(|| "rayon default (all logical cores)".into()),
        fs::read_to_string("/proc/loadavg").unwrap_or_default().trim(),
        mem_available_kb(),
        default_options(),
    );
    fs::write(out.join("env.txt"), s).unwrap();
}

const USAGE: &str = "usage: proofbench smoke|full [--out DIR] [--threads N] [--only scale|q] [--sizes N1,N2,...] [--with-auth] | ablation [--out DIR] [--threads N] [--quick]\n\
  --sizes LIST   (smoke|full) replaces the N_Q points of R_RC and R_Exec (default: full 1000,10000,100000; smoke 1000,10000). Each size must be a\n\
                 multiple of the block size (100), at most 100000, strictly ascending. With --sizes the R_Auth depth points are skipped unless --with-auth is given.";

/// Parses `--sizes`: comma separated, each a positive multiple of BLOCK_SIZE, <= MAX_NQ, strictly ascending (the driver stops the larger
/// N_Q of a relation after a failed point, so the order must be ascending).
fn parse_sizes(s: &str) -> Result<Vec<usize>, String> {
    let mut v: Vec<usize> = Vec::new();
    for t in s.split(',') {
        let t = t.trim();
        let n: usize = t.parse().map_err(|_| format!("--sizes: '{t}' is not a non-negative integer"))?;
        if n == 0 || n % BLOCK_SIZE != 0 {
            return Err(format!("--sizes: {n} is not a positive multiple of the block size {BLOCK_SIZE}"));
        }
        if n > MAX_NQ {
            return Err(format!("--sizes: {n} is above the maximum N_Q {MAX_NQ}"));
        }
        if let Some(&last) = v.last() {
            if n <= last {
                return Err(format!("--sizes: the list must be strictly ascending ({n} follows {last})"));
            }
        }
        v.push(n);
    }
    Ok(v)
}

fn usage_exit(why: &str) -> ! {
    eprintln!("error: {why}\n{USAGE}");
    std::process::exit(2);
}

fn driver(mode: &str, rest: &[String]) {
    let quick = mode == "smoke";
    let mut out: Option<std::path::PathBuf> = None;
    let mut threads: Option<usize> = None;
    let mut only: Option<String> = None;
    let mut sizes_arg: Option<Vec<usize>> = None;
    let mut with_auth = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--out" => {
                out = Some(rest[i + 1].clone().into());
                i += 1;
            }
            "--threads" => {
                threads = Some(rest[i + 1].parse().unwrap());
                i += 1;
            }
            "--only" => {
                only = Some(rest[i + 1].clone());
                i += 1;
            }
            "--sizes" => {
                let Some(v) = rest.get(i + 1) else { usage_exit("--sizes needs a value, e.g. --sizes 1000,2000,5000") };
                match parse_sizes(v) {
                    Ok(s) => sizes_arg = Some(s),
                    Err(e) => usage_exit(&e),
                }
                i += 1;
            }
            "--with-auth" => with_auth = true,
            x => panic!("unknown argument {x}"),
        }
        i += 1;
    }
    if sizes_arg.is_some() && only.as_deref() == Some("q") {
        eprintln!("[driver] note: --sizes has no effect with --only q (the q experiments use a fixed N_Q = {Q_N})");
    }
    let stamp = cmd_out("date", &["-u", "+%Y%m%d-%H%M%S"]);
    let out = out.unwrap_or_else(|| format!("results/{mode}-{stamp}").into());
    fs::create_dir_all(&out).unwrap();
    write_env(&out, threads, mode);
    if let Some(s) = &sizes_arg {
        // only when --sizes is given: the default env.txt stays unchanged
        let mut e = OpenOptions::new().append(true).open(out.join("env.txt")).unwrap();
        writeln!(
            e,
            "custom scale sizes (--sizes) for rc and exec, N_Q in {s:?}; R_Auth depth points {}",
            if with_auth { "run (--with-auth)" } else { "skipped (no --with-auth)" }
        )
        .unwrap();
    }
    let mut csv = File::create(out.join("raw.csv")).unwrap();
    writeln!(csv, "{HEADER}").unwrap();
    let failures = OpenOptions::new().create(true).append(true).open(out.join("failures.txt")).unwrap();
    let mut d = Driver { out: out.clone(), threads, quick, csv, failures };
    let want = |name: &str| only.as_deref().map(|o| o == name).unwrap_or(true);

    // scale: rc and exec over N_Q, auth over depth
    let run_auth = sizes_arg.is_none() || with_auth; // default behaviour: auth points always run
    let sizes: Vec<usize> = match sizes_arg {
        Some(s) => s,
        None if quick => vec![1_000, 10_000],
        None => vec![1_000, 10_000, 100_000],
    };
    for rel in ["rc", "exec"] {
        if !want("scale") {
            break;
        }
        for &n in &sizes {
            assert!(n <= MAX_NQ);
            match d.run_point(&format!("scale {rel} n={n}"), &["scale".into(), format!("rel={rel}"), format!("n={n}")]) {
                PointResult::Ok => {}
                PointResult::Failed(_) => {
                    eprintln!("[driver] stopping larger N_Q for {rel}");
                    break;
                }
            }
        }
    }
    if want("scale") && run_auth {
        for &depth in if quick { &AUTH_DEPTHS[..1] } else { &AUTH_DEPTHS[..] } {
            d.run_point(&format!("scale auth depth={depth}"), &["scale".into(), "rel=auth".into(), format!("depth={depth}")]);
        }
    }
    if want("q") {
        for rel in ["rc", "auth", "exec", "bundle"] {
            for m in ["same", "distinct"] {
                d.run_point(&format!("q {rel} {m}"), &["q".into(), format!("rel={rel}"), format!("mode={m}")]);
            }
        }
    }
    eprintln!("[driver] done; results in {}", d.out.display());
}

/// `proofbench ablation --out DIR [--threads N] [--quick]`: Exp 6, "w/o Batched RC". Points: G in {1,4,16,64} (quick: {1,4}) times
/// series {batched, per_block}. Raw rows only (raw.csv = the usual columns plus g_blocks), env.txt, failures.txt.
fn driver_ablation(rest: &[String]) {
    let mut out: Option<std::path::PathBuf> = None;
    let mut threads: Option<usize> = None;
    let mut quick = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--out" => {
                out = Some(rest[i + 1].clone().into());
                i += 1;
            }
            "--threads" => {
                threads = Some(rest[i + 1].parse().unwrap());
                i += 1;
            }
            "--quick" => quick = true,
            x => panic!("unknown argument {x}"),
        }
        i += 1;
    }
    let stamp = cmd_out("date", &["-u", "+%Y%m%d-%H%M%S"]);
    let out = out.unwrap_or_else(|| format!("results/ablation-{stamp}").into());
    fs::create_dir_all(&out).unwrap();
    write_env(&out, threads, if quick { "ablation (quick)" } else { "ablation" });
    {
        let mut e = OpenOptions::new().append(true).open(out.join("env.txt")).unwrap();
        writeln!(
            e,
            "ablation: R_RC only; each block = {ABL_BLOCK} records (the 'block size' line above applies to the other modes); G in {:?}; \
series batched (one proof over G*{ABL_BLOCK} records, G blocks) and per_block (G proofs of one block each, one after the other); \
rule {}; times, sizes and trace rows are sums over the proofs of a run",
            if quick { &ABL_G_QUICK[..] } else { &ABL_G[..] },
            if quick { "1 warm-up + 2 runs (quick)" } else { "3 warm-up + 30 runs" }
        )
        .unwrap();
    }
    let mut csv = File::create(out.join("raw.csv")).unwrap();
    writeln!(csv, "{HEADER},g_blocks").unwrap();
    let failures = OpenOptions::new().create(true).append(true).open(out.join("failures.txt")).unwrap();
    let mut d = Driver { out: out.clone(), threads, quick, csv, failures };
    for &g in if quick { &ABL_G_QUICK[..] } else { &ABL_G[..] } {
        for series in ["batched", "per_block"] {
            d.run_point(
                &format!("ablation {series} G={g}"),
                &["ablation".into(), format!("series={series}"), format!("g={g}")],
            );
        }
    }
    eprintln!("[driver] done; results in {}", d.out.display());
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(|s| s.as_str()) {
        Some("child") => match a.get(1).map(|s| s.as_str()) {
            Some("scale") => child_scale(&a[2..]),
            Some("q") => child_q(&a[2..]),
            Some("ablation") => child_ablation(&a[2..]),
            _ => panic!("bad child kind"),
        },
        Some(m @ ("smoke" | "full")) => driver(m, &a[1..]),
        Some("ablation") => driver_ablation(&a[1..]),
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}
