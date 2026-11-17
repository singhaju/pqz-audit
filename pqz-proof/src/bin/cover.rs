//! cover: measures R_Cover (BlockCover + PruneValid, DESIGN.md section 7) and, for the clustered case, R_Exec on the retained
//! records only (blocks of 500 records).
//!
//! Driver:  cover [--out DIR] [--threads N] [--quick] [--only cover|exec]
//! Child:   cover child cover g=G r=R     /    cover child exec g=G r=R      (one fresh process per point, so peak RSS is per point)
//!
//! Points: cover: G in {100, 500, 2000, 8000} x r in {round(G*21/2000), G/4, round(G*1987/2000)}, k = 7, W = 8.
//!         exec:  G = 2000, r in {21, 1987}: R_Exec over r*500 records (existing code, theta = 2^31).
//! Rule per point: 3 warm-up runs, then 30 timed runs; if the first warm-up run takes more than 300 s, 10 timed runs (stated in
//! the `note` column). Every run proves, then verifies the serialized proof (parse included).
//! Stops: a point is killed if no row arrives for 900 s or if MemAvailable drops below 4 GiB (the machine is shared); the event is
//! written to failures.txt AND to raw.csv as a row with the note FAILED (the message), as the task requires.

use pqz_proof::cover::{cover_public, build_cover_trace, CoverAir, CoverInstance, CoverPublic, K, SW};
use pqz_proof::data::Workload;
use pqz_proof::exec::{build_exec_trace, exec_public, ExecAir, ExecPublic};
use pqz_proof::prove::{default_options, prove_trace, security_of, verify_proof};
use pqz_proof::rescue::F;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use winterfell::{Proof, Trace};

const MIN_BITS: u32 = 80;
const THETA: u64 = 1 << 31;
const EXEC_BLOCK: usize = 500;
const G_LIST: [usize; 4] = [100, 500, 2000, 8000];
const G_LIST_QUICK: [usize; 2] = [100, 500];
const WARMUP: usize = 3;
const RUNS: usize = 30;
const RUNS_SLOW: usize = 10;
const SLOW_S: f64 = 300.0;
const WATCHDOG_S: u64 = 900;
const MIN_AVAIL_KB: u64 = 4 * 1024 * 1024;

const HEADER: &str = "experiment,rel,n_records,block_size,depth,q,mode,run,warmup,rule,trace_rows,trace_s,prove_s,verify_s,\
total_verify_s,proof_bytes,prove_peak_rss_kb,verify_rss_baseline_kb,verify_peak_rss_kb,conj_bits,udr_bits,ldr_bits,loadavg1,hwm_reset_ok,\
g_blocks,r_retained,k,w,note";

fn status_kb(key: &str) -> u64 {
    let s = fs::read_to_string("/proc/self/status").unwrap_or_default();
    for l in s.lines() {
        if let Some(r) = l.strip_prefix(key) {
            return r.trim().trim_end_matches("kB").trim().parse().unwrap_or(0);
        }
    }
    0
}

fn pid_status_kb(pid: u32, key: &str) -> u64 {
    let s = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
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

fn arg(args: &[String], key: &str) -> Option<String> {
    args.iter().find_map(|a| a.strip_prefix(&format!("{key}=")).map(|s| s.to_string()))
}

fn r_lo(g: usize) -> usize {
    (g * 21 + 1000) / 2000
}
fn r_hi(g: usize) -> usize {
    (g * 1987 + 1000) / 2000
}

// ------------------------------------------------------------------------------------------------
// One run: build trace, prove, serialize, verify
// ------------------------------------------------------------------------------------------------

struct Made {
    trace_rows: usize,
    trace_s: f64,
    prove_s: f64,
    verify_s: f64,
    bytes: usize,
    conj: u32,
    udr: u32,
    ldr: u32,
    prove_rss: u64,
    base: u64,
    vrss: u64,
    hwm_ok: bool,
}

enum Prepared {
    Cover(CoverInstance, CoverPublic),
    Exec(Workload, ExecPublic),
}

fn run_once(pr: &Prepared) -> Result<Made, String> {
    let hwm_ok = reset_hwm();
    let opts = default_options();
    let t0 = Instant::now();
    let (trace_rows, trace_s, proof, prove_s) = match pr {
        Prepared::Cover(inst, p) => {
            let trace = build_cover_trace(inst);
            let trace_s = t0.elapsed().as_secs_f64();
            let rows = trace.length();
            let t1 = Instant::now();
            let proof = prove_trace::<CoverAir>(trace, p.clone(), opts)?;
            (rows, trace_s, proof, t1.elapsed().as_secs_f64())
        }
        Prepared::Exec(w, p) => {
            let trace = build_exec_trace(w, THETA);
            let trace_s = t0.elapsed().as_secs_f64();
            let rows = trace.length();
            let t1 = Instant::now();
            let proof = prove_trace::<ExecAir>(trace, p.clone(), opts)?;
            (rows, trace_s, proof, t1.elapsed().as_secs_f64())
        }
    };
    let sec = security_of(&proof);
    let bytes = proof.to_bytes();
    let prove_rss = status_kb("VmHWM:");
    let base = status_kb("VmRSS:");
    reset_hwm();
    let t = Instant::now();
    let parsed = Proof::from_bytes(&bytes).map_err(|e| format!("parse: {e:?}"))?;
    match pr {
        Prepared::Cover(_, p) => verify_proof::<CoverAir>(parsed, p.clone(), MIN_BITS)?,
        Prepared::Exec(_, p) => verify_proof::<ExecAir>(parsed, p.clone(), MIN_BITS)?,
    }
    let verify_s = t.elapsed().as_secs_f64();
    let vrss = status_kb("VmHWM:");
    Ok(Made {
        trace_rows,
        trace_s,
        prove_s,
        verify_s,
        bytes: bytes.len(),
        conj: sec.conjectured_bits,
        udr: sec.proven_unique_decoding_bits,
        ldr: sec.proven_list_decoding_bits,
        prove_rss,
        base,
        vrss,
        hwm_ok,
    })
}

// ------------------------------------------------------------------------------------------------
// Child
// ------------------------------------------------------------------------------------------------

fn row_line(kind: &str, g: usize, r: usize, n_records: usize, run: usize, warm: bool, rule: &str, m: &Made, note: &str) -> String {
    let (exp, rel, bs, kk, ww) = if kind == "cover" {
        ("cover", "cover", String::new(), K.to_string(), SW.to_string())
    } else {
        ("cover_exec", "exec", EXEC_BLOCK.to_string(), String::new(), String::new())
    };
    let nrec = if kind == "cover" { String::new() } else { n_records.to_string() };
    format!(
        "{exp},{rel},{nrec},{bs},,,,{run},{},{rule},{},{:.6},{:.6},{:.6},,{},{},{},{},{},{},{},{},{},{g},{r},{kk},{ww},{note}",
        warm as u8,
        m.trace_rows,
        m.trace_s,
        m.prove_s,
        m.verify_s,
        m.bytes,
        m.prove_rss,
        m.base,
        m.vrss,
        m.conj,
        m.udr,
        m.ldr,
        loadavg1(),
        m.hwm_ok as u8
    )
}

fn emit(s: &str) {
    println!("ROW,{s}");
    let _ = std::io::stdout().flush();
}

fn child(args: &[String]) {
    let kind = args[0].clone();
    let g: usize = arg(args, "g").unwrap().parse().unwrap();
    let r: usize = arg(args, "r").unwrap().parse().unwrap();
    let quick = arg(args, "quick").is_some();
    assert!(r <= g);
    let (pr, n_records, layout) = if kind == "cover" {
        let inst = CoverInstance::honest(g, r, 1);
        assert_eq!(inst.retained(), r);
        let p = cover_public(&inst);
        (Prepared::Cover(inst, p), 0usize, "retained blocks spread evenly; k=7 positions; W=8 words of 32 bits")
    } else {
        let n = r * EXEC_BLOCK;
        let w = Workload::synthetic(n, EXEC_BLOCK, 1);
        let ctx = [F::new(1), F::new(2), F::new(3), F::new(4)];
        let p = exec_public(&w, THETA, ctx);
        (Prepared::Exec(w, p), n, "R_Exec over the r retained blocks of 500 records only (clustered layout; existing code, theta=2^31)")
    };
    let (n_warm, n_runs) = if quick { (1, 2) } else { (WARMUP, RUNS) };
    let mut n_runs = n_runs;
    let mut note = layout.to_string();
    let mut rule = if quick { "quick(1 warmup+2)".to_string() } else { format!("{RUNS} runs + {WARMUP} warm-up") };
    let mut i = 0usize;
    while i < n_warm + n_runs {
        let warm = i < n_warm;
        let m = match run_once(&pr) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("prove/verify failed: {e}");
                std::process::exit(4);
            }
        };
        let secs = m.trace_s + m.prove_s + m.verify_s;
        if i == 0 && !quick && secs > SLOW_S {
            n_runs = RUNS_SLOW;
            rule = format!("{RUNS_SLOW} runs + {WARMUP} warm-up (first run over {SLOW_S} s)");
            note = format!("{layout}; only {RUNS_SLOW} timed runs because one run takes more than 5 minutes");
        }
        let run = if warm { i } else { i - n_warm + 1 };
        emit(&row_line(&kind, g, r, n_records, run, warm, &rule, &m, &note.replace(',', ";")));
        i += 1;
    }
}

// ------------------------------------------------------------------------------------------------
// Driver
// ------------------------------------------------------------------------------------------------

struct Driver {
    threads: Option<usize>,
    quick: bool,
    csv: File,
    failures: File,
}

impl Driver {
    fn run_point(&mut self, kind: &str, g: usize, r: usize) {
        let desc = format!("{kind} G={g} r={r}");
        eprintln!("[driver] point: {desc}");
        let exe = std::env::current_exe().unwrap();
        let mut cmd = Command::new(exe);
        cmd.arg("child").arg(kind).arg(format!("g={g}")).arg(format!("r={r}"));
        if self.quick {
            cmd.arg("quick=1");
        }
        if let Some(t) = self.threads {
            cmd.env("RAYON_NUM_THREADS", t.to_string());
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn child");
        let pid = child.id();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            for l in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        let (etx, erx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            for l in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("[child] {l}");
                if etx.send(l).is_err() {
                    break;
                }
            }
        });
        let mut last = Instant::now();
        let mut rows = 0usize;
        let mut max_rss = 0u64;
        let mut why: Option<String> = None;
        loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(l) => {
                    if let Some(row) = l.strip_prefix("ROW,") {
                        writeln!(self.csv, "{row}").unwrap();
                        self.csv.flush().unwrap();
                        rows += 1;
                        last = Instant::now();
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            max_rss = max_rss.max(pid_status_kb(pid, "VmHWM:"));
            if last.elapsed().as_secs() > WATCHDOG_S {
                let _ = child.kill();
                let _ = child.wait();
                why = Some(format!("no result for {WATCHDOG_S} s; child killed after {rows} rows; child peak RSS seen {max_rss} kB"));
                break;
            }
            let avail = mem_available_kb();
            if avail < MIN_AVAIL_KB {
                let _ = child.kill();
                let _ = child.wait();
                why = Some(format!(
                    "driver memory guard: MemAvailable fell to {avail} kB (below the {MIN_AVAIL_KB} kB guard); child killed after {rows} rows; child peak RSS seen {max_rss} kB"
                ));
                break;
            }
        }
        if why.is_none() {
            let st = child.wait().unwrap();
            if !st.success() {
                use std::os::unix::process::ExitStatusExt;
                let mut msgs: Vec<String> = Vec::new();
                while let Ok(l) = erx.recv_timeout(Duration::from_millis(300)) {
                    msgs.push(l);
                }
                let tail = msgs.iter().rev().take(2).cloned().collect::<Vec<_>>().join(" | ");
                why = Some(format!(
                    "child exited abnormally: code {:?} signal {:?}; {rows} rows written; child peak RSS seen {max_rss} kB; last stderr: {tail}",
                    st.code(),
                    st.signal()
                ));
            }
        }
        if let Some(w) = why {
            let msg = format!("FAILED {desc}: {w}");
            eprintln!("[driver] {msg}");
            writeln!(self.failures, "{msg}").unwrap();
            let (exp, rel) = if kind == "cover" { ("cover", "cover") } else { ("cover_exec", "exec") };
            let nrec = if kind == "exec" { (r * EXEC_BLOCK).to_string() } else { String::new() };
            let bs = if kind == "exec" { EXEC_BLOCK.to_string() } else { String::new() };
            let (kk, ww) = if kind == "cover" { (K.to_string(), SW.to_string()) } else { (String::new(), String::new()) };
            let note = format!("FAILED: {w}").replace(',', ";").replace('\n', " ");
            writeln!(
                self.csv,
                "{exp},{rel},{nrec},{bs},,,,,,point failed,,,,,,,,,,,,,,,{g},{r},{kk},{ww},{note}"
            )
            .unwrap();
            self.csv.flush().unwrap();
        }
    }
}

fn cmd_out(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unavailable".into())
}

fn write_env(out: &std::path::Path, threads: Option<usize>, quick: bool) {
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
    let s = format!(
        "mode: cover{}\ncpu: {cpu}\nlogical_cores: {cores}\n{memtotal}\nkernel: {}\nrustc: {}\ncargo: {}\n\
Cargo.lock sha256: {}\nwinterfell: 0.13.1 (pinned =0.13.1)\nconcurrent feature: {}\nthreads: {}\n\
loadavg at start: {}\nMemAvailable at start (kB): {}\nproof options: {:?}\nhash for commitments: Sha3_256 (winterfell DefaultRandomCoin, MerkleTree)\n\
in-circuit hash: Rescue Prime Rp64_256 (algebraic; see DESIGN.md)\n\
cover: G in {:?}, r in {{round(G*21/2000), G/4, round(G*1987/2000)}}, k={K}, W={SW} words of 32 bits, 16 rows per block\n\
exec rows: R_Exec over r*{EXEC_BLOCK} records (existing code), theta={THETA}, G=2000, r in {{21, 1987}}\n\
rule: {WARMUP} warm-up + {RUNS} timed runs per point ({RUNS_SLOW} timed runs if the first run takes over {SLOW_S} s)\n\
min_bits accepted by the verifier (library conjectured estimate): {MIN_BITS}\n\
driver guards: kill a point if no row for {WATCHDOG_S} s or MemAvailable < {MIN_AVAIL_KB} kB\n",
        if quick { " (quick)" } else { "" },
        cmd_out("uname", &["-sr"]),
        cmd_out("rustc", &["--version"]),
        cmd_out("cargo", &["--version"]),
        cmd_out("sha256sum", &["Cargo.lock"]),
        cfg!(feature = "concurrent"),
        threads.map(|t| t.to_string()).unwrap_or_else(|| "rayon default (all logical cores)".into()),
        fs::read_to_string("/proc/loadavg").unwrap_or_default().trim(),
        mem_available_kb(),
        default_options(),
        if quick { &G_LIST_QUICK[..] } else { &G_LIST[..] },
    );
    fs::write(out.join("env.txt"), s).unwrap();
}

fn driver(rest: &[String]) {
    let mut out: Option<std::path::PathBuf> = None;
    let mut threads: Option<usize> = None;
    let mut quick = false;
    let mut only: Option<String> = None;
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
            "--quick" => quick = true,
            x => panic!("unknown argument {x}"),
        }
        i += 1;
    }
    let out = out.unwrap_or_else(|| format!("results/cover-{}", cmd_out("date", &["-u", "+%Y%m%d-%H%M%S"])).into());
    assert!(!out.join("raw.csv").exists(), "refusing to overwrite an existing result folder");
    fs::create_dir_all(&out).unwrap();
    write_env(&out, threads, quick);
    let mut csv = File::create(out.join("raw.csv")).unwrap();
    writeln!(csv, "{HEADER}").unwrap();
    let failures = OpenOptions::new().create(true).append(true).open(out.join("failures.txt")).unwrap();
    let mut d = Driver { threads, quick, csv, failures };
    let want = |name: &str| only.as_deref().map(|o| o == name).unwrap_or(true);
    if want("cover") {
        for &g in if quick { &G_LIST_QUICK[..] } else { &G_LIST[..] } {
            for r in [r_lo(g), g / 4, r_hi(g)] {
                d.run_point("cover", g, r);
            }
        }
    }
    if want("exec") && !quick {
        for r in [21usize, 1987] {
            d.run_point("exec", 2000, r);
        }
    }
    eprintln!("[driver] done; results in {}", out.display());
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(|s| s.as_str()) {
        Some("child") => child(&a[1..]),
        Some(_) | None => driver(&a),
    }
}
