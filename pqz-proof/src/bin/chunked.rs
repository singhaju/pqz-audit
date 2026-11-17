//! chunked: cost of proving M records as M/chunk SEPARATE proofs (R_RC or R_Exec, blocks of 500 records), one after the other.
//! This is NOT the paper's single proof: each chunk binds only its own records, and nothing here links the chunks to each other.
//! Library functions are reused unchanged (Workload, build_rc_trace / build_exec_trace, prove_trace, verify_proof).
//!
//! Driver:  chunked [--out DIR] [--smoke]
//! Child:   chunked child rel=rc|exec m=M chunk=C block=B run=I warmup=0|1      (one fresh process per run)
//!
//! Matrix (TASK-chunked.md): A: rel rc and exec, M in {1e5, 1e6}, chunk 1e4 (1 warm-up only at M = 1e5; 5 timed runs at 1e5, 3 at 1e6).
//!                           B: rel exec, M = 993,500, chunk 1e4 (99 chunks of 1e4 and one of 3,500), 3 timed runs.
//! Per run, the child (1) generates all chunk workloads and public inputs OUTSIDE the timers, (2) proves the chunks one after the other
//! (timed as ONE wall-clock interval around the loop: trace build + prove + proof serialisation), (3) verifies every proof (parse + verify,
//! timed as one wall-clock interval). Peak RSS is VmHWM, reset before each chunk; the maximum over chunks is reported.
//! Stops: the driver kills a run after 1200 s (point recorded FAILED, remaining runs of that point skipped) or if MemAvailable < 4 GiB
//! (the same guard as `cover`). No guard override exists.

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
use winterfell::{Proof, Trace};

const MIN_BITS: u32 = 80;
const THETA: u64 = 1 << 31;
const BLOCK: usize = 500;
const CHUNK: usize = 10_000;
const RUN_LIMIT_S: u64 = 1200;
const MIN_AVAIL_KB: u64 = 4 * 1024 * 1024;

const HEADER: &str = "experiment,rel,m_records,chunk_records,block_size,n_chunks,last_chunk_records,run,warmup,prove_total_s,trace_total_s,\
prove_only_total_s,verify_total_s,proof_bytes_sum,prove_peak_rss_kb_max_chunk,baseline_rss_kb,max_chunk_prove_s,conj_bits,udr_bits,ldr_bits,\
loadavg1_start,loadavg1_end,hwm_reset_ok,note";

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

fn pid_status_kb(pid: u32, key: &str) -> u64 {
    let s = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    for l in s.lines() {
        if let Some(r) = l.strip_prefix(key) {
            return r.trim().trim_end_matches("kB").trim().parse().unwrap_or(0);
        }
    }
    0
}

fn arg(args: &[String], key: &str) -> Option<String> {
    args.iter().find_map(|a| a.strip_prefix(&format!("{key}=")).map(|s| s.to_string()))
}

enum Prep {
    Rc(Workload, RcPublic),
    Exec(Workload, ExecPublic),
}

enum Stmt {
    Rc(RcPublic),
    Exec(ExecPublic),
}

fn child(args: &[String]) {
    let rel = arg(args, "rel").expect("rel");
    let m: usize = arg(args, "m").expect("m").parse().unwrap();
    let chunk: usize = arg(args, "chunk").expect("chunk").parse().unwrap();
    let block: usize = arg(args, "block").expect("block").parse().unwrap();
    let run: usize = arg(args, "run").expect("run").parse().unwrap();
    let warmup: usize = arg(args, "warmup").expect("warmup").parse().unwrap();
    let experiment = arg(args, "exp").unwrap_or_else(|| "chunked".into());
    assert!(rel == "rc" || rel == "exec");
    assert!(chunk % block == 0 && m % block == 0);
    let n_full = m / chunk;
    let rem = m % chunk;
    let mut sizes: Vec<usize> = vec![chunk; n_full];
    if rem > 0 {
        sizes.push(rem);
    }
    let n_chunks = sizes.len();
    let last = *sizes.last().unwrap();

    // Prepare (outside the timers): workloads and public inputs; chunk i uses seed i+1.
    let mut prep: Vec<Prep> = Vec::with_capacity(n_chunks);
    for (i, &sz) in sizes.iter().enumerate() {
        let seed = (i + 1) as u64;
        let w = Workload::synthetic(sz, block, seed);
        if rel == "rc" {
            let p = rc_public(&w);
            prep.push(Prep::Rc(w, p));
        } else {
            let ctx = [F::new(seed), F::new(2), F::new(3), F::new(4)];
            let p = exec_public(&w, THETA, ctx);
            prep.push(Prep::Exec(w, p));
        }
    }
    let baseline = status_kb("VmRSS:");
    let opts = default_options();
    let mut proofs: Vec<(Stmt, Vec<u8>)> = Vec::with_capacity(n_chunks);
    let (mut trace_total, mut prove_only_total, mut max_chunk_prove) = (0f64, 0f64, 0f64);
    let mut peak = 0u64;
    let mut hwm_ok = true;
    let (mut conj, mut udr, mut ldr) = (u32::MAX, u32::MAX, u32::MAX);
    let load_start = loadavg1();

    let t_all = Instant::now();
    for (i, pr) in prep.iter().enumerate() {
        hwm_ok &= reset_hwm();
        let t0 = Instant::now();
        let (trace, stmt) = match pr {
            Prep::Rc(w, p) => (build_rc_trace(w), Stmt::Rc(p.clone())),
            Prep::Exec(w, p) => (build_exec_trace(w, THETA), Stmt::Exec(p.clone())),
        };
        let trace_s = t0.elapsed().as_secs_f64();
        let _rows = trace.length();
        let t1 = Instant::now();
        let r = match &stmt {
            Stmt::Rc(p) => prove_trace::<RcAir>(trace, p.clone(), opts.clone()),
            Stmt::Exec(p) => prove_trace::<ExecAir>(trace, p.clone(), opts.clone()),
        };
        let proof = match r {
            Ok(p) => p,
            Err(e) => {
                eprintln!("prove failed on chunk {i}: {e}");
                std::process::exit(4);
            }
        };
        let prove_s = t1.elapsed().as_secs_f64();
        let sec = security_of(&proof);
        conj = conj.min(sec.conjectured_bits);
        udr = udr.min(sec.proven_unique_decoding_bits);
        ldr = ldr.min(sec.proven_list_decoding_bits);
        let bytes = proof.to_bytes();
        drop(proof);
        peak = peak.max(status_kb("VmHWM:"));
        trace_total += trace_s;
        prove_only_total += prove_s;
        max_chunk_prove = max_chunk_prove.max(trace_s + prove_s);
        proofs.push((stmt, bytes));
    }
    let prove_total = t_all.elapsed().as_secs_f64();

    let t_v = Instant::now();
    for (i, (stmt, bytes)) in proofs.iter().enumerate() {
        let proof = match Proof::from_bytes(bytes) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("parse failed on chunk {i}: {e:?}");
                std::process::exit(5);
            }
        };
        let r = match stmt {
            Stmt::Rc(p) => verify_proof::<RcAir>(proof, p.clone(), MIN_BITS),
            Stmt::Exec(p) => verify_proof::<ExecAir>(proof, p.clone(), MIN_BITS),
        };
        if let Err(e) = r {
            eprintln!("verify failed on chunk {i}: {e}");
            std::process::exit(5);
        }
    }
    let verify_total = t_v.elapsed().as_secs_f64();
    let bytes_sum: usize = proofs.iter().map(|x| x.1.len()).sum();

    println!(
        "ROW,{experiment},{rel},{m},{chunk},{block},{n_chunks},{last},{run},{warmup},{prove_total:.6},{trace_total:.6},{prove_only_total:.6},\
{verify_total:.6},{bytes_sum},{peak},{baseline},{max_chunk_prove:.6},{conj},{udr},{ldr},{load_start},{},{},",
        loadavg1(),
        hwm_ok as u8
    );
    let _ = std::io::stdout().flush();
}

// ------------------------------------------------------------------------------------------------
// Driver
// ------------------------------------------------------------------------------------------------

struct Point {
    exp: &'static str,
    rel: &'static str,
    m: usize,
    warm: usize,
    timed: usize,
}

struct Driver {
    csv: File,
    failures: File,
}

impl Driver {
    /// Returns true if the run succeeded.
    fn run_once(&mut self, p: &Point, run: usize, warmup: usize) -> bool {
        let desc = format!("{} rel={} M={} run={} warmup={}", p.exp, p.rel, p.m, run, warmup);
        eprintln!("[driver] {desc}");
        let exe = std::env::current_exe().unwrap();
        let mut cmd = Command::new(exe);
        cmd.arg("child")
            .arg(format!("rel={}", p.rel))
            .arg(format!("m={}", p.m))
            .arg(format!("chunk={CHUNK}"))
            .arg(format!("block={BLOCK}"))
            .arg(format!("run={run}"))
            .arg(format!("warmup={warmup}"))
            .arg(format!("exp={}", p.exp));
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let t_start = Instant::now();
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
        let mut got_row = false;
        let mut max_rss = 0u64;
        let mut why: Option<String> = None;
        loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(l) => {
                    if let Some(row) = l.strip_prefix("ROW,") {
                        writeln!(self.csv, "{row}").unwrap();
                        self.csv.flush().unwrap();
                        got_row = true;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            max_rss = max_rss.max(pid_status_kb(pid, "VmHWM:"));
            if t_start.elapsed().as_secs() > RUN_LIMIT_S {
                let _ = child.kill();
                let _ = child.wait();
                why = Some(format!("run exceeded {RUN_LIMIT_S} s; child killed; child peak RSS seen {max_rss} kB"));
                break;
            }
            let avail = mem_available_kb();
            if avail < MIN_AVAIL_KB {
                let _ = child.kill();
                let _ = child.wait();
                why = Some(format!(
                    "driver memory guard: MemAvailable fell to {avail} kB (below the {MIN_AVAIL_KB} kB guard); child killed; child peak RSS seen {max_rss} kB"
                ));
                break;
            }
        }
        if why.is_none() {
            let st = child.wait().unwrap();
            if !st.success() || !got_row {
                use std::os::unix::process::ExitStatusExt;
                let mut msgs: Vec<String> = Vec::new();
                while let Ok(l) = erx.recv_timeout(Duration::from_millis(300)) {
                    msgs.push(l);
                }
                let tail = msgs.iter().rev().take(2).cloned().collect::<Vec<_>>().join(" | ");
                why = Some(format!(
                    "child exited abnormally: code {:?} signal {:?}; row written: {got_row}; child peak RSS seen {max_rss} kB; last stderr: {tail}",
                    st.code(),
                    st.signal()
                ));
            }
        }
        if let Some(w) = why {
            let msg = format!("FAILED {desc}: {w}");
            eprintln!("[driver] {msg}");
            writeln!(self.failures, "{msg}").unwrap();
            let note = format!("FAILED: {w}").replace(',', ";").replace('\n', " ");
            writeln!(
                self.csv,
                "{},{},{},{CHUNK},{BLOCK},,,{run},{warmup},,,,,,,,,,,,,,,{note}",
                p.exp, p.rel, p.m
            )
            .unwrap();
            self.csv.flush().unwrap();
            return false;
        }
        true
    }

    fn run_point(&mut self, p: &Point) {
        for w in 0..p.warm {
            if !self.run_once(p, w, 1) {
                eprintln!("[driver] point stopped after failed warm-up");
                return;
            }
        }
        for r in 1..=p.timed {
            if !self.run_once(p, r, 0) {
                eprintln!("[driver] point stopped after failed run {r}");
                return;
            }
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

fn write_env(out: &std::path::Path, smoke: bool) {
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
        "mode: chunked{}\ncpu: {cpu}\nlogical_cores: {cores}\n{memtotal}\nkernel: {}\nrustc: {}\ncargo: {}\n\
Cargo.lock sha256: {}\nwinterfell: 0.13.1 (pinned =0.13.1)\nconcurrent feature: {}\nthreads: rayon default (all logical cores)\n\
loadavg at start: {}\nMemAvailable at start (kB): {}\nproof options: {:?}\nhash for commitments: Sha3_256 (winterfell DefaultRandomCoin, MerkleTree)\n\
in-circuit hash: Rescue Prime Rp64_256 (algebraic; see DESIGN.md)\n\
chunking: M records split into chunks of {CHUNK} records (blocks of {BLOCK} records, {} blocks per chunk), last chunk smaller if M is not a multiple;\n\
  every chunk is a separate proof of the existing R_RC / R_Exec AIR over its own records only; chunk i uses workload seed i+1; theta={THETA}\n\
timed regions: prove_total_s = one wall-clock interval around the loop over all chunks (trace build + prove + proof serialisation);\n\
  verify_total_s = one wall-clock interval around parse + verify of all proofs; workload generation and public inputs are outside both\n\
peak RSS: VmHWM reset (clear_refs) before each chunk; the maximum over chunks after proving; baseline_rss_kb = VmRSS after workload generation (all chunk workloads are held in memory)\n\
rule: A: rel rc and exec, M in 1e5 (1 warm-up + 5 timed) and 1e6 (3 timed, no warm-up); B: rel exec, M=993500 (3 timed, no warm-up); every run in a fresh process\n\
min_bits accepted by the verifier (library conjectured estimate): {MIN_BITS}\n\
driver guards: kill a run after {RUN_LIMIT_S} s (point recorded FAILED) or if MemAvailable < {MIN_AVAIL_KB} kB; no guard override\n",
        if smoke { " (smoke)" } else { "" },
        cmd_out("uname", &["-sr"]),
        cmd_out("rustc", &["--version"]),
        cmd_out("cargo", &["--version"]),
        cmd_out("sha256sum", &["Cargo.lock"]),
        cfg!(feature = "concurrent"),
        fs::read_to_string("/proc/loadavg").unwrap_or_default().trim(),
        mem_available_kb(),
        default_options(),
        CHUNK / BLOCK,
    );
    fs::write(out.join("env.txt"), s).unwrap();
}

fn driver(rest: &[String]) {
    let mut out: Option<std::path::PathBuf> = None;
    let mut smoke = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--out" => {
                out = Some(rest[i + 1].clone().into());
                i += 1;
            }
            "--smoke" => smoke = true,
            x => panic!("unknown argument {x}"),
        }
        i += 1;
    }
    let out = out.expect("--out DIR is required");
    assert!(!out.join("raw.csv").exists(), "refusing to overwrite an existing result folder");
    fs::create_dir_all(&out).unwrap();
    write_env(&out, smoke);
    let mut csv = File::create(out.join("raw.csv")).unwrap();
    writeln!(csv, "{HEADER}").unwrap();
    let failures = OpenOptions::new().create(true).append(true).open(out.join("failures.txt")).unwrap();
    let mut d = Driver { csv, failures };
    let points: Vec<Point> = if smoke {
        // 25,000 records = 2 chunks of 10,000 and one of 5,000; checks the split and the pipeline only
        vec![
            Point { exp: "A", rel: "rc", m: 25_000, warm: 0, timed: 1 },
            Point { exp: "A", rel: "exec", m: 25_000, warm: 0, timed: 1 },
        ]
    } else {
        vec![
            Point { exp: "A", rel: "rc", m: 100_000, warm: 1, timed: 5 },
            Point { exp: "A", rel: "rc", m: 1_000_000, warm: 0, timed: 3 },
            Point { exp: "A", rel: "exec", m: 100_000, warm: 1, timed: 5 },
            Point { exp: "A", rel: "exec", m: 1_000_000, warm: 0, timed: 3 },
            Point { exp: "B", rel: "exec", m: 993_500, warm: 0, timed: 3 },
        ]
    };
    for p in &points {
        d.run_point(p);
    }
    eprintln!("[driver] done; results in {}", out.display());
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(|s| s.as_str()) {
        Some("child") => child(&a[1..]),
        _ => driver(&a),
    }
}
