//! covermerkle: measures R_CoverM (block coverage with Merkle-opened probes over real-size Bloom summaries, DESIGN.md section 8).
//!
//! Driver:  covermerkle [--out DIR] [--threads N] [--quick] [--g 100,500,2000] [--append]
//! Child:   covermerkle child covermerkle g=G r=R      (one fresh process per point, so peak RSS is per point)
//!
//! Points: G in {100, 500, 2000} (8000 only through `--g 8000 --append`, after the 2000 point shows it can fit)
//!         x r in {round(G*21/2000), G/4, round(G*1987/2000)} (the formulas of `cover`), k = 7, summary 6,740 limbs, depth 13.
//! Rule per point: 3 warm-up runs, then 30 timed runs; if the first warm-up run takes more than 300 s, 10 timed runs (stated in
//! the `note` column). Every run builds the trace, proves, then verifies the serialized proof (parse included). The summaries and
//! their Merkle trees are built before the first run, outside every timer (6 template trees + one patched leaf per block).
//! Stops: a point is killed if no row arrives for 900 s or if MemAvailable drops below 4 GiB (the machine is shared); the event is
//! written to failures.txt AND to raw.csv as a row with the note FAILED (the message).

use pqz_proof::cover::K;
use pqz_proof::covermerkle::{build_trace, covermerkle_public, CoverMAir, CoverMInstance, CoverMPublic, DEPTH, LIMBS, WIDTH};
use pqz_proof::prove::{default_options, prove_trace, security_of, verify_proof};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use winterfell::{Proof, Trace};

const G_LIST: [usize; 3] = [100, 500, 2000];
const G_LIST_QUICK: [usize; 2] = [100, 500];
const WARMUP: usize = 3;
const RUNS: usize = 30;
const RUNS_SLOW: usize = 10;
const SLOW_S: f64 = 300.0;
const WATCHDOG_S: u64 = 900;
const MIN_AVAIL_KB: u64 = 4 * 1024 * 1024;
const LAYOUT: &str = "synthetic 6740-limb summaries (not Bloom filters of records); 6 template trees + 1 patched leaf per block; retained blocks spread evenly; pruned blocks have at least one 0 among the k=7 probed bits; k=7 positions; depth 13";

const HEADER: &str = "experiment,rel,n_records,block_size,depth,q,mode,run,warmup,rule,trace_rows,trace_s,prove_s,verify_s,\
total_verify_s,proof_bytes,prove_peak_rss_kb,verify_rss_baseline_kb,verify_peak_rss_kb,conj_bits,udr_bits,ldr_bits,loadavg1,hwm_reset_ok,\
g_blocks,r_retained,k,w,width,note";

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

fn run_once(inst: &CoverMInstance, p: &CoverMPublic) -> Result<Made, String> {
    let hwm_ok = reset_hwm();
    let opts = default_options();
    let t0 = Instant::now();
    let trace = build_trace(inst);
    let trace_s = t0.elapsed().as_secs_f64();
    let trace_rows = trace.length();
    let t1 = Instant::now();
    let proof = prove_trace::<CoverMAir>(trace, p.clone(), opts)?;
    let prove_s = t1.elapsed().as_secs_f64();
    let sec = security_of(&proof);
    let bytes = proof.to_bytes();
    let prove_rss = status_kb("VmHWM:");
    let base = status_kb("VmRSS:");
    reset_hwm();
    let t = Instant::now();
    let parsed = Proof::from_bytes(&bytes).map_err(|e| format!("parse: {e:?}"))?;
    verify_proof::<CoverMAir>(parsed, p.clone())?;
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

fn row_line(g: usize, r: usize, run: usize, warm: bool, rule: &str, m: &Made, note: &str) -> String {
    format!(
        "covermerkle,covermerkle,,,{DEPTH},,,{run},{},{rule},{},{:.6},{:.6},{:.6},,{},{},{},{},{},{},{},{},{},{g},{r},{K},{LIMBS},{WIDTH},{note}",
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
    let g: usize = arg(args, "g").unwrap().parse().unwrap();
    let r: usize = arg(args, "r").unwrap().parse().unwrap();
    let quick = arg(args, "quick").is_some();
    assert!(r <= g);
    // summaries and trees are built here, before any timer
    let tb = Instant::now();
    let inst = CoverMInstance::honest(g, r, 1);
    assert_eq!(inst.retained(), r);
    let p = covermerkle_public(&inst);
    eprintln!("instance built in {:.1} s (outside the timers)", tb.elapsed().as_secs_f64());
    let (n_warm, n_runs) = if quick { (1, 2) } else { (WARMUP, RUNS) };
    let mut n_runs = n_runs;
    let mut note = LAYOUT.to_string();
    let mut rule = if quick { "quick(1 warmup+2)".to_string() } else { format!("{RUNS} runs + {WARMUP} warm-up") };
    let mut i = 0usize;
    while i < n_warm + n_runs {
        let warm = i < n_warm;
        let m = match run_once(&inst, &p) {
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
            note = format!("{LAYOUT}; only {RUNS_SLOW} timed runs because one run takes more than 5 minutes");
        }
        let run = if warm { i } else { i - n_warm + 1 };
        emit(&row_line(g, r, run, warm, &rule, &m, &note.replace(',', ";")));
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
    fn run_point(&mut self, g: usize, r: usize) {
        let desc = format!("covermerkle G={g} r={r}");
        eprintln!("[driver] point: {desc}");
        let exe = std::env::current_exe().unwrap();
        let mut cmd = Command::new(exe);
        cmd.arg("child").arg("covermerkle").arg(format!("g={g}")).arg(format!("r={r}"));
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
            let note = format!("FAILED: {w}").replace(',', ";").replace('\n', " ");
            writeln!(
                self.csv,
                "covermerkle,covermerkle,,,{DEPTH},,,,,point failed,,,,,,,,,,,,,,,{g},{r},{K},{LIMBS},{WIDTH},{note}"
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

fn write_env(out: &std::path::Path, threads: Option<usize>, quick: bool, gs: &[usize]) {
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
    let lock_hash = cmd_out("sha256sum", &["Cargo.lock"]);
    let s = format!(
        "mode: covermerkle{}\ncpu: {cpu}\nlogical_cores: {cores}\n{memtotal}\nkernel: {}\nrustc: {}\ncargo: {}\n\
lockfile sha256: {lock_hash}\nwinterfell: 0.13.1 (pinned =0.13.1)\nconcurrent feature: {}\nthreads: {}\n\
loadavg at start: {}\nMemAvailable at start (kB): {}\nproof options: {:?}\nhash for commitments: Sha3_256 (winterfell DefaultRandomCoin, MerkleTree)\n\
in-circuit hash: Rescue Prime Rp64_256 (algebraic; see DESIGN.md)\n\
covermerkle: G in {:?}, r in {{round(G*21/2000), G/4, round(G*1987/2000)}}, k={K}, summary {LIMBS} limbs of 32 bits, Merkle depth {DEPTH}, trace width {WIDTH}, 1024 rows per block\n\
summaries: {LAYOUT}\n\
rule: {WARMUP} warm-up + {RUNS} timed runs per point ({RUNS_SLOW} timed runs if the first run takes over {SLOW_S} s)\n\
verifier accepts only default_options() (strict, no bit floor)\n\
driver guards: kill a point if no row for {WATCHDOG_S} s or MemAvailable < {MIN_AVAIL_KB} kB\n",
        if quick { " (quick)" } else { "" },
        cmd_out("uname", &["-sr"]),
        cmd_out("rustc", &["--version"]),
        cmd_out("cargo", &["--version"]),
        cfg!(feature = "concurrent"),
        threads.map(|t| t.to_string()).unwrap_or_else(|| "rayon default (all logical cores)".into()),
        fs::read_to_string("/proc/loadavg").unwrap_or_default().trim(),
        mem_available_kb(),
        default_options(),
        gs,
    );
    let name = if out.join("env.txt").exists() { "env-append.txt" } else { "env.txt" };
    fs::write(out.join(name), s).unwrap();
}

fn driver(rest: &[String]) {
    let mut out: Option<std::path::PathBuf> = None;
    let mut threads: Option<usize> = None;
    let mut quick = false;
    let mut append = false;
    let mut gs: Option<Vec<usize>> = None;
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
            "--g" => {
                gs = Some(rest[i + 1].split(',').map(|x| x.parse().unwrap()).collect());
                i += 1;
            }
            "--quick" => quick = true,
            "--append" => append = true,
            x => panic!("unknown argument {x}"),
        }
        i += 1;
    }
    let out = out.unwrap_or_else(|| format!("results/covermerkle-{}", cmd_out("date", &["-u", "+%Y%m%d-%H%M%S"])).into());
    let gs: Vec<usize> = gs.unwrap_or_else(|| if quick { G_LIST_QUICK.to_vec() } else { G_LIST.to_vec() });
    let csv = if append {
        assert!(out.join("raw.csv").exists(), "--append needs an existing raw.csv");
        OpenOptions::new().append(true).open(out.join("raw.csv")).unwrap()
    } else {
        assert!(!out.join("raw.csv").exists(), "refusing to overwrite an existing result folder");
        fs::create_dir_all(&out).unwrap();
        let mut f = File::create(out.join("raw.csv")).unwrap();
        writeln!(f, "{HEADER}").unwrap();
        f
    };
    write_env(&out, threads, quick, &gs);
    let failures = OpenOptions::new().create(true).append(true).open(out.join("failures.txt")).unwrap();
    let mut d = Driver { threads, quick, csv, failures };
    for &g in &gs {
        for r in [r_lo(g), g / 4, r_hi(g)] {
            d.run_point(g, r);
        }
    }
    eprintln!("[driver] done; results in {}", out.display());
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(|s| s.as_str()) {
        Some("child") => child(&a[2..]),
        Some(_) | None => driver(&a),
    }
}
