//! w34: end-to-end PQZ-Audit driver with the Plonky3 (w33) proof layer (CHANGES-w34.md).
//!
//! Driver:  w34 run   --out DIR --setting P3 [--n 20000] [--layouts clustered,scattered] [--runs 3] [--limit-s 7200] [--append] [--exec-stream retained|whole] [--fmt old|p2r]
//! Child:   w34 child setting=P3 n=N layout=clustered|scattered run=I [exec=retained|whole]    (one fresh process per run, prints one ROW line)
//! Exit codes of a child: 0 ok, 2 bad arguments, 4 prover failed, 5 a verifier rejected, 6 a consistency check failed.
//! The only setting is P3 (Plonky3 0.8.0, Goldilocks, Poseidon2 width 12, Blake3 Merkle, plain mode, FriOpts::std()).

use pqz_eval::Layout;
use pqz_integrated_w46::{opts, run_one_with_fmt, setting_of, WFmt, sys, ExecStream, Outcome, RunError, BLOCK, DEFAULT_SEED, STAGE_NAMES, THETA};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const MIN_AVAIL_KB: u64 = 4 * 1024 * 1024;

const COLS: &[&str] = &[
    "setting", "hash", "n", "layout", "run", "seed", "block", "g_blocks", "sigma", "r_retained", "r_hit_blocks", "n_selected",
    "gen_s", "setup_s",
    "p3a_s",
    "p3b_s", "rc_pub_s", "rc_trace_s", "rc_prove_s", "rc_rows", "rc_chunks", "rc_proof_bytes", "rc_conj_bits", "rc_udr_bits", "rc_ldr_bits",
    "p4a_s",
    "p4b_s", "led_seal_s", "led_txsign_s", "led_submit_s", "led_blocks",
    "p5_s", "auth_prep_s", "auth_trace_s", "auth_prove_s", "auth_rows", "auth_proof_bytes", "auth_conj_bits", "auth_udr_bits", "auth_ldr_bits",
    "p6a_s", "bps_s", "rps_s",
    "p6b_s", "exec_prep_s", "exec_pub_s", "exec_trace_s", "exec_prove_s", "exec_rows", "exec_chunks", "exec_proof_bytes", "exec_conj_bits", "exec_udr_bits", "exec_ldr_bits",
    "p7_s", "p7_auth_s", "p7_exec_s",
    "total_s", "wall_s", "gates_s", "gate_ledger_read_s",
    "peak_p3a_kb", "peak_p3b_kb", "peak_p4a_kb", "peak_p4b_kb", "peak_p5_kb", "peak_p6a_kb", "peak_p6b_kb", "peak_p7_kb", "peak_gates_kb",
    "process_peak_rss_kb", "hwm_reset_ok", "loadavg1_start", "loadavg1_end", "status", "note",
    // w34: extra columns, only at the END
    "p7_native_s", "stream_link", "exec_stream",
    // w46
    "fmt",
];

/// A CSV row built from named values; columns not given stay empty.
struct Row(BTreeMap<&'static str, String>);

impl Row {
    fn new() -> Self {
        Row(BTreeMap::new())
    }
    fn set(&mut self, k: &'static str, v: impl ToString) -> &mut Self {
        self.0.insert(k, v.to_string());
        self
    }
    fn f(&mut self, k: &'static str, v: f64) -> &mut Self {
        self.0.insert(k, format!("{v:.6}"));
        self
    }
    fn csv(&self, cols: &[&str]) -> String {
        for k in self.0.keys() {
            assert!(cols.contains(k), "unknown column {k}");
        }
        cols.iter().map(|c| self.0.get(c).cloned().unwrap_or_default().replace([',', '\n'], ";")).collect::<Vec<_>>().join(",")
    }
}

fn arg(args: &[String], key: &str) -> Option<String> {
    args.iter().find_map(|a| a.strip_prefix(&format!("{key}=")).map(|s| s.to_string()))
}

fn flag(rest: &[String], name: &str) -> Option<String> {
    rest.iter().position(|a| a == name).and_then(|i| rest.get(i + 1).cloned())
}

fn has(rest: &[String], name: &str) -> bool {
    rest.iter().any(|a| a == name)
}

fn layout_of(s: &str) -> Option<Layout> {
    match s {
        "clustered" => Some(Layout::Clustered),
        "scattered" => Some(Layout::Scattered),
        _ => None,
    }
}

fn emit(r: &Row) {
    println!("ROW,{}", r.csv(COLS));
    let _ = std::io::stdout().flush();
}

// ------------------------------------------------------------------------------------------------
// Child
// ------------------------------------------------------------------------------------------------

fn row_of(o: &Outcome, setting: &str, hash: &str, layout: &str, run: usize, la0: &str) -> Row {
    let mut r = Row::new();
    r.set("setting", setting).set("hash", hash).set("n", o.n).set("layout", layout).set("run", run).set("seed", DEFAULT_SEED).set("block", BLOCK)
        .set("g_blocks", o.g).set("sigma", o.sigma).set("r_retained", o.r).set("r_hit_blocks", o.r_hit_blocks).set("n_selected", o.n_sel)
        .f("gen_s", o.gen_s).f("setup_s", o.setup_s).f("p3a_s", o.p3a_s);
    r.f("p3b_s", o.p3b_s).f("rc_pub_s", o.rc.pub_s).f("rc_trace_s", o.rc.trace_s).f("rc_prove_s", o.rc.prove_s).set("rc_rows", o.rc.rows)
        .set("rc_chunks", o.rc.chunks).set("rc_proof_bytes", o.rc.bytes).set("rc_conj_bits", o.rc.conj).set("rc_udr_bits", o.rc.udr).set("rc_ldr_bits", o.rc.ldr);
    r.f("p4a_s", o.p4a_s);
    r.f("p4b_s", o.p4b_s).f("led_seal_s", o.led.seal_s).f("led_txsign_s", o.led.txsign_s).f("led_submit_s", o.led.submit_s).set("led_blocks", o.led.blocks);
    r.f("p5_s", o.p5_s).f("auth_prep_s", o.auth.prep_s).f("auth_trace_s", o.auth.trace_s).f("auth_prove_s", o.auth.prove_s).set("auth_rows", o.auth.rows)
        .set("auth_proof_bytes", o.auth.bytes).set("auth_conj_bits", o.auth.conj).set("auth_udr_bits", o.auth.udr).set("auth_ldr_bits", o.auth.ldr);
    r.f("p6a_s", o.p6a_s).f("bps_s", o.bps_s).f("rps_s", o.rps_s);
    r.f("p6b_s", o.p6b_s).f("exec_prep_s", o.exec_prep_s).f("exec_pub_s", o.exec.pub_s).f("exec_trace_s", o.exec.trace_s).f("exec_prove_s", o.exec.prove_s)
        .set("exec_rows", o.exec.rows).set("exec_chunks", o.exec.chunks).set("exec_proof_bytes", o.exec.bytes).set("exec_conj_bits", o.exec.conj)
        .set("exec_udr_bits", o.exec.udr).set("exec_ldr_bits", o.exec.ldr);
    r.f("p7_s", o.p7_s).f("p7_auth_s", o.p7_auth_s).f("p7_exec_s", o.p7_exec_s);
    r.f("total_s", o.total_s).f("wall_s", o.wall_s).f("gates_s", o.gates_s).f("gate_ledger_read_s", o.gate_ledger_read_s);
    let keys = ["peak_p3a_kb", "peak_p3b_kb", "peak_p4a_kb", "peak_p4b_kb", "peak_p5_kb", "peak_p6a_kb", "peak_p6b_kb", "peak_p7_kb", "peak_gates_kb"];
    debug_assert_eq!(keys.len(), STAGE_NAMES.len());
    for (i, k) in keys.iter().enumerate() {
        r.set(k, o.peak[i]);
    }
    r.set("process_peak_rss_kb", o.process_peak_kb).set("hwm_reset_ok", o.hwm_reset_ok as u8).set("loadavg1_start", la0).set("loadavg1_end", sys::loadavg1())
        .set("status", "ok");
    r.f("p7_native_s", o.p7_native_s).set("stream_link", o.link_kind.map(|k| k.name()).unwrap_or("")).set("exec_stream", o.exec_stream.map(|k| k.name()).unwrap_or(""));
    r.set("fmt", o.fmt.name());
    r.set(
        "note",
        "stage timers exclude gen_s, setup_s and gates; total_s = sum of the 8 stage timers; peak_* = VmHWM after each stage (HWM reset before it); cold run, no warm-up; verifiers accepted and all gates passed",
    );
    r
}

fn es_of(s: &str) -> Option<ExecStream> {
    match s {
        "retained" => Some(ExecStream::Retained),
        "whole" => Some(ExecStream::Whole),
        _ => None,
    }
}

fn child_run(args: &[String]) -> i32 {
    let (Some(n), Some(l), Some(sname)) = (arg(args, "n").and_then(|x| x.parse::<usize>().ok()), arg(args, "layout"), arg(args, "setting")) else {
        eprintln!("child needs setting= n= layout=");
        return 2;
    };
    let Some(layout) = layout_of(&l) else {
        eprintln!("unknown layout {l}");
        return 2;
    };
    let setting = match setting_of(&sname) {
        Ok(s) => s,
        Err(RunError { code, msg }) => {
            eprintln!("{msg}");
            return code;
        }
    };
    let es = match es_of(&arg(args, "exec").unwrap_or_else(|| "retained".into())) {
        Some(e) => e,
        None => {
            eprintln!("exec= must be retained or whole");
            return 2;
        }
    };
    let run: usize = arg(args, "run").and_then(|x| x.parse().ok()).unwrap_or(1);
    let Some(fmt) = WFmt::parse(&arg(args, "fmt").unwrap_or_else(|| "old".into())) else {
        eprintln!("fmt must be old or p2r");
        return 2;
    };
    let la0 = sys::loadavg1();
    match run_one_with_fmt(n, layout, &setting, DEFAULT_SEED, es, fmt) {
        Ok(o) => {
            emit(&row_of(&o, setting.name, setting.hash, &l, run, &la0));
            0
        }
        Err(RunError { code, msg }) => {
            eprintln!("run failed (code {code}): {msg}");
            code
        }
    }
}

// ------------------------------------------------------------------------------------------------
// Parent
// ------------------------------------------------------------------------------------------------

struct Out {
    dir: std::path::PathBuf,
    csv: File,
    failures: File,
}

impl Out {
    fn open(dir: &str, append: bool) -> Out {
        let dir = std::path::PathBuf::from(dir);
        fs::create_dir_all(dir.join("stderr")).expect("create out dir");
        let p = dir.join("raw.csv");
        let csv = if append {
            assert!(p.exists(), "--append needs an existing raw.csv");
            OpenOptions::new().append(true).open(&p).unwrap()
        } else {
            assert!(!p.exists(), "refusing to overwrite an existing result folder");
            let mut f = File::create(&p).unwrap();
            writeln!(f, "{}", COLS.join(",")).unwrap();
            f
        };
        let failures = OpenOptions::new().create(true).append(true).open(dir.join("failures.txt")).unwrap();
        Out { dir, csv, failures }
    }
}

/// Run one child process; copy its ROW lines to raw.csv; on any failure write failures.txt and one FAILED row. Returns success.
fn run_child(out: &mut Out, args: &[String], desc: &str, stderr_name: &str, limit_s: u64, key_row: Row) -> bool {
    eprintln!("[driver] {desc}");
    let exe = std::env::current_exe().unwrap();
    let errf = File::create(out.dir.join("stderr").join(stderr_name)).unwrap();
    let mut child = Command::new(exe).args(args).stdout(Stdio::piped()).stderr(Stdio::from(errf)).spawn().expect("spawn child");
    let pid = child.id();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for l in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(l).is_err() {
                break;
            }
        }
    });
    let start = Instant::now();
    let mut rows = 0usize;
    let mut seen_rss = 0u64;
    let mut why: Option<String> = None;
    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(l) => {
                if let Some(row) = l.strip_prefix("ROW,") {
                    writeln!(out.csv, "{row}").unwrap();
                    out.csv.flush().unwrap();
                    rows += 1;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        seen_rss = seen_rss.max(sys::pid_status_kb(pid, "VmRSS:"));
        if start.elapsed().as_secs() > limit_s {
            let _ = child.kill();
            let _ = child.wait();
            why = Some(format!("per-run limit of {limit_s} s exceeded; child killed after {rows} rows; largest RSS seen {seen_rss} kB"));
            break;
        }
        let avail = sys::mem_available_kb();
        if avail < MIN_AVAIL_KB {
            let _ = child.kill();
            let _ = child.wait();
            why = Some(format!("memory guard: MemAvailable fell to {avail} kB (below {MIN_AVAIL_KB} kB); child killed after {rows} rows; largest RSS seen {seen_rss} kB"));
            break;
        }
    }
    if why.is_none() {
        let st = child.wait().unwrap();
        if !st.success() {
            use std::os::unix::process::ExitStatusExt;
            let tail = fs::read_to_string(out.dir.join("stderr").join(stderr_name))
                .unwrap_or_default()
                .lines()
                .rev()
                .take(2)
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(" | ");
            why = Some(format!("child exited abnormally: code {:?} signal {:?}; {rows} rows written; largest RSS seen {seen_rss} kB; last stderr: {tail}", st.code(), st.signal()));
        } else if rows == 0 {
            why = Some("child exited 0 but wrote no ROW".to_string());
        }
    }
    match why {
        None => true,
        Some(w) => {
            let msg = format!("FAILED {desc}: {w}");
            eprintln!("[driver] {msg}");
            writeln!(out.failures, "{msg}").unwrap();
            let mut r = key_row;
            r.set("status", "FAILED").set("note", w);
            writeln!(out.csv, "{}", r.csv(COLS)).unwrap();
            out.csv.flush().unwrap();
            false
        }
    }
}

fn write_env(dir: &std::path::Path, setting: &str, hash: &str, extra: &str) {
    let o = opts();
    let cpu = fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("model name"))
        .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
        .unwrap_or_default();
    let memtotal = fs::read_to_string("/proc/meminfo").unwrap_or_default().lines().find(|l| l.starts_with("MemTotal")).unwrap_or("").to_string();
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let lock = ["Cargo", ".lock"].concat();
    let s = format!(
        "mode: w34 run\nsetting: {setting}\nproof layer: Plonky3 0.8.0 via pqz-plonky3-w35 (Goldilocks deg-2 ext, Poseidon2 width 12, Blake3 Merkle), plain mode, one proof per relation\nhash of this build: {hash}\ncpu: {cpu}\nlogical_cores: {cores}\n{memtotal}\nkernel: {}\nrustc: {}\ncargo: {}\nlockfile sha256: {}\n\
FriOpts: {:?}\nR_Exec predicate: v >= theta, theta = {THETA}; block size {BLOCK}\nseed: {DEFAULT_SEED:#x}\nloadavg at start: {}\nMemAvailable at start (kB): {}\n\
driver guard: MemAvailable < {MIN_AVAIL_KB} kB kills the child; per-run limit by --limit-s\n{extra}",
        sys::cmd_out("uname", &["-sr"]),
        sys::cmd_out("rustc", &["--version"]),
        sys::cmd_out("cargo", &["--version"]),
        sys::cmd_out("sha256sum", &[lock.as_str()]),
        o,
        fs::read_to_string("/proc/loadavg").unwrap_or_default().trim(),
        sys::mem_available_kb(),
    );
    let name = if dir.join("env.txt").exists() { "env-append.txt" } else { "env.txt" };
    fs::write(dir.join(name), s).unwrap();
}

fn driver_run(rest: &[String]) -> i32 {
    let sname = flag(rest, "--setting").unwrap_or_else(|| "P3".into());
    let setting = match setting_of(&sname) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e.msg);
            return e.code;
        }
    };
    let out_dir = flag(rest, "--out").unwrap_or_else(|| format!("results/w34-{sname}-{}", sys::cmd_out("date", &["-u", "+%Y%m%d-%H%M%S"])));
    let n: usize = flag(rest, "--n").and_then(|x| x.parse().ok()).unwrap_or(20_000);
    let layouts: Vec<String> = flag(rest, "--layouts").unwrap_or_else(|| "clustered,scattered".into()).split(',').map(|s| s.to_string()).collect();
    let runs: usize = flag(rest, "--runs").and_then(|x| x.parse().ok()).unwrap_or(3);
    let es_name = flag(rest, "--exec-stream").unwrap_or_else(|| "retained".into());
    if es_of(&es_name).is_none() {
        eprintln!("--exec-stream must be retained or whole");
        return 2;
    }
    let fmt_name = flag(rest, "--fmt").unwrap_or_else(|| "old".into());
    let Some(fmt) = WFmt::parse(&fmt_name) else {
        eprintln!("--fmt must be old or p2r");
        return 2;
    };
    if fmt == WFmt::P2r && es_of(&es_name) != Some(ExecStream::Whole) {
        eprintln!("--fmt p2r supports only --exec-stream whole (the retained stream has no packed arm in w46)");
        return 2;
    }
    let limit_s: u64 = flag(rest, "--limit-s").and_then(|x| x.parse().ok()).unwrap_or(7200);
    for l in &layouts {
        if layout_of(l).is_none() {
            eprintln!("unknown layout {l}");
            return 2;
        }
    }
    if n == 0 || n % BLOCK != 0 {
        eprintln!("N must be a positive multiple of {BLOCK}");
        return 2;
    }
    let mut out = Out::open(&out_dir, has(rest, "--append"));
    write_env(&out.dir, setting.name, setting.hash, &format!("N: {n}, layouts {layouts:?}, runs per point {runs} (no warm-up, the cold run counts), exec-stream {es_name}, fmt {fmt_name}\n"));
    let mut all_ok = true;
    for l in &layouts {
        for run in 1..=runs {
            let args = vec!["child".to_string(), format!("setting={}", setting.name), format!("n={n}"), format!("layout={l}"), format!("run={run}"), format!("exec={es_name}"), format!("fmt={fmt_name}")];
            let mut key = Row::new();
            key.set("setting", setting.name).set("hash", setting.hash).set("n", n).set("layout", l).set("run", run).set("fmt", &fmt_name);
            all_ok &= run_child(&mut out, &args, &format!("w34 {} N={n} {l} fmt={fmt_name} run {run}", setting.name), &format!("{}-n{n}-{l}-{fmt_name}-run{run}.txt", setting.name), limit_s, key);
        }
    }
    if all_ok {
        0
    } else {
        1
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let code = match a.first().map(|s| s.as_str()) {
        Some("run") => driver_run(&a[1..]),
        Some("child") => child_run(&a[1..]),
        _ => {
            eprintln!("usage: w34 run|child (see the header of src/bin/w34.rs)");
            2
        }
    };
    std::process::exit(code);
}
