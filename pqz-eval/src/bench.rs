//! Benchmark harness and the Stage A experiment definitions.
//!
//! One CSV per experiment, raw rows only (no aggregation inside the harness).
//! Every query experiment gates the three approaches on the same selected set;
//! a mismatch aborts.

use std::fs::{self, File, OpenOptions};
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::eapat::{Block, BlockHeader, EpochKeys, aead_encrypt, encrypt_record, sign_header};
use crate::eapat::{leaf_hash, merkle_root, verify_chain};
use crate::he::HePool;
use crate::r#gen::r#gen;
use crate::search::{Bloom, Formula, Tag, bps_eval, formula_for, rps_eval, tags_for_record};
use crate::{Layout, Predicate, Record, sha3_256};

pub const DEFAULT_SEED: u64 = 0x5051_5A41_5544_4954;

pub const CSV_COLUMNS: &[&str] = &[
    "exp",
    "series",
    "n",
    "mb",
    "sigma",
    "layout",
    "predicate",
    "agg",
    "approach",
    "run",
    "warmup",
    "time_ns",
    "n_blocks",
    "n_retained_blocks",
    "n_cand",
    "n_sel",
    "bytes",
];

pub struct Options {
    pub name: String,
    pub n: Option<usize>,
    pub runs: usize,
    pub warmup: usize,
    pub out: PathBuf,
    pub smoke: bool,
    pub seed: u64,
    /// Print the full non-smoke grid instead of running anything.
    pub list: bool,
    /// Print the memory estimate for the largest N instead of running anything.
    pub estimate: bool,
}

struct Row {
    exp: &'static str,
    series: String,
    n: usize,
    mb: usize,
    sigma: f64,
    layout: &'static str,
    predicate: &'static str,
    agg: &'static str,
    approach: &'static str,
    run: usize,
    warmup: bool,
    time_ns: u128,
    n_blocks: usize,
    n_retained_blocks: usize,
    n_cand: usize,
    n_sel: usize,
    bytes: usize,
}

struct CsvWriter {
    w: BufWriter<File>,
    path: PathBuf,
}

impl CsvWriter {
    fn create(path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| {
                format!(
                    "cannot create {} (existing files are never overwritten): {e}",
                    path.display()
                )
            })?;
        let mut w = BufWriter::new(file);
        writeln!(w, "{}", CSV_COLUMNS.join(",")).map_err(|e| e.to_string())?;
        Ok(CsvWriter { w, path })
    }

    fn write(&mut self, r: &Row) -> Result<(), String> {
        writeln!(
            self.w,
            "{},{},{},{},{:.4},{},{},{},{},{},{},{},{},{},{},{},{}",
            r.exp,
            r.series,
            r.n,
            r.mb,
            r.sigma,
            r.layout,
            r.predicate,
            r.agg,
            r.approach,
            r.run,
            if r.warmup { 1 } else { 0 },
            r.time_ns,
            r.n_blocks,
            r.n_retained_blocks,
            r.n_cand,
            r.n_sel,
            r.bytes
        )
        .map_err(|e| e.to_string())
    }
}

fn seed_for(base: u64, parts: &[&str]) -> u64 {
    let mut buf = base.to_le_bytes().to_vec();
    for p in parts {
        buf.extend_from_slice(p.as_bytes());
        buf.push(0);
    }
    let h = sha3_256(&buf);
    u64::from_le_bytes(h[..8].try_into().expect("8 bytes"))
}

fn write_env(out: &Path, seed: u64) -> Result<(), String> {
    fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let cpu = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let rustc = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lock = fs::read(root.join("Cargo.lock")).map_err(|e| e.to_string())?;
    let lock_hash = hex(&sha3_256(&lock));
    let src_hash = hex(&hash_tree(&root.join("src"))?);

    let text = format!(
        "experiment_harness: pqz-eval Stage A\n\
         cpu_model: {cpu}\n\
         kernel: {kernel}\n\
         rustc: {rustc}\n\
         cargo_lock_sha3_256: {lock_hash}\n\
         src_sha3_256: {src_hash}\n\
         hash_note: SHA3-256 is used for both hashes (no sha2 dependency)\n\
         seed: {seed:#x}\n"
    );
    fs::write(out.join("env.txt"), text).map_err(|e| e.to_string())
}

fn hash_tree(dir: &Path) -> Result<[u8; 32], String> {
    let mut files = Vec::new();
    collect_files(dir, &mut files)?;
    files.sort();
    let mut buf = Vec::new();
    for f in files {
        let rel = f.strip_prefix(dir).map_err(|e| e.to_string())?;
        buf.extend_from_slice(rel.to_string_lossy().as_bytes());
        buf.push(0);
        buf.extend_from_slice(&fs::read(&f).map_err(|e| format!("{}: {e}", f.display()))?);
        buf.push(0);
    }
    Ok(sha3_256(&buf))
}

fn collect_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let p = entry.map_err(|e| e.to_string())?.path();
        if p.is_dir() {
            collect_files(&p, files)?;
        } else if p.is_file() {
            files.push(p);
        }
    }
    Ok(())
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

struct Data {
    records: Vec<Record>,
    keys: EpochKeys,
    blocks: Vec<Block>,
}

fn build_data(n: usize, sigma: usize, layout: Layout, mb: usize, seed: u64) -> Result<Data, String> {
    let records = r#gen(n, sigma, layout, seed);
    let keys = EpochKeys::from_seed(seed);
    let encs: Vec<_> = records.iter().map(|r| encrypt_record(&keys, r)).collect();
    let mut it = encs.into_iter();
    let mut blocks = Vec::new();
    let mut prev = [0u8; 32];
    loop {
        let chunk: Vec<_> = it.by_ref().take(mb).collect();
        if chunk.is_empty() {
            break;
        }
        let block = crate::eapat::build_block(blocks.len() as u64, chunk, prev, &keys);
        prev = block.header.hash();
        blocks.push(block);
    }
    Ok(Data {
        records,
        keys,
        blocks,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QueryApproach {
    TradScan,
    ProtFullScan,
    Pqz,
}

impl QueryApproach {
    fn name(self) -> &'static str {
        match self {
            QueryApproach::TradScan => "trad_scan",
            QueryApproach::ProtFullScan => "prot_full_scan",
            QueryApproach::Pqz => "pqz",
        }
    }
}

fn run_query(
    approach: QueryApproach,
    records: &[Record],
    blocks: &[Block],
    p: Predicate,
    f: &Formula,
) -> (Vec<u64>, usize, usize) {
    let mut out = Vec::new();
    let mut retained = 0usize;
    let mut cand = 0usize;
    match approach {
        QueryApproach::TradScan => {
            cand = records.len();
            for r in records {
                if p.matches(r) {
                    out.push(r.id);
                }
            }
        }
        QueryApproach::ProtFullScan => {
            cand = records.len();
            for b in blocks {
                for r in &b.records {
                    if rps_eval(&r.tags, f) {
                        out.push(r.id);
                    }
                }
            }
        }
        QueryApproach::Pqz => {
            for b in blocks {
                if bps_eval(&b.summary, f) {
                    retained += 1;
                    cand += b.records.len();
                    for r in &b.records {
                        if rps_eval(&r.tags, f) {
                            out.push(r.id);
                        }
                    }
                }
            }
        }
    }
    // all approaches visit records in id order, so no sort is needed in the timed region
    (out, retained, cand)
}

#[allow(clippy::too_many_arguments)]
fn run_queries(
    csv: &mut CsvWriter,
    exp: &'static str,
    series: &str,
    n: usize,
    mb: usize,
    sigma_count: usize,
    layout: Layout,
    p: Predicate,
    data: &Data,
    approaches: &[QueryApproach],
    runs: usize,
    warmup: usize,
) -> Result<(), String> {
    let f = formula_for(p, &data.keys.tag_key);
    let n_blocks = data.blocks.len();
    let sigma = sigma_count as f64 / n as f64;

    let (baseline, _, _) = run_query(QueryApproach::TradScan, &data.records, &data.blocks, p, &f);
    let plain_count = data.records.iter().filter(|r| p.matches(r)).count();
    if plain_count != sigma_count {
        return Err(format!(
            "generator/gate mismatch: {plain_count} hits, expected {sigma_count}"
        ));
    }
    if baseline.len() != sigma_count {
        return Err("traditional scan returned the wrong cardinality".into());
    }

    for &approach in approaches {
        let total = warmup + runs;
        for i in 0..total {
            let is_warmup = i < warmup;
            let run_no = if is_warmup { i } else { i - warmup };
            let t0 = Instant::now();
            let (sel, retained, cand) = run_query(approach, &data.records, &data.blocks, p, &f);
            let time_ns = t0.elapsed().as_nanos();
            black_box(&sel);
            if sel != baseline {
                return Err(format!(
                    "gate failed: {} selected {} records, trad_scan selected {}",
                    approach.name(),
                    sel.len(),
                    baseline.len()
                ));
            }
            csv.write(&Row {
                exp,
                series: series.to_string(),
                n,
                mb,
                sigma,
                layout: layout.name(),
                predicate: p.name(),
                agg: "none",
                approach: approach.name(),
                run: run_no,
                warmup: is_warmup,
                time_ns,
                n_blocks,
                n_retained_blocks: retained,
                n_cand: cand,
                n_sel: sel.len(),
                bytes: 0,
            })?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Agg {
    Count,
    Sum,
    Avg,
}

impl Agg {
    fn name(self) -> &'static str {
        match self {
            Agg::Count => "COUNT",
            Agg::Sum => "SUM",
            Agg::Avg => "AVG",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AggApproach {
    PlainAgg,
    FullHe,
    Pqz,
}

impl AggApproach {
    fn name(self) -> &'static str {
        match self {
            AggApproach::PlainAgg => "plain_agg",
            AggApproach::FullHe => "full_he",
            AggApproach::Pqz => "pqz",
        }
    }
}

const FULL_HE_MAX_RUNS: usize = 10;
const FULL_HE_MAX_WARMUP: usize = 1;

fn full_he_runs(runs: usize) -> usize {
    runs.min(FULL_HE_MAX_RUNS)
}

fn full_he_warmup(warmup: usize) -> usize {
    warmup.min(FULL_HE_MAX_WARMUP)
}

#[allow(clippy::too_many_arguments)]
fn run_aggregation(
    csv: &mut CsvWriter,
    exp: &'static str,
    series: &str,
    n: usize,
    mb: usize,
    predicate: Predicate,
    sigma_count: usize,
    layout: Layout,
    agg: Agg,
    records: &[Record],
    selected: &[&Record],
    pool: &HePool,
    approaches: &[AggApproach],
    runs: usize,
    warmup: usize,
) -> Result<(), String> {
    let value = |r: &Record| pool.pool_value(r.b);
    let plain_sum: u64 = selected.iter().map(|r| value(r)).sum();
    let total_sum: u64 = records.iter().map(value).sum();
    let sel_n = selected.len() as u64;
    let n_u64 = n as u64;

    let plain_result = match agg {
        Agg::Count => sel_n,
        Agg::Sum => plain_sum,
        Agg::Avg => {
            if sel_n == 0 {
                0
            } else {
                plain_sum / sel_n
            }
        }
    };
    let full_expected = match agg {
        Agg::Count => n_u64,
        Agg::Sum => total_sum,
        Agg::Avg => total_sum / n_u64,
    };

    if agg == Agg::Avg && sel_n == 0 {
        // the paper defines AVG for n_Q = 0 as undefined (bottom)
        return Err("AVG is undefined for n_Q = 0".into());
    }

    for &approach in approaches {
        let (approach_runs, approach_warmup) = if approach == AggApproach::FullHe {
            (full_he_runs(runs), full_he_warmup(warmup))
        } else {
            (runs, warmup)
        };
        let total = approach_warmup + approach_runs;
        for i in 0..total {
            let is_warmup = i < approach_warmup;
            let run_no = if is_warmup { i } else { i - approach_warmup };

            match approach {
                AggApproach::PlainAgg => {
                    let t0 = Instant::now();
                    let mut acc = 0u64;
                    match agg {
                        Agg::Count => {
                            for _ in selected {
                                acc += 1;
                            }
                        }
                        Agg::Sum | Agg::Avg => {
                            for r in selected {
                                acc += value(r);
                            }
                        }
                    }
                    let time_ns = t0.elapsed().as_nanos();
                    black_box(acc);
                    let expected_acc = match agg {
                        Agg::Count => sel_n,
                        Agg::Sum | Agg::Avg => plain_sum,
                    };
                    if acc != expected_acc {
                        return Err("plain_agg result mismatch".into());
                    }
                    csv.write(&Row {
                        exp,
                        series: series.to_string(),
                        n,
                        mb,
                        sigma: sigma_count as f64 / n as f64,
                        layout: layout.name(),
                        predicate: predicate.name(),
                        agg: agg.name(),
                        approach: approach.name(),
                        run: run_no,
                        warmup: is_warmup,
                        time_ns,
                        n_blocks: 0,
                        n_retained_blocks: 0,
                        // plain_agg reduces over the selected records, so it
                        // evaluates the same record-level set as pqz.
                        n_cand: selected.len(),
                        n_sel: selected.len(),
                        bytes: 0,
                    })?;
                }
                AggApproach::Pqz if agg == Agg::Count => {
                    // PQZ-Audit COUNT is the cardinality n_Q of the verified
                    // selected set: no HE aggregation and nothing to decrypt.
                    let t0 = Instant::now();
                    let card = black_box(selected).len() as u64;
                    let time_ns = t0.elapsed().as_nanos();
                    black_box(card);
                    if card != sigma_count as u64 || card != plain_result {
                        return Err(format!(
                            "pqz COUNT gate failed: cardinality {card}, generator promised {sigma_count}"
                        ));
                    }
                    csv.write(&Row {
                        exp,
                        series: series.to_string(),
                        n,
                        mb,
                        sigma: sigma_count as f64 / n as f64,
                        layout: layout.name(),
                        predicate: predicate.name(),
                        agg: agg.name(),
                        approach: approach.name(),
                        run: run_no,
                        warmup: is_warmup,
                        time_ns,
                        n_blocks: 0,
                        n_retained_blocks: 0,
                        n_cand: selected.len(),
                        n_sel: selected.len(),
                        bytes: 0,
                    })?;
                }
                AggApproach::FullHe | AggApproach::Pqz => {
                    let source: Vec<&Record> = if approach == AggApproach::FullHe {
                        // Aggregating every record is the no-filter baseline.
                        records.iter().collect()
                    } else {
                        selected.to_vec()
                    };
                    let t0 = Instant::now();
                    let mut acc = pool.zero();
                    match agg {
                        Agg::Count => {
                            for _ in source {
                                acc += pool.one();
                            }
                        }
                        Agg::Sum | Agg::Avg => {
                            for r in source {
                                acc += pool.ct_for_b(r.b);
                            }
                        }
                    }
                    let time_ns = t0.elapsed().as_nanos();
                    black_box(&acc);

                    let got = pool.decrypt(&acc)?;
                    let expected = if approach == AggApproach::FullHe {
                        full_expected
                    } else {
                        plain_result
                    };
                    let got_result = match agg {
                        Agg::Avg => {
                            let d = if approach == AggApproach::FullHe {
                                n_u64
                            } else {
                                sel_n
                            };
                            if d == 0 { 0 } else { got / d }
                        }
                        _ => got,
                    };
                    if got_result != expected {
                        return Err(format!(
                            "HE gate failed for {} {}: got {got_result}, expected {expected}",
                            approach.name(),
                            agg.name()
                        ));
                    }

                    csv.write(&Row {
                        exp,
                        series: series.to_string(),
                        n,
                        mb,
                        sigma: sigma_count as f64 / n as f64,
                        layout: layout.name(),
                        predicate: predicate.name(),
                        agg: agg.name(),
                        approach: approach.name(),
                        run: run_no,
                        warmup: is_warmup,
                        time_ns,
                        n_blocks: 0,
                        n_retained_blocks: 0,
                        n_cand: if approach == AggApproach::FullHe {
                            n
                        } else {
                            selected.len()
                        },
                        n_sel: selected.len(),
                        bytes: 0,
                    })?;
                }
            }
        }
    }
    Ok(())
}

const EXP3C_NS: [usize; 5] = [10_000, 50_000, 100_000, 500_000, 1_000_000];
const EXP3C_MB: usize = 500;

/// Untimed set gate for `exp3c`: the three query approaches (trad_scan,
/// prot_full_scan, pqz with BPS then RPS) must return the same ids for P1, and
/// that set must have the generated cardinality. The aggregation approaches
/// then reduce over exactly this set (plain_agg and pqz) or over all records
/// (full_he), as in exp3a.
fn exp3c_selected_set(data: &Data, sigma_count: usize) -> Result<Vec<&Record>, String> {
    let p = Predicate::P1;
    let f = formula_for(p, &data.keys.tag_key);
    let (base, _, _) = run_query(QueryApproach::TradScan, &data.records, &data.blocks, p, &f);
    for approach in [QueryApproach::ProtFullScan, QueryApproach::Pqz] {
        let (ids, _, _) = run_query(approach, &data.records, &data.blocks, p, &f);
        if ids != base {
            return Err(format!(
                "exp3c set gate failed: {} selected {} records, trad_scan selected {}",
                approach.name(),
                ids.len(),
                base.len()
            ));
        }
    }
    if base.len() != sigma_count {
        return Err(format!(
            "exp3c: {} records selected, generator promised {sigma_count}",
            base.len()
        ));
    }
    // records are in id order and so is `base`, so one forward pass maps ids to records
    let mut want = base.iter().peekable();
    let selected: Vec<&Record> = data
        .records
        .iter()
        .filter(|r| {
            if want.peek() == Some(&&r.id) {
                want.next();
                true
            } else {
                false
            }
        })
        .collect();
    if selected.len() != sigma_count {
        return Err("exp3c: selected ids not found among records".into());
    }
    Ok(selected)
}

fn sigma_for(n: usize, pct: f64) -> usize {
    ((n as f64) * pct / 100.0).round() as usize
}

pub fn run(opts: &Options) -> Result<Vec<PathBuf>, String> {
    fs::create_dir_all(&opts.out).map_err(|e| format!("{}: {e}", opts.out.display()))?;
    write_env(&opts.out, opts.seed)?;
    let csv_path = opts.out.join(format!("{}.csv", opts.name));
    let mut csv = CsvWriter::create(csv_path.clone())?;
    let base = opts.seed;

    println!("# pqz-eval Stage A: {} (smoke={})", opts.name, opts.smoke);
    println!(
        "# seed={base:#x} runs={} warmup={} out={}",
        opts.runs,
        opts.warmup,
        opts.out.display()
    );
    if opts.name == "exp3a" || opts.name == "exp3b" || opts.name == "exp3c" {
        println!(
            "# full_he reduced to {} runs, see FULL-RUN-PLAN.md",
            full_he_runs(opts.runs)
        );
    }

    match opts.name.as_str() {
        "exp1" => {
            let ns = if opts.smoke {
                vec![2000]
            } else if let Some(n) = opts.n {
                vec![n]
            } else {
                vec![10_000, 50_000, 100_000, 500_000, 1_000_000]
            };
            for n in ns {
                for (series, sigma) in [
                    ("sigma1pct", n / 100),
                    ("fixed_nq1000", 1000.min(n)),
                ] {
                    let seed = seed_for(base, &["exp1", series, &n.to_string()]);
                    println!("# exp1 n={n} series={series} sigma={sigma}");
                    let data = build_data(n, sigma, Layout::Clustered, 500, seed)?;
                    run_queries(
                        &mut csv,
                        "exp1",
                        series,
                        n,
                        500,
                        sigma,
                        Layout::Clustered,
                        Predicate::P4,
                        &data,
                        &[QueryApproach::Pqz],
                        opts.runs,
                        opts.warmup,
                    )?;
                }
            }
        }
        "exp2a" => {
            let n = opts.n.unwrap_or(1_000_000);
            let sigma = n / 100;
            for layout in [Layout::Clustered, Layout::Scattered] {
                let seed = seed_for(base, &["exp2a", layout.name()]);
                println!("# exp2a n={n} sigma_count={sigma} layout={}", layout.name());
                let data = build_data(n, sigma, layout, 500, seed)?;
                for p in Predicate::ALL {
                    run_queries(
                        &mut csv,
                        "exp2a",
                        "main",
                        n,
                        500,
                        sigma,
                        layout,
                        p,
                        &data,
                        &[
                            QueryApproach::TradScan,
                            QueryApproach::ProtFullScan,
                            QueryApproach::Pqz,
                        ],
                        opts.runs,
                        opts.warmup,
                    )?;
                }
            }
        }
        "exp2b" => {
            let n = opts.n.unwrap_or(1_000_000);
            let pcts: &[f64] = if opts.smoke {
                &[0.1, 1.0, 10.0, 25.0]
            } else {
                &[0.1, 1.0, 5.0, 10.0, 25.0]
            };
            for layout in [Layout::Clustered, Layout::Scattered] {
                for &pct in pcts {
                    let sigma = sigma_for(n, pct);
                    let seed = seed_for(
                        base,
                        &["exp2b", layout.name(), &format!("{pct}"), &n.to_string()],
                    );
                    println!(
                        "# exp2b n={n} sigma={pct}% ({sigma}) layout={}",
                        layout.name()
                    );
                    let data = build_data(n, sigma, layout, 500, seed)?;
                    run_queries(
                        &mut csv,
                        "exp2b",
                        "sigma",
                        n,
                        500,
                        sigma,
                        layout,
                        Predicate::P4,
                        &data,
                        &[
                            QueryApproach::TradScan,
                            QueryApproach::ProtFullScan,
                            QueryApproach::Pqz,
                        ],
                        opts.runs,
                        opts.warmup,
                    )?;
                }
            }
        }
        "exp2c" => {
            let n = opts.n.unwrap_or(1_000_000);
            let sigma = n / 100;
            for layout in [Layout::Clustered, Layout::Scattered] {
                for mb in [100usize, 250, 500, 1000] {
                    let seed = seed_for(
                        base,
                        &["exp2c", layout.name(), &mb.to_string(), &n.to_string()],
                    );
                    println!("# exp2c n={n} mb={mb} layout={}", layout.name());
                    let data = build_data(n, sigma, layout, mb, seed)?;
                    run_queries(
                        &mut csv,
                        "exp2c",
                        "mb",
                        n,
                        mb,
                        sigma,
                        layout,
                        Predicate::P4,
                        &data,
                        &[
                            QueryApproach::TradScan,
                            QueryApproach::ProtFullScan,
                            QueryApproach::Pqz,
                        ],
                        opts.runs,
                        opts.warmup,
                    )?;
                }
            }
        }
        "exp3a" => {
            let n = opts.n.unwrap_or(1_000_000);
            let pool = HePool::new(seed_for(base, &["exp3a", "he-pool"]))?;
            print_he_header(&pool);
            let pcts: &[f64] = if opts.smoke {
                &[1.0]
            } else {
                &[0.1, 1.0, 5.0, 10.0, 25.0]
            };
            for &pct in pcts {
                let sigma = sigma_for(n, pct);
                let seed = seed_for(base, &["exp3a", &format!("{pct}"), &n.to_string()]);
                println!("# exp3a n={n} sigma={pct}% ({sigma})");
                let records = r#gen(n, sigma, Layout::Clustered, seed);
                let selected: Vec<&Record> = records
                    .iter()
                    .filter(|r| Predicate::P4.matches(r))
                    .collect();
                run_aggregation(
                    &mut csv,
                    "exp3a",
                    "sigma",
                    n,
                    0,
                    Predicate::P4,
                    sigma,
                    Layout::Clustered,
                    Agg::Sum,
                    &records,
                    &selected,
                    &pool,
                    &[
                        AggApproach::PlainAgg,
                        AggApproach::FullHe,
                        AggApproach::Pqz,
                    ],
                    opts.runs,
                    opts.warmup,
                )?;
            }
        }
        "exp3b" => {
            let n = opts.n.unwrap_or(1_000_000);
            let sigma = sigma_for(n, 1.0);
            let pool = HePool::new(seed_for(base, &["exp3b", "he-pool"]))?;
            print_he_header(&pool);
            let seed = seed_for(base, &["exp3b", &n.to_string()]);
            let records = r#gen(n, sigma, Layout::Clustered, seed);
            let selected: Vec<&Record> =
                records.iter().filter(|r| Predicate::P4.matches(r)).collect();
            println!("# exp3b n={n} sigma=1% ({sigma}) aggs=COUNT,SUM,AVG");
            for agg in [Agg::Count, Agg::Sum, Agg::Avg] {
                run_aggregation(
                    &mut csv,
                    "exp3b",
                    "agg",
                    n,
                    0,
                    Predicate::P4,
                    sigma,
                    Layout::Clustered,
                    agg,
                    &records,
                    &selected,
                    &pool,
                    &[
                        AggApproach::PlainAgg,
                        AggApproach::FullHe,
                        AggApproach::Pqz,
                    ],
                    opts.runs,
                    opts.warmup,
                )?;
            }
        }
        "exp3c" => {
            let ns = if opts.smoke {
                vec![2000]
            } else if let Some(n) = opts.n {
                vec![n]
            } else {
                EXP3C_NS.to_vec()
            };
            let pool = HePool::new(seed_for(base, &["exp3c", "he-pool"]))?;
            print_he_header(&pool);
            for n in ns {
                let sigma = sigma_for(n, 1.0);
                for layout in [Layout::Clustered, Layout::Scattered] {
                    let seed = seed_for(base, &["exp3c", layout.name(), &n.to_string()]);
                    println!(
                        "# exp3c n={n} mb={EXP3C_MB} sigma=1% ({sigma}) layout={} predicate=P1 agg=SUM",
                        layout.name()
                    );
                    let data = build_data(n, sigma, layout, EXP3C_MB, seed)?;
                    let selected = exp3c_selected_set(&data, sigma)?;
                    run_aggregation(
                        &mut csv,
                        "exp3c",
                        "n_sweep",
                        n,
                        EXP3C_MB,
                        Predicate::P1,
                        sigma,
                        layout,
                        Agg::Sum,
                        &data.records,
                        &selected,
                        &pool,
                        &[
                            AggApproach::PlainAgg,
                            AggApproach::FullHe,
                            AggApproach::Pqz,
                        ],
                        opts.runs,
                        opts.warmup,
                    )?;
                }
            }
        }
        "exp3d" => {
            // Same path as exp3a (plaintext P4 filter, no log, mb=0 in the rows)
            // with agg=COUNT; full_he is left out on purpose (its cost does not
            // depend on selectivity).
            let n = opts.n.unwrap_or(1_000_000);
            let pool = HePool::new(seed_for(base, &["exp3d", "he-pool"]))?;
            print_he_header(&pool);
            let pcts: &[f64] = if opts.smoke { &[1.0] } else { &EXP2B_PCTS };
            for &pct in pcts {
                let sigma = sigma_for(n, pct);
                let seed = seed_for(base, &["exp3d", &format!("{pct}"), &n.to_string()]);
                println!("# exp3d n={n} sigma={pct}% ({sigma}) predicate=P4 agg=COUNT");
                let records = r#gen(n, sigma, Layout::Clustered, seed);
                let selected: Vec<&Record> = records
                    .iter()
                    .filter(|r| Predicate::P4.matches(r))
                    .collect();
                if selected.len() != sigma {
                    return Err(format!(
                        "exp3d: {} records selected, generator promised {sigma}",
                        selected.len()
                    ));
                }
                run_aggregation(
                    &mut csv,
                    "exp3d",
                    "count_sweep",
                    n,
                    0,
                    Predicate::P4,
                    sigma,
                    Layout::Clustered,
                    Agg::Count,
                    &records,
                    &selected,
                    &pool,
                    &[AggApproach::PlainAgg, AggApproach::Pqz],
                    opts.runs,
                    opts.warmup,
                )?;
            }
        }
        // ---- Dense sweeps (new names; the experiments above are unchanged) ----
        "exp1d" => {
            // Same code path as exp1 (P4, mb=500, clustered, pqz only, two series),
            // with the denser N grid DENSE_EXP1_NS.
            let ns = if opts.smoke {
                vec![2000]
            } else if let Some(n) = opts.n {
                vec![n]
            } else {
                DENSE_EXP1_NS.to_vec()
            };
            for n in ns {
                for (series, sigma) in [
                    ("sigma1pct", n / 100),
                    ("fixed_nq1000", 1000.min(n)),
                ] {
                    let seed = seed_for(base, &["exp1d", series, &n.to_string()]);
                    println!("# exp1d n={n} series={series} sigma={sigma}");
                    let data = build_data(n, sigma, Layout::Clustered, 500, seed)?;
                    run_queries(
                        &mut csv,
                        "exp1d",
                        series,
                        n,
                        500,
                        sigma,
                        Layout::Clustered,
                        Predicate::P4,
                        &data,
                        &[QueryApproach::Pqz],
                        opts.runs,
                        opts.warmup,
                    )?;
                }
            }
        }
        "exp2bd" => {
            // Same code path as exp2b (selectivity sweep, P4, mb=500, both layouts,
            // trad_scan / prot_full_scan / pqz) with the denser DENSE_PCTS grid.
            let n = opts.n.unwrap_or(1_000_000);
            let pcts: &[f64] = if opts.smoke {
                &[0.2, 2.0, 15.0]
            } else {
                &DENSE_PCTS
            };
            for layout in [Layout::Clustered, Layout::Scattered] {
                for &pct in pcts {
                    let sigma = sigma_for(n, pct);
                    let seed = seed_for(
                        base,
                        &["exp2bd", layout.name(), &format!("{pct}"), &n.to_string()],
                    );
                    println!(
                        "# exp2bd n={n} sigma={pct}% ({sigma}) layout={}",
                        layout.name()
                    );
                    let data = build_data(n, sigma, layout, 500, seed)?;
                    run_queries(
                        &mut csv,
                        "exp2bd",
                        "sigma",
                        n,
                        500,
                        sigma,
                        layout,
                        Predicate::P4,
                        &data,
                        &[
                            QueryApproach::TradScan,
                            QueryApproach::ProtFullScan,
                            QueryApproach::Pqz,
                        ],
                        opts.runs,
                        opts.warmup,
                    )?;
                }
            }
        }
        "exp3ad" => {
            // Same path as exp3a (plaintext P4 filter, no log, mb=0, agg=SUM) with the
            // denser DENSE_PCTS grid. full_he is left out on purpose (about 102 s per
            // run, and its cost does not depend on selectivity); the 10-run full_he
            // data of exp3a is kept.
            let n = opts.n.unwrap_or(1_000_000);
            let pool = HePool::new(seed_for(base, &["exp3ad", "he-pool"]))?;
            print_he_header(&pool);
            let pcts: &[f64] = if opts.smoke {
                &[1.0]
            } else {
                &DENSE_PCTS
            };
            for &pct in pcts {
                let sigma = sigma_for(n, pct);
                let seed = seed_for(base, &["exp3ad", &format!("{pct}"), &n.to_string()]);
                println!("# exp3ad n={n} sigma={pct}% ({sigma}) predicate=P4 agg=SUM");
                let records = r#gen(n, sigma, Layout::Clustered, seed);
                let selected: Vec<&Record> = records
                    .iter()
                    .filter(|r| Predicate::P4.matches(r))
                    .collect();
                if selected.len() != sigma {
                    return Err(format!(
                        "exp3ad: {} records selected, generator promised {sigma}",
                        selected.len()
                    ));
                }
                run_aggregation(
                    &mut csv,
                    "exp3ad",
                    "sigma",
                    n,
                    0,
                    Predicate::P4,
                    sigma,
                    Layout::Clustered,
                    Agg::Sum,
                    &records,
                    &selected,
                    &pool,
                    &[AggApproach::PlainAgg, AggApproach::Pqz],
                    opts.runs,
                    opts.warmup,
                )?;
            }
        }
        "exp1_construction" => {
            let n = opts.n.unwrap_or(1_000_000);
            let sigma = n / 100;
            let mb = 500;
            let seed = seed_for(base, &["exp1_construction", &n.to_string()]);
            println!("# exp1_construction n={n} mb={mb} sigma_count={sigma}");
            construction_experiment(&mut csv, n, sigma, mb, seed, opts.runs)?;
        }
        other => return Err(format!("unknown experiment: {other}")),
    }

    csv.w
        .flush()
        .map_err(|e| format!("{}: {e}", csv.path.display()))?;
    println!("# wrote {}", csv.path.display());
    Ok(vec![csv.path])
}

/// Every experiment name accepted by [`run`], [`list`] and [`estimate`].
pub const EXPERIMENTS: &[&str] = &[
    "exp1",
    "exp2a",
    "exp2b",
    "exp2c",
    "exp3a",
    "exp3b",
    "exp3c",
    "exp3d",
    "exp1_construction",
];

const QUERY_APPROACHES: [&str; 3] = ["trad_scan", "prot_full_scan", "pqz"];
const AGG_APPROACHES: [&str; 3] = ["plain_agg", "full_he", "pqz"];
const EXP2B_PCTS: [f64; 5] = [0.1, 1.0, 5.0, 10.0, 25.0];

/// Dense-sweep experiments (new names). They are NOT in [`EXPERIMENTS`], so
/// `exp all --list|--estimate` stays exactly as before; they are accepted by
/// name in [`run`], [`list`] and [`estimate`].
pub const DENSE_EXPERIMENTS: &[&str] = &["exp1d", "exp2bd", "exp3ad"];
const DENSE_EXP1_NS: [usize; 7] = [10_000, 20_000, 50_000, 100_000, 200_000, 500_000, 1_000_000];
const DENSE_PCTS: [f64; 9] = [0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 15.0, 25.0];

fn canonical(name: &str) -> Option<&'static str> {
    EXPERIMENTS
        .iter()
        .chain(DENSE_EXPERIMENTS.iter())
        .copied()
        .find(|&e| e == name)
}

/// One point of the full (non-smoke) experiment grid: one CSV series for one
/// approach. `runs` is the number of measured runs (warmups are extra).
#[derive(Clone, Debug)]
pub struct GridPoint {
    pub name: &'static str,
    pub n: usize,
    pub mb: usize,
    pub sigma: f64,
    pub layout: &'static str,
    pub predicate: &'static str,
    pub approach: String,
    pub runs: usize,
}

#[allow(clippy::too_many_arguments)]
fn point(
    name: &'static str,
    n: usize,
    mb: usize,
    sigma_count: usize,
    layout: &'static str,
    predicate: &'static str,
    approach: impl Into<String>,
    runs: usize,
) -> GridPoint {
    GridPoint {
        name,
        n,
        mb,
        sigma: sigma_count as f64 / n as f64,
        layout,
        predicate,
        approach: approach.into(),
        runs,
    }
}

/// The complete grid that `run` executes without `--smoke` or `--n`.
///
/// The `--list` schema has no `series` and no `agg` column. `exp1` therefore
/// prints its two series as distinct rows that can coincide numerically
/// (`sigma1pct` and `fixed_nq1000` both select 1000 records at n=100000), and
/// `exp3b` appends the aggregate to the approach (`plain_agg:COUNT`) so the
/// nine points are distinguishable.
pub fn full_grid(name: &str, runs: usize) -> Result<Vec<GridPoint>, String> {
    let name = canonical(name).ok_or_else(|| format!("unknown experiment: {name}"))?;
    let mut out = Vec::new();
    match name {
        "exp1" => {
            let mb = 500;
            for n in [10_000usize, 50_000, 100_000, 500_000, 1_000_000] {
                for sigma_count in [n / 100, 1000.min(n)] {
                    out.push(point(
                        name,
                        n,
                        mb,
                        sigma_count,
                        "clustered",
                        "P4",
                        "pqz",
                        runs,
                    ));
                }
            }
        }
        "exp2a" => {
            let n = 1_000_000;
            let sigma_count = n / 100;
            for layout in ["clustered", "scattered"] {
                for predicate in ["P1", "P2", "P3", "P4"] {
                    for approach in QUERY_APPROACHES {
                        out.push(point(
                            name,
                            n,
                            500,
                            sigma_count,
                            layout,
                            predicate,
                            approach,
                            runs,
                        ));
                    }
                }
            }
        }
        "exp2b" => {
            let n = 1_000_000;
            for layout in ["clustered", "scattered"] {
                for pct in EXP2B_PCTS {
                    let sigma_count = sigma_for(n, pct);
                    for approach in QUERY_APPROACHES {
                        out.push(point(
                            name,
                            n,
                            500,
                            sigma_count,
                            layout,
                            "P4",
                            approach,
                            runs,
                        ));
                    }
                }
            }
        }
        "exp2c" => {
            let n = 1_000_000;
            let sigma_count = n / 100;
            for layout in ["clustered", "scattered"] {
                for mb in [100usize, 250, 500, 1000] {
                    for approach in QUERY_APPROACHES {
                        out.push(point(
                            name,
                            n,
                            mb,
                            sigma_count,
                            layout,
                            "P4",
                            approach,
                            runs,
                        ));
                    }
                }
            }
        }
        "exp1d" => {
            let mb = 500;
            for n in DENSE_EXP1_NS {
                for sigma_count in [n / 100, 1000.min(n)] {
                    out.push(point(
                        name,
                        n,
                        mb,
                        sigma_count,
                        "clustered",
                        "P4",
                        "pqz",
                        runs,
                    ));
                }
            }
        }
        "exp2bd" => {
            let n = 1_000_000;
            for layout in ["clustered", "scattered"] {
                for pct in DENSE_PCTS {
                    let sigma_count = sigma_for(n, pct);
                    for approach in QUERY_APPROACHES {
                        out.push(point(
                            name,
                            n,
                            500,
                            sigma_count,
                            layout,
                            "P4",
                            approach,
                            runs,
                        ));
                    }
                }
            }
        }
        "exp3ad" => {
            let n = 1_000_000;
            for pct in DENSE_PCTS {
                let sigma_count = sigma_for(n, pct);
                for approach in ["plain_agg", "pqz"] {
                    out.push(point(
                        name,
                        n,
                        0,
                        sigma_count,
                        "clustered",
                        "P4",
                        approach,
                        runs,
                    ));
                }
            }
        }
        "exp3a" => {
            let n = 1_000_000;
            for pct in EXP2B_PCTS {
                let sigma_count = sigma_for(n, pct);
                for approach in AGG_APPROACHES {
                    let approach_runs = if approach == "full_he" {
                        full_he_runs(runs)
                    } else {
                        runs
                    };
                    out.push(point(
                        name,
                        n,
                        0,
                        sigma_count,
                        "clustered",
                        "P4",
                        approach,
                        approach_runs,
                    ));
                }
            }
        }
        "exp3b" => {
            let n = 1_000_000;
            let sigma_count = sigma_for(n, 1.0);
            for agg in ["COUNT", "SUM", "AVG"] {
                for approach in AGG_APPROACHES {
                    let approach_runs = if approach == "full_he" {
                        full_he_runs(runs)
                    } else {
                        runs
                    };
                    out.push(point(
                        name,
                        n,
                        0,
                        sigma_count,
                        "clustered",
                        "P4",
                        format!("{approach}:{agg}"),
                        approach_runs,
                    ));
                }
            }
        }
        "exp3c" => {
            for n in EXP3C_NS {
                let sigma_count = sigma_for(n, 1.0);
                for layout in ["clustered", "scattered"] {
                    for approach in AGG_APPROACHES {
                        let approach_runs = if approach == "full_he" {
                            full_he_runs(runs)
                        } else {
                            runs
                        };
                        out.push(point(
                            name,
                            n,
                            EXP3C_MB,
                            sigma_count,
                            layout,
                            "P1",
                            approach,
                            approach_runs,
                        ));
                    }
                }
            }
        }
        "exp3d" => {
            let n = 1_000_000;
            for pct in EXP2B_PCTS {
                let sigma_count = sigma_for(n, pct);
                for approach in ["plain_agg", "pqz"] {
                    out.push(point(
                        name,
                        n,
                        0,
                        sigma_count,
                        "clustered",
                        "P4",
                        approach,
                        runs,
                    ));
                }
            }
        }
        "exp1_construction" => {
            let n = 1_000_000;
            let sigma_count = n / 100;
            for series in [
                "aead",
                "tags",
                "bloom",
                "merkle",
                "signature",
                "total",
                "storage_record",
                "storage_total",
                "storage_block_overhead",
            ] {
                out.push(point(
                    name,
                    n,
                    500,
                    sigma_count,
                    "clustered",
                    "P4",
                    series,
                    1,
                ));
            }
        }
        _ => unreachable!("canonical name"),
    }
    Ok(out)
}

/// Print the full non-smoke grid as
/// `name,n,mb,sigma,layout,predicate,approach,runs` rows, without running
/// anything. `name = "all"` prints every experiment.
pub fn list(opts: &Options) -> Result<(), String> {
    let names: Vec<&'static str> = if opts.name == "all" {
        EXPERIMENTS.to_vec()
    } else {
        vec![canonical(&opts.name)
            .ok_or_else(|| format!("unknown experiment: {}", opts.name))?]
    };
    println!("name,n,mb,sigma,layout,predicate,approach,runs");
    for name in names {
        for p in full_grid(name, opts.runs)? {
            println!(
                "{},{},{},{:.4},{},{},{},{}",
                p.name, p.n, p.mb, p.sigma, p.layout, p.predicate, p.approach, p.runs
            );
        }
    }
    Ok(())
}

/// Actual bytes held by the structures of one built data set. Counts use
/// `size_of` for the structs and `capacity`/`len` for the owned buffers; it is
/// not a guess and it is not RSS.
struct MemUse {
    records: usize,
    ciphertexts: usize,
    tags: usize,
    blocks: usize,
    blooms: usize,
}

impl MemUse {
    fn log(&self) -> usize {
        self.ciphertexts + self.tags + self.blocks + self.blooms
    }

    fn total(&self) -> usize {
        self.records + self.log()
    }
}

fn measure(data: &Data) -> MemUse {
    let records = data.records.capacity() * size_of::<Record>();
    let mut ciphertexts = 0usize;
    let mut tags = 0usize;
    let mut blooms = 0usize;
    let mut blocks = data.blocks.capacity() * size_of::<Block>();
    for b in &data.blocks {
        blocks += b.records.capacity() * size_of::<crate::eapat::EncryptedRecord>();
        blocks += b.signature.capacity();
        for r in &b.records {
            ciphertexts += r.ciphertext.capacity();
            tags += r.tags.capacity() * size_of::<Tag>();
        }
        blooms += b.summary.heap_bytes();
    }
    MemUse {
        records,
        ciphertexts,
        tags,
        blocks,
        blooms,
    }
}

/// Largest N of each experiment's full grid. Every Stage A experiment tops out
/// at 10^6, so the estimate builds that size with the default block size and a
/// 1% predicate hit rate.
fn estimate_config(name: &str) -> Result<(&'static str, usize, usize, usize), String> {
    let name = canonical(name).ok_or_else(|| format!("unknown experiment: {name}"))?;
    Ok((name, 1_000_000, 500, 10_000))
}

/// Print the memory estimate for the largest N of an experiment (or of every
/// experiment with `name = "all"`). Builds the real structures, then measures
/// them; nothing is run or timed as an experiment.
pub fn estimate(opts: &Options) -> Result<(), String> {
    let names: Vec<&'static str> = if opts.name == "all" {
        EXPERIMENTS.to_vec()
    } else {
        vec![canonical(&opts.name)
            .ok_or_else(|| format!("unknown experiment: {}", opts.name))?]
    };
    for name in names {
        estimate_one(name, opts.seed)?;
    }
    Ok(())
}

fn estimate_one(name: &'static str, base: u64) -> Result<(), String> {
    let (name, n, mb, sigma_count) = estimate_config(name)?;
    let seed = seed_for(base, &[name, "estimate", &n.to_string()]);
    println!(
        "# estimate {name}: largest_n={n} mb={mb} sigma_count={sigma_count} \
         layout=clustered predicate=P4"
    );
    println!("# sizes are computed from the real structs (size_of + lengths/capacities)");
    let t0 = Instant::now();
    let data = build_data(n, sigma_count, Layout::Clustered, mb, seed)?;
    let mem = measure(&data);
    println!("# built in {:.3} s", t0.elapsed().as_secs_f64());
    println!("records_bytes={}", mem.records);
    println!("ciphertext_bytes={}", mem.ciphertexts);
    println!("tag_bytes={}", mem.tags);
    println!("block_bytes={}", mem.blocks);
    println!("bloom_bytes={}", mem.blooms);
    println!("log_bytes={}", mem.log());
    let total = mem.total();
    println!(
        "total_bytes={total} ({:.3} GiB / {:.3} GB)",
        total as f64 / (1024.0 * 1024.0 * 1024.0),
        total as f64 / 1e9
    );
    if name == "exp3a"
        || name == "exp3b"
        || name == "exp3c"
        || name == "exp3d"
        || name == "exp3ad"
    {
        let pool_seed = seed_for(base, &[name, "estimate-pool"]);
        let pool = HePool::new(pool_seed)?;
        let pool_bytes = pool.serialized_bytes();
        println!("he_pool_bytes={pool_bytes} (serialized pool ciphertexts and keys)");
        println!("total_with_he_pool_bytes={}", total + pool_bytes);
    }
    Ok(())
}

fn print_he_header(pool: &HePool) {
    println!("# HE pool: {}", pool.describe());
    println!(
        "# HE limitation: pool slot j encrypts j; HE adds aggregate (b mod K), not b. \
         plain_agg uses the same pool values so the gate is exact. full_he aggregates \
         all N records (no query filter), so it is not expected to equal pqz."
    );
}

fn construction_experiment(
    csv: &mut CsvWriter,
    n: usize,
    sigma: usize,
    mb: usize,
    seed: u64,
    _runs: usize,
) -> Result<(), String> {
    let records = r#gen(n, sigma, Layout::Clustered, seed);
    let keys = EpochKeys::from_seed(seed);

    let t0 = Instant::now();
    let cts: Vec<Vec<u8>> = records.iter().map(|r| aead_encrypt(&keys, r)).collect();
    let t_aead = t0.elapsed().as_nanos();
    black_box(&cts);

    let t0 = Instant::now();
    let tag_vecs: Vec<Vec<Tag>> = records
        .iter()
        .map(|r| tags_for_record(r, &keys.tag_key))
        .collect();
    let t_tags = t0.elapsed().as_nanos();
    black_box(&tag_vecs);

    let encs: Vec<_> = records
        .iter()
        .zip(cts.iter())
        .zip(tag_vecs.iter())
        .map(|((r, ct), tags)| crate::eapat::EncryptedRecord {
            id: r.id,
            ts: r.ts,
            ciphertext: ct.clone(),
            tags: tags.clone(),
        })
        .collect();

    let mut blocks = Vec::new();
    let mut prev = [0u8; 32];
    let mut t_bloom = 0u128;
    let mut t_merkle = 0u128;
    let mut t_sig = 0u128;
    let mut it = encs.into_iter();
    loop {
        let chunk: Vec<_> = it.by_ref().take(mb).collect();
        if chunk.is_empty() {
            break;
        }
        let t0 = Instant::now();
        let summary = Bloom::build(chunk.len(), chunk.iter().flat_map(|r| r.tags.iter()));
        let summary_digest = summary.digest();
        t_bloom += t0.elapsed().as_nanos();

        let t0 = Instant::now();
        let leaves: Vec<[u8; 32]> = chunk.iter().map(leaf_hash).collect();
        let root = merkle_root(&leaves);
        t_merkle += t0.elapsed().as_nanos();

        let header = BlockHeader {
            block_index: blocks.len() as u64,
            count: chunk.len() as u32,
            merkle_root: root,
            summary_digest,
            prev_header_hash: prev,
        };
        let t0 = Instant::now();
        let signature = sign_header(&keys, &header);
        t_sig += t0.elapsed().as_nanos();
        prev = header.hash();
        blocks.push(Block {
            header,
            summary,
            records: chunk,
            signature,
        });
    }

    verify_chain(&blocks, &keys).map_err(|e| format!("construction chain invalid: {e}"))?;

    let t_total = t_aead + t_tags + t_bloom + t_merkle + t_sig;
    let per = |t: u128| t / n as u128;
    let base_row = |approach: &'static str, series: &'static str, time_ns: u128, bytes: usize| Row {
        exp: "exp1_construction",
        series: series.to_string(),
        n,
        mb,
        sigma: sigma as f64 / n as f64,
        layout: Layout::Clustered.name(),
        predicate: Predicate::P4.name(),
        agg: "none",
        approach,
        run: 0,
        warmup: false,
        time_ns,
        n_blocks: blocks.len(),
        n_retained_blocks: 0,
        n_cand: 0,
        n_sel: 0,
        bytes,
    };

    csv.write(&base_row("aead", "per_record", per(t_aead), 0))?;
    csv.write(&base_row("tags", "per_record", per(t_tags), 0))?;
    csv.write(&base_row("bloom", "per_record", per(t_bloom), 0))?;
    csv.write(&base_row("merkle", "per_record", per(t_merkle), 0))?;
    csv.write(&base_row("signature", "per_record", per(t_sig), 0))?;
    csv.write(&base_row("total", "per_record", per(t_total), 0))?;

    let record_bytes: usize = blocks
        .iter()
        .flat_map(|b| b.records.iter())
        .map(|r| 8 + 8 + r.ciphertext.len() + r.tags.len() * 16 + 32)
        .sum();
    let overhead_bytes: usize = blocks
        .iter()
        .map(|b| b.header.to_bytes().len() + b.signature.len() + b.summary.bytes())
        .sum();
    let n_blocks = blocks.len().max(1);
    csv.write(&base_row(
        "storage_record",
        "bytes",
        0,
        record_bytes / n,
    ))?;
    csv.write(&base_row(
        "storage_total",
        "bytes",
        0,
        (record_bytes + overhead_bytes) / n,
    ))?;
    csv.write(&base_row(
        "storage_block_overhead",
        "bytes_per_block",
        0,
        overhead_bytes / n_blocks,
    ))?;

    Ok(())
}

// Re-exported for tests of the CSV column list.
pub fn column_count() -> usize {
    CSV_COLUMNS.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_columns_match_spec_plus_bytes() {
        assert_eq!(column_count(), 17);
        assert_eq!(CSV_COLUMNS[0], "exp");
        assert_eq!(CSV_COLUMNS[10], "warmup");
        assert_eq!(CSV_COLUMNS[15], "n_sel");
        assert_eq!(CSV_COLUMNS[16], "bytes");
    }

    #[test]
    fn seed_changes_with_configuration() {
        assert_ne!(seed_for(1, &["a"]), seed_for(1, &["b"]));
        assert_eq!(seed_for(1, &["a"]), seed_for(1, &["a"]));
    }

    #[test]
    fn sigma_rounding() {
        assert_eq!(sigma_for(1_000_000, 1.0), 10_000);
        assert_eq!(sigma_for(1_000_000, 0.1), 1_000);
        assert_eq!(sigma_for(2000, 25.0), 500);
    }

    #[test]
    fn full_grid_counts_match_spec() {
        // Counts implied by SPEC.md for the full (non-smoke) grid.
        let expected = [
            ("exp1", 10),
            ("exp2a", 24),
            ("exp2b", 30),
            ("exp2c", 24),
            ("exp3a", 15),
            ("exp3b", 9),
            ("exp3c", 30),
            ("exp3d", 10),
            ("exp1_construction", 9),
        ];
        for (name, count) in expected {
            let grid = full_grid(name, 30).expect("grid");
            assert_eq!(grid.len(), count, "{name}");
            assert!(grid.iter().all(|p| p.n > 0 && p.runs > 0));
        }
        assert!(full_grid("nope", 1).is_err());
    }

    #[test]
    fn dense_grid_counts() {
        for (name, count) in [("exp1d", 14), ("exp2bd", 54), ("exp3ad", 18)] {
            let grid = full_grid(name, 30).expect("grid");
            assert_eq!(grid.len(), count, "{name}");
            assert!(grid.iter().all(|p| p.n > 0 && p.runs == 30));
            assert!(!EXPERIMENTS.contains(&name));
        }
    }

    #[test]
    fn exp3b_grid_points_are_distinguishable() {
        let grid = full_grid("exp3b", 30).expect("grid");
        let approaches: std::collections::BTreeSet<_> =
            grid.iter().map(|p| p.approach.clone()).collect();
        assert_eq!(approaches.len(), 9);
    }

    #[test]
    fn memory_measure_uses_real_lengths() {
        let data = build_data(100, 1, Layout::Scattered, 10, 7).expect("data");
        let mem = measure(&data);
        assert!(mem.records >= 100 * size_of::<Record>());
        assert!(mem.ciphertexts >= 100 * 32);
        assert_eq!(mem.tags, 100 * 45 * size_of::<Tag>());
        assert!(mem.blocks > 0 && mem.blooms > 0);
        assert_eq!(mem.total(), mem.records + mem.log());
    }

    #[test]
    fn exp3c_rows_and_gate_at_small_n() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-exp3c");
        let _ = fs::remove_dir_all(&dir);
        let opts = Options {
            name: "exp3c".into(),
            n: Some(2000),
            runs: 2,
            warmup: 1,
            out: dir.clone(),
            smoke: false,
            seed: DEFAULT_SEED,
            list: false,
            estimate: false,
        };
        let paths = run(&opts).expect("exp3c runs and the gates hold");
        let text = fs::read_to_string(&paths[0]).expect("csv");
        let mut lines = text.lines();
        assert_eq!(lines.next().expect("header"), CSV_COLUMNS.join(","));
        let col = |name: &str| CSV_COLUMNS.iter().position(|c| *c == name).expect("column");
        let rows: Vec<Vec<&str>> = lines.map(|l| l.split(',').collect()).collect();
        // 2 layouts x 3 approaches x (1 warm-up + 2 runs); full_he caps are above 1 + 2
        assert_eq!(rows.len(), 2 * 9);
        for r in &rows {
            assert_eq!(r.len(), CSV_COLUMNS.len());
            assert_eq!(r[col("exp")], "exp3c");
            assert_eq!(r[col("series")], "n_sweep");
            assert_eq!(r[col("predicate")], "P1");
            assert_eq!(r[col("agg")], "SUM");
            assert_eq!(r[col("mb")], "500");
            assert_eq!(r[col("n")], "2000");
            assert_eq!(r[col("n_sel")], "20");
        }
        for layout in ["clustered", "scattered"] {
            for approach in ["plain_agg", "full_he", "pqz"] {
                assert!(rows.iter().any(|r| r[col("layout")] == layout
                    && r[col("approach")] == approach));
            }
        }
        for r in rows.iter().filter(|r| r[col("approach")] == "full_he") {
            assert_eq!(r[col("n_cand")], "2000");
        }
        for r in rows.iter().filter(|r| r[col("approach")] == "pqz") {
            assert_eq!(r[col("n_cand")], "20");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pqz_count_uses_no_he_and_avg_of_nothing_is_undefined() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-exp3b-count");
        let _ = fs::remove_dir_all(&dir);
        let opts = Options {
            name: "exp3b".into(),
            n: Some(2000),
            runs: 3,
            warmup: 0,
            out: dir.clone(),
            smoke: false,
            seed: DEFAULT_SEED,
            list: false,
            estimate: false,
        };
        let paths = run(&opts).expect("exp3b runs and the gates hold");
        let text = fs::read_to_string(&paths[0]).expect("csv");
        let col = |name: &str| CSV_COLUMNS.iter().position(|c| *c == name).expect("column");
        let rows: Vec<Vec<&str>> = text.lines().skip(1).map(|l| l.split(',').collect()).collect();
        let times = |approach: &str, agg: &str| -> Vec<u128> {
            rows.iter()
                .filter(|r| r[col("approach")] == approach && r[col("agg")] == agg)
                .map(|r| r[col("time_ns")].parse().expect("time"))
                .collect()
        };
        let count = times("pqz", "COUNT");
        let sum = times("pqz", "SUM");
        assert_eq!(count.len(), 3);
        assert_eq!(sum.len(), 3);
        // 20 HE adds take about a millisecond; a cardinality read does not
        assert!(count.iter().max() < sum.iter().min(), "{count:?} vs {sum:?}");
        for r in rows
            .iter()
            .filter(|r| r[col("approach")] == "pqz" && r[col("agg")] == "COUNT")
        {
            assert_eq!(r[col("n_sel")], "20");
            assert_eq!(r[col("n_cand")], "20");
        }
        let _ = fs::remove_dir_all(&dir);

        // AVG with n_Q = 0 is undefined (bottom): the harness refuses it
        let records = r#gen(200, 0, Layout::Clustered, 5);
        let none: Vec<&Record> = Vec::new();
        let pool = HePool::new(9).expect("pool");
        let csv_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-avg0.csv");
        let _ = fs::remove_file(&csv_path);
        let mut csv = CsvWriter::create(csv_path.clone()).expect("csv");
        let r = run_aggregation(
            &mut csv,
            "exp3b",
            "agg",
            200,
            0,
            Predicate::P4,
            0,
            Layout::Clustered,
            Agg::Avg,
            &records,
            &none,
            &pool,
            &[AggApproach::Pqz],
            1,
            0,
        );
        assert!(r.is_err());
        let _ = fs::remove_file(&csv_path);
    }

    #[test]
    fn exp3d_rows_and_gate_at_small_n() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-exp3d");
        let _ = fs::remove_dir_all(&dir);
        let opts = Options {
            name: "exp3d".into(),
            n: Some(2000),
            runs: 2,
            warmup: 1,
            out: dir.clone(),
            smoke: false,
            seed: DEFAULT_SEED,
            list: false,
            estimate: false,
        };
        let paths = run(&opts).expect("exp3d runs and the gates hold");
        let text = fs::read_to_string(&paths[0]).expect("csv");
        let mut lines = text.lines();
        assert_eq!(lines.next().expect("header"), CSV_COLUMNS.join(","));
        let col = |name: &str| CSV_COLUMNS.iter().position(|c| *c == name).expect("column");
        let rows: Vec<Vec<&str>> = lines.map(|l| l.split(',').collect()).collect();
        // 5 sigma x 2 approaches x (1 warm-up + 2 runs)
        assert_eq!(rows.len(), 5 * 2 * 3);
        for r in &rows {
            assert_eq!(r.len(), CSV_COLUMNS.len());
            assert_eq!(r[col("exp")], "exp3d");
            assert_eq!(r[col("series")], "count_sweep");
            assert_eq!(r[col("predicate")], "P4");
            assert_eq!(r[col("agg")], "COUNT");
            assert_eq!(r[col("layout")], "clustered");
            assert_ne!(r[col("approach")], "full_he");
            assert_eq!(r[col("n")], "2000");
            assert_eq!(r[col("n_cand")], r[col("n_sel")]);
        }
        // n_sel is the generated sigma_count for each selected fraction
        for (pct, count) in [(0.1, 2), (1.0, 20), (5.0, 100), (10.0, 200), (25.0, 500)] {
            for approach in ["plain_agg", "pqz"] {
                let hit = rows
                    .iter()
                    .filter(|r| {
                        r[col("approach")] == approach
                            && r[col("n_sel")] == count.to_string()
                            && (r[col("sigma")].parse::<f64>().expect("sigma") - pct / 100.0)
                                .abs()
                                < 1e-9
                    })
                    .count();
                assert_eq!(hit, 3, "{approach} sigma {pct}%");
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
