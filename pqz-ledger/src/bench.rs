//! Benchmark driver: Exp 5(a), 5(b), bytes per epoch, and the (t,n) threshold panel.
//! Raw rows only (one row per run, warm-up rows flagged); no summaries are computed here.
//!
//! Every ledger number comes from ONE process on ONE machine with no network. It measures
//! computation (execution, hashing, ML-DSA signing and verification), not consensus over a
//! network. `scope` in every row says so. Client-side transaction signing is excluded from
//! ledger timings. `derived_*` columns are computed from the measured per-validator times
//! under a zero-network-delay, parallel-validator assumption; they are not measurements.

use crate::audit;
use crate::contract::*;
use crate::hashing::*;
use crate::ledger::*;
use crate::shamir::Share;
use crate::sig::SigKeys;
use crate::threshold::{self, multisig, Domain};
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::Path;
use std::time::Instant;

pub const SCOPE_LEDGER: &str = "single process; computation and signature verification only; no network; not consensus latency";
pub const SCOPE_THR: &str = "single process; one thread; sharing and reconstruction arithmetic (or ML-DSA for multisig) only; no HE or threshold-signature or KEM operation";

#[derive(Clone, Debug)]
pub struct BenchCfg {
    pub runs: usize,
    pub warmup: usize,
    pub seed: u64,
    pub n_validators: usize,
    pub max_block_txs: usize,
    pub qs: Vec<usize>,
    pub ns: Vec<u64>,
    /// largest N for which the per-record baseline is executed on the simulated ledger; larger N use the byte formula
    pub baseline_measured_max: u64,
    pub panel: Vec<(usize, usize)>,
    pub rec_secret_sizes: Vec<usize>,
    pub only: Vec<String>,
    /// per-transaction ML-DSA submitter signature (provisional design choice; `--no-tx-auth` turns it off)
    pub tx_auth: bool,
}

impl Default for BenchCfg {
    fn default() -> Self {
        BenchCfg {
            runs: 30,
            warmup: 3,
            seed: 1,
            n_validators: 4,
            max_block_txs: 100,
            qs: vec![1, 10, 25, 50, 100, 200],
            ns: vec![10_000, 100_000, 1_000_000],
            baseline_measured_max: 10_000,
            panel: vec![(3, 5), (5, 9), (7, 13)],
            rec_secret_sizes: vec![32, 1024, 16384],
            only: vec![],
            tx_auth: true,
        }
    }
}

impl BenchCfg {
    /// Tiny settings for smoke tests (NOT for reporting).
    pub fn quick() -> Self {
        BenchCfg {
            runs: 2,
            warmup: 1,
            qs: vec![1, 10],
            ns: vec![1_000, 10_000],
            baseline_measured_max: 1_000,
            panel: vec![(3, 5)],
            rec_secret_sizes: vec![32],
            ..Default::default()
        }
    }
    fn want(&self, what: &str) -> bool {
        self.only.is_empty() || self.only.iter().any(|o| o == what)
    }
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("runs_timed: {}", self.runs),
            format!("runs_warmup: {}", self.warmup),
            format!("seed: {}", self.seed),
            format!("validators: {}", self.n_validators),
            format!("max_block_txs: {}", self.max_block_txs),
            format!("q_values: {:?}", self.qs),
            format!("N_values: {:?}", self.ns),
            format!("baseline_measured_max_N: {}", self.baseline_measured_max),
            format!("panel_t_n: {:?}", self.panel),
            format!("T_rec_secret_bytes: {:?}", self.rec_secret_sizes),
            format!("tx_auth: {} (per-transaction ML-DSA-65 submitter signature, provisional)", self.tx_auth),
        ]
    }
}

struct Csv {
    s: String,
    cols: usize,
    rows: usize,
}

impl Csv {
    fn new(header: &str) -> Csv {
        Csv { s: format!("{}\n", header), cols: header.split(',').count(), rows: 0 }
    }
    fn row(&mut self, fields: &[String]) {
        assert_eq!(fields.len(), self.cols, "row width");
        for f in fields {
            assert!(!f.contains(',') && !f.contains('\n'), "csv field {:?}", f);
        }
        self.s.push_str(&fields.join(","));
        self.s.push('\n');
        self.rows += 1;
    }
    fn write(&self, dir: &Path, name: &str) -> io::Result<()> {
        fs::write(dir.join(name), &self.s)
    }
}

fn kind(i: usize, warmup: usize) -> &'static str {
    if i < warmup {
        "warmup"
    } else {
        "timed"
    }
}

fn s<T: ToString>(x: T) -> String {
    x.to_string()
}

fn mk_seed(cfg: &BenchCfg, tag: &str, run: usize) -> [u8; 32] {
    h(&[b"pqz-ledger-bench", &u64b(cfg.seed), tag.as_bytes(), &u64b(run as u64)])
}

// ------------------------------------------------------------------ fixture

struct Fix {
    led: Ledger,
    aa: SigKeys,
    csp: SigKeys,
    chain: audit::Chain,
    omegas: Vec<Hash>,
    r_pol: Hash,
    e_last: u64,
}

impl Fix {
    fn new(cfg: &BenchCfg, tag: &str, run: usize, epochs: usize) -> Fix {
        let seed = mk_seed(cfg, tag, run);
        let aa = SigKeys::from_seed(h(&[b"aa", &seed]));
        let csp = SigKeys::from_seed(h(&[b"csp", &seed]));
        let chain = audit::Chain::genesis(&aa);
        let lcfg = LedgerConfig { n_validators: cfg.n_validators, max_block_txs: cfg.max_block_txs, tx_auth: cfg.tx_auth };
        let led = Ledger::new(lcfg, chain.genesis_contract(), vec![aa.vk.clone(), csp.vk.clone()], seed);
        let omegas = vec![chain.epoch(0).omega];
        let r_pol = chain.r_pol;
        let mut f = Fix { led, aa, csp, chain, omegas, r_pol, e_last: 0 };
        for _ in 0..epochs {
            let tx = f.chain.next_anchor(&f.aa, 8, 4);
            let st = SignedTx::sign(tx, 0, &f.aa, &f.led.cfg);
            let r = f.led.submit(vec![st]);
            assert_eq!(r.receipts[0].result, Ok(()));
            f.e_last += 1;
            f.omegas.push(f.chain.epoch(f.e_last).omega);
        }
        f
    }
    fn sign(&self, tx: Tx) -> SignedTx {
        SignedTx::sign(tx, 1, &self.csp, &self.led.cfg)
    }
    fn auth_tx(&self, qid: u64) -> Tx {
        let (rid, pred) = self.rid_pred(qid);
        Tx::Authorize { rid, pred_hash: pred, e: self.e_last, omega: self.omegas[self.e_last as usize], mode: Mode::Current }
    }
    fn consume_tx(&self, qid: u64) -> Tx {
        let (rid, pred) = self.rid_pred(qid);
        Tx::Consume { rid, pred_hash: pred }
    }
    fn rid_pred(&self, qid: u64) -> (Hash, Hash) {
        let pred = h(&[b"predicate", &u64b(qid)]);
        let om = self.omegas[self.e_last as usize];
        let b_q = binding_bq(&d_q(qid, &pred), 7, 1, &self.r_pol, 0, &om);
        (derive_rid(qid, &b_q, &h(&[b"auth-tac", &u64b(qid)])), pred)
    }
    fn submit_ok(&mut self, txs: Vec<Tx>) {
        let signed: Vec<SignedTx> = txs.into_iter().map(|t| self.sign(t)).collect();
        let r = self.led.submit(signed);
        assert!(r.receipts.iter().all(|x| x.result.is_ok()), "setup transaction rejected");
    }
}

struct Metrics {
    blocks: usize,
    total_ns: u64,
    lat: Vec<u64>,
    crit_total_ns: u64,
    leader_ns: u64,
    validator_ns: u64,
    qc_ns: u64,
    bytes: BlockBytes,
    accepted: usize,
}

/// Timed region = Ledger::submit only (client-side signing happens before the call).
fn timed_submit(f: &mut Fix, txs: Vec<SignedTx>) -> Metrics {
    let h0 = f.led.chain.len();
    let quorum = f.led.cfg.quorum();
    let t = Instant::now();
    let r = f.led.submit(txs);
    let total_ns = t.elapsed().as_nanos() as u64;
    let mut bytes = BlockBytes::default();
    for b in &f.led.chain[h0..] {
        bytes.add(&b.bytes());
    }
    let mut lat: Vec<u64> = r.receipts.iter().map(|x| x.latency_ns).collect();
    lat.sort_unstable();
    Metrics {
        blocks: r.blocks.len(),
        total_ns,
        lat,
        crit_total_ns: r.blocks.iter().map(|b| b.crit_path_ns(quorum)).sum(),
        leader_ns: r.blocks.iter().map(|b| b.leader_ns).sum(),
        validator_ns: r.blocks.iter().map(|b| b.validator_sum_ns()).sum(),
        qc_ns: r.blocks.iter().map(|b| b.qc_verify_ns).sum(),
        bytes,
        accepted: r.receipts.iter().filter(|x| x.result.is_ok()).count(),
    }
}

fn pct(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64) * p).ceil() as usize;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

// ------------------------------------------------------------------ Exp 5(a)

const H5A: &str = "exp,system,workload,q,run,kind,n_validators,quorum,max_block_txs,tx_auth,blocks,accepted_txs,submit_total_ns,throughput_tx_per_s,lat_mean_ns,lat_p50_ns,lat_p95_ns,lat_max_ns,derived_crit_path_total_ns,derived_throughput_tx_per_s,leader_ns_sum,validator_ns_sum,qc_verify_ns_sum,bytes_header,bytes_tx_body,bytes_tx_sig,bytes_qc,bytes_total,scope";

pub fn exp5a(cfg: &BenchCfg) -> Csv5 {
    let mut csv = Csv::new(H5A);
    for (system, workload) in [("pqz", "authorize"), ("per_record_baseline", "commit_record")] {
        for &q in &cfg.qs {
            for i in 0..cfg.warmup + cfg.runs {
                let mut f = Fix::new(cfg, workload, i * 1000 + q, 3);
                let txs: Vec<Tx> = (0..q as u64)
                    .map(|j| match workload {
                        "authorize" => f.auth_tx(j),
                        _ => Tx::CommitRecord { e: f.e_last, i: j, c: h(&[b"record", &u64b(j)]) },
                    })
                    .collect();
                let signed: Vec<SignedTx> = txs.into_iter().map(|t| f.sign(t)).collect();
                let m = timed_submit(&mut f, signed);
                assert_eq!(m.accepted, q, "all honest transactions must commit");
                let mean = m.lat.iter().sum::<u64>() / m.lat.len().max(1) as u64;
                csv.row(&[
                    s("exp5a"),
                    s(system),
                    s(workload),
                    s(q),
                    s(i),
                    s(kind(i, cfg.warmup)),
                    s(cfg.n_validators),
                    s(f.led.cfg.quorum()),
                    s(cfg.max_block_txs),
                    s(f.led.cfg.tx_auth),
                    s(m.blocks),
                    s(m.accepted),
                    s(m.total_ns),
                    format!("{:.3}", q as f64 / (m.total_ns as f64 / 1e9)),
                    s(mean),
                    s(pct(&m.lat, 0.5)),
                    s(pct(&m.lat, 0.95)),
                    s(m.lat.last().copied().unwrap_or(0)),
                    s(m.crit_total_ns),
                    format!("{:.3}", q as f64 / (m.crit_total_ns as f64 / 1e9)),
                    s(m.leader_ns),
                    s(m.validator_ns),
                    s(m.qc_ns),
                    s(m.bytes.header),
                    s(m.bytes.tx_body),
                    s(m.bytes.tx_sig),
                    s(m.bytes.qc),
                    s(m.bytes.total()),
                    s(SCOPE_LEDGER),
                ]);
            }
        }
    }
    Csv5(csv)
}

pub struct Csv5(Csv);

// ------------------------------------------------------------------ Exp 5(b)

const H5B: &str = "exp,op,run,kind,n_validators,quorum,blocks,op_latency_ns,read_ns,verify_ns,derived_crit_path_ns,leader_ns,validator_ns_sum,qc_verify_ns,bytes_header,bytes_tx_body,bytes_tx_sig,bytes_qc,bytes_total,state_entries,scope";

pub fn exp5b(cfg: &BenchCfg) -> Csv5 {
    let mut csv = Csv::new(H5B);
    for op in ["routine_anchor", "routine_read", "authorize", "consume"] {
        for i in 0..cfg.warmup + cfg.runs {
            let mut f = Fix::new(cfg, op, i, 3);
            let quorum = f.led.cfg.quorum();
            let entries = f.led.contract().state.len();
            let (blocks, lat, read_ns, verify_ns, crit, leader, vsum, qc, bytes);
            match op {
                "routine_read" => {
                    // light-client read of State[e_last]: serve (Merkle proof + latest QC) and verify both
                    let key = key_state(f.e_last);
                    let t = Instant::now();
                    let rp = f.led.read_state(&key).expect("State[e] present");
                    let r_ns = t.elapsed().as_nanos() as u64;
                    let t = Instant::now();
                    let ok = verify_read(&rp, &f.led.validator_vks, quorum);
                    let v_ns = t.elapsed().as_nanos() as u64;
                    assert!(ok);
                    blocks = 0;
                    lat = r_ns + v_ns;
                    read_ns = r_ns;
                    verify_ns = v_ns;
                    crit = 0;
                    leader = 0;
                    vsum = 0;
                    qc = 0;
                    bytes = BlockBytes::default();
                }
                _ => {
                    let tx = match op {
                        "routine_anchor" => f.chain.next_anchor(&f.aa, 8, 4),
                        "authorize" => f.auth_tx(1),
                        _ => {
                            let a = f.auth_tx(1);
                            f.submit_ok(vec![a]);
                            f.consume_tx(1)
                        }
                    };
                    let signer = if op == "routine_anchor" { 0 } else { 1 };
                    let st = if signer == 0 { SignedTx::sign(tx, 0, &f.aa, &f.led.cfg) } else { f.sign(tx) };
                    let m = timed_submit(&mut f, vec![st]);
                    assert_eq!(m.accepted, 1);
                    blocks = m.blocks;
                    lat = m.total_ns;
                    read_ns = 0;
                    verify_ns = 0;
                    crit = m.crit_total_ns;
                    leader = m.leader_ns;
                    vsum = m.validator_ns;
                    qc = m.qc_ns;
                    bytes = m.bytes;
                }
            }
            csv.row(&[
                s("exp5b"),
                s(op),
                s(i),
                s(kind(i, cfg.warmup)),
                s(cfg.n_validators),
                s(quorum),
                s(blocks),
                s(lat),
                s(read_ns),
                s(verify_ns),
                s(crit),
                s(leader),
                s(vsum),
                s(qc),
                s(bytes.header),
                s(bytes.tx_body),
                s(bytes.tx_sig),
                s(bytes.qc),
                s(bytes.total()),
                s(entries),
                s(SCOPE_LEDGER),
            ]);
        }
    }
    Csv5(csv)
}

// ------------------------------------------------------------------ bytes per epoch vs N

const H5C: &str = "exp,system,N,run,kind,method,n_validators,quorum,blocks,epoch_txs,anchor_or_commit_latency_ns,bytes_header,bytes_tx_body,bytes_tx_sig,bytes_qc,bytes_total,scope";

pub fn exp5c(cfg: &BenchCfg) -> Csv5 {
    let mut csv = Csv::new(H5C);
    for &n in &cfg.ns {
        // ---- PQZ: the epoch commits ONE anchor transaction, whatever N is. N only enters through the root.
        let root = audit::root_over_n_records(n);
        for i in 0..cfg.warmup + cfg.runs {
            let mut f = Fix::new(cfg, "bytes-pqz", i, 0);
            let tx = f.chain.next_anchor_root_only(&f.aa, root, n, 1);
            let st = SignedTx::sign(tx, 0, &f.aa, &f.led.cfg);
            let m = timed_submit(&mut f, vec![st]);
            assert_eq!(m.accepted, 1);
            csv.row(&[
                s("exp5c"),
                s("pqz"),
                s(n),
                s(i),
                s(kind(i, cfg.warmup)),
                s("measured"),
                s(cfg.n_validators),
                s(f.led.cfg.quorum()),
                s(m.blocks),
                s(1),
                s(m.total_ns),
                s(m.bytes.header),
                s(m.bytes.tx_body),
                s(m.bytes.tx_sig),
                s(m.bytes.qc),
                s(m.bytes.total()),
                s(SCOPE_LEDGER),
            ]);
        }
        // ---- per-record baseline: N commitments on-chain
        if n <= cfg.baseline_measured_max {
            for i in 0..cfg.warmup + cfg.runs {
                let mut f = Fix::new(cfg, "bytes-base", i, 0);
                let txs: Vec<SignedTx> = (0..n).map(|j| f.sign(Tx::CommitRecord { e: 1, i: j, c: h(&[b"record", &u64b(j)]) })).collect();
                let m = timed_submit(&mut f, txs);
                assert_eq!(m.accepted as u64, n);
                csv.row(&[
                    s("exp5c"),
                    s("per_record_baseline"),
                    s(n),
                    s(i),
                    s(kind(i, cfg.warmup)),
                    s("measured"),
                    s(cfg.n_validators),
                    s(f.led.cfg.quorum()),
                    s(m.blocks),
                    s(n),
                    s(m.total_ns),
                    s(m.bytes.header),
                    s(m.bytes.tx_body),
                    s(m.bytes.tx_sig),
                    s(m.bytes.qc),
                    s(m.bytes.total()),
                    s(SCOPE_LEDGER),
                ]);
            }
        } else {
            // Not executed (state-root recomputation is O(state) per block, quadratic overall): exact byte formula,
            // checked against measured runs in the unit test `baseline_formula_equals_measurement`.
            let f = Fix::new(cfg, "bytes-base-formula", 0, 0);
            let b = baseline_bytes_formula(n, cfg.max_block_txs, f.led.cfg.quorum());
            csv.row(&[
                s("exp5c"),
                s("per_record_baseline"),
                s(n),
                s(0),
                s("formula"),
                s("formula_checked_against_measurement"),
                s(cfg.n_validators),
                s(f.led.cfg.quorum()),
                s(n.div_ceil(cfg.max_block_txs as u64)),
                s(n),
                s(""),
                s(b.header),
                s(b.tx_body),
                s(b.tx_sig),
                s(b.qc),
                s(b.total()),
                s(SCOPE_LEDGER),
            ]);
        }
    }
    Csv5(csv)
}

/// Bytes on-chain for `n` per-record commitments in blocks of at most `max_block_txs`.
pub fn baseline_bytes_formula(n: u64, max_block_txs: usize, quorum: usize) -> BlockBytes {
    let tx = Tx::CommitRecord { e: 0, i: 0, c: [0u8; 32] };
    let tx_body = tx.encode().len() + 2;
    let mut total = BlockBytes::default();
    let mut left = n as usize;
    while left > 0 {
        let m = left.min(max_block_txs);
        total.add(&block_bytes_formula(m, tx_body, crate::sig::SIG_BYTES, quorum));
        left -= m;
    }
    total
}

// ------------------------------------------------------------------ threshold panel

const HTHR: &str = "exp,domain,paper_name,variant,t,n,secret_bytes,op,run,kind,inner_reps,ns_per_op,share_bytes,evidence_bytes,scope";

fn reps_for(len: usize) -> usize {
    if len <= 1024 {
        200
    } else {
        20
    }
}

pub fn thr(cfg: &BenchCfg) -> Csv5 {
    let mut csv = Csv::new(HTHR);
    for dom in Domain::ALL {
        let sizes: Vec<usize> = if dom == Domain::Rec { cfg.rec_secret_sizes.clone() } else { vec![32] };
        for &(t, n) in &cfg.panel {
            for &len in &sizes {
                for i in 0..cfg.warmup + cfg.runs {
                    let mut rng = threshold::domain_rng(dom, &mk_seed(cfg, "thr", i));
                    let secret = threshold::random_secret(&mut rng, len);
                    let reps = reps_for(len);
                    // deal
                    let t0 = Instant::now();
                    let mut last = None;
                    for _ in 0..reps {
                        last = Some(threshold::setup(dom, t, n, &secret, &mut rng));
                    }
                    let deal_ns = t0.elapsed().as_nanos() as u64 / reps as u64;
                    let (info, shares) = last.unwrap();
                    let sb = threshold::share_bytes(&shares);
                    // combine from the LAST t shares (not the first, which is the cheapest case in no way, but fixed)
                    let pick: Vec<Share> = shares[n - t..].to_vec();
                    let t1 = Instant::now();
                    let mut ok = true;
                    for _ in 0..reps {
                        ok &= threshold::combine(&info, &pick).map(|x| x == secret).unwrap_or(false);
                    }
                    let comb_ns = t1.elapsed().as_nanos() as u64 / reps as u64;
                    assert!(ok, "reconstruction must succeed");
                    for (op, ns) in [("setup_deal", deal_ns), ("combine", comb_ns)] {
                        csv.row(&[
                            s("thr"),
                            s(dom.label()),
                            s(dom.paper_name()),
                            s("shamir_gf2^127-1"),
                            s(t),
                            s(n),
                            s(len),
                            s(op),
                            s(i),
                            s(kind(i, cfg.warmup)),
                            s(reps),
                            s(ns),
                            s(sb),
                            s(0),
                            s(SCOPE_THR),
                        ]);
                    }
                }
            }
        }
    }
    // provisional T_priv variant: t-of-n ML-DSA-65 approvals
    for &(t, n) in &cfg.panel {
        let com = multisig::Committee::setup(t, n, &mk_seed(cfg, "ms", 0));
        let b_q = h(&[b"B_Q"]);
        for i in 0..cfg.warmup + cfg.runs {
            let reps = 5usize;
            let t0 = Instant::now();
            let mut ap = Vec::new();
            for _ in 0..reps {
                ap = (0..n).map(|j| com.approve(j, &b_q)).collect::<Vec<_>>();
            }
            let approve_ns = t0.elapsed().as_nanos() as u64 / (reps * n) as u64;
            let t1 = Instant::now();
            for _ in 0..reps {
                com.combine(&b_q, &ap).expect("valid approvals");
            }
            let comb_ns = t1.elapsed().as_nanos() as u64 / reps as u64;
            for (op, ns, inner) in [("approve_one_member", approve_ns, reps * n), ("combine_verify_t", comb_ns, reps)] {
                csv.row(&[
                    s("thr"),
                    s(Domain::Priv.label()),
                    s(Domain::Priv.paper_name()),
                    s("mldsa65_multisig"),
                    s(t),
                    s(n),
                    s(32),
                    s(op),
                    s(i),
                    s(kind(i, cfg.warmup)),
                    s(inner),
                    s(ns),
                    s(0),
                    s(com.evidence_bytes()),
                    s(SCOPE_THR),
                ]);
            }
        }
    }
    Csv5(csv)
}

// ------------------------------------------------------------------ driver

/// Runs the selected experiments, writes raw CSVs and env.txt into `dir`, returns (file, rows).
pub fn run_all(cfg: &BenchCfg, dir: &Path, program: &str) -> io::Result<Vec<(String, usize)>> {
    fs::create_dir_all(dir)?;
    let mut out = Vec::new();
    let mut put = |name: &str, c: Csv5| -> io::Result<()> {
        c.0.write(dir, name)?;
        out.push((name.to_string(), c.0.rows));
        Ok(())
    };
    if cfg.want("exp5a") {
        put("exp5a_latency_throughput.csv", exp5a(cfg))?;
    }
    if cfg.want("exp5b") {
        put("exp5b_governance.csv", exp5b(cfg))?;
    }
    if cfg.want("exp5c") {
        put("exp5c_bytes_per_epoch.csv", exp5c(cfg))?;
    }
    if cfg.want("thr") {
        put("threshold.csv", thr(cfg))?;
    }
    let mut env = crate::env::env_txt(program, &cfg.lines());
    let _ = write!(env, "");
    fs::write(dir.join("env.txt"), env)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_formula_equals_measurement() {
        let cfg = BenchCfg::quick();
        for n in [1u64, 99, 100, 101, 250] {
            let mut f = Fix::new(&cfg, "t", 0, 0);
            let txs: Vec<SignedTx> = (0..n).map(|j| f.sign(Tx::CommitRecord { e: 1, i: j, c: h(&[b"record", &u64b(j)]) })).collect();
            let m = timed_submit(&mut f, txs);
            let b = baseline_bytes_formula(n, cfg.max_block_txs, f.led.cfg.quorum());
            assert_eq!(b, m.bytes, "n={}", n);
        }
    }

    #[test]
    fn pqz_epoch_bytes_do_not_depend_on_n() {
        let cfg = BenchCfg::quick();
        let mut seen = None;
        for n in [10u64, 1_000, 100_000] {
            let mut f = Fix::new(&cfg, "t", 1, 0);
            let tx = f.chain.next_anchor_root_only(&f.aa, audit::root_over_n_records(n.min(1000)), n, 1);
            let st = SignedTx::sign(tx, 0, &f.aa, &f.led.cfg);
            let m = timed_submit(&mut f, vec![st]);
            match seen {
                None => seen = Some(m.bytes),
                Some(b) => assert_eq!(b, m.bytes),
            }
        }
    }

    #[test]
    fn smoke_runs_write_all_files_with_expected_shape() {
        let cfg = BenchCfg::quick();
        let dir = std::env::temp_dir().join(format!("pqz-ledger-smoke-{}", std::process::id()));
        let files = run_all(&cfg, &dir, "unit-test").unwrap();
        let rows = |n: &str| files.iter().find(|f| f.0 == n).unwrap().1;
        let per = cfg.runs + cfg.warmup;
        assert_eq!(rows("exp5a_latency_throughput.csv"), 2 * cfg.qs.len() * per);
        assert_eq!(rows("exp5b_governance.csv"), 4 * per);
        // exp5c: pqz per N, baseline measured for N <= max else one formula row
        let measured = cfg.ns.iter().filter(|n| **n <= cfg.baseline_measured_max).count();
        let formula = cfg.ns.len() - measured;
        assert_eq!(rows("exp5c_bytes_per_epoch.csv"), cfg.ns.len() * per + measured * per + formula);
        // thr: 3 domains x panel x (2 ops) x runs, plus multisig 2 ops
        assert_eq!(rows("threshold.csv"), (3 * cfg.panel.len() * 2 * per) + cfg.panel.len() * 2 * per);
        for f in ["exp5a_latency_throughput.csv", "exp5b_governance.csv", "exp5c_bytes_per_epoch.csv", "threshold.csv"] {
            let txt = fs::read_to_string(dir.join(f)).unwrap();
            let mut lines = txt.lines();
            let w = lines.next().unwrap().split(',').count();
            assert!(lines.all(|l| l.split(',').count() == w), "{}", f);
            assert!(txt.contains("no network") || f == "threshold.csv");
        }
        let env = fs::read_to_string(dir.join("env.txt")).unwrap();
        assert!(env.contains("cpu_model:") && env.contains("rustc:") && env.contains("cargo_lock_sha256:"));
        let _ = fs::remove_dir_all(&dir);
    }
}
