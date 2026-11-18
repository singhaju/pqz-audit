//! demo_scenarios: scenario runner for the live demo (front end: demo/demo.py). It only CALLS existing public functions
//! (pqz_eval, pqz_ledger, pqz_integrated_w46); it adds no protocol logic and changes no measured path.
//! Use case: hospital EHR ACCESS LOG audit (insider data theft). Query: COUNT and SUM(b) over "a = 7 (EXPORT_RECORDS)".
//!
//! Usage: demo_scenarios --scenario <s1|a1|a2|a3|a4|a5|a6|a7|search> [--n N]
//! Output: JSON Lines on stdout, one event per line. Every number / hash / ACCEPT / REJECT / error text in the events is produced by
//! the library call that is named in the event; nothing is hard-coded. Timings: this laptop, one run, not a paper number.

use pqz_eval::eapat::{aead_decrypt, encrypt_record, EpochKeys};
use pqz_eval::he::HePool;
use pqz_eval::search::{bps_eval, eq_tag, formula_for, range_tags, Formula, ATTR_A, ATTR_B, ATTR_C, ATTR_D};
use pqz_eval::{Predicate, Record, B_DOMAIN, X, Z};
use pqz_integrated_w46::w35::*;
use pqz_integrated_w46::*;
use pqz_ledger::contract::{d_q, derive_rid, key_state, Mode, Tx};
use pqz_ledger::hashing::{h as hs, hex as lhex, u64b, Hash};
use pqz_ledger::ledger::{verify_read, SignedTx};
use pqz_ledger::threshold::{self, Domain};
use pqz_plonky3_w36::c1;
use pqz_plonky3_w36::request::exec_context;
use std::io::Write;
use std::time::Instant;

const FMT: WFmt = WFmt::P2r;
const CHUNK: usize = 2;
const HE_POOL: usize = 1024;

// ------------------------------------------------------------------------------------------------ JSON Lines
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

struct Ev {
    kind: &'static str,
    scenario: String,
    phase: String,
    title: String,
    items: Vec<(String, String)>,
    tables: Vec<(String, Vec<String>, Vec<Vec<String>>)>,
    time_s: Option<f64>,
    status: String,
    detail: String,
    note: String,
    counts: bool,
}

impl Ev {
    fn new(kind: &'static str, scenario: &str, phase: &str, title: &str) -> Ev {
        Ev { kind, scenario: scenario.into(), phase: phase.into(), title: title.into(), items: vec![], tables: vec![], time_s: None, status: String::new(), detail: String::new(), note: String::new(), counts: true }
    }
    fn item(mut self, k: &str, v: impl Into<String>) -> Ev {
        self.items.push((k.into(), v.into()));
        self
    }
    fn table(mut self, caption: &str, head: &[&str], rows: Vec<Vec<String>>) -> Ev {
        self.tables.push((caption.into(), head.iter().map(|s| s.to_string()).collect(), rows));
        self
    }
    fn time(mut self, t: f64) -> Ev {
        self.time_s = Some(t);
        self
    }
    fn status(mut self, s: &str) -> Ev {
        self.status = s.into();
        self
    }
    fn detail(mut self, s: impl Into<String>) -> Ev {
        self.detail = s.into();
        self
    }
    fn note(mut self, s: impl Into<String>) -> Ev {
        self.note = s.into();
        self
    }
    fn info_only(mut self) -> Ev {
        self.counts = false;
        self
    }
    fn emit(self) {
        let mut s = String::from("{");
        s.push_str(&format!("\"kind\":{},\"scenario\":{},\"phase\":{},\"title\":{}", esc(self.kind), esc(&self.scenario), esc(&self.phase), esc(&self.title)));
        s.push_str(",\"items\":[");
        s.push_str(&self.items.iter().map(|(k, v)| format!("[{},{}]", esc(k), esc(v))).collect::<Vec<_>>().join(","));
        s.push_str("],\"tables\":[");
        let tabs: Vec<String> = self
            .tables
            .iter()
            .map(|(c, hd, rows)| {
                format!(
                    "{{\"caption\":{},\"headers\":[{}],\"rows\":[{}]}}",
                    esc(c),
                    hd.iter().map(|x| esc(x)).collect::<Vec<_>>().join(","),
                    rows.iter().map(|r| format!("[{}]", r.iter().map(|x| esc(x)).collect::<Vec<_>>().join(","))).collect::<Vec<_>>().join(",")
                )
            })
            .collect();
        s.push_str(&tabs.join(","));
        s.push(']');
        match self.time_s {
            Some(t) => s.push_str(&format!(",\"time_s\":{t:.6}")),
            None => s.push_str(",\"time_s\":null"),
        }
        s.push_str(&format!(",\"status\":{},\"detail\":{},\"note\":{},\"counts\":{}}}", esc(&self.status), esc(&self.detail), esc(&self.note), self.counts));
        println!("{s}");
        std::io::stdout().flush().ok();
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn short(b: &[u8]) -> String {
    format!("{}...{}", hex(&b[..6]), hex(&b[b.len() - 3..]))
}

// ------------------------------------------------------------------------------------------------ hospital log (own generator, std only)
const ACTIONS: [(u32, &str); 7] = [(1, "VIEW_CHART"), (2, "EDIT_CHART"), (3, "PRINT"), (4, "LOGIN"), (5, "LOGOUT"), (6, "ORDER_MEDICATION"), (7, "EXPORT_RECORDS")];
const DEPTS: [(u32, &str); 8] = [(101, "ER"), (118, "ICU"), (140, "Admissions/Records"), (205, "Oncology"), (220, "Radiology"), (310, "Pharmacy"), (330, "Laboratory"), (500, "Psychiatry (restricted)")];
const INSIDER: u32 = 417;
const INSIDER_DEPT: u32 = 140;
const EPOCH_START: (i64, u32, u32) = (2026, 11, 17); // 18:00:00 UTC on this day
const START_HOUR: u64 = 18;

fn action_name(a: u32) -> &'static str {
    ACTIONS.iter().find(|x| x.0 == a).map(|x| x.1).unwrap_or("?")
}
/// The action code x of the proved predicate P1 (a = x). 7 unless `--x` was given (demo choice).
fn xa() -> u32 {
    pqz_eval::x()
}
fn p1_col() -> String {
    format!("P1 (a={})", xa())
}
fn dept_name(c: u32) -> &'static str {
    DEPTS.iter().find(|x| x.0 == c).map(|x| x.1).unwrap_or("?")
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        (self.next() >> 11) % n
    }
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
fn fmt_ts(ts: u64) -> String {
    let (y, m, d) = civil_from_days((ts / 86400) as i64);
    let s = ts % 86400;
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

struct Meta {
    burst_start: usize,
    burst_len: usize,
}

/// Seeded synthetic EHR access log. id = position, ts = seconds since the Unix epoch (UTC), strictly increasing.
/// Invariants kept (as `pqz_eval::gen`): a = 7 only for the insider's burst; b < 2^20; c, d < 1000.
fn make_records(n: usize, seed: u64) -> (Vec<Record>, Meta) {
    let mut rng = Rng(seed | 1);
    let base = days_from_civil(EPOCH_START.0, EPOCH_START.1, EPOCH_START.2) as u64 * 86400 + START_HOUR * 3600;
    let routine = [101u32, 118, 205, 220, 310, 330, 140];
    let mut recs: Vec<Record> = Vec::with_capacity(n);
    for i in 0..n {
        let mut staff = 100 + rng.below(900) as u32;
        if staff == INSIDER {
            staff = 418;
        }
        let roll = rng.below(100);
        let (a, b) = match roll {
            0..=51 => (1, if rng.below(100) < 90 { 1 + rng.below(3) as u32 } else { 20 + rng.below(60) as u32 }),
            52..=71 => (2, 1),
            72..=75 => (3, 1 + rng.below(2) as u32),
            76..=87 => (4, 0),
            88..=93 => (5, 0),
            _ => (6, 1),
        };
        let c = routine[(staff as usize) % routine.len()];
        let ts = base + i as u64 * 21 + rng.below(20);
        recs.push(Record { id: i as u64, ts, a, b, c, d: staff });
    }
    // three Psychiatry (ward 500 = Z) accesses early in the epoch (used by the OR example of the search scenario)
    for k in 0..3 {
        let i = 40 + k * 130 + rng.below(50) as usize;
        recs[i].c = Z;
        recs[i].a = 1;
        recs[i].b = 1;
    }
    // the insider: staff 417 logs in at night, looks around, exports in a burst (consecutive records), logs out
    let start = n * 69 / 100;
    let len = 20usize;
    let set = |recs: &mut Vec<Record>, i: usize, a: u32, b: u32| {
        recs[i].a = a;
        recs[i].b = b;
        recs[i].c = INSIDER_DEPT;
        recs[i].d = INSIDER;
    };
    set(&mut recs, start - 6, 4, 0);
    for k in 1..6 {
        set(&mut recs, start - 6 + k, if k % 2 == 0 { 2 } else { 1 }, 1);
    }
    for k in 0..len {
        let b = if rng.below(100) < 35 { 2 + rng.below(28) as u32 } else { 150 + rng.below(750) as u32 };
        set(&mut recs, start + k, 7, b);
    }
    set(&mut recs, start + len, 5, 0);
    // invariants
    for r in &recs {
        assert!(r.b < B_DOMAIN && r.c < 1000 && r.d < 1000);
        assert!(r.a != X || (r.d == INSIDER && r.c == INSIDER_DEPT));
    }
    (recs, Meta { burst_start: start, burst_len: len })
}

fn plain_ref(records: &[Record]) -> (u64, u64) {
    records.iter().filter(|r| Predicate::P1.matches(r)).fold((0, 0), |s, r| (s.0 + 1, s.1 + r.b as u64))
}


// ------------------------------------------------------------------------------------------------ honest pipeline (phases 1 to 6)
struct H {
    n: usize,
    records: Vec<Record>,
    meta: Meta,
    keys: EpochKeys,
    formula: Formula,
    tag_a: [u8; 16],
    w: World35,
    lc: LedgerCtx,
    omega: Hash,
    auth: AuthProof,
    so: SearchOut,
    ranges: Vec<(usize, usize)>,
    covered: Vec<bool>,
    resp: CspResponse,
    an: Anchor,
    ctx: [u64; 4],
}

fn rows_plain(records: &[Record], idx: &[usize]) -> Vec<Vec<String>> {
    idx.iter()
        .map(|&i| {
            let r = &records[i];
            vec![
                r.id.to_string(),
                fmt_ts(r.ts),
                format!("{} {}", r.a, action_name(r.a)),
                r.b.to_string(),
                format!("{} {}", r.c, dept_name(r.c)),
                r.d.to_string(),
                if Predicate::P1.matches(r) { "HIT".into() } else { "-".into() },
            ]
        })
        .collect()
}

/// Phases 1 to 6. With `verbose` every step is emitted as an event (scenario s1); otherwise nothing is printed.
fn honest(n: usize, sc: &str, verbose: bool) -> H {
    let seed = DEFAULT_SEED;
    let t_all = Instant::now();
    let ev = |phase: &str, title: &str| Ev::new("phase", sc, phase, title);

    // ---------------- Phase 1: initialization
    let t = Instant::now();
    let keys = EpochKeys::from_seed(seed);
    let mut lc = ledger_setup(seed);
    let t1 = t.elapsed().as_secs_f64();
    if verbose {
        let ep0 = lc.chain.epoch(0);
        ev("1", "Initialization: epoch keys, authority key, 4-validator ledger, genesis")
            .item("epoch keys (AES-256-GCM key, tag key, ML-DSA-65 block key)", "derived from a benchmark seed (never printed)")
            .item("audit authority (AA)", "ML-DSA-65 key pair, genesis chain built (Chain::genesis)")
            .item("ledger", format!("{} validators, quorum {} (in-process simulation, no network)", lc.led.cfg.n_validators, lc.led.cfg.quorum()))
            .item("policy root R_pol (genesis)", short(&lc.chain.r_pol))
            .item("Gamma_0 (genesis)", short(&ep0.gamma))
            .item("Omega_0 (genesis canonical state)", short(&ep0.omega))
            .item("epoch e / log size N", format!("e = {EPOCH}, N = {n} records in {} blocks of {BLOCK}, chunk = {CHUNK} blocks, stream format {}", n / BLOCK, FMT.name()))
            .item("audit question", if xa() == X { "How many EXPORT_RECORDS actions happened in this epoch, and how many patient records were exported in total?  ->  COUNT and SUM(b) where a = 7".to_string() } else { format!("CHOSEN ACTION: how many {} actions happened in this epoch, and how many patient records did they touch?  ->  COUNT and SUM(b) where a = {}", action_name(xa()), xa()) })
            .table(
                "How the library record Record {id, ts, a, b, c, d} is used for the hospital access log",
                &["field", "meaning in this demo", "values"],
                vec![
                    vec!["id".into(), "position in the log".into(), format!("0..{}", n - 1)],
                    vec!["ts".into(), "event time, seconds since Unix epoch (UTC), shown as date and time".into(), format!("{} to {}", fmt_ts(base_ts()), fmt_ts(base_ts() + n as u64 * 21))],
                    vec!["a".into(), format!("action code; the proved predicate P1 is a = x, here x = {} ({})", xa(), action_name(xa())), ACTIONS.iter().map(|(c, nm)| format!("{c} {nm}")).collect::<Vec<_>>().join(", ")],
                    vec!["b".into(), "number of patient records touched by the action (must be < 2^20)".into(), "0 for LOGIN/LOGOUT, mostly 1 for chart actions, large for exports".into()],
                    vec!["c".into(), "department / ward code".into(), DEPTS.iter().map(|(c, nm)| format!("{c} {nm}")).collect::<Vec<_>>().join(", ")],
                    vec!["d".into(), "staff id (< 1000)".into(), format!("100..999; the insider is staff {INSIDER}")],
                ],
            )
            .time(t1)
            .status("ok")
            .note("The prototype has no separate registration service: the AA key and the policy root are created here (Chain::genesis); the log producer registers its records in phase 2.")
            .emit();
    }

    // ---------------- Phase 2: the log as the log producer sees it (plaintext)
    let t = Instant::now();
    let (records, meta) = make_records(n, 0xC0FFEE_5EED);
    let t2 = t.elapsed().as_secs_f64();
    if verbose {
        let first: Vec<usize> = (0..12).collect();
        let around: Vec<usize> = (meta.burst_start - 2..meta.burst_start + 4).collect();
        let mut hist = vec![0usize; 8];
        for r in &records {
            hist[r.a as usize] += 1;
        }
        ev("2", "Registration: the plaintext access log (what the log producer sees; the cloud never sees this)")
            .table("First 12 rows of the log (plaintext)", &["id", "time (UTC)", "a action", "b patients", "c dept", "d staff", p1_col().as_str()], rows_plain(&records, &first))
            .table(
                &format!("Rows {}..{} (inside the insider's burst, same plaintext view)", around[0], around[around.len() - 1]),
                &["id", "time (UTC)", "a action", "b patients", "c dept", "d staff", p1_col().as_str()],
                rows_plain(&records, &around),
            )
            .table(
                "Action histogram of the whole log",
                &["code", "action", "records"],
                ACTIONS.iter().map(|(c, nm)| vec![c.to_string(), nm.to_string(), hist[*c as usize].to_string()]).collect(),
            )
            .item("log generation", format!("own seeded generator (xorshift), {n} records; a = 7 appears only in the insider's burst (ids {}..{})", meta.burst_start, meta.burst_start + meta.burst_len - 1))
            .time(t2)
            .status("ok")
            .emit();
    }

    // ---------------- Phase 3a: protect each record
    let first12: Vec<_> = records[..12].iter().map(|r| encrypt_record(&keys, r)).collect();
    let t = Instant::now();
    let log = build_log(&records, &keys);
    let t3a = t.elapsed().as_secs_f64();
    if verbose {
        let rows: Vec<Vec<String>> = first12
            .iter()
            .map(|e| vec![e.id.to_string(), hex(&e.ciphertext[..8]) + "...", e.ciphertext.len().to_string(), e.tags.len().to_string(), short(&e.tags[0])])
            .collect();
        let back = aead_decrypt(&keys, first12[0].id, first12[0].ts, &first12[0].ciphertext);
        ev("3a", "Protect each record: AES-256-GCM ciphertext + 45 keyed search tags (what the cloud stores)")
            .table("The same 12 rows as the cloud sees them", &["id", "ciphertext (first 8 bytes)", "ct bytes", "tags", "first tag"], rows)
            .item("decrypt check (key holder only)", if back == Some(records[0]) { "row 0 decrypts back to the plaintext row: round trip OK" } else { "FAILED" })
            .item("descriptor D_0", format!("{}  (SHA3 over pid, id, epoch, seq, H(CT), H(tags))", short(&log.descriptors[0])))
            .item("whole epoch", format!("{n} records encrypted, {} tags each, descriptors, Merkle leaves, one Bloom filter per block ({} blocks)", TAGS_PER_RECORD, log.n_blocks()))
            .time(t3a)
            .status("ok")
            .note("Time is for build_log over the whole epoch (encryption, tags, descriptors, Bloom filters, record Merkle roots, proof word stream).")
            .emit();
    }

    // ---------------- Phase 3b: skippable blocks, R_RC proofs, AA check
    let t = Instant::now();
    let w = World35::prepare_fmt(log, CHUNK, FMT);
    let t3b_prep = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let (proofs, rc) = w.prove_chunks().expect("prove chunks");
    let t3b_prove = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let aa = aa_finalize_fmt(&proofs, &w.blocks, &w.material(), AaChecks::ON, FMT).expect("AA check");
    let t3b_aa = t.elapsed().as_secs_f64();
    if verbose {
        let rows: Vec<Vec<String>> = w
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| {
                vec![
                    (i + 1).to_string(),
                    format!("{}..{}", b.q_start, b.q_next - 1),
                    b.count.to_string(),
                    short(&b.r_rec),
                    short(&b.s_root),
                    short(&b.commitment()),
                    if b.sigma.is_some() { "chunk-end state".into() } else { "-".into() },
                ]
            })
            .collect();
        let (nbits, k) = bloom_params(BLOCK);
        ev("3b", "Skippable blocks: block commitments, Bloom summaries, R_RC STARK proofs, AA check")
            .table("Blocks B_(e,g) (what the epoch root is built from)", &["g", "seq range", "count", "r_rec (Merkle of descriptors)", "s_root (Merkle of Bloom filter)", "commitment", "sigma"], rows)
            .item("Bloom filter per block", format!("{nbits} bits, k = {k} hash positions per tag"))
            .item("R_e = MerkleRoot(B_1..B_G)", short(&w.r_e))
            .item("R_RC proofs", format!("{} chunk proofs (each chunk = {CHUNK} blocks), {} bytes in total, ~{} conjectured bits, {t3b_prove:.3} s", proofs.len(), rc.bytes, rc.conj))
            .item("AA check (aa_finalize_fmt)", format!("passed in {t3b_aa:.3} s: verified every chunk proof, rebuilt tag lists, headers and blocks; R_e = {}, N_e = {}, G_e = {}", short(&aa.r_e), aa.n_e, aa.g_e))
            .time(t3b_prep + t3b_prove + t3b_aa)
            .status("ok")
            .note("STARK proofs in this prototype are PLAIN mode, not zero-knowledge.")
            .emit();
    }

    // ---------------- Phase 4: blockchain anchor
    let t = Instant::now();
    let (led_st, omega) = commit_epoch(&mut lc, aa.r_e, aa.n_e, aa.g_e).expect("anchor");
    let t4 = t.elapsed().as_secs_f64();
    let gate = ledger_read_gate(&lc, &omega);
    if verbose {
        let ep = lc.chain.epoch(EPOCH);
        let b0 = &lc.led.chain[0];
        ev("4", "Canonical state: anchor the epoch on the blockchain")
            .item("A_e", format!("e={}, R_e={}, N_e={}, G_e={}, t_e={}, p_e={}", ep.a.e, short(&ep.a.r_e), ep.a.n_e, ep.a.g_e, ep.a.t_e, short(&ep.a.p_e)))
            .item("sigma_e", format!("ML-DSA-65 signature by the AA, {} bytes", ep.sigma.len()))
            .item("Gamma_e = H(A_e || sigma_e)", hex(&ep.gamma))
            .item("Omega_e = H(label, e, Gamma_e, R_pol, v_auth)", hex(&omega))
            .item("ledger block", format!("height {}, {} tx, state_root {}, quorum certificate: {} votes (need {} of {} validators)", b0.header.height, b0.header.n_txs, short(&b0.header.state_root), b0.qc.len(), lc.led.cfg.quorum(), lc.led.cfg.n_validators))
            .item("timing", format!("anchor {t4:.4} s (seal {:.4}, tx sign {:.4}, submit + consensus simulation {:.4})", led_st.seal_s, led_st.txsign_s, led_st.submit_s))
            .item("light-client read of State[e] (Merkle path + QC) and Omega check", match &gate { Ok(s) => format!("verified in {s:.4} s"), Err(e) => format!("REJECTED: {}", e.msg) })
            .time(t4 + gate.as_ref().copied().unwrap_or(0.0))
            .status(if gate.is_ok() { "ok" } else { "reject" })
            .note("The blockchain is an in-process SIMULATION: 4 validators in one process, no network, no real consensus latency.")
            .emit();
    }
    gate.expect("ledger gate");

    // ---------------- Phase 5: authorization proof
    let t = Instant::now();
    let (auth, ast) = auth_stage(&omega, 1, "P1: A = x", seed).expect("auth");
    let verdict = verify_auth_stage(&auth);
    let t5 = t.elapsed().as_secs_f64();
    if verbose {
        ev("5", "Audit request: authorization proof R_Auth (bound to Omega_e)")
            .item("request", format!("auditor asks for COUNT and SUM(b) where a = {} (qid 1, predicate text \"P1: A = x\")", xa()))
            .item("R_Auth proof", format!("{} bytes, {} trace rows, proving {:.4} s", auth.bytes.len(), ast.rows, ast.prove_s))
            .item("public: Omega", format!("{:?}", auth.stmt.omega))
            .item("public: d_Q (hash of the query)", format!("{:?}", auth.stmt.d_q))
            .item("public: B_Q (binding of query, policy, Omega)", format!("{:?}", auth.stmt.b_q))
            .item("verify_auth_stage says", match &verdict { Ok(()) => "accepted".to_string(), Err(e) => format!("rejected: {}", e.msg) })
            .time(t5)
            .status(if verdict.is_ok() { "ok" } else { "reject" })
            .note("The policy leaf, scope and other policy-tree leaves are fixed synthetic values in this prototype (honest_auth_instance), not a real hospital policy.")
            .emit();
    }
    verdict.expect("auth");

    // ---------------- Phase 6: execution
    let (formula, tag_a) = predicate_formula(&keys);
    let ctx = exec_context(&c1::perm(), auth.stmt.b_q, auth.stmt.d_q, RID);
    let t = Instant::now();
    let so = search(&w.log, &formula);
    let ranges = plan_runs(&so.flags, &w.plan, 0);
    let mut covered = vec![false; w.g];
    for &(ca, cb) in &ranges {
        for b in w.plan[ca].first_block..w.plan[cb].first_block + w.plan[cb].n_blocks {
            covered[b] = true;
        }
    }
    let openings = openings_for_blocks(&w.blooms, &formula, (0..w.g).filter(|&i| !covered[i])).expect("openings");
    let t6a = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let (runs, ex) = prove_runs(&w, &ranges, ctx).expect("prove runs");
    let t6b = t.elapsed().as_secs_f64();
    let claim: (u64, u64) = (runs.iter().map(|r| r.stmt.count).sum(), runs.iter().map(|r| r.stmt.sum).sum());
    let resp = CspResponse { blocks: w.blocks.clone(), runs, openings, claim };
    let an = {
        let a = lc.chain.epoch(EPOCH).a.clone();
        Anchor { r_e: a.r_e, n_e: a.n_e, g_e: a.g_e }
    };
    if verbose {
        let mut sel_per_block = vec![0usize; w.g];
        for &id in &so.sel {
            sel_per_block[id as usize / BLOCK] += 1;
        }
        let rows: Vec<Vec<String>> = (0..w.g)
            .map(|g| {
                let nop = resp.openings.iter().find(|(b, _)| *b == g as u64 + 1).map(|(_, o)| o.len());
                vec![
                    (g + 1).to_string(),
                    if so.flags[g] { format!("may contain a = {}", xa()) } else { format!("no a = {}", xa()) },
                    if covered[g] { "proved (inside a run)".into() } else { "SKIPPED".into() },
                    match nop {
                        Some(k) => format!("{k} Bloom leaves opened; all query positions are 0 bits -> a = {} cannot be here", xa()),
                        None => "-".into(),
                    },
                    sel_per_block[g].to_string(),
                ]
            })
            .collect();
        ev("6", "Execution: block pruning, exact predicate, execution proof R_Exec")
            .table("Block pruning (Bloom summary = BPS, then exact record tags = RPS)", &["block", "Bloom (bps_eval)", "decision", "why (PruneValid openings)", "records selected (rps_eval)"], rows)
            .item("runs to prove (chunk ranges)", format!("{ranges:?}  ({} of {} blocks inside runs)", covered.iter().filter(|&&c| c).count(), w.g))
            .item("exact predicate", format!("{} records selected by rps_eval on the retained blocks (search {:.4} s + {:.4} s)", so.sel.len(), so.bps_s, so.rps_s))
            .item("R_Exec", format!("{} run proof(s), {} bytes, {t6b:.3} s, ~{} conjectured bits", resp.runs.len(), ex.bytes, ex.conj))
            .item("claimed result from the proofs", format!("COUNT = {}, SUM(b) = {}", claim.0, claim.1))
            .time(t6a + t6b)
            .status("ok")
            .note(format!("R_Exec proves the equality predicate a = x only, here x = {} (the value v = THETA is set by v_of in the log builder, so x is fixed when the epoch is built); it is plain-mode STARK, not zero-knowledge.", xa()))
            .emit();
    }
    let _ = t_all;
    H { n, records, meta, keys, formula, tag_a, w, lc, omega, auth, so, ranges, covered, resp, an, ctx }
}

fn base_ts() -> u64 {
    days_from_civil(EPOCH_START.0, EPOCH_START.1, EPOCH_START.2) as u64 * 86400 + START_HOUR * 3600
}

fn vreq(h: &H, resp: &CspResponse, auth: &AuthProof) -> Result<(u64, u64), String> {
    verify_requester35_fmt(&h.an, &h.formula, auth, resp, ReqChecks::ON, FMT).map(|(_, r)| r).map_err(|e| e.msg)
}

// ------------------------------------------------------------------------------------------------ S1
fn s1(n: usize) {
    let h = honest(n, "s1", true);
    let plain = plain_ref(&h.records);

    // Phase 6 (continued): selective HE over the selected records only
    let t = Instant::now();
    let pool = HePool::with_pool_size(DEFAULT_SEED, HE_POOL).expect("he pool");
    let t_pool = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let mut cnt = pool.zero();
    let mut sm = pool.zero();
    let mut plain_pool_sum = 0u64;
    for &id in &h.so.sel {
        let b = h.records[id as usize].b;
        cnt += pool.one();
        sm += pool.ct_for_b(b);
        plain_pool_sum += pool.pool_value(b);
    }
    let t_add = t.elapsed().as_secs_f64();
    Ev::new("phase", "s1", "6", "Execution (continued): selective homomorphic aggregation (BFV) over the selected records only")
        .item("scheme", pool.describe())
        .item("what is added", format!("{} ciphertexts (only the records selected by the exact predicate), COUNT via encrypted 1s, SUM via encrypted b", h.so.sel.len()))
        .item("timing", format!("pool setup {t_pool:.3} s (setup, not counted in the phase), {} homomorphic additions {t_add:.4} s", h.so.sel.len() * 2))
        .time(t_add)
        .status("ok")
        .note("PROTOTYPE LIMIT (pqz_eval::he): HE ciphertexts come from a pool of 1024 pre-encrypted values, a record with value b uses the ciphertext of (b mod 1024). So the encrypted COUNT is exact, but the encrypted SUM is the sum of (b mod 1024), not of b. The exact SUM(b) comes from the proved result.")
        .emit();

    // Phase 7
    let t = Instant::now();
    let r = verify_requester35_fmt(&h.an, &h.formula, &h.auth, &h.resp, ReqChecks::ON, FMT);
    let t7 = t.elapsed().as_secs_f64();
    let (verdict, result, tm) = match r {
        Ok((tm, res)) => ("ACCEPT".to_string(), Some(res), Some(tm)),
        Err(e) => (format!("REJECT: {}", e.msg), None, None),
    };
    let mut ev = Ev::new("phase", "s1", "7", "Verify and recover: requester checks, result, comparison with the plaintext")
        .item("requester verdict (verify_requester35_fmt)", verdict.clone());
    if let (Some(res), Some(tm)) = (result, tm) {
        ev = ev
            .item("checks run", format!("native {:.4} s (block list vs anchored R_e, run shape, anchored states, PruneValid openings, claim), auth proof {:.4} s, run proofs {:.4} s", tm.native_s, tm.auth_s, tm.runs_s))
            .item("verified result", format!("COUNT = {}, SUM(b) = {}", res.0, res.1))
            .item("plain reference over the plaintext records", format!("COUNT = {}, SUM(b) = {}", plain.0, plain.1))
            .item("comparison", if res == plain { "MATCH" } else { "MISMATCH" })
            .item("bytes the requester receives", requester_bytes(&h.resp, &h.auth).to_string());
    }
    // decrypt the HE aggregate and show threshold recovery
    let he_cnt = pool.decrypt(&cnt);
    let he_sum = pool.decrypt(&sm);
    ev = ev
        .item("HE aggregate decrypted (key held in the pool object)", format!("COUNT = {:?} (expected {}), SUM of (b mod 1024) = {:?} (plain {})", he_cnt, h.so.sel.len(), he_sum, plain_pool_sum));
    let seed32 = hs(&[b"demo-threshold", &u64b(DEFAULT_SEED)]);
    let mut rng = threshold::domain_rng(Domain::Rec, &seed32);
    let secret = threshold::random_secret(&mut rng, 32);
    let (info, shares) = threshold::setup(Domain::Rec, 3, 5, &secret, &mut rng);
    let two = threshold::combine(&info, &shares[..2]);
    let three = threshold::combine(&info, &shares[..3]);
    let mut bad = shares[..3].to_vec();
    bad[0].y[0] ^= 1;
    let badr = threshold::combine(&info, &bad);
    ev = ev
        .item("recovery committee (3-of-5 Shamir, T_rec)", format!("2 shares: {:?}; 3 shares: {}; 3 shares with one corrupted: {:?}", two.as_ref().map(|_| "ok"), if three.as_ref().ok() == Some(&secret) { "key reconstructed (matches the dealt secret)".to_string() } else { format!("{three:?}") }, badr.as_ref().map(|_| "ok")))
        .time(t7)
        .status(if result.is_some() && result == Some(plain) { "ok" } else { "reject" })
        .note("HONEST LIMIT (pqz_ledger::threshold): only Shamir sharing and reconstruction exist. A reconstruction hands the key to the combiner; it is NOT a threshold decryption. Here the shared secret is a stand-in value and is not the BFV key held by the HE pool.");
    ev.emit();
    let total_ok = result == Some(plain);
    Ev::new("result", "s1", "end", "S1 honest audit")
        .item("expected", "ACCEPT with result MATCH")
        .item("observed", if total_ok { "ACCEPT, MATCH" } else { "NOT ACCEPTED or MISMATCH" })
        .status(if total_ok { "ok" } else { "reject" })
        .emit();
    let _ = h.meta;
}

// ------------------------------------------------------------------------------------------------ attacks
struct Att {
    sc: String,
    all_rejected: bool,
}
impl Att {
    fn new(sc: &str) -> Att {
        Att { sc: sc.into(), all_rejected: true }
    }
    /// Emit one check. `r` = Err(text) when the verifier rejected, Ok(text) when it accepted. `counts` = part of the verdict.
    fn check(&mut self, phase: &str, title: &str, changed: &str, r: Result<String, String>, t: f64, counts: bool) {
        let (status, detail) = match &r {
            Err(e) => ("reject", e.clone()),
            Ok(s) => ("accept", s.clone()),
        };
        if counts && r.is_ok() {
            self.all_rejected = false;
        }
        let mut e = Ev::new("check", &self.sc, phase, title).item("what the attacker changed", changed).time(t).status(status).detail(detail);
        if !counts {
            e = e.info_only();
        }
        e.emit();
    }
    fn finish(&self, title: &str, expected: &str, total: f64) {
        Ev::new("result", &self.sc, "end", title)
            .item("expected", expected)
            .item("observed", if self.all_rejected { "REJECTED by the verifier (every counted check returned Err)" } else { "ACCEPTED (unexpected)" })
            .time(total)
            .status(if self.all_rejected { "ok" } else { "reject" })
            .emit();
    }
}

fn setup_event(sc: &str, h: &H, t: f64) -> (f64, Result<(u64, u64), String>) {
    let t0 = Instant::now();
    let r = vreq(h, &h.resp, &h.auth);
    let tv = t0.elapsed().as_secs_f64();
    let plain = plain_ref(&h.records);
    Ev::new("phase", sc, "0", "Honest setup (phases 1 to 6 exactly as in S1) and control: the honest response is accepted")
        .item("log", format!("N = {} hospital access records, insider burst ids {}..{}", h.n, h.meta.burst_start, h.meta.burst_start + h.meta.burst_len - 1))
        .item("blocks / runs", format!("{} blocks, runs {:?}, skipped blocks: {:?}", h.w.g, h.ranges, (0..h.w.g).filter(|&i| !h.covered[i]).map(|i| i + 1).collect::<Vec<_>>()))
        .item("honest claimed result", format!("COUNT = {}, SUM(b) = {}", h.resp.claim.0, h.resp.claim.1))
        .item("control: requester verdict on the honest response", match &r { Ok(res) => format!("ACCEPT, result {:?}, plain reference {:?} -> {}", res, plain, if *res == plain { "MATCH" } else { "MISMATCH" }), Err(e) => format!("REJECT: {e}") })
        .time(t + tv)
        .status(if r.is_ok() { "ok" } else { "reject" })
        .note("Setup time is shown once; every attack below changes ONE thing and calls the real verifier.")
        .emit();
    (t + tv, r)
}

fn hit_block(h: &H) -> usize {
    h.so.sel.first().map(|&id| id as usize / BLOCK).expect("no hit")
}

/// Response with the run that covers block `hb` (0-based) removed; claim recomputed from the remaining runs; openings of the honest response kept.
fn drop_run_of(h: &H, hb: usize) -> (CspResponse, (usize, usize)) {
    let mut resp = h.resp.clone();
    let pos = resp.runs.iter().position(|r| r.first <= hb + 1 && hb + 1 <= r.last).expect("run");
    let run = resp.runs.remove(pos);
    resp.claim = (resp.runs.iter().map(|r| r.stmt.count).sum(), resp.runs.iter().map(|r| r.stmt.sum).sum());
    (resp, (run.first, run.last))
}

fn attack(sc: &str, n: usize) {
    let t_all = Instant::now();
    let mut h = honest(n, sc, false);
    let t_setup = t_all.elapsed().as_secs_f64();
    let (_ts, ctl) = setup_event(sc, &h, t_setup);
    ctl.as_ref().expect("honest control must be accepted");
    let mut a = Att::new(sc);
    let seed = DEFAULT_SEED;
    match sc {
        "a1" => {
            let c = h.resp.claim;
            for (i, (title, what, dc, ds)) in [
                ("A1a: cloud claims COUNT + 1", "claimed COUNT in the response (+1); proofs untouched", 1u64, 0u64),
                ("A1b: cloud claims SUM + 1", "claimed SUM(b) in the response (+1); proofs untouched", 0, 1),
            ]
            .into_iter()
            .enumerate()
            {
                let mut r = h.resp.clone();
                r.claim = (c.0 + dc, c.1 + ds);
                let t = Instant::now();
                let v = vreq(&h, &r, &h.auth).map(|x| format!("accepted {x:?}"));
                a.check("A1", title, &format!("{what}: {:?} -> {:?}", c, r.claim), v, t.elapsed().as_secs_f64(), true);
                let _ = i;
            }
            // consistent forgery: the cloud also edits the public statement of the run so that the claim equals the sum over runs
            let mut r = h.resp.clone();
            r.runs[0].stmt.count += 1;
            r.claim = (r.runs.iter().map(|x| x.stmt.count).sum(), r.runs.iter().map(|x| x.stmt.sum).sum());
            let t = Instant::now();
            let v = vreq(&h, &r, &h.auth).map(|x| format!("accepted {x:?}"));
            a.check("A1", "A1c: cloud also edits the run statement so claim = sum over runs", &format!("run 0 statement count +1 and claim {:?} -> {:?} (native claim check now passes)", c, r.claim), v, t.elapsed().as_secs_f64(), true);
            a.finish("A1 cloud changes the result", "REJECT", t_all.elapsed().as_secs_f64());
        }
        "a2" => {
            let hb = hit_block(&h);
            let t = Instant::now();
            let ask = openings_for_blocks(&h.w.blooms, &h.formula, std::iter::once(hb)).map(|_| "an opening was produced".to_string());
            a.check("A2", "A2a: honest opening function asked to prove the hit block empty", &format!("asked openings_for_blocks for block {} (it holds {} matching records)", hb + 1, h.so.sel.iter().filter(|&&id| id as usize / BLOCK == hb).count()), ask, t.elapsed().as_secs_f64(), true);
            let (resp, (f, l)) = drop_run_of(&h, hb);
            let t = Instant::now();
            let v = vreq(&h, &resp, &h.auth).map(|x| format!("accepted {x:?}"));
            a.check("A2", "A2b: cloud drops the run that contains the matches and pretends the blocks were pruned", &format!("run over blocks {f}..{l} removed, claim recomputed {:?} -> {:?}, no openings for those blocks", h.resp.claim, resp.claim), v, t.elapsed().as_secs_f64(), true);
            a.finish("A2 cloud hides a block that contains matches", "REJECT", t_all.elapsed().as_secs_f64());
        }
        "a3" => {
            let hb = hit_block(&h);
            let (base, (f, l)) = drop_run_of(&h, hb);
            // honest openings for every block of the removed run that really has no match
            let honest_ops = |idx: usize| openings_for_blocks(&h.w.blooms, &h.formula, std::iter::once(idx)).ok().and_then(|mut v| v.pop());
            let mk = |hit_ops: Option<Vec<BloomOpening>>| {
                let mut r = base.clone();
                for b in f - 1..l {
                    if b == hb {
                        if let Some(o) = &hit_ops {
                            r.openings.push((b as u64 + 1, o.clone()));
                        }
                    } else if let Some(o) = honest_ops(b) {
                        r.openings.push(o);
                    }
                }
                r
            };
            // (i) openings of a different, truly empty block relabelled as the hit block
            let empty = (0..h.w.g).find(|&i| !h.covered[i]).expect("a skipped block");
            let foreign = honest_ops(empty).expect("opening").1;
            let r1 = mk(Some(foreign));
            let t = Instant::now();
            let v = vreq(&h, &r1, &h.auth).map(|x| format!("accepted {x:?}"));
            a.check("A3", "A3a: openings of another (empty) block presented for the hit block", &format!("hit block {} skipped; Bloom openings copied from block {} and relabelled", hb + 1, empty + 1), v, t.elapsed().as_secs_f64(), true);
            // (ii) genuine openings of the hit block (valid Merkle paths) but they show 1 bits
            let (nbits, k) = bloom_params(BLOCK);
            let mut idx: Vec<usize> = bloom_positions(&h.tag_a, nbits, k).iter().map(|p| p / 64).collect();
            idx.sort_unstable();
            idx.dedup();
            let ops = h.w.blooms[hb].open_many(&idx);
            let r2 = mk(Some(ops));
            let t = Instant::now();
            let v = vreq(&h, &r2, &h.auth).map(|x| format!("accepted {x:?}"));
            a.check("A3", "A3b: genuine openings of the hit block (paths verify) but its query bits are 1", &format!("hit block {} skipped; {} Bloom leaves opened with open_many (real paths against MRoot(S))", hb + 1, idx.len()), v, t.elapsed().as_secs_f64(), true);
            // (iii) doctored word in an honest opening of an empty block
            let mut r3 = h.resp.clone();
            r3.openings[0].1[0].word ^= 1;
            let t = Instant::now();
            let v = vreq(&h, &r3, &h.auth).map(|x| format!("accepted {x:?}"));
            a.check("A3", "A3c: one bit of an honest opening word flipped", &format!("block {}: opening word of leaf {} changed by one bit", r3.openings[0].0, r3.openings[0].1[0].leaf_idx), v, t.elapsed().as_secs_f64(), true);
            // (iv) missing openings for a skipped block
            let mut r4 = h.resp.clone();
            let gone = r4.openings.remove(0).0;
            let t = Instant::now();
            let v = vreq(&h, &r4, &h.auth).map(|x| format!("accepted {x:?}"));
            a.check("A3", "A3d: openings of a skipped block left out", &format!("openings of skipped block {gone} removed"), v, t.elapsed().as_secs_f64(), true);
            a.finish("A3 cloud claims a block was skipped without a valid Bloom opening", "REJECT", t_all.elapsed().as_secs_f64());
        }
        "a4" => {
            let hb = hit_block(&h);
            let id = h.so.sel[0] as usize;
            let mut recs2 = h.records.clone();
            let old_b = recs2[id].b;
            recs2[id].b = 1;
            let t = Instant::now();
            let log2 = build_log(&recs2, &h.keys);
            let w2 = World35::prepare_fmt(log2, CHUNK, FMT);
            let so2 = search(&w2.log, &h.formula);
            let ranges2 = plan_runs(&so2.flags, &w2.plan, 0);
            let (runs2, _) = prove_runs(&w2, &ranges2, h.ctx).expect("prove tampered runs");
            let resp2 = respond(&w2, &h.formula, &ranges2, runs2).expect("respond");
            let t_re = t.elapsed().as_secs_f64();
            Ev::new("phase", sc, "A4", "The cloud edits one stored record and rebuilds everything from the edited data")
                .item("edit", format!("record id {id} (block {}): b {old_b} -> 1 (an export of {old_b} patient records made to look like 1)", hb + 1))
                .item("block commitment of block", format!("anchored {}  vs  rebuilt {}", short(&h.w.blocks[hb].commitment()), short(&w2.blocks[hb].commitment())))
                .item("epoch root", format!("anchored R_e {}  vs  rebuilt {}", short(&h.an.r_e), short(&w2.r_e)))
                .item("the cheating result the cloud would like to deliver", format!("COUNT = {}, SUM(b) = {} (honest: {:?})", resp2.claim.0, resp2.claim.1, h.resp.claim))
                .time(t_re)
                .status("ok")
                .info_only()
                .emit();
            let t = Instant::now();
            let v = vreq(&h, &resp2, &h.auth).map(|x| format!("accepted {x:?}"));
            a.check("A4", "A4a: edited data, fully consistent response, checked against the anchored R_e", "stored record changed after anchoring; blocks, run proofs, openings all rebuilt from the edited data", v, t.elapsed().as_secs_f64(), true);
            // edited run proofs under the honest block list
            let mut r2 = h.resp.clone();
            r2.runs = resp2.runs.clone();
            r2.claim = resp2.claim;
            let t = Instant::now();
            let v = vreq(&h, &r2, &h.auth).map(|x| format!("accepted {x:?}"));
            a.check("A4", "A4b: cloud shows the ANCHORED block list but run proofs made over the edited data", "block list honest (matches R_e), run proofs + claim from the edited records", v, t.elapsed().as_secs_f64(), true);
            a.finish("A4 cloud changes one stored record after anchoring", "REJECT", t_all.elapsed().as_secs_f64());
        }
        "a5" => {
            // stale approval: the Omega of the previous canonical state (genesis, epoch 0)
            let stale = h.lc.chain.epoch(0).omega;
            let (auth_s, _) = auth_stage(&stale, 1, "P1: A = x", seed).expect("stale auth");
            let t = Instant::now();
            let v = vreq(&h, &h.resp, &auth_s).map(|x| format!("accepted {x:?}"));
            a.check("A5", "A5a: stale authorization (bound to Omega_0) presented with the honest run proofs", &format!("auth proof made for Omega {}, run proofs bound to the current authorization", short(&stale)), v, t.elapsed().as_secs_f64(), true);
            // a smarter cloud re-proves the runs for the stale authorization: internally consistent
            let ctx_s = exec_context(&c1::perm(), auth_s.stmt.b_q, auth_s.stmt.d_q, RID);
            let t = Instant::now();
            let (runs_s, _) = prove_runs(&h.w, &h.ranges, ctx_s).expect("runs under stale ctx");
            let resp_s = respond(&h.w, &h.formula, &h.ranges, runs_s).expect("respond");
            let v = vreq(&h, &resp_s, &auth_s).map(|x| format!("accepted {x:?}  (the proofs alone are internally consistent: this is why the ledger gate exists)"));
            a.check("A5", "A5b: cloud re-proves the runs for the stale authorization (requester proof checks only)", "run proofs re-made under the stale authorization's context", v, t.elapsed().as_secs_f64(), false);
            let t = Instant::now();
            let g = ledger_read_gate(&h.lc, &stale).map(|s| format!("gate passed in {s:.4} s")).map_err(|e| e.msg);
            a.check("A5", "A5c: ledger gate (ledger_read_gate) with the Omega the stale authorization is bound to", "Omega in the Auth statement = Omega_0 (previous canonical state), ledger holds Omega_1", g, t.elapsed().as_secs_f64(), true);
            // contract level
            let pred = hs(&[b"predicate", b"P1: A = x"]);
            let rid = derive_rid(1, &h.auth.stmt_bq_hash(), &hs(&[b"demo-tac"]));
            let om_now = h.lc.chain.epoch(EPOCH).omega;
            let good = Tx::Authorize { rid, pred_hash: pred, e: EPOCH, omega: om_now, mode: Mode::Current };
            let r_good = submit_one(&mut h.lc, good);
            a.check("A5", "A5d-control: Authorize with the current Omega_1 (honest)", "nothing", r_good.map(|_| "committed".to_string()), 0.0, false);
            let rid2 = derive_rid(2, &h.auth.stmt_bq_hash(), &hs(&[b"demo-tac"]));
            let stale_tx = Tx::Authorize { rid: rid2, pred_hash: pred, e: EPOCH, omega: stale, mode: Mode::Current };
            let t = Instant::now();
            let r = submit_one(&mut h.lc, stale_tx).map(|_| "committed".to_string());
            a.check("A5", "A5d: Authorize transaction carrying the stale Omega_0 for epoch 1", "Omega field of the Authorize tx = Omega_0", r, t.elapsed().as_secs_f64(), true);
            a.finish("A5 authorization bound to a different epoch / Omega (stale or replayed approval)", "REJECT", t_all.elapsed().as_secs_f64());
        }
        "a6" => {
            let (auth2, _) = auth_stage(&h.omega, 2, "P2: A = x AND B >= y (a different query)", seed).expect("auth2");
            let t = Instant::now();
            let v = vreq(&h, &h.resp, &auth2).map(|x| format!("accepted {x:?}"));
            a.check("A6", "A6a: authorization for a different query (different d_Q) with the honest run proofs", &format!("d_Q honest {:?} -> authorization proof for another query, d_Q {:?}", h.auth.stmt.d_q, auth2.stmt.d_q), v, t.elapsed().as_secs_f64(), true);
            // contract: authorize predicate P1, then try to consume with another predicate hash
            let p1 = hs(&[b"predicate", b"P1: A = x"]);
            let p2 = hs(&[b"predicate", b"P2: A = x AND B >= y"]);
            let rid = derive_rid(1, &d_q(1, &p1), &hs(&[b"demo-tac"]));
            let om = h.lc.chain.epoch(EPOCH).omega;
            let r0 = submit_one(&mut h.lc, Tx::Authorize { rid, pred_hash: p1, e: EPOCH, omega: om, mode: Mode::Current });
            a.check("A6", "A6b-control: ledger Authorize for the predicate P1", "nothing", r0.map(|_| "committed".to_string()), 0.0, false);
            let t = Instant::now();
            let r = submit_one(&mut h.lc, Tx::Consume { rid, pred_hash: p2 }).map(|_| "committed".to_string());
            a.check("A6", "A6b: ledger Consume with the hash of another predicate", "Consume tx names predicate P2, the reservation was authorized for P1", r, t.elapsed().as_secs_f64(), true);
            a.finish("A6 authorization for a different query (d_Q mismatch)", "REJECT", t_all.elapsed().as_secs_f64());
        }
        "a7" => {
            let (e_blk, n_v) = (h.lc.led.chain.len() - 1, h.lc.led.cfg.n_validators);
            let t = Instant::now();
            let g = ledger_read_gate(&h.lc, &h.omega).map(|s| format!("gate passed in {s:.4} s"));
            a.check("A7", "A7-control: honest ledger, light-client read", "nothing", g.map_err(|e| e.msg), t.elapsed().as_secs_f64(), false);
            // (a) forged block header (state root edited)
            let orig = h.lc.led.chain[e_blk].header.clone();
            h.lc.led.chain[e_blk].header.state_root[0] ^= 1;
            let t = Instant::now();
            let g = ledger_read_gate(&h.lc, &h.omega).map(|s| format!("gate passed in {s:.4} s")).map_err(|e| e.msg);
            a.check("A7", "A7a: forged ledger block header (state_root edited, QC kept)", "one bit of the latest block's state_root", g, t.elapsed().as_secs_f64(), true);
            h.lc.led.chain[e_blk].header = orig;
            // (b) quorum certificate with too few votes
            let orig_qc = h.lc.led.chain[e_blk].qc.clone();
            let quorum = h.lc.led.cfg.quorum();
            h.lc.led.chain[e_blk].qc.truncate(quorum - 1);
            let t = Instant::now();
            let g = ledger_read_gate(&h.lc, &h.omega).map(|s| format!("gate passed in {s:.4} s")).map_err(|e| e.msg);
            a.check("A7", "A7b: quorum certificate with too few validator votes", &format!("QC cut to {} votes, quorum is {quorum} of {n_v}", quorum - 1), g, t.elapsed().as_secs_f64(), true);
            h.lc.led.chain[e_blk].qc = orig_qc;
            // (c) tampered state value in the read proof (verify_read returns a bool)
            let mut rp = h.lc.led.read_state(&key_state(EPOCH)).expect("read proof");
            rp.value[5] ^= 1;
            let t = Instant::now();
            let ok = verify_read(&rp, &h.lc.led.validator_vks, h.lc.led.cfg.quorum());
            a.check("A7", "A7c: tampered anchor entry (State[e] value edited in the read proof)", "one bit of the stored State[e] entry (Gamma/Omega) in the light-client read proof", if ok { Ok("verify_read returned true".into()) } else { Err("verify_read returned false (Merkle path from the edited entry does not reach the QC-signed state_root); the library returns a bool, no text".into()) }, t.elapsed().as_secs_f64(), true);
            // (d) forged anchor transaction for the next epoch
            let ep1 = h.lc.chain.epoch(EPOCH).clone();
            let forged = Tx::Anchor { e: 2, gamma: hs(&[b"forged-gamma"]), p_e: ep1.gamma, r_pol: h.lc.chain.r_pol, v_auth: 0, omega: hs(&[b"forged-omega"]), omega_prev: ep1.omega };
            let t = Instant::now();
            let r = submit_one(&mut h.lc, forged).map(|_| "committed".to_string());
            a.check("A7", "A7d: forged anchor transaction for epoch 2 (Omega not equal to H(label, e, Gamma, R_pol, v_auth))", "attacker-chosen Gamma and Omega in an Anchor tx", r, t.elapsed().as_secs_f64(), true);
            a.finish("A7 forged or tampered anchor fails the light-client read / contract", "REJECT", t_all.elapsed().as_secs_f64());
        }
        _ => unreachable!(),
    }
}

/// Submit one transaction signed by the AA key; returns the contract's verdict for it.
fn submit_one(lc: &mut LedgerCtx, tx: Tx) -> Result<(), String> {
    let signed = SignedTx::sign(tx, 0, &lc.aa, &lc.led.cfg);
    let res = lc.led.submit(vec![signed]);
    match res.receipts.first() {
        Some(r) => r.result.map_err(|e| format!("contract rejected: {} ({:?})", e.reason(), e)),
        None => Err("no receipt".into()),
    }
}

trait BqHash {
    fn stmt_bq_hash(&self) -> Hash;
}
impl BqHash for AuthProof {
    /// 32-byte hash of the statement's B_Q words, used only to derive a reservation id for the ledger demo.
    fn stmt_bq_hash(&self) -> Hash {
        let mut parts: Vec<[u8; 8]> = Vec::new();
        for w in self.stmt.b_q {
            parts.push(u64b(w));
        }
        hs(&[b"demo-bq", &parts[0], &parts[1], &parts[2], &parts[3]])
    }
}

// ------------------------------------------------------------------------------------------------ search layer
fn search_scenario(n: usize, custom: Option<String>) {
    let t_all = Instant::now();
    let (records, meta) = make_records(n, 0xC0FFEE_5EED);
    let keys = EpochKeys::from_seed(DEFAULT_SEED);
    let t = Instant::now();
    let log = build_log(&records, &keys);
    let t_log = t.elapsed().as_secs_f64();
    let kk = &keys.tag_key;
    let a7 = || Formula::leaf(vec![eq_tag(kk, ATTR_A, X)]);
    type Rf = Box<dyn Fn(&Record) -> bool>;
    let cases: Vec<(&str, &str, Formula, Rf)> = vec![
        ("Q1", "EXPORT_RECORDS (a = 7): the predicate P1 of the proved audit (formula_for(P1))", formula_for(Predicate::P1, kk), Box::new(|r: &Record| r.a == X)),
        ("Q2", "EXPORT_RECORDS AND more than 49 patient records (a = 7 AND b >= 50)", Formula::and(a7(), Formula::leaf(range_tags(kk, ATTR_B, 50, B_DOMAIN))), Box::new(|r: &Record| r.a == X && r.b >= 50)),
        (
            "Q3",
            "(EXPORT_RECORDS AND b >= 200) OR dept = 500 Psychiatry (restricted)",
            Formula::or(Formula::and(a7(), Formula::leaf(range_tags(kk, ATTR_B, 200, B_DOMAIN))), Formula::leaf(vec![eq_tag(kk, ATTR_C, Z)])),
            Box::new(|r: &Record| (r.a == X && r.b >= 200) || r.c == Z),
        ),
        (
            "Q4",
            "EXPORT_RECORDS AND b >= 50 AND (dept in 100..199 OR staff = 417)",
            Formula::and(Formula::and(a7(), Formula::leaf(range_tags(kk, ATTR_B, 50, B_DOMAIN))), Formula::or(Formula::leaf(range_tags(kk, ATTR_C, 100, 200)), Formula::leaf(vec![eq_tag(kk, ATTR_D, INSIDER)]))),
            Box::new(|r: &Record| r.a == X && r.b >= 50 && ((100..200).contains(&r.c) || r.d == INSIDER)),
        ),
        (
            "Q5",
            "EXPORT by staff 417 AND more than 100 patients (a = 7 AND d = 417 AND b >= 101)",
            Formula::and(Formula::and(a7(), Formula::leaf(vec![eq_tag(kk, ATTR_D, INSIDER)])), Formula::leaf(range_tags(kk, ATTR_B, 101, B_DOMAIN))),
            Box::new(|r: &Record| r.a == X && r.d == INSIDER && r.b >= 101),
        ),
    ];
    let cases: Vec<(String, String, Formula, Rf)> = match custom {
        None => cases.into_iter().map(|(i, t, f, p)| (i.to_string(), t.to_string(), f, p)).collect(),
        Some(spec) => vec![custom_case(&spec, kk)],
    };
    Ev::new("phase", "search", "0", "Setup: same hospital log, encrypted and tagged exactly as in S1")
        .item("log", format!("N = {n}, {} blocks of {BLOCK}; insider burst ids {}..{}", log.n_blocks(), meta.burst_start, meta.burst_start + meta.burst_len - 1))
        .item("build_log", format!("{t_log:.3} s"))
        .time(t_log)
        .status("ok")
        .note("SEARCH LAYER ONLY. The calls below are pqz_eval's bps_eval (block Bloom summary) and rps_eval (record tags) through pqz_integrated_w46::search. No proof, no ledger anchor and no requester check are involved. The execution proof (R_Exec) of this prototype covers only the equality predicate a = X: the value v = THETA is fixed at log-build time by v_of (lib.rs), and prove_runs/verify_requester35 take no predicate argument, so a second equality predicate, or a compound one, cannot be proved end to end with the public functions.")
        .emit();
    let mut all_ok = true;
    for (id, text, f, plain) in cases {
        let so = search(&log, &f);
        let mut sel_per_block = vec![0usize; log.n_blocks()];
        for &sid in &so.sel {
            sel_per_block[sid as usize / BLOCK] += 1;
        }
        let want: Vec<u64> = records.iter().filter(|r| plain(r)).map(|r| r.id).collect();
        let ok = want == so.sel;
        all_ok &= ok;
        let rows: Vec<Vec<String>> = (0..log.n_blocks())
            .map(|g| {
                vec![
                    (g + 1).to_string(),
                    if bps_eval(&log.blooms[g], &f) { "may match".into() } else { "no match possible".into() },
                    if so.flags[g] { "retained: records checked".into() } else { "SKIPPED (no record is read)".into() },
                    sel_per_block[g].to_string(),
                ]
            })
            .collect();
        let sel_rows: Vec<Vec<String>> = so.sel.iter().take(6).map(|&sid| rows_plain(&records, &[sid as usize]).remove(0)).collect();
        let (cnt, sum) = so.sel.iter().fold((0u64, 0u64), |s, &sid| (s.0 + 1, s.1 + records[sid as usize].b as u64));
        Ev::new("phase", "search", &id, &text)
            .table("Per block", &["block", "Bloom summary (bps_eval)", "decision", "records selected (rps_eval)"], rows)
            .table("First selected records (plaintext shown here only because this is the demo)", &["id", "time (UTC)", "a action", "b patients", "c dept", "d staff", p1_col().as_str()], sel_rows)
            .item("trapdoor", format!("{} distinct search tags in the formula", f.tag_count()))
            .item("selected", format!("{cnt} records, sum of b = {sum} (search layer, not proved)"))
            .item("plaintext reference (same predicate evaluated on the plaintext records)", format!("{} records -> {}", want.len(), if ok { "MATCH" } else { "MISMATCH" }))
            .item("timing", format!("bps {:.5} s, rps {:.5} s", so.bps_s, so.rps_s))
            .time(so.bps_s + so.rps_s)
            .status(if ok { "ok" } else { "reject" })
            .note("search only, no proof")
            .emit();
    }
    Ev::new("result", "search", "end", "S-search honest search-layer predicates")
        .item("expected", "selected ids equal the plaintext reference for every query")
        .item("observed", if all_ok { "all MATCH" } else { "MISMATCH" })
        .time(t_all.elapsed().as_secs_f64())
        .status(if all_ok { "ok" } else { "reject" })
        .emit();
}

/// One audience-chosen query for the search layer: spec "a=7,d=417,bmin=101,bmax=900,c=140" (every key optional, at least one).
fn custom_case(spec: &str, kk: &pqz_eval::search::TagKey) -> (String, String, Formula, Box<dyn Fn(&Record) -> bool>) {
    let mut a: Option<u32> = None;
    let mut c: Option<u32> = None;
    let mut dd: Option<u32> = None;
    let mut bmin: u32 = 0;
    let mut bmax: Option<u32> = None;
    for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (k, v) = part.split_once('=').unwrap_or_else(|| panic!("bad part {part:?}, use key=value"));
        let v: u32 = v.trim().parse().unwrap_or_else(|_| panic!("bad number in {part:?}"));
        match k.trim() {
            "a" => a = Some(v),
            "c" => c = Some(v),
            "d" => dd = Some(v),
            "bmin" => bmin = v,
            "bmax" => bmax = Some(v),
            o => panic!("unknown key {o:?} (use a, c, d, bmin, bmax)"),
        }
    }
    let hi = bmax.map(|x| x + 1).unwrap_or(B_DOMAIN).min(B_DOMAIN);
    assert!(bmin < hi, "bmin must be <= bmax");
    let mut parts: Vec<Formula> = vec![];
    let mut words: Vec<String> = vec![];
    if let Some(v) = a {
        parts.push(Formula::leaf(vec![eq_tag(kk, ATTR_A, v)]));
        words.push(format!("action a = {v} ({})", action_name(v)));
    }
    if let Some(v) = dd {
        parts.push(Formula::leaf(vec![eq_tag(kk, ATTR_D, v)]));
        words.push(format!("staff d = {v}"));
    }
    if let Some(v) = c {
        parts.push(Formula::leaf(vec![eq_tag(kk, ATTR_C, v)]));
        words.push(format!("dept c = {v} ({})", dept_name(v)));
    }
    if bmin > 0 || bmax.is_some() {
        parts.push(Formula::leaf(range_tags(kk, ATTR_B, bmin, hi)));
        words.push(match bmax {
            Some(m) => format!("{bmin} <= patients b <= {m}"),
            None => format!("patients b >= {bmin}"),
        });
    }
    let f = parts.into_iter().reduce(Formula::and).expect("give at least one of a, c, d, bmin, bmax");
    let plain: Box<dyn Fn(&Record) -> bool> = Box::new(move |r: &Record| {
        a.map_or(true, |v| r.a == v) && c.map_or(true, |v| r.c == v) && dd.map_or(true, |v| r.d == v) && r.b >= bmin && r.b < hi
    });
    ("Q*".to_string(), format!("Your query: {}", words.join(" AND ")), f, plain)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let sc = get("--scenario").unwrap_or_else(|| {
        eprintln!("usage: demo_scenarios --scenario <s1|a1|a2|a3|a4|a5|a6|a7|search|custom|dump> [--n N] [--q a=7,d=417,bmin=101] [--x 1..7 (s1: proved action code, default 7)]");
        std::process::exit(2)
    });
    let n: usize = get("--n").map(|s| s.parse().expect("--n number")).unwrap_or(2000);
    assert!(n >= 2000 && n % BLOCK == 0, "--n must be a multiple of {BLOCK} and at least 2000");
    if let Some(v) = get("--x") {
        let v: u32 = v.parse().expect("--x number");
        assert!(ACTIONS.iter().any(|a| a.0 == v), "--x must be an action code 1..7");
        // demo choice: the proved predicate becomes P1 = (a = v); set before any log is built
        pqz_eval::set_x_for_demo(v);
    }
    match sc.as_str() {
        "s1" => s1(n),
        "search" => search_scenario(n, None),
        "custom" => search_scenario(n, Some(get("--q").expect("--q a=..,d=..,c=..,bmin=..,bmax=.."))),
        "a1" | "a2" | "a3" | "a4" | "a5" | "a6" | "a7" => attack(&sc, n),
        // demo only: print the plaintext log (the same seeded records every scenario builds) as CSV, so COUNT and SUM
        // can be re-checked with any other tool. In the protocol only encrypted records leave the producer.
        "dump" => {
            let (records, _) = make_records(n, 0xC0FFEE_5EED);
            println!("id,time,action_code,action,patients,dept_code,dept,staff");
            for r in &records {
                println!("{},{},{},{},{},{},{},{}", r.id, fmt_ts(r.ts), r.a, action_name(r.a), r.b, r.c, dept_name(r.c).replace(',', ";"), r.d);
            }
        }
        o => {
            eprintln!("unknown scenario {o}");
            std::process::exit(2)
        }
    }
    let _ = lhex;
}
