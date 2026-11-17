//! demo_explain: a step-by-step walk through one tiny audit for a live demo. It only CALLS existing public
//! functions (pqz_eval, pqz_ledger, pqz_integrated_w46); it adds no protocol logic and changes no measured path.
//! Part A: 16 records, one encrypted, one block built and signed (pqz_eval).
//! Part B: the real w35 pipeline on N = 2000 records (4 blocks of 500, chunk = 2): anchor, Auth, query, run proof, requester check.
//! Usage: demo_explain [--no-pause]    (otherwise it waits for Enter between steps)
//! LAPTOP DEMO DATA: timings are from one run on this machine, not paper numbers.

use pqz_eval::eapat::{aead_decrypt, build_block, encrypt_record, leaf_hash, verify_block, EpochKeys};
use pqz_eval::r#gen::r#gen;
use pqz_eval::search::{bps_eval, rps_eval};
use pqz_eval::{Layout, Predicate};
use pqz_integrated_w46::w35::*;
use pqz_integrated_w46::*;
use pqz_plonky3_w36::request::exec_context;
use pqz_plonky3_w36::c1;
use std::io::{self, BufRead, Write};
use std::time::Instant;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn short(b: &[u8]) -> String {
    format!("{}...{}", hex(&b[..6]), hex(&b[b.len() - 3..]))
}

struct Pace(bool);
impl Pace {
    fn step(&self, title: &str) {
        println!("\n==================== {title} ====================");
    }
    fn pause(&self) {
        if self.0 {
            print!("\n[press Enter] ");
            io::stdout().flush().ok();
            let mut s = String::new();
            io::stdin().lock().read_line(&mut s).ok();
        }
    }
}

fn main() {
    let pace = Pace(!std::env::args().any(|a| a == "--no-pause"));
    let seed = DEFAULT_SEED;
    println!("PQZ-Audit explain demo (laptop demo run, not a paper number)");
    println!("Everything runs in ONE process: LP, CSP, AA, ledger and requester are all played by this program.");

    // ---------------------------------------------------------------- A1
    pace.step("1. Log generation: 16 plaintext records (a, b, c, d)");
    let recs = r#gen(16, 4, Layout::Clustered, seed);
    println!("   id    a     b       c    d    P1 (a = 7)?");
    for r in &recs {
        println!("  {:>3} {:>4} {:>7} {:>4} {:>4}    {}", r.id, r.a, r.b, r.c, r.d, if Predicate::P1.matches(r) { "HIT" } else { "-" });
    }
    let hit = *recs.iter().find(|r| Predicate::P1.matches(r)).unwrap();
    println!("  4 of 16 records are hits (clustered = consecutive ids). Example record: {hit:?}");
    pace.pause();

    // ---------------------------------------------------------------- A2
    pace.step("2. Record encryption and search tags (pqz_eval::eapat::encrypt_record)");
    let keys = EpochKeys::from_seed(seed);
    let enc = encrypt_record(&keys, &hit);
    println!("  plaintext      : id={} ts={} a={} b={} c={} d={}   (16 bytes of attributes)", hit.id, hit.ts, hit.a, hit.b, hit.c, hit.d);
    println!("  ciphertext     : {}  ({} bytes = 16 data + 16 AES-GCM tag)", hex(&enc.ciphertext), enc.ciphertext.len());
    println!("  search tags    : {} tags of {} bytes, sorted. first three:", enc.tags.len(), enc.tags[0].len());
    for t in enc.tags.iter().take(3) {
        println!("                   {}", hex(t));
    }
    let back = aead_decrypt(&keys, enc.id, enc.ts, &enc.ciphertext);
    println!("  decrypt check  : {}", if back == Some(hit) { "round trip OK (key holder only)" } else { "FAILED" });
    println!("  Merkle leaf    : {}", hex(&leaf_hash(&enc)));
    pace.pause();

    // ---------------------------------------------------------------- A3
    pace.step("3. One block of 16 records: Merkle root, Bloom summary, ML-DSA-65 signature");
    let encs: Vec<_> = recs.iter().map(|r| encrypt_record(&keys, r)).collect();
    let blk = build_block(0, encs, [0u8; 32], &keys);
    println!("  block_index    : {}", blk.header.block_index);
    println!("  count          : {}", blk.header.count);
    println!("  merkle_root    : {}", hex(&blk.header.merkle_root));
    println!("  summary_digest : {}  (Bloom filter: {} bits, k = {})", hex(&blk.header.summary_digest), blk.summary.nbits(), blk.summary.k());
    println!("  prev_header    : {}  (first block)", hex(&blk.header.prev_header_hash));
    println!("  signature      : {} bytes (ML-DSA-65), header hash {}", blk.signature.len(), short(&blk.header.hash()));
    println!("  verify_block   : {:?}", verify_block(&blk, &keys));
    let (formula, _tag) = predicate_formula(&keys);
    println!("  block summary says 'may contain a match' for P1: {}", bps_eval(&blk.summary, &formula));
    let sel: Vec<u64> = blk.records.iter().filter(|r| rps_eval(&r.tags, &formula)).map(|r| r.id).collect();
    println!("  exact predicate on the 16 records selects ids: {sel:?}");
    pace.pause();

    // ---------------------------------------------------------------- B
    println!("\n----- From here: the real w35 pipeline on N = 2000 (4 blocks of 500, chunk = 2) -----");
    let n = 2000usize;
    let chunk = 2usize;
    let fmt = WFmt::P2r;
    let records = r#gen(n, n / 100, Layout::Clustered, seed);
    let log = build_log(&records, &keys);
    pace.step("4. Blocks (EAPAT) and the epoch root R_e");
    println!("  descriptor D_0 : {}  (SHA3 over pid, id, epoch, seq, H(CT), H(tags))", hex(&log.descriptors[0]));
    let w = World35::prepare_fmt(log, chunk, fmt);
    let b0 = &w.blocks[0];
    println!("  block B_(e,1)  : e={} g={} q_start={} q_next={} count={}", b0.e, b0.g, b0.q_start, b0.q_next, b0.count);
    println!("                   r_rec  = {}  (Merkle root of the 500 record descriptors)", hex(&b0.r_rec));
    println!("                   s_root = {}  (Merkle root of the block Bloom filter)", hex(&b0.s_root));
    println!("                   commitment = {}", hex(&b0.commitment()));
    println!("  blocks in epoch: {}   R_e = MerkleRoot(B_1..B_{}) = {}", w.g, w.g, hex(&w.r_e));
    println!("  chunks: {} (each chunk = {} blocks), sigma = sponge state kept at the end of each chunk", w.plan.len(), chunk);
    for (i, b) in w.blocks.iter().enumerate() {
        println!("   block {}: s_root={}  sigma={}", i + 1, short(&b.s_root), if b.sigma.is_some() { "chunk-end state" } else { "none" });
    }
    pace.pause();

    pace.step("5. Record consistency proof R_RC (STARK per chunk) and the AA check");
    let t = Instant::now();
    let (proofs, rc) = w.prove_chunks().expect("prove chunks");
    println!("  proved {} chunk proofs in {:.3} s, {} bytes in total, ~{} conjectured bits", proofs.len(), t.elapsed().as_secs_f64(), rc.bytes, rc.conj);
    let t = Instant::now();
    let aa = aa_finalize_fmt(&proofs, &w.blocks, &w.material(), AaChecks::ON, fmt).expect("AA check");
    println!("  AA check passed in {:.3} s (verifies every chunk proof + rebuilds tag lists, headers, blocks)", t.elapsed().as_secs_f64());
    println!("  R_e = {}   N_e = {}   G_e = {}", short(&aa.r_e), aa.n_e, aa.g_e);
    pace.pause();

    pace.step("6. Blockchain: anchor the epoch, canonical state Omega");
    let mut lc = ledger_setup(seed);
    let t = Instant::now();
    let (led_st, omega) = commit_epoch(&mut lc, aa.r_e, aa.n_e, aa.g_e).expect("anchor");
    let ep = lc.chain.epoch(EPOCH);
    println!("  A_e = (e={}, R_e={}, N_e={}, G_e={}, t_e={}, p_e={})", ep.a.e, short(&ep.a.r_e), ep.a.n_e, ep.a.g_e, ep.a.t_e, short(&ep.a.p_e));
    println!("  sigma_e (ML-DSA-65 by the AA) : {} bytes", ep.sigma.len());
    println!("  Gamma_e = H(A_e || sigma_e)   : {}", hex(&ep.gamma));
    println!("  Omega_e = H(label, e, Gamma_e, R_pol, v_auth) : {}", hex(&omega));
    let blk0 = &lc.led.chain[0];
    println!("  ledger block height {}: {} tx, state_root {}, quorum certificate with {} votes (need {} of {})", blk0.header.height, blk0.header.n_txs, short(&blk0.header.state_root), blk0.qc.len(), lc.led.cfg.quorum(), lc.led.cfg.n_validators);
    println!("  anchor took {:.4} s (seal {:.4}, tx sign {:.4}, submit+consensus sim {:.4})", t.elapsed().as_secs_f64(), led_st.seal_s, led_st.txsign_s, led_st.submit_s);
    println!("  light-client read of State[e] with Merkle path + QC: {:?}", ledger_read_gate(&lc, &omega).map(|_| "verified"));
    println!("  NOTE: the chain is SIMULATED in this process (4 validators, no network).");
    pace.pause();

    pace.step("7. Authorization proof R_Auth (bound to Omega_e)");
    let t = Instant::now();
    let (auth, ast) = auth_stage(&omega, 1, "P1: A = x", seed).expect("auth");
    println!("  proof {} bytes, {} trace rows, proving {:.4} s (total stage {:.4} s)", auth.bytes.len(), ast.rows, ast.prove_s, t.elapsed().as_secs_f64());
    println!("  public: omega = {:?}", auth.stmt.omega);
    println!("          d_Q   = {:?}  (hash of the query)", auth.stmt.d_q);
    println!("  verifier says: {:?}", verify_auth_stage(&auth).map(|_| "accepted"));
    pace.pause();

    pace.step("8. Query execution: block pruning, exact predicate");
    let ctx = exec_context(&c1::perm(), auth.stmt.b_q, auth.stmt.d_q, RID);
    let so = search(&w.log, &formula);
    println!("  block summaries (Bloom) say: {:?}   (true = block may hold a match)", so.flags);
    println!("  exact predicate on the retained blocks selects {} records", so.sel.len());
    let ranges = plan_runs(&so.flags, &w.plan, 0);
    let mut covered = vec![false; w.g];
    for &(ca, cb) in &ranges {
        for b in w.plan[ca].first_block..w.plan[cb].first_block + w.plan[cb].n_blocks {
            covered[b] = true;
        }
    }
    println!("  runs to prove (chunk ranges): {ranges:?}   blocks covered: {covered:?}");
    let openings = openings_for_blocks(&w.blooms, &formula, (0..w.g).filter(|&i| !covered[i])).expect("openings");
    println!("  pruned blocks must show Bloom zero bits: {} openings", openings.iter().map(|(_, v)| v.len()).sum::<usize>());
    pace.pause();

    pace.step("9. Execution proof R_Exec (Plonky3 STARK, plain mode) and the result");
    let t = Instant::now();
    let (runs, ex) = prove_runs(&w, &ranges, ctx).expect("prove runs");
    println!("  {} run proof(s), {} bytes, {:.3} s, ~{} conjectured bits", runs.len(), ex.bytes, t.elapsed().as_secs_f64(), ex.conj);
    let claim: (u64, u64) = (runs.iter().map(|r| r.stmt.count).sum(), runs.iter().map(|r| r.stmt.sum).sum());
    println!("  claimed result from the proofs: count = {}, sum of b = {}", claim.0, claim.1);
    let resp = CspResponse { blocks: w.blocks.clone(), runs, openings, claim };
    pace.pause();

    pace.step("10. Requester verification");
    let a = lc.chain.epoch(EPOCH).a.clone();
    let an = Anchor { r_e: a.r_e, n_e: a.n_e, g_e: a.g_e };
    let t = Instant::now();
    let (tm, result) = verify_requester35_fmt(&an, &formula, &auth, &resp, ReqChecks::ON, fmt).expect("requester rejected");
    println!("  requester ACCEPTED in {:.4} s (native {:.4}, auth {:.4}, run proofs {:.4})", t.elapsed().as_secs_f64(), tm.native_s, tm.auth_s, tm.runs_s);
    println!("  result: count = {}, sum = {}", result.0, result.1);
    let plain: (u64, u64) = records.iter().filter(|r| Predicate::P1.matches(r)).fold((0, 0), |s, r| (s.0 + 1, s.1 + r.b as u64));
    println!("  plain reference over the records: count = {}, sum = {}   -> {}", plain.0, plain.1, if plain == result { "MATCH" } else { "MISMATCH" });
    println!("  bytes the requester receives: {}", requester_bytes(&resp, &auth));
    println!("\nDone. (STARK proofs here are plain mode, not zero-knowledge; the chain is an in-process simulation.)");
}
