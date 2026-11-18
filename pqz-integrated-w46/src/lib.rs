//! w34 end-to-end PQZ-Audit driver (library): the w30 driver with the PROOF LAYER swapped to Plonky3 0.8.0 (crate `pqz-plonky3-w35`).
//! One run = the SAME records through every stage; each stage is timed separately with a monotonic clock (`std::time::Instant`).
//! CHANGES-w34.md says what changed against w30, what each timer contains, what is tied and what is not.
//! No AIR is copied: the proofs come from `pqz-plonky3-w35` (plain mode, `FriOpts::std()`, one proof per relation over the whole stream),
//! the data and the protected search from `pqz_eval`, the ledger from `pqz_ledger`.

pub mod sys;
pub mod w35;

use p3_matrix::Matrix;
use p3_symmetric::Permutation;
use pqz_eval::eapat::{encrypt_record, EpochKeys};
use pqz_eval::r#gen::r#gen;
use pqz_eval::search::{bps_eval, eq_tag, formula_for, rps_eval, Bloom, Formula, Tag, ATTR_A};
use pqz_eval::{sha3_parts, Layout, Predicate, Record};
use pqz_ledger::audit::{epoch_root, AuditBlock, Chain};
use pqz_ledger::contract::key_state;
use pqz_ledger::hashing::{h, leaf_hash, merkle_root, u64b, Hash};
use pqz_ledger::ledger::{verify_read, Ledger, LedgerConfig, SignedTx};
use pqz_ledger::sig::SigKeys;
use pqz_plonky3_w36::air::{native_digest, ExecPublic};
use pqz_plonky3_w36::auth::{bind_hash, honest_auth_instance, AuthPublic};
use pqz_plonky3_w36::data::{header_word, RawWord, Workload, DOM_CHAIN, GOLDILOCKS_P};
use pqz_plonky3_w36::rc::RcPublic;
use pqz_plonky3_w36::rel::plain;
use pqz_plonky3_w36::request::{check_stream_link, exec_context, native_bundle_checks, native_request_checks, NativeChecks};
use pqz_plonky3_w36::security::estimate;
use pqz_plonky3_w36::{c1, FriOpts};
use std::time::Instant;

pub const BLOCK: usize = 500;
pub const TAGS_PER_RECORD: usize = 45;
/// theta of R_Exec ("v >= theta"); the driver maps a record to v = THETA if the predicate P1 (A = x) holds, else 0.
pub const THETA: u64 = 1 << 31;
/// Depth of the policy Merkle tree inside R_Auth (the w29 default, as in w30).
pub const AUTH_DEPTH: usize = 10;
pub const EPOCH: u64 = 1;
pub const PID: u64 = 7;
/// Request id RID_Q of the one request of a run (w33 `pchild3` uses the same value; w30 used qid = 1 for d_Q).
pub const RID: u64 = 1;
pub const DEFAULT_SEED: u64 = pqz_eval::bench::DEFAULT_SEED;

/// Failure of a run with the exit code the child process uses (2 bad arguments, 4 prover failed, 5 a verifier rejected, 6 a gate failed).
#[derive(Debug)]
pub struct RunError {
    pub code: i32,
    pub msg: String,
}

impl RunError {
    pub fn new(code: i32, msg: impl Into<String>) -> Self {
        RunError { code, msg: msg.into() }
    }
}

pub type Res<T> = Result<T, RunError>;

// ---------------------------------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Setting {
    pub name: &'static str,
    /// hash of the proof system (statement hash / Merkle hash)
    pub hash: &'static str,
}

/// The FRI options of every proof of this driver: w33 `FriOpts::std()` (blowup 8, 40 queries, 16 bit query PoW), the same as `pchild3` default.
pub fn opts() -> FriOpts {
    FriOpts::std()
}

/// Which words R_Exec runs over. `Retained` = the blocks BPS retained (as w30); `Whole` = every block of the epoch stream (then the
/// R_Exec digest equals the R_RC digest and w33's full stream link applies).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecStream {
    Retained,
    Whole,
}

impl ExecStream {
    pub fn name(self) -> &'static str {
        match self {
            ExecStream::Retained => "retained",
            ExecStream::Whole => "whole",
        }
    }
}

/// w46: stream format. `Old` = one record per absorbed word (w33-w36 AIRs), `P2r` = two records per word (packed, pair/pchunk/prun of
/// `pqz-plonky3-w46`; v < 2^32 and b < 2^20 are range-checked by the packed R_RC chunk proofs, not by the Exec / run AIR).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum WFmt {
    #[default]
    Old,
    P2r,
}

impl WFmt {
    pub fn parse(s: &str) -> Option<WFmt> {
        match s {
            "old" => Some(WFmt::Old),
            "p2r" => Some(WFmt::P2r),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            WFmt::Old => "old",
            WFmt::P2r => "p2r",
        }
    }
    /// absorbed words (= trace rows) per block of `block_size` records
    pub fn rows_per_block(self, block_size: usize) -> usize {
        match self {
            WFmt::Old => block_size + 1,
            WFmt::P2r => pqz_plonky3_w36::pair::rows_per_block(block_size),
        }
    }
}

/// P3 = Plonky3 (w33): Goldilocks, Poseidon2 width 12, Blake3 Merkle, plain mode, one proof per relation. The only setting of this driver.
pub fn setting_of(name: &str) -> Res<Setting> {
    match name {
        "P3" => Ok(Setting { name: "P3", hash: "Poseidon2/Blake3" }),
        _ => Err(RunError::new(2, format!("unknown setting {name}: this driver (w34) has the single setting P3 (Plonky3, one proof per relation); S0/S2 belong to the w30 driver"))),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------------------------

/// 32 bytes -> 4 field elements as canonical u64 (each 8 bytes little endian, reduced mod p). Used for Omega_e, d_Q and the descriptor tag.
pub fn f4(x: &[u8; 32]) -> [u64; 4] {
    let mut o = [0u64; 4];
    for (i, e) in o.iter_mut().enumerate() {
        *e = u64::from_le_bytes(x[8 * i..8 * i + 8].try_into().unwrap()) % GOLDILOCKS_P;
    }
    o
}

fn tag_of_descriptor(d: &[u8; 32]) -> u64 {
    u64::from_le_bytes(d[..8].try_into().unwrap()) % GOLDILOCKS_P
}

/// w35 v3 (D1c): hd_g = SHA3("pqz-w35-hd" || e || g || D_{g,1} || ... || D_{g,B}) for the block with 0-based index `g0` (the `g` of the
/// header word). Truncated into the two header slots 5 and 6 by `header_of_block`.
pub fn hd_of(g0: u64, ds: &[[u8; 32]]) -> [u8; 32] {
    let (e, g) = (u64b(EPOCH), u64b(g0));
    let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + ds.len());
    parts.push(b"pqz-w35-hd");
    parts.push(&e);
    parts.push(&g);
    for d in ds {
        parts.push(d);
    }
    sha3_parts(&parts)
}

/// w35 v3 header word [e, g, m_b, pid, seq_start_g, hd_lo, hd_hi, 1]; hd_lo, hd_hi = u64 LE of bytes 0..8 and 8..16 of hd_g, each mod p
/// (about 127 bits of hd_g). `ds` = the descriptors D_{g,1..B} of the block.
pub fn header_of_block(g0: usize, ds: &[[u8; 32]]) -> RawWord {
    let hd = hd_of(g0 as u64, ds);
    let mut w = header_word(EPOCH, g0 as u64, BLOCK as u64, PID, 1 + (g0 * BLOCK) as u64);
    w[5] = u64::from_le_bytes(hd[..8].try_into().unwrap()) % GOLDILOCKS_P;
    w[6] = u64::from_le_bytes(hd[8..16].try_into().unwrap()) % GOLDILOCKS_P;
    w
}

/// The value v of the record that R_Exec sees: THETA if the predicate P1 (A = x) holds, else 0.
pub fn v_of(r: &Record) -> u64 {
    if Predicate::P1.matches(r) {
        THETA
    } else {
        0
    }
}

/// Reference hash chain of a word stream, written here directly on the Plonky3 permutation (NOT through w33's `native_digest`),
/// so the gates compare the statements against an independent implementation of the sponge of `bench/pqz-plonky3-w35/README.md` section 3:
/// capacity = [DOM_CHAIN, n_words, 0, 0] at state[8..12]; per word `state[0..8] += word`, then one permutation; digest = state[0..4] after the last word.
pub fn ref_chain_digest(words: &[RawWord]) -> Vec<u64> {
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    let perm = c1::perm();
    let mut s = [c1::Val::ZERO; 12];
    s[8] = c1::Val::from_u64(DOM_CHAIN);
    s[9] = c1::Val::from_u64(words.len() as u64);
    for w in words {
        for j in 0..8 {
            s[j] += c1::Val::from_u64(w[j]);
        }
        perm.permute_mut(&mut s);
    }
    (0..4).map(|j| s[j].as_canonical_u64()).collect()
}

/// Same reference chain over PACKED words (IV = packed word count), independent of the circuits (as `ref_chain_digest`).
pub fn ref_chain_digest_packed(words: &[Vec<u64>]) -> Vec<u64> {
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    let perm = c1::perm();
    let mut s = [c1::Val::ZERO; 12];
    s[8] = c1::Val::from_u64(DOM_CHAIN);
    s[9] = c1::Val::from_u64(words.len() as u64);
    for w in words {
        for j in 0..8 {
            s[j] += c1::Val::from_u64(w[j]);
        }
        perm.permute_mut(&mut s);
    }
    (0..4).map(|j| s[j].as_canonical_u64()).collect()
}

// ---------------------------------------------------------------------------------------------------------------
// P3a: log construction + descriptors
// ---------------------------------------------------------------------------------------------------------------

/// What P3a produces. `tags` are the 45 keyed tags per record (flat), kept for the protected search.
pub struct Log {
    pub tags: Vec<Tag>,
    pub blooms: Vec<Bloom>,
    /// D_i per record, in record order
    pub descriptors: Vec<[u8; 32]>,
    /// w35: H(CT_i) = sha3("pqz-ct", ct) per record (the AA recomputes D_i from it, `descriptor_h`)
    pub h_cts: Vec<[u8; 32]>,
    /// header + record words of the whole epoch (the R_RC stream), in the w33 `Workload` form (8 raw values per word)
    pub wl: Workload,
    pub blocks: Vec<AuditBlock>,
    /// R_e = MerkleRoot(B_{e,1..G_e}) (ledger's `epoch_root`)
    pub r_e: Hash,
}

impl Log {
    pub fn n_blocks(&self) -> usize {
        self.blooms.len()
    }
    pub fn record_tags(&self, g: usize, i: usize) -> &[Tag] {
        let s = (g * BLOCK + i) * TAGS_PER_RECORD;
        &self.tags[s..s + TAGS_PER_RECORD]
    }
}

/// Descriptor of one record (CHANGES-w30.md, "what D_i contains"): SHA3 over PID, ID, e, seq, H(CT), H(I^PS).
/// Left out because the prototype has no such object: WK_i, CT_i^HE, C_i, and H(pi_i^RC) (our R_RC is one batch proof made AFTER the descriptors).
pub fn descriptor(id: u64, seq: u64, ct: &[u8], tags: &[Tag]) -> [u8; 32] {
    descriptor_h(id, seq, &h_ct_of(ct), tags)
}

/// H(CT_i) as used in D_i.
pub fn h_ct_of(ct: &[u8]) -> [u8; 32] {
    sha3_parts(&[b"pqz-ct", ct])
}

/// D_i from the ciphertext hash (w35: the AA holds H(CT_i), not the ciphertext). Same bytes as `descriptor`.
pub fn descriptor_h(id: u64, seq: u64, h_ct: &[u8; 32], tags: &[Tag]) -> [u8; 32] {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(1 + tags.len());
    parts.push(b"pqz-ips");
    for t in tags {
        parts.push(t);
    }
    let h_ips = sha3_parts(&parts);
    sha3_parts(&[b"pqz-D", &u64b(PID), &u64b(id), &u64b(EPOCH), &u64b(seq), h_ct, &h_ips])
}

/// P3a. Real AES-256-GCM encryption + 45 keyed tags per record (`pqz_eval::eapat::encrypt_record`), descriptor D_i, leaf, Bloom block
/// summary (`Bloom::build`, the call `eapat::build_block` makes), block record root, block commitment B_{e,g}, epoch root R_e, and the
/// word stream of R_RC. Single thread. `records.len()` must be a multiple of BLOCK. The ciphertext is hashed and dropped (not stored).
/// Unchanged from w30 except the word type: a word is `[PID, EPOCH, seq, id, v, b, tag, 0]` as 8 plain u64 (w33 `RawWord`), a header is w33 `header_word`.
pub fn build_log(records: &[Record], keys: &EpochKeys) -> Log {
    assert!(records.len() % BLOCK == 0 && !records.is_empty());
    let n = records.len();
    let g_e = n / BLOCK;
    let seq_start = 1u64;
    let mut tags: Vec<Tag> = Vec::with_capacity(n * TAGS_PER_RECORD);
    let mut blooms = Vec::with_capacity(g_e);
    let mut descriptors = Vec::with_capacity(n);
    let mut h_cts: Vec<[u8; 32]> = Vec::with_capacity(n);
    let mut words: Vec<RawWord> = Vec::with_capacity(g_e * (BLOCK + 1));
    let mut blocks = Vec::with_capacity(g_e);
    for (g, chunk) in records.chunks(BLOCK).enumerate() {
        let q_start = seq_start + (g * BLOCK) as u64;
        let hdr_idx = words.len();
        words.push(header_word(EPOCH, g as u64, BLOCK as u64, PID, q_start)); // slots 5-6 are set below (w35 v3: hd_g)
        let tag_start = tags.len();
        let mut leaves: Vec<Hash> = Vec::with_capacity(BLOCK);
        for (i, r) in chunk.iter().enumerate() {
            let seq = q_start + i as u64;
            let enc = encrypt_record(keys, r);
            assert_eq!(enc.tags.len(), TAGS_PER_RECORD);
            let h_ct = h_ct_of(&enc.ciphertext);
            let d = descriptor_h(r.id, seq, &h_ct, &enc.tags);
            h_cts.push(h_ct);
            leaves.push(leaf_hash(&h(&[&u64b(EPOCH), &u64b(seq), &d])));
            words.push([PID, EPOCH, seq, r.id, v_of(r), r.b as u64, tag_of_descriptor(&d), 0]);
            tags.extend_from_slice(&enc.tags);
            descriptors.push(d);
        }
        words[hdr_idx] = header_of_block(g, &descriptors[g * BLOCK..(g + 1) * BLOCK]);
        let bloom = Bloom::build(chunk.len(), tags[tag_start..].iter());
        blocks.push(AuditBlock {
            e: EPOCH,
            g: g as u64 + 1,
            q_start,
            q_next: q_start + BLOCK as u64,
            count: BLOCK as u64,
            r_rec: merkle_root(&leaves),
            s_hash: h(&[b"PQZ-summary", &bloom.digest()]),
        });
        blooms.push(bloom);
    }
    let r_e = epoch_root(&blocks);
    Log { tags, blooms, descriptors, h_cts, wl: Workload { n_blocks: g_e, block_size: BLOCK, epoch: EPOCH, pid: PID, seq_start, words }, blocks, r_e }
}

// ---------------------------------------------------------------------------------------------------------------
// Proof stages (R_RC, R_Exec)
// ---------------------------------------------------------------------------------------------------------------

/// Sub-timers and sizes of one proof stage. `pub_s` = word mapping + public inputs by the native sponge (digest) and the claimed result;
/// `trace_s` = trace building (+ public value vector); `prove_s` = proving + serialising. All three are inside the stage timer.
#[derive(Clone, Debug, Default)]
pub struct ProofStage {
    pub pub_s: f64,
    pub trace_s: f64,
    pub prove_s: f64,
    pub rows: usize,
    pub chunks: usize,
    pub bytes: usize,
    pub conj: u32,
    pub udr: u32,
    pub ldr: u32,
}

impl ProofStage {
    pub fn total_s(&self) -> f64 {
        self.pub_s + self.trace_s + self.prove_s
    }
    /// security estimate (`security.rs`) of a proof made with `opts()` over a trace of `rows` rows
    fn note(&mut self, rows: usize) {
        let s = estimate(&c1::sec_input(&opts(), rows));
        self.conj = if self.conj == 0 { s.conjectured } else { self.conj.min(s.conjectured) };
        self.udr = if self.udr == 0 { s.proven_unique_decoding } else { self.udr.min(s.proven_unique_decoding) };
        self.ldr = if self.ldr == 0 { s.proven_list_decoding } else { self.ldr.min(s.proven_list_decoding) };
    }
}

/// The R_RC proof as sent to the AA: serialised proof + the statement. ONE proof over the whole epoch stream.
pub struct RcProof {
    pub bytes: Vec<u8>,
    pub stmt: RcPublic,
}

/// P3b. Prove R_RC over the whole epoch stream (body of `pchild3` `run_rc`).
pub fn prove_rc_stage(wl: &Workload) -> Res<(RcProof, ProofStage)> {
    let mut st = ProofStage::default();
    let o = opts();
    let t = Instant::now();
    let words = c1::words(wl);
    let stmt = plain::rc_public(&words, wl.block_size);
    st.pub_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let a = plain::rc_air(stmt.block_size as u64, stmt.n_words() as u64);
    let trace = a.build_trace(&c1::perm(), &words);
    let pv = stmt.to_values::<c1::Val>(&a.lay);
    st.trace_s = t.elapsed().as_secs_f64();
    st.rows = trace.height();
    let t = Instant::now();
    let proof = p3_uni_stark::prove(&c1::config(&o), &a, trace, &pv).map_err(|e| RunError::new(4, format!("R_RC prove failed: {e:?}")))?;
    st.note(st.rows);
    let b = c1::to_bytes(&proof);
    st.prove_s = t.elapsed().as_secs_f64();
    st.chunks = 1;
    st.bytes = b.len();
    Ok((RcProof { bytes: b, stmt }, st))
}

fn parse(b: &[u8], what: &str) -> Res<c1::P> {
    c1::from_bytes(b).map_err(|e| RunError::new(5, format!("{what}: proof parse failed: {e}")))
}

/// P4a. The AA parses and verifies the R_RC proof (the verifier builds its own AIR and its own `FriOpts`).
pub fn verify_rc_stage(p: &RcProof) -> Res<()> {
    plain::verify_rc(&opts(), &parse(&p.bytes, "R_RC")?, &p.stmt).map_err(|e| RunError::new(5, format!("R_RC verifier rejected: {e}")))
}

/// R_Exec proof as sent to the requester.
pub struct ExecProof {
    pub bytes: Vec<u8>,
    pub stmt: ExecPublic,
}

/// P6b. Prove R_Exec over the words of `wl` (body of `pchild3` `run_exec`). `claim` = (count, sum) the CSP states (NOT recomputed from the words:
/// a wrong claim gives a proof that does not verify); `ctx` = execution context C_Q (`exec_context(B_Q, d_Q, RID)` of the Auth statement).
pub fn prove_exec_stage(wl: &Workload, ctx: [u64; 4], claim: (u64, u64)) -> Res<(ExecProof, ProofStage)> {
    let mut st = ProofStage::default();
    let o = opts();
    let t = Instant::now();
    let words = c1::words(wl);
    let digest = native_digest::<c1::Val, 12, _>(&c1::lay(), &c1::perm(), &words);
    let stmt = ExecPublic { digest, n_blocks: wl.n_blocks, block_size: wl.block_size, theta: THETA, count: claim.0, sum: vec![claim.1], ctx };
    st.pub_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let a = c1::air(THETA, stmt.n_words() as u64);
    let trace = a.build_trace(&c1::perm(), &words);
    let pv = stmt.to_values::<c1::Val>(&a.lay);
    st.trace_s = t.elapsed().as_secs_f64();
    st.rows = trace.height();
    let t = Instant::now();
    let proof = p3_uni_stark::prove(&c1::config(&o), &a, trace, &pv).map_err(|e| RunError::new(4, format!("R_Exec prove failed: {e:?}")))?;
    st.note(st.rows);
    let b = c1::to_bytes(&proof);
    st.prove_s = t.elapsed().as_secs_f64();
    st.chunks = 1;
    st.bytes = b.len();
    Ok((ExecProof { bytes: b, stmt }, st))
}

/// Parse and verify the R_Exec proof against the statement `stmt` the requester holds (guarded verifier: a panic on malformed input is a rejection).
pub fn verify_exec_stage(p: &ExecProof, stmt: &ExecPublic) -> Res<()> {
    plain::verify_exec(&opts(), &parse(&p.bytes, "R_Exec")?, stmt).map_err(|e| RunError::new(5, format!("R_Exec verifier rejected: {e}")))
}

// ---------------------------------------------------------------------------------------------------------------
// w46: P2r stages of the w34 driver (`--exec-stream whole` only)
// ---------------------------------------------------------------------------------------------------------------

/// P2r R_RC proof as sent to the AA: ONE packed chunk (chunk_index 0) that holds every block, plus the tag / header lists.
pub struct PRcProof {
    pub bytes: Vec<u8>,
    pub stmt: pqz_plonky3_w36::chunk::RcChunkPublic,
    pub lists: pqz_plonky3_w36::chunk::ChunkLists,
}

/// P3b (P2r): R_RC over the packed epoch stream = one pchunk chunk with all blocks.
pub fn prove_rc_stage_p(wl: &Workload) -> Res<(PRcProof, ProofStage)> {
    use pqz_plonky3_w36::{pair, pchunk};
    let mut st = ProofStage::default();
    let o = opts();
    let t = Instant::now();
    let words = pair::pack_workload(wl);
    let (mut pubs, mut lists) = pchunk::plain::honest_publics(&words, wl.block_size, wl.n_blocks);
    if pubs.len() != 1 {
        return Err(RunError::new(6, "P2r R_RC: expected one chunk for the whole stream"));
    }
    let stmt = pubs.remove(0);
    let lists = lists.remove(0);
    st.pub_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let a = pchunk::plain::chunk_air(&stmt).map_err(|e| RunError::new(4, format!("R_RC (p2r) statement: {e}")))?;
    let trace = a.build_trace(&c1::perm(), &words, &stmt.s_in, &stmt.alpha, &stmt.beta, stmt.hdr_before as u64);
    let pv = pchunk::plain::values(&stmt);
    st.trace_s = t.elapsed().as_secs_f64();
    st.rows = trace.height();
    let t = Instant::now();
    let proof = p3_uni_stark::prove(&c1::config(&o), &a, trace, &pv).map_err(|e| RunError::new(4, format!("R_RC (p2r) prove failed: {e:?}")))?;
    st.note(st.rows);
    let b = c1::to_bytes(&proof);
    st.prove_s = t.elapsed().as_secs_f64();
    st.chunks = 1;
    st.bytes = b.len();
    Ok((PRcProof { bytes: b, stmt, lists }, st))
}

/// P4a (P2r): the AA verifies the packed R_RC proof.
pub fn verify_rc_stage_p(p: &PRcProof) -> Res<()> {
    pqz_plonky3_w36::pchunk::plain::verify_chunk(&opts(), &parse(&p.bytes, "R_RC (p2r)")?, &p.stmt).map_err(|e| RunError::new(5, format!("R_RC (p2r) verifier rejected: {e}")))
}

/// P6b (P2r): packed R_Exec (P2r AIR: no range check of v) over the words of `wl`. `claim` as in `prove_exec_stage`.
pub fn prove_exec_stage_p(wl: &Workload, ctx: [u64; 4], claim: (u64, u64)) -> Res<(ExecProof, ProofStage)> {
    use pqz_plonky3_w36::pair::{self, Fmt};
    let mut st = ProofStage::default();
    let o = opts();
    let t = Instant::now();
    let words = pair::pack_workload(wl);
    let digest = native_digest::<c1::Val, 12, _>(&pqz_plonky3_w36::air::Layout::new(0, 12, 0), &c1::perm(), &words);
    let stmt = ExecPublic { digest, n_blocks: wl.n_blocks, block_size: wl.block_size, theta: THETA, count: claim.0, sum: vec![claim.1], ctx };
    st.pub_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let a = pair::pair_air(THETA, pair::pair_n_words(wl.n_blocks, wl.block_size) as u64, Fmt::P2r);
    let trace = a.build_trace(&c1::perm(), &words, wl.block_size);
    let pv = pair::pair_values(&stmt);
    st.trace_s = t.elapsed().as_secs_f64();
    st.rows = trace.height();
    let t = Instant::now();
    let proof = p3_uni_stark::prove(&c1::config(&o), &a, trace, &pv).map_err(|e| RunError::new(4, format!("R_Exec (p2r) prove failed: {e:?}")))?;
    st.note(st.rows);
    let b = c1::to_bytes(&proof);
    st.prove_s = t.elapsed().as_secs_f64();
    st.chunks = 1;
    st.bytes = b.len();
    Ok((ExecProof { bytes: b, stmt }, st))
}

pub fn verify_exec_stage_p(p: &ExecProof, stmt: &ExecPublic) -> Res<()> {
    pqz_plonky3_w36::pair::verify_pair(&opts(), &parse(&p.bytes, "R_Exec (p2r)")?, stmt, pqz_plonky3_w36::pair::Fmt::P2r)
        .map_err(|e| RunError::new(5, format!("R_Exec (p2r) verifier rejected: {e}")))
}

/// Native checks of the requester for P2r whole: theta, then `native_bundle_checks_p` (packed stream link `check_stream_link_p`, the lists
/// `check_sealed`, C_Q link, scope). Old arm: theta + `native_bundle_checks` (digest / n_blocks / block_size link, C_Q link, scope).
pub fn requester_native_checks_p(auth: &AuthPublic, exec: &ExecPublic, rc: &PRcProof) -> Result<LinkKind, String> {
    if exec.theta != THETA {
        return Err(format!("exec theta {} != requested theta {}", exec.theta, THETA));
    }
    pqz_plonky3_w36::prequest::native_bundle_checks_p(NativeChecks::ON, auth, exec, std::slice::from_ref(&rc.stmt), std::slice::from_ref(&rc.lists), RID)?;
    Ok(LinkKind::Full)
}

/// P7 (P2r): native checks first, then R_Auth, then the packed R_Exec.
pub fn verify_requester_p(auth: &AuthProof, exec: &ExecProof, rc: &PRcProof) -> Res<(RequesterTimes, LinkKind)> {
    let mut tm = RequesterTimes::default();
    let t = Instant::now();
    let kind = requester_native_checks_p(&auth.stmt, &exec.stmt, rc).map_err(|e| RunError::new(5, format!("requester native check rejected: {e}")))?;
    tm.native_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    verify_auth_stage(auth)?;
    tm.auth_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    verify_exec_stage_p(exec, &exec.stmt)?;
    tm.exec_s = t.elapsed().as_secs_f64();
    Ok((tm, kind))
}

/// How the requester ties the R_Exec statement to the R_RC statement.
/// `Full` (R_Exec covers the whole epoch stream): w33 `native_bundle_checks`, i.e. digest, n_blocks and block_size equal, then the C_Q link and the scope order.
/// `Subset` (R_Exec covers only the retained blocks, so its digest cannot equal the epoch digest): block_size equal and 0 < exec blocks <= rc blocks,
/// then the C_Q link and the scope order (`native_request_checks`). The retained words being really blocks of the epoch stream is NOT proven (as in w30; the gates check it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    Full,
    Subset,
}

impl LinkKind {
    pub fn name(self) -> &'static str {
        match self {
            LinkKind::Full => "full",
            LinkKind::Subset => "subset",
        }
    }
    /// `Full` iff the two statements have the same number of blocks, else `Subset`.
    pub fn of(exec: &ExecPublic, rc: &RcPublic) -> LinkKind {
        if exec.n_blocks == rc.n_blocks {
            LinkKind::Full
        } else {
            LinkKind::Subset
        }
    }
}

/// All native (proof-free) checks of the requester, with w33's `NativeChecks::ON` (stream link, C_Q link, scope). Returns which link was applied.
pub fn requester_native_checks(auth: &AuthPublic, exec: &ExecPublic, rc: &RcPublic) -> Result<LinkKind, String> {
    // the requester knows its own predicate: theta of the statement must be the one it asked for (not a w33 check; the proof only binds the stated theta)
    if exec.theta != THETA {
        return Err(format!("exec theta {} != requested theta {}", exec.theta, THETA));
    }
    let kind = LinkKind::of(exec, rc);
    match kind {
        LinkKind::Full => native_bundle_checks(NativeChecks::ON, auth, exec, rc, RID)?,
        LinkKind::Subset => {
            if exec.block_size != rc.block_size {
                return Err(format!("link: block_size differ (exec {} vs rc {})", exec.block_size, rc.block_size));
            }
            if exec.n_blocks == 0 || exec.n_blocks > rc.n_blocks {
                return Err(format!("link: exec n_blocks {} not in 1..={} (rc)", exec.n_blocks, rc.n_blocks));
            }
            native_request_checks(NativeChecks::ON, auth, exec, RID)?;
        }
    }
    Ok(kind)
}

/// Times of the requester stage (P7).
#[derive(Clone, Copy, Debug, Default)]
pub struct RequesterTimes {
    pub native_s: f64,
    pub auth_s: f64,
    pub exec_s: f64,
}

/// P7. Requester verification = w33 request verification (`request::verify_request_with` body, plus the stream link against the R_RC statement the AA
/// verified in P4a): native checks FIRST (stream link, C_Q link, scope; all ON), then parse + verify R_Auth, then parse + verify R_Exec. R_RC is not
/// re-verified here (the AA did it in P4a, as in w30 and in the paper's Phase 4). The Exec statement is the one the CSP sent (its `ctx` is CHECKED against
/// the C_Q recomputed from the verified Auth statement by `check_ctx`; it is not overwritten).
pub fn verify_requester(auth: &AuthProof, exec: &ExecProof, rc_stmt: &RcPublic) -> Res<(RequesterTimes, LinkKind)> {
    let mut tm = RequesterTimes::default();
    let t = Instant::now();
    let kind = requester_native_checks(&auth.stmt, &exec.stmt, rc_stmt).map_err(|e| RunError::new(5, format!("requester native check rejected: {e}")))?;
    tm.native_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    verify_auth_stage(auth)?;
    tm.auth_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    verify_exec_stage(exec, &exec.stmt)?;
    tm.exec_s = t.elapsed().as_secs_f64();
    Ok((tm, kind))
}

/// Used by the tests: is the full-stream link satisfied (w33 `check_stream_link`)?
pub fn full_link_ok(exec: &ExecPublic, rc: &RcPublic) -> Result<(), String> {
    check_stream_link(exec, rc)
}

// ---------------------------------------------------------------------------------------------------------------
// Ledger (P4b)
// ---------------------------------------------------------------------------------------------------------------

pub struct LedgerCtx {
    pub led: Ledger,
    pub aa: SigKeys,
    pub chain: Chain,
}

/// Setup (outside every stage timer): AA key, genesis chain, a 4-validator ledger simulation (ML-DSA-65 keys from seeds, benchmark only).
pub fn ledger_setup(seed: u64) -> LedgerCtx {
    let s = h(&[b"pqz-w30", &u64b(seed)]);
    let aa = SigKeys::from_seed(h(&[b"aa", &s]));
    let chain = Chain::genesis(&aa);
    let cfg = LedgerConfig::default();
    let led = Ledger::new(cfg, chain.genesis_contract(), vec![aa.vk.clone()], s);
    LedgerCtx { led, aa, chain }
}

#[derive(Clone, Debug, Default)]
pub struct LedgerStats {
    /// A_e, sigma_e = ML-DSA.Sign_AA(H(A_e)), Gamma_e, Omega_e (`Chain::next_anchor_root_only`)
    pub seal_s: f64,
    /// submitter signature on the anchor transaction
    pub txsign_s: f64,
    /// `Ledger::submit`: leader proposal, 4 validators execute and vote, quorum certificate checked
    pub submit_s: f64,
    pub blocks: usize,
}

impl LedgerStats {
    pub fn total_s(&self) -> f64 {
        self.seal_s + self.txsign_s + self.submit_s
    }
}

/// P4b. Commit epoch `EPOCH` (R_e, N_e, G_e from the real log) in the ledger simulation. The contract checks the anchor rules (epoch number, p_e, Omega_e).
pub fn commit_epoch(lc: &mut LedgerCtx, r_e: Hash, n_e: u64, g_e: u64) -> Res<(LedgerStats, Hash)> {
    let mut st = LedgerStats::default();
    let t = Instant::now();
    let tx = lc.chain.next_anchor_root_only(&lc.aa, r_e, n_e, g_e);
    st.seal_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let signed = SignedTx::sign(tx, 0, &lc.aa, &lc.led.cfg);
    st.txsign_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let res = lc.led.submit(vec![signed]);
    st.submit_s = t.elapsed().as_secs_f64();
    st.blocks = res.blocks.len();
    match res.receipts.first() {
        Some(r) if r.result.is_ok() => {}
        other => return Err(RunError::new(6, format!("ledger rejected the anchor transaction: {:?}", other.map(|r| &r.result)))),
    }
    let om = lc.chain.epoch(EPOCH).omega;
    Ok((st, om))
}

/// Light-client read of State[e] with its Merkle path and quorum certificate, and a comparison of the committed Omega_e with `omega`.
/// A gate (outside every stage timer): returns the seconds it took.
pub fn ledger_read_gate(lc: &LedgerCtx, omega: &Hash) -> Res<f64> {
    let t = Instant::now();
    let rp = lc.led.read_state(&key_state(EPOCH)).ok_or_else(|| RunError::new(6, "State[e] not found in the ledger"))?;
    if !verify_read(&rp, &lc.led.validator_vks, lc.led.cfg.quorum()) {
        return Err(RunError::new(6, "ledger read proof (QC + Merkle path) did not verify"));
    }
    let entry = lc.led.contract().state_entry(EPOCH).ok_or_else(|| RunError::new(6, "no state entry for the epoch"))?;
    if &entry.omega != omega {
        return Err(RunError::new(6, "Omega_e in the ledger differs from the Omega_e used in the Auth statement"));
    }
    Ok(t.elapsed().as_secs_f64())
}


// ---------------------------------------------------------------------------------------------------------------
// P5: authorization proof
// ---------------------------------------------------------------------------------------------------------------

pub struct AuthProof {
    pub bytes: Vec<u8>,
    pub stmt: AuthPublic,
}

#[derive(Clone, Debug, Default)]
pub struct AuthStage {
    pub prep_s: f64,
    pub trace_s: f64,
    pub prove_s: f64,
    pub rows: usize,
    pub bytes: usize,
    pub conj: u32,
    pub udr: u32,
    pub ldr: u32,
}

impl AuthStage {
    pub fn total_s(&self) -> f64 {
        self.prep_s + self.trace_s + self.prove_s
    }
}

/// d_Q of the request: SHA3 over a fixed label, the query id and the textual predicate (field elements via `f4`). Unchanged from w30 (SHA3, not Rescue).
pub fn d_q_of(qid: u64, predicate: &str) -> [u64; 4] {
    f4(&sha3_parts(&[b"pqz-dQ", &u64b(qid), predicate.as_bytes()]))
}

/// P5. Build the R_Auth statement (policy leaf and path from w33 `honest_auth_instance`; d_Q from the predicate; Omega from the ledger's Omega_e;
/// B_Q recomputed with w33 `bind_hash` = Poseidon2) and prove it. The policy leaf, the scope and the other policy-tree leaves are FIXED synthetic values (as w30).
pub fn auth_stage(omega: &Hash, qid: u64, predicate: &str, seed: u64) -> Res<(AuthProof, AuthStage)> {
    let mut st = AuthStage::default();
    let o = opts();
    let perm = c1::perm();
    let t = Instant::now();
    let (mut p, w) = honest_auth_instance::<c1::Val, _>(&perm, AUTH_DEPTH, seed);
    p.d_q = d_q_of(qid, predicate);
    p.omega = f4(omega);
    p.b_q = bind_hash::<c1::Val, _>(&perm, p.d_q, p.uid, p.v_a, p.v_auth, p.r_pol, p.omega);
    st.prep_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let a = plain::auth_air_for(&o, p.depth);
    let trace = a.build_trace(&perm, &p, &w).map_err(|e| RunError::new(4, format!("R_Auth trace failed: {e}")))?;
    let pv = p.to_values::<c1::Val>();
    st.trace_s = t.elapsed().as_secs_f64();
    st.rows = trace.height();
    let t = Instant::now();
    let proof = p3_uni_stark::prove(&c1::config(&o), &a, trace, &pv).map_err(|e| RunError::new(4, format!("R_Auth prove failed: {e:?}")))?;
    let s = estimate(&c1::sec_input(&o, st.rows));
    st.conj = s.conjectured;
    st.udr = s.proven_unique_decoding;
    st.ldr = s.proven_list_decoding;
    let bytes = c1::to_bytes(&proof);
    st.prove_s = t.elapsed().as_secs_f64();
    st.bytes = bytes.len();
    Ok((AuthProof { bytes, stmt: p }, st))
}

pub fn verify_auth_stage(a: &AuthProof) -> Res<()> {
    plain::verify_auth(&opts(), &parse(&a.bytes, "R_Auth")?, &a.stmt).map_err(|e| RunError::new(5, format!("R_Auth verifier rejected: {e}")))
}

// ---------------------------------------------------------------------------------------------------------------
// P6a: protected search
// ---------------------------------------------------------------------------------------------------------------

/// The predicate of this driver: P1 = (A = x), one leaf with one tag (the same formula pqz-integrated used).
pub fn predicate_formula(keys: &EpochKeys) -> (Formula, Tag) {
    let f = formula_for(Predicate::P1, &keys.tag_key);
    let tag = eq_tag(&keys.tag_key, ATTR_A, pqz_eval::x());
    match &f {
        Formula::Leaf(t) if t.len() == 1 && t[0] == tag => {}
        _ => panic!("P1 is expected to be a single leaf with one tag"),
    }
    (f, tag)
}

pub struct SearchOut {
    /// block may contain a match
    pub flags: Vec<bool>,
    /// ids of the records the exact predicate selected, in record order
    pub sel: Vec<u64>,
    pub bps_s: f64,
    pub rps_s: f64,
}

/// P6a. BPS: real `bps_eval` on every block summary. RPS (exact predicate): real `rps_eval` on the tags of every record of every retained block.
pub fn search(log: &Log, f: &Formula) -> SearchOut {
    let t = Instant::now();
    let flags: Vec<bool> = std::hint::black_box(log.blooms.iter().map(|b| bps_eval(b, f)).collect());
    let bps_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let mut sel = Vec::new();
    for (g, &fl) in flags.iter().enumerate() {
        if fl {
            for i in 0..BLOCK {
                if rps_eval(log.record_tags(g, i), f) {
                    sel.push(log.wl.words[g * (BLOCK + 1) + 1 + i][3]);
                }
            }
        }
    }
    let sel = std::hint::black_box(sel);
    let rps_s = t.elapsed().as_secs_f64();
    SearchOut { flags, sel, bps_s, rps_s }
}

/// P6b preparation: the words of the used blocks (headers kept as they are in the epoch stream) as a w33 Workload, the claimed result
/// (count = number of selected ids, sum = sum of b over the selected ids, read from the selected records' words) and the used-block flags.
/// `Retained` = the blocks BPS retained (w30); `Whole` = every block of the epoch stream.
pub fn exec_input(log: &Log, s: &SearchOut, es: ExecStream) -> (Workload, (u64, u64), Vec<bool>) {
    let used: Vec<bool> = match es {
        ExecStream::Retained => s.flags.clone(),
        ExecStream::Whole => vec![true; s.flags.len()],
    };
    let mut words = Vec::new();
    let mut n_blocks = 0;
    for (g, &fl) in used.iter().enumerate() {
        if fl {
            words.extend_from_slice(&log.wl.words[g * (BLOCK + 1)..(g + 1) * (BLOCK + 1)]);
            n_blocks += 1;
        }
    }
    let mut sum = 0u64;
    for &id in &s.sel {
        sum += log.wl.words[(id as usize / BLOCK) * (BLOCK + 1) + 1 + id as usize % BLOCK][5];
    }
    let wl = Workload { n_blocks, block_size: BLOCK, epoch: EPOCH, pid: PID, seq_start: log.wl.seq_start, words };
    (wl, (s.sel.len() as u64, sum), used)
}

// ---------------------------------------------------------------------------------------------------------------
// One end-to-end run
// ---------------------------------------------------------------------------------------------------------------

#[derive(Default)]
pub struct Outcome {
    pub n: usize,
    pub g: usize,
    pub sigma: usize,
    pub r: usize,
    pub r_hit_blocks: usize,
    pub n_sel: usize,
    pub gen_s: f64,
    pub setup_s: f64,
    pub p3a_s: f64,
    pub rc: ProofStage,
    pub p3b_s: f64,
    pub p4a_s: f64,
    pub led: LedgerStats,
    pub p4b_s: f64,
    pub auth: AuthStage,
    pub p5_s: f64,
    pub bps_s: f64,
    pub rps_s: f64,
    pub p6a_s: f64,
    pub exec_prep_s: f64,
    pub exec: ProofStage,
    pub p6b_s: f64,
    pub p7_auth_s: f64,
    pub p7_exec_s: f64,
    pub p7_s: f64,
    /// w34 additions (trailing CSV columns): time of the requester's native checks (inside p7_s), link kind applied, R_Exec stream choice
    pub p7_native_s: f64,
    pub link_kind: Option<LinkKind>,
    pub exec_stream: Option<ExecStream>,
    /// w46: stream format of the run
    pub fmt: WFmt,
    pub total_s: f64,
    pub wall_s: f64,
    pub gates_s: f64,
    pub gate_ledger_read_s: f64,
    /// VmHWM after each stage (reset before it)
    pub peak: [u64; 9],
    pub hwm_reset_ok: bool,
    pub process_peak_kb: u64,
}

pub const STAGE_NAMES: [&str; 9] = ["p3a", "p3b", "p4a", "p4b", "p5", "p6a", "p6b", "p7", "gates"];

fn stage<T>(o: &mut Outcome, idx: usize, f: impl FnOnce() -> T) -> (T, f64) {
    o.hwm_reset_ok &= sys::reset_hwm();
    let t = Instant::now();
    let r = f();
    let s = t.elapsed().as_secs_f64();
    o.peak[idx] = sys::status_kb("VmHWM:");
    (r, s)
}

/// Everything the gates compare; separate from `Outcome` so the tests can use the same checks.
pub struct GateInput<'a> {
    pub records: &'a [Record],
    pub log: &'a Log,
    pub search: &'a SearchOut,
    pub exec_wl: &'a Workload,
    /// blocks of the epoch stream the R_Exec stream consists of, in order
    pub exec_used: &'a [bool],
    pub claim: (u64, u64),
    pub rc: &'a RcProof,
    pub exec: &'a ExecProof,
    pub link: LinkKind,
    pub exec_stream: ExecStream,
}

fn gate_err(m: impl Into<String>) -> RunError {
    RunError::new(6, m)
}

/// The gates of CHANGES-w30.md (all outside the timers). The verifiers' acceptance is checked by the stage functions themselves.
/// G2 result = plain reference computed over the PLAINTEXT records; G3 tie = the ids the search selected are exactly the matching
/// records inside the Exec stream, the Exec stream is the retained blocks of the RC stream word for word, and both digests are
/// recomputed here with the reference hash chain.
/// The stream-format independent gates G1, G2, G3 (a)-(c) (shared by `gates` and `gates_p2r`).
#[allow(clippy::too_many_arguments)]
pub fn gates_stream(records: &[Record], log: &Log, search: &SearchOut, exec_wl: &Workload, exec_used: &[bool], claim: (u64, u64), exec_count: u64, exec_sum: u64, es: ExecStream) -> Res<()> {
    let n_blocks = log.n_blocks();
    // G1 plaintext references
    let plain_ids: Vec<u64> = records.iter().filter(|r| Predicate::P1.matches(r)).map(|r| r.id).collect();
    let plain_sum: u64 = records.iter().filter(|r| Predicate::P1.matches(r)).map(|r| r.b as u64).sum();
    // search = plaintext predicate, and no block with a hit was pruned
    if search.sel != plain_ids {
        return Err(gate_err(format!("search selected {} ids, plaintext predicate {}", search.sel.len(), plain_ids.len())));
    }
    let mut hit_block = vec![false; n_blocks];
    for id in &plain_ids {
        hit_block[*id as usize / BLOCK] = true;
    }
    for b in 0..n_blocks {
        if hit_block[b] && !search.flags[b] {
            return Err(gate_err(format!("block {b} contains a hit but BPS pruned it (false negative)")));
        }
    }
    // G2 result: claimed (count, sum) = plain reference; the Exec statement carries the same numbers
    if claim != (plain_ids.len() as u64, plain_sum) {
        return Err(gate_err(format!("claimed result {:?} differs from the plain reference ({}, {})", claim, plain_ids.len(), plain_sum)));
    }
    if exec_count != claim.0 || exec_sum != claim.1 {
        return Err(gate_err("the R_Exec statement does not carry the claimed result"));
    }
    if exec_wl.reference_result(THETA) != claim {
        return Err(gate_err("reference result over the Exec words differs from the claimed result"));
    }
    // G3 tie search <-> Exec: same records. (a) the matching words of the Exec stream carry exactly the selected ids
    let mut exec_ids: Vec<u64> = exec_wl.words.iter().filter(|w| w[7] == 0 && w[4] >= THETA).map(|w| w[3]).collect();
    exec_ids.sort_unstable();
    if exec_ids != search.sel {
        return Err(gate_err("ids matched inside the Exec stream differ from the ids the search selected"));
    }
    // (b) the Exec stream is the used blocks (retained, or all with `Whole`) of the RC stream, word for word, in block order
    if es == ExecStream::Retained && exec_used != search.flags.as_slice() {
        return Err(gate_err("retained mode: the used blocks are not the BPS-retained blocks"));
    }
    let mut off = 0usize;
    for (b, &fl) in exec_used.iter().enumerate() {
        if fl {
            let src = &log.wl.words[b * (BLOCK + 1)..(b + 1) * (BLOCK + 1)];
            if exec_wl.words[off..off + BLOCK + 1] != *src {
                return Err(gate_err(format!("Exec stream block {off} is not block {b} of the RC stream")));
            }
            off += BLOCK + 1;
        }
    }
    if off != exec_wl.words.len() {
        return Err(gate_err("Exec stream has words beyond the used blocks"));
    }
    // (c) every record word carries its descriptor tag, id, b and v from the plaintext record
    for (i, r) in records.iter().enumerate() {
        let w = &log.wl.words[(i / BLOCK) * (BLOCK + 1) + 1 + i % BLOCK];
        if w[3] != r.id || w[5] != r.b as u64 || w[4] != v_of(r) || w[6] != tag_of_descriptor(&log.descriptors[i]) {
            return Err(gate_err(format!("record {i}: word differs from the record or its descriptor")));
        }
    }
    Ok(())
}

/// The gates of CHANGES-w30.md (see `gates_stream`; here the digest and link gates of the OLD format).
pub fn gates(g: &GateInput) -> Res<()> {
    gates_stream(g.records, g.log, g.search, g.exec_wl, g.exec_used, g.claim, g.exec.stmt.count, g.exec.stmt.sum_int(), g.exec_stream)?;
    let log = g.log;
    let n_blocks = log.n_blocks();
    // (d) digests recomputed with the reference chain (independent of the circuits and of the instance builders)
    if ref_chain_digest(&log.wl.words) != g.rc.stmt.digest {
        return Err(gate_err("R_RC digest differs from the reference hash chain over the epoch stream"));
    }
    if ref_chain_digest(&g.exec_wl.words) != g.exec.stmt.digest {
        return Err(gate_err("R_Exec digest differs from the reference hash chain over the retained stream"));
    }
    if g.rc.stmt.n_blocks != n_blocks || g.exec.stmt.n_blocks != g.exec_used.iter().filter(|&&f| f).count() {
        return Err(gate_err("block counts in the statements differ from the log / the used-block count"));
    }
    // (e) the link the requester applied is the one the statements call for (Full iff the Exec stream has every block of the RC stream)
    let want = if g.exec.stmt.n_blocks == g.rc.stmt.n_blocks { LinkKind::Full } else { LinkKind::Subset };
    if g.link != want || (g.exec_stream == ExecStream::Whole && g.link != LinkKind::Full) {
        return Err(gate_err(format!("requester applied the {} link, the statements need the {} link", g.link.name(), want.name())));
    }
    if g.link == LinkKind::Full {
        // the full link also holds when written out here (w33 `check_stream_link` on the two statements)
        full_link_ok(&g.exec.stmt, &g.rc.stmt).map_err(|e| gate_err(format!("full stream link does not hold: {e}")))?;
    }
    Ok(())
}

/// w46: the gates of the P2r whole run. G1-G3 (a)-(c) are `gates_stream`; the digest gates are recomputed with the packed reference chain; the
/// link gate = `check_stream_link_p` written out again on the two statements, plus: the RC statement describes ALL blocks of the log.
pub fn gates_p2r(g: &GateInput, rc: &PRcProof) -> Res<()> {
    gates_stream(g.records, g.log, g.search, g.exec_wl, g.exec_used, g.claim, g.exec.stmt.count, g.exec.stmt.sum_int(), g.exec_stream)?;
    let n_blocks = g.log.n_blocks();
    let packed_rc = pqz_plonky3_w36::pair::pack_workload(&g.log.wl);
    let packed_ex = pqz_plonky3_w36::pair::pack_workload(g.exec_wl);
    if ref_chain_digest_packed(&packed_rc)[..] != rc.stmt.s_out[..4] {
        return Err(gate_err("R_RC (p2r) digest differs from the reference hash chain over the packed epoch stream"));
    }
    if ref_chain_digest_packed(&packed_ex) != g.exec.stmt.digest {
        return Err(gate_err("R_Exec (p2r) digest differs from the reference hash chain over the packed Exec stream"));
    }
    if rc.stmt.n_blocks_chunk != n_blocks || g.exec.stmt.n_blocks != n_blocks || g.exec_stream != ExecStream::Whole || g.link != LinkKind::Full {
        return Err(gate_err("P2r: statements must cover all blocks with the full link (whole mode only)"));
    }
    pqz_plonky3_w36::prequest::check_stream_link_p(&g.exec.stmt, std::slice::from_ref(&rc.stmt)).map_err(|e| gate_err(format!("full stream link (p2r) does not hold: {e}")))?;
    Ok(())
}

/// One end-to-end run in this process. Errors carry the exit code of the child.
pub fn run_one(n: usize, layout: Layout, setting: &Setting, seed: u64) -> Res<Outcome> {
    run_one_with(n, layout, setting, seed, ExecStream::Retained)
}

/// As `run_one` with the R_Exec stream choice (see `ExecStream`). Old format.
pub fn run_one_with(n: usize, layout: Layout, setting: &Setting, seed: u64, es: ExecStream) -> Res<Outcome> {
    run_one_with_fmt(n, layout, setting, seed, es, WFmt::Old)
}

/// w46: as `run_one_with` with the stream format. `WFmt::P2r` needs `ExecStream::Whole` (exit code 2 otherwise).
pub fn run_one_with_fmt(n: usize, layout: Layout, setting: &Setting, seed: u64, es: ExecStream, fmt: WFmt) -> Res<Outcome> {
    let _ = setting;
    if fmt == WFmt::P2r && es != ExecStream::Whole {
        return Err(RunError::new(2, "fmt=p2r supports only --exec-stream whole (the retained stream of w34 has no packed arm; use w35 for the block cover)"));
    }
    if n == 0 || n % BLOCK != 0 {
        return Err(RunError::new(2, format!("N = {n} must be a positive multiple of {BLOCK}")));
    }
    let wall = Instant::now();
    let mut o = Outcome { n, g: n / BLOCK, sigma: n / 100, hwm_reset_ok: true, exec_stream: Some(es), fmt, ..Default::default() };

    let t = Instant::now();
    let records = r#gen(n, o.sigma, layout, seed);
    o.gen_s = t.elapsed().as_secs_f64();

    // setup outside every stage timer: epoch keys (AES master, tag key, ML-DSA key), the predicate formula, the ledger simulation
    let t = Instant::now();
    let keys = EpochKeys::from_seed(seed);
    let (formula, _tag) = predicate_formula(&keys);
    let mut lc = ledger_setup(seed);
    o.setup_s = t.elapsed().as_secs_f64();

    // P3a
    let (log, s) = stage(&mut o, 0, || build_log(&records, &keys));
    o.p3a_s = s;

    // P3b
    let mut rc_p: Option<PRcProof> = None;
    let mut rc_proof = None;
    let (res, s) = stage(&mut o, 1, || match fmt {
        WFmt::Old => prove_rc_stage(&log.wl).map(|(p, st)| (Some(p), None, st)),
        WFmt::P2r => prove_rc_stage_p(&log.wl).map(|(p, st)| (None, Some(p), st)),
    });
    let (a, b, rc_st) = res?;
    rc_proof = a.or(rc_proof);
    rc_p = b.or(rc_p);
    o.rc = rc_st;
    o.p3b_s = s;

    // P4a
    let (res, s) = stage(&mut o, 2, || match fmt {
        WFmt::Old => verify_rc_stage(rc_proof.as_ref().unwrap()),
        WFmt::P2r => verify_rc_stage_p(rc_p.as_ref().unwrap()),
    });
    res?;
    o.p4a_s = s;

    // P4b
    let g_e = o.g as u64;
    let (res, s) = stage(&mut o, 3, || commit_epoch(&mut lc, log.r_e, n as u64, g_e));
    let (led_st, omega) = res?;
    o.led = led_st;
    o.p4b_s = s;

    // P5
    let predicate = "P1: A = x";
    let (res, s) = stage(&mut o, 4, || auth_stage(&omega, 1, predicate, seed));
    let (auth_proof, auth_st) = res?;
    o.auth = auth_st;
    o.p5_s = s;

    // P6a
    let (so, s) = stage(&mut o, 5, || search(&log, &formula));
    o.bps_s = so.bps_s;
    o.rps_s = so.rps_s;
    o.p6a_s = s;
    o.n_sel = so.sel.len();
    o.r = so.flags.iter().filter(|&&f| f).count();
    if o.r == 0 {
        return Err(RunError::new(6, "no retained block: R_Exec has nothing to prove"));
    }

    // P6b: ctx = C_Q = exec_context(B_Q, d_Q, RID) of the Auth statement (w33 Poseidon2 sponge)
    let ctx = exec_context(&c1::perm(), auth_proof.stmt.b_q, auth_proof.stmt.d_q, RID);
    let (res, s) = stage(&mut o, 6, || {
        let t = Instant::now();
        let (wl_ex, claim, used) = exec_input(&log, &so, es);
        let prep = t.elapsed().as_secs_f64();
        let r = match fmt {
            WFmt::Old => prove_exec_stage(&wl_ex, ctx, claim)?,
            WFmt::P2r => prove_exec_stage_p(&wl_ex, ctx, claim)?,
        };
        Ok::<_, RunError>((wl_ex, claim, used, r, prep))
    });
    let (exec_wl, claim, exec_used, (exec_proof, ex_st), prep) = res?;
    o.exec = ex_st;
    o.exec_prep_s = prep;
    o.p6b_s = s;

    // P7: the requester verifies (native checks all ON, then R_Auth, then R_Exec); R_RC was verified by the AA in P4a
    let (res, s) = stage(&mut o, 7, || match fmt {
        WFmt::Old => verify_requester(&auth_proof, &exec_proof, &rc_proof.as_ref().unwrap().stmt),
        WFmt::P2r => verify_requester_p(&auth_proof, &exec_proof, rc_p.as_ref().unwrap()),
    });
    let (tm, link) = res?;
    o.p7_native_s = tm.native_s;
    o.p7_auth_s = tm.auth_s;
    o.p7_exec_s = tm.exec_s;
    o.p7_s = s;
    o.link_kind = Some(link);

    o.total_s = o.p3a_s + o.p3b_s + o.p4a_s + o.p4b_s + o.p5_s + o.p6a_s + o.p6b_s + o.p7_s;

    // gates (outside the timers)
    let (res, s) = stage(&mut o, 8, || {
        match fmt {
            WFmt::Old => gates(&GateInput { records: &records, log: &log, search: &so, exec_wl: &exec_wl, exec_used: &exec_used, claim, rc: rc_proof.as_ref().unwrap(), exec: &exec_proof, link, exec_stream: es })?,
            WFmt::P2r => {
                // GateInput needs an old-format RcProof only for `gates`; the P2r gates take the packed statement
                let dummy = RcProof { bytes: Vec::new(), stmt: plain::rc_public(&c1::words(&exec_wl), BLOCK) };
                gates_p2r(&GateInput { records: &records, log: &log, search: &so, exec_wl: &exec_wl, exec_used: &exec_used, claim, rc: &dummy, exec: &exec_proof, link, exec_stream: es }, rc_p.as_ref().unwrap())?
            }
        }
        ledger_read_gate(&lc, &omega)
    });
    o.gate_ledger_read_s = res?;
    o.gates_s = s;
    o.r_hit_blocks = {
        let mut hb = vec![false; o.g];
        for id in &so.sel {
            hb[*id as usize / BLOCK] = true;
        }
        hb.iter().filter(|&&x| x).count()
    };
    o.process_peak_kb = o.peak.iter().copied().max().unwrap_or(0);
    o.wall_s = wall.elapsed().as_secs_f64();
    Ok(o)
}
