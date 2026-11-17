//! w35 (laptop prototype): BlockCover and PruneValid tied to the anchored epoch root R_e.
//! Spec: `journal2/DESIGN-w35-blockcover.md` section 3 (D1, D1b, D2-D5). README.md of this crate lists what is built and what is not.
//!
//! Parts:
//!   D2  `Block35` (B_{e,g} with sigma and MRoot(S)), `Bloom35` (bits, MRoot, openings), `epoch_root35`.
//!   D3  `aa_finalize`  (the AA before it signs A_e).
//!   D4  `plan_runs`, `prove_runs` (the CSP; run choice is the CSP's alone).
//!   D5  `verify_requester35` (native checks first, then C_Q / scope / theta, then Auth, then each run proof).
//! Every check has a switch in a test-only struct (`AaChecks`, `ReqChecks`); production code uses `::ON`.
//! `aa_finalize` / `verify_requester35` always get the production defaults from the library entry points (`run_one35`).

use crate::*;
use pqz_plonky3_w36::chunk::{self, acc_native, alphas_of, betas_of, iv_state, plan_chunks, ChunkLists, ChunkPlan, RcChunkPublic, State, NACC};
use pqz_plonky3_w36::request::{check_ctx, check_scope};
use pqz_plonky3_w36::run::{self, RunPublic};
use pqz_plonky3_w36::{pair, pchunk, prun};
use p3_maybe_rayon::prelude::*;
use pqz_ledger::hashing::{merkle_path, merkle_root, node_hash, verify_path};
use std::collections::HashMap;

/// 32-byte hash of the ledger crate.
pub type Hash32 = Hash;

// ---------------------------------------------------------------------------------------------------------------
// Bloom35: the same bits as `pqz_eval::search::Bloom`, plus MRoot and openings (D2)
// ---------------------------------------------------------------------------------------------------------------

/// (nbits, k) of the block Bloom filter for `count` records. Same arithmetic as `pqz_eval::search::Bloom::with_fp_rate(count * 45, 0.01)`.
pub fn bloom_params(count: usize) -> (usize, usize) {
    assert!(count > 0);
    let m = count * 45;
    let fp_rate = 0.01f64;
    let ln2 = std::f64::consts::LN_2;
    let nbits = ((m as f64) * (-fp_rate.ln()) / (ln2 * ln2)).ceil() as usize;
    let nbits = nbits.max(64);
    let k = (((nbits as f64) / (m as f64)) * ln2).round() as usize;
    (nbits, k.clamp(1, 8))
}

/// The k bit positions of a tag (same formula as pqz-eval: h1 = u64 LE of tag[..8], h2 = u64 LE of tag[8..] | 1, (h1 + i*h2) mod nbits).
pub fn bloom_positions(tag: &Tag, nbits: usize, k: usize) -> Vec<usize> {
    let h1 = u64::from_le_bytes(tag[..8].try_into().unwrap());
    let h2 = u64::from_le_bytes(tag[8..].try_into().unwrap()) | 1;
    (0..k).map(|i| (h1.wrapping_add((i as u64).wrapping_mul(h2)) % nbits as u64) as usize).collect()
}

/// Same split as `pqz_ledger::hashing::split_point` (private there): largest power of two strictly smaller than n (n >= 2).
fn split_point35(n: usize) -> usize {
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Root of `leaves` and, for every index in `want` (sorted, distinct, absolute = `base` + position in `leaves`), its audit path
/// (leaf upwards, last = top sibling) written to `out[j]` for `want[j]`. Each subtree root is computed once.
fn root_and_paths(leaves: &[Hash], base: usize, want: &[usize], out: &mut [Vec<Hash>]) -> Hash {
    if want.is_empty() {
        return merkle_root(leaves);
    }
    let n = leaves.len();
    if n == 1 {
        return leaves[0];
    }
    let k = split_point35(n);
    let cut = want.partition_point(|&i| i < base + k);
    let (wl, wr) = want.split_at(cut);
    let (ol, or) = out.split_at_mut(cut);
    let rl = root_and_paths(&leaves[..k], base, wl, ol);
    let rr = root_and_paths(&leaves[k..], base + k, wr, or);
    for p in ol.iter_mut() {
        p.push(rr);
    }
    for p in or.iter_mut() {
        p.push(rl);
    }
    node_hash(&rl, &rr)
}

#[derive(Clone)]
pub struct Bloom35 {
    pub bits: Vec<u64>,
    pub nbits: usize,
    pub k: usize,
}

/// One opened 8-byte leaf of the bit array with its Merkle path to MRoot(S).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BloomOpening {
    pub leaf_idx: usize,
    pub word: u64,
    pub path: Vec<Hash>,
}

impl BloomOpening {
    pub fn bytes(&self) -> usize {
        8 + 8 + 32 * self.path.len()
    }
}

impl Bloom35 {
    pub fn build<'a>(count: usize, tags: impl Iterator<Item = &'a Tag>) -> Self {
        let (nbits, k) = bloom_params(count);
        let mut b = Bloom35 { bits: vec![0u64; nbits.div_ceil(64)], nbits, k };
        for t in tags {
            for idx in bloom_positions(t, nbits, k) {
                b.bits[idx / 64] |= 1u64 << (idx % 64);
            }
        }
        b
    }
    pub fn bit(&self, idx: usize) -> bool {
        self.bits[idx / 64] >> (idx % 64) & 1 == 1
    }
    pub fn contains(&self, t: &Tag) -> bool {
        bloom_positions(t, self.nbits, self.k).iter().all(|&i| self.bit(i))
    }
    /// Same bytes as `pqz_eval::search::Bloom::digest` (so the test can compare all bits at once).
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(16 + self.bits.len() * 8);
        bytes.extend_from_slice(&(self.nbits as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.k as u64).to_le_bytes());
        for w in &self.bits {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        sha3_parts(&[b"pqz-bloom", &bytes])
    }
    pub fn leaves(&self) -> Vec<Hash> {
        self.bits.iter().map(|w| leaf_hash(&w.to_le_bytes())).collect()
    }
    /// MRoot(S): Merkle root over the bit array in 8-byte leaves (no parameter wrapper: nbits and k come from B.count at the requester).
    pub fn mroot(&self) -> Hash {
        merkle_root(&self.leaves())
    }
    /// w36 (S3): the leaves are hashed and the Merkle tree is walked ONCE per filter; every requested path is taken from that one walk
    /// (O(n + c log n) hashes for c openings, instead of O(c n) for `open_many_per_index`). The tree shape is the ledger's (RFC 6962
    /// style split at the largest power of two below n), so the openings are byte-identical to `open_many_per_index` (test `w36_s3_openings`).
    pub fn open_many(&self, idxs: &[usize]) -> Vec<BloomOpening> {
        let leaves = self.leaves();
        let mut want: Vec<usize> = idxs.to_vec();
        want.sort_unstable();
        want.dedup();
        for &i in &want {
            assert!(i < leaves.len());
        }
        let mut paths: Vec<Vec<Hash>> = vec![Vec::new(); want.len()];
        root_and_paths(&leaves, 0, &want, &mut paths);
        idxs.iter()
            .map(|&i| BloomOpening { leaf_idx: i, word: self.bits[i], path: paths[want.binary_search(&i).unwrap()].clone() })
            .collect()
    }
    /// The w35 method, kept for comparison and for the equality test: one `merkle_path` call per index (each call recomputes the sibling
    /// subtree roots, O(n) per path).
    pub fn open_many_per_index(&self, idxs: &[usize]) -> Vec<BloomOpening> {
        let leaves = self.leaves();
        idxs.iter().map(|&i| BloomOpening { leaf_idx: i, word: self.bits[i], path: merkle_path(&leaves, i) }).collect()
    }
    /// CSP side: bit positions (one zero bit per tag of a leaf) that show the formula false, or None if the filter cannot show it.
    pub fn plan_absent(&self, f: &Formula) -> Option<Vec<usize>> {
        match f {
            Formula::Leaf(tags) => {
                let mut v = Vec::new();
                for t in tags {
                    let p = bloom_positions(t, self.nbits, self.k).into_iter().find(|&p| !self.bit(p))?;
                    v.push(p);
                }
                Some(v)
            }
            Formula::And(a, b) => self.plan_absent(a).or_else(|| self.plan_absent(b)),
            Formula::Or(a, b) => {
                let mut x = self.plan_absent(a)?;
                x.extend(self.plan_absent(b)?);
                Some(x)
            }
        }
    }
    /// The openings (distinct leaves, sorted) that show the formula false.
    pub fn openings_for(&self, f: &Formula) -> Option<Vec<BloomOpening>> {
        let pos = self.plan_absent(f)?;
        let mut idx: Vec<usize> = pos.iter().map(|p| p / 64).collect();
        idx.sort_unstable();
        idx.dedup();
        Some(self.open_many(&idx))
    }
}

/// Requester side: is the formula shown false by the zero bits among the opened leaves? (`zero(p)` = bit p is opened and 0.)
/// Leaf false iff every tag has an opened zero position; And false iff one side is; Or false iff both are (`bps_eval` negated).
pub fn formula_absent(f: &Formula, nbits: usize, k: usize, zero: &dyn Fn(usize) -> bool) -> bool {
    match f {
        Formula::Leaf(tags) => tags.iter().all(|t| bloom_positions(t, nbits, k).iter().any(|&p| zero(p))),
        Formula::And(a, b) => formula_absent(a, nbits, k, zero) || formula_absent(b, nbits, k, zero),
        Formula::Or(a, b) => formula_absent(a, nbits, k, zero) && formula_absent(b, nbits, k, zero),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Block commitment B_{e,g} (D2) and R_e
// ---------------------------------------------------------------------------------------------------------------

/// B_{e,g} of w35: the w34 fields, `s_root` = MRoot(S_{e,g}) instead of H(S), and `sigma` (full sponge state after block g if g ends a chunk, else None).
/// `g` is 1-based (as `AuditBlock.g`); the header word of the same block carries g - 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block35 {
    pub e: u64,
    pub g: u64,
    pub q_start: u64,
    pub q_next: u64,
    pub count: u64,
    pub r_rec: Hash,
    pub s_root: Hash,
    pub sigma: Option<State>,
}

impl Block35 {
    pub fn commitment(&self) -> Hash {
        let mut se: Vec<u8> = Vec::with_capacity(97);
        match &self.sigma {
            None => se.push(0),
            Some(s) => {
                se.push(1);
                for x in s {
                    se.extend_from_slice(&x.to_le_bytes());
                }
            }
        }
        h(&[b"PQZ-B35", &u64b(self.e), &u64b(self.g), &u64b(self.q_start), &u64b(self.q_next), &u64b(self.count), &self.r_rec, &self.s_root, &se])
    }
    pub fn leaf(&self) -> Hash {
        leaf_hash(&self.commitment())
    }
    pub fn bytes(&self) -> usize {
        5 * 8 + 64 + if self.sigma.is_some() { 97 } else { 1 }
    }
}

/// R_e = MerkleRoot(leaf(B_{e,1}), ..., leaf(B_{e,G_e})) with the w35 commitment.
pub fn epoch_root35(blocks: &[Block35]) -> Hash {
    let leaves: Vec<Hash> = blocks.iter().map(|b| b.leaf()).collect();
    merkle_root(&leaves)
}

// ---------------------------------------------------------------------------------------------------------------
// What the AA holds per record (the paper's x_i^RC, as far as the prototype has it): id, H(CT), the 45 tags.
// ---------------------------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct AaMaterial<'a> {
    pub ids: &'a [u64],
    pub h_cts: &'a [[u8; 32]],
    /// 45 tags per record, flat, in record order
    pub tags: &'a [Tag],
}

impl AaMaterial<'_> {
    pub fn n(&self) -> usize {
        self.ids.len()
    }
}

/// D_i and the tag slot of the stream word for every record (the AA derives them; it does not read them from the stream).
pub fn derive_slots(m: &AaMaterial) -> (Vec<[u8; 32]>, Vec<u64>) {
    let n = m.n();
    assert!(m.h_cts.len() == n && m.tags.len() == n * TAGS_PER_RECORD);
    let mut ds = Vec::with_capacity(n);
    let mut slots = Vec::with_capacity(n);
    for i in 0..n {
        let seq = 1 + i as u64;
        let d = descriptor_h(m.ids[i], seq, &m.h_cts[i], &m.tags[i * TAGS_PER_RECORD..(i + 1) * TAGS_PER_RECORD]);
        slots.push(tag_of_descriptor(&d));
        ds.push(d);
    }
    (ds, slots)
}

/// w35 v3 (D1c): the header word of every block, rebuilt from the AA's own descriptors (e, g, m_b, pid, seq_start from the block position;
/// hd_g from D_{g,1..B}).
pub fn derive_headers(ds: &[[u8; 32]]) -> Vec<RawWord> {
    assert!(ds.len() % BLOCK == 0);
    (0..ds.len() / BLOCK).map(|g0| header_of_block(g0, &ds[g0 * BLOCK..(g0 + 1) * BLOCK])).collect()
}

/// B_{e,g0+1} and its Bloom filter from the material (without sigma).
pub fn build_block(m: &AaMaterial, ds: &[[u8; 32]], g0: usize, sigma: Option<State>) -> (Block35, Bloom35) {
    let q_start = 1 + (g0 * BLOCK) as u64;
    let leaves: Vec<Hash> = (0..BLOCK)
        .map(|i| {
            let seq = q_start + i as u64;
            leaf_hash(&h(&[&u64b(EPOCH), &u64b(seq), &ds[g0 * BLOCK + i]]))
        })
        .collect();
    let bloom = Bloom35::build(BLOCK, m.tags[g0 * BLOCK * TAGS_PER_RECORD..(g0 + 1) * BLOCK * TAGS_PER_RECORD].iter());
    let b = Block35 { e: EPOCH, g: g0 as u64 + 1, q_start, q_next: q_start + BLOCK as u64, count: BLOCK as u64, r_rec: merkle_root(&leaves), s_root: bloom.mroot(), sigma };
    (b, bloom)
}

/// sigma per block from the chunk statements: Some(s_out) at the last block of each chunk, else None.
pub fn sigmas_from(pubs: &[RcChunkPublic], g: usize) -> Vec<Option<State>> {
    let mut v = vec![None; g];
    for p in pubs {
        let end = p.hdr_before + p.n_blocks_chunk;
        if end >= 1 && end <= g {
            v[end - 1] = Some(p.s_out);
        }
    }
    v
}

// ---------------------------------------------------------------------------------------------------------------
// The epoch as the LP/CSP side builds it (ingest, chunk statements, B list, Bloom filters)
// ---------------------------------------------------------------------------------------------------------------

/// R_RC chunk proof as sent to the AA.
#[derive(Clone)]
pub struct ChunkProof {
    pub bytes: Vec<u8>,
    pub stmt: RcChunkPublic,
    /// The tag slots and header words of the stream the proof is about (what the LP's stream holds). The production AA NEVER reads this:
    /// it rebuilds both lists from its own material. It is read only when a test switch (`AaChecks::tag_slots` or `AaChecks::d1c_hdr`) is
    /// OFF, to model an AA that trusts that part of the stream.
    pub claimed: ChunkLists,
}

impl ChunkProof {
    pub fn new(bytes: Vec<u8>, stmt: RcChunkPublic, claimed: ChunkLists) -> Self {
        ChunkProof { bytes, stmt, claimed }
    }
}

pub struct World35 {
    pub n: usize,
    pub g: usize,
    pub c: usize,
    pub ids: Vec<u64>,
    pub log: Log,
    pub words: Vec<Vec<u64>>,
    pub plan: Vec<ChunkPlan>,
    pub pubs: Vec<RcChunkPublic>,
    pub tag_lists: Vec<ChunkLists>,
    pub blocks: Vec<Block35>,
    pub blooms: Vec<Bloom35>,
    pub r_e: Hash,
    /// w46: stream format of `words`, `pubs` and (via `prove_runs`) the run proofs
    pub fmt: WFmt,
}

impl World35 {
    /// Honest ingest: chunk statements (native sponge), Bloom filters with MRoot, B list with sigma at chunk ends, R_e.
    /// `log` comes from `build_log` (the data the LPs/CSP hold); the B list here is built by the same function the AA uses to check it.
    pub fn prepare(log: Log, c: usize) -> World35 {
        World35::prepare_fmt(log, c, WFmt::Old)
    }
    /// w46: as `prepare` with the stream format. P2r: packed words (`pair::pack_raw`), packed chunk statements (`pchunk`), sigma from them.
    pub fn prepare_fmt(log: Log, c: usize, fmt: WFmt) -> World35 {
        let g = log.n_blocks();
        let n = g * BLOCK;
        let ids: Vec<u64> = (0..n)
            .map(|i| log.wl.words[(i / BLOCK) * (BLOCK + 1) + 1 + i % BLOCK][3])
            .collect();
        let (words, (pubs, tag_lists)) = match fmt {
            WFmt::Old => {
                let words = c1::words(&log.wl);
                let pl = chunk::plain::honest_publics(&words, BLOCK, c);
                (words, pl)
            }
            WFmt::P2r => {
                let words = pair::pack_raw(&log.wl.words, BLOCK);
                let pl = pchunk::plain::honest_publics(&words, BLOCK, c);
                (words, pl)
            }
        };
        let plan = plan_chunks(g, c);
        let mat = AaMaterial { ids: &ids, h_cts: &log.h_cts, tags: &log.tags };
        let (ds, _slots) = derive_slots(&mat);
        let sig = sigmas_from(&pubs, g);
        let mut blocks = Vec::with_capacity(g);
        let mut blooms = Vec::with_capacity(g);
        for (g0, s) in sig.into_iter().enumerate() {
            let (b, bl) = build_block(&mat, &ds, g0, s);
            blocks.push(b);
            blooms.push(bl);
        }
        let r_e = epoch_root35(&blocks);
        World35 { n, g, c, ids, log, words, plan, pubs, tag_lists, blocks, blooms, r_e, fmt }
    }
    pub fn material(&self) -> AaMaterial<'_> {
        AaMaterial { ids: &self.ids, h_cts: &self.log.h_cts, tags: &self.log.tags }
    }
    /// words of blocks [first0, first0 + nb) (0-based block index)
    pub fn block_words(&self, first0: usize, nb: usize) -> &[Vec<u64>] {
        let r = self.fmt.rows_per_block(BLOCK);
        &self.words[first0 * r..(first0 + nb) * r]
    }
    /// Prove every chunk (the LP side, plain mode). Returns the proofs and the summed prover stage numbers.
    pub fn prove_chunks(&self) -> Res<(Vec<ChunkProof>, ProofStage)> {
        let mut st = ProofStage::default();
        let o = opts();
        let mut out = Vec::with_capacity(self.pubs.len());
        for p in &self.pubs {
            let cw = self.block_words(p.hdr_before, p.n_blocks_chunk);
            let t = Instant::now();
            let (proof, rows) = match self.fmt {
                WFmt::Old => (chunk::plain::prove_chunk(&o, cw, p), chunk::plain::chunk_rows(p.n_words())),
                WFmt::P2r => (pchunk::plain::prove_chunk(&o, cw, p), pchunk::plain::chunk_rows(pchunk::pc_n_words(p))),
            };
            let proof = proof.map_err(|e| RunError::new(4, format!("R_RC chunk {} prove failed: {e}", p.chunk_index)))?;
            st.rows += rows;
            sec_note(&mut st, rows);
            let b = c1::to_bytes(&proof);
            st.prove_s += t.elapsed().as_secs_f64();
            st.bytes += b.len();
            st.chunks += 1;
            out.push(ChunkProof::new(b, p.clone(), self.tag_lists[out.len()].clone()));
        }
        Ok((out, st))
    }
}

/// min over proofs of the security estimates (same estimator and options as `ProofStage::note`).
pub fn sec_note(st: &mut ProofStage, rows: usize) {
    let s = estimate(&c1::sec_input(&opts(), rows));
    st.conj = if st.conj == 0 { s.conjectured } else { st.conj.min(s.conjectured) };
    st.udr = if st.udr == 0 { s.proven_unique_decoding } else { st.udr.min(s.proven_unique_decoding) };
    st.ldr = if st.ldr == 0 { s.proven_list_decoding } else { st.ldr.min(s.proven_list_decoding) };
}

// ---------------------------------------------------------------------------------------------------------------
// D3: the AA at finalization
// ---------------------------------------------------------------------------------------------------------------

/// TEST-ONLY switches of the AA checks (production = `ON`).
#[derive(Clone, Copy, Debug)]
pub struct AaChecks {
    /// verify every chunk proof (with `iv` off, chunk 0 is verified with the AIR that has no IV rule R2b)
    pub proofs: bool,
    /// statement bookkeeping: block_size, total_words, consecutive chunk_index, hdr_before adds up, hdr_first = header of the chunk's first block
    pub meta: bool,
    /// chunk 0 starts at IV (explicit check; also the AIR rule R2b)
    pub iv: bool,
    /// s_out_j = s_in_{j+1}
    pub links: bool,
    /// alpha_1..3 and beta_1..3 = H(...) recomputed from the AA's tag list and header words
    pub d1b_alpha: bool,
    /// acc_1..3 recomputed from the AA's tag list, header words and the proof's alphas, betas
    pub d1b_acc: bool,
    /// w35 v3 (D1c): the AA rebuilds every header word of the chunk from its own block list and descriptors (e, g, m_b, pid, seq_start, hd_g)
    /// and uses them in the hash and the accumulators. OFF: it uses the header words the LP's stream claims (`ChunkProof::claimed`).
    pub d1c_hdr: bool,
    /// the tag slots of the chunk come from the AA's own D_i (64-bit prefix each). OFF: it uses the tag slots the stream claims, which stands
    /// for an attacker who found a second preimage of the 64-bit slot (A14 only).
    pub tag_slots: bool,
    /// sigma in B equals the proven s_out at chunk ends, None elsewhere
    pub sigma: bool,
    /// B fields (r_rec, s_root, counts) equal what the AA rebuilds from its material
    pub summaries: bool,
}

impl AaChecks {
    pub const ON: AaChecks = AaChecks { proofs: true, meta: true, iv: true, links: true, d1b_alpha: true, d1b_acc: true, d1c_hdr: true, tag_slots: true, sigma: true, summaries: true };
}

#[derive(Clone, Debug)]
pub struct AaOut {
    pub r_e: Hash,
    pub n_e: u64,
    pub g_e: u64,
    /// digest of the last chunk's s_out = the w33 one-proof digest of the epoch stream
    pub digest: [u64; 4],
    pub verify_s: f64,
    pub native_s: f64,
}

/// The AA, before it signs A_e. Any mismatch is an error (the AA refuses). Material = what the AA holds for every record.
pub fn aa_finalize(proofs: &[ChunkProof], blocks: &[Block35], mat: &AaMaterial, sw: AaChecks) -> Result<AaOut, String> {
    aa_finalize_fmt(proofs, blocks, mat, sw, WFmt::Old)
}

/// w46: the AA with the stream format. Every check of the old arm is kept with its packed counterpart (see CHANGES-w46.md).
pub fn aa_finalize_fmt(proofs: &[ChunkProof], blocks: &[Block35], mat: &AaMaterial, sw: AaChecks, fmt: WFmt) -> Result<AaOut, String> {
    let t_all = Instant::now();
    let n = mat.n();
    if n == 0 || n % BLOCK != 0 {
        return Err(format!("AA: N = {n} is not a positive multiple of {BLOCK}"));
    }
    let g = n / BLOCK;
    if blocks.len() != g {
        return Err(format!("AA: {} blocks presented, the material has {g}", blocks.len()));
    }
    if proofs.is_empty() {
        return Err("AA: no chunk proof".into());
    }
    let total_words = g * fmt.rows_per_block(BLOCK);
    // chunk start blocks (cumulative); a list that does not cover the epoch exactly is refused whatever the switches say
    let mut starts = Vec::with_capacity(proofs.len());
    let mut acc_blocks = 0usize;
    for p in proofs {
        starts.push(acc_blocks);
        acc_blocks += p.stmt.n_blocks_chunk;
    }
    if acc_blocks != g {
        return Err(format!("AA: chunks cover {acc_blocks} blocks, the epoch has {g}"));
    }
    // the AA's own lists: D_i, tag slot per record, header word per block (v3)
    let (ds, slots) = derive_slots(mat);
    let own_hdrs = derive_headers(&ds);
    // 1. statement bookkeeping, links, IV
    if sw.meta {
        for (j, p) in proofs.iter().enumerate() {
            let s = &p.stmt;
            if s.chunk_index != j {
                return Err(format!("AA: chunk {j} has chunk_index {}", s.chunk_index));
            }
            if s.block_size != BLOCK || s.total_words != total_words {
                return Err(format!("AA: chunk {j}: block_size/total_words ({}, {}) differ from ({BLOCK}, {total_words})", s.block_size, s.total_words));
            }
            if s.hdr_before != starts[j] {
                return Err(format!("AA: chunk {j}: hdr_before {} != {}", s.hdr_before, starts[j]));
            }
            let want = header_word(EPOCH, starts[j] as u64, BLOCK as u64, PID, 1 + (starts[j] * BLOCK) as u64);
            // slots 0..4 and the flag are compared here; slots 5-6 hold hd_g since v3 and are covered by the D1c check (the first header of
            // the chunk is the first entry of the header list that goes into alpha, beta and acc)
            if s.hdr_first[..5] != want[..5] || s.hdr_first[7] != 1 {
                return Err(format!("AA: chunk {j}: hdr_first is not the header of block {}", starts[j] + 1));
            }
        }
    }
    if sw.links {
        for j in 1..proofs.len() {
            if proofs[j].stmt.s_in != proofs[j - 1].stmt.s_out {
                return Err(format!("AA: chunk link broken: s_in of chunk {j} != s_out of chunk {}", j - 1));
            }
        }
    }
    if sw.iv && proofs[0].stmt.s_in != iv_state(total_words as u64) {
        return Err("AA: chunk 0 does not start at the IV".into());
    }
    let native1 = t_all.elapsed().as_secs_f64();
    // 2. chunk proofs
    let t = Instant::now();
    if sw.proofs {
        let o = opts();
        for (j, p) in proofs.iter().enumerate() {
            let proof = c1::from_bytes(&p.bytes).map_err(|e| format!("AA: chunk {j}: proof parse failed: {e}"))?;
            let r = if j == 0 && !sw.iv {
                // the verifier AIR without the IV rule
                match fmt {
                    WFmt::Old => {
                        let a = chunk::plain::ChunkA::new(chunk::plain::consts(), BLOCK as u64, p.stmt.n_words() as u64, false);
                        chunk::plain::verify_chunk_with(&o, &a, &proof, &p.stmt)
                    }
                    WFmt::P2r => {
                        let a = pchunk::plain::PcA::new(pchunk::plain::consts(), BLOCK as u64, pchunk::pc_n_words(&p.stmt) as u64, false);
                        pchunk::plain::verify_chunk_with(&o, &a, &proof, &p.stmt)
                    }
                }
            } else {
                match fmt {
                    WFmt::Old => chunk::plain::verify_chunk(&o, &proof, &p.stmt),
                    WFmt::P2r => pchunk::plain::verify_chunk(&o, &proof, &p.stmt),
                }
            };
            r.map_err(|e| format!("AA: chunk {j} proof rejected: {e}"))?;
        }
    }
    let verify_s = t.elapsed().as_secs_f64();
    // 3. D1b + D1c: the AA's own tag lists and header words
    let t = Instant::now();
    for (j, p) in proofs.iter().enumerate() {
        let nb = p.stmt.n_blocks_chunk;
        let lists = ChunkLists {
            tags: if sw.tag_slots { slots[starts[j] * BLOCK..(starts[j] + nb) * BLOCK].to_vec() } else { p.claimed.tags.clone() },
            hdrs: if sw.d1c_hdr { own_hdrs[starts[j]..starts[j] + nb].iter().map(|w| *w).collect() } else { p.claimed.hdrs.clone() },
        };
        if lists.tags.len() != nb * BLOCK || lists.hdrs.len() != nb {
            return Err(format!("AA: chunk {j}: list lengths ({}, {}) differ from ({}, {nb})", lists.tags.len(), lists.hdrs.len(), nb * BLOCK));
        }
        if sw.d1b_alpha {
            let (al, be) = match fmt {
                WFmt::Old => (alphas_of(&p.stmt, &lists), betas_of(&p.stmt, &lists)),
                WFmt::P2r => (std::array::from_fn(|k| pchunk::alpha_of(k, &p.stmt, &lists)), std::array::from_fn(|k| pchunk::beta_of(k, &p.stmt, &lists))),
            };
            if al != p.stmt.alpha {
                return Err(format!("AA: chunk {j}: alpha differs from H(s_in, s_out, meta, my tag slots and header words)"));
            }
            if be != p.stmt.beta {
                return Err(format!("AA: chunk {j}: beta differs from H(s_in, s_out, meta, my tag slots and header words)"));
            }
        }
        if sw.d1b_acc {
            for k in 0..NACC {
                let acc = match fmt {
                    WFmt::Old => acc_native::<c1::Val>(p.stmt.alpha[k], p.stmt.beta[k], nb, BLOCK, &lists),
                    WFmt::P2r => pchunk::acc_native_p::<c1::Val>(p.stmt.alpha[k], p.stmt.beta[k], nb, BLOCK, &lists),
                };
                if acc != p.stmt.acc[k] {
                    return Err(format!("AA: chunk {j}: acc_{k} differs from the fingerprint of my tag slots and header words (the stream's tags or header words are not the ones I hold)"));
                }
            }
        }
    }
    // 4. sigma at chunk ends, None elsewhere
    if sw.sigma {
        let want = sigmas_from(&proofs.iter().map(|p| p.stmt.clone()).collect::<Vec<_>>(), g);
        for (i, b) in blocks.iter().enumerate() {
            if b.sigma != want[i] {
                return Err(format!("AA: block {}: sigma is not the proven chunk-end state (or not 'none')", i + 1));
            }
        }
    }
    // 5. rebuild every B field from the material
    if sw.summaries {
        for (g0, b) in blocks.iter().enumerate() {
            let (w, _) = build_block(mat, &ds, g0, b.sigma);
            if &w != b {
                let f = if w.r_rec != b.r_rec {
                    "r_rec"
                } else if w.s_root != b.s_root {
                    "MRoot(S)"
                } else {
                    "e/g/q/count"
                };
                return Err(format!("AA: block {}: {f} differs from what I rebuild from the tags and descriptors", g0 + 1));
            }
        }
    }
    // 6. R_e
    let r_e = epoch_root35(blocks);
    let native_s = native1 + t.elapsed().as_secs_f64();
    let last = &proofs[proofs.len() - 1].stmt;
    Ok(AaOut { r_e, n_e: n as u64, g_e: g as u64, digest: chunk::plain::digest_of(&last.s_out), verify_s, native_s })
}

// ---------------------------------------------------------------------------------------------------------------
// D4: runs (the CSP)
// ---------------------------------------------------------------------------------------------------------------

/// Chunk ranges (first, last chunk index) of the runs: every chunk with a flagged block, chunks separated by at most `gap_merge`
/// unflagged chunks are merged into one run. No flagged block gives no run.
pub fn plan_runs(flags: &[bool], plan: &[ChunkPlan], gap_merge: usize) -> Vec<(usize, usize)> {
    let used: Vec<usize> = plan.iter().filter(|p| flags[p.first_block..p.first_block + p.n_blocks].iter().any(|&f| f)).map(|p| p.chunk_index).collect();
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for u in used {
        match runs.last_mut() {
            Some(r) if u - r.1 - 1 <= gap_merge => r.1 = u,
            _ => runs.push((u, u)),
        }
    }
    runs
}

/// One run as sent to the requester. `first`/`last` are 1-based block positions (first block of the first chunk, last block of the last chunk).
#[derive(Clone)]
pub struct RunClaim {
    pub first: usize,
    pub last: usize,
    pub stmt: RunPublic,
    pub proof: Vec<u8>,
}

impl RunClaim {
    pub fn bytes(&self) -> usize {
        self.proof.len() + 8 * (2 + 12 + 12 + 8 + 7 + 4)
    }
}

/// Prove one run over blocks `first1..=last1` (1-based) starting from the state `s_in`; `words` = the stream words of those blocks.
pub fn prove_run_over(words: &[Vec<u64>], s_in: &State, first1: usize, last1: usize, ctx: [u64; 4], theta: u64) -> Result<RunClaim, String> {
    prove_run_over_fmt(words, s_in, first1, last1, ctx, theta, WFmt::Old)
}

/// w46: as `prove_run_over`; P2r = `prun` over PACKED `words` (no range check of v in the run AIR: it comes from the packed chunk proofs
/// through the anchored sigma).
pub fn prove_run_over_fmt(words: &[Vec<u64>], s_in: &State, first1: usize, last1: usize, ctx: [u64; 4], theta: u64, fmt: WFmt) -> Result<RunClaim, String> {
    match fmt {
        WFmt::Old => {
            let stmt = run::plain::honest_public(words, s_in, BLOCK, theta, ctx);
            let proof = run::plain::prove_run(&opts(), words, &stmt)?;
            Ok(RunClaim { first: first1, last: last1, stmt, proof: c1::to_bytes(&proof) })
        }
        WFmt::P2r => {
            let stmt = prun::plain::honest_public(words, s_in, BLOCK, theta, ctx);
            let (bytes, _, _, _) = prun::plain::prove_run_bytes_par(&opts(), words, &stmt)?;
            Ok(RunClaim { first: first1, last: last1, stmt, proof: bytes })
        }
    }
}

/// CSP: one proof per run (blocks of whole chunks), s_in from the chunk statements.
pub fn prove_runs(w: &World35, ranges: &[(usize, usize)], ctx: [u64; 4]) -> Res<(Vec<RunClaim>, ProofStage)> {
    let mut st = ProofStage::default();
    let mut v = Vec::new();
    for &(ca, cb) in ranges {
        let first0 = w.plan[ca].first_block;
        let end0 = w.plan[cb].first_block + w.plan[cb].n_blocks;
        let t = Instant::now();
        let cl = prove_run_over_fmt(w.block_words(first0, end0 - first0), &w.pubs[ca].s_in, first0 + 1, end0, ctx, THETA, w.fmt)
            .map_err(|e| RunError::new(4, format!("run {ca}..{cb} prove failed: {e}")))?;
        let rows = match w.fmt {
            WFmt::Old => run::plain::run_rows(cl.stmt.n_words()),
            WFmt::P2r => prun::plain::run_rows(prun::prun_n_words(&cl.stmt)),
        };
        st.rows += rows;
        sec_note(&mut st, rows);
        st.prove_s += t.elapsed().as_secs_f64();
        st.bytes += cl.proof.len();
        st.chunks += 1;
        v.push(cl);
    }
    Ok((v, st))
}

/// What the CSP sends the requester besides the Auth proof.
#[derive(Clone)]
pub struct CspResponse {
    pub blocks: Vec<Block35>,
    pub runs: Vec<RunClaim>,
    /// per block (key = Block35.g) the opened Bloom leaves that show the query false; only for blocks outside the runs
    pub openings: Vec<(u64, Vec<BloomOpening>)>,
    pub claim: (u64, u64),
}

impl CspResponse {
    pub fn block_list_bytes(&self) -> usize {
        self.blocks.iter().map(|b| b.bytes()).sum()
    }
    pub fn openings_bytes(&self) -> usize {
        self.openings.iter().map(|(_, o)| 8 + o.iter().map(|x| x.bytes()).sum::<usize>()).sum()
    }
    pub fn runs_bytes(&self) -> usize {
        self.runs.iter().map(|r| r.bytes()).sum()
    }
    pub fn bytes(&self) -> usize {
        self.block_list_bytes() + self.openings_bytes() + self.runs_bytes() + 16
    }
}

/// Openings for every block of `blocks_idx` (0-based) from the CSP's filters. Err(g) if the filter cannot show the formula false for block g.
/// w36 (S3): the blocks are processed in parallel (rayon); the result order and content are those of the sequential loop (the first
/// failing block in index order is reported).
pub fn openings_for_blocks(blooms: &[Bloom35], f: &Formula, idxs: impl Iterator<Item = usize>) -> Result<Vec<(u64, Vec<BloomOpening>)>, String> {
    let idxs: Vec<usize> = idxs.collect();
    let res: Vec<Option<Vec<BloomOpening>>> = idxs.par_iter().map(|&i| blooms[i].openings_for(f)).collect();
    let mut v = Vec::with_capacity(idxs.len());
    for (&i, o) in idxs.iter().zip(res) {
        match o {
            Some(o) => v.push((i as u64 + 1, o)),
            None => return Err(format!("block {} cannot be shown absent (its filter may contain the query)", i + 1)),
        }
    }
    Ok(v)
}

/// The w35 sequential loop with per-index paths (comparison only: tests and the timing helper).
pub fn openings_for_blocks_w35(blooms: &[Bloom35], f: &Formula, idxs: impl Iterator<Item = usize>) -> Result<Vec<(u64, Vec<BloomOpening>)>, String> {
    let mut v = Vec::new();
    for i in idxs {
        let o = blooms[i].plan_absent(f).map(|pos| {
            let mut ix: Vec<usize> = pos.iter().map(|p| p / 64).collect();
            ix.sort_unstable();
            ix.dedup();
            blooms[i].open_many_per_index(&ix)
        });
        match o {
            Some(o) => v.push((i as u64 + 1, o)),
            None => return Err(format!("block {} cannot be shown absent (its filter may contain the query)", i + 1)),
        }
    }
    Ok(v)
}

/// Honest CSP response for the run ranges `ranges` (chunk indexes): runs + openings for every block outside them + the claimed result.
pub fn respond(w: &World35, f: &Formula, ranges: &[(usize, usize)], runs: Vec<RunClaim>) -> Result<CspResponse, String> {
    let mut covered = vec![false; w.g];
    for &(ca, cb) in ranges {
        for b in w.plan[ca].first_block..w.plan[cb].first_block + w.plan[cb].n_blocks {
            covered[b] = true;
        }
    }
    let openings = openings_for_blocks(&w.blooms, f, (0..w.g).filter(|&i| !covered[i]))?;
    let claim = (runs.iter().map(|r| r.stmt.count).sum(), runs.iter().map(|r| r.stmt.sum).sum());
    Ok(CspResponse { blocks: w.blocks.clone(), runs, openings, claim })
}

// ---------------------------------------------------------------------------------------------------------------
// D5: requester
// ---------------------------------------------------------------------------------------------------------------

/// The anchored epoch values (from the signed A_e / ledger).
#[derive(Clone, Copy, Debug)]
pub struct Anchor {
    pub r_e: Hash,
    pub n_e: u64,
    pub g_e: u64,
}

/// TEST-ONLY switches of the requester's native checks (production = `ON`).
#[derive(Clone, Copy, Debug)]
pub struct ReqChecks {
    /// block list: length = G_e, e/g/q continuity, sum of counts = N_e, R_e rebuilt from all B equals the anchored R_e
    pub block_list: bool,
    /// runs ordered, disjoint, inside 1..G_e, on chunk boundaries (sigma set at the end of the run and at the block before it), n_blocks and block_size consistent
    pub run_shape: bool,
    /// s_in / s_out of every run equal the anchored sigma (IV for the first chunk)
    pub states: bool,
    /// hdr_first is the header word of the run's first block
    pub hdr_first: bool,
    /// every block outside the runs has openings that show the query false
    pub prune: bool,
    /// the Merkle path of every opening is checked against the anchored MRoot(S)
    pub open_path: bool,
    /// the claimed result equals the sum over the runs
    pub claim: bool,
}

impl ReqChecks {
    pub const ON: ReqChecks = ReqChecks { block_list: true, run_shape: true, states: true, hdr_first: true, prune: true, open_path: true, claim: true };
}

/// Native (proof-free) checks of the requester, in the order of DESIGN D5. Returns the result (sum over the runs; with `claim` off, the CSP's claim).
pub fn requester_native35(an: &Anchor, f: &Formula, resp: &CspResponse, sw: ReqChecks) -> Result<(u64, u64), String> {
    requester_native35_fmt(an, f, resp, sw, WFmt::Old)
}

/// w46: with the stream format (only the IV, which depends on the packed word count, differs; run shape, anchored states, hdr_first,
/// PruneValid and the claim are format independent: block counts, sigma and the header word are the same in both formats).
pub fn requester_native35_fmt(an: &Anchor, f: &Formula, resp: &CspResponse, sw: ReqChecks, fmt: WFmt) -> Result<(u64, u64), String> {
    let blocks = &resp.blocks;
    let g_e = an.g_e as usize;
    // 1. BlockCover
    if sw.block_list {
        if blocks.len() != g_e {
            return Err(format!("block list has {} blocks, the anchored G_e is {g_e}", blocks.len()));
        }
        let mut total = 0u64;
        for (i, b) in blocks.iter().enumerate() {
            if b.e != EPOCH || b.g != i as u64 + 1 {
                return Err(format!("block list: position {} holds (e, g) = ({}, {})", i + 1, b.e, b.g));
            }
            if b.count == 0 || b.q_next != b.q_start + b.count {
                return Err(format!("block list: block {} has an inconsistent sequence range", i + 1));
            }
            if i > 0 && b.q_start != blocks[i - 1].q_next {
                return Err(format!("block list: block {} does not continue block {}", i + 1, i));
            }
            total += b.count;
        }
        if total != an.n_e {
            return Err(format!("block list: counts sum to {total}, the anchored N_e is {}", an.n_e));
        }
        if blocks.last().map_or(true, |b| b.sigma.is_none()) {
            return Err("block list: the last block does not end a chunk".into());
        }
        if epoch_root35(blocks) != an.r_e {
            return Err("block list: R_e rebuilt from the blocks differs from the anchored R_e".into());
        }
    }
    let gl = blocks.len();
    // 2. runs
    let total_words = (g_e * fmt.rows_per_block(BLOCK)) as u64;
    let mut prev_last = 0usize;
    for (k, r) in resp.runs.iter().enumerate() {
        if sw.run_shape {
            if r.first < 1 || r.first > r.last || r.last > gl {
                return Err(format!("run {k}: blocks {}..{} outside 1..{gl}", r.first, r.last));
            }
            if r.first <= prev_last {
                return Err(format!("run {k}: starts at block {} but the previous run ends at {prev_last} (not ordered/disjoint)", r.first));
            }
            if r.first > 1 && blocks[r.first - 2].sigma.is_none() {
                return Err(format!("run {k}: does not start on a chunk boundary (block {} ends no chunk)", r.first - 1));
            }
            if blocks[r.last - 1].sigma.is_none() {
                return Err(format!("run {k}: does not end on a chunk boundary (block {} ends no chunk)", r.last));
            }
            if r.stmt.n_blocks != r.last - r.first + 1 || r.stmt.block_size != BLOCK {
                return Err(format!("run {k}: statement n_blocks/block_size do not match blocks {}..{}", r.first, r.last));
            }
            prev_last = r.last;
        }
        if sw.states {
            if r.first < 1 || r.last > gl || r.first > r.last {
                return Err(format!("run {k}: blocks {}..{} outside 1..{gl}", r.first, r.last));
            }
            let want_in = if r.first == 1 { Some(iv_state(total_words)) } else { blocks[r.first - 2].sigma };
            if want_in != Some(r.stmt.s_in) {
                return Err(format!("run {k}: s_in is not the anchored state before block {}", r.first));
            }
            if blocks[r.last - 1].sigma != Some(r.stmt.s_out) {
                return Err(format!("run {k}: s_out is not the anchored state after block {}", r.last));
            }
        }
        if sw.hdr_first {
            if r.first < 1 || r.first > gl {
                return Err(format!("run {k}: first block {} outside 1..{gl}", r.first));
            }
            // slots 0..4 and the flag; slots 5-6 hold hd_g (v3), which the requester does not have (it is bound by the anchored states)
            let want = header_word(EPOCH, r.first as u64 - 1, BLOCK as u64, PID, blocks[r.first - 1].q_start);
            if r.stmt.hdr_first[..5] != want[..5] || r.stmt.hdr_first[7] != 1 {
                return Err(format!("run {k}: hdr_first is not the header word of block {}", r.first));
            }
        }
    }
    // 3. PruneValid
    if sw.prune {
        let mut covered = vec![false; gl];
        for r in &resp.runs {
            for b in r.first.saturating_sub(1)..r.last.min(gl) {
                covered[b] = true;
            }
        }
        let by_g: HashMap<u64, &Vec<BloomOpening>> = resp.openings.iter().map(|(g, o)| (*g, o)).collect();
        for (i, b) in blocks.iter().enumerate() {
            if covered[i] {
                continue;
            }
            let Some(ops) = by_g.get(&b.g) else {
                return Err(format!("block {} is outside the runs and has no Bloom opening", b.g));
            };
            if b.count == 0 {
                return Err(format!("block {}: count 0", b.g));
            }
            let (nbits, k) = bloom_params(b.count as usize);
            let n_leaves = nbits.div_ceil(64);
            let mut words: HashMap<usize, u64> = HashMap::new();
            for o in ops.iter() {
                if o.leaf_idx >= n_leaves {
                    return Err(format!("block {}: opened leaf {} outside the bit array", b.g, o.leaf_idx));
                }
                if sw.open_path && !verify_path(&leaf_hash(&o.word.to_le_bytes()), o.leaf_idx, n_leaves, &o.path, &b.s_root) {
                    return Err(format!("block {}: Merkle path of leaf {} does not verify against MRoot(S)", b.g, o.leaf_idx));
                }
                words.insert(o.leaf_idx, o.word);
            }
            let zero = |p: usize| words.get(&(p / 64)).map_or(false, |w| (w >> (p % 64)) & 1 == 0);
            if !formula_absent(f, nbits, k, &zero) {
                return Err(format!("block {}: the opened zero bits do not show the query false", b.g));
            }
        }
    }
    // 4. result
    let sum: (u64, u64) = (resp.runs.iter().map(|r| r.stmt.count).sum(), resp.runs.iter().map(|r| r.stmt.sum).sum());
    if sw.claim {
        if resp.claim != sum {
            return Err(format!("claimed result {:?} differs from the sum over the runs {:?}", resp.claim, sum));
        }
        Ok(sum)
    } else {
        Ok(resp.claim)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ReqTimes35 {
    pub native_s: f64,
    pub auth_s: f64,
    pub runs_s: f64,
}

/// P7 of w35. Order: native checks (D5 1-3), then C_Q link / scope / theta, then R_Auth, then every run proof. Result = sum over the runs.
pub fn verify_requester35(an: &Anchor, f: &Formula, auth: &AuthProof, resp: &CspResponse, sw: ReqChecks) -> Res<(ReqTimes35, (u64, u64))> {
    verify_requester35_fmt(an, f, auth, resp, sw, WFmt::Old)
}

/// w46: P7 with the stream format (P2r: run proofs verified with `prun`).
pub fn verify_requester35_fmt(an: &Anchor, f: &Formula, auth: &AuthProof, resp: &CspResponse, sw: ReqChecks, fmt: WFmt) -> Res<(ReqTimes35, (u64, u64))> {
    let mut tm = ReqTimes35::default();
    let t = Instant::now();
    let result = requester_native35_fmt(an, f, resp, sw, fmt).map_err(|e| RunError::new(5, format!("requester native check rejected: {e}")))?;
    for (k, r) in resp.runs.iter().enumerate() {
        check_ctx(&auth.stmt, &r.stmt.ctx, RID).map_err(|e| RunError::new(5, format!("requester native check rejected: run {k}: {e}")))?;
        if r.stmt.theta != THETA {
            return Err(RunError::new(5, format!("requester native check rejected: run {k}: theta {} != requested {THETA}", r.stmt.theta)));
        }
    }
    check_scope(&auth.stmt).map_err(|e| RunError::new(5, format!("requester native check rejected: {e}")))?;
    tm.native_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    verify_auth_stage(auth)?;
    tm.auth_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    for (k, r) in resp.runs.iter().enumerate() {
        let proof = parse(&r.proof, "R_Exec run")?;
        match fmt {
            WFmt::Old => run::plain::verify_run(&opts(), &proof, &r.stmt),
            WFmt::P2r => prun::plain::verify_run(&opts(), &proof, &r.stmt),
        }
        .map_err(|e| RunError::new(5, format!("run {k}: R_Exec verifier rejected: {e}")))?;
    }
    tm.runs_s = t.elapsed().as_secs_f64();
    Ok((tm, result))
}

/// Bytes the requester receives: B list, run statements and proofs, openings, Auth proof (+ the statement size is not counted).
pub fn requester_bytes(resp: &CspResponse, auth: &AuthProof) -> usize {
    resp.bytes() + auth.bytes.len()
}

// ---------------------------------------------------------------------------------------------------------------
// One end-to-end run (the CLI child)
// ---------------------------------------------------------------------------------------------------------------

/// Stage names of `Outcome35::peak` (VmHWM after each stage, reset before it).
pub const STAGE_NAMES35: [&str; 10] = ["p3a", "p3a2", "p3b", "p4a", "p4b", "p5", "p6a", "p6b", "p7", "gates"];

#[derive(Default)]
pub struct Outcome35 {
    pub fmt: WFmt,
    pub n: usize,
    pub g: usize,
    pub sigma: usize,
    pub chunk: usize,
    pub gap_merge: usize,
    pub n_chunks: usize,
    /// blocks BPS retained (flags) / blocks inside the runs
    pub r_retained: usize,
    pub runs: usize,
    pub blocks_proven: usize,
    pub gen_s: f64,
    pub setup_s: f64,
    pub p3a_s: f64,
    /// ingest: chunk statements, B list with sigma, Bloom filters with MRoot(S), R_e
    pub p3a2_s: f64,
    pub rc: ProofStage,
    pub p3b_s: f64,
    /// AA finalization (D3): all chunk proofs verified + native checks
    pub aa_check_s: f64,
    pub aa_verify_s: f64,
    pub aa_native_s: f64,
    pub p4b_s: f64,
    pub led: LedgerStats,
    pub auth: AuthStage,
    pub p5_s: f64,
    pub bps_s: f64,
    pub p6a_s: f64,
    pub rps_s: f64,
    pub plan_s: f64,
    pub openings_s: f64,
    pub exec: ProofStage,
    pub p6b_s: f64,
    pub req_native_s: f64,
    pub req_auth_s: f64,
    pub req_runs_s: f64,
    pub p7_s: f64,
    pub req_bytes: usize,
    pub req_bytes_blocklist: usize,
    pub req_bytes_openings: usize,
    pub req_bytes_runs: usize,
    pub req_bytes_auth: usize,
    pub n_openings: usize,
    pub total_s: f64,
    pub wall_s: f64,
    pub gates_s: f64,
    pub gate_ledger_read_s: f64,
    pub peak: [u64; 10],
    pub hwm_reset_ok: bool,
    pub process_peak_kb: u64,
    pub result: (u64, u64),
}

fn stage35<T>(o: &mut Outcome35, idx: usize, f: impl FnOnce() -> T) -> (T, f64) {
    o.hwm_reset_ok &= sys::reset_hwm();
    let t = Instant::now();
    let r = f();
    let s = t.elapsed().as_secs_f64();
    o.peak[idx] = sys::status_kb("VmHWM:");
    (r, s)
}

/// One end-to-end w35 run: ingest with chunked R_RC, AA finalization (D3), ledger anchor of R_e (w35), Auth, BPS + run plan + openings,
/// run proofs (D4), requester verification (D5), then gates (result = plain reference, chunked digest = one-proof digest = reference chain,
/// Bloom35 bits = pqz-eval bits, ledger read). Production check settings (`::ON`) everywhere.
pub fn run_one35(n: usize, layout: Layout, seed: u64, chunk: usize, gap_merge: usize) -> Res<Outcome35> {
    run_one35_fmt(n, layout, seed, chunk, gap_merge, WFmt::Old)
}

/// w46: as `run_one35` with the stream format (`WFmt::P2r` = packed chunks, packed run proofs; same checks, same stages).
pub fn run_one35_fmt(n: usize, layout: Layout, seed: u64, chunk: usize, gap_merge: usize, fmt: WFmt) -> Res<Outcome35> {
    if n == 0 || n % BLOCK != 0 {
        return Err(RunError::new(2, format!("N = {n} must be a positive multiple of {BLOCK}")));
    }
    if chunk == 0 {
        return Err(RunError::new(2, "chunk must be >= 1"));
    }
    let wall = Instant::now();
    let mut o = Outcome35 { fmt, n, g: n / BLOCK, sigma: n / 100, chunk, gap_merge, hwm_reset_ok: true, ..Default::default() };
    let t = Instant::now();
    let records = r#gen(n, o.sigma, layout, seed);
    o.gen_s = t.elapsed().as_secs_f64();

    let t = Instant::now();
    let keys = EpochKeys::from_seed(seed);
    let (formula, _tag) = predicate_formula(&keys);
    let mut lc = ledger_setup(seed);
    o.setup_s = t.elapsed().as_secs_f64();

    // P3a: log (tags, descriptors, w34 summaries, stream words)
    let (log, s) = stage35(&mut o, 0, || build_log(&records, &keys));
    o.p3a_s = s;
    // P3a2: w35 ingest
    let (w, s) = stage35(&mut o, 1, || World35::prepare_fmt(log, chunk, fmt));
    o.p3a2_s = s;
    o.n_chunks = w.plan.len();
    // P3b: chunk proofs (the LPs)
    let (res, s) = stage35(&mut o, 2, || w.prove_chunks());
    let (proofs, rc_st) = res?;
    o.rc = rc_st;
    o.p3b_s = s;
    // P4a: AA finalization
    let (res, s) = stage35(&mut o, 3, || aa_finalize_fmt(&proofs, &w.blocks, &w.material(), AaChecks::ON, fmt));
    let aa = res.map_err(|e| RunError::new(5, e))?;
    o.aa_check_s = s;
    o.aa_verify_s = aa.verify_s;
    o.aa_native_s = aa.native_s;
    // P4b: anchor the w35 epoch root
    let (res, s) = stage35(&mut o, 4, || commit_epoch(&mut lc, aa.r_e, aa.n_e, aa.g_e));
    let (led_st, omega) = res?;
    o.led = led_st;
    o.p4b_s = s;
    // P5: Auth
    let (res, s) = stage35(&mut o, 5, || auth_stage(&omega, 1, "P1: A = x", seed));
    let (auth, auth_st) = res?;
    o.auth = auth_st;
    o.p5_s = s;
    // P6a: BPS over the summaries, the run plan, the Bloom openings of the pruned blocks (CSP)
    let ctx = exec_context(&c1::perm(), auth.stmt.b_q, auth.stmt.d_q, RID);
    let (res, s) = stage35(&mut o, 6, || {
        let so = search(&w.log, &formula);
        let t = Instant::now();
        let ranges = plan_runs(&so.flags, &w.plan, gap_merge);
        let plan_s = t.elapsed().as_secs_f64();
        let mut covered = vec![false; w.g];
        for &(ca, cb) in &ranges {
            for b in w.plan[ca].first_block..w.plan[cb].first_block + w.plan[cb].n_blocks {
                covered[b] = true;
            }
        }
        let t = Instant::now();
        let openings = openings_for_blocks(&w.blooms, &formula, (0..w.g).filter(|&i| !covered[i]));
        (so, ranges, covered, openings, plan_s, t.elapsed().as_secs_f64())
    });
    let (so, ranges, covered, openings, plan_s, open_s) = res;
    let openings = openings.map_err(|e| RunError::new(6, format!("CSP cannot open zero bits for a block outside the runs: {e}")))?;
    o.p6a_s = s;
    o.bps_s = so.bps_s;
    o.rps_s = so.rps_s;
    o.plan_s = plan_s;
    o.openings_s = open_s;
    o.r_retained = so.flags.iter().filter(|&&f| f).count();
    o.runs = ranges.len();
    o.blocks_proven = covered.iter().filter(|&&c| c).count();
    // P6b: run proofs (R_Exec stream mode, one proof per run)
    let (res, s) = stage35(&mut o, 7, || prove_runs(&w, &ranges, ctx));
    let (runs, ex_st) = res?;
    o.exec = ex_st;
    o.p6b_s = s;
    let claim: (u64, u64) = (runs.iter().map(|r| r.stmt.count).sum(), runs.iter().map(|r| r.stmt.sum).sum());
    let resp = CspResponse { blocks: w.blocks.clone(), runs, openings, claim };
    o.n_openings = resp.openings.iter().map(|(_, v)| v.len()).sum();
    // P7: the requester. The anchor comes from the A_e the ledger holds.
    let a = lc.chain.epoch(EPOCH).a.clone();
    let an = Anchor { r_e: a.r_e, n_e: a.n_e, g_e: a.g_e };
    let (res, s) = stage35(&mut o, 8, || verify_requester35_fmt(&an, &formula, &auth, &resp, ReqChecks::ON, fmt));
    let (tm, result) = res?;
    o.req_native_s = tm.native_s;
    o.req_auth_s = tm.auth_s;
    o.req_runs_s = tm.runs_s;
    o.p7_s = s;
    o.req_bytes = requester_bytes(&resp, &auth);
    o.req_bytes_blocklist = resp.block_list_bytes();
    o.req_bytes_openings = resp.openings_bytes();
    o.req_bytes_runs = resp.runs_bytes();
    o.req_bytes_auth = auth.bytes.len();
    o.result = result;
    o.total_s = o.p3a_s + o.p3a2_s + o.p3b_s + o.aa_check_s + o.p4b_s + o.p5_s + o.p6a_s + o.p6b_s + o.p7_s;

    // gates (outside the timers)
    let (res, s) = stage35(&mut o, 9, || -> Res<f64> {
        let mut t = (0u64, 0u64);
        for r in &records {
            if Predicate::P1.matches(r) {
                t.0 += 1;
                t.1 += r.b as u64;
            }
        }
        if result != t {
            return Err(RunError::new(6, format!("gate: requester result {result:?} != plain reference {t:?}")));
        }
        let (one, one_proof_digest) = match fmt {
            WFmt::Old => (ref_chain_digest(&w.log.wl.words), plain::rc_public(&w.words, BLOCK).digest.to_vec()),
            WFmt::P2r => {
                // one chunk holding every block = the one-proof statement of the packed stream
                let (mut ps, _) = pchunk::plain::honest_publics(&w.words, BLOCK, w.g);
                (ref_chain_digest_packed(&w.words), ps.remove(0).s_out[..4].to_vec())
            }
        };
        if aa.digest.to_vec() != one {
            return Err(RunError::new(6, "gate: chunked digest differs from the reference one-proof chain digest"));
        }
        if aa.digest.to_vec() != one_proof_digest {
            return Err(RunError::new(6, "gate: chunked digest differs from the w33 one-proof digest"));
        }
        for (i, b) in w.blooms.iter().enumerate() {
            if b.digest() != w.log.blooms[i].digest() {
                return Err(RunError::new(6, format!("gate: Bloom35 of block {} differs from the pqz-eval filter", i + 1)));
            }
        }
        if aa.r_e != a.r_e || aa.n_e != a.n_e || aa.g_e != a.g_e {
            return Err(RunError::new(6, "gate: ledger A_e differs from the AA's R_e/N_e/G_e"));
        }
        if !so.sel.iter().all(|id| covered[*id as usize / BLOCK]) {
            return Err(RunError::new(6, "gate: a selected record lies in a block outside the runs"));
        }
        ledger_read_gate(&lc, &omega)
    });
    o.gate_ledger_read_s = res?;
    o.gates_s = s;
    o.process_peak_kb = o.peak.iter().copied().max().unwrap_or(0);
    o.wall_s = wall.elapsed().as_secs_f64();
    Ok(o)
}
