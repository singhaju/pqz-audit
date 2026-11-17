//! w35 D1 + D1b: R_RC over LINKED CHUNKS of whole blocks, with public full sponge states and a tag fingerprint.
//!
//! Ported (constraints, not code) from the winterfell `bench/pqz-proof-w30/src/rc_link.rs` (`RcChunkPublic`) to the Plonky3
//! layout of `rc.rs` (ONE row = ONE absorbed word = ONE Poseidon2 permutation). The rules inside a chunk are the w33 R_RC
//! rules (R3-R7 of `rc.rs`); the rules across chunks are carried by the public boundary values.
//!
//! Sponge (same as w33): state = [rate 0..8 | capacity 8..12]; per word `state[0..8] += word`, then one permutation.
//! The w33 one-proof IV is `(0^8, DOM_CHAIN, n_words_total, 0, 0)` (air.rs `sponge_rows`, rc.rs R2: `inputs[8] = DOM_CHAIN`,
//! `inputs[9] = n_words`, the rest 0, plus word 0 on the rate): chunk 0 of a chunked stream starts from exactly this IV
//! (`iv_state`), so the final state of the last chunk is the final state of the one-proof sponge (tests/w35_chunk.rs).
//!
//! Public values (flat order, `ChunkLayout`):
//!   s_in[12], s_out[12], chunk_index, n_blocks_chunk, hdr_before, block_size, total_words, hdr_first[8], alpha[3], acc[3], beta[3]   (46)
//!
//! Constraints (all of degree <= 3 after the selector, same as R_RC):
//!   R1  Poseidon2 permutation of the row.
//!   R2  row 0: inputs[j] = s_in[j] + word[j] (j < 8), inputs[8+j] = s_in[8+j]; transition: inputs' = out + word' (rate), out (cap).
//!   R2b (only if chunk_index = 0, decided by the AIR the verifier builds from the public chunk_index) row 0:
//!       s_in = IV = (0^8, DOM_CHAIN, total_words, 0, 0).
//!   R3  row 0: word = hdr_first (public), flag = 1, word[2] = block_size, K = (word[3], word[0], word[4]-1), cnt = 0, mb = block_size,
//!       hdr = hdr_before + 1.
//!   R4  flag boolean; a header announces m_B in {0, block_size} (f * mb * (mb - block_size) = 0).
//!   R5  transition: record continues (pid, e) and seq+1; K update; header only after a complete block (cnt = mb); cnt, mb, hdr update.
//!   R6  idx counter, `last` = [idx = n_words_chunk - 1], `seen`.
//!   R7  at the row `last`: ALL 12 elements of the output state = s_out; cnt = mb = block_size; hdr = hdr_before + n_blocks_chunk;
//!       acc_j = public acc_j.
//!   D1b three accumulators over the tag slot (word slot 6) of RECORD rows:
//!       row 0:      acc_j = (1 - h) * w6
//!       transition: acc_j' = acc_j * alpha_j + (1 - h') * w6'          (alpha_j = public value)
//!       degree 2 (acc * alpha is degree 1 because alpha is a public value; (1-h')*w6' is degree 2); with the transition
//!       selector (degree 1) the quotient constraint has degree 3, the same as the Poseidon2 part. h = word slot 7 (header flag).
//!       acc_j is read at the row n_words_chunk-1 (`last`), NOT at the end of the padded trace, so the padding rows (header-flag
//!       words, which contribute 0 but still multiply by alpha) do not matter. Native value:
//!       acc_j = sum over rows r < n_words_chunk of (1-h_r) * w6_r * alpha_j^(n_words_chunk - 1 - r)   (`acc_native`).
//!   D1c (v3) header terms: hdr_term(w) = w7 * sum_{k=0..6} beta_j^k * w_k (beta_j = public). Row 0: acc_j = (1-h)*w6 + hdr_term;
//!       transition: acc_j' = acc_j*alpha_j + (1-h')*w6' + hdr_term'. Degree <= 3 with the selector, no new column. Header word (v3) =
//!       [e, g, m_b, pid, seq_start_g, hd_lo, hd_hi, 1]; the AA rebuilds all header words of the chunk (see README). `acc_native` is the
//!       D1b sum plus the header terms; alpha and beta (`beta_of`) are hashed over the tag slots AND the chunk's header words.
//!   alpha_j = blake3("PQZ-w35-alpha" || j || s_in || s_out || chunk meta || hdr_first || len(T) || T) (first 16 bytes, LE, mod p)
//!       (`alpha_of`). It depends on the tag list T of the chunk, which the AA holds; see README.
//!
//! Soundness of D1b (sketch): s_out pins the words of the chunk (collision resistance of the sponge, 128-bit generic bound),
//! hence their tags T'; the AA recomputes alpha from ITS tag list T, so for T != T' the polynomial P_T - P_T' (degree < n_rows,
//! nonzero) must vanish at all three alphas: about (n_rows/p)^3 per hash query (random-oracle model for blake3).

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{generate_trace_rows, Poseidon2Air, Poseidon2Cols, RoundConstants};
use p3_symmetric::{CryptographicHasher, Permutation};

use p3_uni_stark::SubAirBuilder;

use crate::air::MIN_ROWS;
use crate::psponge::{checkpoints, ins_par, Ckpt};
use crate::data::{DOM_CHAIN, GOLDILOCKS_P};

pub const WLEN: usize = 8;
pub const RATE: usize = 8;
pub const NACC: usize = 3;
pub const STATE: usize = 12;

pub type State = [u64; STATE];

/// IV of the one-proof sponge of w33 (`air.rs` / `rc.rs`): rate 0, capacity (DOM_CHAIN, n_words_total, 0, 0).
pub fn iv_state(total_words: u64) -> State {
    let mut s = [0u64; STATE];
    s[8] = DOM_CHAIN;
    s[9] = total_words;
    s
}

#[derive(Clone, Debug)]
pub struct ChunkLayout {
    pub w: usize,
    pub p: usize,
    pub c_word: usize,
    pub c_k: usize,
    pub c_cnt: usize,
    pub c_mb: usize,
    pub c_hdr: usize,
    pub c_idx: usize,
    pub c_inv: usize,
    pub c_last: usize,
    pub c_seen: usize,
    pub c_acc: usize,
    pub width: usize,
    pub pv_s_in: usize,
    pub pv_s_out: usize,
    pub pv_chunk_index: usize,
    pub pv_nblocks: usize,
    pub pv_hdr_before: usize,
    pub pv_bsize: usize,
    pub pv_total: usize,
    pub pv_hdr_first: usize,
    pub pv_alpha: usize,
    pub pv_acc: usize,
    pub pv_beta: usize,
    pub n_pv: usize,
}

impl ChunkLayout {
    pub fn new(w: usize, p: usize) -> Self {
        assert_eq!(w, STATE, "chunk R_RC is written for Poseidon2 width 12 (rate 8, capacity 4)");
        let c_word = p;
        let c_k = c_word + WLEN;
        let c_cnt = c_k + 3;
        let c_mb = c_cnt + 1;
        let c_hdr = c_mb + 1;
        let c_idx = c_hdr + 1;
        let c_inv = c_idx + 1;
        let c_last = c_inv + 1;
        let c_seen = c_last + 1;
        let c_acc = c_seen + 1;
        let width = c_acc + NACC;
        ChunkLayout {
            w, p, c_word, c_k, c_cnt, c_mb, c_hdr, c_idx, c_inv, c_last, c_seen, c_acc, width,
            pv_s_in: 0, pv_s_out: 12, pv_chunk_index: 24, pv_nblocks: 25, pv_hdr_before: 26, pv_bsize: 27, pv_total: 28,
            pv_hdr_first: 29, pv_alpha: 37, pv_acc: 40, pv_beta: 43, n_pv: 46,
        }
    }
}

/// Public inputs of one chunk proof (w30 `RcChunkPublic` + D1b values), field elements as canonical u64.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RcChunkPublic {
    pub s_in: State,
    pub s_out: State,
    pub chunk_index: usize,
    pub n_blocks_chunk: usize,
    pub hdr_before: usize,
    pub block_size: usize,
    /// number of words of the WHOLE epoch stream, G * (block_size + 1)
    pub total_words: usize,
    pub hdr_first: [u64; 8],
    pub alpha: [u64; NACC],
    pub acc: [u64; NACC],
    /// w35 D1c: header-word weights, one per accumulator
    pub beta: [u64; NACC],
}

impl RcChunkPublic {
    pub fn n_words(&self) -> usize {
        self.n_blocks_chunk * (self.block_size + 1)
    }
    pub fn to_values<F: PrimeField64>(&self, lay: &ChunkLayout) -> Vec<F> {
        let mut v: Vec<F> = Vec::with_capacity(lay.n_pv);
        v.extend(self.s_in.iter().map(|&x| F::from_u64(x)));
        v.extend(self.s_out.iter().map(|&x| F::from_u64(x)));
        v.push(F::from_u64(self.chunk_index as u64));
        v.push(F::from_u64(self.n_blocks_chunk as u64));
        v.push(F::from_u64(self.hdr_before as u64));
        v.push(F::from_u64(self.block_size as u64));
        v.push(F::from_u64(self.total_words as u64));
        v.extend(self.hdr_first.iter().map(|&x| F::from_u64(x)));
        v.extend(self.alpha.iter().map(|&x| F::from_u64(x)));
        v.extend(self.acc.iter().map(|&x| F::from_u64(x)));
        v.extend(self.beta.iter().map(|&x| F::from_u64(x)));
        assert_eq!(v.len(), lay.n_pv);
        v
    }
}

// -------------------------------------------------------------------------------------------------------------
// Native helpers: alpha, acc, chunk states
// -------------------------------------------------------------------------------------------------------------

/// The two lists of a chunk that D1b / D1c fingerprint: the tag slot (word slot 6) of every record word and every header word
/// (8 values, slots 0..6 enter the accumulators), both in stream order.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ChunkLists {
    pub tags: Vec<u64>,
    pub hdrs: Vec<[u64; 8]>,
}

/// The lists of a chunk from its words (header first, header flag = word slot 7).
pub fn lists_of(words: &[Vec<u64>]) -> ChunkLists {
    let mut l = ChunkLists::default();
    for w in words {
        if w[7] == 0 {
            l.tags.push(w[6]);
        } else {
            let mut h = [0u64; 8];
            h.copy_from_slice(&w[..8]);
            l.hdrs.push(h);
        }
    }
    l
}

fn hash_input(dom: &[u8], j: usize, p: &RcChunkPublic, l: &ChunkLists) -> u64 {
    let mut m: Vec<u8> = Vec::with_capacity(48 + 8 * (24 + 6 + 8 + l.tags.len() + 8 * l.hdrs.len()));
    m.extend_from_slice(dom);
    m.push(j as u8);
    for x in p.s_in.iter().chain(p.s_out.iter()) {
        m.extend_from_slice(&x.to_le_bytes());
    }
    for x in [p.chunk_index, p.n_blocks_chunk, p.hdr_before, p.block_size, p.total_words] {
        m.extend_from_slice(&(x as u64).to_le_bytes());
    }
    for x in &p.hdr_first {
        m.extend_from_slice(&x.to_le_bytes());
    }
    m.extend_from_slice(&(l.tags.len() as u64).to_le_bytes());
    for t in &l.tags {
        m.extend_from_slice(&t.to_le_bytes());
    }
    // D1c: the chunk's header words (all 8 slots) join the hash input
    m.extend_from_slice(&(l.hdrs.len() as u64).to_le_bytes());
    for h in &l.hdrs {
        for x in h {
            m.extend_from_slice(&x.to_le_bytes());
        }
    }
    let d: [u8; 32] = p3_blake3::Blake3.hash_iter(m);
    (u128::from_le_bytes(d[..16].try_into().unwrap()) % GOLDILOCKS_P as u128) as u64
}

/// alpha_j of D1b: blake3 over a fixed domain string, j, the chunk's boundary states, its meta values, hdr_first, the tag list and
/// (D1c) the header words. Output: first 16 bytes little endian, reduced mod p (bias < 2^-63).
pub fn alpha_of(j: usize, p: &RcChunkPublic, l: &ChunkLists) -> u64 {
    hash_input(b"PQZ-w35-alpha", j, p, l)
}

/// beta_j of D1c: same inputs as alpha_j, other domain string.
pub fn beta_of(j: usize, p: &RcChunkPublic, l: &ChunkLists) -> u64 {
    hash_input(b"PQZ-w35-beta", j, p, l)
}

/// The three alphas of a chunk (the fields `alpha`, `beta`, `acc` of `p` are ignored).
pub fn alphas_of(p: &RcChunkPublic, l: &ChunkLists) -> [u64; NACC] {
    [alpha_of(0, p, l), alpha_of(1, p, l), alpha_of(2, p, l)]
}

pub fn betas_of(p: &RcChunkPublic, l: &ChunkLists) -> [u64; NACC] {
    [beta_of(0, p, l), beta_of(1, p, l), beta_of(2, p, l)]
}

/// Native accumulator value at the row n_words_chunk-1 (see the module doc): Horner over the rows. Record rows contribute their tag
/// slot, header rows contribute sum_{k=0..6} beta^k * w_k. `n_blocks` blocks of `block_size` records each, header first.
pub fn acc_native<F: PrimeField64>(alpha: u64, beta: u64, n_blocks: usize, block_size: usize, l: &ChunkLists) -> u64 {
    assert_eq!(l.tags.len(), n_blocks * block_size);
    assert_eq!(l.hdrs.len(), n_blocks);
    let a = F::from_u64(alpha);
    let b = F::from_u64(beta);
    let mut acc = F::ZERO;
    let mut t = l.tags.iter();
    for h in &l.hdrs {
        // header row r: acc = acc * alpha + sum_k beta^k h_k   (acc = 0 before the very first row, so the loop is exact)
        let mut hv = F::ZERO;
        let mut bk = F::ONE;
        for k in 0..7 {
            hv += bk * F::from_u64(h[k]);
            bk *= b;
        }
        acc = acc * a + hv;
        for _ in 0..block_size {
            acc = acc * a + F::from_u64(*t.next().unwrap());
        }
    }
    acc.as_canonical_u64()
}

/// Set alpha, beta and acc of `p` from the lists (honest statement).
pub fn seal<F: PrimeField64>(p: &mut RcChunkPublic, l: &ChunkLists) {
    p.alpha = alphas_of(p, l);
    p.beta = betas_of(p, l);
    for j in 0..NACC {
        p.acc[j] = acc_native::<F>(p.alpha[j], p.beta[j], p.n_blocks_chunk, p.block_size, l);
    }
}

/// Sponge from an arbitrary start state: per row r, state[0..8] += word_r, record the permutation input, permute, record the output.
/// Rows >= words.len() absorb the pad word [0,..,0,1].
pub fn sponge_rows_from<F: PrimeField64, const W: usize, P: Permutation<[F; W]>>(
    perm: &P,
    start: &State,
    words: &[Vec<u64>],
    n_rows: usize,
) -> (Vec<[F; W]>, Vec<[F; W]>) {
    assert_eq!(W, STATE);
    assert!(n_rows >= words.len());
    let mut s = [F::ZERO; W];
    for j in 0..W {
        s[j] = F::from_u64(start[j]);
    }
    let mut ins = Vec::with_capacity(n_rows);
    let mut outs = Vec::with_capacity(n_rows);
    let mut pad = vec![0u64; WLEN];
    pad[7] = 1;
    for k in 0..n_rows {
        let wk = if k < words.len() { &words[k] } else { &pad };
        for j in 0..WLEN {
            s[j] += F::from_u64(wk[j]);
        }
        ins.push(s);
        perm.permute_mut(&mut s);
        outs.push(s);
    }
    (ins, outs)
}

/// w36 (S1) ingest-side helper: the sponge states before rows 0, k, 2k, ... (< `n_rows`) of a chunk that starts at `start`.
pub fn sponge_checkpoints_from<F: PrimeField64, const W: usize, P: Permutation<[F; W]>>(
    perm: &P,
    start: &State,
    words: &[Vec<u64>],
    n_rows: usize,
    k: usize,
) -> Vec<Ckpt<W>> {
    assert_eq!(W, STATE);
    let mut st = [0u64; W];
    st.copy_from_slice(&start[..W]);
    let mut pad = vec![0u64; WLEN];
    pad[7] = 1;
    checkpoints::<F, W, P>(perm, &st, words, WLEN, &pad, n_rows, k)
}

/// w36 (S1): the `ins` of `sponge_rows_from`, filled in parallel from the checkpoints (first checkpoint = row 0 = `start`).
pub fn sponge_ins_par_from<F: PrimeField64, const W: usize, P: Permutation<[F; W]>>(
    perm: &P,
    words: &[Vec<u64>],
    n_rows: usize,
    ckpts: &[Ckpt<W>],
) -> Vec<[F; W]> {
    assert_eq!(W, STATE);
    let mut pad = vec![0u64; WLEN];
    pad[7] = 1;
    ins_par::<F, W, P>(perm, words, WLEN, &pad, n_rows, ckpts)
}

/// Full sponge state after absorbing `words` from `start` (native, no circuit).
pub fn state_after<F: PrimeField64, const W: usize, P: Permutation<[F; W]>>(perm: &P, start: &State, words: &[Vec<u64>]) -> State {
    let (_, outs) = sponge_rows_from::<F, W, P>(perm, start, words, words.len());
    let last = outs.last().expect("empty chunk");
    let mut o = [0u64; STATE];
    for j in 0..STATE {
        o[j] = last[j].as_canonical_u64();
    }
    o
}

/// Description of one chunk of a split stream (honest, native).
#[derive(Clone, Debug)]
pub struct ChunkPlan {
    pub chunk_index: usize,
    /// first block (0-based) and number of blocks
    pub first_block: usize,
    pub n_blocks: usize,
    pub hdr_before: usize,
}

/// Split `n_blocks` blocks in chunks of `c` whole blocks (the last may be shorter).
pub fn plan_chunks(n_blocks: usize, c: usize) -> Vec<ChunkPlan> {
    assert!(c >= 1 && n_blocks >= 1);
    let mut v = Vec::new();
    let mut b = 0;
    while b < n_blocks {
        let k = c.min(n_blocks - b);
        v.push(ChunkPlan { chunk_index: v.len(), first_block: b, n_blocks: k, hdr_before: b });
        b += k;
    }
    v
}

/// Honest public statements for every chunk of the stream `words` (mapped words, 8 values each), `block_size` records per block.
/// Returns (public statements with alpha/beta/acc, the tag and header lists per chunk).
pub fn honest_chunk_publics<F: PrimeField64, const W: usize, P: Permutation<[F; W]>>(
    perm: &P,
    words: &[Vec<u64>],
    block_size: usize,
    c: usize,
) -> (Vec<RcChunkPublic>, Vec<ChunkLists>) {
    let bw = block_size + 1;
    assert!(words.len() % bw == 0);
    let n_blocks = words.len() / bw;
    let total = words.len();
    let mut s = iv_state(total as u64);
    let mut pubs = Vec::new();
    let mut tag_lists = Vec::new();
    for pl in plan_chunks(n_blocks, c) {
        let cw = &words[pl.first_block * bw..(pl.first_block + pl.n_blocks) * bw];
        let s_out = state_after::<F, W, P>(perm, &s, cw);
        let lists = lists_of(cw);
        let mut hdr_first = [0u64; 8];
        hdr_first.copy_from_slice(&cw[0][..8]);
        let mut p = RcChunkPublic {
            s_in: s,
            s_out,
            chunk_index: pl.chunk_index,
            n_blocks_chunk: pl.n_blocks,
            hdr_before: pl.hdr_before,
            block_size,
            total_words: total,
            hdr_first,
            alpha: [0; NACC],
            acc: [0; NACC],
            beta: [0; NACC],
        };
        seal::<F>(&mut p, &lists);
        pubs.push(p);
        tag_lists.push(lists);
        s = s_out;
    }
    (pubs, tag_lists)
}

/// Tag slot (word slot 6) of the record words (flag slot 7 = 0) in stream order.
pub fn tags_of(words: &[Vec<u64>]) -> Vec<u64> {
    words.iter().filter(|w| w[7] == 0).map(|w| w[6]).collect()
}

// -------------------------------------------------------------------------------------------------------------
// AIR
// -------------------------------------------------------------------------------------------------------------

pub struct RcChunkAir<
    F: PrimeCharacteristicRing,
    LL,
    const W: usize,
    const SBOX: u64,
    const REG: usize,
    const HF: usize,
    const PR: usize,
> {
    pub p2: Poseidon2Air<F, LL, W, SBOX, REG, HF, PR>,
    pub consts: RoundConstants<F, W, HF, PR>,
    pub lay: ChunkLayout,
    pub block_size: u64,
    /// number of words of this chunk (AIR constant, also derived from the public values)
    pub n_words: u64,
    /// chunk_index == 0: row 0 also asserts s_in = IV(total_words)
    pub first_chunk: bool,
    /// how many of the three D1b accumulator constraints are active (3 in production; the test-only switch of the attack tests
    /// uses `RcChunkAir::without_d1b` to show the constraint is needed)
    pub d1b: bool,
}

impl<
        F: PrimeCharacteristicRing + Sync + Clone,
        LL,
        const W: usize,
        const SBOX: u64,
        const REG: usize,
        const HF: usize,
        const PR: usize,
    > RcChunkAir<F, LL, W, SBOX, REG, HF, PR>
{
    pub fn new(consts: RoundConstants<F, W, HF, PR>, block_size: u64, n_words: u64, first_chunk: bool) -> Self {
        assert!(block_size >= 1 && n_words >= 1);
        let p = p3_poseidon2_air::num_cols::<W, SBOX, REG, HF, PR>();
        RcChunkAir { p2: Poseidon2Air::new(consts.clone()), consts, lay: ChunkLayout::new(W, p), block_size, n_words, first_chunk, d1b: true }
    }
    /// TEST ONLY: an AIR without the D1b accumulator constraints (never used in a production path).
    pub fn without_d1b(mut self) -> Self {
        self.d1b = false;
        self
    }
}

impl<
        F: PrimeCharacteristicRing + Sync + Clone,
        LL: Sync,
        const W: usize,
        const SBOX: u64,
        const REG: usize,
        const HF: usize,
        const PR: usize,
    > BaseAir<F> for RcChunkAir<F, LL, W, SBOX, REG, HF, PR>
{
    fn width(&self) -> usize {
        self.lay.width
    }
    fn num_public_values(&self) -> usize {
        self.lay.n_pv
    }
}

impl<
        AB: AirBuilder<F = F>,
        F: Field,
        LL: GenericPoseidon2LinearLayers<W> + Sync,
        const W: usize,
        const SBOX: u64,
        const REG: usize,
        const HF: usize,
        const PR: usize,
    > Air<AB> for RcChunkAir<F, LL, W, SBOX, REG, HF, PR>
{
    fn eval(&self, builder: &mut AB) {
        let lay = &self.lay;
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let pv: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let c = |x: u64| -> AB::Expr { AB::Expr::from_u64(x) };
        let one = || -> AB::Expr { AB::Expr::ONE };
        let inv_bs = F::from_u64(self.block_size).inverse();

        // ---- (R1) Poseidon2 permutation of this row
        {
            let mut sub =
                SubAirBuilder::<AB, Poseidon2Air<F, LL, W, SBOX, REG, HF, PR>, AB::Var>::new(builder, 0..lay.p);
            self.p2.eval(&mut sub);
        }
        let p2l: &Poseidon2Cols<AB::Var, W, SBOX, REG, HF, PR> = local[..lay.p].borrow();
        let p2n: &Poseidon2Cols<AB::Var, W, SBOX, REG, HF, PR> = next[..lay.p].borrow();
        let out = |i: usize| -> AB::Expr { p2l.ending_full_rounds[HF - 1].post[i].into() };
        let wd = |i: usize| -> AB::Expr { local[lay.c_word + i].into() };
        let wdn = |i: usize| -> AB::Expr { next[lay.c_word + i].into() };
        let col = |i: usize| -> AB::Expr { local[i].into() };
        let coln = |i: usize| -> AB::Expr { next[i].into() };
        let pvx = |i: usize| -> AB::Expr { pv[i].into() };
        let bs_pv = pvx(lay.pv_bsize);

        // ---- (R2) sponge from the PUBLIC start state: row 0 input = s_in + word0 (rate), s_in (capacity)
        {
            let mut b = builder.when_first_row();
            for j in 0..RATE {
                b.assert_zero(Into::<AB::Expr>::into(p2l.inputs[j]) - wd(j) - pvx(lay.pv_s_in + j));
            }
            for j in RATE..W {
                b.assert_zero(Into::<AB::Expr>::into(p2l.inputs[j]) - pvx(lay.pv_s_in + j));
            }
        }
        {
            let mut b = builder.when_transition();
            for j in 0..RATE {
                b.assert_zero(Into::<AB::Expr>::into(p2n.inputs[j]) - out(j) - wdn(j));
            }
            for j in RATE..W {
                b.assert_zero(Into::<AB::Expr>::into(p2n.inputs[j]) - out(j));
            }
        }
        // ---- (R2b) chunk 0 starts at the IV of the one-proof sponge: (0^8, DOM_CHAIN, total_words, 0, 0)
        if self.first_chunk {
            let mut b = builder.when_first_row();
            for j in 0..RATE {
                b.assert_zero(pvx(lay.pv_s_in + j));
            }
            b.assert_zero(pvx(lay.pv_s_in + 8) - c(DOM_CHAIN));
            b.assert_zero(pvx(lay.pv_s_in + 9) - pvx(lay.pv_total));
            b.assert_zero(pvx(lay.pv_s_in + 10));
            b.assert_zero(pvx(lay.pv_s_in + 11));
        }

        // ---- (R3) row 0: the word is the public hdr_first and a header of block_size records; K, cnt, mb, hdr start values
        {
            let mut b = builder.when_first_row();
            for j in 0..8 {
                b.assert_zero(wd(j) - pvx(lay.pv_hdr_first + j));
            }
            b.assert_zero(wd(7) - one());
            b.assert_zero(wd(2) - bs_pv.clone());
            b.assert_zero(col(lay.c_k) - wd(3));
            b.assert_zero(col(lay.c_k + 1) - wd(0));
            b.assert_zero(col(lay.c_k + 2) - wd(4) + one());
            b.assert_zero(col(lay.c_cnt));
            b.assert_zero(col(lay.c_mb) - bs_pv.clone());
            b.assert_zero(col(lay.c_hdr) - pvx(lay.pv_hdr_before) - one());
        }

        // ---- (R4) per-row: flag boolean; a header announces m_B in {0, block_size}
        let f = wd(7);
        let mb = col(lay.c_mb);
        builder.assert_zero(f.clone() * (f.clone() - one()));
        builder.assert_zero(f.clone() * mb.clone() * (mb.clone() - bs_pv.clone()));

        // ---- (R5) transition row k -> k+1 (as rc.rs)
        {
            let nf = wdn(7);
            let not_nf = one() - nf.clone();
            let (k0, k1, k2) = (col(lay.c_k), col(lay.c_k + 1), col(lay.c_k + 2));
            let (cnt, hdr) = (col(lay.c_cnt), col(lay.c_hdr));
            let mut b = builder.when_transition();
            b.assert_zero(not_nf.clone() * (wdn(0) - k0.clone()));
            b.assert_zero(not_nf.clone() * (wdn(1) - k1.clone()));
            b.assert_zero(not_nf.clone() * (wdn(2) - k2.clone() - one()));
            b.assert_zero(coln(lay.c_k) - (nf.clone() * wdn(3) + not_nf.clone() * k0));
            b.assert_zero(coln(lay.c_k + 1) - (nf.clone() * wdn(0) + not_nf.clone() * k1));
            b.assert_zero(coln(lay.c_k + 2) - (nf.clone() * (wdn(4) - one()) + not_nf.clone() * wdn(2)));
            b.assert_zero(nf.clone() * (cnt.clone() - mb.clone()));
            b.assert_zero(coln(lay.c_cnt) - not_nf.clone() * (cnt + one()));
            b.assert_zero(coln(lay.c_mb) - (nf.clone() * wdn(2) + not_nf * mb));
            b.assert_zero(coln(lay.c_hdr) - hdr - nf * wdn(2) * AB::Expr::from(inv_bs));
        }

        // ---- (R6) row counter and "this is row n_words-1" selector
        let idx = col(lay.c_idx);
        let last = col(lay.c_last);
        let inv = col(lay.c_inv);
        let seen = col(lay.c_seen);
        let diff = idx.clone() - c(self.n_words - 1);
        builder.assert_zero(diff.clone() * last.clone());
        builder.assert_zero(diff * inv - (one() - last.clone()));
        {
            let mut b = builder.when_first_row();
            b.assert_zero(idx.clone());
            b.assert_zero(seen.clone() - last.clone());
        }
        {
            let mut b = builder.when_transition();
            b.assert_zero(coln(lay.c_idx) - idx - one());
            b.assert_zero(coln(lay.c_seen) - seen.clone() - coln(lay.c_last));
        }
        builder.when_last_row().assert_zero(seen - one());

        // ---- (D1b + D1c) three accumulators: tag slot of record rows, beta-weighted slots 0..6 of header rows
        if self.d1b {
            // beta_j^k are public constants (degree 0); the constraint is degree 2, degree 3 with the transition selector
            let hdr_term = |w: &dyn Fn(usize) -> AB::Expr, j: usize| -> AB::Expr {
                let beta = pvx(lay.pv_beta + j);
                let mut bk = AB::Expr::ONE;
                let mut sum = AB::Expr::ZERO;
                for k in 0..7 {
                    sum += bk.clone() * w(k);
                    bk *= beta.clone();
                }
                w(7) * sum
            };
            {
                let mut b = builder.when_first_row();
                for j in 0..NACC {
                    b.assert_zero(col(lay.c_acc + j) - (one() - wd(7)) * wd(6) - hdr_term(&wd, j));
                }
            }
            {
                let not_hn = one() - wdn(7);
                let mut b = builder.when_transition();
                for j in 0..NACC {
                    b.assert_zero(
                        coln(lay.c_acc + j)
                            - col(lay.c_acc + j) * pvx(lay.pv_alpha + j)
                            - not_hn.clone() * wdn(6)
                            - hdr_term(&wdn, j),
                    );
                }
            }
        }

        // ---- (R7) at row n_words-1: full output state = s_out, cnt = mb = block_size, hdr = hdr_before + n_blocks_chunk, acc
        {
            let mut b = builder.when(last);
            for j in 0..W {
                b.assert_zero(out(j) - pvx(lay.pv_s_out + j));
            }
            b.assert_zero(col(lay.c_cnt) - bs_pv.clone());
            b.assert_zero(col(lay.c_mb) - bs_pv);
            b.assert_zero(col(lay.c_hdr) - pvx(lay.pv_hdr_before) - pvx(lay.pv_nblocks));
            if self.d1b {
                for j in 0..NACC {
                    b.assert_zero(col(lay.c_acc + j) - pvx(lay.pv_acc + j));
                }
            }
        }
    }
}

impl<
        F: PrimeField64,
        LL: GenericPoseidon2LinearLayers<W> + Sync,
        const W: usize,
        const SBOX: u64,
        const REG: usize,
        const HF: usize,
        const PR: usize,
    > RcChunkAir<F, LL, W, SBOX, REG, HF, PR>
{
    /// Witness for whatever words are given, starting from `start` (the honest start state of the chunk). `alpha` = the alphas the prover
    /// puts in the public values (the accumulator column is computed with them).
    pub fn build_trace<P: Permutation<[F; W]>>(
        &self,
        perm: &P,
        words: &[Vec<u64>],
        start: &State,
        alpha: &[u64; NACC],
        beta: &[u64; NACC],
        hdr_before: u64,
    ) -> RowMajorMatrix<F> {
        let n_rows = words.len().next_power_of_two().max(MIN_ROWS);
        let (ins, _outs) = sponge_rows_from::<F, W, P>(perm, start, words, n_rows);
        self.build_trace_ins(words, ins, alpha, beta, hdr_before)
    }

    /// w36 (S1): same trace as `build_trace`, sponge rows filled in parallel from stored checkpoints
    /// (`sponge_checkpoints_from`; the first checkpoint is row 0 = `start`).
    pub fn build_trace_par<P: Permutation<[F; W]>>(
        &self,
        perm: &P,
        words: &[Vec<u64>],
        ckpts: &[Ckpt<W>],
        alpha: &[u64; NACC],
        beta: &[u64; NACC],
        hdr_before: u64,
    ) -> RowMajorMatrix<F> {
        let n_rows = words.len().next_power_of_two().max(MIN_ROWS);
        let ins = sponge_ins_par_from::<F, W, P>(perm, words, n_rows, ckpts);
        self.build_trace_ins(words, ins, alpha, beta, hdr_before)
    }

    /// The rest of the witness, given the permutation inputs `ins` of every row (unchanged w35 code).
    fn build_trace_ins(&self, words: &[Vec<u64>], ins: Vec<[F; W]>, alpha: &[u64; NACC], beta: &[u64; NACC], hdr_before: u64) -> RowMajorMatrix<F> {
        let lay = &self.lay;
        let n_words = words.len();
        let n_rows = n_words.next_power_of_two().max(MIN_ROWS);
        let p2 = generate_trace_rows::<F, LL, W, SBOX, REG, HF, PR>(ins, &self.consts, 0);
        assert_eq!(p2.width, lay.p);
        let mut vals = vec![F::ZERO; n_rows * lay.width];
        let mut pad = vec![0u64; WLEN];
        pad[7] = 1;
        let inv_bs = F::from_u64(self.block_size).inverse();
        let wf = |x: &Vec<u64>, j: usize| F::from_u64(x[j]);
        let x0 = &words[0];
        let mut k = [wf(x0, 3), wf(x0, 0), wf(x0, 4) - F::ONE];
        // the hdr column starts at hdr_before + 1 (row 0 is a header)
        let (mut cnt, mut mb, mut hdr) = (F::ZERO, wf(x0, 2), F::from_u64(hdr_before + 1));
        let mut acc = [F::ZERO; NACC];
        let al: Vec<F> = alpha.iter().map(|&a| F::from_u64(a)).collect();
        let be: Vec<F> = beta.iter().map(|&a| F::from_u64(a)).collect();
        for r in 0..n_rows {
            let x = if r < n_words { &words[r] } else { &pad };
            if r > 0 {
                if x[7] == 1 {
                    k = [wf(x, 3), wf(x, 0), wf(x, 4) - F::ONE];
                    cnt = F::ZERO;
                    mb = wf(x, 2);
                    hdr += wf(x, 2) * inv_bs;
                } else {
                    k = [k[0], k[1], wf(x, 2)];
                    cnt += F::ONE;
                }
            }
            for j in 0..NACC {
                let contrib = if x[7] == 0 {
                    wf(x, 6)
                } else {
                    let (mut hv, mut bk) = (F::ZERO, F::ONE);
                    for k in 0..7 {
                        hv += bk * wf(x, k);
                        bk *= be[j];
                    }
                    hv
                };
                acc[j] = if r == 0 { contrib } else { acc[j] * al[j] + contrib };
            }
            let row = &mut vals[r * lay.width..(r + 1) * lay.width];
            row[..lay.p].copy_from_slice(&p2.values[r * lay.p..(r + 1) * lay.p]);
            for j in 0..WLEN {
                row[lay.c_word + j] = wf(x, j);
            }
            row[lay.c_k..lay.c_k + 3].copy_from_slice(&k);
            row[lay.c_cnt] = cnt;
            row[lay.c_mb] = mb;
            row[lay.c_hdr] = hdr;
            row[lay.c_idx] = F::from_u64(r as u64);
            let is_last = r as u64 == self.n_words - 1;
            row[lay.c_last] = F::from_bool(is_last);
            row[lay.c_inv] =
                if is_last { F::ZERO } else { (F::from_u64(r as u64) - F::from_u64(self.n_words - 1)).inverse() };
            row[lay.c_seen] = F::from_bool(r as u64 >= self.n_words - 1);
            row[lay.c_acc..lay.c_acc + NACC].copy_from_slice(&acc);
        }
        RowMajorMatrix::new(vals, lay.width)
    }
}

// -------------------------------------------------------------------------------------------------------------
// C1 (Goldilocks / Poseidon2-12 / Blake3, plain mode) prove / verify wrappers
// -------------------------------------------------------------------------------------------------------------

/// Largest chunk the verifier accepts (public values are the verifier's own input; this only guards the AIR constructor).
pub const MAX_CHUNK_BLOCKS: usize = 1 << 20;

pub mod plain {
    use super::*;
    use crate::rel::{guard, LL};
    use crate::variants::FriOpts;
    pub use crate::variants::c1::{config, consts, from_bytes, perm, to_bytes, Val, HF, P, PR, REG, SBOX, W};
    use p3_uni_stark::{prove, verify};

    pub type ChunkA = RcChunkAir<Val, LL, W, { SBOX }, REG, { HF }, { PR }>;

    /// The verifier's AIR for a chunk statement: block_size, number of words and "chunk 0" come from the PUBLIC statement.
    pub fn chunk_air(p: &RcChunkPublic) -> Result<ChunkA, String> {
        if p.block_size == 0 || p.block_size > (1 << 20) || p.n_blocks_chunk == 0 || p.n_blocks_chunk > MAX_CHUNK_BLOCKS {
            return Err("chunk statement out of range".into());
        }
        Ok(ChunkA::new(consts(), p.block_size as u64, p.n_words() as u64, p.chunk_index == 0))
    }

    /// Prove a chunk. `words` = the chunk's words (header first). The trace starts at `p.s_in` with the alphas of `p`.
    pub fn prove_chunk(o: &FriOpts, words: &[Vec<u64>], p: &RcChunkPublic) -> Result<P, String> {
        let a = chunk_air(p)?;
        prove_chunk_with(o, &a, words, p)
    }

    /// As `prove_chunk` with a caller-chosen AIR (used by the tests for the OFF variants).
    pub fn prove_chunk_with(o: &FriOpts, a: &ChunkA, words: &[Vec<u64>], p: &RcChunkPublic) -> Result<P, String> {
        if words.is_empty() {
            return Err("empty chunk".into());
        }
        let trace = a.build_trace(&perm(), words, &p.s_in, &p.alpha, &p.beta, p.hdr_before as u64);
        let pv = p.to_values::<Val>(&a.lay);
        prove(&config(o), a, trace, &pv).map_err(|e| format!("{e:?}"))
    }

    pub fn verify_chunk(o: &FriOpts, proof: &P, p: &RcChunkPublic) -> Result<(), String> {
        guard(|| {
            let a = chunk_air(p)?;
            let pv = p.to_values::<Val>(&a.lay);
            verify(&config(o), &a, proof, &pv).map_err(|e| format!("{e:?}"))
        })
    }

    /// Verifier with a caller-chosen AIR (TEST ONLY: the OFF variants).
    pub fn verify_chunk_with(o: &FriOpts, a: &ChunkA, proof: &P, p: &RcChunkPublic) -> Result<(), String> {
        guard(|| {
            let pv = p.to_values::<Val>(&a.lay);
            verify(&config(o), a, proof, &pv).map_err(|e| format!("{e:?}"))
        })
    }

    pub fn chunk_rows(n_words: usize) -> usize {
        n_words.next_power_of_two().max(crate::air::MIN_ROWS)
    }

    /// Honest statements + tag lists for the words of a whole epoch stream (mapped C1 words).
    pub fn honest_publics(words: &[Vec<u64>], block_size: usize, c: usize) -> (Vec<RcChunkPublic>, Vec<ChunkLists>) {
        honest_chunk_publics::<Val, W, _>(&perm(), words, block_size, c)
    }

    /// The one-proof digest of the w33 sponge for the same words (first 4 rate elements of the final state).
    pub fn digest_of(s_out: &State) -> [u64; 4] {
        [s_out[0], s_out[1], s_out[2], s_out[3]]
    }
}
