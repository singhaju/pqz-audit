//! w38 stage 3: R_RC over linked chunks of the PACKED stream (two records per absorbed word) with range checks.
//!
//! Port of `chunk.rs` (w35 D1/D1b/D1c) to the packed format of `pair.rs`. The row kinds are the countdown of `pair.rs`
//! (hdr / va / vb, rem, zr, rinv; pad = seen - last), so the old K = (pid, e, seq) columns are gone: pid and e live in the header
//! word, seq = seq_start + position. A single RC proof (the w33 `rc.rs` role) is ONE chunk with `chunk_index = 0` that holds all
//! blocks (the verifier then knows the whole final state, whose first 4 elements are the stream digest); there is no separate AIR.
//!
//! Packed word (record row): [id_a, v_a, b_a, tag_a, id_b, v_b, b_b, tag_b]; header row: [e, g, m_g, pid, seq_start, hd_lo, hd_hi, 1].
//! Rows per block: 1 + ceil(B/2). Public values: `ChunkLayout` (46), `total_words` and the chunk size count PACKED words.
//!
//! Constraints (degree <= 3):
//!   R1/R2/R2b  Poseidon2 per row, sponge from the public s_in (chunk 0: s_in = IV(total_words)).
//!   R3  row 0: word = hdr_first (public), a header row; hdr counter = hdr_before + 1.
//!   R4  row kinds, countdown, empty half b holds the all-zero half word (so its tag, v, b are 0).
//!   R5  counter hn' = hn + hdr'.  Last real row: zr = 1 (block complete), hn = hdr_before + n_blocks_chunk, out = s_out.
//!   R6  idx / last / seen as in `pair.rs`.
//!   D1  three accumulators binding BOTH tags of a record row with distinct powers of alpha, and the header slots 0..6 with powers of beta:
//!         row 0 / transition:  acc' = alpha^2 acc + (1-hdr') (alpha tag_a' + tag_b') + hdr' sum_{i<7} beta^i w_i'
//!       (an empty half contributes tag 0). Read at row `last`.
//!   RANGE  (w38 stage 3) for every row with va = 1: v_a, v_b < 2^32 and b_a, b_b < 2^20, by bit columns (32 + 20 per half).
//!       The empty half is covered too: its word is forced to zero, so its bits are zero. This is what makes Exec P2r sound.
//! Padding rows are outside every structural rule (pad = seen - last) and are not read by any boundary constraint.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{generate_trace_rows, Poseidon2Air, Poseidon2Cols, RoundConstants};
use p3_symmetric::Permutation;
use p3_uni_stark::SubAirBuilder;

use crate::air::MIN_ROWS;
use crate::chunk::{hash_input, iv_state, plan_chunks, sponge_rows_from, state_after, ChunkLayout, ChunkLists, RcChunkPublic, State, NACC};
use crate::data::DOM_CHAIN;
use crate::pair::{kinds_by_position, pair_n_words, rows_per_block, Kind};

pub const WLEN: usize = 8;
pub const RATE: usize = 8;
pub const V_BITS: usize = 32;
pub const B_BITS: usize = 20;

/// Number of packed words of a chunk statement.
pub fn pc_n_words(p: &RcChunkPublic) -> usize {
    pair_n_words(p.n_blocks_chunk, p.block_size)
}

#[derive(Clone, Debug)]
pub struct PcLayout {
    pub p: usize,
    pub c_word: usize,
    pub c_hdr: usize,
    pub c_va: usize,
    pub c_vb: usize,
    pub c_rem: usize,
    pub c_zr: usize,
    pub c_rinv: usize,
    pub c_hn: usize,
    pub c_idx: usize,
    pub c_inv: usize,
    pub c_last: usize,
    pub c_seen: usize,
    pub c_acc: usize,
    /// bit columns: v_a (32), b_a (20), v_b (32), b_b (20)
    pub c_bva: usize,
    pub c_bba: usize,
    pub c_bvb: usize,
    pub c_bbb: usize,
    pub width: usize,
    /// public-value offsets (same as `ChunkLayout`)
    pub pv: ChunkLayout,
}

impl PcLayout {
    pub fn new(p: usize) -> Self {
        let c_word = p;
        let mut c = c_word + WLEN;
        let mut take = |n: usize| {
            let s = c;
            c += n;
            s
        };
        let c_hdr = take(1);
        let c_va = take(1);
        let c_vb = take(1);
        let c_rem = take(1);
        let c_zr = take(1);
        let c_rinv = take(1);
        let c_hn = take(1);
        let c_idx = take(1);
        let c_inv = take(1);
        let c_last = take(1);
        let c_seen = take(1);
        let c_acc = take(NACC);
        let c_bva = take(V_BITS);
        let c_bba = take(B_BITS);
        let c_bvb = take(V_BITS);
        let c_bbb = take(B_BITS);
        PcLayout {
            p, c_word, c_hdr, c_va, c_vb, c_rem, c_zr, c_rinv, c_hn, c_idx, c_inv, c_last, c_seen, c_acc, c_bva, c_bba, c_bvb, c_bbb,
            width: c, pv: ChunkLayout::new(12, p),
        }
    }
}

// -------------------------------------------------------------------------------------------------------------
// Native helpers
// -------------------------------------------------------------------------------------------------------------

/// Tag and header lists of PACKED words of blocks of `block_size` records (tags: both halves of every record row, the empty half of an
/// odd block is not listed; hdrs: the header words).
pub fn lists_of_packed(words: &[Vec<u64>], block_size: usize) -> ChunkLists {
    let rpb = rows_per_block(block_size);
    let nrec = (block_size + 1) / 2;
    let mut l = ChunkLists::default();
    for (k, w) in words.iter().enumerate() {
        let pos = k % rpb;
        if pos == 0 {
            let mut h = [0u64; 8];
            h.copy_from_slice(&w[..8]);
            l.hdrs.push(h);
        } else {
            l.tags.push(w[3]);
            if !(pos == nrec && block_size % 2 == 1) {
                l.tags.push(w[7]);
            }
        }
    }
    l
}

/// Tag list only (stream order).
pub fn tags_of_packed(words: &[Vec<u64>], block_size: usize) -> Vec<u64> {
    lists_of_packed(words, block_size).tags
}

pub fn alpha_of(j: usize, p: &RcChunkPublic, l: &ChunkLists) -> u64 {
    hash_input(b"PQZ-w38-alpha", j, p, l)
}
pub fn beta_of(j: usize, p: &RcChunkPublic, l: &ChunkLists) -> u64 {
    hash_input(b"PQZ-w38-beta", j, p, l)
}

/// Native accumulator at the row n_words_chunk-1: Horner with factor alpha^2 per row; a record row adds alpha*tag_a + tag_b
/// (tag_b = 0 for the empty half), a header row adds sum_{i<7} beta^i h_i.
pub fn acc_native_p<F: PrimeField64>(alpha: u64, beta: u64, n_blocks: usize, block_size: usize, l: &ChunkLists) -> u64 {
    assert_eq!(l.tags.len(), n_blocks * block_size);
    assert_eq!(l.hdrs.len(), n_blocks);
    let a = F::from_u64(alpha);
    let a2 = a * a;
    let b = F::from_u64(beta);
    let mut acc = F::ZERO;
    let mut t = l.tags.chunks(block_size);
    for h in &l.hdrs {
        let (mut hv, mut bk) = (F::ZERO, F::ONE);
        for k in 0..7 {
            hv += bk * F::from_u64(h[k]);
            bk *= b;
        }
        acc = acc * a2 + hv;
        for pr in t.next().unwrap().chunks(2) {
            let tb = if pr.len() == 2 { F::from_u64(pr[1]) } else { F::ZERO };
            acc = acc * a2 + a * F::from_u64(pr[0]) + tb;
        }
    }
    acc.as_canonical_u64()
}

/// Set alpha, beta and acc of `p` from the lists (honest statement).
pub fn seal_p<F: PrimeField64>(p: &mut RcChunkPublic, l: &ChunkLists) {
    for j in 0..NACC {
        p.alpha[j] = alpha_of(j, p, l);
        p.beta[j] = beta_of(j, p, l);
    }
    for j in 0..NACC {
        p.acc[j] = acc_native_p::<F>(p.alpha[j], p.beta[j], p.n_blocks_chunk, p.block_size, l);
    }
}

/// The verifier side (AA): alpha, beta, acc of `p` must be the values of ITS lists.
pub fn check_sealed<F: PrimeField64>(p: &RcChunkPublic, l: &ChunkLists) -> Result<(), String> {
    if l.hdrs.len() != p.n_blocks_chunk || l.tags.len() != p.n_blocks_chunk * p.block_size {
        return Err("lists: size differs from the chunk statement".into());
    }
    let mut q = p.clone();
    seal_p::<F>(&mut q, l);
    if q.alpha != p.alpha || q.beta != p.beta || q.acc != p.acc {
        return Err("lists: alpha / beta / acc differ from the AA's lists".into());
    }
    Ok(())
}

/// Honest public statements and lists of every chunk of the PACKED stream `words` (`block_size` records per block, `c` blocks per chunk).
pub fn honest_chunk_publics_p<F: PrimeField64, const W: usize, P: Permutation<[F; W]>>(
    perm: &P,
    words: &[Vec<u64>],
    block_size: usize,
    c: usize,
) -> (Vec<RcChunkPublic>, Vec<ChunkLists>) {
    let bw = rows_per_block(block_size);
    assert!(words.len() % bw == 0);
    let n_blocks = words.len() / bw;
    let total = words.len();
    let mut s = iv_state(total as u64);
    let (mut pubs, mut lists) = (Vec::new(), Vec::new());
    for pl in plan_chunks(n_blocks, c) {
        let cw = &words[pl.first_block * bw..(pl.first_block + pl.n_blocks) * bw];
        let s_out = state_after::<F, W, P>(perm, &s, cw);
        let l = lists_of_packed(cw, block_size);
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
        seal_p::<F>(&mut p, &l);
        pubs.push(p);
        lists.push(l);
        s = s_out;
    }
    (pubs, lists)
}

// -------------------------------------------------------------------------------------------------------------
// AIR
// -------------------------------------------------------------------------------------------------------------

pub struct PChunkAir<
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
    pub lay: PcLayout,
    pub block_size: u64,
    /// packed words of this chunk
    pub n_words: u64,
    pub first_chunk: bool,
    /// TEST ONLY: `false` drops the range-check constraints (shows they are needed)
    pub ranges: bool,
}

impl<F: PrimeCharacteristicRing + Sync + Clone, LL, const W: usize, const SBOX: u64, const REG: usize, const HF: usize, const PR: usize>
    PChunkAir<F, LL, W, SBOX, REG, HF, PR>
{
    pub fn new(consts: RoundConstants<F, W, HF, PR>, block_size: u64, n_words: u64, first_chunk: bool) -> Self {
        assert!(W == 12 && block_size >= 1 && n_words >= 1);
        let p = p3_poseidon2_air::num_cols::<W, SBOX, REG, HF, PR>();
        PChunkAir { p2: Poseidon2Air::new(consts.clone()), consts, lay: PcLayout::new(p), block_size, n_words, first_chunk, ranges: true }
    }
    /// TEST ONLY.
    pub fn without_ranges(mut self) -> Self {
        self.ranges = false;
        self
    }
}

impl<F: PrimeCharacteristicRing + Sync + Clone, LL: Sync, const W: usize, const SBOX: u64, const REG: usize, const HF: usize, const PR: usize>
    BaseAir<F> for PChunkAir<F, LL, W, SBOX, REG, HF, PR>
{
    fn width(&self) -> usize {
        self.lay.width
    }
    fn num_public_values(&self) -> usize {
        self.lay.pv.n_pv
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
    > Air<AB> for PChunkAir<F, LL, W, SBOX, REG, HF, PR>
{
    fn eval(&self, builder: &mut AB) {
        let l = &self.lay;
        let q = &l.pv;
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let pv: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let c = |x: u64| -> AB::Expr { AB::Expr::from_u64(x) };
        let one = || -> AB::Expr { AB::Expr::ONE };

        // R1 Poseidon2
        {
            let mut sub = SubAirBuilder::<AB, Poseidon2Air<F, LL, W, SBOX, REG, HF, PR>, AB::Var>::new(builder, 0..l.p);
            self.p2.eval(&mut sub);
        }
        let p2l: &Poseidon2Cols<AB::Var, W, SBOX, REG, HF, PR> = local[..l.p].borrow();
        let p2n: &Poseidon2Cols<AB::Var, W, SBOX, REG, HF, PR> = next[..l.p].borrow();
        let out = |i: usize| -> AB::Expr { p2l.ending_full_rounds[HF - 1].post[i].into() };
        let wd = |i: usize| -> AB::Expr { local[l.c_word + i].into() };
        let wdn = |i: usize| -> AB::Expr { next[l.c_word + i].into() };
        let col = |i: usize| -> AB::Expr { local[i].into() };
        let coln = |i: usize| -> AB::Expr { next[i].into() };
        let pvx = |i: usize| -> AB::Expr { pv[i].into() };
        let bs_pv = pvx(q.pv_bsize);

        // R2 sponge from the public start state
        {
            let mut b = builder.when_first_row();
            for j in 0..RATE {
                b.assert_zero(Into::<AB::Expr>::into(p2l.inputs[j]) - wd(j) - pvx(q.pv_s_in + j));
            }
            for j in RATE..W {
                b.assert_zero(Into::<AB::Expr>::into(p2l.inputs[j]) - pvx(q.pv_s_in + j));
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
        if self.first_chunk {
            let mut b = builder.when_first_row();
            for j in 0..RATE {
                b.assert_zero(pvx(q.pv_s_in + j));
            }
            b.assert_zero(pvx(q.pv_s_in + 8) - c(DOM_CHAIN));
            b.assert_zero(pvx(q.pv_s_in + 9) - pvx(q.pv_total));
            b.assert_zero(pvx(q.pv_s_in + 10));
            b.assert_zero(pvx(q.pv_s_in + 11));
        }

        // R4 row kinds and countdown (as pair.rs)
        let (hdr, va, vb) = (col(l.c_hdr), col(l.c_va), col(l.c_vb));
        let (idx, last, inv, seen) = (col(l.c_idx), col(l.c_last), col(l.c_inv), col(l.c_seen));
        let (rem, zr, rinv) = (col(l.c_rem), col(l.c_zr), col(l.c_rinv));
        let pad = seen.clone() - last.clone();
        let pad_next = coln(l.c_seen) - coln(l.c_last);
        for x in [&hdr, &va, &vb] {
            builder.assert_zero(x.clone() * (x.clone() - one()));
        }
        builder.assert_zero(hdr.clone() + va.clone() + pad - one());
        builder.assert_zero(vb.clone() * (one() - va.clone()));
        builder.assert_zero(hdr.clone() * (wd(7) - one()));
        builder.assert_zero(hdr.clone() * (wd(2) - bs_pv.clone()));
        builder.assert_zero(hdr.clone() * (rem.clone() - wd(2)));
        let short = va.clone() * (one() - vb.clone());
        builder.assert_zero(short.clone() * rem.clone());
        for i in 4..8 {
            builder.assert_zero(short.clone() * wd(i));
        }
        builder.assert_zero(rem.clone() * rinv - (one() - zr.clone()));
        builder.assert_zero(zr.clone() * rem.clone());

        // R3 row 0
        {
            let mut b = builder.when_first_row();
            b.assert_zero(hdr.clone() - one());
            for j in 0..8 {
                b.assert_zero(wd(j) - pvx(q.pv_hdr_first + j));
            }
            b.assert_zero(col(l.c_hn) - pvx(q.pv_hdr_before) - one());
        }
        {
            let mut b = builder.when_transition();
            b.assert_zero((one() - pad_next) * (coln(l.c_hdr) - zr.clone()));
            b.assert_zero(coln(l.c_va) * (coln(l.c_rem) - rem.clone() + one() + coln(l.c_vb)));
            b.assert_zero(coln(l.c_hn) - col(l.c_hn) - coln(l.c_hdr));
        }

        // RANGE: v < 2^32 and b < 2^20 for both halves of every row with va = 1 (the empty half is zero, so its bits are zero)
        if self.ranges {
            let pw = |base: usize, n: usize| -> AB::Expr {
                let mut acc = AB::Expr::ZERO;
                for k in 0..n {
                    acc += col(base + k) * c(1u64 << k);
                }
                acc
            };
            for (base, n) in [(l.c_bva, V_BITS), (l.c_bba, B_BITS), (l.c_bvb, V_BITS), (l.c_bbb, B_BITS)] {
                for k in 0..n {
                    let x = col(base + k);
                    builder.assert_zero(x.clone() * (x - one()));
                }
            }
            builder.assert_zero(va.clone() * (pw(l.c_bva, V_BITS) - wd(1)));
            builder.assert_zero(va.clone() * (pw(l.c_bba, B_BITS) - wd(2)));
            builder.assert_zero(va.clone() * (pw(l.c_bvb, V_BITS) - wd(5)));
            builder.assert_zero(va.clone() * (pw(l.c_bbb, B_BITS) - wd(6)));
        }

        // R6 counter and `last`
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
            b.assert_zero(coln(l.c_idx) - idx - one());
            b.assert_zero(coln(l.c_seen) - seen.clone() - coln(l.c_last));
        }
        builder.when_last_row().assert_zero(seen - one());

        // D1 accumulators
        let alpha2 = |j: usize| -> AB::Expr { pvx(q.pv_alpha + j) * pvx(q.pv_alpha + j) };
        let contrib = |w: &dyn Fn(usize) -> AB::Expr, h: AB::Expr, j: usize| -> AB::Expr {
            let beta = pvx(q.pv_beta + j);
            let (mut bk, mut sum) = (AB::Expr::ONE, AB::Expr::ZERO);
            for k in 0..7 {
                sum += bk.clone() * w(k);
                bk *= beta.clone();
            }
            (one() - h.clone()) * (pvx(q.pv_alpha + j) * w(3) + w(7)) + h * sum
        };
        {
            let mut b = builder.when_first_row();
            for j in 0..NACC {
                b.assert_zero(col(l.c_acc + j) - contrib(&wd, hdr.clone(), j));
            }
        }
        {
            let mut b = builder.when_transition();
            for j in 0..NACC {
                b.assert_zero(coln(l.c_acc + j) - col(l.c_acc + j) * alpha2(j) - contrib(&wdn, coln(l.c_hdr), j));
            }
        }

        // R7 at row n_words-1
        {
            let mut b = builder.when(last);
            for j in 0..W {
                b.assert_zero(out(j) - pvx(q.pv_s_out + j));
            }
            b.assert_zero(zr - one());
            b.assert_zero(col(l.c_hn) - pvx(q.pv_hdr_before) - pvx(q.pv_nblocks));
            for j in 0..NACC {
                b.assert_zero(col(l.c_acc + j) - pvx(q.pv_acc + j));
            }
        }
    }
}

impl<F: PrimeField64, LL: GenericPoseidon2LinearLayers<W> + Sync, const W: usize, const SBOX: u64, const REG: usize, const HF: usize, const PR: usize>
    PChunkAir<F, LL, W, SBOX, REG, HF, PR>
{
    /// Honest witness: kinds by position of `block_size`.
    pub fn build_trace<P: Permutation<[F; W]>>(
        &self,
        perm: &P,
        words: &[Vec<u64>],
        start: &State,
        alpha: &[u64; NACC],
        beta: &[u64; NACC],
        hdr_before: u64,
    ) -> RowMajorMatrix<F> {
        let kinds = kinds_by_position(words.len(), self.block_size as usize);
        self.build_trace_kinds(perm, words, &kinds, start, alpha, beta, hdr_before)
    }

    /// Witness with hand-made row kinds (tests).
    pub fn build_trace_kinds<P: Permutation<[F; W]>>(
        &self,
        perm: &P,
        words: &[Vec<u64>],
        kinds: &[Kind],
        start: &State,
        alpha: &[u64; NACC],
        beta: &[u64; NACC],
        hdr_before: u64,
    ) -> RowMajorMatrix<F> {
        let l = &self.lay;
        let n_words = words.len();
        assert_eq!(kinds.len(), n_words);
        let n_rows = n_words.next_power_of_two().max(MIN_ROWS);
        let (ins, _) = sponge_rows_from::<F, W, P>(perm, start, words, n_rows);
        self.build_trace_ins(words, kinds, ins, alpha, beta, hdr_before)
    }

    /// w38 stage 3: `trace=par` (checkpoints of `sponge_checkpoints_from`, made at ingest) -> same trace, permutation inputs filled in parallel.
    pub fn build_trace_par<P: Permutation<[F; W]>>(
        &self,
        perm: &P,
        words: &[Vec<u64>],
        alpha: &[u64; NACC],
        beta: &[u64; NACC],
        hdr_before: u64,
        ckpts: &[crate::psponge::Ckpt<W>],
    ) -> RowMajorMatrix<F> {
        let kinds = kinds_by_position(words.len(), self.block_size as usize);
        let n_rows = words.len().next_power_of_two().max(MIN_ROWS);
        let ins = crate::chunk::sponge_ins_par_from::<F, W, P>(perm, words, n_rows, ckpts);
        self.build_trace_ins(words, &kinds, ins, alpha, beta, hdr_before)
    }

    fn build_trace_ins(
        &self,
        words: &[Vec<u64>],
        kinds: &[Kind],
        ins: Vec<[F; W]>,
        alpha: &[u64; NACC],
        beta: &[u64; NACC],
        hdr_before: u64,
    ) -> RowMajorMatrix<F> {
        let l = &self.lay;
        let n_words = words.len();
        let n_rows = n_words.next_power_of_two().max(MIN_ROWS);
        let p2 = generate_trace_rows::<F, LL, W, SBOX, REG, HF, PR>(ins, &self.consts, 0);
        assert_eq!(p2.width, l.p);
        let mut vals = vec![F::ZERO; n_rows * l.width];
        let mut pad = vec![0u64; WLEN];
        pad[7] = 1;
        let al: Vec<F> = alpha.iter().map(|&a| F::from_u64(a)).collect();
        let be: Vec<F> = beta.iter().map(|&a| F::from_u64(a)).collect();
        let mut acc = [F::ZERO; NACC];
        let mut rem = F::ZERO;
        let mut hn = F::from_u64(hdr_before);
        let bits = |x: u64, n: usize, row: &mut [F], base: usize| {
            for i in 0..n {
                row[base + i] = F::from_u64((x >> i) & 1);
            }
        };
        for r in 0..n_rows {
            let x = if r < n_words { &words[r] } else { &pad };
            let kind = if r < n_words { kinds[r] } else { Kind { hdr: false, va: false, vb: false } };
            if r >= n_words {
                rem = F::ZERO;
            } else if kind.hdr {
                rem = F::from_u64(x[2]);
                hn += F::ONE;
            } else if kind.va {
                rem = rem - F::ONE - F::from_bool(kind.vb);
            }
            for j in 0..NACC {
                let w = |k: usize| F::from_u64(x[k]);
                let contrib = if kind.hdr {
                    let (mut hv, mut bk) = (F::ZERO, F::ONE);
                    for k in 0..7 {
                        hv += bk * w(k);
                        bk *= be[j];
                    }
                    hv
                } else {
                    al[j] * w(3) + w(7)
                };
                acc[j] = if r == 0 { contrib } else { acc[j] * al[j] * al[j] + contrib };
            }
            let row = &mut vals[r * l.width..(r + 1) * l.width];
            row[..l.p].copy_from_slice(&p2.values[r * l.p..(r + 1) * l.p]);
            for j in 0..WLEN {
                row[l.c_word + j] = F::from_u64(x[j]);
            }
            if kind.va {
                bits(x[1], V_BITS, row, l.c_bva);
                bits(x[2], B_BITS, row, l.c_bba);
                bits(x[5], V_BITS, row, l.c_bvb);
                bits(x[6], B_BITS, row, l.c_bbb);
            }
            row[l.c_hdr] = F::from_bool(kind.hdr);
            row[l.c_va] = F::from_bool(kind.va);
            row[l.c_vb] = F::from_bool(kind.vb);
            row[l.c_rem] = rem;
            let z = rem == F::ZERO;
            row[l.c_zr] = F::from_bool(z);
            row[l.c_rinv] = if z { F::ZERO } else { rem.inverse() };
            row[l.c_hn] = hn;
            row[l.c_idx] = F::from_u64(r as u64);
            let is_last = r as u64 == self.n_words - 1;
            row[l.c_last] = F::from_bool(is_last);
            row[l.c_inv] = if is_last { F::ZERO } else { (F::from_u64(r as u64) - F::from_u64(self.n_words - 1)).inverse() };
            row[l.c_seen] = F::from_bool(r as u64 >= self.n_words - 1);
            row[l.c_acc..l.c_acc + NACC].copy_from_slice(&acc);
        }
        RowMajorMatrix::new(vals, l.width)
    }
}

// -------------------------------------------------------------------------------------------------------------
// C1 wrappers (Goldilocks / Poseidon2-12 / Blake3, plain mode)
// -------------------------------------------------------------------------------------------------------------

pub const MAX_CHUNK_BLOCKS: usize = 1 << 20;

pub mod plain {
    use super::*;
    use crate::rel::{guard, LL};
    use crate::variants::FriOpts;
    pub use crate::variants::c1::{config, consts, from_bytes, perm, to_bytes, Val, HF, P, PR, REG, SBOX, W};
    use p3_uni_stark::{prove, verify};

    pub type PcA = PChunkAir<Val, LL, W, { SBOX }, REG, { HF }, { PR }>;

    pub fn chunk_air(p: &RcChunkPublic) -> Result<PcA, String> {
        if p.block_size == 0 || p.block_size > (1 << 20) || p.n_blocks_chunk == 0 || p.n_blocks_chunk > MAX_CHUNK_BLOCKS {
            return Err("chunk statement out of range".into());
        }
        Ok(PcA::new(consts(), p.block_size as u64, pc_n_words(p) as u64, p.chunk_index == 0))
    }
    pub fn values(p: &RcChunkPublic) -> Vec<Val> {
        p.to_values::<Val>(&ChunkLayout::new(12, 0))
    }
    pub fn prove_chunk(o: &FriOpts, words: &[Vec<u64>], p: &RcChunkPublic) -> Result<P, String> {
        let a = chunk_air(p)?;
        prove_chunk_with(o, &a, words, p)
    }
    pub fn prove_chunk_with(o: &FriOpts, a: &PcA, words: &[Vec<u64>], p: &RcChunkPublic) -> Result<P, String> {
        if words.is_empty() {
            return Err("empty chunk".into());
        }
        let trace = a.build_trace(&perm(), words, &p.s_in, &p.alpha, &p.beta, p.hdr_before as u64);
        prove(&config(o), a, trace, &values(p)).map_err(|e| format!("{e:?}"))
    }
    pub fn prove_chunk_kinds(o: &FriOpts, words: &[Vec<u64>], kinds: &[Kind], p: &RcChunkPublic) -> Result<P, String> {
        let a = chunk_air(p)?;
        let trace = a.build_trace_kinds(&perm(), words, kinds, &p.s_in, &p.alpha, &p.beta, p.hdr_before as u64);
        prove(&config(o), &a, trace, &values(p)).map_err(|e| format!("{e:?}"))
    }
    pub fn verify_chunk(o: &FriOpts, proof: &P, p: &RcChunkPublic) -> Result<(), String> {
        guard(|| {
            let a = chunk_air(p)?;
            verify(&config(o), &a, proof, &values(p)).map_err(|e| format!("{e:?}"))
        })
    }
    /// TEST ONLY: verifier with a caller-chosen AIR.
    pub fn verify_chunk_with(o: &FriOpts, a: &PcA, proof: &P, p: &RcChunkPublic) -> Result<(), String> {
        guard(|| verify(&config(o), a, proof, &values(p)).map_err(|e| format!("{e:?}")))
    }
    pub fn chunk_rows(n_words: usize) -> usize {
        n_words.next_power_of_two().max(MIN_ROWS)
    }
    pub fn chunk_width() -> usize {
        PcA::new(consts(), 1, 1, true).lay.width
    }
    pub fn honest_publics(words: &[Vec<u64>], block_size: usize, c: usize) -> (Vec<RcChunkPublic>, Vec<ChunkLists>) {
        honest_chunk_publics_p::<Val, W, _>(&perm(), words, block_size, c)
    }
    /// The words state after the whole stream (chunk-wise): digest = first 4 elements.
    pub fn digest_of(s_out: &State) -> [u64; 4] {
        [s_out[0], s_out[1], s_out[2], s_out[3]]
    }
}
