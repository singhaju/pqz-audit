//! w29 (NEW file): helpers shared by the linked-chunk variants of R_Exec (`exec_link.rs`) and R_RC (`rc_link.rs`).
//!
//! * `fill_chain_from`: like `chain::fill_chain`, but starts from a given 12-element sponge state and a word slice
//!   (copy of the loop of `chain::fill_chain`, which is tied to a whole `Workload`; the existing file is not edited).
//! * `reference_chunks`: the public link values of an honest split, computed with the REFERENCE sponge (`rescue::perm`),
//!   never from a trace.
//! * `check_links`: the checks of the plan (section 1, "The verifier checks") that are common to both relations.

use crate::data::{cap_init, pad_word, Word, Workload};
use crate::rescue::{perm, perm_states, F, GROUP, W};
use winterfell::math::{FieldElement, StarkField};

pub type State = [F; W];

/// Largest values the count/sum may have (they are field elements in the AIR; the verifier refuses values that alias mod p).
pub const MAX_ACC: u64 = F::MODULUS - 1;

/// The sponge state at the start of chunk 0: capacity `cap_init(total_groups)`, rate zero.
pub fn initial_state(total_groups: usize) -> State {
    let mut s = [F::ZERO; W];
    s[..4].copy_from_slice(&cap_init(total_groups));
    s
}

/// Fill columns S (0..12) and R (12..20) for `n` rows (n = multiple of 8), starting from `start` (the state BEFORE absorbing
/// `words[0]`). Words after the real ones are `pad_word()` (as in `chain::fill_chain`). Returns the extended word list.
pub fn fill_chain_from(cols: &mut [Vec<F>], words: &[Word], n: usize, start: State) -> Vec<Word> {
    let ng = n / GROUP;
    assert!(words.len() <= ng);
    let mut ws = words.to_vec();
    ws.resize(ng, pad_word());
    let mut s = start;
    for k in 0..ng {
        for j in 0..8 {
            s[4 + j] += ws[k][j];
        }
        let states = perm_states(s);
        let next_word = if k + 1 < ng { ws[k + 1] } else { pad_word() };
        for r in 0..GROUP {
            let row = k * GROUP + r;
            for j in 0..W {
                cols[j][row] = states[r][j];
            }
            for j in 0..8 {
                cols[12 + j][row] = next_word[j];
            }
        }
        s = states[GROUP - 1];
    }
    ws
}

/// Public values of one chunk of an honest split (reference computation).
#[derive(Clone, Debug)]
pub struct ChunkRef {
    pub chunk_index: usize,
    /// index (in the stream) of the chunk's first word
    pub first_word: usize,
    pub n_words: usize,
    pub n_blocks: usize,
    pub hdr_before: usize,
    pub s_in: Option<State>,
    pub s_out: State,
    pub hdr_first: Word,
    pub cnt_in: u64,
    pub sum_in: u64,
    pub cnt_out: u64,
    pub sum_out: u64,
    pub is_last: bool,
}

/// Reference sponge over the workload, cut into chunks of `split[i]` whole blocks. `theta` is the Exec predicate
/// (match iff v >= theta); the same rule as `Workload::reference_result`. For the LAST chunk `s_out` is the full final state
/// (the AIR publics keep only the digest part, see `exec_link` / `rc_link`).
pub fn reference_chunks(w: &Workload, theta: u64, split: &[usize]) -> Vec<ChunkRef> {
    assert!(!split.is_empty() && split.iter().all(|&b| b > 0), "every chunk needs at least one block");
    assert_eq!(split.iter().sum::<usize>(), w.n_blocks, "split must cover all blocks");
    let words_per_block = w.block_size + 1;
    let total = w.n_groups();
    let mut s = initial_state(total);
    let (mut cnt, mut sum) = (0u64, 0u64);
    let mut out = Vec::with_capacity(split.len());
    let (mut first, mut hdr_before) = (0usize, 0usize);
    for (i, &nb) in split.iter().enumerate() {
        let n_words = nb * words_per_block;
        let s_in = if i == 0 { None } else { Some(s) };
        let (cnt_in, sum_in) = (cnt, sum);
        for x in &w.words[first..first + n_words] {
            if x[7] == F::ZERO && x[4].as_int() >= theta {
                cnt += 1;
                sum += x[5].as_int();
            }
            for j in 0..8 {
                s[4 + j] += x[j];
            }
            perm(&mut s);
        }
        out.push(ChunkRef {
            chunk_index: i,
            first_word: first,
            n_words,
            n_blocks: nb,
            hdr_before,
            s_in,
            s_out: s,
            hdr_first: w.words[first],
            cnt_in,
            sum_in,
            cnt_out: cnt,
            sum_out: sum,
            is_last: i + 1 == split.len(),
        });
        first += n_words;
        hdr_before += nb;
    }
    out
}

/// The part of a chunk public input that the common chain checks look at.
pub struct LinkView<'a> {
    pub chunk_index: usize,
    pub total_groups: usize,
    pub n_blocks_chunk: usize,
    pub block_size: usize,
    pub s_in: &'a Option<State>,
    pub hdr_first: &'a Word,
    pub s_out: &'a State,
    pub is_last: bool,
}

/// Plan section 1, "The verifier checks", the part common to R_Exec and R_RC. `n_blocks`, `block_size` and `digest` are the
/// verifier's own expectation (from the statement), never taken from the chunks.
pub fn check_links(views: &[LinkView], n_blocks: usize, block_size: usize, digest: &[F; 4]) -> Result<(), String> {
    let k = views.len();
    if k == 0 {
        return Err("link: no chunks".into());
    }
    if n_blocks == 0 || block_size == 0 {
        return Err("link: n_blocks and block_size must be positive".into());
    }
    let total_groups = n_blocks * (block_size + 1);
    let bs = F::new(block_size as u64);
    let mut sum_blocks = 0usize;
    for (i, v) in views.iter().enumerate() {
        if v.chunk_index != i {
            return Err(format!("link: chunk {i} carries chunk_index {}", v.chunk_index));
        }
        if v.block_size != block_size {
            return Err(format!("link: chunk {i} block_size {} != {block_size}", v.block_size));
        }
        if v.total_groups != total_groups {
            return Err(format!("link: chunk {i} total_groups {} != {total_groups}", v.total_groups));
        }
        if v.n_blocks_chunk == 0 {
            return Err(format!("link: chunk {i} has no block"));
        }
        sum_blocks = sum_blocks.checked_add(v.n_blocks_chunk).ok_or("link: n_blocks overflow")?;
        if v.s_in.is_some() != (i > 0) {
            return Err(format!("link: chunk {i}: s_in must be present exactly for chunks after the first"));
        }
        if v.is_last != (i + 1 == k) {
            return Err(format!("link: chunk {i}: is_last = {} but there are {k} chunks", v.is_last));
        }
        // header word of the first block of the chunk: flag (index 7) = 1 and announced size (index 2) = block_size
        if v.hdr_first[7] != F::ONE {
            return Err(format!("link: chunk {i}: hdr_first flag is not 1"));
        }
        if v.hdr_first[2] != bs {
            return Err(format!("link: chunk {i}: hdr_first m_b != block_size"));
        }
        if i > 0 {
            let prev = &views[i - 1];
            if v.s_in.as_ref().unwrap() != prev.s_out {
                return Err(format!("link: S_out of chunk {} != S_in of chunk {i}", i - 1));
            }
        }
        if v.is_last {
            if v.s_out[4..8] != digest[..] {
                return Err("link: digest of the last chunk != D".into());
            }
            // canonical form of the last S_out: only the 4 digest elements are used, the rest must be zero
            if v.s_out[..4].iter().chain(v.s_out[8..].iter()).any(|x| *x != F::ZERO) {
                return Err("link: last S_out must be zero outside the digest elements".into());
            }
        }
    }
    if sum_blocks != n_blocks {
        return Err(format!("link: sum of n_blocks_chunk {sum_blocks} != n_blocks {n_blocks}"));
    }
    Ok(())
}

/// Proof options of all chunks must be the same (and `verify_proof` accepts only `default_options()` on every chunk).
pub fn check_same_options(proofs: &[&winterfell::Proof]) -> Result<(), String> {
    for p in proofs.iter().skip(1) {
        if p.options() != proofs[0].options() {
            return Err("link: chunk proofs use different proof options".into());
        }
    }
    Ok(())
}
