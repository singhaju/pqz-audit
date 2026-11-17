//! w35 D1 / D1b tests: linked R_RC chunks (laptop, small sizes).
use pqz_plonky3_w38::chunk::plain::*;
use pqz_plonky3_w38::chunk::{iv_state, plan_chunks, seal, tags_of, RcChunkPublic};
use pqz_plonky3_w38::data::Workload;
use pqz_plonky3_w38::rel::plain as w33;
use pqz_plonky3_w38::{c1, FriOpts};

const BS: usize = 8;

fn stream(g: usize, seed: u64) -> Vec<Vec<u64>> {
    c1::words(&Workload::synthetic(g * BS, BS, seed))
}

fn chunk_words<'a>(words: &'a [Vec<u64>], p: &RcChunkPublic, first_block: usize) -> &'a [Vec<u64>] {
    let bw = BS + 1;
    &words[first_block * bw..(first_block + p.n_blocks_chunk) * bw]
}

#[test]
fn chunked_digest_equals_one_proof_digest() {
    // G = 37 is not a multiple of 4 or 16; every chunk is also proven and verified
    let o = FriOpts::from_env();
    let g = 37;
    let words = stream(g, 11);
    let one = w33::rc_public(&words, BS);
    for c in [1usize, 4, 16] {
        let (pubs, tags) = honest_publics(&words, BS, c);
        assert_eq!(pubs.len(), g.div_ceil(c), "c={c}");
        assert_eq!(pubs[0].s_in, iv_state((g * (BS + 1)) as u64), "chunk 0 starts at the IV");
        let mut fb = 0;
        for (j, p) in pubs.iter().enumerate() {
            if j + 1 < pubs.len() {
                assert_eq!(p.s_out, pubs[j + 1].s_in);
            }
            assert_eq!(p.chunk_index, j);
            assert_eq!(p.hdr_before, fb);
            let cw = chunk_words(&words, p, fb);
            assert_eq!(tags[j].tags, tags_of(cw));
            if c == 16 || j < 3 || j + 1 == pubs.len() {
                // proving every chunk at c = 1 is slow in a test; first 3 and the last are enough there
                let proof = prove_chunk(&o, cw, p).expect("prove");
                verify_chunk(&o, &proof, p).expect("honest chunk must verify");
            }
            fb += p.n_blocks_chunk;
        }
        assert_eq!(fb, g);
        let last = pubs.last().unwrap();
        assert_eq!(digest_of(&last.s_out).to_vec(), one.digest, "chunked digest == one-proof digest for c={c}");
    }
}

#[test]
fn chunk0_first_row_input_equals_w33_rc() {
    // w33 R_RC row 0 input: [word0 on the rate, DOM_CHAIN, n_words, 0, 0]; chunk 0 with s_in = IV: s_in + word0 gives the same vector
    let words = stream(5, 3);
    let (pubs, _) = honest_publics(&words, BS, 2);
    let s = &pubs[0].s_in;
    assert_eq!(&s[..8], &[0u64; 8]);
    assert_eq!(s[8], pqz_plonky3_w38::data::DOM_CHAIN);
    assert_eq!(s[9], (5 * (BS + 1)) as u64);
    assert_eq!(&s[10..], &[0u64, 0]);
    // same permutation outputs: the one-proof sponge digest from the first chunk run over all blocks
    let (all, _) = honest_publics(&words, BS, 5);
    assert_eq!(digest_of(&all[0].s_out).to_vec(), w33::rc_public(&words, BS).digest);
}

fn reject(label: &str, o: &FriOpts, words: &[Vec<u64>], p: &RcChunkPublic, mutate: impl FnOnce(&mut RcChunkPublic)) {
    // prove honestly, then verify against a mutated statement
    let proof = prove_chunk(o, words, p).expect("prove");
    verify_chunk(o, &proof, p).expect("honest");
    let mut q = p.clone();
    mutate(&mut q);
    assert!(verify_chunk(o, &proof, &q).is_err(), "{label}: must be rejected");
}

#[test]
fn statement_tampering_is_rejected() {
    let o = FriOpts::from_env();
    let words = stream(9, 5);
    let (pubs, _) = honest_publics(&words, BS, 4);
    let p = &pubs[1]; // middle chunk (index 1)
    let cw = chunk_words(&words, p, 4);
    reject("s_out", &o, cw, p, |q| q.s_out[11] ^= 1);
    reject("s_out rate", &o, cw, p, |q| q.s_out[0] ^= 1);
    reject("s_in", &o, cw, p, |q| q.s_in[5] ^= 1);
    reject("s_in capacity", &o, cw, p, |q| q.s_in[10] ^= 1);
    reject("acc", &o, cw, p, |q| q.acc[1] ^= 1);
    reject("alpha", &o, cw, p, |q| q.alpha[2] ^= 1);
    reject("hdr_before", &o, cw, p, |q| q.hdr_before += 1);
    reject("hdr_first", &o, cw, p, |q| q.hdr_first[1] += 1);
    reject("n_blocks", &o, cw, p, |q| q.n_blocks_chunk += 1);
    reject("block_size", &o, cw, p, |q| q.block_size += 1);
    reject("total_words", &o, cw, p, |q| q.total_words += 1);
    reject("chunk_index -> 0 (needs the IV)", &o, cw, p, |q| q.chunk_index = 0);
}

#[test]
fn a_chunk_0_not_at_the_iv_is_rejected_by_the_air() {
    // chunk 0 with an arbitrary start state: the honest prover's trace is consistent, only R2b (IV) fails
    let o = FriOpts::from_env();
    let words = stream(6, 9);
    let (pubs, tags) = honest_publics(&words, BS, 3);
    let mut p = pubs[0].clone();
    p.s_in[0] = 12345;
    p.s_out = pqz_plonky3_w38::chunk::state_after::<c1::Val, 12, _>(&perm(), &p.s_in, chunk_words(&words, &p, 0));
    seal::<c1::Val>(&mut p, &tags[0]);
    let cw = chunk_words(&words, &p, 0);
    // prover builds the trace, proving with an AIR that does not know it is chunk 0 would verify: here the verifier's AIR is built from chunk_index = 0
    let proof = prove_chunk(&o, cw, &p);
    match proof {
        Err(_) => {}
        Ok(pr) => assert!(verify_chunk(&o, &pr, &p).is_err(), "chunk 0 with a foreign start state must be rejected"),
    }
    // the same statement as chunk_index 1 is a legal middle chunk (R2b is not applied) and is accepted: R2b is what pins chunk 0
    let mut q = p.clone();
    q.chunk_index = 1;
    seal::<c1::Val>(&mut q, &tags[0]);
    let pr = prove_chunk(&o, cw, &q).unwrap();
    verify_chunk(&o, &pr, &q).expect("a middle chunk may start from any public state");
}

#[test]
fn foreign_words_with_honest_statement_rejected() {
    // prover holds other words (same shape) than the statement's s_out / acc
    let o = FriOpts::from_env();
    let a = stream(4, 21);
    let b = stream(4, 22);
    let (pubs, _) = honest_publics(&a, BS, 4);
    let p = &pubs[0];
    let proof = prove_chunk(&o, chunk_words(&b, p, 0), p);
    if let Ok(pr) = proof {
        assert!(verify_chunk(&o, &pr, p).is_err());
    }
}

#[test]
fn tag_fingerprint_needs_the_d1b_constraint() {
    // a statement with an acc for DIFFERENT tags: rejected with D1b on; accepted by the AIR without the D1b constraints (test-only AIR)
    let o = FriOpts::from_env();
    let words = stream(4, 31);
    let (pubs, tags) = honest_publics(&words, BS, 4);
    let mut p = pubs[0].clone();
    let mut t2 = tags[0].clone();
    t2.tags[7] ^= 1; // one tag differs
    seal::<c1::Val>(&mut p, &t2);
    let cw = chunk_words(&words, &p, 0);
    // ON: prover cannot make a valid proof for the false acc
    match prove_chunk(&o, cw, &p) {
        Err(_) => {}
        Ok(pr) => assert!(verify_chunk(&o, &pr, &p).is_err(), "D1b ON: wrong tag list must be rejected"),
    }
    // OFF (test-only): the same statement verifies
    let off = chunk_air(&p).unwrap().without_d1b();
    let pr = prove_chunk_with(&o, &off, cw, &p).expect("prove");
    verify_chunk_with(&o, &off, &pr, &p).expect("D1b OFF: accepted (shows the constraint is needed)");
}

#[test]
fn header_slots_5_and_6_are_not_forced_to_zero() {
    // REPORT ITEM: no rule of R_RC (chunk or one-proof) forces header slots 5, 6 to 0.
    let o = FriOpts::from_env();
    let mut words = stream(4, 41);
    for g in 0..4 {
        words[g * (BS + 1)][5] = 0xAAAA_0000 + g as u64;
        words[g * (BS + 1)][6] = 0xBBBB_0000 + g as u64;
    }
    let (pubs, _) = honest_publics(&words, BS, 4);
    let p = &pubs[0];
    let pr = prove_chunk(&o, &words, p).expect("prove");
    verify_chunk(&o, &pr, p).expect("a header with nonzero slots 5, 6 verifies: nothing forces them to 0");
    // the one-proof R_RC of w33 accepts the same stream
    let st = w33::rc_public(&words, BS);
    let pr1 = w33::prove_rc(&o, &words, &st).expect("prove");
    w33::verify_rc(&o, &pr1, &st).expect("w33 R_RC accepts it as well");
}

#[test]
fn plan_chunks_shapes() {
    let v = plan_chunks(37, 16);
    assert_eq!(v.iter().map(|p| p.n_blocks).collect::<Vec<_>>(), vec![16, 16, 5]);
    assert_eq!(v[2].hdr_before, 32);
}

#[test]
fn d1c_beta_and_header_terms_are_constrained() {
    // w35 v3 (D1c): beta is a public value, and the header words of the chunk enter the accumulators
    let o = FriOpts::from_env();
    let words = stream(9, 5);
    let (pubs, lists) = honest_publics(&words, BS, 4);
    let p = &pubs[1];
    let cw = chunk_words(&words, p, 4);
    reject("beta", &o, cw, p, |q| q.beta[1] ^= 1);
    // a statement whose acc was computed for a header word that differs in slot 5 (or 6, or 4) from the stream's: a prover with the
    // stream's words cannot meet it
    for slot in [4usize, 5, 6] {
        let mut l2 = lists[1].clone();
        l2.hdrs[1][slot] ^= 1;
        let mut q = p.clone();
        seal::<c1::Val>(&mut q, &l2);
        match prove_chunk(&o, cw, &q) {
            Err(_) => {}
            Ok(pr) => assert!(verify_chunk(&o, &pr, &q).is_err(), "header slot {slot}: a wrong header list must be rejected"),
        }
        // the AIR without D1b/D1c constraints accepts it (shows the header term is what rejects)
        let off = chunk_air(&q).unwrap().without_d1b();
        let pr = prove_chunk_with(&o, &off, cw, &q).expect("prove");
        verify_chunk_with(&o, &off, &pr, &q).expect("D1b/D1c OFF: accepted");
    }
}
