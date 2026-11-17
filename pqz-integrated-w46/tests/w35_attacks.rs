//! Attacks A1-A16 of DESIGN sections 7 and 8 (A14-A16 are the v3 / D1c attacks) (release mode: `cargo test --release --offline`).
//! Every attack is REJECTED with all checks ON (and the message names the intended check). Where meaningful it is ACCEPTED when only its own
//! check is switched off (test-only switch structs `ReqChecks` / `AaChecks`); where a second check covers the same attack, the test says so and
//! shows that the attack is accepted only when BOTH are off.
mod common;
use common::*;
use pqz_eval::eapat::EpochKeys;
use pqz_eval::{B_DOMAIN};
use pqz_integrated_w46::w35::*;
use pqz_integrated_w46::*;
use pqz_plonky3_w36::chunk::{self, acc_native, iv_state};
use pqz_plonky3_w36::c1;

const ON: ReqChecks = ReqChecks::ON;

fn off(f: impl Fn(&mut ReqChecks)) -> ReqChecks {
    let mut s = ON;
    f(&mut s);
    s
}
fn off_aa(f: impl Fn(&mut AaChecks)) -> AaChecks {
    let mut s = AaChecks::ON;
    f(&mut s);
    s
}

/// ON must reject with a message containing `needle`.
fn rejected(fx: &Fx, resp: &CspResponse, needle: &str) {
    match fx.full(resp, ON) {
        Ok((_, r)) => panic!("attack ACCEPTED with all checks on (result {r:?})"),
        Err(e) => assert!(e.msg.contains(needle), "rejected for another reason: {}", e.msg),
    }
}
/// With `sw` the attack is accepted; returns the result.
fn accepted(fx: &Fx, resp: &CspResponse, sw: ReqChecks) -> (u64, u64) {
    fx.full(resp, sw).unwrap_or_else(|e| panic!("attack still rejected with its own check off: {}", e.msg)).1
}
fn still_rejected(fx: &Fx, resp: &CspResponse, sw: ReqChecks, needle: &str) {
    match fx.full(resp, sw) {
        Ok(_) => panic!("accepted with one check off, but a second check was expected to catch it"),
        Err(e) => assert!(e.msg.contains(needle), "{}", e.msg),
    }
}

fn foreign_words(fx: &Fx) -> Vec<Vec<u64>> {
    let mut rs2 = fx.records.clone();
    for r in rs2.iter_mut().filter(|r| r.a == pqz_eval::X) {
        r.b = (r.b + 1) % B_DOMAIN;
    }
    let log2 = build_log(&rs2, &EpochKeys::from_seed(fx.seed));
    c1::words(&log2.wl)
}

fn cleared(b: &Bloom35) -> Bloom35 {
    Bloom35 { bits: vec![0; b.bits.len()], nbits: b.nbits, k: b.k }
}

fn covered_of(runs: &[(usize, usize)], g: usize) -> Vec<bool> {
    let mut c = vec![false; g];
    for &(a, b) in runs {
        for i in a - 1..b {
            c[i] = true;
        }
    }
    c
}

fn claim_of(runs: &[RunClaim]) -> (u64, u64) {
    (runs.iter().map(|r| r.stmt.count).sum(), runs.iter().map(|r| r.stmt.sum).sum())
}

// ---------------------------------------------------------------------------------------------------------------

#[test]
fn a1_run_over_a_foreign_stream_of_the_same_size() {
    let fx = fx_one();
    let fw = foreign_words(fx);
    let iv = iv_state((fx.w.g * (BLOCK + 1)) as u64);
    let cl = prove_run_over(&fw[0..4 * (BLOCK + 1)], &iv, 1, 4, fx.ctx, THETA).unwrap();
    let mut resp = fx.honest(0);
    resp.claim = claim_of(std::slice::from_ref(&cl));
    resp.runs = vec![cl];
    assert_ne!(resp.claim, truth(&fx.records));
    rejected(fx, &resp, "s_out is not the anchored state");
    let r = accepted(fx, &resp, off(|s| s.states = false));
    assert_ne!(r, truth(&fx.records), "with `states` off the foreign result is accepted");
}

#[test]
fn a2_a_retained_chunk_left_out_of_the_runs() {
    let fx = fx_two();
    let mut resp = fx.honest(0);
    assert_eq!(resp.runs.len(), 2);
    resp.runs.truncate(1); // chunk 2 (block 10 holds hits) is dropped
    resp.claim = claim_of(&resp.runs);
    // the CSP cannot open zero bits for the flagged block
    assert!(fx.w.blooms[9].openings_for(&fx.f).is_none());
    assert!(!resp.openings.iter().any(|(g, _)| *g == 10));
    rejected(fx, &resp, "no Bloom opening");
    let r = accepted(fx, &resp, off(|s| s.prune = false));
    assert_ne!(r, truth(&fx.records));
}

#[test]
fn a3_block_list_with_a_block_removed_duplicated_or_reordered() {
    // removed: the block with hits is dropped from the list together with its chunk's run
    let fx = fx_two();
    let mut resp = fx.honest(0);
    resp.runs.truncate(1);
    resp.claim = claim_of(&resp.runs);
    for g in [9usize, 11, 12] {
        resp.openings.push((g as u64, fx.w.blooms[g - 1].openings_for(&fx.f).unwrap())); // the clean blocks of chunk 2 are opened
    }
    resp.blocks.remove(9);
    rejected(fx, &resp, "block list has 12 blocks");
    let r = accepted(fx, &resp, off(|s| s.block_list = false));
    assert_ne!(r, truth(&fx.records), "the hits of the removed block are silently lost");

    // duplicated
    let fx1 = fx_one();
    let mut resp = fx1.honest(0);
    let d = resp.blocks[8].clone();
    resp.blocks.insert(9, d);
    rejected(fx1, &resp, "block list has 14 blocks");
    accepted(fx1, &resp, off(|s| s.block_list = false));

    // reordered
    let mut resp = fx1.honest(0);
    resp.blocks.swap(9, 10);
    rejected(fx1, &resp, "block list");
    accepted(fx1, &resp, off(|s| s.block_list = false));
}

#[test]
fn a4_summary_forged_after_the_aa_signed_bits_cleared() {
    let fx = fx_two();
    let forged = cleared(&fx.w.blooms[9]);
    // (a) the CSP puts the forged MRoot(S) into the B list: R_e rebuilt from the list differs from the anchored R_e
    let mut resp = fx.honest(0);
    resp.runs.truncate(1);
    resp.claim = claim_of(&resp.runs);
    for g in [9usize, 11, 12] {
        resp.openings.push((g as u64, fx.w.blooms[g - 1].openings_for(&fx.f).unwrap()));
    }
    resp.openings.push((10, forged.openings_for(&fx.f).unwrap()));
    resp.blocks[9].s_root = forged.mroot();
    rejected(fx, &resp, "R_e rebuilt from the blocks differs");
    let r = accepted(fx, &resp, off(|s| s.block_list = false));
    assert_ne!(r, truth(&fx.records));
    // (b) the B list is honest, the openings come from the cleared filter: the path does not verify against the anchored MRoot(S)
    resp.blocks[9].s_root = fx.w.blooms[9].mroot();
    rejected(fx, &resp, "Merkle path");
    let r = accepted(fx, &resp, off(|s| s.open_path = false));
    assert_ne!(r, truth(&fx.records));
}

#[test]
fn a5_summary_forged_at_ingest_the_aa_refuses() {
    let fx = fx_two();
    let mut blocks = fx.w.blocks.clone();
    blocks[9].s_root = cleared(&fx.w.blooms[9]).mroot();
    let e = aa_finalize(&fx.proofs, &blocks, &fx.w.material(), AaChecks::ON).unwrap_err();
    assert!(e.contains("MRoot(S)"), "{e}");
    assert!(aa_finalize(&fx.proofs, &blocks, &fx.w.material(), off_aa(|s| s.summaries = false)).is_ok());
    // a forged r_rec or count is refused by the same check
    let mut b2 = fx.w.blocks.clone();
    b2[3].r_rec[0] ^= 1;
    assert!(aa_finalize(&fx.proofs, &b2, &fx.w.material(), AaChecks::ON).unwrap_err().contains("r_rec"));
}

#[test]
fn a6_bloom_opening_with_a_wrong_bit_or_path() {
    let fx = fx_one();
    // (a) wrong bit: the hit block's filter has the query bit set; the CSP claims it is 0 and uses the honest path
    let tag = first_tag(&fx.f);
    let bl = &fx.w.blooms[1];
    let p0 = bloom_positions(&tag, bl.nbits, bl.k)[0];
    let mut ops = bl.open_many(&[p0 / 64]);
    assert_eq!(ops[0].word >> (p0 % 64) & 1, 1, "the query bit is set in the hit block");
    ops[0].word &= !(1u64 << (p0 % 64));
    let mut resp = fx.honest(0);
    resp.runs.clear();
    resp.claim = (0, 0);
    resp.openings = fx.openings_except(&vec![false; fx.w.g], &[1]);
    resp.openings.push((2, ops));
    rejected(fx, &resp, "Merkle path");
    let r = accepted(fx, &resp, off(|s| s.open_path = false));
    assert_eq!(r, (0, 0));
    assert_ne!(r, truth(&fx.records));
    // (b) honest zero bit, corrupted path
    let mut resp = fx.honest(0);
    let o = resp.openings.iter_mut().find(|(g, _)| *g == 5).unwrap();
    o.1[0].path[0][0] ^= 1;
    rejected(fx, &resp, "Merkle path");
    assert_eq!(accepted(fx, &resp, off(|s| s.open_path = false)), truth(&fx.records));
    // (c) a leaf index outside the array
    let mut resp = fx.honest(0);
    let o = resp.openings.iter_mut().find(|(g, _)| *g == 5).unwrap();
    o.1[0].leaf_idx += 100000;
    rejected(fx, &resp, "outside the bit array");
}

#[test]
fn a7_run_not_on_chunk_boundaries_or_overlapping_runs() {
    let fx = fx_one();
    // (a) run over blocks 2..5: neither end is a chunk boundary; s_in is the true state after block 1
    let cl = fx.run_over(2, 5, &fx.state_after_blocks(1));
    let mut resp = fx.honest(0);
    resp.claim = claim_of(std::slice::from_ref(&cl));
    resp.runs = vec![cl];
    resp.openings = fx.openings_except(&covered_of(&[(2, 5)], fx.w.g), &[]);
    rejected(fx, &resp, "chunk boundary");
    // second check: s_in is not an anchored sigma
    still_rejected(fx, &resp, off(|s| s.run_shape = false), "s_in is not the anchored state");
    accepted(fx, &resp, off(|s| {
        s.run_shape = false;
        s.states = false
    }));
    // (b) overlapping runs: chunk 0 and chunks 0..1 (the hits are counted twice)
    let r1 = fx.run_over(1, 4, &fx.state_after_blocks(0));
    let r2 = fx.run_over(1, 8, &fx.state_after_blocks(0));
    let mut resp = fx.honest(0);
    resp.claim = claim_of(&[r1.clone(), r2.clone()]);
    resp.runs = vec![r1, r2];
    resp.openings = fx.openings_except(&covered_of(&[(1, 8)], fx.w.g), &[]);
    rejected(fx, &resp, "not ordered/disjoint");
    let r = accepted(fx, &resp, off(|s| s.run_shape = false));
    assert_eq!(r.0, 2 * truth(&fx.records).0, "double count");
}

#[test]
fn a8_run_from_another_chunks_or_epochs_state() {
    let fx = fx_one();
    // (a) the honest proof of chunk 1 (blocks 5..8), labelled as blocks 1..4; the hits of block 2 are hidden
    let mut cl = fx.run_over(5, 8, &fx.state_after_blocks(4));
    cl.first = 1;
    cl.last = 4;
    let mut resp = fx.honest(0);
    resp.claim = claim_of(std::slice::from_ref(&cl));
    resp.runs = vec![cl];
    resp.openings = fx.openings_except(&covered_of(&[(1, 4)], fx.w.g), &[]);
    rejected(fx, &resp, "s_in is not the anchored state");
    still_rejected(fx, &resp, off(|s| s.states = false), "hdr_first");
    let r = accepted(fx, &resp, off(|s| {
        s.states = false;
        s.hdr_first = false
    }));
    assert_eq!(r, (0, 0));
    assert_ne!(r, truth(&fx.records));
    // (b) chunk 0 started from another epoch's IV (other total_words), over a foreign stream
    let fw = foreign_words(fx);
    let other_iv = iv_state((fx.w.g * (BLOCK + 1) + BLOCK + 1) as u64);
    let cl = prove_run_over(&fw[0..4 * (BLOCK + 1)], &other_iv, 1, 4, fx.ctx, THETA).unwrap();
    let mut resp = fx.honest(0);
    resp.claim = claim_of(std::slice::from_ref(&cl));
    resp.runs = vec![cl];
    rejected(fx, &resp, "s_in is not the anchored state");
    let r = accepted(fx, &resp, off(|s| s.states = false));
    assert_ne!(r, truth(&fx.records));
}

#[test]
fn a9_claimed_result_differs_from_the_sum_of_the_runs() {
    let fx = fx_one();
    let mut resp = fx.honest(0);
    resp.claim.0 += 1;
    rejected(fx, &resp, "claimed result");
    let r = accepted(fx, &resp, off(|s| s.claim = false));
    assert_eq!(r.0, truth(&fx.records).0 + 1);
    let mut resp = fx.honest(0);
    resp.claim.1 += 5;
    rejected(fx, &resp, "claimed result");
}

#[test]
fn a10_broken_chunk_link() {
    let fx = fx_two();
    // chunk 1 is proven from the state after block 1 only; chunks 2, 3 continue from it; B' carries those states
    let proofs = fx.rechain(1, fx.state_after_blocks(1), false);
    let blocks = fx.blocks_for(&proofs, &fx.w.material());
    let e = aa_finalize(&proofs, &blocks, &fx.w.material(), AaChecks::ON).unwrap_err();
    assert!(e.contains("chunk link broken"), "{e}");
    let out = aa_finalize(&proofs, &blocks, &fx.w.material(), off_aa(|s| s.links = false)).expect("accepted with `links` off");
    assert_ne!(out.digest, fx.aa(AaChecks::ON).unwrap().digest, "the digest of the broken chain is not the stream's");
}

#[test]
fn a11_chunk_0_not_starting_at_the_iv() {
    let fx = fx_two();
    let proofs = fx.rechain(0, fx.state_after_blocks(1), true); // chunk 0 proven with the AIR that has no IV rule
    let blocks = fx.blocks_for(&proofs, &fx.w.material());
    let e = aa_finalize(&proofs, &blocks, &fx.w.material(), AaChecks::ON).unwrap_err();
    assert!(e.contains("does not start at the IV"), "{e}");
    assert!(aa_finalize(&proofs, &blocks, &fx.w.material(), off_aa(|s| s.iv = false)).is_ok());
    // the AIR rule alone (explicit check off, proofs verified with the standard verifier) also rejects
    let proof = c1::from_bytes(&proofs[0].bytes).unwrap();
    assert!(chunk::plain::verify_chunk(&opts(), &proof, &proofs[0].stmt).is_err(), "the chunk-0 AIR rule R2b rejects a non-IV start");
}

#[test]
fn a12_aa_tag_list_differs_from_the_streams_in_one_record() {
    let fx = fx_two();
    let mut tags2 = fx.w.log.tags.clone();
    tags2[2500 * TAGS_PER_RECORD][0] ^= 1; // one record of chunk 1
    let m2 = AaMaterial { ids: &fx.w.ids, h_cts: &fx.w.log.h_cts, tags: &tags2 };
    let blocks = fx.blocks_for(&fx.proofs, &m2); // B' consistent with the AA's own material
    let e = aa_finalize(&fx.proofs, &blocks, &m2, AaChecks::ON).unwrap_err();
    assert!(e.contains("alpha differs"), "{e}");
    let e = aa_finalize(&fx.proofs, &blocks, &m2, off_aa(|s| s.d1b_alpha = false)).unwrap_err();
    assert!(e.contains("acc_"), "second check (acc) catches it: {e}");
    let e = aa_finalize(&fx.proofs, &blocks, &m2, off_aa(|s| s.d1b_acc = false)).unwrap_err();
    assert!(e.contains("alpha differs"), "{e}");
    assert!(aa_finalize(&fx.proofs, &blocks, &m2, off_aa(|s| {
        s.d1b_alpha = false;
        s.d1b_acc = false
    }))
    .is_ok());
}

#[test]
fn a13_chunk_proof_with_alpha_not_the_hash() {
    let fx = fx_two();
    // the AA's material differs from the stream in record 100 (a non-last record of chunk 0)
    let mut tags2 = fx.w.log.tags.clone();
    tags2[100 * TAGS_PER_RECORD][0] ^= 1;
    let m2 = AaMaterial { ids: &fx.w.ids, h_cts: &fx.w.log.h_cts, tags: &tags2 };
    // the CSP chooses alpha = 0: then acc = the tag slot of the LAST record only, which both lists agree on
    let mut proofs = fx.proofs.clone();
    let mut p = proofs[0].stmt.clone();
    let cw = fx.w.block_words(0, p.n_blocks_chunk);
    p.alpha = [0; 3];
    let tl = chunk::lists_of(cw);
    for t in 0..3 {
        p.acc[t] = acc_native::<c1::Val>(0, p.beta[t], p.n_blocks_chunk, BLOCK, &tl);
    }
    assert_eq!(p.acc[0], *tl.tags.last().unwrap());
    let proof = chunk::plain::prove_chunk(&opts(), cw, &p).unwrap();
    proofs[0] = ChunkProof::new(c1::to_bytes(&proof), p, tl);
    let blocks = fx.blocks_for(&proofs, &m2);
    let e = aa_finalize(&proofs, &blocks, &m2, AaChecks::ON).unwrap_err();
    assert!(e.contains("alpha differs"), "{e}");
    // with only the alpha check off the acc is consistent for alpha = 0 and the AA signs
    assert!(aa_finalize(&proofs, &blocks, &m2, off_aa(|s| s.d1b_alpha = false)).is_ok());
}

// ---------------------------------------------------------------------------------------------------------------
// v3 (D1c): the 64-bit tag-slot link and the header words
// ---------------------------------------------------------------------------------------------------------------

/// words of the honest stream with the header word of block `g0` (0-based) changed by `f`
fn stream_with_header(fx: &Fx, g0: usize, f: impl Fn(&mut Vec<u64>)) -> Vec<Vec<u64>> {
    let mut w = fx.w.words.clone();
    f(&mut w[g0 * (BLOCK + 1)]);
    w
}

/// a wrong seq_start_g in the header of block `g0` (0-based), with the block's records renumbered to match: the R_RC AIR ties header slot 4
/// to the first record's seq (K = (pid, e, seq_start - 1)), so a stream that R_RC proves has to be consistent in that way
fn stream_with_seq_start(fx: &Fx, g0: usize, delta: u64) -> Vec<Vec<u64>> {
    let mut w = fx.w.words.clone();
    w[g0 * (BLOCK + 1)][4] += delta;
    for i in 1..=BLOCK {
        w[g0 * (BLOCK + 1) + i][2] += delta;
    }
    w
}

/// ON refuses with `needle`; the second check (alpha switched off) still refuses through the accumulator ("acc_"), i.e. defence in depth;
/// with only the D1c header check off the AA signs.
fn a_header_attack(fx: &Fx, words: Vec<Vec<u64>>, needle: &str) {
    let proofs = fx.reprove_stream(&words);
    // the stream is internally consistent, so R_RC proves it and every proof verifies
    let mat = fx.w.material();
    let blocks = fx.blocks_for(&proofs, &mat);
    let e = aa_finalize(&proofs, &blocks, &mat, AaChecks::ON).unwrap_err();
    assert!(e.contains(needle), "{e}");
    // only the header check off: the AA signs
    let out = aa_finalize(&proofs, &blocks, &mat, off_aa(|s| s.d1c_hdr = false)).expect("accepted with the header check off");
    assert_eq!(out.g_e as usize, fx.w.g);
    // defence in depth: with alpha off the accumulator (beta, header terms) still refuses it
    let e = aa_finalize(&proofs, &blocks, &mat, off_aa(|s| s.d1b_alpha = false)).unwrap_err();
    assert!(e.contains("acc_"), "{e}");
}

#[test]
fn a14_tag_keywords_substituted_with_the_slot_collision_assumed() {
    let fx = fx_one();
    let tag = first_tag(&fx.f);
    // the attacker replaces the keyword tags of every hit record (ids 600..640, block 2) so that the query bits clear
    let mut tags2 = fx.w.log.tags.clone();
    for id in 600..640 {
        for t in 0..TAGS_PER_RECORD {
            tags2[id * TAGS_PER_RECORD + t][0] ^= 1;
        }
    }
    let m2 = AaMaterial { ids: &fx.w.ids, h_cts: &fx.w.log.h_cts, tags: &tags2 };
    let (ds2, _) = derive_slots(&m2);
    let pubs: Vec<_> = fx.proofs.iter().map(|p| p.stmt.clone()).collect();
    let sig = sigmas_from(&pubs, fx.w.g);
    let built: Vec<(Block35, Bloom35)> = (0..fx.w.g).map(|g0| build_block(&m2, &ds2, g0, sig[g0])).collect();
    let blocks: Vec<Block35> = built.iter().map(|b| b.0.clone()).collect();
    let blooms: Vec<Bloom35> = built.into_iter().map(|b| b.1).collect();
    assert!(!blooms[1].contains(&tag), "the forged filter of block 2 no longer holds the query tag");
    assert!(fx.w.blooms[1].contains(&tag));
    // all checks on: refused
    let e = aa_finalize(&fx.proofs, &blocks, &m2, AaChecks::ON).unwrap_err();
    assert!(e.contains("alpha differs"), "{e}");
    // the 2^64 capability: the forged keyword tags keep the stream's 64-bit slots (tag-slot check off). The D1c header check still refuses
    // (hd_g binds the whole descriptor, about 127 bits)
    let e = aa_finalize(&fx.proofs, &blocks, &m2, off_aa(|s| s.tag_slots = false)).unwrap_err();
    assert!(e.contains("alpha differs"), "{e}");
    let e = aa_finalize(&fx.proofs, &blocks, &m2, off_aa(|s| {
        s.tag_slots = false;
        s.d1b_alpha = false
    }))
    .unwrap_err();
    assert!(e.contains("acc_"), "defence in depth, the accumulator refuses too: {e}");
    // the header check off alone does not help the attacker (the slots of the forged records differ)
    assert!(aa_finalize(&fx.proofs, &blocks, &m2, off_aa(|s| s.d1c_hdr = false)).is_err());
    // both off: the AA signs and the requester gets a WRONG answer
    let out = aa_finalize(&fx.proofs, &blocks, &m2, off_aa(|s| {
        s.tag_slots = false;
        s.d1c_hdr = false
    }))
    .expect("accepted with the slot check and the header check off");
    let an = Anchor { r_e: out.r_e, n_e: out.n_e, g_e: out.g_e };
    let openings = openings_for_blocks(&blooms, &fx.f, 0..fx.w.g).expect("every forged filter shows the query absent");
    let resp = CspResponse { blocks, runs: vec![], openings, claim: (0, 0) };
    let (_, r) = verify_requester35(&an, &fx.f, &fx.auth, &resp, ON).expect("requester accepts the forged epoch");
    assert_eq!(r, (0, 0));
    assert_ne!(r, truth(&fx.records), "the hit records are missing from the answer");
}

#[test]
fn a15_wrong_seq_start_or_g_in_a_later_header() {
    let fx = fx_two();
    // header of block 3 (0-based 2), a later header of chunk 0 (c = 4): seq_start_g is wrong
    a_header_attack(fx, stream_with_seq_start(fx, 2, 7), "alpha differs");
    // the same header with a wrong g (slot 1)
    a_header_attack(fx, stream_with_header(fx, 2, |h| h[1] = 5), "alpha differs");
    // a later chunk, not at its first block either (chunk 2 = blocks 9-12, header of block 11)
    a_header_attack(fx, stream_with_seq_start(fx, 10, 1), "alpha differs");
    // the FIRST header of chunk 1 (block 5): the hdr_first meta check refuses it first; with meta off the D1c check does
    let proofs = fx.reprove_stream(&stream_with_seq_start(fx, 4, 7));
    let mat = fx.w.material();
    let blocks = fx.blocks_for(&proofs, &mat);
    let e = aa_finalize(&proofs, &blocks, &mat, AaChecks::ON).unwrap_err();
    assert!(e.contains("hdr_first"), "{e}");
    let e = aa_finalize(&proofs, &blocks, &mat, off_aa(|s| s.meta = false)).unwrap_err();
    assert!(e.contains("alpha differs"), "{e}");
    assert!(aa_finalize(&proofs, &blocks, &mat, off_aa(|s| {
        s.meta = false;
        s.d1c_hdr = false
    }))
    .is_ok());
}

#[test]
fn a16_header_slots_5_and_6_differ_from_hd_g() {
    let fx = fx_two();
    // hd_lo wrong, hd_hi wrong, both wrong (one later header of chunk 0, one of chunk 1)
    a_header_attack(fx, stream_with_header(fx, 2, |h| h[5] = (h[5] + 1) % pqz_plonky3_w36::data::GOLDILOCKS_P), "alpha differs");
    a_header_attack(fx, stream_with_header(fx, 6, |h| h[6] = (h[6] + 1) % pqz_plonky3_w36::data::GOLDILOCKS_P), "alpha differs");
    a_header_attack(fx, stream_with_header(fx, 3, |h| {
        h[5] = 0;
        h[6] = 0
    }), "alpha differs");
    // the first header of chunk 1: slots 5-6 are NOT compared by the meta check, only by D1c
    let proofs = fx.reprove_stream(&stream_with_header(fx, 4, |h| h[5] = (h[5] + 1) % pqz_plonky3_w36::data::GOLDILOCKS_P));
    let mat = fx.w.material();
    let blocks = fx.blocks_for(&proofs, &mat);
    let e = aa_finalize(&proofs, &blocks, &mat, AaChecks::ON).unwrap_err();
    assert!(e.contains("alpha differs"), "{e}");
    assert!(aa_finalize(&proofs, &blocks, &mat, off_aa(|s| s.d1c_hdr = false)).is_ok());
}
