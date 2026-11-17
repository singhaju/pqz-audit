//! w46: P2r (packed) arm of the w35 driver: honest end-to-end runs (equal to the old arm and the plain reference), the honest fixtures of
//! `w35_honest.rs` in the packed format, and the P2r-specific tamper tests (chunk proof, sigma, run statement, format mixing, v range).
//! The attacks A1-A16 of the old suite are repeated in `w46_p2r_attacks.rs`. Release mode only: `cargo test --release --offline`.
mod common;
use common::*;
use pqz_eval::r#gen::r#gen;
use pqz_eval::Layout;
use pqz_integrated_w46::w35::*;
use pqz_integrated_w46::*;
use pqz_plonky3_w36::{c1, chunk, pair, pchunk, prun};

const RPB: usize = 1 + (BLOCK + 1) / 2;
const P2R: WFmt = WFmt::P2r;

fn aa(fx: &Fx, proofs: &[ChunkProof], blocks: &[Block35], sw: AaChecks) -> Result<AaOut, String> {
    aa_finalize_fmt(proofs, blocks, &fx.w.material(), sw, P2R)
}

fn all_req_off() -> ReqChecks {
    ReqChecks { block_list: false, run_shape: false, states: false, hdr_first: false, prune: false, open_path: false, claim: false }
}

// ---------------------------------------------------------------------------------------------------------------
// honest end to end (the CLI child function)
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn run_one35_p2r_equals_old_and_the_plain_reference_n5000_n10000() {
    for n in [5000usize, 10000] {
        for layout in [Layout::Clustered, Layout::Scattered] {
            let old = run_one35_fmt(n, layout, DEFAULT_SEED, 4, 1, WFmt::Old).unwrap_or_else(|e| panic!("old {n} {layout:?}: {}", e.msg));
            let new = run_one35_fmt(n, layout, DEFAULT_SEED, 4, 1, P2R).unwrap_or_else(|e| panic!("p2r {n} {layout:?}: {}", e.msg));
            // run_one35 compares the result with the plain reference inside its gates; here old = p2r
            assert_eq!(old.result, new.result, "(count, sum) n={n} {layout:?}");
            assert_eq!(new.fmt, P2R);
            assert_eq!((old.runs, old.blocks_proven, old.r_retained), (new.runs, new.blocks_proven, new.r_retained));
            // the packed stream has fewer rows
            assert!(new.rc.rows < old.rc.rows, "rc rows {} vs {}", new.rc.rows, old.rc.rows);
            assert!(new.result.0 > 0, "non-empty result");
        }
    }
}

#[test]
fn run_one35_default_fmt_is_the_old_arm() {
    let a = run_one35(5000, Layout::Clustered, DEFAULT_SEED, 4, 1).unwrap();
    assert_eq!(a.fmt, WFmt::Old);
    assert_eq!(WFmt::default(), WFmt::Old);
    assert_eq!(WFmt::parse("old"), Some(WFmt::Old));
    assert_eq!(WFmt::parse("p2r"), Some(WFmt::P2r));
    assert_eq!(WFmt::parse("x"), None);
}

// ---------------------------------------------------------------------------------------------------------------
// honest fixtures in the packed format
// ---------------------------------------------------------------------------------------------------------------

fn check_honest_p(fx: &Fx, records: &[pqz_eval::Record]) {
    let t = truth(records);
    let out = fx.aa(AaChecks::ON).expect("AA accepts the honest packed epoch");
    // chunked digest == one-chunk digest of the packed stream == independent packed reference chain
    let (one, _) = pchunk::plain::honest_publics(&fx.w.words, BLOCK, fx.w.g);
    assert_eq!(one.len(), 1);
    assert_eq!(out.digest, [one[0].s_out[0], one[0].s_out[1], one[0].s_out[2], one[0].s_out[3]], "c = {}", fx.w.c);
    assert_eq!(out.digest.to_vec(), ref_chain_digest_packed(&fx.w.words));
    assert_eq!(out.r_e, fx.w.r_e);
    for gm in [0usize, 1] {
        let resp = fx.honest(gm);
        let (_tm, res) = fx.full(&resp, ReqChecks::ON).unwrap_or_else(|e| panic!("honest rejected (c={}, gm={gm}): {}", fx.w.c, e.msg));
        assert_eq!(res, t, "result = plain reference (c={}, gm={gm})", fx.w.c);
        assert_eq!(resp.claim, t);
    }
}

#[test]
fn p2r_honest_c1_c4_c16_clustered_and_scattered_g13() {
    for layout in [Layout::Clustered, Layout::Scattered] {
        let sigma = if layout == Layout::Clustered { 60 } else { 4 };
        for c in [1usize, 4, 16] {
            let seed = DEFAULT_SEED + 3;
            let rs = r#gen(6500, sigma, layout, seed);
            let fx = Fx::new_fmt(rs.clone(), c, seed, P2R);
            assert_eq!(fx.w.plan.len(), 13usize.div_ceil(c));
            assert_eq!(fx.w.words.len(), 13 * RPB, "packed rows per block");
            check_honest_p(&fx, &rs);
        }
    }
}

#[test]
fn p2r_honest_empty_result_and_all_retained() {
    for k in 0..40u64 {
        let seed = DEFAULT_SEED + 100 + k;
        let rs = r#gen(6500, 0, Layout::Clustered, seed);
        let fx = Fx::new_fmt(rs.clone(), 4, seed, P2R);
        if fx.flags.iter().any(|&f| f) {
            continue;
        }
        let resp = fx.honest(1);
        assert!(resp.runs.is_empty());
        assert_eq!(fx.full(&resp, ReqChecks::ON).expect("empty result accepted").1, (0, 0));
        break;
    }
    let seed = DEFAULT_SEED + 7;
    let rs = r#gen(6500, 6500, Layout::Clustered, seed);
    let fx = Fx::new_fmt(rs.clone(), 4, seed, P2R);
    let resp = fx.honest(1);
    assert_eq!(resp.runs.len(), 1);
    assert_eq!(fx.full(&resp, ReqChecks::ON).expect("accepted").1, truth(&rs));
}

#[test]
fn p2r_gap_merge_0_and_1() {
    let fx = fx_two_p();
    assert_eq!(fx.ranges(0), vec![(0, 0), (2, 2)]);
    assert_eq!(fx.ranges(1), vec![(0, 2)]);
    let t = truth(&fx.records);
    for gm in [0usize, 1] {
        assert_eq!(fx.full(&fx.honest(gm), ReqChecks::ON).unwrap().1, t);
    }
}

// ---------------------------------------------------------------------------------------------------------------
// P2r-specific tampering
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn p2r_tampered_chunk_proof_bytes_are_refused_by_the_aa() {
    let fx = fx_two_p();
    for j in [0usize, 1, 3] {
        let mut proofs = fx.proofs.clone();
        let n = proofs[j].bytes.len();
        proofs[j].bytes[n / 2] ^= 1;
        let e = aa(fx, &proofs, &fx.w.blocks, AaChecks::ON).unwrap_err();
        assert!(e.contains("proof"), "chunk {j}: {e}");
        // with only the proof check off the same material passes: the proof check is the one that refuses it
        let mut sw = AaChecks::ON;
        sw.proofs = false;
        assert!(aa(fx, &proofs, &fx.w.blocks, sw).is_ok());
    }
}

#[test]
fn p2r_chunk_statement_changed_after_proving_is_refused() {
    let fx = fx_two_p();
    // (a) s_out changed: the proof no longer verifies against the statement (and alpha/beta would differ as well)
    let mut proofs = fx.proofs.clone();
    proofs[1].stmt.s_out[0] ^= 1;
    let e = aa(fx, &proofs, &fx.w.blocks, AaChecks::ON).unwrap_err();
    assert!(e.contains("link broken") || e.contains("proof"), "{e}");
    // (b) acc changed
    let mut proofs = fx.proofs.clone();
    proofs[2].stmt.acc[0] ^= 1;
    let e = aa(fx, &proofs, &fx.w.blocks, AaChecks::ON).unwrap_err();
    assert!(e.contains("proof rejected"), "{e}");
    let mut sw = AaChecks::ON;
    sw.proofs = false;
    assert!(aa(fx, &proofs, &fx.w.blocks, sw).unwrap_err().contains("acc_0"), "second check: the AA's own accumulator");
    // (c) total_words of the OLD format (g * (B + 1)): meta refuses
    let mut proofs = fx.proofs.clone();
    for p in proofs.iter_mut() {
        p.stmt.total_words = fx.w.g * (BLOCK + 1);
    }
    let e = aa(fx, &proofs, &fx.w.blocks, AaChecks::ON).unwrap_err();
    assert!(e.contains("total_words"), "{e}");
}

#[test]
fn p2r_wrong_sigma_in_the_block_list() {
    let fx = fx_two_p();
    // sigma changed at a chunk end
    let mut blocks = fx.w.blocks.clone();
    let mut s = blocks[3].sigma.unwrap();
    s[0] ^= 1;
    blocks[3].sigma = Some(s);
    let e = aa(fx, &fx.proofs, &blocks, AaChecks::ON).unwrap_err();
    assert!(e.contains("sigma"), "{e}");
    let mut sw = AaChecks::ON;
    sw.sigma = false;
    assert!(aa(fx, &fx.proofs, &blocks, sw).is_ok(), "accepted with only the sigma check off: that check is the one that refuses it");
    // sigma missing at a chunk end / present in the middle of a chunk
    let mut blocks = fx.w.blocks.clone();
    blocks[7].sigma = None;
    assert!(aa(fx, &fx.proofs, &blocks, AaChecks::ON).unwrap_err().contains("sigma"));
    let mut blocks = fx.w.blocks.clone();
    blocks[1].sigma = Some([1; 12]);
    assert!(aa(fx, &fx.proofs, &blocks, AaChecks::ON).unwrap_err().contains("sigma"));
}

#[test]
fn p2r_run_statement_count_sum_hdr_and_proof_tampered() {
    let fx = fx_one_p();
    // wrong count (claim made consistent so only the proof can refuse it)
    let mut resp = fx.honest(0);
    resp.runs[0].stmt.count += 1;
    resp.claim.0 += 1;
    let e = fx.full(&resp, ReqChecks::ON).unwrap_err();
    assert!(e.msg.contains("R_Exec verifier rejected"), "{}", e.msg);
    // wrong sum
    let mut resp = fx.honest(0);
    resp.runs[0].stmt.sum += 3;
    resp.claim.1 += 3;
    let e = fx.full(&resp, ReqChecks::ON).unwrap_err();
    assert!(e.msg.contains("R_Exec verifier rejected"), "{}", e.msg);
    // wrong run count without fixing the claim: the claim check refuses first, the proof second
    let mut resp = fx.honest(0);
    resp.runs[0].stmt.count += 1;
    assert!(fx.full(&resp, ReqChecks::ON).unwrap_err().msg.contains("claimed result"));
    let mut sw = ReqChecks::ON;
    sw.claim = false;
    assert!(fx.full(&resp, sw).unwrap_err().msg.contains("R_Exec verifier rejected"));
    // run proof bytes flipped
    let mut resp = fx.honest(0);
    let n = resp.runs[0].proof.len();
    resp.runs[0].proof[n / 3] ^= 1;
    let e = fx.full(&resp, ReqChecks::ON).unwrap_err();
    assert!(e.msg.contains("R_Exec"), "{}", e.msg);
    // run theta changed
    let mut resp = fx.honest(0);
    resp.runs[0].stmt.theta += 1;
    assert!(fx.full(&resp, ReqChecks::ON).unwrap_err().msg.contains("theta"));
    // hdr_first
    let mut resp = fx.honest(0);
    resp.runs[0].stmt.hdr_first[1] ^= 1;
    assert!(fx.full(&resp, ReqChecks::ON).unwrap_err().msg.contains("hdr_first"));
    // n_blocks of the run statement
    let mut resp = fx.honest(0);
    resp.runs[0].stmt.n_blocks += 1;
    assert!(fx.full(&resp, ReqChecks::ON).unwrap_err().msg.contains("n_blocks"));
    // ctx of another request
    let mut resp = fx.honest(0);
    resp.runs[0].stmt.ctx[0] ^= 1;
    assert!(fx.full(&resp, ReqChecks::ON).is_err());
}

#[test]
fn p2r_run_statement_built_over_old_words_does_not_verify_as_p2r() {
    let fx = fx_one_p();
    // the OLD (one record per word) stream of the same log, and a run proof of the OLD run AIR over blocks 1..4 from the P2r IV
    let old_words = c1::words(&fx.w.log.wl);
    let iv_p2r = chunk::iv_state((fx.w.g * RPB) as u64);
    let cl = prove_run_over_fmt(&old_words[0..4 * (BLOCK + 1)], &iv_p2r, 1, 4, fx.ctx, THETA, WFmt::Old).unwrap();
    // (a) the P2r verifier rejects the old proof under the old statement
    let proof = c1::from_bytes(&cl.proof).unwrap();
    assert!(prun::plain::verify_run(&opts(), &proof, &cl.stmt).is_err(), "prun must not accept an old-format run proof");
    // (b) in the requester: native checks refuse it (s_out is the state after the OLD words, not the anchored sigma)
    let mut resp = fx.honest(0);
    resp.claim = (cl.stmt.count, cl.stmt.sum);
    resp.runs = vec![cl.clone()];
    resp.openings = fx.openings_except(&{
        let mut c = vec![false; fx.w.g];
        c[..4].iter_mut().for_each(|x| *x = true);
        c
    }, &[]);
    let e = fx.full(&resp, ReqChecks::ON).unwrap_err();
    assert!(e.msg.contains("s_out is not the anchored state") || e.msg.contains("n_blocks"), "{}", e.msg);
    // (c) with every native check off, the proof check alone refuses it
    let e = fx.full(&resp, all_req_off()).unwrap_err();
    assert!(e.msg.contains("R_Exec verifier rejected"), "{}", e.msg);
    // (d) and an honest P2r run proof does not verify under the OLD verifier
    let good = fx.honest(0);
    let gp = c1::from_bytes(&good.runs[0].proof).unwrap();
    assert!(pqz_plonky3_w36::run::plain::verify_run(&opts(), &gp, &good.runs[0].stmt).is_err());
}

#[test]
fn p2r_chunk_proofs_and_the_aa_do_not_mix_with_the_old_format() {
    let fx = fx_one_p();
    // packed chunk proofs to the AA of the old format
    let e = aa_finalize_fmt(&fx.proofs, &fx.w.blocks, &fx.w.material(), AaChecks::ON, WFmt::Old).unwrap_err();
    assert!(e.contains("total_words") || e.contains("IV") || e.contains("proof"), "{e}");
    // the requester of the old format on a packed response: s_in of the first run is not the old IV
    let resp = fx.honest(0);
    let e = verify_requester35_fmt(&fx.an, &fx.f, &fx.auth, &resp, ReqChecks::ON, WFmt::Old).unwrap_err();
    assert!(e.msg.contains("s_in is not the anchored state"), "{}", e.msg);
    // an old-format chunk (old words) against the packed verifier
    let old_fx = fx_one();
    let e = aa_finalize_fmt(&old_fx.proofs, &old_fx.w.blocks, &old_fx.w.material(), AaChecks::ON, P2R).unwrap_err();
    assert!(e.contains("total_words") || e.contains("IV") || e.contains("proof"), "{e}");
}

#[test]
fn p2r_v_above_2_pow_32_cannot_be_proven_by_the_packed_chunk() {
    // The run AIR (prun) has no range check of v; v < 2^32 comes from the packed chunk proofs. A stream with v = 2^32 + 5 must therefore
    // have no verifying chunk proof.
    let fx = fx_one_p();
    let mut words = fx.w.words.clone();
    words[1][1] = (1u64 << 32) + 5; // v_a of the first record of block 1
    let (pubs, _lists) = pchunk::plain::honest_publics(&words, BLOCK, 4);
    let cw = &words[0..4 * RPB];
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pchunk::plain::prove_chunk(&opts(), cw, &pubs[0])));
    match r {
        Err(_) => {} // the prover refused (constraint failed while proving)
        Ok(Err(_)) => {}
        Ok(Ok(proof)) => assert!(pchunk::plain::verify_chunk(&opts(), &proof, &pubs[0]).is_err(), "a chunk proof of v >= 2^32 verified"),
    }
    // same for b >= 2^20 (v_b / b_a slot 2)
    let mut words = fx.w.words.clone();
    words[1][2] = 1u64 << 20;
    let (pubs, _l) = pchunk::plain::honest_publics(&words, BLOCK, 4);
    let cw = &words[0..4 * RPB];
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pchunk::plain::prove_chunk(&opts(), cw, &pubs[0])));
    match r {
        Err(_) => {}
        Ok(Err(_)) => {}
        Ok(Ok(proof)) => assert!(pchunk::plain::verify_chunk(&opts(), &proof, &pubs[0]).is_err(), "a chunk proof of b >= 2^20 verified"),
    }
}

#[test]
fn p2r_packed_words_are_what_pack_raw_gives() {
    let fx = fx_one_p();
    assert_eq!(fx.w.words, pair::pack_raw(&fx.w.log.wl.words, BLOCK));
    assert_eq!(fx.w.words.len(), fx.w.g * RPB);
    assert_eq!(fx.w.block_words(2, 3).len(), 3 * RPB);
}
