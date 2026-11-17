//! The honest gates of DESIGN section 7 (release mode: `cargo test --release --offline`).
//! Clustered / scattered data, empty and all-retained results, c in {1, 4, 16} with G not a multiple of c, gap_merge 0 and 1,
//! result = plain reference, chunked digest = one-proof digest.
mod common;
use common::*;
use pqz_eval::r#gen::r#gen;
use pqz_eval::Layout;
use pqz_integrated_w46::w35::*;
use pqz_integrated_w46::*;
use pqz_plonky3_w36::chunk;

fn one_proof_digest(words: &[Vec<u64>]) -> Vec<u64> {
    pqz_plonky3_w36::rel::plain::rc_public(words, BLOCK).digest.to_vec()
}

fn check_honest(fx: &Fx, records: &[pqz_eval::Record]) {
    let t = truth(records);
    let out = fx.aa(AaChecks::ON).expect("AA accepts the honest epoch");
    // chunked digest == w33 one-proof digest == independent reference chain
    let one = one_proof_digest(&fx.w.words);
    assert_eq!(out.digest.to_vec(), one, "chunked digest = one-proof digest (c = {})", fx.w.c);
    assert_eq!(one, ref_chain_digest(&fx.w.log.wl.words));
    assert_eq!(out.r_e, fx.w.r_e);
    assert_eq!((out.n_e, out.g_e), (fx.w.n as u64, fx.w.g as u64));
    for gm in [0usize, 1] {
        let resp = fx.honest(gm);
        let (_tm, res) = fx.full(&resp, ReqChecks::ON).unwrap_or_else(|e| panic!("honest rejected (c={}, gm={gm}): {}", fx.w.c, e.msg));
        assert_eq!(res, t, "result = plain reference (c={}, gm={gm})", fx.w.c);
        assert_eq!(resp.claim, t);
        // every run is whole chunks, ordered and disjoint
        let mut prev = 0;
        for r in &resp.runs {
            assert!(r.first > prev && r.first <= r.last);
            prev = r.last;
        }
        if t.0 == 0 && fx.flags.iter().all(|&f| !f) {
            assert!(resp.runs.is_empty());
        }
    }
}

#[test]
fn chunked_digest_equals_one_proof_digest_native_for_c_1_4_16() {
    for (n, rs_seed) in [(6500usize, 1u64), (20000, 2)] {
        let rs = r#gen(n, 30, Layout::Scattered, DEFAULT_SEED + rs_seed);
        let keys = pqz_eval::eapat::EpochKeys::from_seed(DEFAULT_SEED);
        let log = build_log(&rs, &keys);
        let words = pqz_plonky3_w36::c1::words(&log.wl);
        let one = one_proof_digest(&words);
        let g = n / BLOCK;
        for c in [1usize, 4, 16] {
            let (pubs, _) = chunk::plain::honest_publics(&words, BLOCK, c);
            assert_eq!(pubs.len(), g.div_ceil(c));
            for k in 1..pubs.len() {
                assert_eq!(pubs[k].s_in, pubs[k - 1].s_out);
            }
            assert_eq!(pubs[0].s_in, chunk::iv_state(words.len() as u64));
            assert_eq!(chunk::plain::digest_of(&pubs.last().unwrap().s_out).to_vec(), one, "n={n} c={c}");
        }
        assert!(g % 16 != 0, "G = {g} is not a multiple of 16");
        if g == 13 {
            assert!(g % 4 != 0, "G = 13 is not a multiple of 4");
        }
    }
}

#[test]
fn honest_c1_c4_c16_clustered_and_scattered_g13() {
    for layout in [Layout::Clustered, Layout::Scattered] {
        let sigma = if layout == Layout::Clustered { 60 } else { 4 };
        for c in [1usize, 4, 16] {
            let seed = DEFAULT_SEED + 3;
            let rs = r#gen(6500, sigma, layout, seed);
            let fx = Fx::new(rs.clone(), c, seed);
            assert_eq!(fx.w.plan.len(), 13usize.div_ceil(c));
            check_honest(&fx, &rs);
        }
    }
}

#[test]
fn honest_g40_c16_chunks_16_16_8() {
    let seed = DEFAULT_SEED + 5;
    let rs = r#gen(20000, 50, Layout::Clustered, seed);
    let fx = Fx::new(rs.clone(), 16, seed);
    let sizes: Vec<usize> = fx.w.plan.iter().map(|p| p.n_blocks).collect();
    assert_eq!(sizes, vec![16, 16, 8]);
    check_honest(&fx, &rs);
}

#[test]
fn empty_result_has_no_run_and_gives_zero_zero() {
    // a seed with no Bloom false positive: every block pruned, zero runs
    for k in 0..40u64 {
        let seed = DEFAULT_SEED + 100 + k;
        let rs = r#gen(6500, 0, Layout::Clustered, seed);
        let fx = Fx::new(rs.clone(), 4, seed);
        if fx.flags.iter().any(|&f| f) {
            continue;
        }
        for gm in [0usize, 1] {
            let resp = fx.honest(gm);
            assert!(resp.runs.is_empty());
            assert_eq!(resp.claim, (0, 0));
            assert_eq!(resp.openings.len(), 13);
            let (_, res) = fx.full(&resp, ReqChecks::ON).expect("empty result accepted");
            assert_eq!(res, (0, 0));
        }
        assert_eq!(truth(&rs), (0, 0));
        return;
    }
    panic!("no seed without a false positive");
}

#[test]
fn all_blocks_retained_one_run_covers_everything() {
    let seed = DEFAULT_SEED + 7;
    let rs = r#gen(6500, 6500, Layout::Clustered, seed);
    for c in [4usize, 16] {
        let fx = Fx::new(rs.clone(), c, seed);
        assert!(fx.flags.iter().all(|&f| f));
        for gm in [0usize, 1] {
            let resp = fx.honest(gm);
            assert_eq!(resp.runs.len(), 1);
            assert_eq!((resp.runs[0].first, resp.runs[0].last), (1, 13));
            assert!(resp.openings.is_empty());
            let (_, res) = fx.full(&resp, ReqChecks::ON).expect("accepted");
            assert_eq!(res, truth(&rs));
            assert_eq!(res.0, 6500);
        }
    }
}

#[test]
fn gap_merge_0_and_1_run_counts_and_same_result() {
    let fx = fx_two(); // hits in chunk 0 and chunk 2, chunk 1 between them
    assert_eq!(fx.ranges(0), vec![(0, 0), (2, 2)]);
    assert_eq!(fx.ranges(1), vec![(0, 2)]);
    let t = truth(&fx.records);
    let r0 = fx.honest(0);
    let r1 = fx.honest(1);
    assert_eq!(r0.runs.len(), 2);
    assert_eq!(r1.runs.len(), 1);
    let blocks_proven = |r: &CspResponse| r.runs.iter().map(|x| x.last - x.first + 1).sum::<usize>();
    assert_eq!(blocks_proven(&r0), 8);
    assert_eq!(blocks_proven(&r1), 12);
    for r in [&r0, &r1] {
        let (_, res) = fx.full(r, ReqChecks::ON).expect("accepted");
        assert_eq!(res, t);
    }
    // the merged run has fewer openings (the unflagged chunk 1 is proven instead of opened)
    assert!(r1.openings.len() < r0.openings.len());
}

#[test]
fn plan_runs_unit() {
    let plan = chunk::plan_chunks(10, 2); // 5 chunks
    let mut fl = vec![false; 10];
    assert!(plan_runs(&fl, &plan, 1).is_empty());
    fl[0] = true;
    fl[9] = true;
    assert_eq!(plan_runs(&fl, &plan, 0), vec![(0, 0), (4, 4)]);
    assert_eq!(plan_runs(&fl, &plan, 2), vec![(0, 0), (4, 4)]);
    assert_eq!(plan_runs(&fl, &plan, 3), vec![(0, 4)]);
    fl[4] = true; // chunk 2
    assert_eq!(plan_runs(&fl, &plan, 1), vec![(0, 4)]);
    assert_eq!(plan_runs(&fl, &plan, 0), vec![(0, 0), (2, 2), (4, 4)]);
}

#[test]
fn zero_runs_give_zero_zero_even_with_claim_checks_on() {
    // zero runs, honest openings for every block impossible if a block holds the query: so use the empty fixture of a seed without false positive
    for k in 0..40u64 {
        let seed = DEFAULT_SEED + 300 + k;
        let rs = r#gen(6500, 0, Layout::Scattered, seed);
        let fx = Fx::new(rs, 16, seed);
        if fx.flags.iter().any(|&f| f) {
            continue;
        }
        let resp = fx.honest(1);
        assert_eq!(requester_native35(&fx.an, &fx.f, &resp, ReqChecks::ON), Ok((0, 0)));
        return;
    }
    panic!("no seed");
}

#[test]
fn requester_bytes_and_times_are_reported() {
    let fx = fx_two();
    let resp = fx.honest(1);
    let (tm, _) = fx.full(&resp, ReqChecks::ON).unwrap();
    assert!(tm.native_s >= 0.0 && tm.auth_s > 0.0 && tm.runs_s > 0.0);
    assert!(requester_bytes(&resp, &fx.auth) > resp.runs_bytes() + resp.block_list_bytes());
}
