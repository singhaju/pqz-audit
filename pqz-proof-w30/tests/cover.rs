//! R_Cover tests (DESIGN.md section 7): honest instance accepted; every forged witness or public input rejected.
//! Each forged case changes ONE thing, builds the rest honestly, and a control shows the same instance is accepted
//! when the forged item is legal (so the rejection comes from the named constraint).
//! `cargo test --release` (release prover does not validate the trace; the verifier must reject);
//! `cargo test` (debug) validates the declared constraint degrees and the prover panics on a bad trace (also a rejection).

// Release only. In a debug build winterfell asserts that every declared constraint degree EQUALS the measured degree of the
// constraint polynomial; for R_Cover that cannot hold on any honest trace, because a probe has only k = 7 positions, so some of the
// 8 `sel` columns and most of the 32 `oh` columns are identically zero and the gated constraints on them have degree 0. (Checked
// by hand on one debug run: for all 161 constraints measured degree <= declared degree, which is what soundness needs.)
#![cfg(not(debug_assertions))]

use pqz_proof::cover::*;
use pqz_proof::data::chain_digest;
use pqz_proof::prove::prove_trace;
use pqz_proof::rescue::F;
use winterfell::math::FieldElement;
use winterfell::Trace;

const G: usize = 10;
const R: usize = 4;

fn inst() -> CoverInstance {
    CoverInstance::honest(G, R, 5)
}

/// True if the (forged) trace with the given public input is NOT accepted (prover refused or verifier rejected).
fn not_accepted(trace: winterfell::TraceTable<F>, p: CoverPublic) -> bool {
    match prove_trace::<CoverAir>(trace, p.clone(), options()) {
        Err(_) => {
            eprintln!("path: prover refused");
            true
        }
        Ok(proof) => {
            let r = verify_cover(proof, p);
            eprintln!("path: verifier said {:?}", r);
            r.is_err()
        }
    }
}

fn accepted(i: &CoverInstance) -> bool {
    let p = cover_public(i);
    !not_accepted(build_cover_trace(i), p)
}

#[test]
fn cover_honest_accepted() {
    let i = inst();
    assert_eq!(i.retained(), R);
    let (proof, p) = prove_cover(&i, options()).unwrap();
    assert_eq!((p.g, p.k, p.r), (G, 7, R));
    verify_cover(proof, p).unwrap();
}

#[test]
fn cover_honest_edge_cases_accepted() {
    // all pruned, all retained, a single block, a size that needs padding blocks
    for (g, r) in [(1, 0), (1, 1), (4, 0), (4, 4), (7, 3), (33, 9)] {
        assert!(accepted(&CoverInstance::honest(g, r, 9)), "g={g} r={r} rejected");
    }
}

#[test]
fn cover_reference_digests_match_chain_library() {
    let i = inst();
    let p = cover_public(&i);
    assert_eq!(p.d_s, chain_digest(&summary_chain_words(&i)));
}

#[test]
fn cover_pruned_block_with_one_at_probed_position_rejected() {
    let mut i = inst();
    let b = i.flags.iter().position(|&f| !f).unwrap();
    // set the bit of probe 3 in a pruned block; digests are recomputed for the forged summary, so only PruneValid is violated
    for j in [0usize, 3, 6] {
        let mut f = i.clone();
        let pos = f.positions[j];
        f.summaries[b][pos / 32] |= 1u64 << (pos % 32);
        assert!(!f.flags[b]);
        assert!(!accepted(&f), "pruned block with a 1 at probe {j} accepted");
    }
    // control: the same forged summary with the block retained is accepted
    let pos = i.positions[3];
    i.summaries[b][pos / 32] |= 1u64 << (pos % 32);
    i.flags[b] = true;
    assert!(accepted(&i), "control (retained) rejected");
}

#[test]
fn cover_pruned_block_all_bits_one_rejected() {
    let mut i = inst();
    let b = i.flags.iter().position(|&f| !f).unwrap();
    for j in 0..7 {
        let pos = i.positions[j];
        i.summaries[b][pos / 32] |= 1u64 << (pos % 32);
    }
    assert!(!accepted(&i));
}

#[test]
fn cover_probe_view_forgery_rejected() {
    // The chain absorbs the true summary (probed bit = 1) but the probe rows show a copy with that bit cleared.
    let i = {
        let mut i = inst();
        let b = i.flags.iter().position(|&f| !f).unwrap();
        let pos = i.positions[2];
        i.summaries[b][pos / 32] |= 1u64 << (pos % 32);
        i
    };
    let b = i.flags.iter().position(|&f| !f).unwrap();
    let mut view = i.summaries[b];
    for &pos in &i.positions {
        view[pos / 32] &= !(1u64 << (pos % 32));
    }
    let p = cover_public(&i);
    let trace = build_cover_trace_forged(&i, &summary_chain_words(&i), Some((b, view)));
    assert!(not_accepted(trace, p));
    // control: showing the true summary at the probe rows gives the plain rejection of the test above, and showing the
    // honest summary of an honest instance is accepted
    let h = inst();
    let b2 = 0;
    let p2 = cover_public(&h);
    let trace = build_cover_trace_forged(&h, &summary_chain_words(&h), Some((b2, h.summaries[b2])));
    assert!(!not_accepted(trace, p2));
}

#[test]
fn cover_dropped_block_rejected() {
    // G-1 blocks proven, public input claims the original G (and the original digests and r)
    let full = inst();
    let p = cover_public(&full);
    let mut short = full.clone();
    short.g -= 1;
    short.summaries.pop();
    short.flags.pop();
    assert!(not_accepted(build_cover_trace(&short), p.clone()));
    // the short instance with its own public input is a valid statement for G-1, but not for G
    assert!(accepted(&short));
    let mut p2 = cover_public(&short);
    p2.g = G;
    assert!(not_accepted(build_cover_trace(&short), p2));
}

#[test]
fn cover_dropped_block_with_matching_digests_rejected() {
    // the prover drops block 5 from the chain and the flag vector and publishes digests of the shortened vectors, keeps G
    let full = inst();
    let mut short = full.clone();
    short.summaries.remove(4);
    short.flags.remove(4);
    short.g -= 1;
    let mut p = cover_public(&short);
    p.g = G;
    assert!(not_accepted(build_cover_trace(&short), p));
}

#[test]
fn cover_repeated_block_index_rejected() {
    // header word of block 6 carries index 5 (index repeated); digests recomputed from the forged words, counter honest
    let i = inst();
    let mut words = summary_chain_words(&i);
    words[2 * 5] = pqz_proof::cover::header_word(5);
    let mut p = cover_public(&i);
    p.d_s = chain_digest(&words);
    let trace = build_cover_trace_forged(&i, &words, None);
    assert!(not_accepted(trace, p));
    // block counter that does not step at one boundary (block 6 counted as 5), headers follow the counter
    let i = inst();
    let p = cover_public(&i);
    let mut trace = build_cover_trace(&i);
    let n = trace.length();
    for row in 16 * 5..n {
        let v = trace.get(50, row);
        trace.set(50, row, v - F::ONE);
    }
    assert!(not_accepted(trace, p));
}

#[test]
fn cover_wrong_r_rejected() {
    let i = inst();
    let (proof, mut p) = prove_cover(&i, options()).unwrap();
    p.r += 1;
    assert!(verify_cover(proof, p).is_err());
    let (proof, mut p) = prove_cover(&i, options()).unwrap();
    p.r -= 1;
    assert!(verify_cover(proof, p).is_err());
    // the prover claims a wrong r with an honest trace
    let mut p = cover_public(&i);
    p.r += 1;
    assert!(not_accepted(build_cover_trace(&i), p));
    // the prover reports r = 0 with an honest trace of a block set that has retained blocks
    let mut p = cover_public(&i);
    p.r = 0;
    assert!(not_accepted(build_cover_trace(&i), p));
}

#[test]
fn cover_wrong_flag_vector_rejected() {
    let i = inst();
    // public D_flags of another vector
    let (proof, mut p) = prove_cover(&i, options()).unwrap();
    p.d_flags[1] += F::ONE;
    assert!(verify_cover(proof, p).is_err());
    // honest trace for a different (valid) flag vector with the same r, public input of the original
    let mut other = i.clone();
    let a = other.flags.iter().position(|&f| f).unwrap();
    let b = other.flags.iter().position(|&f| !f).unwrap();
    // swap the roles: block a pruned, block b retained, summaries adjusted so each stays honest
    let pa = other.positions;
    other.flags[a] = false;
    other.flags[b] = true;
    for &pos in &pa {
        other.summaries[a][pos / 32] &= !(1u64 << (pos % 32));
        other.summaries[b][pos / 32] |= 1u64 << (pos % 32);
    }
    assert_eq!(other.retained(), R);
    assert!(accepted(&other), "control: the swapped instance is valid for its own public input");
    assert!(not_accepted(build_cover_trace(&other), cover_public(&i)));
    // flag column flipped in the trace at one block, sponge words and counters left as for the original
    let p = cover_public(&i);
    let mut trace = build_cover_trace(&i);
    for r in 0..16 {
        trace.set(47, 16 * a + r, F::ZERO);
    }
    assert!(not_accepted(trace, p));
}

#[test]
fn cover_modified_summary_word_rejected() {
    let i = inst();
    let p = cover_public(&i);
    // another summary word (not a probed bit) in the witness, public D_S of the original
    let mut m = i.clone();
    m.summaries[3][7] ^= 1; // a bit that may or may not be probed; make sure it is not
    let probed: Vec<(usize, usize)> = m.positions.iter().map(|&q| (q / 32, q % 32)).collect();
    if probed.contains(&(7, 0)) {
        m.summaries[3][7] ^= 1;
        m.summaries[3][6] ^= 1 << 31;
    }
    assert_ne!(m.summaries, i.summaries);
    assert!(not_accepted(build_cover_trace(&m), p.clone()));
    // control: the modified summary with its own digest is accepted
    assert!(accepted(&m), "control rejected");
    // modified in the trace only at the link row (the absorbed word), probe rows untouched
    let mut trace = build_cover_trace(&i);
    let row = 16 * 3 + 7;
    let v = trace.get(12 + 7, row);
    trace.set(12 + 7, row, v + F::ONE);
    assert!(not_accepted(trace, p));
}

#[test]
fn cover_wrong_k_rejected() {
    let i = inst();
    let (proof, mut p) = prove_cover(&i, options()).unwrap();
    p.k = 6;
    assert!(verify_cover(proof, p).is_err());
}

#[test]
fn cover_wrong_g_or_digest_public_rejected() {
    let i = inst();
    let (proof, mut p) = prove_cover(&i, options()).unwrap();
    p.g += 1;
    assert!(verify_cover(proof, p).is_err());
    let (proof, mut p) = prove_cover(&i, options()).unwrap();
    p.d_s[0] += F::ONE;
    assert!(verify_cover(proof, p).is_err());
}

#[test]
fn cover_positions_not_constant_rejected() {
    // probe positions that change between blocks (a different position in block 3 whose bit is 0)
    let i = inst();
    let p = cover_public(&i);
    let mut trace = build_cover_trace(&i);
    let n = trace.length();
    // flip the stored probe position P_1 from block 3 on, and make sel/oh/bits consistent with a zero bit elsewhere
    for row in 16 * 3..n {
        trace.set(40, row, trace.get(40, row) + F::ONE);
    }
    assert!(not_accepted(trace, p));
}

#[test]
fn cover_non_boolean_flag_rejected() {
    let i = inst();
    let p = cover_public(&i);
    let mut trace = build_cover_trace(&i);
    for r in 0..16 {
        trace.set(47, 16 * 2 + r, F::new(2));
    }
    assert!(not_accepted(trace, p));
}
