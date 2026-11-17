//! R_CoverM tests (DESIGN.md section 8): honest instance accepted; every forged witness, trace or public input rejected.
//! Each forged case changes ONE thing and builds the rest honestly; a control shows the same instance is accepted when the
//! forged item is legal (so the rejection comes from the named constraint).
//! Release only (as tests/cover.rs): in a debug build winterfell requires the declared degree to equal the measured degree.
#![cfg(not(debug_assertions))]

use pqz_proof::auth::{root_of, PolicyLeaf, DOM_LEAF};
use pqz_proof::cover::{flag_digest, K};
use pqz_proof::covermerkle::*;
use pqz_proof::data::{chain_digest, Rng};
use pqz_proof::prove::prove_trace;
use pqz_proof::rescue::{perm, F, W};
use winterfell::math::FieldElement;
use winterfell::Trace;

const G: usize = 10;
const R: usize = 4;

fn inst() -> CoverMInstance {
    CoverMInstance::honest(G, R, 5)
}

fn not_accepted(trace: winterfell::TraceTable<F>, p: CoverMPublic) -> bool {
    match prove_trace::<CoverMAir>(trace, p.clone(), options()) {
        Err(_) => {
            eprintln!("path: prover refused");
            true
        }
        Ok(proof) => {
            let r = verify_covermerkle(proof, p);
            eprintln!("path: verifier said {:?}", r);
            r.is_err()
        }
    }
}

fn accepted(i: &CoverMInstance) -> bool {
    !not_accepted(build_trace(i), covermerkle_public(i))
}

/// A fresh summary of 6,740 limbs with the given probed bits, its tree opened at the probe leaves.
fn witness_with_bits(i: &CoverMInstance, seed: u64, bits: [bool; K], flag: bool) -> BlockWitness {
    let mut rng = Rng::new(seed);
    let l = synth_limbs(&mut rng, &i.positions, &bits);
    BlockWitness::from_limbs(&l, &i.positions, flag)
}

fn first_pruned(i: &CoverMInstance) -> usize {
    i.blocks.iter().position(|b| !b.flag).unwrap()
}
fn first_retained(i: &CoverMInstance) -> usize {
    i.blocks.iter().position(|b| b.flag).unwrap()
}

#[test]
fn covermerkle_honest_accepted() {
    let i = inst();
    assert_eq!(i.retained(), R);
    let (proof, p) = prove_covermerkle(&i, options()).unwrap();
    assert_eq!((p.g, p.k, p.r), (G, 7, R));
    verify_covermerkle(proof, p).unwrap();
}

#[test]
fn covermerkle_honest_edge_cases_accepted() {
    // all pruned, all retained, a single block, sizes that need padding blocks
    for (g, r) in [(1, 0), (1, 1), (4, 0), (4, 4), (7, 3), (33, 9)] {
        assert!(accepted(&CoverMInstance::honest(g, r, 9)), "g={g} r={r} rejected");
    }
}

#[test]
fn covermerkle_instance_shape() {
    // the synthetic content follows the rule it claims: retained = all probed bits 1, pruned = at least one 0, roots distinct
    let i = inst();
    let mut roots = std::collections::HashSet::new();
    for b in &i.blocks {
        let ones = (0..K).filter(|&j| b.probed_bit(&i.positions, j)).count();
        if b.flag {
            assert_eq!(ones, K);
        } else {
            assert!(ones < K);
        }
        assert!(roots.insert(format!("{:?}", b.root)));
    }
    assert!(i.positions.iter().all(|&p| p < NBITS));
}

#[test]
fn covermerkle_reference_digests_match_library() {
    let i = inst();
    let p = covermerkle_public(&i);
    assert_eq!(p.d_s, chain_digest(&chain_words(&i, &Forge::default())));
    assert_eq!(p.d_flags, flag_digest(&i.flags()));
}

#[test]
fn covermerkle_merkle_compression_equals_r_auth() {
    // my 2-to-1 compression and path folding equal auth::root_of (auth's leaf hash is private: replicate it here, as the
    // test of the shared merge only needs the same leaf digest on both sides)
    let leaf = PolicyLeaf { uid: 1, v_a: 2, s: (3, 4), e: (5, 6), t: (7, 8), p: (9, 10), level: 11, blind: 12 };
    let p = leaf.to_p();
    let mut s = [F::ZERO; W];
    s[0] = F::new(DOM_LEAF);
    s[4..12].copy_from_slice(&p[..8]);
    perm(&mut s);
    for j in 0..4 {
        s[4 + j] += p[8 + j];
    }
    perm(&mut s);
    let ld = [s[4], s[5], s[6], s[7]];
    let mut rng = Rng::new(3);
    let sibs: Vec<[F; 4]> = (0..DEPTH).map(|_| [F::new(rng.next_u64() >> 8), F::new(rng.next_u64() >> 8), F::new(5), F::new(6)]).collect();
    for idx in [0usize, 1, 5, 4095, 8191] {
        assert_eq!(fold_path(ld, idx, &sibs), root_of(&leaf, idx as u64, &sibs));
    }
}

#[test]
fn covermerkle_tree_open_matches_root() {
    let i = inst();
    let idx = leaf_indices(&i.positions);
    for b in i.blocks.iter().take(4).chain(std::iter::once(&i.pad)) {
        for j in 0..K {
            assert_eq!(fold_path(leaf_digest(b.limbs[j]), idx[j], &b.sibs[j]), b.root);
        }
    }
}

#[test]
fn covermerkle_pruned_block_with_all_probed_bits_one_rejected() {
    let i = inst();
    let b = first_pruned(&i);
    // the forged block is a fully valid Merkle opening (honest tree, honest decomposition); only PruneValid is violated
    let mut f = i.clone();
    f.blocks[b] = witness_with_bits(&i, 77, [true; K], false);
    assert!(not_accepted(build_trace(&f), covermerkle_public(&f)), "pruned block with all probed bits 1 was accepted");
    // control: the same summary kept (f = 1) is accepted when the counts are recomputed
    let mut c = i.clone();
    c.blocks[b] = witness_with_bits(&i, 77, [true; K], true);
    assert!(accepted(&c));
}

#[test]
fn covermerkle_pruned_block_with_exactly_one_zero_accepted() {
    // the paper's rule: one zero among the k probed bits is enough (R_Cover needed all k zero)
    let i = inst();
    let b = first_pruned(&i);
    for z in 0..K {
        let mut f = i.clone();
        let mut bits = [true; K];
        bits[z] = false;
        f.blocks[b] = witness_with_bits(&i, 100 + z as u64, bits, false);
        assert!(accepted(&f), "exactly one zero at probe {z} rejected");
    }
    // also five zeros of seven, and all seven zeros
    let mut f = i.clone();
    f.blocks[b] = witness_with_bits(&i, 200, [false, true, false, false, true, false, false], false);
    assert!(accepted(&f));
    f.blocks[b] = witness_with_bits(&i, 201, [false; K], false);
    assert!(accepted(&f));
}

#[test]
fn covermerkle_wrong_merkle_path_rejected() {
    let i = inst();
    for (b, j, lvl) in [(0usize, 0usize, 0usize), (3, 3, 6), (5, 6, 12), (9, 2, 1)] {
        let mut f = i.clone();
        f.blocks[b].sibs[j][lvl][0] += F::ONE;
        assert!(not_accepted(build_trace(&f), covermerkle_public(&f)), "sibling change at b={b} j={j} level={lvl} accepted");
    }
}

#[test]
fn covermerkle_limb_not_matching_root_rejected() {
    let i = inst();
    let b = first_retained(&i);
    for j in [0usize, 4] {
        // flip a bit of the opened limb that is NOT a probed bit of this block's probe (the limb no longer matches the leaf of the root)
        let mut f = i.clone();
        let bit = (i.positions[j] % LIMB_BITS + 1) % LIMB_BITS;
        f.blocks[b].limbs[j] ^= 1u64 << bit;
        assert!(not_accepted(build_trace(&f), covermerkle_public(&f)), "changed limb accepted (probe {j})");
    }
}

#[test]
fn covermerkle_decomposition_bits_not_matching_limb_rejected() {
    // trace-level forgery: pruned all-ones block whose probed BD bit is set to 0 in the decomposition only
    let i = inst();
    let b = first_pruned(&i);
    let mut f = i.clone();
    f.blocks[b] = witness_with_bits(&i, 77, [true; K], false);
    let p = covermerkle_public(&f);
    let mut trace = build_trace(&f);
    let t = f.positions[2] % LIMB_BITS;
    let from_msb = LIMB_BITS - 1 - t;
    let row = BLOCK_ROWS * b + 8 * (3 + 14 * 2) + from_msb / 4;
    let col = pqz_proof::covermerkle::C_BD + from_msb % 4;
    assert_eq!(trace.get(col, row), F::ONE);
    trace.set(col, row, F::ZERO);
    assert!(not_accepted(trace, p), "decomposition bit not tied to the limb");
}

#[test]
fn covermerkle_forged_product_column_rejected() {
    let i = inst();
    let b = first_pruned(&i);
    let mut f = i.clone();
    f.blocks[b] = witness_with_bits(&i, 77, [true; K], false);
    let p = covermerkle_public(&f);
    let mut trace = build_trace(&f);
    for r in 1..BLOCK_ROWS {
        trace.set(C_PR, BLOCK_ROWS * b + r, F::ZERO);
    }
    assert!(not_accepted(trace, p));
}

#[test]
fn covermerkle_leaf_from_another_position_rejected() {
    // a valid opening of the neighbouring leaf (index ^ 1) presented for the probe position
    let i = inst();
    let b = first_retained(&i);
    let mut rng = Rng::new(8);
    let l = synth_limbs(&mut rng, &i.positions, &[true; K]);
    let t = Tree::build(&l);
    let idx = leaf_indices(&i.positions);
    // control: the right indices
    let mut c = i.clone();
    c.blocks[b] = BlockWitness::open(&Patched::none(&t), &idx, true);
    assert!(accepted(&c));
    for j in [0usize, 5] {
        let mut alt = idx;
        alt[j] ^= 1;
        let mut f = i.clone();
        f.blocks[b] = BlockWitness::open(&Patched::none(&t), &alt, true);
        assert!(not_accepted(build_trace(&f), covermerkle_public(&f)), "opening of leaf index^1 accepted (probe {j})");
    }
}

#[test]
fn covermerkle_dropped_block_rejected() {
    let i = inst();
    let p = covermerkle_public(&i);
    let mut f = i.clone();
    f.blocks.remove(4);
    f.g = G - 1;
    // (a) public input of the full chain (G, D_S, r, D_flags of the original)
    assert!(not_accepted(build_trace(&f), p.clone()));
    // (b) digests recomputed from the shorter chain, but G still claimed
    let pf = covermerkle_public(&f);
    let q = CoverMPublic { g: G, ..pf.clone() };
    assert!(not_accepted(build_trace(&f), q));
    // (c) control: the shorter instance with its own G is accepted
    assert!(accepted(&f));
}

#[test]
fn covermerkle_repeated_block_index_rejected() {
    let i = inst();
    // block 4 absorbs the index of block 3 (4) instead of 5; public D_S computed from that forged chain
    let forge = Forge { header_override: Some((4, 4)) };
    let mut p = covermerkle_public(&i);
    p.d_s = chain_digest(&chain_words(&i, &forge));
    assert!(not_accepted(build_trace_forged(&i, &forge), p.clone()));
    // the counter column also repeats (GG = 4 from block 4 on), so only the step at the block boundary is wrong
    let mut trace = build_trace_forged(&i, &forge);
    for b in 4..trace.length() / BLOCK_ROWS {
        for r in 0..BLOCK_ROWS {
            trace.set(C_GG, BLOCK_ROWS * b + r, F::new(b as u64));
        }
    }
    assert!(not_accepted(trace, p));
}

#[test]
fn covermerkle_wrong_r_rejected() {
    let i = inst();
    for r in [R - 1, R + 1, 0, G] {
        let mut p = covermerkle_public(&i);
        p.r = r;
        assert!(not_accepted(build_trace(&i), p), "r = {r} accepted");
    }
}

#[test]
fn covermerkle_wrong_flag_vector_rejected() {
    let i = inst();
    let b = first_pruned(&i);
    // (a) one flag flipped (pruned -> retained is always PruneValid-legal), public values of the original
    let mut f = i.clone();
    f.blocks[b].flag = true;
    assert!(not_accepted(build_trace(&f), covermerkle_public(&i)));
    // (b) D_flags recomputed, r not
    let mut p = covermerkle_public(&f);
    p.r = R;
    assert!(not_accepted(build_trace(&f), p));
    // (c) r recomputed, D_flags not
    let mut p = covermerkle_public(&f);
    p.d_flags = flag_digest(&i.flags());
    assert!(not_accepted(build_trace(&f), p));
    // control: everything recomputed is accepted
    assert!(accepted(&f));
}

#[test]
fn covermerkle_modified_root_rejected() {
    let i = inst();
    let mut f = i.clone();
    f.blocks[2].root[1] += F::ONE;
    // (a) original public D_S
    assert!(not_accepted(build_trace(&f), covermerkle_public(&i)));
    // (b) D_S recomputed over the modified root, paths unchanged: the path no longer ends at the root
    assert!(not_accepted(build_trace(&f), covermerkle_public(&f)));
    // (c) trace-level: the chain absorbs the original root but the M column (used for the path) holds another one
    let mut trace = build_trace(&i);
    for r in 0..BLOCK_ROWS {
        let v = trace.get(C_M, BLOCK_ROWS * 2 + r);
        trace.set(C_M, BLOCK_ROWS * 2 + r, v + F::ONE);
    }
    assert!(not_accepted(trace, covermerkle_public(&i)));
}

#[test]
fn covermerkle_wrong_public_inputs_rejected() {
    let i = inst();
    let honest = covermerkle_public(&i);
    let mut p = honest.clone();
    p.d_s[0] += F::ONE;
    assert!(not_accepted(build_trace(&i), p));
    let mut p = honest.clone();
    p.d_flags[3] += F::ONE;
    assert!(not_accepted(build_trace(&i), p));
    let mut p = honest.clone();
    p.g = G + 1;
    assert!(not_accepted(build_trace(&i), p));
    let mut p = honest.clone();
    p.g = G - 1;
    assert!(not_accepted(build_trace(&i), p));
    let mut p = honest.clone();
    p.k = K - 1;
    assert!(not_accepted(build_trace(&i), p));
    // another probed limb (leaf index changes): the openings no longer fit the public positions
    let mut p = honest.clone();
    p.positions[0] ^= 1 << 5;
    assert!(not_accepted(build_trace(&i), p));
}

#[test]
fn covermerkle_non_boolean_flag_rejected() {
    let i = inst();
    let mut trace = build_trace(&i);
    let b = first_retained(&i);
    for r in 0..BLOCK_ROWS {
        trace.set(C_F, BLOCK_ROWS * b + r, F::new(2));
    }
    assert!(not_accepted(trace, covermerkle_public(&i)));
}
