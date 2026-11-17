//! work39 tests of the Groth16 step (identical file in dart-zk and dart-zk-par).
use ark_bn254::Fr;
use ark_ff::{One, Zero};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use pqz_bl_dart_par::zk::*;
use pqz_bl_dart_par::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

const D: usize = 24;
const N: usize = 3;
const M: usize = 10;
const Z: usize = 3;

struct Fx {
    p: Public,
    node: Node,
    ctx: ZkCtx,
    k1: [u8; 32],
    k2: [u8; 32],
    lam: Vec<(usize, bls12_381::Scalar)>,
    rng: ChaCha20Rng,
}

fn fixture() -> Fx {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let (p, node) = setup(Params { m: M, n: N, d: D }, D, &mut rng);
    let ctx = zk_setup(Z, N, M, &mut rng);
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    rng.fill_bytes(&mut k1);
    rng.fill_bytes(&mut k2);
    let lam = challenge_set(&k1, &k2, Z, D, &mut Ops::default());
    Fx { p, node, ctx, k1, k2, lam, rng }
}

fn satisfied(ctx: &ZkCtx, inp: &ZkInput) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    DartLocCircuit { z: ctx.z, n: ctx.n, m: ctx.m, pos: ctx.pos.clone(), blocks: Some(&inp.blocks), alphas: Some(&inp.alphas), gamma: Some(&inp.gamma) }
        .generate_constraints(cs.clone())
        .unwrap();
    cs.is_satisfied().unwrap()
}

#[test]
fn constraint_count_is_as_specified() {
    let f = fixture();
    // per (i,j): 8 full rounds x 11 S-boxes x 3 + 66 partial x 3 + 1 (alpha * H); plus N sums
    let per = RF * (M + 1) * 3 + RP * 3 + 1;
    assert_eq!(f.ctx.constraints, Z * N * per + N);
    assert_eq!(f.ctx.public_inputs, Z + N);
    assert_eq!(f.ctx.witness_vars, Z * N * (M + RF * (M + 1) * 3 + RP * 3 + 1));
}

#[test]
fn honest_zk_proof_verifies_and_circuit_matches_native_hash() {
    let mut f = fixture();
    let inp = zk_prepare(&f.ctx, &f.p.p, &f.node, &f.lam);
    assert!(satisfied(&f.ctx, &inp), "circuit and native Poseidon disagree");
    let pi = zk_prove(&f.ctx, &inp, &mut f.rng);
    assert!(zk_verify(&f.ctx, &inp.alphas, &inp.gamma, &pi));
    // full verify_zk path: Eq. 8/9 + Groth16
    let prf = prove_nozk(&f.p, &f.node, &f.k1, &f.k2, Z, &mut Ops::default());
    assert!(verify_nozk(&f.p, &prf, &f.k1, &f.k2, Z, &mut Ops::default()).ok);
}

#[test]
fn tampered_block_makes_verify_fail() {
    let mut f = fixture();
    let inp = zk_prepare(&f.ctx, &f.p.p, &f.node, &f.lam); // public values from the ORIGINAL data
    // the node now holds a tampered block in a challenged chunk and proves with it
    let i = f.lam[0].0;
    f.node.blocks[i * N * M * BLOCK_BYTES + 5] ^= 1;
    let bad = zk_prepare(&f.ctx, &f.p.p, &f.node, &f.lam);
    assert_ne!(bad.blocks, inp.blocks);
    let forged = ZkInput { blocks: bad.blocks.clone(), alphas: inp.alphas.clone(), gamma: inp.gamma.clone() };
    assert!(!satisfied(&f.ctx, &forged));
    let pi = zk_prove(&f.ctx, &forged, &mut f.rng); // proof for an unsatisfied witness
    assert!(!zk_verify(&f.ctx, &inp.alphas, &inp.gamma, &pi), "tampered block accepted");
    // an honest-looking proof of the tampered data has a different gamma than the committed one
    let pi2 = zk_prove(&f.ctx, &bad, &mut f.rng);
    assert!(zk_verify(&f.ctx, &bad.alphas, &bad.gamma, &pi2));
    assert!(!zk_verify(&f.ctx, &inp.alphas, &inp.gamma, &pi2), "proof for other gamma accepted");
}

#[test]
fn tampered_commitment_or_alpha_makes_verify_fail() {
    let mut f = fixture();
    let inp = zk_prepare(&f.ctx, &f.p.p, &f.node, &f.lam);
    let pi = zk_prove(&f.ctx, &inp, &mut f.rng);
    let mut g = inp.gamma.clone();
    g[1] += Fr::one();
    assert!(!zk_verify(&f.ctx, &inp.alphas, &g, &pi), "tampered gamma_a accepted");
    let mut a = inp.alphas.clone();
    a[0] += Fr::one();
    assert!(!zk_verify(&f.ctx, &a, &inp.gamma, &pi), "tampered alpha accepted");
    // a commitment that does not match the witness (gamma_a[0] replaced, proof built for it) is unsatisfiable
    let mut forged = inp.clone();
    forged.gamma[0] = Fr::zero();
    assert!(!satisfied(&f.ctx, &forged));
    let pi3 = zk_prove(&f.ctx, &forged, &mut f.rng);
    assert!(!zk_verify(&f.ctx, &forged.alphas, &forged.gamma, &pi3), "forged commitment accepted");
    // wrong number of public inputs
    assert!(!zk_verify(&f.ctx, &inp.alphas[..Z - 1], &inp.gamma, &pi));
}
