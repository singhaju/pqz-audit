use bls12_381::{G1Affine, G1Projective, Scalar};
use ff::Field;
use pqz_bl_dart_par::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

const D: usize = 24;
const N: usize = 4;
const Z: usize = 5;

fn fixture() -> (Public, Node, [u8; 32], [u8; 32], ChaCha20Rng) {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let (p, n) = setup(Params { m: 10, n: N, d: D }, D, &mut rng);
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    rng.fill_bytes(&mut k1);
    rng.fill_bytes(&mut k2);
    (p, n, k1, k2, rng)
}

#[test]
fn honest_proof_passes_eq8_and_eq9() {
    let (p, n, k1, k2, _) = fixture();
    let prf = prove_nozk(&p, &n, &k1, &k2, Z, &mut Ops::default());
    let v = verify_nozk(&p, &prf, &k1, &k2, Z, &mut Ops::default());
    assert_eq!(v, Verdict { eq8: true, eq9: true, ok: true });
    // also z = |D| (D \ Lambda empty) and z = 1
    for z in [1, D] {
        let prf = prove_nozk(&p, &n, &k1, &k2, z, &mut Ops::default());
        assert!(verify_nozk(&p, &prf, &k1, &k2, z, &mut Ops::default()).ok, "z={z}");
    }
}

#[test]
fn tampered_chunk_fails() {
    let (p, mut n, k1, k2, _) = fixture();
    let lam = challenge_set(&k1, &k2, Z, D, &mut Ops::default());
    let i = lam[0].0;
    let chunk_bytes = N * 10 * BLOCK_BYTES;
    n.blocks[i * chunk_bytes + 3] ^= 1; // flip one bit of one block of a challenged chunk
    let prf = prove_nozk(&p, &n, &k1, &k2, Z, &mut Ops::default());
    let v = verify_nozk(&p, &prf, &k1, &k2, Z, &mut Ops::default());
    assert!(!v.ok);
    assert!(v.eq8, "tau untouched, so Eq. 8 still holds");
    assert!(!v.eq9, "wrong gamma_a must break Eq. 9");
    // a chunk that is NOT challenged does not matter
    let (p, mut n, k1, k2, _) = fixture();
    let out = (0..D).find(|j| lam.iter().all(|(i, _)| i != j)).unwrap();
    n.blocks[out * chunk_bytes] ^= 1;
    let prf = prove_nozk(&p, &n, &k1, &k2, Z, &mut Ops::default());
    assert!(verify_nozk(&p, &prf, &k1, &k2, Z, &mut Ops::default()).ok);
}

#[test]
fn tampered_tau_fails() {
    let (p, n, k1, k2, _) = fixture();
    let mut prf = prove_nozk(&p, &n, &k1, &k2, Z, &mut Ops::default());
    prf.tau[0] = G1Affine::from(G1Projective::from(prf.tau[0]) + G1Projective::generator());
    let v = verify_nozk(&p, &prf, &k1, &k2, Z, &mut Ops::default());
    assert!(!v.ok);
    assert!(!v.eq8 && !v.eq9);
}

#[test]
fn tampered_eta_gamma_and_wrong_challenge_fail() {
    let (p, n, k1, k2, mut rng) = fixture();
    let good = prove_nozk(&p, &n, &k1, &k2, Z, &mut Ops::default());
    let mut prf = prove_nozk(&p, &n, &k1, &k2, Z, &mut Ops::default());
    prf.eta = G1Affine::from(G1Projective::from(prf.eta) + G1Projective::generator());
    let v = verify_nozk(&p, &prf, &k1, &k2, Z, &mut Ops::default());
    assert!(!v.eq8 && v.eq9);
    let mut prf = prove_nozk(&p, &n, &k1, &k2, Z, &mut Ops::default());
    prf.gamma_a[1] += Scalar::ONE;
    let v = verify_nozk(&p, &prf, &k1, &k2, Z, &mut Ops::default());
    assert!(v.eq8 && !v.eq9);
    // proof for challenge A checked against challenge B
    let mut k2b = [0u8; 32];
    rng.fill_bytes(&mut k2b);
    assert!(!verify_nozk(&p, &good, &k1, &k2b, Z, &mut Ops::default()).eq9);
    // FINDING: k1 (the PRP key, i.e. WHICH chunks are challenged) is not used by any check of Algorithm 2 lines 10-15
    // (only alpha_i from k2 enter Eq. 9); the index binding must come from the ZKP, which is not run here.
    let mut k1b = [0u8; 32];
    rng.fill_bytes(&mut k1b);
    assert!(verify_nozk(&p, &good, &k1b, &k2, Z, &mut Ops::default()).ok);
}

#[test]
fn prp_is_a_permutation_and_expansion_is_right() {
    let mut ops = Ops::default();
    for n in [2u64, 3, 24, 37, 400] {
        let prp = Prp::new(&[9u8; 32], n);
        let mut seen = vec![false; n as usize];
        for x in 0..n {
            let y = prp.eval(x, &mut ops) as usize;
            assert!(!seen[y]);
            seen[y] = true;
        }
    }
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let cs: Vec<Scalar> = (0..9).map(|_| Scalar::random(&mut rng)).collect();
    let b = expand_product(&cs, &mut ops);
    assert_eq!(b.len(), 10);
    let x0 = Scalar::random(&mut rng);
    let direct = cs.iter().fold(Scalar::ONE, |a, c| a * (c + x0));
    let (mut sum, mut pw) = (Scalar::ZERO, Scalar::ONE);
    for bk in &b {
        sum += bk * pw;
        pw *= x0;
    }
    assert_eq!(direct, sum);
}

#[test]
fn op_counts_match_the_algorithms() {
    let (p, n, k1, k2, _) = fixture();
    let (mut po, mut vo) = (Ops::default(), Ops::default());
    let prf = prove_nozk(&p, &n, &k1, &k2, Z, &mut po);
    verify_nozk(&p, &prf, &k1, &k2, Z, &mut vo);
    // proofgen: eta_tau is |D|-z+1 exponentiations in G1; no pairing, no G2
    assert_eq!(po.g1_exp as usize, D - Z + 1);
    assert_eq!((po.g2_exp, po.pairing), (0, 0));
    // verify: 2 pairings; z+1 G2 exps (H_Lambda); N + z G1 exps (Omega_f line 14 and line 15)
    assert_eq!(vo.pairing, 2);
    assert_eq!(vo.g2_exp as usize, Z + 1);
    assert_eq!(vo.g1_exp as usize, N + Z);
    // schoolbook expansions: sum_{k=1}^{n} (k+1) field mults
    assert_eq!(vo.fr_mul as usize, (1..=Z).map(|k| k + 1).sum::<usize>());
}

// ---------------------------------------------------------------- SPEC-w16: matched coverage, prove_fast, verify_q

fn fixture_trap() -> (Public, Node, Trapdoor, ChaCha20Rng) {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let (p, n, t) = setup_with_trapdoor(Params { m: 10, n: 20, d: D }, D, &mut rng);
    (p, n, t, rng)
}

fn keys(rng: &mut ChaCha20Rng) -> ([u8; 32], [u8; 32]) {
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    rng.fill_bytes(&mut a);
    rng.fill_bytes(&mut b);
    (a, b)
}

#[test]
fn chunk_and_challenge_sizes_follow_the_spec() {
    // D = ceil(file_records / 200), z = max(1, ceil(cov / 200)), chunk = N*M = 200 blocks
    assert_eq!(chunks_for_records(1_000_000, 20, 10), 5000);
    assert_eq!(chunks_for_records(10_000, 20, 10), 50);
    assert_eq!(chunks_for_records(201, 20, 10), 2);
    assert_eq!(z_for_cov(100, 20, 10), 1);
    assert_eq!(z_for_cov(1000, 20, 10), 5);
    assert_eq!(z_for_cov(100_000, 20, 10), 500);
    assert_eq!(z_for_cov(201, 20, 10), 2);
}

#[test]
fn prove_fast_equals_prove_nozk() {
    let (p, n, t, mut rng) = fixture_trap();
    for z in [1usize, 3, D] {
        let (k1, k2) = keys(&mut rng);
        let a = prove_nozk(&p, &n, &k1, &k2, z, &mut Ops::default());
        let b = prove_fast(&p, &n, &t, &k1, &k2, z);
        assert_eq!(a.eta, b.eta, "z={z}");
        assert_eq!(a.tau, b.tau);
        assert_eq!(a.gamma_a, b.gamma_a);
    }
}

#[test]
fn verify_q_honest_passes_and_each_tamper_fails() {
    let (p, n, t, mut rng) = fixture_trap();
    let z = 3;
    let ks: Vec<_> = (0..4).map(|_| keys(&mut rng)).collect();
    let proofs: Vec<Prf> = ks.iter().map(|(a, b)| prove_fast(&p, &n, &t, a, b, z)).collect();
    // q different challenges -> different proofs
    assert!(proofs[0].gamma_a != proofs[1].gamma_a);
    let mut ops = Ops::default();
    assert!(verify_q(&p, &proofs, &ks, z, &mut ops));
    // cost is q times a single verification: 2 pairings each, z+1 G2 exps, N+z G1 exps
    assert_eq!(ops.pairing, 8);
    assert_eq!(ops.g2_exp as usize, 4 * (z + 1));
    assert_eq!(ops.g1_exp as usize, 4 * (20 + z));
    // tamper ONE proof of the four (flip gamma_a, eta, tau): the batch is rejected
    for which in 0..3 {
        let mut bad: Vec<Prf> = ks.iter().map(|(a, b)| prove_fast(&p, &n, &t, a, b, z)).collect();
        match which {
            0 => bad[2].gamma_a[0] += Scalar::ONE,
            1 => bad[3].eta = G1Affine::from(G1Projective::from(bad[3].eta) + G1Projective::generator()),
            _ => bad[1].tau[0] = G1Affine::from(G1Projective::from(bad[1].tau[0]) + G1Projective::generator()),
        }
        assert!(!verify_q(&p, &bad, &ks, z, &mut Ops::default()), "tamper {which}");
    }
    // a proof checked against another audit's challenge is rejected
    let mut swapped = ks.clone();
    swapped.swap(0, 1);
    assert!(!verify_q(&p, &proofs, &swapped, z, &mut Ops::default()));
}

#[test]
fn matched_coverage_stages_with_data_tamper() {
    // cov=600 -> z=3 on a file of 24 chunks: proofgen_nozk + verify_nozk honest passes; a flipped block in a challenged chunk fails
    let (p, mut n, t, mut rng) = fixture_trap();
    let z = z_for_cov(600, 20, 10);
    assert_eq!(z, 3);
    let (k1, k2) = keys(&mut rng);
    let prf = prove_nozk(&p, &n, &k1, &k2, z, &mut Ops::default());
    assert!(verify_nozk(&p, &prf, &k1, &k2, z, &mut Ops::default()).ok);
    let lam = challenge_set(&k1, &k2, z, D, &mut Ops::default());
    n.blocks[lam[1].0 * 20 * 10 * BLOCK_BYTES + 5] ^= 1;
    let prf = prove_nozk(&p, &n, &k1, &k2, z, &mut Ops::default());
    assert!(!verify_nozk(&p, &prf, &k1, &k2, z, &mut Ops::default()).ok);
    let _ = t;
}
