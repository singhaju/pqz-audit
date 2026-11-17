//! -par: the parallel functions give byte-identical outputs (tau, eta, gamma_a, verdicts, Ops counts, setup
//! values) to the original sequential functions (`*_seq`, kept verbatim in the library), for fixed seeds, at
//! 1, 2 and 7 rayon threads. Points are compared in compressed (canonical) encoding.
use bls12_381::{G1Affine, G1Projective, Scalar};
use ff::Field;
use pqz_bl_dart_par::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn pool<T: Send>(k: usize, f: impl FnOnce() -> T + Send) -> T {
    rayon::ThreadPoolBuilder::new().num_threads(k).build().unwrap().install(f)
}

fn g1b(v: &[G1Affine]) -> Vec<[u8; 48]> {
    v.iter().map(|p| p.to_compressed()).collect()
}
fn sb(v: &[Scalar]) -> Vec<[u8; 32]> {
    v.iter().map(|s| s.to_bytes()).collect()
}

fn keys(rng: &mut ChaCha20Rng) -> ([u8; 32], [u8; 32]) {
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    rng.fill_bytes(&mut k1);
    rng.fill_bytes(&mut k2);
    (k1, k2)
}

#[test]
fn setup_identical_to_sequential() {
    let p = Params { m: 10, n: 5, d: 37 };
    let zmax = 40; // > d: exercises the zmax > d branch of the original loop
    let mut r = ChaCha20Rng::seed_from_u64(99);
    let (a, b, t) = setup_with_trapdoor_seq(p, zmax, &mut r);
    let after_seq = r.next_u64();
    for k in [1usize, 2, 7] {
        let mut r2 = ChaCha20Rng::seed_from_u64(99);
        let (a2, b2, t2) = pool(k, || setup_with_trapdoor(p, zmax, &mut r2));
        assert_eq!(r2.next_u64(), after_seq, "rng stream position differs (k={k})");
        assert_eq!(g1b(&a.rho), g1b(&a2.rho));
        assert_eq!(g1b(&a.phi1), g1b(&a2.phi1));
        assert_eq!(a.phi2.iter().map(|x| x.to_compressed().to_vec()).collect::<Vec<_>>(),
                   a2.phi2.iter().map(|x| x.to_compressed().to_vec()).collect::<Vec<_>>());
        assert_eq!(a.s_auth.to_compressed(), a2.s_auth.to_compressed());
        assert_eq!(a.h.to_compressed(), a2.h.to_compressed());
        assert_eq!(b.blocks, b2.blocks);
        assert_eq!(g1b(&b.tau), g1b(&b2.tau));
        assert_eq!(sb(&b.c_tau), sb(&b2.c_tau));
        assert_eq!((t.zeta, t.s_v, t.p_all), (t2.zeta, t2.s_v, t2.p_all));
    }
}

#[test]
fn challenge_set_and_expand_identical() {
    let mut r = ChaCha20Rng::seed_from_u64(3);
    let (k1, k2) = keys(&mut r);
    for (z, d) in [(1usize, 5usize), (9, 9), (40, 700), (300, 1000)] {
        let mut os = Ops::default();
        let s = challenge_set_seq(&k1, &k2, z, d, &mut os);
        for k in [1usize, 2, 7] {
            let mut op = Ops::default();
            let p = pool(k, || challenge_set(&k1, &k2, z, d, &mut op));
            assert_eq!(s.iter().map(|(i, a)| (*i, a.to_bytes())).collect::<Vec<_>>(),
                       p.iter().map(|(i, a)| (*i, a.to_bytes())).collect::<Vec<_>>());
            assert_eq!(os, op);
        }
    }
    // expand_product: sizes below, at and above the leaf size and the polymul parallel threshold
    for n in [0usize, 1, 2, 17, 255, 256, 257, 600, 1500] {
        let cs: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut r)).collect();
        let mut os = Ops::default();
        let s = expand_product_seq(&cs, &mut os);
        for k in [1usize, 2, 7] {
            let mut op = Ops::default();
            let p = pool(k, || expand_product(&cs, &mut op));
            assert_eq!(sb(&s), sb(&p), "n={n} k={k}");
            assert_eq!(os, op, "logical op counts, n={n}");
        }
    }
}

#[test]
fn prove_verify_identical_to_sequential() {
    let mut r = ChaCha20Rng::seed_from_u64(7);
    let p = Params { m: 10, n: 4, d: 300 };
    let (pubp, node, trap) = setup_with_trapdoor_seq(p, 300, &mut r);
    for z in [1usize, 5, 40, 300] {
        let (k1, k2) = keys(&mut r);
        let mut os = Ops::default();
        let ps = prove_nozk_seq(&pubp, &node, &k1, &k2, z, &mut os);
        let mut ovs = Ops::default();
        let vs = verify_nozk_seq(&pubp, &ps, &k1, &k2, z, &mut ovs);
        assert!(vs.ok);
        let fs = prove_fast_seq(&pubp, &node, &trap, &k1, &k2, z);
        for k in [1usize, 2, 7] {
            let mut op = Ops::default();
            let pp = pool(k, || prove_nozk(&pubp, &node, &k1, &k2, z, &mut op));
            assert_eq!(g1b(&ps.tau), g1b(&pp.tau), "tau z={z} k={k}");
            assert_eq!(ps.eta.to_compressed(), pp.eta.to_compressed(), "eta z={z} k={k}");
            assert_eq!(sb(&ps.gamma_a), sb(&pp.gamma_a), "gamma_a z={z} k={k}");
            assert_eq!(os, op, "prove ops z={z}");
            let mut ovp = Ops::default();
            let vp = pool(k, || verify_nozk(&pubp, &pp, &k1, &k2, z, &mut ovp));
            assert_eq!(vs, vp);
            assert_eq!(ovs, ovp, "verify ops z={z}");
            let ff = pool(k, || prove_fast(&pubp, &node, &trap, &k1, &k2, z));
            assert_eq!(g1b(&fs.tau), g1b(&ff.tau));
            assert_eq!(fs.eta.to_compressed(), ff.eta.to_compressed());
            assert_eq!(sb(&fs.gamma_a), sb(&ff.gamma_a));
            // tampered proofs are rejected the same way
            let mut bad = Prf { tau: pp.tau.clone(), eta: pp.eta, gamma_a: pp.gamma_a.clone() };
            bad.tau[0] = G1Affine::from(G1Projective::from(bad.tau[0]) + G1Projective::generator());
            let a = verify_nozk_seq(&pubp, &bad, &k1, &k2, z, &mut Ops::default());
            let b = pool(k, || verify_nozk(&pubp, &bad, &k1, &k2, z, &mut Ops::default()));
            assert_eq!(a, b);
            assert!(!b.ok);
            let mut bad = Prf { tau: pp.tau.clone(), eta: pp.eta, gamma_a: pp.gamma_a.clone() };
            bad.gamma_a[1] += Scalar::ONE;
            let a = verify_nozk_seq(&pubp, &bad, &k1, &k2, z, &mut Ops::default());
            let b = pool(k, || verify_nozk(&pubp, &bad, &k1, &k2, z, &mut Ops::default()));
            assert_eq!(a, b);
            assert!(!b.ok && b.eq8 && !b.eq9);
        }
    }
}

#[test]
fn verify_q_identical_to_sequential() {
    let mut r = ChaCha20Rng::seed_from_u64(11);
    let p = Params { m: 10, n: 4, d: 120 };
    let (pubp, node, trap) = setup_with_trapdoor_seq(p, 120, &mut r);
    let z = 12;
    let mut ks = Vec::new();
    let mut prfs = Vec::new();
    for _ in 0..9 {
        let k = keys(&mut r);
        prfs.push(prove_fast_seq(&pubp, &node, &trap, &k.0, &k.1, z));
        ks.push(k);
    }
    let mut os = Ops::default();
    assert!(verify_q_seq(&pubp, &prfs, &ks, z, &mut os));
    for t in [1usize, 2, 7] {
        let mut op = Ops::default();
        assert!(pool(t, || verify_q(&pubp, &prfs, &ks, z, &mut op)));
        assert_eq!(os, op);
    }
    // one bad audit among q: both reject
    prfs[4].gamma_a[0] += Scalar::ONE;
    assert!(!verify_q_seq(&pubp, &prfs, &ks, z, &mut Ops::default()));
    assert!(!pool(7, || verify_q(&pubp, &prfs, &ks, z, &mut Ops::default())));
}
