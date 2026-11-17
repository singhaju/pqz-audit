use crate::audit::*;
use crate::circuits::*;
use crate::mimc::Mimc;
use crate::ring::*;
use ark_bn254::{Bn254, Fr};
use ark_ff::{One, UniformRand};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::sync::Arc;

#[test]
fn primes_and_q() {
    let ps = find_ntt_primes(4096, 54, 2);
    assert!(ps.iter().all(|&p| is_prime(p) && (p - 1) % 8192 == 0 && p < (1 << 54)));
    let q = ps[0] as u128 * ps[1] as u128;
    assert_eq!(128 - q.leading_zeros(), 108);
}

#[test]
fn ntt_matches_schoolbook_negacyclic() {
    let n = 32;
    let p = find_ntt_primes(n, 54, 1)[0];
    let pr = Prime::new(p, n);
    let mut rng = StdRng::seed_from_u64(1);
    let a: Vec<u64> = (0..n).map(|_| rng.gen_range(0..p)).collect();
    let b: Vec<u64> = (0..n).map(|_| rng.gen_range(0..p)).collect();
    let mut want = vec![0u64; n];
    for i in 0..n {
        for j in 0..n {
            let v = mul_mod(a[i], b[j], p);
            let k = i + j;
            if k < n {
                want[k] = (want[k] + v) % p;
            } else {
                want[k - n] = (want[k - n] + p - v) % p;
            }
        }
    }
    assert_eq!(pr.poly_mul(&a, &b), want);
    let mut x = a.clone();
    pr.ntt_fwd(&mut x);
    pr.ntt_inv(&mut x);
    assert_eq!(x, a);
}

#[test]
fn decryption_returns_the_encrypted_message() {
    let mut rng = StdRng::seed_from_u64(2);
    let (ctx, insts) = AuditCtx::setup(&mut rng, 4, 3);
    assert_eq!(ctx.params.n, 4096);
    assert_eq!(ctx.params.log_q(), 108);
    for inst in &insts {
        let pt = ctx.params.decrypt(&ctx.sk, &inst.ct);
        assert_eq!(pt, inst.plain, "all 4096 plaintext coefficients must decrypt exactly");
        assert_eq!(inst.ct.bytes(), 131072);
    }
}

#[test]
fn wrong_secret_key_does_not_decrypt() {
    let mut rng = StdRng::seed_from_u64(3);
    let (ctx, insts) = AuditCtx::setup(&mut rng, 0, 1);
    let (sk2, _) = ctx.params.keygen(&mut rng);
    let pt = ctx.params.decrypt(&sk2, &insts[0].ct);
    assert_ne!(pt, insts[0].plain);
}

#[test]
fn audit_accepts_honest_and_rejects_wrong_cm() {
    let mut rng = StdRng::seed_from_u64(4);
    let (ctx, insts) = AuditCtx::setup(&mut rng, 8, 2);
    let i = &insts[0];
    assert_eq!(ctx.audit(&i.tx_id, &i.ct, &i.cm_g, &i.r_shared), Ok(i.m));
    let bad = i.cm_g + Fr::one();
    assert_eq!(ctx.audit(&i.tx_id, &i.ct, &bad, &i.r_shared), Err(AuditError::VerificationFailed));
    let bad_r = i.r_shared + Fr::one();
    assert_eq!(ctx.audit(&i.tx_id, &i.ct, &i.cm_g, &bad_r), Err(AuditError::VerificationFailed));
    // ciphertext of another transaction under the same txId: message differs -> cm differs
    let j = &insts[1];
    assert_eq!(ctx.audit(&i.tx_id, &j.ct, &i.cm_g, &i.r_shared), Err(AuditError::VerificationFailed));
    // cache miss path is not implemented
    assert_eq!(ctx.audit(&[7u8; 32], &i.ct, &i.cm_g, &i.r_shared), Err(AuditError::CacheMiss));
}

#[test]
fn mimc_is_deterministic_and_input_sensitive() {
    let m = Mimc::new();
    assert_eq!(m.c.len(), 110);
    let a = m.hash(&[Fr::from(1u64), Fr::from(2u64)]);
    assert_eq!(a, m.hash(&[Fr::from(1u64), Fr::from(2u64)]));
    assert_ne!(a, m.hash(&[Fr::from(2u64), Fr::from(1u64)]));
    assert_ne!(a, m.hash(&[Fr::from(1u64), Fr::from(3u64)]));
}

#[test]
fn circuit_sizes_are_exact() {
    let consts = Arc::new(Mimc::new().c);
    let mut rng = StdRng::seed_from_u64(5);
    for target in [2676usize, 8786] {
        let (r, pad) = size_for(target);
        let c = new_chain(&consts, r, pad, 0, &mut rng);
        assert_eq!(count_constraints(&c), (target, true));
    }
}

#[test]
fn groth16_verify_accepts_honest_rejects_tampered() {
    let consts = Arc::new(Mimc::new().c);
    let mut rng = StdRng::seed_from_u64(6);
    for pubs in [3usize, 13] {
        let vs = VerifySetup::new(pubs, 2, &consts, &mut rng);
        assert_eq!(vs.items[0].1.len(), pubs);
        assert!(vs.verify(0));
        assert!(vs.verify(1));
        let (proof, inputs) = &vs.items[0];
        for k in 0..pubs {
            let mut bad = inputs.clone();
            bad[k] += Fr::one();
            assert!(!Groth16::<Bn254>::verify_with_processed_vk(&vs.pvk, &bad, proof).unwrap(), "tampered public input {k} accepted");
        }
        // proof of another statement does not verify against these inputs
        assert!(!Groth16::<Bn254>::verify_with_processed_vk(&vs.pvk, inputs, &vs.items[1].0).unwrap());
        // random unrelated inputs
        let r: Vec<Fr> = (0..pubs).map(|_| Fr::rand(&mut rng)).collect();
        assert!(!Groth16::<Bn254>::verify_with_processed_vk(&vs.pvk, &r, proof).unwrap());
    }
}

#[test]
fn groth16_prove_mint_size_verifies() {
    let consts = Arc::new(Mimc::new().c);
    let mut rng = StdRng::seed_from_u64(7);
    let ps = ProveSetup::new(2676, 2, &consts, &mut rng);
    assert_eq!(ps.constraints, 2676);
    let proof = ps.prove(0, &mut rng);
    assert!(ps.check(0, &proof));
    assert!(!ps.check(1, &proof)); // different statement
}

#[test]
fn groth16_prove_mint_q_all_verify_and_tamper_fails() {
    // w19: q Mint stand-in proofs one after the other; each proof verifies against its own witness
    let consts = Arc::new(Mimc::new().c);
    let mut rng = StdRng::seed_from_u64(8);
    let q = 3;
    let ps = ProveSetup::new(2676, q, &consts, &mut rng);
    let proofs = ps.prove_q(0, q, &mut rng);
    assert_eq!(proofs.len(), q);
    assert!(ps.check_q(0, &proofs));
    // a wrapped window uses the witnesses (start + k) mod len, and check_q uses the same ones
    let proofs2 = ps.prove_q(2, q, &mut rng);
    assert!(ps.check_q(2, &proofs2));
    // a window checked against the wrong start fails; two proofs swapped fail
    assert!(!ps.check_q(1, &proofs));
    let mut sw = proofs.clone();
    sw.swap(0, 1);
    assert!(!ps.check_q(0, &sw));
}

#[test]
fn audit_q_honest_passes_and_tampered_fails() {
    let mut rng = StdRng::seed_from_u64(11);
    let q = 5;
    let (ctx, insts) = AuditCtx::setup(&mut rng, 8, q);
    // q different ciphertexts and txIds
    for a in 0..q {
        for b in a + 1..q {
            assert_ne!(insts[a].tx_id, insts[b].tx_id);
            assert_ne!(insts[a].ct.c1, insts[b].ct.c1);
        }
    }
    let res = ctx.audit_q(&insts, 0, q);
    assert_eq!(res.len(), q);
    assert!(audit_q_all_ok(&insts, 0, &res));
    // a window that wraps around the instance list is also honest
    let res = ctx.audit_q(&insts, 3, q);
    assert!(audit_q_all_ok(&insts, 3, &res));
    // tamper one cm_G: that audit fails, the other q-1 still pass
    let mut bad = AuditCtx::setup(&mut StdRng::seed_from_u64(11), 8, q).1;
    bad[2].cm_g += Fr::one();
    let res = ctx.audit_q(&bad, 0, q);
    assert_eq!(res[2], Err(AuditError::VerificationFailed));
    assert_eq!(res.iter().filter(|r| r.is_ok()).count(), q - 1);
    assert!(!audit_q_all_ok(&bad, 0, &res));
}

#[test]
fn groth16_verify_q_honest_passes_and_tampered_fails() {
    let consts = Arc::new(Mimc::new().c);
    let mut rng = StdRng::seed_from_u64(12);
    let q = 6;
    let mut vs = VerifySetup::new(3, q, &consts, &mut rng);
    assert_eq!(vs.public_inputs, 3);
    assert!(vs.items.iter().all(|(_, inp)| inp.len() == 3));
    assert_eq!(vs.verify_q(0, q), q);
    assert_eq!(vs.verify_q(4, q), q); // wrapped window
    // tamper one public input of one item: exactly that one fails, no early exit
    vs.items[3].1[1] += Fr::one();
    assert_eq!(vs.verify_q(0, q), q - 1);
    vs.items[3].1[1] -= Fr::one();
    // swap two proofs: both statements now fail
    let p0 = vs.items[0].0.clone();
    vs.items[0].0 = vs.items[1].0.clone();
    vs.items[1].0 = p0;
    assert_eq!(vs.verify_q(0, q), q - 2);
}

#[test]
fn split_ranges_are_contiguous_nearly_equal_and_cover_q_once() {
    // e405: --threads T. q = 10, T = 4 -> 3,3,2,2; q = 16, T = 4 -> 4 each; T > q -> trailing empty ranges
    let sizes = |q: usize, t: usize| crate::par::split_ranges(q, t).iter().map(|r| r.len()).collect::<Vec<_>>();
    assert_eq!(sizes(10, 4), vec![3, 3, 2, 2]);
    assert_eq!(sizes(16, 4), vec![4, 4, 4, 4]);
    assert_eq!(sizes(3, 4), vec![1, 1, 1, 0]);
    assert_eq!(sizes(7, 1), vec![7]);
    for q in 1..40usize {
        for t in 1..9usize {
            let rs = crate::par::split_ranges(q, t);
            assert_eq!(rs.len(), t);
            assert_eq!(rs[0].start, 0);
            assert_eq!(rs[t - 1].end, q);
            assert!(rs.windows(2).all(|w| w[0].end == w[1].start), "ranges must be contiguous");
            let (mn, mx) = (rs.iter().map(|r| r.len()).min().unwrap(), rs.iter().map(|r| r.len()).max().unwrap());
            assert!(mx - mn <= 1);
        }
    }
}

#[test]
fn run_split_runs_every_item_once_and_every_worker_is_made_first() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (inits, calls) = (AtomicUsize::new(0), AtomicUsize::new(0));
    // init is called once per worker (before the barrier); work is called exactly q times; outputs come back in item order
    let (out, ms) = crate::par::run_split(10, 4, || { inits.fetch_add(1, Ordering::SeqCst); 0u32 }, |st, k| { *st += 1; calls.fetch_add(1, Ordering::SeqCst); k });
    assert_eq!(out, (0..10).collect::<Vec<_>>());
    assert_eq!((inits.load(Ordering::SeqCst), calls.load(Ordering::SeqCst)), (4, 10));
    assert!(ms >= 0.0 && ms.is_finite());
}

#[test]
fn audit_q_threads_t4_all_verify_and_item_count_is_q() {
    let mut rng = StdRng::seed_from_u64(21);
    let (ctx, insts) = AuditCtx::setup(&mut rng, 8, 16);
    for (start, q, t) in [(0usize, 16usize, 4usize), (0, 10, 4), (5, 10, 4), (0, 3, 4), (0, 16, 1)] {
        let (res, ms) = ctx.audit_q_threads(&insts, start, q, t);
        assert_eq!(res.len(), q, "item count must be exactly q (q={q}, T={t})");
        assert!(audit_q_all_ok(&insts, start, &res), "q={q} T={t} start={start}");
        assert!(ms >= 0.0);
        // same inputs, same answers as the single-thread path
        assert_eq!(res, ctx.audit_q(&insts, start, q));
    }
    // tampered cm_G of item 2 fails in its own slot and only there (outputs are in item order)
    let mut bad = AuditCtx::setup(&mut StdRng::seed_from_u64(21), 8, 16).1;
    bad[2].cm_g += Fr::one();
    let (res, _) = ctx.audit_q_threads(&bad, 0, 10, 4);
    assert_eq!(res[2], Err(AuditError::VerificationFailed));
    assert_eq!(res.iter().filter(|r| r.is_ok()).count(), 9);
    assert!(!audit_q_all_ok(&bad, 0, &res));
}

#[test]
fn prove_q_threads_t4_all_verify_item_count_is_q_and_fresh_randomness() {
    let consts = Arc::new(Mimc::new().c);
    let mut rng = StdRng::seed_from_u64(22);
    let ps = ProveSetup::new(2676, 8, &consts, &mut rng);
    // q = 8, T = 4: every proof verifies against the public inputs of its own witness
    let (proofs, ms) = ps.prove_q_threads(0, 8, 4);
    assert_eq!(proofs.len(), 8);
    assert!(ps.check_q(0, &proofs));
    assert!(ms > 0.0);
    // order matters: a shifted start or two swapped proofs must fail the check
    assert!(!ps.check_q(1, &proofs));
    let mut sw = proofs.clone();
    sw.swap(0, 7);
    assert!(!ps.check_q(0, &sw));
    // q = 10 not divisible by T = 4 (ranges 3,3,2,2), witnesses wrap (8 witnesses): items 0 and 8 use the same witness but are
    // proved by different workers with their own rng, so the two proofs differ and both verify
    let (proofs, _) = ps.prove_q_threads(0, 10, 4);
    assert_eq!(proofs.len(), 10);
    assert!(ps.check_q(0, &proofs));
    assert_ne!(proofs[0], proofs[8]);
    // T = 1 through the same helper also works
    let (proofs, _) = ps.prove_q_threads(2, 3, 1);
    assert!(ps.check_q(2, &proofs));
}

/// Breakdown of the audit_hit stage (informational): `cargo test --release breakdown -- --ignored --nocapture`
#[test]
#[ignore]
fn breakdown() {
    use std::time::Instant;
    let mut rng = StdRng::seed_from_u64(9);
    let (ctx, insts) = AuditCtx::setup(&mut rng, 4, 1);
    let i = &insts[0];
    let reps = 200;
    let t = Instant::now();
    for _ in 0..reps {
        std::hint::black_box(ctx.params.decrypt(&ctx.sk, std::hint::black_box(&i.ct)));
    }
    println!("decrypt   {:.1} us", t.elapsed().as_secs_f64() * 1e6 / reps as f64);
    let t = Instant::now();
    for _ in 0..reps {
        std::hint::black_box(ctx.mimc.hash(std::hint::black_box(&[Fr::from(1u64), i.r_shared, ctx.h_pk, ctx.cm_t])));
    }
    println!("mimc(4)   {:.1} us", t.elapsed().as_secs_f64() * 1e6 / reps as f64);
    let pr = &ctx.params.primes[0];
    let mut a = i.ct.c1[0].clone();
    let t = Instant::now();
    for _ in 0..reps {
        pr.ntt_fwd(std::hint::black_box(&mut a));
    }
    println!("ntt_fwd   {:.1} us (one prime)", t.elapsed().as_secs_f64() * 1e6 / reps as f64);
    let t = Instant::now();
    for _ in 0..reps {
        std::hint::black_box(ctx.cache.get(std::hint::black_box(&i.tx_id)));
    }
    println!("cache.get {:.1} us", t.elapsed().as_secs_f64() * 1e6 / reps as f64);
}

// ---------------- w30 (F1): Groth16 batch verification (src/batch.rs) ----------------
mod batch_w30 {
    use super::*;
    use crate::batch::*;
    use ark_bn254::{G1Affine, G2Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_groth16::Proof;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

    type Item = (Proof<Bn254>, Vec<Fr>);
    fn refs(v: &[Item]) -> Vec<(&Proof<Bn254>, &[Fr])> {
        v.iter().map(|(p, x)| (p, x.as_slice())).collect()
    }
    fn setup(n: usize, pubs: usize, seed: u64) -> VerifySetup {
        let consts = Arc::new(Mimc::new().c);
        let mut rng = StdRng::seed_from_u64(seed);
        VerifySetup::new(pubs, n, &consts, &mut rng)
    }
    fn batch(vs: &VerifySetup, v: &[Item]) -> bool {
        batch_verify(&vs.pvk, &refs(v)).unwrap()
    }

    #[test]
    fn batch_accepts_k_1_2_5_and_40_honest() {
        let vs = setup(40, 3, 30);
        for k in [1usize, 2, 5, 40] {
            let v: Vec<Item> = vs.items[..k].to_vec();
            for _ in 0..3 {
                assert!(batch(&vs, &v), "honest batch rejected, k={k}");
            }
        }
        let vs13 = setup(5, 13, 31);
        assert!(batch(&vs13, &vs13.items), "k=5 with 13 public inputs rejected");
    }

    #[test]
    fn batch_rejects_any_changed_proof_element() {
        let vs = setup(5, 3, 32);
        for k in [1usize, 2, 5] {
            for pos in 0..k {
                for elem in 0..3 {
                    let mut v: Vec<Item> = vs.items[..k].to_vec();
                    let p = &mut v[pos].0;
                    match elem {
                        0 => p.a = (p.a + G1Affine::generator()).into_affine(),
                        1 => p.b = (p.b + G2Affine::generator()).into_affine(),
                        _ => p.c = (p.c + G1Affine::generator()).into_affine(),
                    }
                    assert!(!batch(&vs, &v), "changed element {elem} of proof {pos} accepted (k={k})");
                }
            }
        }
        // also with 40 proofs (Pippenger branch for sum r_i C_i), one changed C at the end
        let vs40 = setup(40, 3, 33);
        let mut v: Vec<Item> = vs40.items.clone();
        v[39].0.c = (v[39].0.c + G1Affine::generator()).into_affine();
        assert!(!batch(&vs40, &v));
    }

    #[test]
    fn batch_rejects_any_changed_public_input() {
        let vs = setup(5, 3, 34);
        for k in [1usize, 2, 5] {
            for pos in 0..k {
                for j in 0..3 {
                    let mut v: Vec<Item> = vs.items[..k].to_vec();
                    v[pos].1[j] += Fr::one();
                    assert!(!batch(&vs, &v), "changed input {j} of proof {pos} accepted (k={k})");
                }
            }
        }
    }

    #[test]
    fn batch_rejects_swapped_proofs_with_mismatched_inputs() {
        let vs = setup(5, 3, 35);
        // k = 2: swap the two proofs, keep each input vector in place
        let mut v: Vec<Item> = vs.items[..2].to_vec();
        let p0 = v[0].0.clone();
        v[0].0 = v[1].0.clone();
        v[1].0 = p0;
        assert!(!batch(&vs, &v));
        // k = 5: swap proofs 1 and 3 only
        let mut v: Vec<Item> = vs.items[..5].to_vec();
        let p1 = v[1].0.clone();
        v[1].0 = v[3].0.clone();
        v[3].0 = p1;
        assert!(!batch(&vs, &v));
        // swapping proofs AND their inputs together is the same set: accepted
        let mut v: Vec<Item> = vs.items[..5].to_vec();
        v.swap(1, 3);
        assert!(batch(&vs, &v));
    }

    #[test]
    fn batch_rejects_proof_from_another_circuit_key() {
        let a = setup(2, 3, 36);
        let b = setup(2, 3, 37); // different trusted setup: its proofs must not verify under a's vk
        let mut v: Vec<Item> = a.items.clone();
        v[1] = b.items[1].clone();
        assert!(!batch(&a, &v));
    }

    #[test]
    fn batch_matches_one_by_one_with_fixed_scalars() {
        let vs = setup(6, 3, 38);
        let rs: Vec<u128> = vec![1, u128::MAX, 7, 1u128 << 100, 12345, 99];
        let items = refs(&vs.items);
        assert!(batch_verify_with_scalars(&vs.pvk, &items, &rs).unwrap());
        let mut bad = vs.items.clone();
        bad[4].1[2] -= Fr::one();
        assert!(!batch_verify_with_scalars(&vs.pvk, &refs(&bad), &rs).unwrap());
    }

    #[test]
    fn batch_edge_cases() {
        let vs = setup(2, 3, 39);
        assert!(batch_verify(&vs.pvk, &[]).unwrap()); // empty batch: vacuously true
        let mut v: Vec<Item> = vs.items.clone();
        v[1].1.pop(); // wrong number of public inputs -> same error as the one-by-one path
        assert!(batch_verify(&vs.pvk, &refs(&v)).is_err());
        assert!(Groth16::<Bn254>::verify_with_processed_vk(&vs.pvk, &v[1].1, &v[1].0).is_err());
    }

    #[test]
    fn scalars_are_nonzero_128bit_and_sum_is_exact() {
        let rs = draw_scalars(1000);
        assert_eq!(rs.len(), 1000);
        assert!(rs.iter().all(|&r| r != 0));
        assert!(rs.iter().any(|&r| r >> 120 != 0), "high bits never set: not 128-bit uniform");
        assert_ne!(draw_scalars(4), draw_scalars(4)); // fresh each call
        // exact integer sum: compare with Fr sum (k < 2^64, and Fr is larger than 2^138 so no wrap for small k)
        let s = sum_u128(&rs);
        let mut f = Fr::from(0u64);
        for &r in &rs {
            f += Fr::from(r);
        }
        assert_eq!(Fr::from(ark_ff::BigInt::<4>::new([s[0], s[1], s[2], 0])), f);
        // carry across limbs
        assert_eq!(sum_u128(&[u128::MAX, 1]), [0, 0, 1]);
        assert_eq!(sum_u128(&[u128::MAX, u128::MAX]), [u64::MAX - 1, u64::MAX, 1]);
    }

    #[test]
    fn batch_after_serialize_deserialize_with_validation() {
        // The proofs of the bench are never parsed; this shows batch works on proofs parsed with Validate::Yes
        // (curve + subgroup checks, the arkworks default of `deserialize_compressed`).
        let vs = setup(5, 3, 40);
        let v: Vec<Item> = vs
            .items
            .iter()
            .map(|(p, x)| {
                let mut buf = Vec::new();
                p.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
                (Proof::<Bn254>::deserialize_with_mode(&buf[..], Compress::Yes, Validate::Yes).unwrap(), x.clone())
            })
            .collect();
        assert!(batch(&vs, &v));
    }

    #[test]
    fn verify_batch_q_window_matches_verify_q() {
        let vs = setup(8, 3, 41);
        for (start, q) in [(0usize, 1usize), (0, 2), (3, 5), (6, 8), (13, 3)] {
            assert_eq!(vs.verify_q(start, q), q);
            assert!(vs.verify_batch_q(start, q), "start={start} q={q}");
        }
    }
}

/// w30 (Addendum A2): tests of `--only-setup` (module `setup_w30`).
mod setup_w30_tests {
    use crate::circuits::ProveSetup;
    use crate::mimc::Mimc;
    use crate::setup_w30::*;
    use ark_bn254::{Bn254, Fr};
    use ark_groth16::Groth16;
    use ark_serialize::CanonicalSerialize;
    use ark_snark::SNARK;
    use rand::{rngs::StdRng, SeedableRng};
    use std::sync::Arc;

    fn consts() -> Arc<Vec<Fr>> {
        Arc::new(Mimc::new().c)
    }

    #[test]
    fn setup_circuit_is_the_mint_circuit_of_the_prove_stage() {
        let consts = consts();
        let mut rng = StdRng::seed_from_u64(70);
        let ps = ProveSetup::new(2676, 1, &consts, &mut rng);
        assert_eq!(ps.constraints, MINT_CONSTRAINTS);
        let c0 = mint_setup_circuit(&consts, &mut rng);
        assert_eq!(crate::circuits::count_constraints(&c0), (2676, true));
        assert_eq!(c0.rounds, ps.circuits[0].rounds);
        assert_eq!(c0.bool_constraints, ps.circuits[0].bool_constraints);
        assert_eq!(c0.extra_pub.len(), 0);
        assert_eq!(c0.public_inputs().len(), 3);
        // same shape of keys as the prove stage: gamma_abc_g1 = 1 + 3 public inputs
        let (_, pk, vk) = { let (s, pk, vk) = time_groth16_setup(c0, &mut rng); (s, pk, vk) };
        assert_eq!(vk.gamma_abc_g1.len(), 4);
        assert_eq!(vk.gamma_abc_g1.len(), ps.pk.vk.gamma_abc_g1.len());
        assert_eq!(pk.a_query.len(), ps.pk.a_query.len());
        assert_eq!(pk.l_query.len(), ps.pk.l_query.len());
        assert_eq!(pk.h_query.len(), ps.pk.h_query.len());
    }

    #[test]
    fn setup_keys_produce_verifying_proofs_and_mismatched_keys_fail() {
        let consts = consts();
        let mut rng = StdRng::seed_from_u64(71);
        let (s1, pk1, vk1) = time_groth16_setup(mint_setup_circuit(&consts, &mut rng), &mut rng);
        let (_, pk2, vk2) = time_groth16_setup(mint_setup_circuit(&consts, &mut rng), &mut rng);
        assert!(s1 > 0.0 && s1.is_finite());
        assert!(check_keys(&pk1, &vk1, &consts, &mut rng));
        assert!(check_keys(&pk2, &vk2, &consts, &mut rng));
        // a proof under pk1 must not verify under the vk of another setup (fresh toxic waste)
        assert!(!check_keys(&pk1, &vk2, &consts, &mut rng));
        assert!(!check_keys(&pk2, &vk1, &consts, &mut rng));
        // the key pair is the one `circuit_specific_setup` returns (nothing else is hidden in the timer wrapper)
        let c = mint_setup_circuit(&consts, &mut rng);
        let (pk3, vk3) = Groth16::<Bn254>::circuit_specific_setup(c, &mut rng).unwrap();
        assert!(check_keys(&pk3, &vk3, &consts, &mut rng));
    }

    #[test]
    fn key_sizes_are_the_compressed_serialised_lengths() {
        let consts = consts();
        let mut rng = StdRng::seed_from_u64(72);
        let (_, pk, vk) = time_groth16_setup(mint_setup_circuit(&consts, &mut rng), &mut rng);
        let (pb, vb) = key_sizes(&pk, &vk);
        let mut v = Vec::new();
        pk.serialize_compressed(&mut v).unwrap();
        assert_eq!(v.len(), pb);
        let mut w = Vec::new();
        vk.serialize_compressed(&mut w).unwrap();
        assert_eq!(w.len(), vb);
        assert!(pb > 100 * vb, "pk {pb} vs vk {vb}");
        // vk: alpha (G1, 32 B) + beta, gamma, delta (G2, 64 B each) + length (8 B) + 4 x G1 (32 B each) = 360 B
        assert_eq!(vb, 32 + 3 * 64 + 8 + 4 * 32);
        // a second setup of the same circuit has the same sizes (the sizes depend on the circuit, not on the randomness)
        let (_, pk2, vk2) = time_groth16_setup(mint_setup_circuit(&consts, &mut rng), &mut rng);
        assert_eq!(key_sizes(&pk2, &vk2), (pb, vb));
    }

    #[test]
    fn setup_mode_rows_and_csv_format() {
        let rows = run_setup_mode(2, 1);
        assert_eq!(rows.len(), 4); // 2 Groth16 + 2 BFV, the warm-up round is not written
        assert_eq!(rows.iter().filter(|r| r.stage == "groth16_setup_mint").count(), 2);
        assert_eq!(rows.iter().filter(|r| r.stage == "bfv_keygen_regulator").count(), 2);
        for (k, r) in rows.iter().filter(|r| r.stage == "groth16_setup_mint").enumerate() {
            assert_eq!(r.run, k);
            assert!(r.secs > 0.0 && r.secs.is_finite());
            assert!(r.pk_bytes.parse::<usize>().unwrap() > 100_000);
            assert_eq!(r.vk_bytes, "360");
        }
        for r in rows.iter().filter(|r| r.stage == "bfv_keygen_regulator") {
            assert!(r.secs > 0.0);
            assert_eq!(r.pk_bytes, (2 * 2 * 4096 * 8).to_string());
            assert_eq!(r.vk_bytes, "NA");
        }
        let csv = csv_text(&rows);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "stage,run,secs,pk_bytes,vk_bytes");
        assert_eq!(lines.len(), 5);
        assert!(lines.iter().skip(1).all(|l| l.split(',').count() == 5));
    }

    #[test]
    fn meta_json_names_the_stages_and_escapes_the_tag() {
        let m = meta_json(5, 1, "w30\"x");
        for k in ["\"mode\": \"only-setup\"", "\"runs\": 5", "\"warmup\": 1", "\"threads\": 1", "groth16_setup_mint", "bfv_keygen_regulator", "TrapGen", "\"params_tag\": \"w30\\\"x\"", "stage,run,secs,pk_bytes,vk_bytes"] {
            assert!(m.contains(k), "meta.json lacks {k}");
        }
        assert_eq!(m.matches('{').count(), m.matches('}').count());
    }
}
