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
