use pqz_bl_dopiv::*;

const Q: u64 = 4294967291;

fn small(lazy: bool) -> (Instance, Rng) {
    // n=16, m = ceil(2 n log2 q) = 1024 (the paper's bound holds)
    let p = Params { n: 16, m: 1024, q: Q };
    assert!(p.bound_ok());
    (Instance::setup(&p, 24, 7, lazy), Rng::new(99))
}

fn forced(inst: &Instance, c: usize, rng: &mut Rng) -> Challenge {
    let mut ch = challenge(inst.ell, c, rng);
    ch.beta[0] = 1; // block idx[0] contributes
    ch
}

#[test]
fn honest_proof_verifies() {
    for lazy in [false, true] {
        let (inst, mut rng) = small(lazy);
        for _ in 0..5 {
            let ch = challenge(inst.ell, 10, &mut rng);
            let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
            assert!(verify(&inst, &ch, &pr, &mut NoMeter));
            assert!(proof_verify_full(&inst, &ch, &pr, &mut NoMeter));
        }
        assert!(verify_delegation(&inst, &mut NoMeter));
    }
}

#[test]
fn honest_verifies_sensitivity_shape() {
    // m < bound (violates the paper's bound; planted instance still has to verify)
    let p = Params { n: 32, m: 64, q: Q };
    assert!(!p.bound_ok());
    let inst = Instance::setup(&p, 12, 3, false);
    let mut rng = Rng::new(5);
    let ch = challenge(inst.ell, 8, &mut rng);
    let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
    assert!(verify(&inst, &ch, &pr, &mut NoMeter));
    assert!(verify_delegation(&inst, &mut NoMeter));
}

#[test]
fn tampered_message_block_rejected() {
    let (mut inst, mut rng) = small(false);
    let ch = forced(&inst, 10, &mut rng);
    let i = ch.idx[0];
    inst.files[i][5] = ((inst.files[i][5] as u64 + 1) % Q) as u32;
    let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
    assert!(!verify(&inst, &ch, &pr, &mut NoMeter));
}

#[test]
fn tampered_message_block_head_entry_rejected() {
    let (mut inst, mut rng) = small(false);
    let ch = forced(&inst, 10, &mut rng);
    let i = ch.idx[0];
    let last = inst.p.m - 1;
    inst.files[i][last] = ((inst.files[i][last] as u64 + 1) % Q) as u32;
    let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
    assert!(!verify(&inst, &ch, &pr, &mut NoMeter));
}

#[test]
fn tampered_tag_entry_rejected() {
    let (mut inst, mut rng) = small(false);
    let ch = forced(&inst, 10, &mut rng);
    let i = ch.idx[0];
    inst.tags[i][17] += 1;
    let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
    assert!(!verify(&inst, &ch, &pr, &mut NoMeter));
}

#[test]
fn unchallenged_block_tamper_not_detected_by_this_challenge() {
    // sanity: sampling audit only covers challenged blocks (with beta_i = 1)
    let (mut inst, mut rng) = small(false);
    let ch = challenge(inst.ell, 10, &mut rng);
    let other = (0..inst.ell).find(|i| !ch.idx.contains(i)).unwrap();
    inst.files[other][0] = ((inst.files[other][0] as u64 + 1) % Q) as u32;
    let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
    assert!(verify(&inst, &ch, &pr, &mut NoMeter));
}

#[test]
fn tampered_proof_rejected() {
    let (inst, mut rng) = small(false);
    let ch = challenge(inst.ell, 10, &mut rng);
    let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
    assert!(verify(&inst, &ch, &pr, &mut NoMeter));
    let bump = |v: &mut Vec<u32>| v[3] = ((v[3] as u64 + 1) % Q) as u32;
    let mut a = Proof { f: pr.f.clone(), e: pr.e.clone(), xi: pr.xi.clone() };
    bump(&mut a.f);
    assert!(!verify(&inst, &ch, &a, &mut NoMeter));
    let mut b = Proof { f: pr.f.clone(), e: pr.e.clone(), xi: pr.xi.clone() };
    bump(&mut b.e);
    assert!(!verify(&inst, &ch, &b, &mut NoMeter));
    let mut c = Proof { f: pr.f.clone(), e: pr.e.clone(), xi: pr.xi.clone() };
    bump(&mut c.xi);
    assert!(!verify(&inst, &ch, &c, &mut NoMeter));
}

#[test]
fn proof_for_other_challenge_rejected() {
    let (inst, mut rng) = small(false);
    let ch1 = forced(&inst, 10, &mut rng);
    let mut ch2 = forced(&inst, 10, &mut rng);
    while ch2.idx == ch1.idx {
        ch2 = forced(&inst, 10, &mut rng);
    }
    let pr = proofgen(&inst, &ch1, &mut rng, &mut NoMeter);
    assert!(!verify(&inst, &ch2, &pr, &mut NoMeter));
}

#[test]
fn zero_or_too_long_e_rejected() {
    let (inst, mut rng) = small(false);
    let ch = challenge(inst.ell, 10, &mut rng);
    let mut pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
    pr.e = vec![0; inst.p.m];
    assert!(!verify(&inst, &ch, &pr, &mut NoMeter));
}

#[test]
fn tampered_delegation_rejected() {
    let (mut inst, _) = small(false);
    assert!(verify_delegation(&inst, &mut NoMeter));
    let saved = inst.theta_w.clone();
    inst.theta_w[9] = ((inst.theta_w[9] as u64 + 1) % Q) as u32;
    assert!(!verify_delegation(&inst, &mut NoMeter));
    inst.theta_w = saved;
    inst.v_w[0] = ((inst.v_w[0] as u64 + 1) % Q) as u32;
    assert!(!verify_delegation(&inst, &mut NoMeter));
    inst.v_w[0] = ((inst.v_w[0] as u64 + Q - 1) % Q) as u32;
    assert!(verify_delegation(&inst, &mut NoMeter));
    inst.warrant[2] ^= 1; // warrant text changed: H2 differs
    assert!(!verify_delegation(&inst, &mut NoMeter));
}

#[test]
fn operation_counts_match_table2() {
    for (n, m, ell, c) in [(16usize, 1024usize, 24usize, 10usize), (24, 40, 12, 7), (8, 300, 20, 20)] {
        let p = Params { n, m, q: Q };
        let inst = Instance::setup(&p, ell, 11, false);
        let mut rng = Rng::new(1);
        let ch = challenge(ell, c, &mut rng);
        let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
        let mut cv = Counts::default();
        assert!(verify(&inst, &ch, &pr, &mut cv));
        let (fh, fm) = table2_integrity(n as u64, m as u64, c as u64);
        assert_eq!(cv.hash, fh, "Hash count");
        assert_eq!(cv.mul, fm, "mul count");
        assert_eq!(cv.sq, m as u64, "norm squarings (extra)");
        // term by term
        let d = cv.deltas();
        let get = |l: &str| d.iter().find(|x| x.0 == l).unwrap().clone();
        assert_eq!(get("H5 lambda_j (j=1..n)").3, n as u64);
        assert_eq!(get("H4(N_i||i), i in V").3, c as u64);
        assert_eq!(get("H6").3, 1);
        assert_eq!(get("mul: Q_IDc f").1, (n * m) as u64);
        assert_eq!(get("mul: xi*H6").1, n as u64);
        assert_eq!(get("mul: B v").1, (n * n) as u64);
        assert_eq!(get("mul: Q_pro e").1, (n * m) as u64);
        let mut cd = Counts::default();
        assert!(verify_delegation(&inst, &mut cd));
        let (dh, dm) = table2_delegation(n as u64, m as u64);
        assert_eq!((cd.hash, cd.mul), (dh, dm));
        // proofgen (the paper gives no cost): n*m (stand-in for SamplePre input) + m
        let mut cp = Counts::default();
        let _ = proofgen(&inst, &ch, &mut rng, &mut cp);
        assert_eq!(cp.hash, 1);
        assert_eq!(cp.mul, (n * m + m) as u64);
    }
}

#[test]
fn lazy_and_each_agree() {
    let p = Params { n: 16, m: 1024, q: Q };
    let a = Instance::setup(&p, 12, 4, false);
    let b = Instance::setup(&p, 12, 4, true);
    let mut r1 = Rng::new(8);
    let mut r2 = Rng::new(8);
    let c1 = challenge(12, 6, &mut r1);
    let c2 = challenge(12, 6, &mut r2);
    let p1 = proofgen(&a, &c1, &mut r1, &mut NoMeter);
    let p2 = proofgen(&b, &c2, &mut r2, &mut NoMeter);
    assert_eq!(p1.f, p2.f);
    assert_eq!(p1.xi, p2.xi);
    assert_eq!(p1.e, p2.e);
}

#[test]
fn hash_range() {
    let v = expand_zq(b"t", &[b"abc"], 1000, Q, &mut NoMeter);
    assert_eq!(v.len(), 1000);
    assert!(v.iter().all(|&x| (x as u64) < Q));
    assert_eq!(v, expand_zq(b"t", &[b"abc"], 1000, Q, &mut NoMeter));
}

// ---------------------------------------------------------------- SPEC-w16: stages at c = cov and verify_q

#[test]
fn cov_stage_honest_passes_both_reductions() {
    // challenge covers every planted block (ell = cov), as in the cov sweep with a single cov point
    for lazy in [false, true] {
        let p = Params { n: 16, m: 1024, q: Q };
        let inst = Instance::setup(&p, 20, 11, lazy);
        let mut rng = Rng::new(3);
        let ch = challenge(inst.ell, 20, &mut rng);
        assert_eq!(ch.idx.len(), 20);
        let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
        assert!(verify(&inst, &ch, &pr, &mut NoMeter));
        // operation count at c = cov equals Table 2
        let mut cv = Counts::default();
        assert!(verify(&inst, &ch, &pr, &mut cv));
        assert_eq!((cv.hash, cv.mul), table2_integrity(16, 1024, 20));
    }
}

#[test]
fn cov_stage_tampered_rejected() {
    let p = Params { n: 16, m: 1024, q: Q };
    let inst = Instance::setup(&p, 20, 11, false);
    let mut rng = Rng::new(4);
    let ch = challenge(inst.ell, 20, &mut rng);
    let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
    let mut bad = Proof { f: pr.f.clone(), e: pr.e.clone(), xi: pr.xi.clone() };
    bad.f[7] = ((bad.f[7] as u64 + 1) % Q) as u32;
    assert!(!verify(&inst, &ch, &bad, &mut NoMeter));
    let mut bad = Proof { f: pr.f.clone(), e: pr.e.clone(), xi: pr.xi.clone() };
    bad.e[9] = ((bad.e[9] as u64 + 1) % Q) as u32;
    assert!(!verify(&inst, &ch, &bad, &mut NoMeter));
}

#[test]
fn verify_q_honest_passes_and_tampered_fails() {
    let (inst, mut rng) = small(true);
    let mut audits = make_audits(&inst, 12, 5, &mut rng);
    assert_eq!(audits.len(), 5);
    // the q challenges are independent (not all equal)
    assert!(audits.iter().any(|(c, _)| c.idx != audits[0].0.idx));
    assert!(verify_many(&inst, &audits, &mut NoMeter));
    // one bad proof in the middle must make the batch fail
    audits[3].1.f[0] = ((audits[3].1.f[0] as u64 + 1) % Q) as u32;
    assert!(!verify_many(&inst, &audits, &mut NoMeter));
    // verify_many costs q times a single verify (operation count)
    let audits = make_audits(&inst, 12, 4, &mut rng);
    let mut c1 = Counts::default();
    assert!(verify(&inst, &audits[0].0, &audits[0].1, &mut c1));
    let mut c4 = Counts::default();
    assert!(verify_many(&inst, &audits, &mut c4));
    assert_eq!((c4.hash, c4.mul), (4 * c1.hash, 4 * c1.mul));
}
