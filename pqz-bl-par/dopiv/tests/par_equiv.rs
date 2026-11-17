//! -par: the parallel code (meter = NoMeter) gives byte-identical proofs and the same verify results as the
//! original sequential code (meter = Counts runs the unchanged sequential path), for fixed seeds, at 1, 2 and 7
//! rayon threads, for both hashes and both reductions. The setup (tags, planted blocks) of the parallel code is
//! compared with the original crate through `hash_w30_tests::sha3_run_digest_is_stable` (digest recorded from
//! the untouched original) and, here, through proofs that must verify against the sequential verifier.
use pqz_bl_dopiv_par::*;

const Q: u64 = 4294967291;

fn pool<T: Send>(k: usize, f: impl FnOnce() -> T + Send) -> T {
    rayon::ThreadPoolBuilder::new().num_threads(k).build().unwrap().install(f)
}

fn fnv(h: &mut u64, v: &[u32]) {
    for x in v {
        for b in x.to_le_bytes() {
            *h ^= b as u64;
            *h = h.wrapping_mul(0x100000001b3);
        }
    }
}

fn inst_digest(inst: &Instance) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for f in &inst.files {
        fnv(&mut h, f);
    }
    for e in &inst.tags {
        let v: Vec<u32> = e.iter().map(|&x| x as u16 as u32).collect();
        fnv(&mut h, &v);
    }
    fnv(&mut h, &inst.q_ido);
    fnv(&mut h, &inst.theta_w);
    h
}

#[test]
fn parallel_setup_is_independent_of_thread_count() {
    let p = Params { n: 16, m: 1024, q: Q };
    for kind in [HashKind::Sha3, HashKind::Blake3] {
        let d: Vec<(u64, u64)> = [1usize, 2, 7]
            .iter()
            .map(|&k| pool(k, || {
                let i = Instance::setup_with_hash(&p, 40, 11, false, kind);
                (inst_digest(&i), i.sigma)
            }))
            .collect();
        assert!(d.iter().all(|x| *x == d[0]), "setup differs between thread counts: {:?}", d);
    }
}

#[test]
fn proofgen_and_verify_byte_identical_to_sequential_path() {
    // m = 1024 > ceil(2 n log2 q) for n = 16; ell = 60, c = 25 (some beta = 0 as well)
    let p = Params { n: 16, m: 1024, q: Q };
    for kind in [HashKind::Sha3, HashKind::Blake3] {
        for lazy in [false, true] {
            let inst = Instance::setup_with_hash(&p, 60, 5, lazy, kind);
            for threads in [1usize, 2, 7] {
                let mut r0 = Rng::new(1234);
                for round in 0..4 {
                    let c = 5 + 7 * round;
                    let ch = challenge(inst.ell, c, &mut r0);
                    // sequential reference: Counts meter selects the original code path
                    let mut rs = r0.clone();
                    let mut cnt = Counts::default();
                    let pr_seq = proofgen(&inst, &ch, &mut rs, &mut cnt);
                    let mut cv = Counts::default();
                    let ok_seq = verify(&inst, &ch, &pr_seq, &mut cv);
                    // parallel path
                    let mut rp = r0.clone();
                    let pr_par = pool(threads, || proofgen(&inst, &ch, &mut rp, &mut NoMeter));
                    assert_eq!(pr_seq.f, pr_par.f, "f ({:?} lazy={} thr={} c={})", kind, lazy, threads, c);
                    assert_eq!(pr_seq.e, pr_par.e, "e");
                    assert_eq!(pr_seq.xi, pr_par.xi, "xi");
                    assert_eq!(rs.next_u64(), rp.next_u64(), "rng stream position differs");
                    let ok_par = pool(threads, || verify(&inst, &ch, &pr_par, &mut NoMeter));
                    assert_eq!(ok_seq, ok_par);
                    assert!(ok_par, "honest proof must verify");
                    // tampered proofs: both paths must reject, the same way
                    for which in 0..3 {
                        let mut bad = Proof { f: pr_par.f.clone(), e: pr_par.e.clone(), xi: pr_par.xi.clone() };
                        match which {
                            0 => bad.f[3] = ((bad.f[3] as u64 + 1) % Q) as u32,
                            1 => bad.e[17] = ((bad.e[17] as u64 + 1) % Q) as u32,
                            _ => bad.xi[2] = ((bad.xi[2] as u64 + 1) % Q) as u32,
                        }
                        let s = verify(&inst, &ch, &bad, &mut Counts::default());
                        let pv = pool(threads, || verify(&inst, &ch, &bad, &mut NoMeter));
                        assert!(!s && !pv, "tampered proof accepted (which={})", which);
                    }
                    // delegation check (matvec rows in parallel)
                    let dseq = verify_delegation(&inst, &mut Counts::default());
                    let dpar = pool(threads, || verify_delegation(&inst, &mut NoMeter));
                    assert!(dseq && dpar);
                }
            }
        }
    }
}

#[test]
fn verify_many_matches_sequential() {
    let p = Params { n: 16, m: 1024, q: Q };
    let inst = Instance::setup(&p, 40, 3, false);
    let mut rng = Rng::new(77);
    let audits = pool(2, || make_audits(&inst, 9, 6, &mut rng));
    let seq = verify_many(&inst, &audits, &mut Counts::default());
    for k in [1usize, 2, 7] {
        assert_eq!(seq, pool(k, || verify_many(&inst, &audits, &mut NoMeter)));
    }
    assert!(seq);
    // one bad audit among q: both reject, neither short-circuits to a wrong answer
    let mut bad: Vec<(Challenge, Proof)> = audits.into_iter().collect();
    bad[4].1.f[0] = ((bad[4].1.f[0] as u64 + 1) % Q) as u32;
    assert!(!verify_many(&inst, &bad, &mut Counts::default()));
    assert!(!pool(7, || verify_many(&inst, &bad, &mut NoMeter)));
}

#[test]
fn counts_still_match_table2_with_par_build() {
    // the Counts path is the untouched sequential code: Table 2 counts hold exactly as in the original crate
    let p = Params { n: 16, m: 1024, q: Q };
    let inst = Instance::setup(&p, 30, 1, false);
    let mut rng = Rng::new(5);
    let ch = challenge(inst.ell, 12, &mut rng);
    let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
    let mut cv = Counts::default();
    assert!(verify(&inst, &ch, &pr, &mut cv));
    let (fh, fm) = table2_integrity(16, 1024, 12);
    assert_eq!((cv.hash, cv.mul), (fh, fm));
}
