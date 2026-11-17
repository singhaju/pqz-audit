//! w30 (F2): the same checks for both hashes (`HashKind::Sha3`, `HashKind::Blake3`).
use pqz_bl_dopiv::*;

const Q: u64 = 4294967291;
const KINDS: [HashKind; 2] = [HashKind::Sha3, HashKind::Blake3];

fn small(kind: HashKind, lazy: bool) -> (Instance, Rng) {
    let p = Params { n: 16, m: 1024, q: Q }; // m = ceil(2 n log2 q): the paper's bound holds
    assert!(p.bound_ok());
    (Instance::setup_with_hash(&p, 24, 7, lazy, kind), Rng::new(99))
}

fn forced(inst: &Instance, c: usize, rng: &mut Rng) -> Challenge {
    let mut ch = challenge(inst.ell, c, rng);
    ch.beta[0] = 1;
    ch
}

fn bump(v: &mut [u32], i: usize) {
    v[i] = ((v[i] as u64 + 1) % Q) as u32;
}

#[test]
fn honest_verifies_each_hash() {
    for kind in KINDS {
        for lazy in [false, true] {
            let (inst, mut rng) = small(kind, lazy);
            assert_eq!(inst.hash, kind);
            for _ in 0..5 {
                let ch = challenge(inst.ell, 10, &mut rng);
                let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
                assert!(verify(&inst, &ch, &pr, &mut NoMeter), "{:?}", kind);
                assert!(proof_verify_full(&inst, &ch, &pr, &mut NoMeter), "{:?}", kind);
            }
            assert!(verify_delegation(&inst, &mut NoMeter));
        }
    }
}

#[test]
fn tampered_record_tag_proof_rejected_each_hash() {
    for kind in KINDS {
        // changed record (data block) word
        let (mut inst, mut rng) = small(kind, false);
        let ch = forced(&inst, 10, &mut rng);
        let i = ch.idx[0];
        bump(&mut inst.files[i], 5);
        let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
        assert!(!verify(&inst, &ch, &pr, &mut NoMeter), "record {:?}", kind);
        // changed tag entry
        let (mut inst, mut rng) = small(kind, false);
        let ch = forced(&inst, 10, &mut rng);
        let i = ch.idx[0];
        inst.tags[i][17] += 1;
        let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
        assert!(!verify(&inst, &ch, &pr, &mut NoMeter), "tag {:?}", kind);
        // changed proof entries f, e, xi (one at a time)
        let (inst, mut rng) = small(kind, false);
        let ch = challenge(inst.ell, 10, &mut rng);
        let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
        assert!(verify(&inst, &ch, &pr, &mut NoMeter));
        for which in 0..3 {
            let mut b = Proof { f: pr.f.clone(), e: pr.e.clone(), xi: pr.xi.clone() };
            match which {
                0 => bump(&mut b.f, 3),
                1 => bump(&mut b.e, 3),
                _ => bump(&mut b.xi, 3),
            }
            assert!(!verify(&inst, &ch, &b, &mut NoMeter), "proof part {} {:?}", which, kind);
        }
        // every byte of the proof encoding: a single flipped bit in each of f, e, xi, several positions
        for (which, len) in [(0usize, pr.f.len()), (1, pr.e.len()), (2, pr.xi.len())] {
            for pos in [0usize, len / 2, len - 1] {
                for bit in [0u32, 13, 31] {
                    let mut b = Proof { f: pr.f.clone(), e: pr.e.clone(), xi: pr.xi.clone() };
                    let v = match which {
                        0 => &mut b.f,
                        1 => &mut b.e,
                        _ => &mut b.xi,
                    };
                    v[pos] ^= 1 << bit;
                    assert!(!verify(&inst, &ch, &b, &mut NoMeter), "bit flip {} {} {} {:?}", which, pos, bit, kind);
                }
            }
        }
        // delegation tampering (H2 path)
        let (mut inst, _) = small(kind, false);
        inst.warrant[2] ^= 1;
        assert!(!verify_delegation(&inst, &mut NoMeter), "warrant {:?}", kind);
        let (mut inst, _) = small(kind, false);
        bump(&mut inst.v_w, 0);
        assert!(!verify_delegation(&inst, &mut NoMeter), "v_w {:?}", kind);
    }
}

#[test]
fn proof_for_other_challenge_rejected_each_hash() {
    for kind in KINDS {
        let (inst, mut rng) = small(kind, false);
        let ch1 = forced(&inst, 10, &mut rng);
        let mut ch2 = forced(&inst, 10, &mut rng);
        while ch2.idx == ch1.idx {
            ch2 = forced(&inst, 10, &mut rng);
        }
        let pr = proofgen(&inst, &ch1, &mut rng, &mut NoMeter);
        assert!(!verify(&inst, &ch2, &pr, &mut NoMeter), "{:?}", kind);
    }
}

#[test]
fn prover_and_verifier_must_use_the_same_hash() {
    // an instance planted with one hash does not verify under the other (every H2/H4/H5/H6 call is switched)
    for (a, b) in [(HashKind::Sha3, HashKind::Blake3), (HashKind::Blake3, HashKind::Sha3)] {
        let (mut inst, mut rng) = small(a, false);
        let ch = challenge(inst.ell, 10, &mut rng);
        let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
        assert!(verify(&inst, &ch, &pr, &mut NoMeter));
        inst.hash = b;
        assert!(!verify(&inst, &ch, &pr, &mut NoMeter), "{:?}->{:?}", a, b);
        assert!(!verify_delegation(&inst, &mut NoMeter), "delegation {:?}->{:?}", a, b);
    }
}

#[test]
fn operation_counts_match_table2_each_hash() {
    for kind in KINDS {
        for (n, m, ell, c) in [(16usize, 1024usize, 24usize, 10usize), (24, 40, 12, 7)] {
            let p = Params { n, m, q: Q };
            let inst = Instance::setup_with_hash(&p, ell, 11, false, kind);
            let mut rng = Rng::new(1);
            let ch = challenge(ell, c, &mut rng);
            let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
            let mut cv = Counts::default();
            assert!(verify(&inst, &ch, &pr, &mut cv));
            let (fh, fm) = table2_integrity(n as u64, m as u64, c as u64);
            assert_eq!((cv.hash, cv.mul), (fh, fm), "{:?}", kind);
            assert!(cv.sha3 >= cv.hash); // at least one primitive call per logical hash
            let mut cd = Counts::default();
            assert!(verify_delegation(&inst, &mut cd));
            assert_eq!((cd.hash, cd.mul), table2_delegation(n as u64, m as u64));
        }
    }
}

#[test]
fn expand_matches_direct_digest_and_hashes_differ() {
    // one output word per digest word: expand_zq_with(len=8) = the 8 little-endian words of the 32-byte digest
    // (accepted iff < q; check on a message whose words are all < q, else skip the equality)
    let (domain, part) = (b"DOPIV-test".as_slice(), b"abc".as_slice());
    let mut enc: Vec<u8> = vec![];
    enc.extend_from_slice(domain);
    enc.extend_from_slice(&(part.len() as u64).to_le_bytes());
    enc.extend_from_slice(part);
    enc.extend_from_slice(&0u32.to_le_bytes());
    let d3 = blake3::hash(&enc);
    let words: Vec<u32> = d3.as_bytes().chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
    let got = expand_zq_with(HashKind::Blake3, domain, &[part], 8, Q, &mut NoMeter);
    if words.iter().all(|&w| (w as u64) < Q) {
        assert_eq!(got, words);
    } else {
        // a rejected word shifts the output: still the accepted words in order, prefix of the stream
        let acc: Vec<u32> = words.iter().cloned().filter(|&w| (w as u64) < Q).collect();
        assert_eq!(&got[..acc.len()], &acc[..]);
    }
    let a = expand_zq_with(HashKind::Sha3, domain, &[part], 1000, Q, &mut NoMeter);
    let b = expand_zq_with(HashKind::Blake3, domain, &[part], 1000, Q, &mut NoMeter);
    assert_ne!(a, b);
    assert!(b.iter().all(|&x| (x as u64) < Q) && b.len() == 1000);
    assert_eq!(b, expand_zq_with(HashKind::Blake3, domain, &[part], 1000, Q, &mut NoMeter));
    // default expand_zq is SHA3 (old behaviour)
    assert_eq!(a, expand_zq(domain, &[part], 1000, Q, &mut NoMeter));
}

/// FNV-1a digest of everything a run produces for fixed seeds: used by the old-vs-new equality check
/// (the same program is also built against the ORIGINAL crate, see CHANGES-w30.md).
fn fnv(h: &mut u64, v: &[u32]) {
    for x in v {
        for b in x.to_le_bytes() {
            *h ^= b as u64;
            *h = h.wrapping_mul(0x100000001b3);
        }
    }
}

#[test]
fn sha3_run_digest_is_stable() {
    let p = Params { n: 16, m: 1024, q: Q };
    let inst = Instance::setup(&p, 24, 7, false); // old entry point
    let mut rng = Rng::new(99);
    let ch = challenge(24, 10, &mut rng);
    let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
    let mut h = 0xcbf29ce484222325u64;
    for f in &inst.files {
        fnv(&mut h, f);
    }
    fnv(&mut h, &inst.q_ido);
    fnv(&mut h, &pr.f);
    fnv(&mut h, &pr.e);
    fnv(&mut h, &pr.xi);
    // value recorded from the ORIGINAL crate (bench/pqz-bl/dopiv, built untouched), same program
    println!("RUN_DIGEST {:016x} sigma {}", h, inst.sigma);
    assert_eq!(format!("{:016x}", h), include_str!("orig_digest.txt").trim());
}
