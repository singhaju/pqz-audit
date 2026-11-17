//! D2: Bloom35 is the same filter as pqz-eval's (same bits), with MRoot(S) and openings. Release mode: `cargo test --release --offline`.
mod common;
use pqz_eval::eapat::EpochKeys;
use pqz_eval::search::{bps_eval, Bloom, Formula, Tag};
use pqz_integrated_w46::w35::*;
use pqz_integrated_w46::*;
use pqz_ledger::hashing::{leaf_hash, verify_path};

fn rand_tags(n: usize, seed: u64) -> Vec<Tag> {
    (0..n as u64)
        .map(|i| {
            let mut m = seed.to_le_bytes().to_vec();
            m.extend_from_slice(&i.to_le_bytes());
            pqz_eval::sha3_256(&m)[..16].try_into().unwrap()
        })
        .collect()
}

#[test]
fn bloom35_has_the_same_bits_as_pqz_eval() {
    for (count, seed) in [(1usize, 1u64), (7, 2), (100, 3), (500, 4), (123, 5)] {
        let tags = rand_tags(count * 45, seed);
        let a = Bloom::build(count, tags.iter());
        let b = Bloom35::build(count, tags.iter());
        assert_eq!(a.nbits(), b.nbits, "count {count}");
        assert_eq!(a.k(), b.k, "count {count}");
        assert_eq!(a.digest(), b.digest(), "same sha3 over (nbits, k, bits): bit-identical, count {count}");
        let probe = rand_tags(400, seed + 99);
        for t in probe.iter().chain(tags.iter().take(50)) {
            assert_eq!(a.contains(t), b.contains(t));
        }
        assert_eq!(bloom_params(count), (a.nbits(), a.k()));
    }
}

#[test]
fn openings_verify_against_mroot_and_show_zero_bits() {
    let tags = rand_tags(500 * 45, 11);
    let b = Bloom35::build(500, tags.iter());
    let root = b.mroot();
    let n_leaves = b.nbits.div_ceil(64);
    let probe = rand_tags(50, 12);
    let mut shown = 0;
    for t in probe {
        let f = Formula::leaf(vec![t]);
        match b.openings_for(&f) {
            Some(ops) => {
                shown += 1;
                assert!(!b.contains(&t));
                for o in &ops {
                    assert!(verify_path(&leaf_hash(&o.word.to_le_bytes()), o.leaf_idx, n_leaves, &o.path, &root));
                }
                let zero = |p: usize| ops.iter().find(|o| o.leaf_idx == p / 64).map_or(false, |o| (o.word >> (p % 64)) & 1 == 0);
                assert!(formula_absent(&f, b.nbits, b.k, &zero));
            }
            None => assert!(b.contains(&t), "no zero bit planned for a tag that is not in the filter"),
        }
    }
    assert!(shown >= 40);
    // a wrong word does not verify
    let ops = b.open_many(&[0]);
    assert!(!verify_path(&leaf_hash(&(ops[0].word ^ 1).to_le_bytes()), 0, n_leaves, &ops[0].path, &root));
    // a member tag has no opening
    assert!(b.openings_for(&Formula::leaf(vec![tags[0]])).is_none());
}

#[test]
fn formula_absent_matches_bps_eval_negated() {
    let tags = rand_tags(500 * 45, 21);
    let a = Bloom::build(500, tags.iter());
    let b = Bloom35::build(500, tags.iter());
    let q = rand_tags(60, 22);
    for i in 0..q.len() - 2 {
        let l = |t: Tag| Formula::leaf(vec![t]);
        let fs = [
            l(q[i]),
            Formula::and(l(q[i]), l(tags[i])),
            Formula::or(l(q[i]), l(q[i + 1])),
            Formula::or(l(tags[i]), l(q[i + 2])),
            Formula::and(l(q[i + 1]), l(q[i + 2])),
        ];
        for f in &fs {
            let zero = |p: usize| !b.bit(p);
            assert_eq!(formula_absent(f, b.nbits, b.k, &zero), !bps_eval(&a, f));
        }
    }
}

#[test]
fn descriptor_h_equals_descriptor_and_build_log_keeps_the_hash() {
    let rs = pqz_eval::r#gen::r#gen(500, 10, pqz_eval::Layout::Clustered, DEFAULT_SEED);
    let keys = EpochKeys::from_seed(DEFAULT_SEED);
    let log = build_log(&rs, &keys);
    assert_eq!(log.h_cts.len(), 500);
    let mut dups = 0;
    for i in 0..500 {
        let seq = 1 + i as u64;
        let tags = &log.tags[i * TAGS_PER_RECORD..(i + 1) * TAGS_PER_RECORD];
        let d1 = descriptor_h(i as u64, seq, &log.h_cts[i], tags);
        assert_eq!(d1, log.descriptors[i]);
        let ct = pqz_eval::eapat::encrypt_record(&keys, &rs[i]).ciphertext;
        assert_eq!(descriptor(i as u64, seq, &ct, tags), d1);
        assert_eq!(h_ct_of(&ct), log.h_cts[i]);
        if i > 0 && log.descriptors[i] == log.descriptors[i - 1] {
            dups += 1;
        }
    }
    assert_eq!(dups, 0);
}

#[test]
fn block35_commitment_binds_sigma_and_every_field() {
    let b = Block35 { e: 1, g: 2, q_start: 501, q_next: 1001, count: 500, r_rec: [1; 32], s_root: [2; 32], sigma: None };
    let mut v = vec![b.clone()];
    let mut x = b.clone();
    x.sigma = Some([0; 12]);
    v.push(x.clone());
    let mut y = x.clone();
    y.sigma = Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    v.push(y);
    let mut z = b.clone();
    z.s_root = [3; 32];
    v.push(z);
    let mut z = b.clone();
    z.g = 3;
    v.push(z);
    let cs: Vec<_> = v.iter().map(|b| b.commitment()).collect();
    for i in 0..cs.len() {
        for j in i + 1..cs.len() {
            assert_ne!(cs[i], cs[j], "{i} vs {j}");
        }
    }
}
