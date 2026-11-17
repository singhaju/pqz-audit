//! Stage C, gate G-C1 part 1: generator equality and the same accept / reject verdicts as w30 (read-only dev-dependency).
//!  (1) R_Exec: our generator equals w30 word by word and the reference (count, sum) is equal (also in vs_winterfell.rs);
//!  (2) R_RC: the same mutated streams (5 mutation kinds x 8 trials, drawn once on plain u64 words and applied to both systems)
//!      get the same verdict from the w30 R_RC proof system and from ours, in two variants:
//!        P1 = dishonest prover, original public input; P3 = self-consistent (public input rebuilt from the mutated stream,
//!        n_blocks kept as in w30 `rc_public`). Header and record checks therefore must agree;
//!  (3) R_Auth: the same requests (honest instance of the same constants and draw order, then boundary and violation edits of
//!      scope, leaf and path) get the same accept / reject, and each verdict also equals the semantic expectation.
//! Release build only (winterfell and Plonky3 provers panic on bad traces in debug).
use std::panic::{catch_unwind, AssertUnwindSafe};

use p3_uni_stark::prove;

use pqz_plonky3_w46::auth::{self as a33, honest_auth_instance};
use pqz_plonky3_w46::data::{Rng, Workload, GOLDILOCKS_P};
use pqz_plonky3_w46::rel::plain;
use pqz_plonky3_w46::{c1, FriOpts};
use pqz_proof::auth as a30;
use pqz_proof::data::Workload as W30;
use pqz_proof::prove::{default_options, prove_trace};
use pqz_proof::rc as rc30;
use pqz_proof::rescue::F as F30;

fn below(r: &mut Rng, n: u64) -> u64 {
    r.next_u64() % n
}

#[test]
fn generator_equality_exec_and_rc_streams() {
    for (n, bs, seed) in [(1000usize, 100usize, 1u64), (5000, 100, 2), (200, 100, 3), (10_000, 100, 9)] {
        let a = Workload::synthetic(n, bs, seed);
        let b = W30::synthetic(n, bs, seed);
        assert_eq!(a.words.len(), b.words.len());
        for (i, (x, y)) in a.words.iter().zip(b.words.iter()).enumerate() {
            for j in 0..8 {
                assert_eq!(x[j], y[j].as_int(), "n={n} word {i} elem {j}");
            }
        }
        for theta in [0u64, 1 << 20, 1 << 31, (1 << 32) - 1] {
            assert_eq!(a.reference_result(theta), b.reference_result(theta), "n={n} theta={theta}");
        }
        eprintln!("generator equal: n={n} seed={seed} words={} count/sum equal for 4 thetas", a.words.len());
    }
}

#[test]
fn generator_equality_auth_instance() {
    let perm = c1::perm();
    for depth in [1usize, 6, 10, 14, 20] {
        for seed in [3u64, 9, 77] {
            let (p33, w33) = honest_auth_instance::<c1::Val, _>(&perm, depth, seed);
            let (p30, w30) = a30::honest_auth_instance(depth, seed);
            // hash-independent inputs of the instance: scope, leaf, index, siblings (random draws), d_q, omega, ids
            assert_eq!((p33.scope.s, p33.scope.e, p33.scope.t, p33.scope.p, p33.scope.level), (p30.scope.s, p30.scope.e, p30.scope.t, p30.scope.p, p30.scope.level));
            assert_eq!((p33.uid, p33.v_a, p33.v_auth, p33.depth), (p30.uid, p30.v_a, p30.v_auth, p30.depth));
            assert_eq!(w33.index, w30.index);
            assert_eq!((w33.leaf.uid, w33.leaf.v_a, w33.leaf.s, w33.leaf.e, w33.leaf.t, w33.leaf.p, w33.leaf.level, w33.leaf.blind),
                       (w30.leaf.uid, w30.leaf.v_a, w30.leaf.s, w30.leaf.e, w30.leaf.t, w30.leaf.p, w30.leaf.level, w30.leaf.blind));
            for i in 0..depth {
                for j in 0..4 {
                    assert_eq!(w33.siblings[i][j], w30.siblings[i][j].as_int());
                }
            }
            for j in 0..4 {
                assert_eq!(p33.d_q[j], p30.d_q[j].as_int());
                assert_eq!(p33.omega[j], p30.omega[j].as_int());
            }
        }
    }
    eprintln!("auth instance inputs equal (scope, leaf, index, siblings, d_q, omega) for 15 (depth, seed) pairs; r_pol and b_q differ by design (Poseidon2 instead of Rescue)");
}

// ------------------------------------------------------------------------------------------------ R_RC verdicts

fn mutate_u64(words: &[Vec<u64>], n_blocks: usize, bs: usize, kind: &str, r: &mut Rng) -> Vec<Vec<u64>> {
    let mut m: Vec<Vec<u64>> = words.to_vec();
    let rec_index = |r: &mut Rng| -> usize {
        let g = below(r, n_blocks as u64) as usize;
        let k = below(r, bs as u64) as usize;
        g * (bs + 1) + 1 + k
    };
    let delta = |r: &mut Rng| 1 + r.next_u64() % 1_000_000;
    match kind {
        "changed_record_word" => {
            let i = rec_index(r);
            let j = below(r, 7) as usize;
            m[i][j] = match j {
                4 => m[i][j] ^ (1u64 << below(r, 32)),
                5 => m[i][j] ^ (1u64 << below(r, 20)),
                _ => (m[i][j] + delta(r)) % GOLDILOCKS_P,
            };
        }
        "dropped_record" => {
            let i = rec_index(r);
            m.remove(i);
        }
        "duplicated_record" => {
            let i = rec_index(r);
            let x = m[i].clone();
            m.insert(i, x);
        }
        "reordered_records" => {
            let i = rec_index(r);
            let mut j = rec_index(r);
            while j == i || m[i] == m[j] {
                j = rec_index(r);
            }
            m.swap(i, j);
        }
        "changed_block_header" => {
            let g = below(r, n_blocks as u64) as usize;
            let j = below(r, 5) as usize;
            let i = g * (bs + 1);
            m[i][j] = (m[i][j] + delta(r)) % GOLDILOCKS_P;
        }
        _ => panic!("kind"),
    }
    m
}

fn to_w30(base: &W30, words: &[Vec<u64>]) -> W30 {
    let mut w = base.clone();
    w.words = words.iter().map(|x| {
        let mut a = [F30::new(0); 8];
        for j in 0..8 {
            a[j] = F30::new(x[j]);
        }
        a
    }).collect();
    w
}

fn verdict_w30_rc(w2: &W30, base_pub: &rc30::RcPublic, variant: &str) -> bool {
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        let (prove_pub, ver_pub) = if variant == "P1" { (base_pub.clone(), base_pub.clone()) } else { let p = rc30::rc_public(w2); (p.clone(), p) };
        let proof = prove_trace::<rc30::RcAir>(rc30::build_rc_trace(w2), prove_pub, default_options())?;
        rc30::verify_rc(proof, ver_pub)
    }));
    matches!(r, Ok(Ok(())))
}

fn verdict_w33_rc(words2: &[Vec<u64>], base_pub: &pqz_plonky3_w46::rc::RcPublic, n_blocks: usize, bs: usize, variant: &str) -> bool {
    let o = FriOpts::from_env();
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        let (prove_pub, ver_pub) = if variant == "P1" {
            (base_pub.clone(), base_pub.clone())
        } else {
            let mut p = plain::rc_public(words2, bs);
            p.n_blocks = n_blocks; // as w30 `rc_public`: the stream's n_blocks is kept
            (p.clone(), p)
        };
        let a = plain::rc_air(prove_pub.block_size as u64, prove_pub.n_words() as u64);
        let tr = a.build_trace(&plain::perm(), words2);
        let pv = prove_pub.to_values::<c1::Val>(&a.lay);
        let proof = prove(&c1::config(&o), &a, tr, &pv).map_err(|e| format!("{e:?}"))?;
        plain::verify_rc(&o, &proof, &ver_pub)
    }));
    matches!(r, Ok(Ok(())))
}

#[test]
fn rc_same_verdicts_as_w30() {
    let (n, bs) = (1000usize, 100usize);
    let w33 = Workload::synthetic(n, bs, 21);
    let w30 = W30::synthetic(n, bs, 21);
    let words: Vec<Vec<u64>> = c1::words(&w33);
    let pub33 = plain::rc_public(&words, bs);
    let pub30 = rc30::rc_public(&w30);
    // honest first, in both systems
    assert!(verdict_w30_rc(&w30, &pub30, "P1"), "w30 honest");
    assert!(verdict_w33_rc(&words, &pub33, w33.n_blocks, bs, "P1"), "w33 honest");
    let mut rng = Rng::new(0x9c11_aa);
    let (mut agree, mut total, mut acc_both) = (0, 0, 0);
    let mut table: Vec<String> = Vec::new();
    for kind in ["changed_record_word", "dropped_record", "duplicated_record", "reordered_records", "changed_block_header"] {
        for t in 0..8 {
            let m = mutate_u64(&words, w33.n_blocks, bs, kind, &mut rng);
            let w2 = to_w30(&w30, &m);
            for variant in ["P1", "P3"] {
                let v30 = verdict_w30_rc(&w2, &pub30, variant);
                let v33 = verdict_w33_rc(&m, &pub33, w33.n_blocks, bs, variant);
                total += 1;
                if v30 == v33 {
                    agree += 1;
                }
                if v30 && v33 {
                    acc_both += 1;
                }
                table.push(format!("{kind},{t},{variant},{},{}", v30, v33));
                assert_eq!(v30, v33, "VERDICT DIFFERS: kind={kind} trial={t} variant={variant} w30={v30} w33={v33}");
            }
        }
    }
    eprintln!("rc verdicts: {agree}/{total} equal, {acc_both} accepted by both (well-formed changes: v, b, tag, id words)");
    std::fs::create_dir_all("results/stageC").ok();
    std::fs::write("results/stageC/gc1_rc_vs_w30.csv", format!("kind,trial,variant,w30_accepts,w33_accepts\n{}\n", table.join("\n"))).ok();
}

// ------------------------------------------------------------------------------------------------ R_Auth verdicts

// (name, expected verdict: Some(accept) or None = only equality required, needs_recompute)
const AUTH_EDITS: &[(&str, Option<bool>, bool)] = &[
    ("honest", Some(true), false),
    ("scope_s0_499", Some(false), false),
    ("scope_s0_500", Some(true), false),
    ("scope_s1_4001", Some(false), false),
    ("scope_s1_4000", Some(true), false),
    ("scope_e0_0", Some(false), false),
    ("scope_e0_1", Some(true), false),
    ("scope_e1_9", Some(false), false),
    ("scope_e1_8", Some(true), false),
    ("scope_t0_0", Some(true), false),
    ("scope_t1_5001", Some(false), false),
    ("scope_t1_5000", Some(true), false),
    ("scope_p_8", Some(false), false),
    ("scope_p_7", Some(true), false),
    ("scope_p_0", Some(true), false),
    ("scope_level_4", Some(false), false),
    ("scope_level_3", Some(true), false),
    ("scope_level_0", Some(true), false),
    ("scope_s_inverted", None, false),
    ("scope_ge_2_32", Some(false), false),
    ("wit_uid_changed", Some(false), false),
    ("wit_v_a_changed", Some(false), false),
    ("wit_sibling_changed", Some(false), false),
    ("wit_index_flipped", Some(false), false),
    ("wit_blind_changed", Some(false), false),
    ("pub_uid_changed", Some(false), false),
    ("pub_v_auth_changed", Some(false), false),
    ("leaf_s0_1001_rec", Some(false), true),
    ("leaf_s0_1000_rec", Some(true), true),
    ("leaf_s1_1999_rec", Some(false), true),
    ("leaf_s1_2000_rec", Some(true), true),
    ("leaf_e0_4_rec", Some(false), true),
    ("leaf_e0_3_rec", Some(true), true),
    ("leaf_e1_4_rec", Some(false), true),
    ("leaf_e1_5_rec", Some(true), true),
    ("leaf_t0_101_rec", Some(false), true),
    ("leaf_t0_100_rec", Some(true), true),
    ("leaf_t1_899_rec", Some(false), true),
    ("leaf_t1_900_rec", Some(true), true),
    ("leaf_p_lo_5_rec", Some(false), true),
    ("leaf_p_lo_4_rec", Some(true), true),
    ("leaf_p_hi_3_rec", Some(false), true),
    ("leaf_p_hi_4_rec", Some(true), true),
    ("leaf_level_1_rec", Some(false), true),
    ("leaf_level_2_rec", Some(true), true),
];

macro_rules! apply_edit {
    ($name:expr, $p:ident, $w:ident) => {
        match $name {
            "honest" => {}
            "scope_s0_499" => $p.scope.s.0 = 499,
            "scope_s0_500" => $p.scope.s.0 = 500,
            "scope_s1_4001" => $p.scope.s.1 = 4001,
            "scope_s1_4000" => $p.scope.s.1 = 4000,
            "scope_e0_0" => $p.scope.e.0 = 0,
            "scope_e0_1" => $p.scope.e.0 = 1,
            "scope_e1_9" => $p.scope.e.1 = 9,
            "scope_e1_8" => $p.scope.e.1 = 8,
            "scope_t0_0" => $p.scope.t.0 = 0,
            "scope_t1_5001" => $p.scope.t.1 = 5001,
            "scope_t1_5000" => $p.scope.t.1 = 5000,
            "scope_p_8" => $p.scope.p = 8,
            "scope_p_7" => $p.scope.p = 7,
            "scope_p_0" => $p.scope.p = 0,
            "scope_level_4" => $p.scope.level = 4,
            "scope_level_3" => $p.scope.level = 3,
            "scope_level_0" => $p.scope.level = 0,
            "scope_s_inverted" => $p.scope.s = (2000, 1000),
            "scope_ge_2_32" => $p.scope.s.1 = 1u64 << 32,
            "wit_uid_changed" => $w.leaf.uid += 5,
            "wit_v_a_changed" => $w.leaf.v_a += 5,
            "wit_sibling_changed" => $w.siblings[0][1] = $w.siblings[0][1].clone_plus(),
            "wit_index_flipped" => $w.index ^= 1,
            "wit_blind_changed" => $w.leaf.blind ^= 0x55,
            "pub_uid_changed" => $p.uid += 1,
            "pub_v_auth_changed" => $p.v_auth += 1,
            "leaf_s0_1001_rec" => $w.leaf.s.0 = 1001,
            "leaf_s0_1000_rec" => $w.leaf.s.0 = 1000,
            "leaf_s1_1999_rec" => $w.leaf.s.1 = 1999,
            "leaf_s1_2000_rec" => $w.leaf.s.1 = 2000,
            "leaf_e0_4_rec" => $w.leaf.e.0 = 4,
            "leaf_e0_3_rec" => $w.leaf.e.0 = 3,
            "leaf_e1_4_rec" => $w.leaf.e.1 = 4,
            "leaf_e1_5_rec" => $w.leaf.e.1 = 5,
            "leaf_t0_101_rec" => $w.leaf.t.0 = 101,
            "leaf_t0_100_rec" => $w.leaf.t.0 = 100,
            "leaf_t1_899_rec" => $w.leaf.t.1 = 899,
            "leaf_t1_900_rec" => $w.leaf.t.1 = 900,
            "leaf_p_lo_5_rec" => $w.leaf.p.0 = 5,
            "leaf_p_lo_4_rec" => $w.leaf.p.0 = 4,
            "leaf_p_hi_3_rec" => $w.leaf.p.1 = 3,
            "leaf_p_hi_4_rec" => $w.leaf.p.1 = 4,
            "leaf_level_1_rec" => $w.leaf.level = 1,
            "leaf_level_2_rec" => $w.leaf.level = 2,
            other => panic!("edit {other}"),
        }
    };
}

trait ClonePlus {
    fn clone_plus(&self) -> Self;
}
impl ClonePlus for u64 {
    fn clone_plus(&self) -> u64 {
        (self + 1) % GOLDILOCKS_P
    }
}
impl ClonePlus for F30 {
    fn clone_plus(&self) -> F30 {
        F30::new((self.as_int() + 1) % GOLDILOCKS_P)
    }
}

fn verdict_auth_w33(depth: usize, seed: u64, name: &str, rec: bool) -> bool {
    let o = FriOpts::from_env();
    let perm = c1::perm();
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        let (mut p, mut w) = honest_auth_instance::<c1::Val, _>(&perm, depth, seed);
        apply_edit!(name, p, w);
        if rec {
            p.r_pol = a33::root_of::<c1::Val, _>(&perm, &w.leaf, w.index, &w.siblings);
            p.b_q = a33::bind_hash::<c1::Val, _>(&perm, p.d_q, p.uid, p.v_a, p.v_auth, p.r_pol, p.omega);
        }
        let proof = plain::prove_auth(&o, &p, &w)?;
        plain::verify_auth(&o, &proof, &p)
    }));
    matches!(r, Ok(Ok(())))
}

fn verdict_auth_w30(depth: usize, seed: u64, name: &str, rec: bool) -> bool {
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        let (mut p, mut w) = a30::honest_auth_instance(depth, seed);
        apply_edit!(name, p, w);
        if rec {
            p.r_pol = a30::root_of(&w.leaf, w.index, &w.siblings);
            p.b_q = a30::bind_hash(p.d_q, p.uid, p.v_a, p.v_auth, p.r_pol, p.omega);
        }
        let proof = a30::prove_auth(&p, &w)?;
        a30::verify_auth(proof, p)
    }));
    matches!(r, Ok(Ok(())))
}

#[test]
fn auth_same_verdicts_as_w30() {
    let mut table = Vec::new();
    let (mut total, mut differ) = (0, 0);
    for (depth, seed) in [(6usize, 3u64), (10, 9), (10, 77), (14, 5)] {
        for &(name, expect, rec) in AUTH_EDITS {
            let v33 = verdict_auth_w33(depth, seed, name, rec);
            let v30 = verdict_auth_w30(depth, seed, name, rec);
            total += 1;
            if v33 != v30 {
                differ += 1;
            }
            table.push(format!("{depth},{seed},{name},{},{v30},{v33}", expect.map(|e| e.to_string()).unwrap_or("none".into())));
            eprintln!("auth d={depth:2} seed={seed:2} {name:22} expected {:?} w30 {v30} w33 {v33}", expect);
            if let Some(e) = expect {
                assert_eq!(v30, e, "w30 verdict differs from the semantic expectation: {name} d={depth}");
                assert_eq!(v33, e, "w33 verdict differs from the semantic expectation: {name} d={depth}");
            }
            assert_eq!(v30, v33, "VERDICT DIFFERS: {name} depth={depth} seed={seed}");
        }
    }
    eprintln!("auth verdicts: {}/{} equal", total - differ, total);
    std::fs::create_dir_all("results/stageC").ok();
    std::fs::write("results/stageC/gc1_auth_vs_w30.csv", format!("depth,seed,edit,expected,w30_accepts,w33_accepts\n{}\n", table.join("\n"))).ok();
}
