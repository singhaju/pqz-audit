//! Rejection tests (5 trials per category and per config) and AIR self-checks. Run with `cargo test --release -- --nocapture`.
//! (In a debug build `prove` runs p3-air's constraint checker and panics on a bad trace; the tests then still count
//! it as a rejection but record "prover panic"; the release build gives the real verifier-side result.)
//!
//! Every category first checks that the HONEST proof verifies, so a rejection cannot come from a broken set-up.
//! Outcome kinds: PROVER_ERR (prove returned Err), PROVER_PANIC, DESER_FAIL (proof bytes do not parse),
//! VERIFY_FAIL (proof parsed, verifier returned Err), VERIFY_PANIC (verifier panicked).
//! A trial FAILS only if the verifier ACCEPTS.

use pqz_plonky3_w38::data::Workload;
use pqz_plonky3_w38::{c1, c1r0, c1zk, c2, FriOpts};
use std::panic::{catch_unwind, AssertUnwindSafe};

const THETA: u64 = 1 << 31;
const CTX: [u64; 4] = [1, 2, 3, 4];
const N: usize = 1000;

fn tally(name: &str, kinds: &[&'static str]) {
    let mut s = String::new();
    for k in ["PROVER_ERR", "PROVER_PANIC", "DESER_FAIL", "VERIFY_FAIL", "VERIFY_PANIC"] {
        let c = kinds.iter().filter(|x| **x == k).count();
        if c > 0 {
            s.push_str(&format!(" {k}={c}"));
        }
    }
    println!("REJECT {name}: {} of {} trials rejected:{s}", kinds.len(), 5);
}

macro_rules! suite {
    ($modname:ident, $m:ident) => {
        mod $modname {
            use super::*;
            use p3_field::PrimeField64;
            use p3_matrix::Matrix;

            fn setup() -> (FriOpts, Workload, pqz_plonky3_w38::air::ExecPublic) {
                let o = FriOpts::from_env();
                let w = Workload::synthetic(N, 100, 1);
                let p = $m::public_for(&w, THETA, CTX);
                (o, w, p)
            }

            /// prove (witness `w`, claimed public `p`), then verify against `vp`. Returns the rejection kind, or
            /// panics if the verifier ACCEPTED.
            fn attempt(o: &FriOpts, w: &Workload, p: &pqz_plonky3_w38::air::ExecPublic, vp: &pqz_plonky3_w38::air::ExecPublic, what: &str) -> &'static str {
                let r = catch_unwind(AssertUnwindSafe(|| $m::prove_with(o, w, p)));
                let proof = match r {
                    Err(_) => return "PROVER_PANIC",
                    Ok(Err(_)) => return "PROVER_ERR",
                    Ok(Ok(pr)) => pr,
                };
                match catch_unwind(AssertUnwindSafe(|| $m::verify_with(o, &proof, vp))) {
                    Err(_) => "VERIFY_PANIC",
                    Ok(Err(_)) => "VERIFY_FAIL",
                    Ok(Ok(())) => panic!("ACCEPTED a bad statement: {what}"),
                }
            }

            #[test]
            fn honest_verifies() {
                let (o, w, p) = setup();
                let proof = $m::prove_with(&o, &w, &p).unwrap();
                $m::verify_with(&o, &proof, &p).unwrap();
                println!("{}: honest N={} verifies, {} bytes", $m::LABEL, N, $m::to_bytes(&proof).len());
            }

            #[test]
            fn reject_record_value_changed() {
                let (o, w, p) = setup();
                let mut kinds = vec![];
                for t in 0..5usize {
                    let mut wt = w.clone();
                    let mut r = 1 + (t * 211 + 13) % (wt.words.len() - 1);
                    while wt.words[r][7] == 1 {
                        r += 1;
                    }
                    let x = &mut wt.words[r];
                    match t {
                        0 => x[4] ^= 1 << 31,                            // v: predicate flips (v >= theta <-> v < theta)
                        1 => x[4] ^= 1,                                  // v: low bit
                        2 => x[5] ^= 1,                                  // b
                        3 => x[6] = (x[6] + 1) % pqz_plonky3_w38::data::GOLDILOCKS_P, // tag
                        _ => x[2] += 1,                                  // seq
                    }
                    assert_ne!(wt.words[r], w.words[r]);
                    kinds.push(attempt(&o, &wt, &p, &p, &format!("record {r} changed (trial {t})")));
                }
                tally(&format!("{} record value changed", $m::LABEL), &kinds);
            }

            #[test]
            fn reject_claimed_count_changed() {
                let (o, w, p) = setup();
                let (mut kinds, mut kinds2) = (vec![], vec![]);
                let honest = $m::prove_with(&o, &w, &p).unwrap();
                for t in 0..5usize {
                    let mut pb = p.clone();
                    pb.count = if t == 4 { p.count - 1 } else { p.count + 1 + t as u64 };
                    // (i) prover claims the wrong count with the honest witness
                    kinds.push(attempt(&o, &w, &pb, &pb, &format!("claimed count (prover) trial {t}")));
                    // (ii) honest proof checked against a wrong claimed count
                    match $m::verify_with(&o, &honest, &pb) {
                        Ok(()) => panic!("ACCEPTED honest proof for wrong count, trial {t}"),
                        Err(_) => kinds2.push("VERIFY_FAIL"),
                    }
                }
                tally(&format!("{} claimed count changed (wrong claim proved)", $m::LABEL), &kinds);
                tally(&format!("{} claimed count changed (honest proof, wrong claim)", $m::LABEL), &kinds2);
            }

            #[test]
            fn reject_claimed_sum_changed() {
                let (o, w, p) = setup();
                let (mut kinds, mut kinds2) = (vec![], vec![]);
                let honest = $m::prove_with(&o, &w, &p).unwrap();
                for t in 0..5usize {
                    let mut pb = p.clone();
                    let k = t % pb.sum.len();
                    pb.sum[k] = if t == 4 { pb.sum[k] - 1 } else { pb.sum[k] + 1 + t as u64 };
                    kinds.push(attempt(&o, &w, &pb, &pb, &format!("claimed sum (prover) trial {t}")));
                    match $m::verify_with(&o, &honest, &pb) {
                        Ok(()) => panic!("ACCEPTED honest proof for wrong sum, trial {t}"),
                        Err(_) => kinds2.push("VERIFY_FAIL"),
                    }
                }
                tally(&format!("{} claimed sum changed (wrong claim proved)", $m::LABEL), &kinds);
                tally(&format!("{} claimed sum changed (honest proof, wrong claim)", $m::LABEL), &kinds2);
            }

            #[test]
            fn reject_wrong_public_digest() {
                let (o, w, p) = setup();
                let (mut kinds, mut kinds2) = (vec![], vec![]);
                let honest = $m::prove_with(&o, &w, &p).unwrap();
                let ord = <$m::Val as PrimeField64>::ORDER_U64;
                for t in 0..5usize {
                    let mut pb = p.clone();
                    let j = t % pb.digest.len();
                    pb.digest[j] = (pb.digest[j] + 1 + t as u64) % ord;
                    kinds.push(attempt(&o, &w, &pb, &pb, &format!("digest (prover) trial {t}")));
                    match $m::verify_with(&o, &honest, &pb) {
                        Ok(()) => panic!("ACCEPTED honest proof for wrong digest, trial {t}"),
                        Err(_) => kinds2.push("VERIFY_FAIL"),
                    }
                }
                tally(&format!("{} wrong public digest (wrong claim proved)", $m::LABEL), &kinds);
                tally(&format!("{} wrong public digest (honest proof, wrong claim)", $m::LABEL), &kinds2);
            }

            #[test]
            fn reject_proof_byte_flipped() {
                let (o, w, p) = setup();
                let honest = $m::prove_with(&o, &w, &p).unwrap();
                let bytes = $m::to_bytes(&honest);
                let mut kinds = vec![];
                for t in 0..5usize {
                    let mut b = bytes.clone();
                    let pos = bytes.len() * (2 * t + 1) / 10;
                    b[pos] ^= 1 << (t % 8);
                    assert_ne!(b, bytes);
                    match $m::from_bytes(&b) {
                        Err(_) => kinds.push("DESER_FAIL"),
                        Ok(pr) => match catch_unwind(AssertUnwindSafe(|| $m::verify_with(&o, &pr, &p))) {
                            Err(_) => kinds.push("VERIFY_PANIC"),
                            Ok(Err(_)) => kinds.push("VERIFY_FAIL"),
                            Ok(Ok(())) => panic!("ACCEPTED a proof with byte {pos} flipped"),
                        },
                    }
                }
                tally(&format!("{} proof byte flipped", $m::LABEL), &kinds);
            }

            #[test]
            fn reject_fewer_than_40_queries() {
                let (o40, w, p) = setup();
                let mut kinds = vec![];
                for q in [1usize, 10, 20, 30, 39] {
                    let oq = FriOpts { num_queries: q, ..o40.clone() };
                    let proof = $m::prove_with(&oq, &w, &p).unwrap();
                    // the proof is otherwise valid: it verifies under its own (weak) options ...
                    $m::verify_with(&oq, &proof, &p).expect("weak proof must verify under its own options");
                    // ... and is rejected by the strict verifier (40 queries).
                    match catch_unwind(AssertUnwindSafe(|| $m::verify_with(&o40, &proof, &p))) {
                        Err(_) => kinds.push("VERIFY_PANIC"),
                        Ok(Err(_)) => kinds.push("VERIFY_FAIL"),
                        Ok(Ok(())) => panic!("ACCEPTED a proof made with {q} queries"),
                    }
                }
                tally(&format!("{} fewer than 40 queries (1,10,20,30,39)", $m::LABEL), &kinds);
            }

            /// Cell-level tampering of an otherwise honest trace (the strongest check of the AIR: every listed cell
            /// change breaks one constraint family; the verifier must reject each).
            #[test]
            fn reject_tampered_trace_cells() {
                use p3_matrix::dense::RowMajorMatrix;
                let (o, w, p) = setup();
                let a = $m::air(p.theta, p.n_words() as u64);
                let lay = a.lay.clone();
                let pv = p.to_values::<$m::Val>(&lay);
                let good = a.build_trace(&$m::perm(), &$m::words(&w));
                // honest trace verifies
                let cfg = $m::config(&o);
                let pr = p3_uni_stark::prove(&cfg, &a, good.clone(), &pv).unwrap();
                p3_uni_stark::verify(&cfg, &a, &pr, &pv).unwrap();
                // pick the first record row with m = 1 and the first with m = 0
                let hcol = lay.c_word + lay.h();
                let mut r1 = None;
                let mut r0 = None;
                for k in 1..good.height() {
                    let row = &good.values[k * lay.width..(k + 1) * lay.width];
                    if row[hcol] == <$m::Val as p3_field::PrimeCharacteristicRing>::ZERO {
                        if row[lay.c_m] == <$m::Val as p3_field::PrimeCharacteristicRing>::ONE && r1.is_none() {
                            r1 = Some(k);
                        }
                        if row[lay.c_m] == <$m::Val as p3_field::PrimeCharacteristicRing>::ZERO && r0.is_none() {
                            r0 = Some(k);
                        }
                    }
                }
                let (r1, r0) = (r1.unwrap(), r0.unwrap());
                let one = <$m::Val as p3_field::PrimeCharacteristicRing>::ONE;
                let mut cases: Vec<(String, usize, usize, $m::Val)> = vec![];
                let bump = |v: $m::Val| v + one;
                let at = |r: usize, c: usize| good.values[r * lay.width + c];
                cases.push(("m flipped 1->0 (matching row)".into(), r1, lay.c_m, at(r1, lay.c_m) - one));
                cases.push(("m flipped 0->1 (non-matching row)".into(), r0, lay.c_m, at(r0, lay.c_m) + one));
                cases.push(("a bit of d flipped".into(), r1, lay.c_bd + 3, one - at(r1, lay.c_bd + 3)));
                cases.push(("a bit of v flipped".into(), r1, lay.c_bv + 5, one - at(r1, lay.c_bv + 5)));
                cases.push(("bit cell set to 2 (not boolean)".into(), r1, lay.c_bd + 7, one + one));
                cases.push(("cnt +1 at one row".into(), r1, lay.c_cnt, bump(at(r1, lay.c_cnt))));
                cases.push(("sum +1 at one row".into(), r1, lay.c_sum, bump(at(r1, lay.c_sum))));
                cases.push(("idx +1 at one row".into(), r1, lay.c_idx, bump(at(r1, lay.c_idx))));
                cases.push(("word value v +1 (sponge input not changed)".into(), r1, lay.c_word + 4, bump(at(r1, lay.c_word + 4))));
                cases.push(("header flag set on a record row (skip checks)".into(), r1, hcol, one));
                cases.push(("sponge input rate cell +1".into(), r1, 0, bump(at(r1, 0))));
                cases.push(("sponge input capacity cell +1".into(), r1, lay.rate, bump(at(r1, lay.rate))));
                cases.push(("seen flag cleared at last row".into(), good.height() - 1, lay.c_seen, <$m::Val as p3_field::PrimeCharacteristicRing>::ZERO));
                cases.push(("last flag set on a wrong row".into(), r1, lay.c_last, one));
                if lay.c_br != usize::MAX {
                    cases.push(("borrow bit flipped".into(), r1, lay.c_br, one - at(r1, lay.c_br)));
                }
                let mut accepted = vec![];
                for (name, r, c, val) in cases {
                    let mut vals = good.values.clone();
                    assert_ne!(vals[r * lay.width + c], val, "{name}: tamper is a no-op");
                    vals[r * lay.width + c] = val;
                    let tr = RowMajorMatrix::new(vals, lay.width);
                    let res = catch_unwind(AssertUnwindSafe(|| {
                        let pr = p3_uni_stark::prove(&cfg, &a, tr, &pv).map_err(|e| format!("{e:?}"))?;
                        p3_uni_stark::verify(&cfg, &a, &pr, &pv).map_err(|e| format!("{e:?}"))
                    }));
                    let kind = match res {
                        Err(_) => "panic",
                        Ok(Err(_)) => "rejected",
                        Ok(Ok(())) => {
                            accepted.push(name.clone());
                            "ACCEPTED"
                        }
                    };
                    println!("TAMPER {} | {name}: {kind}", $m::LABEL);
                }
                assert!(accepted.is_empty(), "verifier accepted tampered traces: {accepted:?}");
            }

            /// The Poseidon2 columns of the trace hold the reference permutation: output of row k == native perm.
            #[test]
            fn trace_permutation_equals_reference() {
                use p3_poseidon2_air::Poseidon2Cols;
                use core::borrow::Borrow;
                let (_o, w, p) = setup();
                let a = $m::air(p.theta, p.n_words() as u64);
                let lay = a.lay.clone();
                let words = $m::words(&w);
                let tr = a.build_trace(&$m::perm(), &words);
                let (ins, outs) = pqz_plonky3_w38::air::sponge_rows::<$m::Val, { $m::W }, _>(&lay, &$m::perm(), &words, tr.height());
                for k in 0..tr.height() {
                    let row = &tr.values[k * lay.width..k * lay.width + lay.p];
                    let cols: &Poseidon2Cols<$m::Val, { $m::W }, { $m::SBOX }, { $m::REG }, { $m::HF }, { $m::PR }> = row.borrow();
                    assert_eq!(cols.inputs, ins[k], "inputs row {k}");
                    assert_eq!(cols.ending_full_rounds[$m::HF - 1].post, outs[k], "outputs row {k}");
                    assert_eq!(outs[k], $m::perm_ref(ins[k]), "reference perm row {k}");
                }
            }
        }
    };
}

suite!(t_c1, c1);
suite!(t_c1r0, c1r0);
suite!(t_c2, c2);

suite!(t_c1zk, c1zk);
