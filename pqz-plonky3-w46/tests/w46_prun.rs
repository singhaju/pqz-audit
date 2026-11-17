//! w46 tests: PRunAir (R_Exec over a RUN of whole blocks of the PACKED format, from a public s_in to a public s_out).
//! A trial FAILS only if a verifier ACCEPTS something bad (or an honest statement is rejected).
//! Every test is generated twice by a macro: `plain` (c1) and `zk` (c1zk, hiding PCS).

use pqz_plonky3_w46::air::{native_digest, Layout};
use pqz_plonky3_w46::chunk::{iv_state, State};
use pqz_plonky3_w46::data::Workload;
use pqz_plonky3_w46::pair::*;
use pqz_plonky3_w46::pchunk::plain as pc;
use pqz_plonky3_w46::prun::{prun_n_words, prun_values, RunPublic};
use pqz_plonky3_w46::{c1, FriOpts};
use std::panic::{catch_unwind, AssertUnwindSafe};

const THETA: u64 = 1 << 31;
const CTX: [u64; 4] = [1, 2, 3, 4];
const TH_MAX: u64 = (1u64 << 32) - 1;

fn o() -> FriOpts {
    FriOpts::from_env()
}

/// stream of `g` blocks of `b` records, packed
fn stream(g: usize, b: usize, seed: u64) -> (Workload, Vec<Vec<u64>>) {
    let w = Workload::synthetic(g * b, b, seed);
    let words = pack_workload(&w);
    (w, words)
}

/// anchored chunk-end states of the stream with one block per chunk: st[i] = state before block i, st[g] = end state
fn block_states(words: &[Vec<u64>], b: usize) -> Vec<State> {
    let (pubs, _) = pc::honest_publics(words, b, 1);
    let mut v: Vec<State> = pubs.iter().map(|p| p.s_in).collect();
    v.push(pubs.last().unwrap().s_out);
    v
}

fn pair_digest(words: &[Vec<u64>]) -> Vec<u64> {
    native_digest::<c1::Val, 12, _>(&Layout::new(0, 12, 0), &c1::perm(), words)
}

macro_rules! suite {
    ($modname:ident, $m:ident) => {
        mod $modname {
            use super::*;
            use pqz_plonky3_w46::prun::$m as m;

            fn prove_kinds(o: &FriOpts, words: &[Vec<u64>], kinds: &[Kind], p: &RunPublic) -> Result<m::P, String> {
                let a = m::run_air(p)?;
                let trace = a.build_trace_kinds(&m::perm(), words, &p.s_in, kinds);
                let pv = prun_values::<m::Val>(p);
                p3_uni_stark::prove(&m::config(o), &a, trace, &pv).map_err(|e| format!("{e:?}"))
            }

            /// prove `words` (honest kinds by position unless `kinds`) under `pp`, verify under `vp`; panic if ACCEPTED.
            fn must_reject(words: &[Vec<u64>], kinds: Option<&[Kind]>, pp: &RunPublic, vp: &RunPublic, what: &str) -> &'static str {
                let o = o();
                let r = catch_unwind(AssertUnwindSafe(|| match kinds {
                    Some(k) => prove_kinds(&o, words, k, pp),
                    None => m::prove_run(&o, words, pp),
                }));
                let proof = match r {
                    Err(_) => return "PROVER_PANIC",
                    Ok(Err(_)) => return "PROVER_ERR",
                    Ok(Ok(x)) => x,
                };
                match m::verify_run(&o, &proof, vp) {
                    Err(_) => "VERIFY_FAIL",
                    Ok(()) => panic!("ACCEPTED: {what}"),
                }
            }

            fn honest(words: &[Vec<u64>], s_in: &State, b: usize, theta: u64) -> (RunPublic, m::P) {
                let p = m::honest_public(words, s_in, b, theta, CTX);
                let proof = m::prove_run(&o(), words, &p).unwrap_or_else(|e| panic!("prove b={b} theta={theta}: {e}"));
                m::verify_run(&o(), &proof, &p).unwrap_or_else(|e| panic!("honest rejected b={b} theta={theta}: {e}"));
                (p, proof)
            }

            #[test]
            fn honest_whole_stream_matches_pair() {
                for &(g, b) in &[(10usize, 100usize), (100, 7), (10, 1), (10, 2), (7, 5), (3, 99), (1, 64)] {
                    let (w, words) = stream(g, b, 1);
                    let total = words.len() as u64;
                    for theta in [THETA, 1, TH_MAX] {
                        let (p, proof) = honest(&words, &iv_state(total), b, theta);
                        let ep = pair_public(&w, theta, CTX);
                        assert_eq!(&p.s_out[..4], &ep.digest[..], "digest g={g} b={b}");
                        assert_eq!(&p.s_out[..4], &pair_digest(&words)[..]);
                        assert_eq!((p.count, p.sum), (ep.count, ep.sum[0]), "count/sum g={g} b={b} theta={theta}");
                        assert_eq!(p.n_blocks, g);
                        assert_eq!(prun_n_words(&p), words.len());
                        let bytes = m::to_bytes(&proof);
                        m::verify_run_bytes(&o(), &bytes, &p).unwrap();
                    }
                }
            }

            #[test]
            fn honest_subruns_link_to_chunk_states() {
                for &b in &[100usize, 7, 1, 2, 3, 5, 500] {
                    let g = 9;
                    let (w, words) = stream(g, b, 1);
                    let rpb = rows_per_block(b);
                    let st = block_states(&words, b);
                    let (whole, _) = pc::honest_publics(&words, b, g);
                    assert_eq!(whole[0].s_out, st[g]);
                    for theta in [THETA, 1, TH_MAX] {
                        let ep = pair_public(&w, theta, CTX);
                        let runs: &[(usize, usize)] = if theta == THETA { &[(0, 1), (0, 2), (0, 4), (0, 9), (3, 2), (5, 4), (8, 1)] } else { &[(0, 9), (2, 4)] };
                        for &(s, len) in runs {
                            let rw = &words[s * rpb..(s + len) * rpb];
                            let (p, _) = honest(rw, &st[s], b, theta);
                            assert_eq!(p.s_in, st[s]);
                            assert_eq!(p.s_out, st[s + len], "s_out == chunk-end state b={b} run=({s},{len})");
                        }
                        // runs partitioning the stream add up to the whole-stream (count, sum)
                        let (mut c, mut sm) = (0u64, 0u64);
                        for &(s, len) in &[(0usize, 4usize), (4, 1), (5, 4)] {
                            let (p, _) = honest(&words[s * rpb..(s + len) * rpb], &st[s], b, theta);
                            c += p.count;
                            sm += p.sum;
                        }
                        assert_eq!((c, sm), (ep.count, ep.sum[0]), "partition b={b} theta={theta}");
                    }
                }
            }

            #[test]
            fn rejects_wrong_statements() {
                for &b in &[100usize, 7] {
                    let (_, words) = stream(9, b, 1);
                    let rpb = rows_per_block(b);
                    let st = block_states(&words, b);
                    let (s, len) = (2usize, 4usize);
                    let rw = &words[s * rpb..(s + len) * rpb];
                    let (p, proof) = honest(rw, &st[s], b, THETA);
                    let bump = |mut x: State, i: usize| {
                        x[i] += 1;
                        x
                    };
                    let mut hf = p.hdr_first;
                    hf[3] += 1;
                    let mut hf0 = p.hdr_first;
                    hf0[0] += 1;
                    let cases: Vec<(&str, RunPublic)> = vec![
                        ("count+1", RunPublic { count: p.count + 1, ..p.clone() }),
                        ("count-1", RunPublic { count: p.count - 1, ..p.clone() }),
                        ("sum+1", RunPublic { sum: p.sum + 1, ..p.clone() }),
                        ("theta/2", RunPublic { theta: THETA / 2, ..p.clone() }),
                        ("theta max", RunPublic { theta: TH_MAX, ..p.clone() }),
                        ("s_in[0]", RunPublic { s_in: bump(p.s_in, 0), ..p.clone() }),
                        ("s_in[9] (capacity)", RunPublic { s_in: bump(p.s_in, 9), ..p.clone() }),
                        ("s_out[0]", RunPublic { s_out: bump(p.s_out, 0), ..p.clone() }),
                        ("s_out[3]", RunPublic { s_out: bump(p.s_out, 3), ..p.clone() }),
                        ("s_out[8] (capacity)", RunPublic { s_out: bump(p.s_out, 8), ..p.clone() }),
                        ("s_out[11] (capacity)", RunPublic { s_out: bump(p.s_out, 11), ..p.clone() }),
                        ("hdr_first[3]", RunPublic { hdr_first: hf, ..p.clone() }),
                        ("hdr_first[0]", RunPublic { hdr_first: hf0, ..p.clone() }),
                        ("block_size+1", RunPublic { block_size: b + 1, ..p.clone() }),
                        ("n_blocks+1", RunPublic { n_blocks: len + 1, ..p.clone() }),
                        ("n_blocks-1", RunPublic { n_blocks: len - 1, ..p.clone() }),
                    ];
                    let honest_kinds = kinds_by_position(rw.len(), b);
                    for th in [THETA / 2, TH_MAX] {
                        // the wrong theta must really change the honest answer, else it is a true statement
                        let t = m::honest_public(rw, &st[s], b, th, CTX);
                        assert!((t.count, t.sum) != (p.count, p.sum), "test data: theta {th} gives the same answer");
                    }
                    for (what, q) in &cases {
                        // (1) honest proof against the wrong statement
                        let r = catch_unwind(AssertUnwindSafe(|| m::verify_run(&o(), &proof, q)));
                        assert!(!matches!(r, Ok(Ok(()))), "ACCEPTED honest proof under wrong statement {what} b={b}");
                        // (2) prover uses the wrong statement too (public values consistent on both sides): only the AIR constraints can reject
                        let r1 = must_reject(rw, None, q, q, &format!("prover+verifier wrong {what} b={b}"));
                        let r2 = must_reject(rw, Some(&honest_kinds), q, q, &format!("honest kinds, wrong {what} b={b}"));
                        eprintln!("{what} b={b}: own-statement {r1}, honest kinds {r2}");
                    }
                    // ctx is a public value only: the AIR accepts a different ctx (checked natively by the requester, as run.rs)
                    let q = RunPublic { ctx: [9, 9, 9, 9], ..p.clone() };
                    let pr = m::prove_run(&o(), rw, &q).unwrap();
                    m::verify_run(&o(), &pr, &q).expect("AIR accepts any ctx (ctx is native-only)");
                    assert!(m::verify_run(&o(), &proof, &q).is_err(), "a proof is bound to its own public values (ctx) through the transcript");
                }
            }

            /// Word tampering. (i) honest statement, tampered words: the digest differs. (ii) statement recomputed for the tampered stream:
            /// grammar rules reject structure changes; value changes inside the grammar are ACCEPTED by the AIR but give an s_out different
            /// from the anchored chunk-end state, so the chunk link rejects them (asserted via s_out != anchored state).
            #[test]
            fn rejects_tampered_words() {
                for &b in &[100usize, 7, 1, 2] {
                    let g = 9;
                    let (_, words) = stream(g, b, 1);
                    let rpb = rows_per_block(b);
                    let st = block_states(&words, b);
                    let (s, len) = (2usize, 4usize);
                    let rw: Vec<Vec<u64>> = words[s * rpb..(s + len) * rpb].to_vec();
                    let p = m::honest_public(&rw, &st[s], b, THETA, CTX);
                    // a record row of block 1 of the run (full row unless b == 1)
                    let row = rpb + 1;
                    for (what, slot) in [("id_a", 0usize), ("v_a", 1), ("b_a", 2), ("tag_a", 3), ("id_b", 4), ("v_b", 5), ("b_b", 6), ("tag_b", 7)] {
                        if slot >= 4 && b == 1 {
                            continue;
                        }
                        let mut tw = rw.clone();
                        tw[row][slot] += 1;
                        let r = must_reject(&tw, None, &p, &p, &format!("tamper {what} b={b} under honest statement"));
                        let q = m::honest_public(&tw, &st[s], b, THETA, CTX);
                        assert_ne!(q.s_out, st[s + len], "tampered stream must change the end state ({what})");
                        let res = catch_unwind(AssertUnwindSafe(|| m::prove_run(&o(), &tw, &q).map(|pr| m::verify_run(&o(), &pr, &q).is_ok())));
                        let air_accepts = matches!(res, Ok(Ok(true)));
                        eprintln!("tamper {what} b={b}: honest stmt {r}; recomputed stmt: AIR accepts = {air_accepts} (end state != anchored state: link rejects)");
                    }
                    // swapped halves (needs a full row: b >= 2)
                    if b >= 2 {
                        let mut tw = rw.clone();
                        let (a, bb): (Vec<u64>, Vec<u64>) = (tw[row][..4].to_vec(), tw[row][4..].to_vec());
                        tw[row][..4].copy_from_slice(&bb);
                        tw[row][4..].copy_from_slice(&a);
                        must_reject(&tw, None, &p, &p, &format!("swapped halves b={b}"));
                        let q = m::honest_public(&tw, &st[s], b, THETA, CTX);
                        assert_ne!(q.s_out, st[s + len]);
                    }
                    // non-zero empty half b (odd b): the last row of every block has an empty half b
                    if b % 2 == 1 {
                        for slot in [4usize, 5, 6, 7] {
                            let mut tw = rw.clone();
                            let r = 2 * rpb - 1; // last row of block 1
                            tw[r][slot] = 3;
                            must_reject(&tw, None, &p, &p, &format!("nonzero empty half b slot {slot} b={b}"));
                            let q = m::honest_public(&tw, &st[s], b, THETA, CTX);
                            must_reject(&tw, None, &q, &q, &format!("nonzero empty half b slot {slot}, recomputed statement, b={b}"));
                        }
                    }
                    // moved header: swap the header of block 1 with its first record row
                    {
                        let mut tw = rw.clone();
                        tw.swap(rpb, rpb + 1);
                        must_reject(&tw, None, &p, &p, &format!("moved header b={b}"));
                        let q = m::honest_public(&tw, &st[s], b, THETA, CTX);
                        must_reject(&tw, None, &q, &q, &format!("moved header, recomputed statement, b={b}"));
                        // with hand-made kinds that follow the moved header (what a cheating prover would try)
                        let mut kinds = kinds_by_position(tw.len(), b);
                        kinds.swap(rpb, rpb + 1);
                        must_reject(&tw, Some(&kinds), &q, &q, &format!("moved header with matching kinds b={b}"));
                    }
                    // run that starts mid-block: the first word is a record row; statement as honest as possible for that stream
                    {
                        let s_mid = pqz_plonky3_w46::chunk::state_after::<m::Val, 12, _>(&m::perm(), &st[s], &rw[..1]);
                        let take = (len - 1) * rpb;
                        let mw: Vec<Vec<u64>> = rw[1..1 + take].to_vec();
                        let kk = kinds_by_position(mw.len(), b);
                        let (mut count, mut sum) = (0u64, 0u64);
                        for (w, k) in mw.iter().zip(&kk) {
                            if k.va && w[1] >= THETA {
                                count += 1;
                                sum += w[2];
                            }
                            if k.vb && w[5] >= THETA {
                                count += 1;
                                sum += w[6];
                            }
                        }
                        let mut hdr_first = [0u64; 8];
                        hdr_first.copy_from_slice(&mw[0][..8]);
                        let q = RunPublic {
                            s_in: s_mid,
                            s_out: pqz_plonky3_w46::chunk::state_after::<m::Val, 12, _>(&m::perm(), &s_mid, &mw),
                            hdr_first,
                            n_blocks: len - 1,
                            block_size: b,
                            theta: THETA,
                            count,
                            sum,
                            ctx: CTX,
                        };
                        must_reject(&mw, None, &q, &q, &format!("run starting mid-block b={b}"));
                    }
                    // one record word removed (statement s_out recomputed for the shorter stream)
                    {
                        let mut tw = rw.clone();
                        tw.remove(rpb + 1);
                        let mut q = p.clone();
                        q.s_out = pqz_plonky3_w46::chunk::state_after::<m::Val, 12, _>(&m::perm(), &st[s], &tw);
                        must_reject(&tw, None, &q, &q, &format!("record word removed, full-size statement b={b}"));
                        let mut q2 = q.clone();
                        q2.n_blocks = len - 1;
                        must_reject(&tw, None, &q2, &q2, &format!("record word removed, n_blocks-1 b={b}"));
                        // hand-made kinds that drop one record row inside block 1 (the countdown never reaches 0 there)
                        let mut kinds = kinds_by_position(rw.len(), b);
                        kinds.remove(rpb + 1);
                        must_reject(&tw, Some(&kinds), &q, &q, &format!("record word removed with matching kinds b={b}"));
                    }
                }
            }

            /// P2r property: v = 2^32 + 5 (theta = 2^31) is classified as a match by this AIR (v - theta < 2^32); the packed chunk RANGE check
            /// rejects the stream. Soundness of this relation therefore depends on the chunk proofs.
            #[test]
            fn v_2_32_accepted_by_prun_rejected_by_chunk_range() {
                for &b in &[100usize, 7, 2] {
                    let (_, mut words) = stream(4, b, 1);
                    let rpb = rows_per_block(b);
                    words[rpb + 1][1] = (1u64 << 32) + 5;
                    let (pubs, _) = pc::honest_publics(&words, b, 4);
                    let p = m::honest_public(&words, &iv_state(words.len() as u64), b, THETA, CTX);
                    assert_eq!(p.s_out, pubs[0].s_out);
                    let proof = m::prove_run(&o(), &words, &p).expect("prun proves v = 2^32+5");
                    m::verify_run(&o(), &proof, &p).expect("prun ACCEPTS v = 2^32+5 as a match (documented P2r property)");
                    let r = catch_unwind(AssertUnwindSafe(|| pc::prove_chunk(&o(), &words, &pubs[0]).and_then(|pr| pc::verify_chunk(&o(), &pr, &pubs[0]))));
                    assert!(!matches!(r, Ok(Ok(()))), "chunk range check must reject v = 2^32+5 (b={b})");
                }
            }

            #[test]
            fn bytes_api_par_trace_and_cross_pcs() {
                let (_, words) = stream(4, 100, 1);
                let p = m::honest_public(&words, &iv_state(words.len() as u64), 100, THETA, CTX);
                let (bytes, ts, ps, rows) = m::prove_run_bytes(&o(), &words, &p).unwrap();
                assert!(ts >= 0.0 && ps > 0.0 && rows == m::run_rows(words.len()));
                m::verify_run_bytes(&o(), &bytes, &p).unwrap();
                let (b2, _, _, rows2) = m::prove_run_bytes_par(&o(), &words, &p).unwrap();
                m::verify_run_bytes(&o(), &b2, &p).unwrap();
                assert_eq!(rows2, rows);
                // the other PCS rejects these bytes (parse error or verification failure)
                let other = catch_unwind(AssertUnwindSafe(|| {
                    if stringify!($m) == "plain" {
                        pqz_plonky3_w46::prun::zk::verify_run_bytes(&o(), &bytes, &p)
                    } else {
                        pqz_plonky3_w46::prun::plain::verify_run_bytes(&o(), &bytes, &p)
                    }
                }));
                assert!(!matches!(other, Ok(Ok(()))), "cross-PCS proof accepted");
            }

            #[test]
            fn par_trace_equals_seq_trace() {
                for &b in &[100usize, 7, 1] {
                    let (_, words) = stream(9, b, 1);
                    let rpb = rows_per_block(b);
                    let st = block_states(&words, b);
                    let rw = &words[3 * rpb..8 * rpb];
                    let p = m::honest_public(rw, &st[3], b, THETA, CTX);
                    let a = m::run_air(&p).unwrap();
                    let n_rows = a.n_rows_for(rw);
                    let ck = pqz_plonky3_w46::chunk::sponge_checkpoints_from::<m::Val, 12, _>(&m::perm(), &p.s_in, rw, n_rows, 16);
                    let t1 = a.build_trace(&m::perm(), rw, &p.s_in, b);
                    let t2 = a.build_trace_par(&m::perm(), rw, b, &ck);
                    assert!(t1.values == t2.values, "par trace differs b={b}");
                }
            }

            // ---------------- extra tests (independent review) ----------------

            /// prove an edited trace (the prover may write anything into the trace), verify under `vp`; panic if ACCEPTED.
            fn edit_must_reject(words: &[Vec<u64>], p: &RunPublic, vp: &RunPublic, what: &str, edit: impl FnOnce(&mut Vec<m::Val>, usize, &pqz_plonky3_w46::pair::PLayout)) {
                let o = o();
                let a = m::run_air(p).unwrap();
                let mut trace = a.build_trace(&m::perm(), words, &p.s_in, p.block_size);
                let w = trace.width;
                edit(&mut trace.values, w, &a.lay.cols);
                let pv = prun_values::<m::Val>(p);
                let r = catch_unwind(AssertUnwindSafe(|| p3_uni_stark::prove(&m::config(&o), &a, trace, &pv).map_err(|e| format!("{e:?}"))));
                let proof = match r {
                    Err(_) | Ok(Err(_)) => return,
                    Ok(Ok(x)) => x,
                };
                if m::verify_run(&o, &proof, vp).is_ok() {
                    panic!("ACCEPTED: {what}");
                }
            }

            #[test]
            fn power_of_two_unpadded_trace() {
                let b = 14usize; // 8 rows per block
                let g = (m::MIN_TRACE_ROWS / 8).max(16);
                let (_, words) = stream(g, b, 1);
                assert!(words.len().is_power_of_two() && words.len() >= m::MIN_TRACE_ROWS && words.len() > 64);
                let (p, _) = honest(&words, &iv_state(words.len() as u64), b, THETA);
                assert_eq!(m::run_rows(words.len()), words.len(), "no pad rows");
                for (what, q) in [("count+1", RunPublic { count: p.count + 1, ..p.clone() }), ("count-1", RunPublic { count: p.count - 1, ..p.clone() }), ("sum+1", RunPublic { sum: p.sum + 1, ..p.clone() })] {
                    must_reject(&words, None, &q, &q, what);
                }
            }

            #[test]
            fn rejects_short_row_in_middle() {
                let b = 8usize; // 4 record rows per block
                let (_, words) = stream(3, b, 1);
                let rpb = rows_per_block(b);
                let p = m::honest_public(&words, &iv_state(words.len() as u64), b, THETA, CTX);
                for r in [1usize, 2, 3] {
                    // vb = 0 on a non-final record row of block 0 (and of block 1)
                    for blk in [0usize, 1] {
                        let row = blk * rpb + r;
                        let mut kinds = kinds_by_position(words.len(), b);
                        kinds[row].vb = false;
                        must_reject(&words, Some(&kinds), &p, &p, &format!("vb=0 on middle row {row}"));
                        // also with half b zeroed (then the stream changes: statement recomputed for it)
                        let mut tw = words.clone();
                        for i in 4..8 {
                            tw[row][i] = 0;
                        }
                        let q = m::honest_public(&tw, &iv_state(tw.len() as u64), b, THETA, CTX);
                        must_reject(&tw, Some(&kinds), &q, &q, &format!("vb=0, half b zeroed, middle row {row}"));
                    }
                }
            }

            #[test]
            fn rejects_extra_record_rows_and_header_relabelled() {
                // (a) B=2, two blocks [H0,R0,H1,R1]: label H1 as a record row (extra record row, header skipped)
                let (_, words) = stream(2, 2, 1);
                let p = m::honest_public(&words, &iv_state(words.len() as u64), 2, THETA, CTX);
                let mut kinds = kinds_by_position(words.len(), 2);
                kinds[2] = Kind { hdr: false, va: true, vb: true };
                must_reject(&words, Some(&kinds), &p, &p, "header word labelled as record row");
                // (b) B=1, [H0, R0*, H1, R1], R0* is a record word that looks like a header (w2 = B = 1, w7 = 1) and matches (v >= theta);
                // kinds [hdr, hdr, hdr, va]: the matching record is skipped; statement counts only R1.
                let (_, mut w1) = stream(2, 1, 1);
                w1[1] = vec![w1[1][0], THETA + 7, 1, w1[1][3], 0, 0, 0, 1];
                w1[3][1] = 5; // R1 not a match
                let mut q = m::honest_public(&w1, &iv_state(w1.len() as u64), 1, THETA, CTX);
                let honest_count = q.count;
                q.count = 0;
                q.sum = 0; // statement "without that record"
                let kinds = [Kind { hdr: true, va: false, vb: false }, Kind { hdr: true, va: false, vb: false }, Kind { hdr: true, va: false, vb: false }, Kind { hdr: false, va: true, vb: false }];
                must_reject(&w1, Some(&kinds), &q, &q, "record relabelled as header, skipped from count");
                assert_eq!(honest_count, 1);
                // (the honest parse of these words is itself rejected: a short row needs an all-zero half b, but R0* has tag_b = 1)
            }

            #[test]
            fn rejects_early_pad_and_last_selector_tampering() {
                let b = 100usize;
                let (_, words) = stream(3, b, 1); // 153 words -> 256 rows, 103 pad rows
                let p = m::honest_public(&words, &iv_state(words.len() as u64), b, THETA, CTX);
                let n = words.len();
                // pad row before n_words - 1: seen = 1 from row 40 on
                edit_must_reject(&words, &p, &p, "early pad (seen=1 from row 40)", |v, w, l| {
                    for r in 40..256 {
                        v[r * w + l.c_seen] = m::Val::new(1);
                    }
                });
                edit_must_reject(&words, &p, &p, "early pad, seen=1 on row 40 only", |v, w, l| v[40 * w + l.c_seen] = m::Val::new(1));
                // last = 0 everywhere
                edit_must_reject(&words, &p, &p, "last = 0 everywhere", |v, w, l| v[(n - 1) * w + l.c_last] = m::Val::new(0));
                edit_must_reject(&words, &p, &p, "last = 0 everywhere, inv arbitrary", |v, w, l| {
                    v[(n - 1) * w + l.c_last] = m::Val::new(0);
                    v[(n - 1) * w + l.c_inv] = m::Val::new(1);
                });
                // last = 1 on two rows
                edit_must_reject(&words, &p, &p, "last = 1 on rows 0 and n-1", |v, w, l| v[l.c_last] = m::Val::new(1));
                edit_must_reject(&words, &p, &p, "last = 1 on row n-5 and n-1", |v, w, l| v[(n - 5) * w + l.c_last] = m::Val::new(1));
            }

            #[test]
            fn rejects_count_selector_tampering() {
                let b = 100usize;
                let (_, words) = stream(3, b, 1);
                let p = m::honest_public(&words, &iv_state(words.len() as u64), b, THETA, CTX);
                let kinds = kinds_by_position(words.len(), b);
                let n = words.len();
                // a matching record row (half a) and a non-matching one
                let rm = words.iter().zip(&kinds).position(|(w, k)| k.va && w[1] >= THETA).unwrap();
                let rn = words.iter().zip(&kinds).position(|(w, k)| k.va && w[1] < THETA).unwrap();
                // count a header row: ma = 1 on row 0 (cnt consistently +1 afterwards, statement count+1)
                let q = RunPublic { count: p.count + 1, ..p.clone() };
                edit_must_reject(&words, &p, &q, "count a header row (ma=1, cnt+1 consistent)", |v, w, l| {
                    v[l.c_ma] = m::Val::new(1);
                    for r in 0..256 {
                        let x = v[r * w + l.c_cnt];
                        v[r * w + l.c_cnt] = x + m::Val::new(1);
                    }
                });
                // skip a matching record: m = 0 (cnt, sum consistently lower afterwards), statement count-1, sum-b
                let bsl = words[rm][2];
                let q = RunPublic { count: p.count - 1, sum: p.sum - bsl, ..p.clone() };
                edit_must_reject(&words, &p, &q, "skip matching record with m=0", |v, w, l| {
                    v[rm * w + l.c_ma] = m::Val::new(0);
                    for r in rm..256 {
                        let (c, s) = (v[r * w + l.c_cnt], v[r * w + l.c_sum]);
                        v[r * w + l.c_cnt] = c - m::Val::new(1);
                        v[r * w + l.c_sum] = s - m::Val::new(bsl);
                    }
                });
                // double count: cnt jumps by one extra on a non-matching row, statement count+1
                let q = RunPublic { count: p.count + 1, ..p.clone() };
                edit_must_reject(&words, &p, &q, "double count (cnt +1 extra from a non-matching row)", |v, w, l| {
                    for r in rn..256 {
                        let c = v[r * w + l.c_cnt];
                        v[r * w + l.c_cnt] = c + m::Val::new(1);
                    }
                });
                // mb set on a row whose half b is not valid (last row of odd block would need odd b; use header row)
                edit_must_reject(&words, &p, &p, "mb=1 on a header row", |v, w, l| v[l.c_mb] = m::Val::new(1));
                let _ = n;
            }

            /// Documentation test: v = p - 1 (Goldilocks, a field element that is not a 32-bit value) is classified m = 0 (non-match) and
            /// ACCEPTED by prun alone (d = theta - 1 - v = theta mod p fits 32 bits); the packed chunk proof rejects the word (v < 2^32 check).
            #[test]
            fn prun_range_wrap_false_negative() {
                let pmod: u64 = 0xFFFF_FFFF_0000_0001;
                for &b in &[100usize, 7] {
                    let (_, orig) = stream(4, b, 1);
                    let rpb = rows_per_block(b);
                    let kinds = kinds_by_position(orig.len(), b);
                    let row = orig.iter().zip(&kinds).position(|(w, k)| k.va && w[1] < THETA).unwrap();
                    let p0 = m::honest_public(&orig, &iv_state(orig.len() as u64), b, THETA, CTX);
                    let mut words = orig.clone();
                    let bsl = words[row][2];
                    words[row][1] = pmod - 1;
                    // statement: original count/sum (the word is a non-match), s_out of the changed stream
                    let p = RunPublic { s_out: pqz_plonky3_w46::chunk::state_after::<m::Val, 12, _>(&m::perm(), &p0.s_in, &words), ..p0.clone() };
                    // the honest trace builder classifies the u64 v = p-1 as a match; the dishonest prover writes the m = 0 witness:
                    // d = theta - 1 - v = theta (mod p) fits 32 bits, and cnt / sum do not count the row.
                    let a = m::run_air(&p).unwrap();
                    let mut trace = a.build_trace(&m::perm(), &words, &p.s_in, b);
                    let w = trace.width;
                    let l = &a.lay.cols;
                    trace.values[row * w + l.c_ma] = m::Val::new(0);
                    for i in 0..32 {
                        trace.values[row * w + l.c_bda + i] = m::Val::new((THETA >> i) & 1);
                    }
                    for r in row..(trace.values.len() / w) {
                        let (c, sm) = (trace.values[r * w + l.c_cnt], trace.values[r * w + l.c_sum]);
                        trace.values[r * w + l.c_cnt] = c - m::Val::new(1);
                        trace.values[r * w + l.c_sum] = sm - m::Val::new(bsl);
                    }
                    let pv = prun_values::<m::Val>(&p);
                    let proof = p3_uni_stark::prove(&m::config(&o()), &a, trace, &pv).expect("prove");
                    m::verify_run(&o(), &proof, &p).expect("prun ACCEPTS v = p-1 as a non-match (documented; chunk range check rejects it)");
                    let (pubs, _) = pc::honest_publics(&words, b, 4);
                    let r = catch_unwind(AssertUnwindSafe(|| pc::prove_chunk(&o(), &words, &pubs[0]).and_then(|pr| pc::verify_chunk(&o(), &pr, &pubs[0]))));
                    assert!(!matches!(r, Ok(Ok(()))), "chunk range check must reject v = p-1 (b={b})");
                    let _ = rpb;
                }
            }
        }
    };
}

suite!(plain_tests, plain);
suite!(zk_tests, zk);
