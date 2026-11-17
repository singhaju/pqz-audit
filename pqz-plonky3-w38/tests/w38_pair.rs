//! w38 P2 / P2r tests: honest proofs of the packed format (two records per absorbed word) and rejection of tampering.
//! Run with `cargo test --release` (in debug the prover's constraint checker panics on a bad trace; that still counts as a rejection).
//! A trial FAILS only if the verifier ACCEPTS a bad statement / proof.

use p3_matrix::Matrix;
use pqz_plonky3_w38::air::ExecPublic;
use pqz_plonky3_w38::data::Workload;
use pqz_plonky3_w38::pair::*;
use pqz_plonky3_w38::{c1, FriOpts};
use std::panic::{catch_unwind, AssertUnwindSafe};

const THETA: u64 = 1 << 31;
const CTX: [u64; 4] = [1, 2, 3, 4];

/// plain Rust reference computed from the PACKED words with the honest parse (independent of the circuit and of data.rs)
fn reference_from_packed(words: &[Vec<u64>], block: usize, theta: u64) -> (u64, u64) {
    let (mut cnt, mut sum) = (0u64, 0u64);
    let rpb = rows_per_block(block);
    for (k, w) in words.iter().enumerate() {
        let pos = k % rpb;
        if pos == 0 {
            assert_eq!(w[7], 1);
            assert_eq!(w[2] as usize, block);
            continue;
        }
        let nrec_in_row = if pos * 2 <= block { 2 } else { 1 };
        for h in 0..nrec_in_row {
            let (v, b) = (w[4 * h + 1], w[4 * h + 2]);
            if v >= theta {
                cnt += 1;
                sum += b;
            }
        }
    }
    (cnt, sum)
}

fn outcome(r: std::thread::Result<Result<c1::P, String>>, o: &FriOpts, vp: &ExecPublic, f: Fmt, what: &str) -> &'static str {
    let proof = match r {
        Err(_) => return "PROVER_PANIC",
        Ok(Err(_)) => return "PROVER_ERR",
        Ok(Ok(p)) => p,
    };
    match catch_unwind(AssertUnwindSafe(|| verify_pair(o, &proof, vp, f))) {
        Err(_) => "VERIFY_PANIC",
        Ok(Err(_)) => "VERIFY_FAIL",
        Ok(Ok(())) => panic!("ACCEPTED a bad statement/proof: {what}"),
    }
}
fn attempt_words(o: &FriOpts, words: &[Vec<u64>], pp: &ExecPublic, vp: &ExecPublic, f: Fmt, what: &str) -> &'static str {
    outcome(catch_unwind(AssertUnwindSafe(|| prove_pair_words(o, words, pp, f))), o, vp, f, what)
}
fn attempt_kinds(o: &FriOpts, words: &[Vec<u64>], kinds: &[Kind], pp: &ExecPublic, vp: &ExecPublic, f: Fmt, what: &str) -> &'static str {
    outcome(catch_unwind(AssertUnwindSafe(|| prove_pair_kinds(o, words, kinds, pp, f))), o, vp, f, what)
}
/// public statement of a (possibly tampered) packed stream: digest from the stream, count/sum from the HONEST parse of it
fn public_of_words(words: &[Vec<u64>], w: &Workload, theta: u64) -> ExecPublic {
    let lay0 = pqz_plonky3_w38::air::Layout::new(0, 12, 0);
    let digest = pqz_plonky3_w38::air::native_digest::<c1::Val, 12, _>(&lay0, &c1::perm(), words);
    let (count, s) = reference_from_packed(words, w.block_size, theta);
    ExecPublic { digest, n_blocks: w.n_blocks, block_size: w.block_size, theta, count, sum: vec![s], ctx: CTX }
}

const CASES: [(usize, usize); 9] = [(1000, 100), (700, 7), (990, 99), (10, 1), (20, 2), (30, 3), (35, 5), (64, 64), (101, 101)];

fn honest_case(f: Fmt) {
    let o = FriOpts::from_env();
    for &(n, b) in &CASES {
        let w = Workload::synthetic(n, b, 1);
        let words = pack_workload(&w);
        assert_eq!(words.len(), pair_n_words(w.n_blocks, b));
        for (k, wd) in words.iter().enumerate() {
            let pos = k % rows_per_block(b);
            if pos > 0 && pos * 2 > b {
                assert!(wd[4..8].iter().all(|&x| x == 0), "empty half must be zero");
            }
        }
        let p = pair_public(&w, THETA, CTX);
        // plain Rust reference from the packed words equals the data.rs reference (same records)
        let (rc, rs) = reference_from_packed(&words, b, THETA);
        assert_eq!((rc, rs), w.reference_result(THETA), "packing lost or added a record, n={n} b={b}");
        assert_eq!((p.count, p.sum[0]), (rc, rs));
        let proof = prove_pair(&o, &w, &p, f).unwrap_or_else(|e| panic!("honest prove failed n={n} b={b}: {e}"));
        verify_pair(&o, &proof, &p, f).unwrap_or_else(|e| panic!("honest verify failed n={n} b={b} {f:?}: {e}"));
        // theta variants: low and high thresholds
        for th in [1u64, (1 << 32) - 1] {
            let pt = pair_public(&w, th, CTX);
            let pr = prove_pair(&o, &w, &pt, f).unwrap();
            verify_pair(&o, &pr, &pt, f).unwrap();
        }
        println!("{f:?} honest n={n} b={b}: rows={} count={rc} sum={rs} bytes={}", pair_n_rows(words.len()), c1::to_bytes(&proof).len());
    }
}

#[test]
fn p2_honest_verifies_and_matches_reference() {
    honest_case(Fmt::P2);
}
#[test]
fn p2r_honest_verifies_and_matches_reference() {
    honest_case(Fmt::P2r);
}

#[test]
fn trace_dimensions() {
    // packed trace is about half the rows of the unpacked stream
    let w = Workload::synthetic(1000, 100, 1);
    let words = pack_workload(&w);
    assert_eq!(words.len(), 10 * 51);
    assert_eq!(w.words.len(), 10 * 101);
    let a = pair_air(THETA, words.len() as u64, Fmt::P2);
    let t = a.build_trace(&c1::perm(), &words, 100);
    assert_eq!(t.height(), 512); // 510 packed words (unpacked: 1010 words -> 1024 rows)
    assert_eq!(t.width(), pair_width(Fmt::P2));
    assert_eq!(pair_width(Fmt::P2) - pair_width(Fmt::P2r), 64);
}

#[test]
fn parallel_trace_equals_sequential() {
    use p3_matrix::dense::RowMajorMatrix;
    for &(n, b) in &[(700usize, 7usize), (1000, 100), (990, 99)] {
        let w = Workload::synthetic(n, b, 1);
        let words = pack_workload(&w);
        let a = pair_air(THETA, words.len() as u64, Fmt::P2);
        let seq: RowMajorMatrix<_> = a.build_trace(&c1::perm(), &words, b);
        for k in [1usize, 7, 64, 100, 1024] {
            let ck = pair_checkpoints(&words, pair_n_rows(words.len()), k);
            let par = a.build_trace_par(&c1::perm(), &words, b, &ck);
            assert!(seq.values == par.values, "parallel trace differs n={n} b={b} k={k}");
        }
    }
}

fn tamper_suite(f: Fmt, n: usize, b: usize) {
    let o = FriOpts::from_env();
    let w = Workload::synthetic(n, b, 1);
    let words = pack_workload(&w);
    let p = pair_public(&w, THETA, CTX);
    let proof = prove_pair(&o, &w, &p, f).unwrap();
    verify_pair(&o, &proof, &p, f).expect("honest must verify");
    let mut kinds_seen = vec![];
    let mut rec = |k: &'static str, s: &str| {
        println!("REJECT {f:?} n={n} b={b} {s}: {k}");
        kinds_seen.push(k);
    };

    // --- wrong statements against an honest proof
    for (s, q) in [
        ("count+1", ExecPublic { count: p.count + 1, ..p.clone() }),
        ("count-1", ExecPublic { count: p.count - 1, ..p.clone() }),
        ("sum+1", ExecPublic { sum: vec![p.sum[0] + 1], ..p.clone() }),
        ("theta+1", ExecPublic { theta: THETA + 1, ..p.clone() }),
        ("ctx", ExecPublic { ctx: [9, 2, 3, 4], ..p.clone() }),
        ("block size", ExecPublic { block_size: b + 1, ..p.clone() }),
        ("n_blocks", ExecPublic { n_blocks: w.n_blocks + 1, ..p.clone() }),
    ] {
        match catch_unwind(AssertUnwindSafe(|| verify_pair(&o, &proof, &q, f))) {
            Ok(Ok(())) => panic!("ACCEPTED wrong statement {s}"),
            _ => rec("VERIFY_FAIL", s),
        }
    }
    // digest of another stream
    {
        let w2 = Workload::synthetic(n, b, 2);
        let q = ExecPublic { digest: pair_public(&w2, THETA, CTX).digest, ..p.clone() };
        assert!(verify_pair(&o, &proof, &q, f).is_err(), "accepted digest of another stream");
        rec("VERIFY_FAIL", "digest of another stream");
        // also: prove the other stream but claim our digest
        let r = attempt_words(&o, &pack_workload(&w2), &p, &p, f, "other stream, our statement");
        rec(r, "other stream under our statement");
    }

    // --- a dishonest witness under the honest statement
    let rpb = rows_per_block(b);
    let r1 = if words.len() > rpb + 1 { rpb + 1 } else { 1 }; // a record row of block 1 (or block 0)
    let mutate = |f: &dyn Fn(&mut Vec<Vec<u64>>)| {
        let mut x = words.clone();
        f(&mut x);
        assert_ne!(x, words);
        x
    };
    let cases: Vec<(&str, Vec<Vec<u64>>)> = vec![
        ("v_a flipped (predicate)", mutate(&|x| x[r1][1] ^= 1 << 31)),
        ("v_a low bit", mutate(&|x| x[r1][1] ^= 1)),
        ("b_a", mutate(&|x| x[r1][2] += 1)),
        ("tag_a", mutate(&|x| x[r1][3] += 1)),
        ("id_a", mutate(&|x| x[r1][0] += 1)),
        ("v_b flipped (predicate)", if b >= 2 { mutate(&|x| x[r1][5] ^= 1 << 31) } else { mutate(&|x| x[r1][1] ^= 3) }),
        ("b_b", if b >= 2 { mutate(&|x| x[r1][6] += 1) } else { mutate(&|x| x[r1][2] += 3) }),
        ("tag_b", if b >= 2 { mutate(&|x| x[r1][7] += 1) } else { mutate(&|x| x[r1][3] += 3) }),
        ("id_b", if b >= 2 { mutate(&|x| x[r1][4] += 1) } else { mutate(&|x| x[r1][0] += 3) }),
        ("halves swapped", if b >= 2 { mutate(&|x| { let w = &mut x[r1]; for i in 0..4 { w.swap(i, i + 4); } }) } else { mutate(&|x| x[r1][1] ^= 5) }),
        ("two record words swapped", if rpb > 3 { mutate(&|x| x.swap(r1, r1 + 1)) } else { mutate(&|x| x[r1][1] ^= 7) }),
        ("header changed (m_g)", mutate(&|x| x[0][2] += 1)),
        ("header changed (pid)", mutate(&|x| x[0][3] += 1)),
        ("header flag slot", mutate(&|x| x[0][7] = 0)),
        ("header moved (swapped with next record word)", mutate(&|x| x.swap(0, 1))),
        ("header moved to the end of block 0", mutate(&|x| { let h = x.remove(0); x.insert(rpb - 1, h); })),
    ];
    for (s, x) in &cases {
        let r = attempt_words(&o, x, &p, &p, f, s);
        rec(r, s);
    }
    // padded half made non-zero (odd block)
    if b % 2 == 1 {
        let last_rec = rpb - 1;
        let x = mutate(&|x| x[last_rec][4 + 1] = 1 << 31); // v_b of the empty half set to a matching value
        let r = attempt_words(&o, &x, &p, &p, f, "padded half non-zero (honest statement)");
        rec(r, "padded half non-zero (honest statement)");
        // digest recomputed for the tampered stream: only the AIR can catch it
        let q = public_of_words(&x, &w, THETA);
        let r = attempt_words(&o, &x, &q, &q, f, "padded half non-zero, digest recomputed");
        rec(r, "padded half non-zero, digest recomputed (AIR only)");
        let x2 = mutate(&|x| x[last_rec][4 + 2] = 5);
        let q2 = public_of_words(&x2, &w, THETA);
        let r = attempt_words(&o, &x2, &q2, &q2, f, "padded half b non-zero, digest recomputed");
        rec(r, "padded half b non-zero, digest recomputed (AIR only)");
        // padded half treated as a valid record (kinds): rem would go below zero
        let mut kinds = honest_kinds(w.n_blocks, b);
        let idx = last_rec;
        assert!(kinds[idx].va && !kinds[idx].vb);
        kinds[idx].vb = true;
        let r = attempt_kinds(&o, &words, &kinds, &p, &p, f, "empty half declared valid");
        rec(r, "empty half declared valid (kinds, honest statement)");
    } else {
        // even block: the last half b declared empty (a real record dropped from the count)
        let mut kinds = honest_kinds(w.n_blocks, b);
        let idx = rpb - 1;
        kinds[idx].vb = false;
        let r = attempt_kinds(&o, &words, &kinds, &p, &p, f, "real half declared empty");
        rec(r, "real half declared empty (kinds)");
    }
    // structure attacks with a self-consistent statement (digest and count/sum recomputed from the words the prover uses)
    if w.n_blocks >= 2 && rpb >= 3 {
        // a record row declared a header (words crafted so that w7 = 1 and w2 = m_g): block cut short
        let mut x = words.clone();
        x[2][7] = 1;
        x[2][2] = b as u64;
        let mut kinds = honest_kinds(w.n_blocks, b);
        kinds[2] = Kind { hdr: true, va: false, vb: false };
        let q = public_of_words(&x, &w, THETA);
        let r = attempt_kinds(&o, &x, &kinds, &q, &q, f, "record row declared header");
        rec(r, "record row declared header (digest recomputed)");
        // header declared a record row
        let mut kinds = honest_kinds(w.n_blocks, b);
        kinds[rpb] = Kind { hdr: false, va: true, vb: true };
        let r = attempt_kinds(&o, &words, &kinds, &p, &p, f, "header declared record");
        rec(r, "header declared a record row (kinds)");
        // block longer than m_g: one extra record row inserted (words and statement size consistent via block count of the AIR)
        let r = attempt_kinds(&o, &words, &vec![Kind { hdr: false, va: true, vb: true }; words.len()], &p, &p, f, "all record rows");
        rec(r, "all rows declared record rows (kinds)");
    }
    assert!(!kinds_seen.is_empty());
}

#[test]
fn p2_rejects_tampering_n1000_b100() {
    tamper_suite(Fmt::P2, 1000, 100);
}
#[test]
fn p2_rejects_tampering_odd_b7() {
    tamper_suite(Fmt::P2, 700, 7);
}
#[test]
fn p2_rejects_tampering_odd_b99() {
    tamper_suite(Fmt::P2, 990, 99);
}
#[test]
fn p2_rejects_tampering_b1() {
    tamper_suite(Fmt::P2, 20, 1);
}
#[test]
fn p2r_rejects_tampering_n1000_b100() {
    tamper_suite(Fmt::P2r, 1000, 100);
}
#[test]
fn p2r_rejects_tampering_odd_b7() {
    tamper_suite(Fmt::P2r, 700, 7);
}

/// A proof of one format must not verify as the other (different AIR widths and constraints).
#[test]
fn formats_do_not_cross_verify() {
    let o = FriOpts::from_env();
    let w = Workload::synthetic(1000, 100, 1);
    let p = pair_public(&w, THETA, CTX);
    let a = prove_pair(&o, &w, &p, Fmt::P2).unwrap();
    assert!(verify_pair(&o, &a, &p, Fmt::P2r).is_err());
    let b = prove_pair(&o, &w, &p, Fmt::P2r).unwrap();
    assert!(verify_pair(&o, &b, &p, Fmt::P2).is_err());
}

/// P2r only: a v >= 2^32 (not allowed in the stream) is NOT caught by the P2r Exec AIR; P2 catches it. This documents that the
/// P2r soundness depends on a v < 2^32 check in the chunk (R_RC) proof, which is not built yet.
#[test]
fn p2r_does_not_range_check_v_p2_does() {
    let o = FriOpts::from_env();
    let w = Workload::synthetic(200, 100, 1);
    let mut words = pack_workload(&w);
    // v_a of the first record row set to 2^32 + THETA + 5: honest classification "match" (v >= theta)
    words[1][1] = (1u64 << 32) + THETA + 5;
    let (c, s) = reference_from_packed(&words, 100, THETA);
    let lay0 = pqz_plonky3_w38::air::Layout::new(0, 12, 0);
    let digest = pqz_plonky3_w38::air::native_digest::<c1::Val, 12, _>(&lay0, &c1::perm(), &words);
    // v - theta = 2^32 + 5 is not a 32-bit d, so even P2r rejects this particular value; use v in [2^32, theta+2^32) instead
    let q = ExecPublic { digest: digest.clone(), n_blocks: 2, block_size: 100, theta: THETA, count: c, sum: vec![s], ctx: CTX };
    let r = attempt_words(&o, &words, &q, &q, Fmt::P2r, "v too large by 2^32+THETA+5");
    println!("v = 2^32+THETA+5 under P2r: {r}");
    words[1][1] = (1u64 << 32) + 5; // v >= theta (as integer), v - theta < 2^32: accepted by the P2r Exec AIR
    let (c, s) = reference_from_packed(&words, 100, THETA);
    let digest = pqz_plonky3_w38::air::native_digest::<c1::Val, 12, _>(&lay0, &c1::perm(), &words);
    let q = ExecPublic { digest, n_blocks: 2, block_size: 100, theta: THETA, count: c, sum: vec![s], ctx: CTX };
    let pr = prove_pair_words(&o, &words, &q, Fmt::P2r).expect("P2r prove");
    let acc = verify_pair(&o, &pr, &q, Fmt::P2r).is_ok();
    let rej_p2 = catch_unwind(AssertUnwindSafe(|| prove_pair_words(&o, &words, &q, Fmt::P2).and_then(|pp| verify_pair(&o, &pp, &q, Fmt::P2)))).map(|r| r.is_err()).unwrap_or(true);
    println!("v = 2^32+5: P2r accepts = {acc}, P2 rejects = {rej_p2}");
    assert!(acc, "P2r is documented to accept v in [2^32, 2^32+theta) (the chunk proof must exclude it)");
    assert!(rej_p2, "P2 must reject v >= 2^32");
}

/// Canonical encoding: (a) an odd block with its empty half in the MIDDLE (same records, same number of rows) and (b) blocks of unequal
/// m_g with the same total rows (records moved between blocks, same count and sum) are both rejected, even with the digest recomputed
/// for the stream the prover uses. Neither changes count or sum; they are rejected only by the structure rules (empty half only in the
/// last row of a block, m_g = public block size).
#[test]
fn non_canonical_structure_is_rejected() {
    let o = FriOpts::from_env();
    for f in [Fmt::P2, Fmt::P2r] {
        // (a) B = 7: rows [r1,-], [r2,r3], [r4,r5], [r6,r7]  instead of [r1,r2], [r3,r4], [r5,r6], [r7,-]
        let w = Workload::synthetic(70, 7, 1);
        let words = pack_workload(&w);
        let rpb = rows_per_block(7);
        assert_eq!(rpb, 5);
        let mut x = words.clone();
        for g in 0..w.n_blocks {
            let base = g * rpb;
            let recs: Vec<[u64; 4]> = (1..=4).flat_map(|r| { let wd = &words[base + r]; vec![[wd[0], wd[1], wd[2], wd[3]], [wd[4], wd[5], wd[6], wd[7]]] }).take(7).collect();
            let mut slots: Vec<[u64; 4]> = vec![recs[0], [0; 4]];
            slots.extend_from_slice(&recs[1..]);
            assert_eq!(slots.len(), 8);
            for r in 0..4 {
                x[base + 1 + r] = [slots[2 * r], slots[2 * r + 1]].concat();
            }
        }
        let mut kinds = honest_kinds(w.n_blocks, 7);
        for g in 0..w.n_blocks {
            kinds[g * rpb + 1].vb = false;
            for r in 2..=4 { kinds[g * rpb + r].vb = true; }
        }
        let mut q = pair_public(&w, THETA, CTX);
        let lay0 = pqz_plonky3_w38::air::Layout::new(0, 12, 0);
        q.digest = pqz_plonky3_w38::air::native_digest::<c1::Val, 12, _>(&lay0, &c1::perm(), &x);
        let r = attempt_kinds(&o, &x, &kinds, &q, &q, f, "empty half in the middle");
        println!("REJECT {f:?} empty half in the middle of an odd block: {r}");

        // (b) B = 100, 2 blocks: block 0 gets 102 records (51 rows), block 1 gets 98 (49 rows)
        let w = Workload::synthetic(200, 100, 1);
        let words = pack_workload(&w);
        let mut x: Vec<Vec<u64>> = vec![];
        let mut h0 = words[0].clone();
        h0[2] = 102;
        x.push(h0);
        x.extend_from_slice(&words[1..=50]);
        x.push(words[52].clone());
        let mut h1 = words[51].clone();
        h1[2] = 98;
        x.push(h1);
        x.extend_from_slice(&words[53..]);
        assert_eq!(x.len(), words.len());
        let mut kinds = vec![Kind { hdr: true, va: false, vb: false }];
        kinds.extend(vec![Kind { hdr: false, va: true, vb: true }; 51]);
        kinds.push(Kind { hdr: true, va: false, vb: false });
        kinds.extend(vec![Kind { hdr: false, va: true, vb: true }; 49]);
        let mut q = pair_public(&w, THETA, CTX);
        q.digest = pqz_plonky3_w38::air::native_digest::<c1::Val, 12, _>(&lay0, &c1::perm(), &x);
        let r = attempt_kinds(&o, &x, &kinds, &q, &q, f, "unequal m_g");
        println!("REJECT {f:?} unequal block sizes m_g=102/98: {r}");
    }
}
