//! w38 stage 3 tests: packed chunk / RC proofs with range checks, the packed bundle (Auth + Exec P2r + chunks), and rejection.
//! A trial FAILS only if a verifier ACCEPTS something bad.

use pqz_plonky3_w38::air::ExecPublic;
use pqz_plonky3_w38::auth::honest_auth_instance;
use pqz_plonky3_w38::chunk::{iv_state, ChunkLists, RcChunkPublic};
use pqz_plonky3_w38::data::Workload;
use pqz_plonky3_w38::pair::*;
use pqz_plonky3_w38::pchunk::{acc_native_p, check_sealed, lists_of_packed, plain as pc, seal_p};
use pqz_plonky3_w38::prequest::*;
use pqz_plonky3_w38::request::{exec_context, NativeChecks};
use pqz_plonky3_w38::{c1, FriOpts};
use std::panic::{catch_unwind, AssertUnwindSafe};

const THETA: u64 = 1 << 31;
const CASES: [(usize, usize); 8] = [(1000, 100), (700, 7), (990, 99), (10, 1), (20, 2), (35, 5), (64, 64), (101, 101)];

fn exec_pub_of(words: &[Vec<u64>], w: &Workload, ctx: [u64; 4]) -> ExecPublic {
    let lay0 = pqz_plonky3_w38::air::Layout::new(0, 12, 0);
    let digest = pqz_plonky3_w38::air::native_digest::<c1::Val, 12, _>(&lay0, &c1::perm(), words);
    ExecPublic { digest, n_blocks: w.n_blocks, block_size: w.block_size, theta: THETA, count: 0, sum: vec![0], ctx }
}

/// prove (any panic / error = rejection) then verify; panics if the verifier ACCEPTS.
fn must_reject(o: &FriOpts, words: &[Vec<u64>], p: &RcChunkPublic, what: &str) -> &'static str {
    let r = catch_unwind(AssertUnwindSafe(|| pc::prove_chunk(o, words, p)));
    let proof = match r {
        Err(_) => return "PROVER_PANIC",
        Ok(Err(_)) => return "PROVER_ERR",
        Ok(Ok(x)) => x,
    };
    match pc::verify_chunk(o, &proof, p) {
        Err(_) => "VERIFY_FAIL",
        Ok(()) => panic!("ACCEPTED: {what}"),
    }
}

#[test]
fn honest_chunks_single_and_split() {
    let o = FriOpts::from_env();
    for &(n, b) in &CASES {
        let w = Workload::synthetic(n, b, 1);
        let words = pack_workload(&w);
        for c in [w.n_blocks, 1, 2, 3] {
            let (pubs, lists) = pc::honest_publics(&words, b, c.min(w.n_blocks));
            let mut first = 0;
            let rpw = rows_per_block(b);
            for (p, l) in pubs.iter().zip(&lists) {
                check_sealed::<c1::Val>(p, l).unwrap();
                let cw = &words[first * rpw..(first + p.n_blocks_chunk) * rpw];
                first += p.n_blocks_chunk;
                let proof = pc::prove_chunk(&o, cw, p).unwrap_or_else(|e| panic!("n={n} b={b} c={c}: {e}"));
                pc::verify_chunk(&o, &proof, p).unwrap_or_else(|e| panic!("honest rejected n={n} b={b} c={c}: {e}"));
            }
            let e = exec_pub_of(&words, &w, [1, 2, 3, 4]);
            check_stream_link_p(&e, &pubs).unwrap();
        }
    }
}

#[test]
fn honest_bundle_on_packed_data() {
    let o = FriOpts::from_env();
    for f in [Fmt::P2r, Fmt::P2] {
        for &(n, b) in &[(1000usize, 100usize), (700, 7), (35, 5)] {
            let w = Workload::synthetic(n, b, 1);
            let words = pack_workload(&w);
            let (ap, aw) = honest_auth_instance::<c1::Val, _>(&c1::perm(), 10, 1);
            let ctx = exec_context(&c1::perm(), ap.b_q, ap.d_q, 1);
            let ep = pair_public(&w, THETA, ctx);
            let pa = pqz_plonky3_w38::rel::plain::prove_auth(&o, &ap, &aw).unwrap();
            let pe = prove_pair(&o, &w, &ep, f).unwrap();
            for c in [w.n_blocks, 2] {
                let (cp, cl) = pc::honest_publics(&words, b, c.min(w.n_blocks));
                let rpw = rows_per_block(b);
                let mut first = 0;
                let mut proofs = Vec::new();
                for p in &cp {
                    proofs.push(pc::prove_chunk(&o, &words[first * rpw..(first + p.n_blocks_chunk) * rpw], p).unwrap());
                    first += p.n_blocks_chunk;
                }
                verify_bundle_p(NativeChecks::ON, &o, f, &pa, &ap, &pe, &ep, &proofs, &cp, &cl, 1).unwrap_or_else(|e| panic!("bundle n={n} b={b} c={c}: {e}"));
                verify_request_p(NativeChecks::ON, &o, f, &pa, &ap, &pe, &ep, 1).unwrap();
            }
        }
    }
}

fn tamper_slot(words: &mut [Vec<u64>], b: usize, rec: usize, half: usize, slot: usize, val: u64) {
    // record index `rec` (0-based inside block 0), half = 0 / 1 -> packed word
    let _ = b;
    let row = 1 + rec / 2;
    let h = rec % 2;
    let _ = half;
    words[row][4 * h + slot] = val;
}

#[test]
fn range_check_rejects_v_2_32_and_b_2_20() {
    let o = FriOpts::from_env();
    for &(n, b) in &[(1000usize, 100usize), (700, 7), (35, 5), (20, 2), (10, 1)] {
        let w = Workload::synthetic(n, b, 1);
        for (what, slot, val) in [("v=2^32", 1usize, 1u64 << 32), ("v=2^32+5", 1, (1 << 32) + 5), ("b=2^20", 2, 1 << 20), ("b=2^40+3", 2, (1 << 40) + 3)] {
            for rec in [0usize, 1.min(b - 1), b - 1] {
                let mut words = pack_workload(&w);
                tamper_slot(&mut words, b, rec, rec % 2, slot, val);
                // a statement honestly sealed for the TAMPERED stream: only the range check can reject it
                let (pubs, _) = pc::honest_publics(&words, b, w.n_blocks);
                let rpw = rows_per_block(b);
                let cw = &words[..w.n_blocks * rpw];
                let how = must_reject(&o, cw, &pubs[0], &format!("{what} rec {rec} n={n} b={b}"));
                eprintln!("{what} rec {rec} n={n} b={b}: {how}");
                // the SAME tampered stream is accepted by the AIR without the range check (the check is what rejects it)
                let a = pc::chunk_air(&pubs[0]).unwrap().without_ranges();
                if let Ok(proof) = catch_unwind(AssertUnwindSafe(|| pc::prove_chunk_with(&o, &a, cw, &pubs[0]))).unwrap_or(Err("panic".into())) {
                    pc::verify_chunk_with(&o, &a, &proof, &pubs[0]).unwrap_or_else(|e| panic!("without_ranges variant should accept: {e}"));
                } else {
                    panic!("without_ranges variant could not prove the out-of-range stream ({what})");
                }
            }
        }
    }
}

#[test]
fn range_boundary_values_accepted() {
    let o = FriOpts::from_env();
    for &(n, b) in &[(100usize, 5usize), (64, 64)] {
        let w = Workload::synthetic(n, b, 1);
        let mut words = pack_workload(&w);
        tamper_slot(&mut words, b, 0, 0, 1, (1 << 32) - 1);
        tamper_slot(&mut words, b, 0, 0, 2, (1 << 20) - 1);
        tamper_slot(&mut words, b, b - 1, 0, 1, 0);
        tamper_slot(&mut words, b, b - 1, 0, 2, 0);
        let (pubs, _) = pc::honest_publics(&words, b, w.n_blocks);
        let proof = pc::prove_chunk(&o, &words[..w.n_blocks * rows_per_block(b)], &pubs[0]).unwrap();
        pc::verify_chunk(&o, &proof, &pubs[0]).unwrap();
    }
}

#[test]
fn exec_over_stream_a_with_chunk_publics_of_stream_b() {
    let o = FriOpts::from_env();
    let (n, b) = (700usize, 7usize);
    let wa = Workload::synthetic(n, b, 1);
    let wb = Workload::synthetic(n, b, 2);
    let (wda, wdb) = (pack_workload(&wa), pack_workload(&wb));
    let (ap, aw) = honest_auth_instance::<c1::Val, _>(&c1::perm(), 10, 1);
    let ctx = exec_context(&c1::perm(), ap.b_q, ap.d_q, 1);
    let ea = pair_public(&wa, THETA, ctx);
    let pa = pqz_plonky3_w38::rel::plain::prove_auth(&o, &ap, &aw).unwrap();
    let pe = prove_pair(&o, &wa, &ea, Fmt::P2r).unwrap();
    let (cb, lb) = pc::honest_publics(&wdb, b, wb.n_blocks);
    let proofs_b = vec![pc::prove_chunk(&o, &wdb, &cb[0]).unwrap()];
    // checks on: rejected by the stream link
    let r = verify_bundle_p(NativeChecks::ON, &o, Fmt::P2r, &pa, &ap, &pe, &ea, &proofs_b, &cb, &lb, 1);
    assert!(matches!(&r, Err(e) if e.starts_with("link:")), "{r:?}");
    // checks off: every proof is valid on its own, so the bundle is accepted (this is why the native link check exists)
    let r = verify_bundle_p(NativeChecks { link: false, scope: true }, &o, Fmt::P2r, &pa, &ap, &pe, &ea, &proofs_b, &cb, &lb, 1);
    assert!(r.is_ok(), "documented: with the link check off the mixed bundle verifies: {r:?}");
    // a chunk proof made for stream B cannot be re-labelled with stream A's statement
    let (ca, _) = pc::honest_publics(&wda, b, wa.n_blocks);
    let bad = pc::verify_chunk(&o, &proofs_b[0], &ca[0]);
    assert!(bad.is_err(), "chunk proof of B accepted under A's statement");
    // swapping only the tag list of the AA (same stream sizes) is caught by check_sealed
    let (_, la) = pc::honest_publics(&wda, b, wa.n_blocks);
    assert!(check_sealed::<c1::Val>(&cb[0], &la[0]).is_err());
}

#[test]
fn odd_block_empty_half_in_chunk_air() {
    let o = FriOpts::from_env();
    for &(n, b) in &[(35usize, 5usize), (700, 7), (10, 1), (990, 99), (30, 3)] {
        let w = Workload::synthetic(n, b, 1);
        let words = pack_workload(&w);
        let rpw = rows_per_block(b);
        let nrec = (b + 1) / 2;
        let (pubs, _) = pc::honest_publics(&words, b, w.n_blocks);
        // honest passes (covered elsewhere); here: every way to put something in the empty half is rejected
        for (what, slot, val) in [("id", 4usize, 7u64), ("v", 5, 1), ("b", 6, 1), ("tag", 7, 5)] {
            let mut bad = words.clone();
            bad[nrec][slot] = val; // last record row of block 0 (empty half b since b is odd)
            let (bp, _) = pc::honest_publics(&bad, b, w.n_blocks);
            let how = must_reject(&o, &bad[..w.n_blocks * rpw], &bp[0], &format!("empty half {what} n={n} b={b}"));
            eprintln!("odd empty half {what} n={n} b={b}: {how}");
        }
        // hand-made kinds: claim the empty half is a record (vb = 1) -> countdown breaks
        let mut kinds = honest_kinds(w.n_blocks, b);
        let last = nrec; // row index of the last record row of block 0
        kinds[last].vb = true;
        let r = catch_unwind(AssertUnwindSafe(|| pc::prove_chunk_kinds(&o, &words[..w.n_blocks * rpw], &kinds, &pubs[0])));
        if let Ok(Ok(proof)) = r {
            assert!(pc::verify_chunk(&o, &proof, &pubs[0]).is_err(), "vb on empty half accepted n={n} b={b}");
        }
        // the empty half does not enter the tag list (tags = B per block)
        let l: ChunkLists = lists_of_packed(&words[..rpw], b);
        assert_eq!(l.tags.len(), b);
    }
}

#[test]
fn tampered_publics_and_streams_rejected() {
    let o = FriOpts::from_env();
    let (n, b) = (700usize, 7usize);
    let w = Workload::synthetic(n, b, 1);
    let words = pack_workload(&w);
    let rpw = rows_per_block(b);
    let c = 40; // 100 blocks -> 3 chunks
    let (pubs, lists) = pc::honest_publics(&words, b, c);
    assert!(pubs.len() >= 2);
    let k = 1usize;
    let first = pubs[..k].iter().map(|p| p.n_blocks_chunk).sum::<usize>();
    let cw = &words[first * rpw..(first + pubs[k].n_blocks_chunk) * rpw];
    let proof = pc::prove_chunk(&o, cw, &pubs[k]).unwrap();
    pc::verify_chunk(&o, &proof, &pubs[k]).unwrap();
    let mut muts: Vec<(&str, RcChunkPublic)> = Vec::new();
    let base = pubs[k].clone();
    let mut m = base.clone();
    m.s_out[0] ^= 1;
    muts.push(("s_out", m));
    let mut m = base.clone();
    m.s_in[3] ^= 1;
    muts.push(("s_in", m));
    let mut m = base.clone();
    m.hdr_before += 1;
    muts.push(("hdr_before", m));
    let mut m = base.clone();
    m.alpha[1] = m.alpha[1].wrapping_add(1) % 0xFFFF_FFFF_0000_0001;
    muts.push(("alpha", m));
    let mut m = base.clone();
    m.acc[2] = (m.acc[2] + 1) % 0xFFFF_FFFF_0000_0001;
    muts.push(("acc", m));
    let mut m = base.clone();
    m.beta[0] = (m.beta[0] + 1) % 0xFFFF_FFFF_0000_0001;
    muts.push(("beta", m));
    let mut m = base.clone();
    m.total_words += 1;
    muts.push(("total_words", m));
    let mut m = base.clone();
    m.hdr_first[2] += 1;
    muts.push(("hdr_first", m));
    for (name, m) in muts {
        assert!(pc::verify_chunk(&o, &proof, &m).is_err(), "accepted tampered public {name}");
    }
    // chunk 0: first_chunk is decided by chunk_index; a non-IV start state with index 0 is rejected
    let cw0 = &words[..pubs[0].n_blocks_chunk * rpw];
    let mut bad = pubs[0].clone();
    bad.s_in = iv_state(bad.total_words as u64 + 1);
    must_reject(&o, cw0, &bad, "chunk 0 not at IV");
    // tag fingerprint: a tag list differing from the AA's list (swap tag_a and tag_b of a record) is caught
    let mut swapped = lists[k].clone();
    swapped.tags.swap(0, 1);
    assert!(check_sealed::<c1::Val>(&pubs[k], &swapped).is_err());
    // distinct powers: the accumulator separates (tag_a, tag_b) from (tag_b, tag_a)
    let (a, bt) = (123456789u64, 987654321u64);
    let mk = |t0: u64, t1: u64| ChunkLists { tags: vec![t0, t1], hdrs: vec![[1, 2, 3, 4, 5, 6, 7, 1]] };
    let q = |l: &ChunkLists| acc_native_p::<c1::Val>(11, 13, 1, 2, l);
    assert_ne!(q(&mk(a, bt)), q(&mk(bt, a)));
    // a stream with one tag changed, original sealed publics: s_out differs
    let mut tw = words.clone();
    tw[first * rpw + 2][3] ^= 1;
    must_reject(&o, &tw[first * rpw..(first + pubs[k].n_blocks_chunk) * rpw], &pubs[k], "changed tag, honest publics");
    let _ = seal_p::<c1::Val>;
}

/// trace=par (parallel sponge from checkpoints) builds the SAME trace as the sequential build, for the chunk AIR and the packed Exec.
#[test]
fn par_trace_equals_seq_trace() {
    use pqz_plonky3_w38::chunk::sponge_checkpoints_from;
    use pqz_plonky3_w38::psponge::Ckpt;
    use p3_matrix::Matrix;
    let _ = std::marker::PhantomData::<Ckpt<12>>;
    for &(n, b) in &[(1000usize, 100usize), (700, 7), (35, 5), (10, 1)] {
        let w = Workload::synthetic(n, b, 1);
        let words = pack_workload(&w);
        let rpw = rows_per_block(b);
        for c in [w.n_blocks, 3] {
            let (pubs, _) = pc::honest_publics(&words, b, c.min(w.n_blocks));
            let mut first = 0;
            for p in &pubs {
                let cw = &words[first * rpw..(first + p.n_blocks_chunk) * rpw];
                first += p.n_blocks_chunk;
                let a = pc::chunk_air(p).unwrap();
                let seq = a.build_trace(&c1::perm(), cw, &p.s_in, &p.alpha, &p.beta, p.hdr_before as u64);
                let n_rows = cw.len().next_power_of_two().max(pqz_plonky3_w38::air::MIN_ROWS);
                for k in [1usize, 4, 1024] {
                    let ck = sponge_checkpoints_from::<c1::Val, 12, _>(&c1::perm(), &p.s_in, cw, n_rows, k);
                    let par = a.build_trace_par(&c1::perm(), cw, &p.alpha, &p.beta, p.hdr_before as u64, &ck);
                    assert_eq!(seq.height(), par.height());
                    assert!(seq.values == par.values, "chunk trace par != seq n={n} b={b} k={k}");
                }
            }
        }
        for f in [Fmt::P2, Fmt::P2r] {
            let ctx = [1u64, 2, 3, 4];
            let ep = pair_public(&w, THETA, ctx);
            let nr = pair_n_rows(pair_n_words(w.n_blocks, b));
            let a = pair_air(THETA, pair_n_words(w.n_blocks, b) as u64, f);
            let seq = a.build_trace(&c1::perm(), &words, b);
            for k in [1usize, 4, 1024] {
                let ck = pair_checkpoints(&words, nr, k);
                let par = a.build_trace_par(&c1::perm(), &words, b, &ck);
                assert!(seq.values == par.values, "exec trace par != seq n={n} b={b} k={k}");
            }
            let _ = ep;
        }
    }
}

fn run_bin(exe: &str, args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(exe).args(args).env("RAYON_NUM_THREADS", "2").output().unwrap();
    (out.status.success(), String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr))
}

/// pchild3 is a persistent child: it prints READY, then proves once per "run" line on stdin, and exits on "quit".
fn run_child(exe: &str, args: &[&str]) -> (bool, String) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut ch = Command::new(exe).args(args).env("RAYON_NUM_THREADS", "2")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    ch.stdin.take().unwrap().write_all(b"run\nquit\n").unwrap();
    let out = ch.wait_with_output().unwrap();
    (out.status.success(), String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr))
}

/// pchild3 fmt=p2|p2r with trace=par runs and verifies (exit 0), for exec / rc / bundle; the default (no fmt) is unchanged.
#[test]
fn pchild3_packed_trace_par_runs() {
    let exe = env!("CARGO_BIN_EXE_pchild3");
    for fmt in ["p2", "p2r"] {
        for rel in ["exec", "rc", "bundle"] {
            for extra in [vec!["trace=par", "ckpt_k=64"], vec!["trace=seq"]] {
                let mut args = vec![rel, "n=2100", "block=7", "fri=fast1", "chunk=50"];
                args.push(if fmt == "p2" { "fmt=p2" } else { "fmt=p2r" });
                args.extend(extra.iter().copied());
                let (ok, out) = run_child(exe, &args);
                assert!(ok, "pchild3 {args:?} failed: {out}");
                assert!(out.contains("ROW,"), "{out}");
            }
        }
    }
    let (ok, out) = run_child(exe, &["exec", "n=2000", "block=100", "fri=fast1", "trace=par"]);
    assert!(ok, "old-format default broken: {out}");
}

/// pverify3 fmt=p2r: request and bundle verification use the packed Exec and the chunk proofs (with range checks); the default is the old format.
#[test]
fn pverify3_fmt_packed_request_and_bundle() {
    let exe = env!("CARGO_BIN_EXE_pverify3");
    for fmt in ["fmt=p2", "fmt=p2r"] {
        for rel in ["request", "bundle", "exec", "rc"] {
            let (ok, out) = run_bin(exe, &[rel, "n=2100", "block=7", "fri=fast1", "reps=2", "chunk=50", fmt]);
            assert!(ok, "pverify3 {rel} {fmt} failed: {out}");
            assert!(out.contains("p2"), "label must carry the packed format: {out}");
        }
    }
    for rel in ["request", "bundle"] {
        let (ok, out) = run_bin(exe, &[rel, "n=2000", "block=100", "fri=fast1", "reps=2"]);
        assert!(ok, "old default pverify3 {rel} failed: {out}");
        assert!(!out.contains("-p2"), "old default must not be packed: {out}");
    }
}
