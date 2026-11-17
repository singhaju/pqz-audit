//! w29 gates for the linked-chunk variants (exec_link.rs, rc_link.rs, split.rs). Run with `cargo test --release --test linked`
//! (and once in debug on a small case: winterfell checks constraint degrees only in debug builds).
//!
//! Error strings: "link: ..." = rejected by the verifier's own checks, "chunk i: rejected: ..." = rejected by the STARK verifier.
//! The `deep_*` tests change public values CONSISTENTLY (so that the link checks pass) and demand a STARK rejection.

use pqz_proof::data::{Rng, Workload};
use pqz_proof::exec::prove_exec;
use pqz_proof::exec_link::*;
use pqz_proof::prove::*;
use pqz_proof::rc::prove_rc;
use pqz_proof::rc_link::*;
use pqz_proof::rescue::F;
use pqz_proof::split::*;
use winterfell::math::FieldElement;
use winterfell::Proof;

const THETA: u64 = 1 << 31;

fn ctx() -> [F; 4] {
    [F::new(11), F::new(22), F::new(33), F::new(44)]
}

type EP = Vec<(Proof, ExecChunkPublic)>;
type RP = Vec<(Proof, RcChunkPublic)>;

struct Ex {
    w: Workload,
    proofs: EP,
}
struct Rc {
    w: Workload,
    proofs: RP,
}

fn ex(nb: usize, bs: usize, seed: u64, split: &[usize]) -> Ex {
    let w = Workload::synthetic(nb * bs, bs, seed);
    let proofs = prove_exec_chunked(&w, THETA, ctx(), default_options(), split).unwrap();
    Ex { w, proofs }
}
fn rc(nb: usize, bs: usize, seed: u64, split: &[usize]) -> Rc {
    let w = Workload::synthetic(nb * bs, bs, seed);
    let proofs = prove_rc_chunked(&w, default_options(), split).unwrap();
    Rc { w, proofs }
}

fn vex(e: &Ex, proofs: EP) -> Result<(), String> {
    let (c, s) = e.w.reference_result(THETA);
    vex_claim(e, proofs, c, s)
}
fn vex_claim(e: &Ex, proofs: EP, c: u64, s: u64) -> Result<(), String> {
    verify_exec_chunked(proofs, e.w.commitment(), e.w.n_blocks, e.w.block_size, THETA, ctx(), c, s)
}
fn vrc(r: &Rc, proofs: RP) -> Result<(), String> {
    verify_rc_chunked(proofs, r.w.commitment(), r.w.n_blocks, r.w.block_size, r.w.header0())
}

/// must be rejected; `deep` = must be rejected by the STARK verifier, not by the link checks
fn rej(name: &str, r: Result<(), String>, deep: bool) {
    match r {
        Ok(()) => panic!("{name}: ACCEPTED, must be rejected"),
        Err(e) => {
            eprintln!("  reject {name}: {e}");
            if deep {
                assert!(e.contains("rejected"), "{name}: expected a STARK rejection, got: {e}");
            }
        }
    }
}

const SPLIT3: [usize; 3] = [2, 2, 2];

// ---------------------------------------------------------------- split rule
#[test]
fn split_reproduces_pilot_w25() {
    // pilot (results/pilot-1/l3_dp.csv), block size 500
    assert_eq!(plan_split(10, 500, 4), vec![8, 2]);
    assert_eq!(plan_split(20, 500, 4), vec![16, 4]);
    assert_eq!(plan_split(40, 500, 4), vec![32, 8]);
    assert_eq!(plan_split(100, 500, 4), vec![65, 32, 2, 1]);
    assert_eq!(plan_split(200, 500, 4), vec![130, 65, 4, 1]);
    for nq in [5000usize, 10000, 20000, 50000, 100000] {
        let s = plan_split(nq / 500, 500, 4);
        eprintln!("split N_Q={nq} block_size=500 -> {s:?} rows {}", split_rows(&s, 500));
    }
}

// ---------------------------------------------------------------- honest, 1..4 chunks
#[test]
fn exec_honest_1_to_4_chunks() {
    for split in [vec![8usize], vec![4, 4], vec![3, 3, 2], vec![3, 2, 2, 1]] {
        let e = ex(8, 4, 5, &split);
        assert_eq!(e.proofs.len(), split.len());
        vex(&e, e.proofs.clone()).unwrap_or_else(|er| panic!("split {split:?}: {er}"));
    }
}

#[test]
fn rc_honest_1_to_4_chunks() {
    for split in [vec![8usize], vec![4, 4], vec![3, 3, 2], vec![3, 2, 2, 1]] {
        if cfg!(debug_assertions) && split.contains(&1) {
            continue; // debug build only, see old_rc_one_block_debug_degree_check
        }
        let r = rc(8, 4, 5, &split);
        assert_eq!(r.proofs.len(), split.len());
        vrc(&r, r.proofs.clone()).unwrap_or_else(|er| panic!("split {split:?}: {er}"));
    }
}

#[test]
fn exec_single_chunk_equals_single_statement() {
    // one chunk = whole stream: counts and digest equal the single proof's public input
    let e = ex(6, 5, 9, &[6]);
    let (_, p) = prove_exec(&e.w, THETA, ctx()).unwrap();
    assert_eq!(e.proofs[0].1.cnt_out, p.count);
    assert_eq!(e.proofs[0].1.sum_out, p.sum);
    assert_eq!(e.proofs[0].1.s_out[4..8], p.digest[..]);
}

// ---------------------------------------------------------------- Exec rejections
#[test]
fn exec_control_legal_accepted() {
    let e = ex(6, 4, 3, &SPLIT3);
    vex(&e, e.proofs.clone()).unwrap();
}

#[test]
fn exec_reject_s_in_changed() {
    let e = ex(6, 4, 3, &SPLIT3);
    for j in [0usize, 5, 11] {
        let mut p = e.proofs.clone();
        p[1].1.s_in.as_mut().unwrap()[j] += F::ONE;
        rej(&format!("exec s_in[{j}]"), vex(&e, p), false);
        // consistent change (previous S_out too): the STARK must reject
        let mut p = e.proofs.clone();
        p[1].1.s_in.as_mut().unwrap()[j] += F::ONE;
        p[0].1.s_out[j] += F::ONE;
        rej(&format!("exec deep s_in/s_out[{j}]"), vex(&e, p), true);
    }
}

#[test]
fn exec_reject_s_out_changed() {
    let e = ex(6, 4, 3, &SPLIT3);
    for (i, j) in [(0usize, 0usize), (0, 7), (1, 11), (1, 3)] {
        let mut p = e.proofs.clone();
        p[i].1.s_out[j] += F::ONE;
        rej(&format!("exec s_out[{i}][{j}]"), vex(&e, p), false);
        let mut p = e.proofs.clone();
        p[i].1.s_out[j] += F::ONE;
        p[i + 1].1.s_in.as_mut().unwrap()[j] += F::ONE;
        rej(&format!("exec deep s_out/s_in[{i}][{j}]"), vex(&e, p), true);
    }
    // digest of the last chunk
    let mut p = e.proofs.clone();
    p[2].1.s_out[4] += F::ONE;
    rej("exec last digest", vex(&e, p), false);
    // non-canonical last S_out (element outside the digest)
    let mut p = e.proofs.clone();
    p[2].1.s_out[0] += F::ONE;
    rej("exec last s_out outside digest", vex(&e, p), false);
}

#[test]
fn exec_reject_hdr_first_changed() {
    let e = ex(6, 4, 3, &SPLIT3);
    // an element the link checks do not look at: only the STARK can see it
    let mut p = e.proofs.clone();
    p[1].1.hdr_first[0] += F::ONE;
    rej("exec hdr_first[0] chunk1", vex(&e, p), true);
    let mut p = e.proofs.clone();
    p[0].1.hdr_first[0] += F::ONE; // chunk 0: not asserted, but in the transcript
    rej("exec hdr_first[0] chunk0", vex(&e, p), true);
    let mut p = e.proofs.clone();
    p[1].1.hdr_first[7] = F::ZERO; // flag
    rej("exec hdr_first flag", vex(&e, p), false);
    let mut p = e.proofs.clone();
    p[2].1.hdr_first[2] += F::ONE; // m_b
    rej("exec hdr_first m_b", vex(&e, p), false);
}

#[test]
fn exec_reject_counters_changed() {
    let e = ex(6, 4, 3, &SPLIT3);
    for which in 0..4 {
        let mut p = e.proofs.clone();
        match which {
            0 => p[1].1.cnt_in += 1,
            1 => p[1].1.sum_in += 1,
            2 => p[1].1.cnt_out += 1,
            _ => p[1].1.sum_out += 1,
        }
        rej(&format!("exec counter {which}"), vex(&e, p), false);
    }
    // consistent changes, link checks pass, STARK must reject
    let mut p = e.proofs.clone();
    p[0].1.cnt_out += 1;
    p[1].1.cnt_in += 1;
    rej("exec deep cnt 0/1", vex(&e, p), true);
    let mut p = e.proofs.clone();
    p[1].1.sum_out += 1;
    p[2].1.sum_in += 1;
    rej("exec deep sum 1/2", vex(&e, p), true);
    // first chunk starting from non-zero
    let mut p = e.proofs.clone();
    p[0].1.cnt_in = 1;
    rej("exec cnt_in_0 = 1", vex(&e, p), false);
}

#[test]
fn exec_reject_n_blocks_chunk_changed() {
    let e = ex(6, 4, 3, &SPLIT3);
    let mut p = e.proofs.clone();
    p[1].1.n_blocks_chunk += 1;
    rej("exec n_blocks_chunk +1", vex(&e, p), false);
    let mut p = e.proofs.clone();
    p[1].1.n_blocks_chunk += 1;
    p[2].1.n_blocks_chunk -= 1;
    rej("exec n_blocks_chunk moved", vex(&e, p), true);
}

#[test]
fn exec_reject_chunk_structure() {
    let e = ex(6, 4, 3, &SPLIT3);
    for i in 0..3 {
        let mut p = e.proofs.clone();
        p.remove(i);
        rej(&format!("exec dropped chunk {i}"), vex(&e, p), false);
        let mut p = e.proofs.clone();
        p.remove(i);
        for (k, x) in p.iter_mut().enumerate() {
            x.1.chunk_index = k; // renumbered: still no valid chain
        }
        if let Some(l) = p.last_mut() {
            l.1.is_last = true;
        }
        rej(&format!("exec dropped+renumbered chunk {i}"), vex(&e, p), false);
    }
    // repeated chunk
    let mut p = e.proofs.clone();
    p.insert(2, e.proofs[1].clone());
    rej("exec repeated chunk", vex(&e, p), false);
    let mut p = e.proofs.clone();
    let mut dup = e.proofs[1].clone();
    dup.1.chunk_index = 2;
    p.insert(2, dup);
    p[3].1.chunk_index = 3;
    rej("exec repeated chunk, indices fixed", vex(&e, p), false);
    // swapped
    let mut p = e.proofs.clone();
    p.swap(1, 2);
    rej("exec swapped 1,2", vex(&e, p), false);
    let mut p = e.proofs.clone();
    p.swap(1, 2);
    p[1].1.chunk_index = 1;
    p[2].1.chunk_index = 2;
    p[1].1.is_last = false;
    p[2].1.is_last = true;
    rej("exec swapped 1,2, fields fixed", vex(&e, p), false);
}

#[test]
fn exec_reject_other_workload_chunk() {
    let e = ex(6, 4, 3, &SPLIT3);
    let b = ex(6, 4, 4, &SPLIT3); // same sizes, other records
    for i in 0..3 {
        let mut p = e.proofs.clone();
        p[i] = b.proofs[i].clone();
        rej(&format!("exec chunk {i} from other workload"), vex(&e, p), false);
    }
}

#[test]
fn exec_reject_wrong_claim_ctx_theta() {
    let e = ex(6, 4, 3, &SPLIT3);
    let (c, s) = e.w.reference_result(THETA);
    rej("exec claimed count+1", vex_claim(&e, e.proofs.clone(), c + 1, s), false);
    rej("exec claimed sum+1", vex_claim(&e, e.proofs.clone(), c, s + 1), false);
    let mut p = e.proofs.clone();
    p[1].1.ctx[0] += F::ONE;
    rej("exec ctx in one chunk", vex(&e, p), false);
    let mut p = e.proofs.clone();
    p[1].1.theta += 1;
    rej("exec theta in one chunk", vex(&e, p), false);
    // a chunk honestly proved under another ctx / theta
    let other = prove_exec_chunked(&e.w, THETA, [F::new(1), F::new(2), F::new(3), F::new(4)], default_options(), &SPLIT3).unwrap();
    let mut p = e.proofs.clone();
    p[1] = other[1].clone();
    rej("exec chunk proved under other ctx", vex(&e, p), false);
    let other = prove_exec_chunked(&e.w, THETA + 1, ctx(), default_options(), &SPLIT3).unwrap();
    let mut p = e.proofs.clone();
    p[2] = other[2].clone();
    rej("exec chunk proved under other theta", vex(&e, p), false);
}

#[test]
fn exec_reject_tampered_record_in_chunk() {
    let e = ex(6, 4, 3, &SPLIT3);
    // (a) prover builds the trace from tampered words but proves the honest public input
    let mut insts = exec_chunk_instances(&e.w, THETA, ctx(), &SPLIT3);
    insts[1].words[2][4] += F::ONE; // v of a record
    match insts[1].prove(default_options()) {
        Err(m) => eprintln!("  prover refused: {m}"),
        Ok(pr) => {
            let mut p = e.proofs.clone();
            p[1].0 = pr;
            rej("exec tampered record, honest public", vex(&e, p), true);
        }
    }
    // (b) a self-consistent forged chain (other workload with one record changed), spliced into the honest one
    for (idx_chunk, word) in [(1usize, 3usize), (2, 8)] {
        let mut w2 = e.w.clone();
        let g = idx_chunk * 2 * (w2.block_size + 1) + word; // a word inside the chunk
        w2.words[g][4] += F::ONE;
        let forged = prove_exec_chunked(&w2, THETA, ctx(), default_options(), &SPLIT3).unwrap();
        let mut p = e.proofs.clone();
        for i in idx_chunk..3 {
            p[i] = forged[i].clone();
        }
        rej(&format!("exec forged chain from chunk {idx_chunk}"), vex(&e, p), false);
        // the forged chain as a whole against the honest statement
        rej(&format!("exec whole forged chain {idx_chunk}"), vex(&e, forged), false);
    }
}

// ---------------------------------------------------------------- RC rejections
#[test]
fn rc_control_legal_accepted() {
    let r = rc(6, 4, 3, &SPLIT3);
    vrc(&r, r.proofs.clone()).unwrap();
}

#[test]
fn rc_reject_s_in_s_out_changed() {
    let r = rc(6, 4, 3, &SPLIT3);
    for j in [0usize, 5, 11] {
        let mut p = r.proofs.clone();
        p[1].1.s_in.as_mut().unwrap()[j] += F::ONE;
        rej(&format!("rc s_in[{j}]"), vrc(&r, p), false);
        let mut p = r.proofs.clone();
        p[1].1.s_in.as_mut().unwrap()[j] += F::ONE;
        p[0].1.s_out[j] += F::ONE;
        rej(&format!("rc deep s_in/s_out[{j}]"), vrc(&r, p), true);
        let mut p = r.proofs.clone();
        p[1].1.s_out[j] += F::ONE;
        rej(&format!("rc s_out[1][{j}]"), vrc(&r, p), false);
        let mut p = r.proofs.clone();
        p[1].1.s_out[j] += F::ONE;
        p[2].1.s_in.as_mut().unwrap()[j] += F::ONE;
        rej(&format!("rc deep s_out/s_in[1][{j}]"), vrc(&r, p), true);
    }
    let mut p = r.proofs.clone();
    p[2].1.s_out[5] += F::ONE;
    rej("rc last digest", vrc(&r, p), false);
}

#[test]
fn rc_reject_hdr_first_changed() {
    let r = rc(6, 4, 3, &SPLIT3);
    let mut p = r.proofs.clone();
    p[1].1.hdr_first[3] += F::ONE; // pid: only the STARK can see it
    rej("rc hdr_first[3] chunk1", vrc(&r, p), true);
    let mut p = r.proofs.clone();
    p[1].1.hdr_first[7] = F::ZERO;
    rej("rc hdr_first flag", vrc(&r, p), false);
    let mut p = r.proofs.clone();
    p[2].1.hdr_first[2] += F::ONE;
    rej("rc hdr_first m_b", vrc(&r, p), false);
    let mut p = r.proofs.clone();
    p[0].1.hdr_first[1] += F::ONE; // chunk 0 vs public header0
    rej("rc header0 chunk 0", vrc(&r, p), false);
}

#[test]
fn rc_reject_hdr_before_and_n_blocks() {
    let r = rc(6, 4, 3, &SPLIT3);
    for i in 0..3 {
        let mut p = r.proofs.clone();
        p[i].1.hdr_before += 1;
        rej(&format!("rc hdr_before chunk {i} +1"), vrc(&r, p), false);
    }
    let mut p = r.proofs.clone();
    p[1].1.n_blocks_chunk += 1;
    rej("rc n_blocks_chunk +1", vrc(&r, p), false);
    let mut p = r.proofs.clone();
    p[1].1.n_blocks_chunk += 1;
    p[2].1.n_blocks_chunk -= 1;
    p[2].1.hdr_before += 1;
    rej("rc n_blocks_chunk moved, hdr_before fixed", vrc(&r, p), true);
}

#[test]
fn rc_reject_chunk_structure() {
    let r = rc(6, 4, 3, &SPLIT3);
    for i in 0..3 {
        let mut p = r.proofs.clone();
        p.remove(i);
        rej(&format!("rc dropped chunk {i}"), vrc(&r, p), false);
    }
    let mut p = r.proofs.clone();
    p.insert(2, r.proofs[1].clone());
    rej("rc repeated chunk", vrc(&r, p), false);
    let mut p = r.proofs.clone();
    p.swap(1, 2);
    rej("rc swapped 1,2", vrc(&r, p), false);
    let mut p = r.proofs.clone();
    p.swap(1, 2);
    p[1].1.chunk_index = 1;
    p[2].1.chunk_index = 2;
    p[1].1.is_last = false;
    p[2].1.is_last = true;
    p[1].1.hdr_before = 2;
    p[2].1.hdr_before = 4;
    rej("rc swapped 1,2, fields fixed", vrc(&r, p), false);
    let b = rc(6, 4, 4, &SPLIT3);
    for i in 0..3 {
        let mut p = r.proofs.clone();
        p[i] = b.proofs[i].clone();
        rej(&format!("rc chunk {i} from other workload"), vrc(&r, p), false);
    }
}

#[test]
fn rc_reject_malformed_stream_and_tampered_record() {
    let r = rc(6, 4, 3, &SPLIT3);
    // tampered record word (a seq number off by one) proved against the honest public input
    let mut insts = rc_chunk_instances(&r.w, &SPLIT3);
    insts[1].words[2][2] += F::ONE;
    match insts[1].prove(default_options()) {
        Err(m) => eprintln!("  prover refused: {m}"),
        Ok(pr) => {
            let mut p = r.proofs.clone();
            p[1].0 = pr;
            rej("rc tampered record, honest public", vrc(&r, p), true);
        }
    }
    // a forged chain over a malformed stream (block header announces a wrong size) must not verify against D
    let mut w2 = r.w.clone();
    let g = 2 * (w2.block_size + 1); // header of block 2 = first word of chunk 1
    w2.words[g][2] += F::ONE;
    let forged = prove_rc_chunked(&w2, default_options(), &SPLIT3);
    match forged {
        Err(m) => eprintln!("  prover refused: {m}"),
        Ok(f) => rej("rc forged chain with bad m_b", vrc(&r, f), false),
    }
}

// ---------------------------------------------------------------- equivalence on random workloads
fn random_split(rng: &mut Rng, n_blocks: usize) -> Vec<usize> {
    let c = 1 + (rng.next_u64() as usize) % n_blocks.min(4);
    // c-1 distinct cut points in 1..n_blocks
    let mut cuts: Vec<usize> = Vec::new();
    while cuts.len() < c - 1 {
        let x = 1 + (rng.next_u64() as usize) % (n_blocks - 1);
        if !cuts.contains(&x) {
            cuts.push(x);
        }
    }
    cuts.sort_unstable();
    let mut v = Vec::new();
    let mut prev = 0;
    for x in cuts {
        v.push(x - prev);
        prev = x;
    }
    v.push(n_blocks - prev);
    v
}

#[test]
fn equivalence_random_workloads() {
    let cases = if cfg!(debug_assertions) { 6 } else { 60 };
    let mut rng = Rng::new(2911);
    let mut seen_chunks = [0usize; 5];
    for case in 0..cases {
        let nb = 1 + (rng.next_u64() as usize) % 12;
        let bs = 3 + (rng.next_u64() as usize) % 7;
        let theta = rng.next_u64() & ((1u64 << 32) - 1);
        let seed = rng.next_u64();
        let split = if case % 5 == 0 { plan_split(nb, bs, 4) } else { random_split(&mut rng, nb) };
        assert_eq!(split.iter().sum::<usize>(), nb);
        seen_chunks[split.len()] += 1;
        let w = Workload::synthetic(nb * bs, bs, seed);
        let (cnt, sum) = w.reference_result(theta);
        let proofs = match prove_exec_chunked(&w, theta, ctx(), default_options(), &split) {
            Ok(p) => p,
            Err(e) if cfg!(debug_assertions) => {
                // debug build only: a degenerate chunk (a constant column, e.g. no record matches) trips winterfell's degree check,
                // like the existing exec.rs / rc.rs do on degenerate data. Release is the gate.
                eprintln!("  debug-only skip case {case} nb={nb} bs={bs} theta={theta} split={split:?}: {e}");
                continue;
            }
            Err(e) => panic!("{e}"),
        };
        assert_eq!(proofs.last().unwrap().1.cnt_out, cnt);
        assert_eq!(proofs.last().unwrap().1.sum_out, sum);
        assert_eq!(proofs.last().unwrap().1.s_out[4..8], w.commitment()[..], "last digest = commitment");
        verify_exec_chunked(proofs, w.commitment(), nb, bs, theta, ctx(), cnt, sum)
            .unwrap_or_else(|e| panic!("case {case} exec nb={nb} bs={bs} split={split:?}: {e}"));
        if cfg!(debug_assertions) && split.contains(&1) {
            continue; // debug build: one-block RC chunk trips winterfell's degree check (see old_rc_one_block_debug_degree_check)
        }
        let rp = prove_rc_chunked(&w, default_options(), &split).unwrap();
        assert_eq!(rp.last().unwrap().1.s_out[4..8], w.commitment()[..]);
        verify_rc_chunked(rp, w.commitment(), nb, bs, w.header0())
            .unwrap_or_else(|e| panic!("case {case} rc nb={nb} bs={bs} split={split:?}: {e}"));
    }
    eprintln!("equivalence: {cases} workloads, chunk-count histogram (1..4) = {:?}", &seen_chunks[1..]);
    if !cfg!(debug_assertions) {
        assert!(seen_chunks[1..].iter().all(|&x| x > 0), "every chunk count 1..4 must occur");
    }
}

// ---------------------------------------------------------------- security estimates
#[test]
fn security_of_chunks_equals_single() {
    for (nb, bs, split) in [(6usize, 4usize, vec![2usize, 2, 2]), (12, 9, vec![8, 3, 1]), (8, 5, vec![5, 3])] {
        let w = Workload::synthetic(nb * bs, bs, 21);
        let (sp, _) = prove_exec(&w, THETA, ctx()).unwrap();
        let s0 = security_of(&sp);
        let (rp, _) = prove_rc(&w, default_options()).unwrap();
        let r0 = security_of(&rp);
        eprintln!(
            "single exec conj {} udr {} ldr {}; single rc conj {} udr {} ldr {}",
            s0.conjectured_bits, s0.proven_unique_decoding_bits, s0.proven_list_decoding_bits,
            r0.conjectured_bits, r0.proven_unique_decoding_bits, r0.proven_list_decoding_bits
        );
        for (pr, _) in prove_exec_chunked(&w, THETA, ctx(), default_options(), &split).unwrap() {
            let s = security_of(&pr);
            eprintln!("  exec chunk conj {} udr {} ldr {}", s.conjectured_bits, s.proven_unique_decoding_bits, s.proven_list_decoding_bits);
            assert_eq!(s.conjectured_bits, s0.conjectured_bits);
            assert_eq!(s.proven_unique_decoding_bits, s0.proven_unique_decoding_bits);
            // list-decoding bits depend on the trace length (a shorter chunk gives the same or more): never lower than the single proof
            assert!(s.proven_list_decoding_bits >= s0.proven_list_decoding_bits);
        }
        if cfg!(debug_assertions) && split.contains(&1) {
            continue;
        }
        for (pr, _) in prove_rc_chunked(&w, default_options(), &split).unwrap() {
            let s = security_of(&pr);
            eprintln!("  rc chunk conj {} udr {} ldr {}", s.conjectured_bits, s.proven_unique_decoding_bits, s.proven_list_decoding_bits);
            assert_eq!(s.conjectured_bits, r0.conjectured_bits);
            assert_eq!(s.proven_unique_decoding_bits, r0.proven_unique_decoding_bits);
            assert!(s.proven_list_decoding_bits >= r0.proven_list_decoding_bits);
        }
    }
}

// ---------------------------------------------------------------- debug-only degree artefact (existing code, reported not fixed)
#[test]
fn old_rc_one_block_debug_degree_check() {
    // The "hdr hold" constraint of R_RC is identically zero-degree (the hdr column is constant) when the stream has ONE block.
    // winterfell's DEBUG build then panics on "transition constraint degrees didn't match"; the release build does not check.
    // This is the unchanged rc.rs; the same happens for a one-block chunk of rc_link.rs. Informational: no assertion on the debug result.
    let w = Workload::synthetic(4, 4, 1);
    let r = prove_rc(&w, default_options());
    eprintln!("old prove_rc with ONE block, debug_assertions={}: {:?}", cfg!(debug_assertions), r.as_ref().map(|_| "ok").map_err(|e| e.clone()));
    if !cfg!(debug_assertions) {
        assert!(r.is_ok());
    }
}
