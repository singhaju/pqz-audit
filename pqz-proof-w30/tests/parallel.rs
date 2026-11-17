//! w30 gates for the parallel-chunks mode (par_link.rs). Run with `cargo test --release --test parallel` (both hash builds).
//!
//! 1. Boundary values (S_in, cnt_in, sum_in, hdr_before, s_out, cnt_out, sum_out) are computed natively BEFORE any proof
//!    (`chain_link::reference_chunks`, used by `exec_chunk_instances` / `rc_chunk_instances`, which is also what the sequential
//!    `prove_*_chunked` consume). The test compares them with values read from TRACES: (a) the last real row of each chunk trace and
//!    row 0 of the next one, (b) the one-chunk trace of the whole stream at the row where the chunk starts. No proof is needed for that.
//! 2. The parallel proofs verify with the unchanged verifiers (1..4 chunks, both relations, different thread totals) and carry the same
//!    public inputs as the sequential mode.

use pqz_proof::chain_link::{initial_state, reference_chunks};
use pqz_proof::data::{Rng, Workload};
use pqz_proof::exec_link::*;
use pqz_proof::par_link::*;
use pqz_proof::prove::default_options;
use pqz_proof::rc_link::*;
use pqz_proof::rescue::F;
use pqz_proof::split::plan_split;
use winterfell::math::FieldElement;
use winterfell::TraceTable;

const THETA: u64 = 1 << 31;
// column indices (as in exec_link.rs / rc_link.rs; the AIR files are not edited in w30)
const E_CNT: usize = 31;
const E_SUM: usize = 32;
const R_HDR: usize = 25;
const GROUP: usize = 8;

fn ctx() -> [F; 4] {
    [F::new(11), F::new(22), F::new(33), F::new(44)]
}

/// split of `nb` blocks into exactly `c` chunks (c <= nb), random sizes
fn split_into(rng: &mut Rng, nb: usize, c: usize) -> Vec<usize> {
    let mut cuts: Vec<usize> = Vec::new();
    while cuts.len() < c - 1 {
        let x = 1 + (rng.next_u64() as usize) % (nb - 1);
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
    v.push(nb - prev);
    v
}

fn state_at(t: &TraceTable<F>, row: usize) -> [F; 12] {
    let mut s = [F::ZERO; 12];
    for j in 0..12 {
        s[j] = t.get(j, row);
    }
    s
}

#[test]
fn boundary_values_equal_trace_values_50_workloads_both_relations() {
    let mut rng = Rng::new(3030);
    let mut hist = [0usize; 5];
    for case in 0..50usize {
        let c = 1 + case % 4;
        let nb = c + (rng.next_u64() as usize) % 10; // nb >= c
        let bs = 3 + (rng.next_u64() as usize) % 7;
        let theta = rng.next_u64() & ((1u64 << 32) - 1);
        let seed = rng.next_u64();
        let split = if c == 1 { vec![nb] } else { split_into(&mut rng, nb, c) };
        hist[split.len()] += 1;
        let w = Workload::synthetic(nb * bs, bs, seed);
        let total = w.n_groups();
        let (cnt_all, sum_all) = w.reference_result(theta);
        let refs = reference_chunks(&w, theta, &split);
        assert_eq!(refs.len(), c);
        let exec_inst = exec_chunk_instances(&w, theta, ctx(), &split);
        let rc_inst = rc_chunk_instances(&w, &split);

        // the one-chunk trace of the whole stream (independent of the split)
        let whole_e = build_exec_chunk_trace(&w.words, initial_state(total), 0, 0, theta);
        let whole_r = build_rc_chunk_trace(&w.words, initial_state(total), w.block_size, 0);
        let last_row = total * GROUP - 1;
        assert_eq!(whole_e.get(E_CNT, last_row).as_int(), cnt_all);
        assert_eq!(whole_e.get(E_SUM, last_row).as_int(), sum_all);
        assert_eq!(whole_e.get(4, last_row), w.commitment()[0]);

        let words_per_block = bs + 1;
        let mut first_word = 0usize;
        let mut prev_out: Option<([F; 12], u64, u64, usize)> = None;
        for (i, r) in refs.iter().enumerate() {
            let ei = &exec_inst[i];
            let ri = &rc_inst[i];
            // (0) the instances the sequential prover consumes carry the same numbers
            assert_eq!(ei.public.s_in, r.s_in);
            assert_eq!((ei.public.cnt_in, ei.public.sum_in), (r.cnt_in, r.sum_in));
            assert_eq!((ei.public.cnt_out, ei.public.sum_out), (r.cnt_out, r.sum_out));
            assert_eq!(ri.public.s_in, r.s_in);
            assert_eq!(ri.public.hdr_before, r.hdr_before);
            assert_eq!(ei.start, r.s_in.unwrap_or_else(|| initial_state(total)));
            // (a) chunk traces: last real row holds s_out / cnt_out / sum_out / hdr_before + n_blocks
            let te = ei.build_trace();
            let tr = ri.build_trace();
            let last = r.n_words * GROUP - 1;
            let so = state_at(&te, last);
            assert_eq!(so, r.s_out, "case {case} exec chunk {i}: S at last row");
            assert_eq!(state_at(&tr, last), r.s_out, "case {case} rc chunk {i}: S at last row");
            assert_eq!(te.get(E_CNT, last).as_int(), r.cnt_out);
            assert_eq!(te.get(E_SUM, last).as_int(), r.sum_out);
            assert_eq!(te.get(E_CNT, 0).as_int(), r.cnt_in);
            assert_eq!(te.get(E_SUM, 0).as_int(), r.sum_in);
            assert_eq!(tr.get(R_HDR, last).as_int() as usize, r.hdr_before + r.n_blocks);
            assert_eq!(tr.get(R_HDR, 0).as_int() as usize, r.hdr_before + 1);
            // chain: this chunk starts where the previous one ended
            if let Some((ps, pc, pm, ph)) = prev_out {
                assert_eq!(r.s_in.unwrap(), ps);
                assert_eq!((r.cnt_in, r.sum_in), (pc, pm));
                assert_eq!(r.hdr_before, ph);
            }
            // (b) whole-stream trace at the row before this chunk's first word
            if i > 0 {
                let row = first_word * GROUP - 1;
                assert_eq!(state_at(&whole_e, row), r.s_in.unwrap(), "case {case} chunk {i}: s_in vs whole trace");
                assert_eq!(state_at(&whole_r, row), r.s_in.unwrap());
                assert_eq!(whole_e.get(E_CNT, row).as_int(), r.cnt_in);
                assert_eq!(whole_e.get(E_SUM, row).as_int(), r.sum_in);
                assert_eq!(whole_r.get(R_HDR, row).as_int() as usize, r.hdr_before);
            }
            prev_out = Some((r.s_out, r.cnt_out, r.sum_out, r.hdr_before + r.n_blocks));
            first_word += r.n_blocks * words_per_block;
        }
        assert_eq!(first_word, total);
        let last = refs.last().unwrap();
        assert_eq!((last.cnt_out, last.sum_out), (cnt_all, sum_all));
        assert_eq!(last.s_out[4..8], w.commitment()[..]);
        assert_eq!(last.hdr_before + last.n_blocks, nb);
    }
    eprintln!("boundary test: 50 workloads, chunk-count histogram (1..4) = {:?}", &hist[1..]);
    assert!(hist[1..].iter().all(|&x| x >= 12));
}

fn dbg_pubs<P: std::fmt::Debug>(v: &[(winterfell::Proof, P)]) -> Vec<String> {
    v.iter().map(|(_, p)| format!("{p:?}")).collect()
}

#[test]
fn exec_parallel_proofs_verify_1_to_4_chunks() {
    for split in [vec![8usize], vec![4, 4], vec![3, 3, 2], vec![3, 2, 2, 1]] {
        let w = Workload::synthetic(8 * 4, 4, 5);
        let (cnt, sum) = w.reference_result(THETA);
        for threads in [1usize, 3, 6, total_threads()] {
            let (par, st) = prove_exec_chunked_parallel(&w, THETA, ctx(), default_options(), &split, threads).unwrap();
            assert_eq!(par.len(), split.len());
            assert_eq!(st.threads.len(), split.len());
            if threads >= split.len() {
                assert_eq!(st.threads.iter().sum::<usize>(), threads);
            }
            assert!(st.wall_s >= st.boundary_s && st.boundary_s >= 0.0);
            // same publics as the sequential mode, same verifier
            let seq = prove_exec_chunked(&w, THETA, ctx(), default_options(), &split).unwrap();
            assert_eq!(dbg_pubs(&par), dbg_pubs(&seq));
            verify_exec_chunked(par, w.commitment(), w.n_blocks, w.block_size, THETA, ctx(), cnt, sum)
                .unwrap_or_else(|e| panic!("split {split:?} threads {threads}: {e}"));
        }
    }
}

#[test]
fn rc_parallel_proofs_verify_1_to_4_chunks() {
    for split in [vec![8usize], vec![4, 4], vec![3, 3, 2], vec![3, 2, 2, 1]] {
        if cfg!(debug_assertions) && split.contains(&1) {
            continue; // debug build only: one-block RC chunk trips winterfell's degree check (see linked.rs)
        }
        let w = Workload::synthetic(8 * 4, 4, 5);
        for threads in [1usize, 3, 6, total_threads()] {
            let (par, st) = prove_rc_chunked_parallel(&w, default_options(), &split, threads).unwrap();
            assert_eq!(par.len(), split.len());
            if threads >= split.len() {
                assert_eq!(st.threads.iter().sum::<usize>(), threads);
            }
            let seq = prove_rc_chunked(&w, default_options(), &split).unwrap();
            assert_eq!(dbg_pubs(&par), dbg_pubs(&seq));
            verify_rc_chunked(par, w.commitment(), w.n_blocks, w.block_size, w.header0())
                .unwrap_or_else(|e| panic!("split {split:?} threads {threads}: {e}"));
        }
    }
}

#[test]
fn parallel_with_plan_split_and_a_tampered_parallel_proof_is_rejected() {
    // a split the paper's runs would use (several unequal chunks), then a changed public value must be rejected by the same verifier
    let w = Workload::synthetic(40 * 5, 5, 77);
    let split = plan_split(w.n_blocks, w.block_size, 4);
    let (cnt, sum) = w.reference_result(THETA);
    let (par, _) = prove_exec_chunked_parallel(&w, THETA, ctx(), default_options(), &split, total_threads()).unwrap();
    verify_exec_chunked(par.clone(), w.commitment(), w.n_blocks, w.block_size, THETA, ctx(), cnt, sum).unwrap();
    if par.len() > 1 {
        let mut bad = par.clone();
        bad[1].1.cnt_in += 1;
        assert!(verify_exec_chunked(bad, w.commitment(), w.n_blocks, w.block_size, THETA, ctx(), cnt, sum).is_err());
    }
}

#[cfg(feature = "concurrent")]
#[test]
fn each_chunk_runs_in_its_own_pool_of_the_requested_size() {
    let th = [5usize, 3, 1, 2];
    let got = run_in_pools(vec![0usize, 1, 2, 3], &th, |i| (i, rayon::current_num_threads()));
    for (i, n) in got {
        assert_eq!(n, th[i], "chunk {i}");
    }
    // the chunks really run at the same time: all four wait for each other (would deadlock if run one after the other)
    let barrier = std::sync::Barrier::new(4);
    let _ = run_in_pools(vec![(); 4], &[2, 2, 1, 1], |_| {
        barrier.wait();
    });
}
