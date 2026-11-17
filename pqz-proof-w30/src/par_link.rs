//! w30 (NEW file): PARALLEL proving of the linked chunks of w29 (plan `journal2/UPGRADE-w30-plan.md`, section 5).
//!
//! Why this is possible: the public link values of chunk i (S_in, cnt_in, sum_in, hdr_before, hdr_first) are NOT taken from the trace
//! of chunk i-1. In `chain_link::reference_chunks` they come from the reference sponge (`rescue::perm`) run natively over the earlier
//! records plus plain counting. `exec_chunk_instances` / `rc_chunk_instances` call it for ALL chunks before any proof is made. So
//! the chunks are independent proving jobs. The AIRs, the publics and the verifier are untouched; the proofs verify with
//! `verify_exec_chunked` / `verify_rc_chunked` exactly as the sequential ones.
//!
//! Mode: (1) boundary values of all chunks (single thread, native), (2) one OS thread per chunk; each thread builds its own rayon
//! `ThreadPool` (winterfell's `concurrent` feature uses rayon) and runs trace build + proof inside `pool.install`. Threads are
//! split between the chunks in proportion to their padded rows (`split_threads`).
//!
//! Timer boundary (`ParStats::wall_s`): from the start of (1) to the moment the last chunk proof is returned (includes boundary
//! values, copying the chunk words, creating and dropping the pools, trace building, proving). Serialising and verification are
//! not included.

use crate::data::Workload;
use crate::exec_link::{exec_chunk_instances, ExecChunkPublic};
use crate::rc_link::{rc_chunk_instances, RcChunkPublic};
use crate::rescue::F;
use crate::split::chunk_rows;
use std::time::Instant;
use winterfell::{Proof, ProofOptions};

/// Threads that the rayon global pool has (the pool of every sequential prove): all logical cores unless RAYON_NUM_THREADS is set.
pub fn total_threads() -> usize {
    #[cfg(feature = "concurrent")]
    {
        rayon::current_num_threads()
    }
    #[cfg(not(feature = "concurrent"))]
    {
        1
    }
}

/// Thread split rule: every chunk gets at least 1 thread; the rest of `total` is shared in proportion to the padded rows
/// (largest-remainder rounding; ties go to the higher chunk index when adding, to the lower when removing; both are fixed rules).
/// The result sums to `total` when `total >= rows.len()`; when there are fewer threads than chunks every chunk gets 1
/// (the sum is then `rows.len()`).
pub fn split_threads(rows: &[usize], total: usize) -> Vec<usize> {
    let k = rows.len();
    assert!(k > 0 && rows.iter().all(|&r| r > 0));
    if total <= k {
        return vec![1; k];
    }
    let sum: f64 = rows.iter().map(|&r| r as f64).sum();
    let ideal: Vec<f64> = rows.iter().map(|&r| total as f64 * r as f64 / sum).collect();
    let mut t: Vec<usize> = ideal.iter().map(|&x| (x.floor() as usize).max(1)).collect();
    let cmp = |a: &f64, b: &f64| a.partial_cmp(b).unwrap();
    while t.iter().sum::<usize>() < total {
        // one more thread to the chunk with the largest shortfall (ideal - t)
        let i = (0..k).max_by(|&a, &b| cmp(&(ideal[a] - t[a] as f64), &(ideal[b] - t[b] as f64))).unwrap();
        t[i] += 1;
    }
    while t.iter().sum::<usize>() > total {
        // take one from the chunk (with more than 1) that is most over-served
        let i = (0..k).filter(|&i| t[i] > 1).min_by(|&a, &b| cmp(&(ideal[a] - t[a] as f64), &(ideal[b] - t[b] as f64))).unwrap();
        t[i] -= 1;
    }
    t
}

#[cfg(feature = "concurrent")]
fn in_pool<T: Send>(threads: usize, g: impl FnOnce() -> T + Send) -> T {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().expect("rayon pool");
    pool.install(g)
}
#[cfg(not(feature = "concurrent"))]
fn in_pool<T: Send>(_threads: usize, g: impl FnOnce() -> T + Send) -> T {
    g()
}

/// Run `f` on every item at the same time: item i on its own OS thread, inside its own rayon pool of `threads[i]` threads.
pub fn run_in_pools<I: Send, R: Send, G: Fn(I) -> R + Sync>(items: Vec<I>, threads: &[usize], f: G) -> Vec<R> {
    assert_eq!(items.len(), threads.len());
    std::thread::scope(|s| {
        let hs: Vec<_> = items
            .into_iter()
            .zip(threads.iter().copied())
            .map(|(it, t)| {
                let f = &f;
                s.spawn(move || in_pool(t, move || f(it)))
            })
            .collect();
        hs.into_iter().map(|h| h.join().expect("chunk thread panicked")).collect()
    })
}

/// Measurements of one parallel run (seconds).
#[derive(Clone, Debug)]
pub struct ParStats {
    /// boundary values of all chunks (reference sponge + counting + copying the chunk words)
    pub boundary_s: f64,
    /// TIMED VALUE: start of the boundary computation to the last chunk proof done
    pub wall_s: f64,
    /// threads per chunk (the split rule)
    pub threads: Vec<usize>,
    /// padded rows per chunk
    pub rows: Vec<usize>,
    /// trace build time per chunk (inside the chunk's own thread; information)
    pub trace_s: Vec<f64>,
    /// proving time per chunk (information)
    pub prove_s: Vec<f64>,
}

type Done<P> = Result<(Proof, P, f64, f64), String>;

fn collect<P>(
    done: Vec<Done<P>>,
    boundary_s: f64,
    wall: Instant,
    threads: Vec<usize>,
    rows: Vec<usize>,
) -> Result<(Vec<(Proof, P)>, ParStats), String> {
    let wall_s = wall.elapsed().as_secs_f64();
    let mut proofs = Vec::new();
    let (mut tr, mut pr) = (Vec::new(), Vec::new());
    for d in done {
        let (proof, p, t, s) = d?;
        proofs.push((proof, p));
        tr.push(t);
        pr.push(s);
    }
    Ok((proofs, ParStats { boundary_s, wall_s, threads, rows, trace_s: tr, prove_s: pr }))
}

/// R_Exec: all chunk proofs at the same time. `threads` = total number of threads (e.g. `total_threads()`).
pub fn prove_exec_chunked_parallel(
    w: &Workload,
    theta: u64,
    ctx: [F; 4],
    options: ProofOptions,
    split: &[usize],
    threads: usize,
) -> Result<(Vec<(Proof, ExecChunkPublic)>, ParStats), String> {
    let wall = Instant::now();
    let inst = exec_chunk_instances(w, theta, ctx, split);
    let boundary_s = wall.elapsed().as_secs_f64();
    let rows: Vec<usize> = split.iter().map(|&b| chunk_rows(b, w.block_size)).collect();
    let th = split_threads(&rows, threads);
    let done = run_in_pools(inst, &th, |c| {
        let t0 = Instant::now();
        let trace = c.build_trace();
        let t = t0.elapsed().as_secs_f64();
        let t1 = Instant::now();
        let proof = c.prove_trace(trace, options.clone())?;
        Ok((proof, c.public, t, t1.elapsed().as_secs_f64()))
    });
    collect(done, boundary_s, wall, th, rows)
}

/// R_RC: all chunk proofs at the same time.
pub fn prove_rc_chunked_parallel(
    w: &Workload,
    options: ProofOptions,
    split: &[usize],
    threads: usize,
) -> Result<(Vec<(Proof, RcChunkPublic)>, ParStats), String> {
    let wall = Instant::now();
    let inst = rc_chunk_instances(w, split);
    let boundary_s = wall.elapsed().as_secs_f64();
    let rows: Vec<usize> = split.iter().map(|&b| chunk_rows(b, w.block_size)).collect();
    let th = split_threads(&rows, threads);
    let done = run_in_pools(inst, &th, |c| {
        let t0 = Instant::now();
        let trace = c.build_trace();
        let t = t0.elapsed().as_secs_f64();
        let t1 = Instant::now();
        let proof = c.prove_trace(trace, options.clone())?;
        Ok((proof, c.public, t, t1.elapsed().as_secs_f64()))
    });
    collect(done, boundary_s, wall, th, rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_split_rules() {
        assert_eq!(split_threads(&[1024], 22), vec![22]);
        assert_eq!(split_threads(&[512, 512], 22), vec![11, 11]);
        let s = split_threads(&[65536, 32768, 1024, 32], 22);
        assert_eq!(s.iter().sum::<usize>(), 22);
        assert!(s.iter().all(|&x| x >= 1));
        assert!(s.windows(2).all(|w| w[0] >= w[1]), "{s:?}");
        // fewer threads than chunks: 1 each
        assert_eq!(split_threads(&[64, 32, 32, 32], 3), vec![1, 1, 1, 1]);
        assert_eq!(split_threads(&[64, 32], 2), vec![1, 1]);
        for total in 1..=40usize {
            for rows in [
                vec![32usize],
                vec![64, 32],
                vec![1024, 512, 32],
                vec![4096, 2048, 64, 32],
                vec![32, 32, 32, 32],
                vec![8192, 32, 32, 32],
            ] {
                let t = split_threads(&rows, total);
                assert_eq!(t.len(), rows.len());
                assert!(t.iter().all(|&x| x >= 1));
                if total >= rows.len() {
                    assert_eq!(t.iter().sum::<usize>(), total, "{rows:?} {total} {t:?}");
                }
                for i in 0..rows.len() {
                    for j in 0..rows.len() {
                        if rows[i] > rows[j] {
                            assert!(t[i] >= t[j], "{rows:?} {total} {t:?}");
                        }
                    }
                }
            }
        }
    }
}
