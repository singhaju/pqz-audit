//! (e405, `--threads T`) Driver glue for the two q-stages `audit_hit_q` and `groth16_prove_mint_q` when T > 1. No crypto here.
//! The q items are split into T contiguous ranges (sizes differ by at most 1); T scoped workers are created and ready (each has built
//! its own state, e.g. its own `StdRng::from_entropy()`) BEFORE the timer starts; a `Barrier` of the T workers releases them together.
//! The measured time is the wall time from the first worker's start (right after the barrier) to the last worker's end. Nothing is
//! shared or batched between items; the outputs come back in item order, so the single-thread checks work unchanged.
use std::ops::Range;
use std::sync::Barrier;
use std::time::Instant;

/// `threads` contiguous ranges that cover 0..q exactly once; the first `q % threads` ranges have one item more.
/// With threads > q the last ranges are empty (those workers are created but have nothing to do).
pub fn split_ranges(q: usize, threads: usize) -> Vec<Range<usize>> {
    assert!(threads >= 1, "threads must be >= 1");
    let (base, rem) = (q / threads, q % threads);
    let mut start = 0;
    (0..threads)
        .map(|t| {
            let len = base + usize::from(t < rem);
            let r = start..start + len;
            start += len;
            r
        })
        .collect()
}

/// Runs `work(&mut state, k)` for k = 0..q on `threads` scoped workers. `init()` is called once per worker, inside the worker, BEFORE the
/// barrier (untimed). Returns (outputs in item order, wall time in ms). Each item is processed exactly once.
pub fn run_split<S, O, I, W>(q: usize, threads: usize, init: I, work: W) -> (Vec<O>, f64)
where
    O: Send,
    I: Fn() -> S + Sync,
    W: Fn(&mut S, usize) -> O + Sync,
{
    let ranges = split_ranges(q, threads);
    let barrier = Barrier::new(threads);
    let (barrier, init, work) = (&barrier, &init, &work);
    let parts: Vec<(Vec<O>, Instant, Instant)> = std::thread::scope(|s| {
        let handles: Vec<_> = ranges
            .into_iter()
            .map(|r| {
                s.spawn(move || {
                    let mut st = init(); // untimed: the worker's own state (rng)
                    let mut out = Vec::with_capacity(r.len());
                    barrier.wait(); // releases only when all `threads` workers are ready
                    let t0 = Instant::now();
                    for k in r {
                        out.push(work(&mut st, k));
                    }
                    (out, t0, Instant::now())
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let t_start = parts.iter().map(|p| p.1).min().unwrap();
    let t_end = parts.iter().map(|p| p.2).max().unwrap();
    let ms = t_end.duration_since(t_start).as_secs_f64() * 1e3;
    // untimed: concatenate the ranges in order
    let mut out = Vec::with_capacity(q);
    for (v, _, _) in parts {
        out.extend(v);
    }
    (out, ms)
}
