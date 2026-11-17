use lhcpm::audit::{audit_q_all_ok, AuditCtx};
use lhcpm::circuits::*;
use lhcpm::mimc::Mimc;
use rand::{rngs::StdRng, SeedableRng};
use std::fs;
use std::hint::black_box;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

const BASELINE: &str = "lhcpm";

struct Row {
    stage: String,
    params: String,
    run: usize,
    ms: f64,
}

/// `f(i)` is the timed stage; `check(i, &output)` runs after the timer stops and must be true.
fn time_stage<T, F: FnMut(usize) -> T, C: Fn(usize, &T) -> bool>(stage: &str, params: &str, warmup: usize, runs: usize, rows: &mut Vec<Row>, mut f: F, check: C) {
    for i in 0..warmup {
        let o = f(i);
        assert!(check(i, &o), "{stage}: check failed in warm-up");
    }
    let mut v = Vec::with_capacity(runs);
    for r in 0..runs {
        let t = Instant::now();
        let o = black_box(f(warmup + r));
        let ms = t.elapsed().as_secs_f64() * 1e3;
        assert!(check(warmup + r, &o), "{stage}: check failed in timed run {r}");
        rows.push(Row { stage: stage.into(), params: params.into(), run: r, ms });
        v.push(ms);
    }
    report(stage, params, warmup, v);
}

/// Prints the median/min/max line (shared by `time_stage` and `time_stage_par`; output text unchanged).
fn report(stage: &str, params: &str, warmup: usize, mut v: Vec<f64>) {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let med = if v.len() % 2 == 1 { v[v.len() / 2] } else { (v[v.len() / 2 - 1] + v[v.len() / 2]) / 2.0 };
    println!("{BASELINE} {stage} [{params}]: median {med:.4} ms  min {:.4}  max {:.4}  ({} runs, {} warm-up)", v[0], v[v.len() - 1], v.len(), warmup);
}

/// e405 (`--threads T` > 1): like `time_stage`, but `f(i)` returns (output, ms) because the worker threads take the time themselves
/// (wall time from the barrier release to the last worker's end, see `lhcpm::par`). `check` runs after the timer stops and must be true.
fn time_stage_par<T, F: FnMut(usize) -> (T, f64), C: Fn(usize, &T) -> bool>(stage: &str, params: &str, warmup: usize, runs: usize, rows: &mut Vec<Row>, mut f: F, check: C) {
    for i in 0..warmup {
        let (o, _) = f(i);
        assert!(check(i, &o), "{stage}: check failed in warm-up");
    }
    let mut v = Vec::with_capacity(runs);
    for r in 0..runs {
        let (o, ms) = f(warmup + r);
        let o = black_box(o);
        assert!(check(warmup + r, &o), "{stage}: check failed in timed run {r}");
        rows.push(Row { stage: stage.into(), params: params.into(), run: r, ms });
        v.push(ms);
    }
    report(stage, params, warmup, v);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut runs = 30usize;
    let mut warmup = 3usize;
    let mut out = "results".to_string();
    let mut quick = false;
    let mut qs: Vec<usize> = Vec::new(); // --q LIST: adds audit_hit_q and groth16_verify_q
    let mut params_tag = String::new(); // --params-tag TAG: appended to every params string
    let mut runs_big = 5usize; // timed runs when q > big_above (work per run is large), warm-up 1
    let mut big_above = 2000usize;
    let mut only_q = false; // --only-q: skip the base stages (opt-in; not in SPEC-w16)
    // w19 additions (matched coverage for Figs. 2 and 5); defaults leave every earlier behaviour unchanged
    let mut only_audit_q = false; // --only-audit-q: with --q, run ONLY stage audit_hit_q (no verify, no prove)
    let mut mint_qs: Vec<usize> = Vec::new(); // --mint-q LIST: stage groth16_prove_mint_q (q Mint stand-in proofs, one after the other, per timed run)
    let mut mint_runs = 3usize; // --mint-runs R: timed runs of each groth16_prove_mint_q
    let mut mint_warmup = 0usize; // --mint-warmup W
    let mut only_mint_q = false; // --only-mint-q: run ONLY groth16_prove_mint_q (no audit setup, no other stage)
    // e405 addition: --threads T (default 1) applies ONLY to audit_hit_q and groth16_prove_mint_q; T = 1 = the old single-thread path (same code, same params)
    let mut threads = 1usize; // --threads T: T > 1 splits the q items of those two stages into T contiguous ranges on T scoped workers (barrier start, own rng each); params gets ";threads=T"
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--runs" => { i += 1; runs = args[i].parse().unwrap(); }
            "--warmup" => { i += 1; warmup = args[i].parse().unwrap(); }
            "--out" => { i += 1; out = args[i].clone(); }
            "--quick" => quick = true,
            "--q" => { i += 1; qs = args[i].split(',').map(|x| x.trim().parse().expect("--q needs a comma list of integers")).collect(); assert!(qs.iter().all(|&q| q >= 1), "--q values must be >= 1"); }
            "--params-tag" => { i += 1; params_tag = args[i].clone(); assert!(!params_tag.contains(',') && !params_tag.contains('\n'), "--params-tag must not contain a comma"); }
            "--runs-big" => { i += 1; runs_big = args[i].parse().unwrap(); }
            "--big-above" => { i += 1; big_above = args[i].parse().unwrap(); }
            "--only-q" => only_q = true,
            "--only-audit-q" => only_audit_q = true,
            "--mint-q" => { i += 1; mint_qs = args[i].split(',').map(|x| x.trim().parse().expect("--mint-q needs a comma list of integers")).collect(); assert!(mint_qs.iter().all(|&q| q >= 1), "--mint-q values must be >= 1"); }
            "--mint-runs" => { i += 1; mint_runs = args[i].parse().unwrap(); assert!(mint_runs >= 1); }
            "--mint-warmup" => { i += 1; mint_warmup = args[i].parse().unwrap(); }
            "--only-mint-q" => only_mint_q = true,
            "--threads" => { i += 1; threads = args[i].parse().expect("--threads needs an integer"); assert!(threads >= 1, "--threads must be >= 1"); }
            x => panic!("unknown argument {x}"),
        }
        i += 1;
    }
    let (cache_entries, mut instances) = if quick { runs = 3; warmup = 1; (64, 4) } else { (1024, 16) };
    let max_q = qs.iter().copied().max().unwrap_or(0);
    instances = instances.max(max_q); // q different ciphertexts need at least q instances (only changes anything with --q)
    let tag = |p: String| if params_tag.is_empty() { p } else { format!("{p};{params_tag}") };
    let total = runs + warmup;
    let mut rng = StdRng::from_entropy();
    let mut rows: Vec<Row> = Vec::new();

    // ---- stage 1: audit_hit (setup: keys, H(pk_G), cache, ciphertexts; untimed) ----
    if !only_mint_q {
    let (ctx, insts) = AuditCtx::setup(&mut rng, cache_entries, instances);
    let params = format!("n={};logq={};t=2^{}", ctx.params.n, ctx.params.log_q(), ctx.params.tlog);
    if !only_q && !only_audit_q {
        time_stage(
            "audit_hit",
            &tag(params.clone()),
            warmup,
            runs,
            &mut rows,
            |i| {
                let inst = &insts[i % insts.len()];
                ctx.audit(black_box(&inst.tx_id), black_box(&inst.ct), black_box(&inst.cm_g), black_box(&inst.r_shared))
            },
            |i, r| *r == Ok(insts[i % insts.len()].m),
        );
    }
    // ---- stage 1q: audit_hit_q = q independent audits (q different ciphertexts) in ONE timed run ----
    for &q in &qs {
        let (r, w, big) = if q > big_above { (runs_big, 1, true) } else { (runs, warmup, false) };
        if threads == 1 {
            let p = tag(format!("{params};q={q}{}", if big { format!(";runs={r}") } else { String::new() }));
            time_stage("audit_hit_q", &p, w, r, &mut rows, |i| ctx.audit_q(&insts, black_box(i * q), q), |i, res| res.len() == q && audit_q_all_ok(&insts, i * q, res));
        } else {
            let p = tag(format!("{params};q={q}{};threads={threads}", if big { format!(";runs={r}") } else { String::new() }));
            time_stage_par("audit_hit_q", &p, w, r, &mut rows, |i| ctx.audit_q_threads(&insts, black_box(i * q), q, threads), |i, res| res.len() == q && audit_q_all_ok(&insts, i * q, res));
        }
    }
    drop(ctx);
    drop(insts);
    }

    let consts = Arc::new(Mimc::new().c);
    let skip_rest = only_audit_q || only_mint_q; // stages 2 to 4 are skipped when only the w19 stages are wanted

    // ---- stage 2: groth16_verify (setup + proofs untimed; prepared vk) ----
    let pub_list: Vec<usize> = if only_q || skip_rest { vec![] } else if quick { vec![3] } else { vec![3, 13] };
    for pubs in pub_list {
        let vs = VerifySetup::new(pubs, 8, &consts, &mut rng);
        let params = tag(format!("public_inputs={pubs}"));
        time_stage("groth16_verify", &params, warmup, runs, &mut rows, |i| vs.verify(black_box(i)), |_, ok| *ok);
    }
    // ---- stage 2q: groth16_verify_q = q different proofs (3 public inputs) verified in ONE timed run ----
    if max_q > 0 && !skip_rest {
        let vs = VerifySetup::new(3, max_q.max(8), &consts, &mut rng);
        for &q in &qs {
            let (r, w, big) = if q > big_above { (runs_big, 1, true) } else { (runs, warmup, false) };
            let p = tag(format!("public_inputs=3;q={q}{}", if big { format!(";runs={r}") } else { String::new() }));
            time_stage("groth16_verify_q", &p, w, r, &mut rows, |i| vs.verify_q(black_box(i * q), q), |_, ok| *ok == q);
        }
    }

    // ---- stages 3, 4: proving on stand-in circuits (circuit-specific setup untimed) ----
    let prove_list: Vec<(&str, usize)> = if only_q || skip_rest { vec![] } else { vec![("groth16_prove_mint", 2676usize), ("groth16_prove_transfer", 8786usize)] };
    for (stage, target) in prove_list {
        let ps = ProveSetup::new(target, total, &consts, &mut rng);
        let params = tag(format!("constraints={}", ps.constraints));
        let mut prng = StdRng::from_entropy();
        time_stage(stage, &params, warmup, runs, &mut rows, |i| ps.prove(black_box(i), &mut prng), |i, proof| ps.check(i, proof));
    }
    // ---- stage 3q (w19): groth16_prove_mint_q = q Mint stand-in proofs (2676 constraints) one after the other, one thread, per timed run ----
    // Matched coverage for Fig. 5: L-HCPM proves ONE transaction at a time, so N_Q records = N_Q proofs. Witness synthesis is inside the timer (as in
    // groth16_prove_mint); every proof gets fresh Groth16 randomness; the q witnesses are distinct inside a run and reused between runs.
    // The check (all q proofs verify) runs after the timer stops.
    for &q in &mint_qs {
        let ps = ProveSetup::new(2676, q, &consts, &mut rng);
        if threads == 1 {
            let params = tag(format!("constraints={};q={q};runs={mint_runs}", ps.constraints));
            let mut prng = StdRng::from_entropy();
            time_stage("groth16_prove_mint_q", &params, mint_warmup, mint_runs, &mut rows, |_| ps.prove_q(0, q, &mut prng), |_, proofs| proofs.len() == q && ps.check_q(0, proofs));
        } else {
            // T > 1 (e405): same q witnesses (item k = witness k), T workers each with its own rng made before the barrier; all q proofs checked after the timer
            let params = tag(format!("constraints={};q={q};runs={mint_runs};threads={threads}", ps.constraints));
            time_stage_par("groth16_prove_mint_q", &params, mint_warmup, mint_runs, &mut rows, |_| ps.prove_q_threads(0, q, threads), |_, proofs| proofs.len() == q && ps.check_q(0, proofs));
        }
    }

    fs::create_dir_all(&out).unwrap();
    let mut f = fs::File::create(format!("{out}/raw_runs.csv")).unwrap();
    writeln!(f, "baseline,stage,params,run,ms").unwrap();
    for r in &rows {
        writeln!(f, "{BASELINE},{},{},{},{:.6}", r.stage, r.params, r.run, r.ms).unwrap();
    }
    println!("wrote {out}/raw_runs.csv ({} rows)", rows.len());
}
