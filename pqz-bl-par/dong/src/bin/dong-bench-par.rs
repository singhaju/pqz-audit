//! Timing harness (pqz-bl SPEC rule 5): one thread, std::time::Instant, warm-up runs untimed,
//! timed runs, each run = the whole named stage with a fresh random challenge. Keys, data and tags
//! are generated before timing. Output: raw_runs.csv (baseline,stage,params,run,ms) + summary lines.

use pqz_bl_dong_par::{challenge, make_audits, proof_gen, proof_verify, proof_verify_many, setup, S};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::hint::black_box;
use std::io::Write;
use std::time::Instant;

fn main() {
    eprintln!("rayon threads = {} (RAYON_NUM_THREADS, default all cores)", rayon::current_num_threads());
    let args: Vec<String> = std::env::args().collect();
    let mut runs = 30usize;
    let mut warmup = 3usize;
    let mut out = String::from("results");
    let mut quick = false;
    // SPEC-w16 options (all optional; without --cov / --q the old grid runs unchanged)
    let mut cov: Option<Vec<usize>> = None;
    let mut qs: Option<Vec<usize>> = None;
    let mut runs_big = 5usize;
    let mut big_above = 2000usize;
    let mut tag = String::new();
    let mut n_factor = 10usize;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--runs" => { runs = args[i + 1].parse().expect("--runs N"); i += 1; }
            "--warmup" => { warmup = args[i + 1].parse().expect("--warmup N"); i += 1; }
            "--out" => { out = args[i + 1].clone(); i += 1; }
            "--quick" => quick = true,
            "--cov" => { cov = Some(parse_list(&args[i + 1], "--cov")); i += 1; }
            "--q" => { qs = Some(parse_list(&args[i + 1], "--q")); i += 1; }
            "--runs-big" => { runs_big = args[i + 1].parse().expect("--runs-big R"); i += 1; }
            "--big-above" => { big_above = args[i + 1].parse().expect("--big-above X"); i += 1; }
            "--params-tag" => { tag = args[i + 1].clone(); i += 1; }
            "--n-factor" => { n_factor = args[i + 1].parse().expect("--n-factor F"); i += 1; }
            other => { eprintln!("unknown argument {other}"); std::process::exit(2); }
        }
        i += 1;
    }
    if quick {
        runs = 3;
        warmup = 1;
    }
    // paper's grid c = 10..100 (line 1063-1066); 350 and 1000 are EXTRA points (ours)
    let grid: Vec<(usize, bool)> = if quick {
        vec![(10, false), (50, false)]
    } else {
        let mut g: Vec<(usize, bool)> = (1..=10).map(|k| (k * 10, false)).collect();
        g.push((350, true));
        g.push((1000, true));
        g
    };

    std::fs::create_dir_all(&out).expect("create out dir");
    let mut csv = std::fs::File::create(format!("{out}/raw_runs.csv")).expect("raw_runs.csv");
    writeln!(csv, "baseline,stage,params,run,ms").unwrap();

    let mut rng = ChaCha20Rng::from_seed([0x5a; 32]); // OURS: fixed seed for keys/data; challenges differ per run

    if cov.is_some() || qs.is_some() {
        // SPEC-w16 sweep: stages proofgen / verify at c = cov (s = 3), verify_q for every q in --q.
        // --q alone means Exp 4b: cov = 1000, stage verify_q only.
        let only_q = cov.is_none();
        let covs = cov.unwrap_or_else(|| vec![1000]);
        for &c in &covs {
            let n = n_factor.max(2) * c; // n = n_factor * c blocks (default 10 c, as in the default grid); c <= n always
            let sweep_tag = |extra: &str| {
                let mut p = format!("s={S};c={c}{extra}");
                if !tag.is_empty() { p.push(';'); p.push_str(&tag); }
                p
            };
            let (r_small, w_small) = (runs, warmup);
            let pick = |work: usize| if work > big_above { (runs_big, 1usize) } else { (r_small, w_small) };
            eprintln!("setup c={c} (n={n} blocks, tags) ...");
            let t0 = Instant::now();
            let su = setup(n, S, &mut rng);
            eprintln!("setup done in {:.1} s", t0.elapsed().as_secs_f64());
            if !only_q {
                let (rr, ww) = pick(c);
                let params = sweep_tag(&format!(";n={n};runs={rr}"));
                for stage in ["proofgen", "verify"] {
                    let mut ms: Vec<f64> = Vec::with_capacity(rr);
                    for run in 0..(ww + rr) {
                        let tt = rng.next_u64();
                        let chal = challenge(tt, n, c);
                        let (dt, ok);
                        if stage == "proofgen" {
                            let t0 = Instant::now();
                            let proof = proof_gen(black_box(&chal), black_box(&su.stored));
                            dt = t0.elapsed();
                            let proof = black_box(proof);
                            ok = proof_verify(&su.pp, &su.info, &chal, &proof);
                        } else {
                            let proof = proof_gen(&chal, &su.stored);
                            let t0 = Instant::now();
                            ok = black_box(proof_verify(black_box(&su.pp), black_box(&su.info), black_box(&chal), black_box(&proof)));
                            dt = t0.elapsed();
                        }
                        assert!(ok, "proof did not verify ({stage}, {params}, run {run})");
                        if run >= ww { ms.push(dt.as_secs_f64() * 1e3); }
                    }
                    emit(&mut csv, stage, &params, &ms);
                }
            }
            for &q in qs.as_deref().unwrap_or(&[]) {
                let (rr, ww) = pick(q * c);
                let params = sweep_tag(&format!(";n={n};q={q};runs={rr}"));
                let mut ms: Vec<f64> = Vec::with_capacity(rr);
                for run in 0..(ww + rr) {
                    // q different challenges and q honest proofs, made before the timer
                    let (chals, proofs) = make_audits(&su, c, q, &mut rng);
                    let t0 = Instant::now();
                    let ok = black_box(proof_verify_many(black_box(&su.pp), black_box(&su.info), black_box(&chals), black_box(&proofs)));
                    let dt = t0.elapsed();
                    assert!(ok, "verify_q did not verify ({params}, run {run})");
                    if run >= ww { ms.push(dt.as_secs_f64() * 1e3); }
                }
                emit(&mut csv, "verify_q", &params, &ms);
            }
        }
        return;
    }

    for (c, extra) in grid {
        let n = 10 * c; // paper: 10% of the blocks are challenged (line 1063)
        let mut params = if extra { format!("s={S};c={c};extra=1") } else { format!("s={S};c={c}") };
        if !tag.is_empty() { params.push(';'); params.push_str(&tag); }
        eprintln!("setup {params} (n={n} blocks, tags) ...");
        let su = setup(n, S, &mut rng);

        for stage in ["proofgen", "verify"] {
            let mut ms: Vec<f64> = Vec::with_capacity(runs);
            for run in 0..(warmup + runs) {
                let tt = rng.next_u64(); // fresh nonce -> fresh challenge (untimed: runs in the smart contract)
                let chal = challenge(tt, n, c);
                let (dt, ok);
                if stage == "proofgen" {
                    let t0 = Instant::now();
                    let proof = proof_gen(black_box(&chal), black_box(&su.stored));
                    dt = t0.elapsed();
                    let proof = black_box(proof);
                    ok = proof_verify(&su.pp, &su.info, &chal, &proof); // check, untimed
                } else {
                    let proof = proof_gen(&chal, &su.stored); // untimed
                    let t0 = Instant::now();
                    ok = black_box(proof_verify(black_box(&su.pp), black_box(&su.info), black_box(&chal), black_box(&proof)));
                    dt = t0.elapsed();
                }
                assert!(ok, "proof did not verify ({stage}, {params}, run {run})");
                if run >= warmup {
                    ms.push(dt.as_secs_f64() * 1e3);
                }
            }
            for (k, v) in ms.iter().enumerate() {
                writeln!(csv, "dong,{stage},{params},{k},{v:.6}").unwrap();
            }
            let mut sorted = ms.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let med = if sorted.len() % 2 == 1 {
                sorted[sorted.len() / 2]
            } else {
                0.5 * (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2])
            };
            println!(
                "dong {stage:8} {params:22} runs={} median={:.3} ms min={:.3} max={:.3}",
                sorted.len(), med, sorted[0], sorted[sorted.len() - 1]
            );
        }
    }
}

fn parse_list(v: &str, flag: &str) -> Vec<usize> {
    v.split(',').map(|x| x.trim().parse().unwrap_or_else(|_| panic!("{flag}: bad number {x:?}"))).filter(|&x: &usize| x >= 1).collect()
}

/// Writes the rows of one (stage, params) to the csv and prints the summary line.
fn emit(csv: &mut std::fs::File, stage: &str, params: &str, ms: &[f64]) {
    for (k, v) in ms.iter().enumerate() {
        writeln!(csv, "dong,{stage},{params},{k},{v:.6}").unwrap();
    }
    let mut sorted = ms.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let med = if sorted.len() % 2 == 1 {
        sorted[sorted.len() / 2]
    } else {
        0.5 * (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2])
    };
    println!(
        "dong {stage:8} {params:40} runs={} median={:.3} ms min={:.3} max={:.3}",
        sorted.len(), med, sorted[0], sorted[sorted.len() - 1]
    );
}
