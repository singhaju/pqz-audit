//! dopiv-bench: timing harness (SPEC rule 5/6). One thread, Instant, warm-up runs untimed, each timed
//! run is the whole named stage with a fresh random challenge. Inputs are generated before timing.
use pqz_bl_dopiv::*;
use std::fs;
use std::hint::black_box;
use std::io::Write;
use std::time::Instant;

const Q: u64 = 4294967291; // prime below 2^32 (OURS)
const GRID: [usize; 12] = [50, 100, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600];

fn median(v: &mut Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let k = v.len();
    if k % 2 == 1 {
        v[k / 2]
    } else {
        0.5 * (v[k / 2 - 1] + v[k / 2])
    }
}

struct Out {
    csv: fs::File,
}
impl Out {
    fn stage(&mut self, stage: &str, params: &str, times: &[f64]) {
        for (i, t) in times.iter().enumerate() {
            writeln!(self.csv, "dopiv,{},{},{},{:.6}", stage, params, i + 1, t).unwrap();
        }
        let mut v = times.to_vec();
        let mn = v.iter().cloned().fold(f64::INFINITY, f64::min);
        let mx = v.iter().cloned().fold(0.0, f64::max);
        let md = median(&mut v);
        println!("dopiv {:<16} {:<62} median {:>10.4} ms  min {:>10.4}  max {:>10.4}  (runs {})", stage, params, md, mn, mx, times.len());
    }
}

fn parse_list(s: &str) -> Vec<usize> {
    s.split(',').filter(|x| !x.is_empty()).map(|x| x.trim().parse().expect("list of integers")).collect()
}

struct CovCfg {
    cov: Vec<usize>,
    qs: Vec<usize>,
    runs: usize,
    warmup: usize,
    runs_big: usize,
    big_above: usize,
    params_tag: String,
    lazy: bool,
    no_lazy: bool,
    reading: String,
    seed: u64,
}

/// SPEC-w16: stages proofgen / verify at c = cov and verify_q (q independent audits per timed run).
/// Blocks: ell = max(cov); only these blocks are planted (the challenge can pick exactly these).
fn cov_main(cfg: CovCfg, out_dir: &str) {
    fs::create_dir_all(out_dir).unwrap();
    let mut o = Out { csv: fs::File::create(format!("{}/raw_runs.csv", out_dir)).unwrap() };
    writeln!(o.csv, "baseline,stage,params,run,ms").unwrap();
    let mut cnt = fs::File::create(format!("{}/opcounts.csv", out_dir)).unwrap();
    writeln!(cnt, "params,stage,term,hash_logical,sha3_calls,mul,norm_squarings,vec_adds").unwrap();
    let ell = *cfg.cov.iter().max().unwrap();
    // reductions to run: --lazy -> lazy; no flag -> default (each); both flags -> both
    let mut modes: Vec<bool> = vec![];
    if cfg.lazy {
        modes.push(true);
    }
    if cfg.no_lazy || !cfg.lazy {
        modes.push(false);
    }
    let readings: Vec<(&str, Params)> = vec![
        ("primary", Params { n: 256, m: 16384, q: Q }),
        ("sensitivity", Params { n: 256, m: 512, q: Q }),
    ];
    for (name, p) in readings {
        if cfg.reading != "both" && cfg.reading != name {
            continue;
        }
        eprintln!("[{}] n={} m={} q={} ell={} (= max cov) planting ...", name, p.n, p.m, p.q, ell);
        let t0 = Instant::now();
        let mut inst = Instance::setup(&p, ell, cfg.seed, false);
        eprintln!("[{}] setup (untimed) {:.1} s, sigma(ours)={}", name, t0.elapsed().as_secs_f64(), inst.sigma);
        let mut rng = Rng::new(cfg.seed ^ 0xABCD);
        for &lazy in &modes {
            inst.lazy = lazy;
            for &c in &cfg.cov {
                let mk = |extra: &str, r: usize| -> String {
                    let mut s = p.label(Some(c), lazy);
                    s.push_str(extra);
                    s.push_str(&format!(";runs={}", r));
                    if !cfg.params_tag.is_empty() {
                        s.push(';');
                        s.push_str(&cfg.params_tag);
                    }
                    s
                };
                // run policy: big work per run -> runs_big timed runs, 1 warm-up
                let policy = |work: usize| -> (usize, usize) {
                    if work > cfg.big_above {
                        (cfg.runs_big, 1)
                    } else {
                        (cfg.runs, cfg.warmup)
                    }
                };
                // operation counts (one counted run, same code), checked against Table 2
                {
                    let params = mk("", 0).replace(";runs=0", "");
                    let chal = challenge(ell, c, &mut rng);
                    let mut cp = Counts::default();
                    let proof = proofgen(&inst, &chal, &mut rng, &mut cp);
                    let mut cv = Counts::default();
                    assert!(verify(&inst, &chal, &proof, &mut cv), "honest proof rejected at {}", params);
                    for (st, cc) in [("proofgen", &cp), ("verify", &cv)] {
                        for (l, mul, sq, h, s3, ad) in cc.deltas() {
                            writeln!(cnt, "{},{},{},{},{},{},{},{}", params, st, l.replace(',', ";"), h, s3, mul, sq, ad).unwrap();
                        }
                        writeln!(cnt, "{},{},TOTAL,{},{},{},{},{}", params, st, cc.hash, cc.sha3, cc.mul, cc.sq, cc.add).unwrap();
                    }
                    let (fh, fm) = table2_integrity(p.n as u64, p.m as u64, c as u64);
                    println!("counts [{}] c={} verify: Hash {} (Table 2: {}), mul {} (Table 2: {})", name, c, cv.hash, fh, cv.mul, fm);
                    assert_eq!((cv.hash, cv.mul), (fh, fm), "operation count differs from Table 2");
                }
                let (r, w) = policy(c);
                let params = mk("", r);
                // proofgen
                let mut ts = vec![];
                for i in 0..w + r {
                    let ch = challenge(ell, c, &mut rng);
                    let t0 = Instant::now();
                    let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
                    let dt = t0.elapsed().as_secs_f64() * 1e3;
                    let pr = black_box(pr);
                    assert!(verify(&inst, &ch, &pr, &mut NoMeter), "proofgen output rejected"); // untimed check
                    if i >= w {
                        ts.push(dt);
                    }
                }
                o.stage("proofgen", &params, &ts);
                // verify
                let mut ts = vec![];
                for i in 0..w + r {
                    let ch = challenge(ell, c, &mut rng);
                    let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
                    let t0 = Instant::now();
                    let ok = verify(&inst, &ch, &pr, &mut NoMeter);
                    let dt = t0.elapsed().as_secs_f64() * 1e3;
                    assert!(black_box(ok), "honest proof rejected");
                    if i >= w {
                        ts.push(dt);
                    }
                }
                o.stage("verify", &params, &ts);
                // verify_q: q independent audits (q challenges, q proofs made before the timer) per timed run
                for &qa in &cfg.qs {
                    let (r, w) = policy(qa * c);
                    let params = mk(&format!(";audits={}", qa), r);
                    let mut ts = vec![];
                    for i in 0..w + r {
                        let audits = make_audits(&inst, c, qa, &mut rng);
                        let t0 = Instant::now();
                        let ok = verify_many(&inst, &audits, &mut NoMeter);
                        let dt = t0.elapsed().as_secs_f64() * 1e3;
                        assert!(black_box(ok), "honest audit batch rejected");
                        if i >= w {
                            ts.push(dt);
                        }
                    }
                    o.stage("verify_q", &params, &ts);
                }
            }
        }
    }
    o.csv.flush().unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut runs = 30usize;
    let mut warmup = 3usize;
    let mut out_dir = "results".to_string();
    let mut quick = false;
    let mut lazy = false;
    let mut reading = "both".to_string();
    let mut reading_set = false;
    // SPEC-w16 options (cov mode)
    let mut cov: Vec<usize> = vec![];
    let mut qs: Vec<usize> = vec![];
    let mut runs_big = 5usize;
    let mut big_above = 2000usize;
    let mut params_tag = String::new();
    let mut no_lazy = false;
    let mut seed = 20261106u64;
    let mut k = 1;
    let mut runs_set = false;
    let mut warm_set = false;
    while k < args.len() {
        match args[k].as_str() {
            "--runs" => {
                runs = args[k + 1].parse().unwrap();
                runs_set = true;
                k += 1;
            }
            "--warmup" => {
                warmup = args[k + 1].parse().unwrap();
                warm_set = true;
                k += 1;
            }
            "--out" => {
                out_dir = args[k + 1].clone();
                k += 1;
            }
            "--reading" => {
                reading = args[k + 1].clone();
                reading_set = true;
                k += 1;
            }
            "--seed" => {
                seed = args[k + 1].parse().unwrap();
                k += 1;
            }
            "--cov" => {
                cov = parse_list(&args[k + 1]);
                k += 1;
            }
            "--q" => {
                qs = parse_list(&args[k + 1]);
                k += 1;
            }
            "--runs-big" => {
                runs_big = args[k + 1].parse().unwrap();
                k += 1;
            }
            "--big-above" => {
                big_above = args[k + 1].parse().unwrap();
                k += 1;
            }
            "--params-tag" => {
                params_tag = args[k + 1].clone();
                k += 1;
            }
            "--no-lazy" => no_lazy = true,
            "--quick" => quick = true,
            "--lazy" => lazy = true,
            a => panic!("unknown argument {}", a),
        }
        k += 1;
    }
    if quick {
        if !runs_set {
            runs = 3;
        }
        if !warm_set {
            warmup = 1;
        }
    }
    if !cov.is_empty() {
        if !reading_set {
            reading = "primary".to_string(); // cov mode: the paper's bound reading unless asked otherwise
        }
        let cfg = CovCfg { cov, qs, runs, warmup, runs_big, big_above, params_tag, lazy, no_lazy, reading, seed };
        cov_main(cfg, &out_dir);
        return;
    }
    if !qs.is_empty() {
        panic!("--q needs --cov (verify_q runs at the coverage points of --cov)");
    }
    let grid: Vec<usize> = if quick { vec![50, 350] } else { GRID.to_vec() };
    let ell = *grid.iter().max().unwrap();
    fs::create_dir_all(&out_dir).unwrap();
    let mut o = Out { csv: fs::File::create(format!("{}/raw_runs.csv", out_dir)).unwrap() };
    writeln!(o.csv, "baseline,stage,params,run,ms").unwrap();
    let mut cnt = fs::File::create(format!("{}/opcounts.csv", out_dir)).unwrap();
    writeln!(cnt, "params,stage,term,hash_logical,sha3_calls,mul,norm_squarings,vec_adds").unwrap();

    let readings: Vec<(&str, Params)> = vec![
        ("primary", Params { n: 256, m: 16384, q: Q }),
        ("sensitivity", Params { n: 256, m: 512, q: Q }),
    ];
    for (name, p) in readings {
        if reading != "both" && reading != name {
            continue;
        }
        eprintln!("[{}] n={} m={} q={} (m_bound={} bound_ok={}) ell={} lazy={}", name, p.n, p.m, p.q, p.m_bound(), p.bound_ok(), ell, lazy);
        let t0 = Instant::now();
        let inst = Instance::setup(&p, ell, seed, lazy);
        eprintln!("[{}] setup (untimed) {:.1} s, sigma(ours)={}", name, t0.elapsed().as_secs_f64(), inst.sigma);
        let mut rng = Rng::new(seed ^ 0xABCD);

        // ---- operation counts (one counted run per c; counting build of the same code) ----
        for &c in &grid {
            let params = p.label(Some(c), lazy);
            let chal = challenge(ell, c, &mut rng);
            let mut cp = Counts::default();
            let proof = proofgen(&inst, &chal, &mut rng, &mut cp);
            let mut cv = Counts::default();
            let ok = verify(&inst, &chal, &proof, &mut cv);
            assert!(ok, "honest proof rejected at {}", params);
            for (st, cc) in [("proofgen", &cp), ("verify", &cv)] {
                for (l, mul, sq, h, s3, ad) in cc.deltas() {
                    writeln!(cnt, "{},{},{},{},{},{},{},{}", params, st, l.replace(',', ";"), h, s3, mul, sq, ad).unwrap();
                }
                writeln!(cnt, "{},{},TOTAL,{},{},{},{},{}", params, st, cc.hash, cc.sha3, cc.mul, cc.sq, cc.add).unwrap();
            }
            let (fh, fm) = table2_integrity(p.n as u64, p.m as u64, c as u64);
            println!(
                "counts [{}] c={:<3} verify: Hash {} (Table 2: {}), mul {} (Table 2: {}), extra norm squarings {}, SHA3-256 calls {}",
                name, c, cv.hash, fh, cv.mul, fm, cv.sq, cv.sha3
            );
        }
        {
            let mut cd = Counts::default();
            assert!(verify_delegation(&inst, &mut cd));
            for (l, mul, sq, h, s3, ad) in cd.deltas() {
                writeln!(cnt, "{},verify_delegation,{},{},{},{},{},{}", p.label(None, lazy), l.replace(',', ";"), h, s3, mul, sq, ad).unwrap();
            }
            let (fh, fm) = table2_delegation(p.n as u64, p.m as u64);
            println!("counts [{}] delegation: Hash {} (Table 2: {}), mul {} (Table 2: {}), SHA3-256 calls {}", name, cd.hash, fh, cd.mul, fm, cd.sha3);
        }

        // ---- timing ----
        {
            let params = p.label(None, lazy);
            let mut ts = vec![];
            for r in 0..warmup + runs {
                let t0 = Instant::now();
                let ok = verify_delegation(&inst, &mut NoMeter);
                let dt = t0.elapsed().as_secs_f64() * 1e3;
                assert!(black_box(ok), "delegation rejected");
                if r >= warmup {
                    ts.push(dt);
                }
            }
            o.stage("verify_delegation", &params, &ts);
        }
        for &c in &grid {
            let params = p.label(Some(c), lazy);
            // challenge
            let mut ts = vec![];
            for r in 0..warmup + runs {
                let t0 = Instant::now();
                let ch = challenge(ell, c, &mut rng);
                let dt = t0.elapsed().as_secs_f64() * 1e3;
                black_box(&ch);
                if r >= warmup {
                    ts.push(dt);
                }
            }
            o.stage("challenge", &params, &ts);
            // proofgen
            let mut ts = vec![];
            for r in 0..warmup + runs {
                let ch = challenge(ell, c, &mut rng);
                let t0 = Instant::now();
                let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
                let dt = t0.elapsed().as_secs_f64() * 1e3;
                let pr = black_box(pr);
                assert!(verify(&inst, &ch, &pr, &mut NoMeter), "proofgen output rejected"); // untimed check
                if r >= warmup {
                    ts.push(dt);
                }
            }
            o.stage("proofgen", &params, &ts);
            // verify
            let mut ts = vec![];
            for r in 0..warmup + runs {
                let ch = challenge(ell, c, &mut rng);
                let pr = proofgen(&inst, &ch, &mut rng, &mut NoMeter);
                let t0 = Instant::now();
                let ok = verify(&inst, &ch, &pr, &mut NoMeter);
                let dt = t0.elapsed().as_secs_f64() * 1e3;
                assert!(black_box(ok), "honest proof rejected");
                if r >= warmup {
                    ts.push(dt);
                }
            }
            o.stage("verify", &params, &ts);
        }
    }
    o.csv.flush().unwrap();
}
