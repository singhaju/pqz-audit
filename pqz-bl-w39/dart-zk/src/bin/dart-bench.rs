//! dart-bench: stages `proofgen_nozk` and `verify_nozk` (no zk-SNARK). Single thread, Instant, warm-ups + timed runs.
use pqz_bl_dart::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut runs: Option<usize> = None;
    let mut warmup: Option<usize> = None;
    let mut out = String::from("results");
    let mut quick = false;
    let mut chunks: usize = 400; // |D|: NOT in the paper, ours
    // SPEC-w16 options (matched-coverage mode, active only with --cov)
    let mut cov: Option<Vec<u64>> = None;
    let mut qs: Vec<usize> = Vec::new();
    let mut runs_big: usize = 5;
    let mut big_above: u64 = 2000;
    let mut params_tag = String::new();
    let mut file_records: u64 = 1_000_000;
    let mut file_records_list: Option<Vec<u64>> = None;
    let mut scale_d = false;
    let mut stages_arg: Option<Vec<String>> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--runs" => { i += 1; runs = Some(args[i].parse().unwrap()); }
            "--warmup" => { i += 1; warmup = Some(args[i].parse().unwrap()); }
            "--out" => { i += 1; out = args[i].clone(); }
            "--chunks" => { i += 1; chunks = args[i].parse().unwrap(); }
            "--cov" => { i += 1; cov = Some(args[i].split(',').map(|x| x.parse().unwrap()).collect()); }
            "--q" => { i += 1; qs = args[i].split(',').map(|x| x.parse().unwrap()).collect(); }
            "--runs-big" => { i += 1; runs_big = args[i].parse().unwrap(); }
            "--big-above" => { i += 1; big_above = args[i].parse().unwrap(); }
            "--params-tag" => { i += 1; params_tag = args[i].clone(); }
            "--file-records" => { i += 1; file_records = args[i].parse().unwrap(); }
            "--file-records-list" => { i += 1; file_records_list = Some(args[i].split(',').map(|x| x.parse().unwrap()).collect()); }
            "--scale-d" => scale_d = true,
            "--stages" => { i += 1; stages_arg = Some(args[i].split(',').map(|x| x.to_string()).collect()); }
            "--quick" => quick = true,
            a => panic!("unknown argument {a}"),
        }
        i += 1;
    }
    let runs = runs.unwrap_or(if quick { 3 } else { 30 });
    let warmup = warmup.unwrap_or(if quick { 1 } else { 3 });
    if let Some(cov) = cov {
        run_cov(Cfg { cov, qs, runs, warmup, runs_big, big_above, params_tag, file_records, file_records_list, scale_d, stages: stages_arg, out });
        return;
    }
    assert!(qs.is_empty(), "--q needs --cov");
    let (ns, zs): (Vec<usize>, Vec<usize>) = if quick { (vec![20], vec![10, 100]) } else { (vec![20, 40], vec![10, 50, 100, 200]) };
    let m = 10usize; // paper: M = 10
    let zmax = *zs.iter().max().unwrap();
    assert!(chunks > zmax);

    // OS entropy is not available without extra crates: seed from the clock (inputs are random, not secret)
    let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let mut csv = String::from("baseline,stage,params,run,ms\n");
    let mut opscsv = String::from("baseline,stage,params,op,count\n");
    for &n in &ns {
        let (pubp, node) = setup(Params { m, n, d: chunks }, zmax, &mut rng);
        for &z in &zs {
            let params = format!("M={m};N={n};z={z};D={chunks}");
            for stage in ["proofgen_nozk", "verify_nozk"] {
                let mut times = Vec::new();
                let mut last_ops = Ops::default();
                for r in 0..(warmup + runs) {
                    // fresh random challenge keys per run (drawn outside the timer)
                    let mut k1 = [0u8; 32];
                    let mut k2 = [0u8; 32];
                    rng.fill_bytes(&mut k1);
                    rng.fill_bytes(&mut k2);
                    let mut ops = Ops::default();
                    let ms;
                    if stage == "proofgen_nozk" {
                        let t = Instant::now();
                        let prf = prove_nozk(&pubp, &node, &k1, &k2, z, &mut ops);
                        ms = t.elapsed().as_secs_f64() * 1e3;
                        black_box(&prf);
                    } else {
                        let prf = prove_nozk(&pubp, &node, &k1, &k2, z, &mut Ops::default()); // untimed input
                        let t = Instant::now();
                        let v = verify_nozk(&pubp, &prf, &k1, &k2, z, &mut ops);
                        ms = t.elapsed().as_secs_f64() * 1e3;
                        assert!(black_box(v).ok, "honest proof rejected: {v:?}");
                    }
                    if r >= warmup {
                        times.push(ms);
                        let _ = writeln!(csv, "DART,{stage},{params},{},{ms}", r - warmup + 1);
                    }
                    last_ops = ops;
                }
                for (op, c) in last_ops.rows() {
                    let _ = writeln!(opscsv, "DART,{stage},{params},{op},{c}");
                }
                let mut s = times.clone();
                s.sort_by(|a, b| a.partial_cmp(b).unwrap());
                let med = if s.len() % 2 == 1 { s[s.len() / 2] } else { (s[s.len() / 2 - 1] + s[s.len() / 2]) / 2.0 };
                println!("DART {stage:14} {params:24} median {med:10.3} ms  min {:10.3}  max {:10.3}  (runs {})", s[0], s[s.len() - 1], s.len());
            }
        }
    }
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(format!("{out}/raw_runs.csv"), csv).unwrap();
    std::fs::write(format!("{out}/ops.csv"), opscsv).unwrap();
}

struct Cfg {
    cov: Vec<u64>,
    qs: Vec<usize>,
    runs: usize,
    warmup: usize,
    runs_big: usize,
    big_above: u64,
    params_tag: String,
    file_records: u64,
    file_records_list: Option<Vec<u64>>,
    scale_d: bool,
    stages: Option<Vec<String>>,
    out: String,
}

fn summary(label: &str, params: &str, times: &[f64]) {
    let mut s = times.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let med = if s.len() % 2 == 1 { s[s.len() / 2] } else { (s[s.len() / 2 - 1] + s[s.len() / 2]) / 2.0 };
    println!("DART {label:14} {params:60} median {med:12.3} ms  min {:12.3}  max {:12.3}  (runs {})", s[0], s[s.len() - 1], s.len());
}

fn fresh_keys(rng: &mut ChaCha20Rng) -> ([u8; 32], [u8; 32]) {
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    rng.fill_bytes(&mut k1);
    rng.fill_bytes(&mut k2);
    (k1, k2)
}

/// Matched-coverage mode (SPEC-w16): chunk = N*M = 200 blocks (N=20, M=10); D = ceil(file_records/200); z = max(1, ceil(cov/200)).
fn run_cov(c: Cfg) {
    let (n, m) = (20usize, 10usize);
    let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    if let Some(l) = &c.file_records_list {
        assert_eq!(l.len(), c.cov.len(), "--file-records-list must match --cov in length");
    }
    // D per coverage point: explicit list > --scale-d (file = 100 x cov records) > --file-records
    let dz: Vec<(usize, usize)> = c.cov.iter().enumerate().map(|(k, &cv)| {
        let recs = if let Some(l) = &c.file_records_list { l[k] } else if c.scale_d { cv * 100 } else { c.file_records };
        let d = chunks_for_records(recs, n, m);
        let z = z_for_cov(cv, n, m);
        assert!(d >= 2 && z <= d, "cov={cv}: D={d} must be >= max(2, z={z}); file too small for this coverage");
        (d, z)
    }).collect();
    let stages: Vec<String> = c.stages.clone().unwrap_or_else(|| {
        let mut v = vec!["proofgen_nozk".to_string(), "verify_nozk".to_string()];
        if !c.qs.is_empty() { v.push("verify_q".to_string()); }
        v
    });
    if stages.iter().any(|s| s == "verify_q") { assert!(!c.qs.is_empty(), "stage verify_q needs --q"); }
    let tag = if c.params_tag.is_empty() { String::new() } else { format!(";{}", c.params_tag) };

    let mut csv = String::from("baseline,stage,params,run,ms\n");
    let mut opscsv = String::from("baseline,stage,params,op,count\n");
    let mut cache: Option<(usize, usize, Public, Node, Trapdoor)> = None;
    let mut zkcache: Option<zk::ZkCtx> = None; // work39: Groth16 CRS for the current z (one-time, untimed)
    let mut zkv: Option<((usize, usize, u64), ([u8; 32], [u8; 32], zk::ZkInput, ark_groth16::Proof<ark_bn254::Bn254>, Prf))> = None;
    let mut zkinfo = String::from("z,constraints,public_inputs,witness_vars,setup_ms,pk_bytes,vk_bytes\n");
    for (k, &cv) in c.cov.iter().enumerate() {
        let (d, z) = dz[k];
        // z_max for this D over all points sharing it (so the setup is reused)
        let zmax = dz.iter().filter(|(dd, _)| *dd == d).map(|(_, zz)| *zz).max().unwrap();
        let rebuild = !matches!(&cache, Some((cd, cz, ..)) if *cd == d && *cz >= zmax);
        if rebuild {
            cache = None; // free the old file before building the next
            let t = Instant::now();
            let (pubp, node, trap) = setup_with_trapdoor(Params { m, n, d }, zmax, &mut rng);
            println!("setup (untimed): D={d} z_max={zmax} file_blocks={} ({} MiB) took {:.2} s", d * n * m, d * n * m * BLOCK_BYTES >> 20, t.elapsed().as_secs_f64());
            cache = Some((d, zmax, pubp, node, trap));
        }
        let (_, _, pubp, node, trap) = cache.as_ref().unwrap();
        if stages.iter().any(|s| matches!(s.as_str(), "zkprove_only" | "proofgen_zk" | "verify_zk")) && !matches!(&zkcache, Some(c) if c.z == z) {
            zkcache = None;
            let t = Instant::now();
            let c = zk::zk_setup(z, n, m, &mut rng);
            println!("zk setup (untimed, one-time): z={z} constraints={} public={} witness={} setup {:.2} s (zk_setup_ms={:.0}) pk {} MiB vk {} B", c.constraints, c.public_inputs, c.witness_vars, t.elapsed().as_secs_f64(), c.setup_ms, c.pk_bytes >> 20, c.vk_bytes);
            let _ = writeln!(zkinfo, "{z},{},{},{},{:.1},{},{}", c.constraints, c.public_inputs, c.witness_vars, c.setup_ms, c.pk_bytes, c.vk_bytes);
            zkcache = Some(c);
        }
        for stage in &stages {
            let qlist: Vec<usize> = if stage == "verify_q" { c.qs.clone() } else { vec![0] };
            for &q in &qlist {
                let work = if q > 0 { q as u64 * cv } else { cv };
                let big = if stage == "verify_q" { work > c.big_above } else { cv > c.big_above };
                let (runs, warm) = if big { (c.runs_big, 1) } else { (c.runs, c.warmup) };
                let qpart = if q > 0 { format!(";q={q}") } else { String::new() };
                let params = format!("M={m};N={n};z={z};D={d};cov={cv};runs={runs}{qpart}{tag}");
                let mut times = Vec::new();
                let mut last_ops = Ops::default();
                for r in 0..(warm + runs) {
                    let mut ops = Ops::default();
                    let ms;
                    match stage.as_str() {
                        "proofgen_nozk" => {
                            let (k1, k2) = fresh_keys(&mut rng);
                            let t = Instant::now();
                            let prf = prove_nozk(pubp, node, &k1, &k2, z, &mut ops);
                            ms = t.elapsed().as_secs_f64() * 1e3;
                            black_box(&prf);
                        }
                        "verify_nozk" => {
                            let (k1, k2) = fresh_keys(&mut rng);
                            let prf = prove_fast(pubp, node, trap, &k1, &k2, z); // untimed input (same Prf as prove_nozk)
                            let t = Instant::now();
                            let v = verify_nozk(pubp, &prf, &k1, &k2, z, &mut ops);
                            ms = t.elapsed().as_secs_f64() * 1e3;
                            assert!(black_box(v).ok, "honest proof rejected: {v:?}");
                        }
                        "verify_q" => {
                            // q different challenges and q different proofs, all made before the timer
                            let keys: Vec<_> = (0..q).map(|_| fresh_keys(&mut rng)).collect();
                            let proofs: Vec<Prf> = keys.iter().map(|(k1, k2)| prove_fast(pubp, node, trap, k1, k2, z)).collect();
                            let t = Instant::now();
                            let ok = verify_q(pubp, &proofs, &keys, z, &mut ops);
                            ms = t.elapsed().as_secs_f64() * 1e3;
                            assert!(black_box(ok), "an honest proof was rejected in verify_q");
                        }
                        "zkprove_only" => {
                            // untimed: challenge, challenged blocks -> BN254 witness, public values (same Poseidon, native)
                            let (k1, k2) = fresh_keys(&mut rng);
                            let lam = challenge_set(&k1, &k2, z, d, &mut Ops::default());
                            let ctx = zkcache.as_ref().unwrap();
                            let inp = zk::zk_prepare(ctx, &pubp.p, node, &lam);
                            let t = Instant::now();
                            let pi = zk::zk_prove(ctx, &inp, &mut rng);
                            ms = t.elapsed().as_secs_f64() * 1e3;
                            assert!(zk::zk_verify(ctx, &inp.alphas, &inp.gamma, &pi), "honest zk proof rejected");
                        }
                        "proofgen_zk" => {
                            let (k1, k2) = fresh_keys(&mut rng);
                            let lam = challenge_set(&k1, &k2, z, d, &mut Ops::default());
                            let ctx = zkcache.as_ref().unwrap();
                            let inp = zk::zk_prepare(ctx, &pubp.p, node, &lam);
                            let t = Instant::now();
                            let prf = prove_nozk(pubp, node, &k1, &k2, z, &mut ops);
                            let pi = zk::zk_prove(ctx, &inp, &mut rng);
                            ms = t.elapsed().as_secs_f64() * 1e3;
                            black_box((&prf, &pi));
                        }
                        "verify_zk" => {
                            // one challenge and one zk proof per coverage point (made untimed once); verify_nozk + Groth16 verify timed
                            let ctx = zkcache.as_ref().unwrap();
                            if zkv.as_ref().map_or(true, |(zc, _)| *zc != (d, z, cv)) {
                                let (k1, k2) = fresh_keys(&mut rng);
                                let lam = challenge_set(&k1, &k2, z, d, &mut Ops::default());
                                let inp = zk::zk_prepare(ctx, &pubp.p, node, &lam);
                                let pi = zk::zk_prove(ctx, &inp, &mut rng);
                                let prf = prove_fast(pubp, node, trap, &k1, &k2, z);
                                zkv = Some(((d, z, cv), (k1, k2, inp, pi, prf)));
                            }
                            let (_, (k1, k2, inp, pi, prf)) = zkv.as_ref().unwrap();
                            let t = Instant::now();
                            let v = verify_nozk(pubp, prf, k1, k2, z, &mut ops);
                            let okz = zk::zk_verify(ctx, &inp.alphas, &inp.gamma, pi);
                            ms = t.elapsed().as_secs_f64() * 1e3;
                            assert!(black_box(v).ok && black_box(okz), "honest proof rejected: {v:?} zk={okz}");
                        }
                        other => panic!("unknown stage {other}"),
                    }
                    if r >= warm {
                        times.push(ms);
                        let _ = writeln!(csv, "DART,{stage},{params},{},{ms}", r - warm + 1);
                    }
                    last_ops = ops;
                }
                for (op, cnt) in last_ops.rows() {
                    let _ = writeln!(opscsv, "DART,{stage},{params},{op},{cnt}");
                }
                if matches!(stage.as_str(), "zkprove_only" | "proofgen_zk" | "verify_zk") {
                    let c = zkcache.as_ref().unwrap();
                    for (op, cnt) in [("zk_constraints", c.constraints as u64), ("zk_public_inputs", c.public_inputs as u64), ("zk_pk_bytes", c.pk_bytes as u64), ("zk_vk_bytes", c.vk_bytes as u64), ("zk_setup_ms", c.setup_ms as u64)] {
                        let _ = writeln!(opscsv, "DART,{stage},{params},{op},{cnt}");
                    }
                }
                summary(stage, &params, &times);
            }
        }
    }
    std::fs::create_dir_all(&c.out).unwrap();
    // never overwrite an earlier result: append a numbered name if the default exists
    let (mut raw, mut opsf) = (format!("{}/raw_runs.csv", c.out), format!("{}/ops.csv", c.out));
    let mut idx = 1;
    while std::path::Path::new(&raw).exists() {
        raw = format!("{}/raw_runs_{idx}.csv", c.out);
        opsf = format!("{}/ops_{idx}.csv", c.out);
        idx += 1;
    }
    std::fs::write(&raw, csv).unwrap();
    std::fs::write(&opsf, opscsv).unwrap();
    if zkinfo.lines().count() > 1 {
        let zf = raw.replace("raw_runs", "zk_info");
        std::fs::write(&zf, zkinfo).unwrap();
    }
    println!("wrote {raw} and {opsf}");
}
