use std::path::PathBuf;
use std::process::ExitCode;

use pqz_eval::bench::{DEFAULT_SEED, Options, estimate, list, run};

const USAGE: &str = "\
usage: exp <experiment> [--n N] [--runs R] [--warmup W] [--out DIR] [--seed S] [--smoke]
       exp <experiment> --list
       exp <experiment> --estimate
       exp all --list | exp all --estimate

experiments: exp1, exp2a, exp2b, exp2c, exp3a, exp3b, exp3c, exp3d, exp1_construction
dense sweeps (extra names, not part of `all`): exp1d, exp2bd, exp3ad
  --smoke     N=2000, runs=3, warmup=1, reduced grids
  --list      print the full non-smoke grid as
              name,n,mb,sigma,layout,predicate,approach,runs (runs nothing)
  --estimate  build the largest N of the experiment and print the bytes held
              by records, ciphertexts, tags, blocks and Bloom filters
";

fn parse() -> Result<Options, String> {
    let mut args = std::env::args().skip(1);
    let first = args.next().ok_or_else(|| USAGE.to_string())?;
    if first == "--help" || first == "-h" {
        return Err(USAGE.to_string());
    }

    let mut n = None;
    let mut runs = 30usize;
    let mut warmup = 3usize;
    let mut out = PathBuf::from("results");
    let mut smoke = false;
    let mut seed = DEFAULT_SEED;
    let mut list_mode = false;
    let mut estimate_mode = false;

    let name = match first.as_str() {
        "--list" => {
            list_mode = true;
            "all".to_string()
        }
        "--estimate" => {
            estimate_mode = true;
            "all".to_string()
        }
        _ => first,
    };

    while let Some(a) = args.next() {
        let mut next = |what: &str| -> Result<String, String> {
            args.next()
                .ok_or_else(|| format!("missing value for {what}"))
        };
        match a.as_str() {
            "--n" => {
                n = Some(
                    next("--n")?
                        .parse()
                        .map_err(|e| format!("invalid --n: {e}"))?,
                )
            }
            "--runs" => {
                runs = next("--runs")?
                    .parse()
                    .map_err(|e| format!("invalid --runs: {e}"))?
            }
            "--warmup" => {
                warmup = next("--warmup")?
                    .parse()
                    .map_err(|e| format!("invalid --warmup: {e}"))?
            }
            "--out" => out = PathBuf::from(next("--out")?),
            "--seed" => {
                let v = next("--seed")?;
                seed = if let Some(hex) = v.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16).map_err(|e| format!("invalid --seed: {e}"))?
                } else {
                    v.parse().map_err(|e| format!("invalid --seed: {e}"))?
                };
            }
            "--smoke" => smoke = true,
            "--list" => list_mode = true,
            "--estimate" => estimate_mode = true,
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }

    if list_mode && estimate_mode {
        return Err("--list and --estimate are mutually exclusive".into());
    }

    if smoke {
        n = Some(2000);
        runs = 3;
        warmup = 1;
    }

    Ok(Options {
        name,
        n,
        runs,
        warmup,
        out,
        smoke,
        seed,
        list: list_mode,
        estimate: estimate_mode,
    })
}

fn main() -> ExitCode {
    let opts = match parse() {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = if opts.list {
        list(&opts)
    } else if opts.estimate {
        estimate(&opts)
    } else {
        run(&opts).map(|paths| {
            for p in paths {
                println!("{}", p.display());
            }
        })
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
