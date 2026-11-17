//! ledgerbench: raw CSVs + env.txt for Exp 5(a), 5(b), bytes per epoch, (t,n) panel.
//! Usage: ledgerbench --out DIR [--runs 30] [--warmup 3] [--seed 1] [--validators 4]
//!                    [--only exp5a,exp5b,exp5c,thr] [--quick] [--no-tx-auth] [--no-tx-auth]
//! --quick = tiny settings for a smoke test (not for reporting).
use pqz_ledger::bench::{run_all, BenchCfg};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cfg = if args.iter().any(|a| a == "--quick") { BenchCfg::quick() } else { BenchCfg::default() };
    let mut out = PathBuf::from("results");
    let mut i = 0;
    let need = |i: usize, name: &str| -> String {
        args.get(i + 1).cloned().unwrap_or_else(|| {
            eprintln!("missing value for {}", name);
            std::process::exit(2)
        })
    };
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                out = PathBuf::from(need(i, "--out"));
                i += 1;
            }
            "--runs" => {
                cfg.runs = need(i, "--runs").parse().expect("--runs N");
                i += 1;
            }
            "--warmup" => {
                cfg.warmup = need(i, "--warmup").parse().expect("--warmup N");
                i += 1;
            }
            "--seed" => {
                cfg.seed = need(i, "--seed").parse().expect("--seed N");
                i += 1;
            }
            "--validators" => {
                cfg.n_validators = need(i, "--validators").parse().expect("--validators N (>= 4)");
                i += 1;
            }
            "--only" => {
                cfg.only = need(i, "--only").split(',').map(|x| x.to_string()).collect();
                i += 1;
            }
            "--quick" => {}
            "--no-tx-auth" => cfg.tx_auth = false,
            other => {
                eprintln!("unknown argument {}\nusage: ledgerbench --out DIR [--runs N] [--warmup N] [--seed N] [--validators N] [--only exp5a,exp5b,exp5c,thr] [--quick] [--no-tx-auth]", other);
                std::process::exit(2);
            }
        }
        i += 1;
    }
    eprintln!("ledgerbench: PROVISIONAL in-process simulation; no network (see README.md)");
    match run_all(&cfg, &out, "ledgerbench") {
        Ok(files) => {
            for (f, n) in files {
                println!("{}  rows={}", out.join(f).display(), n);
            }
            println!("{}", out.join("env.txt").display());
        }
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    }
}
