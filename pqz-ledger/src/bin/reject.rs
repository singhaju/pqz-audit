//! reject: rejection harness. Every attack must be rejected; any acceptance prints a trace
//! and exits with status 1. With the `mutation` feature, `--mutate` switches single
//! defences off and checks that exactly the matching attacks become accepted.
//! Usage: reject [--trials 1000] [--seed 1] [--validators 4] [--csv FILE] [--mutate]
//!        (mutation build only) --break NAME: run the main check with defence NAME off, to see the failure path (exit 1 + trace)
use pqz_ledger::attacks::{self, Params, VariantResult};
use std::time::Instant;

fn print_table(res: &[VariantResult]) {
    println!("{:<28} {:<40} {:>6} {:>9} {:>9} {:>12}", "variant", "attack class", "trials", "rejected", "accepted", "control_ok");
    for r in res {
        println!("{:<28} {:<40} {:>6} {:>9} {:>9} {:>6}/{:<5}", r.variant, r.class, r.trials, r.rejected, r.accepted, r.control_ok, r.control_total);
    }
}

fn print_reasons(res: &[VariantResult]) {
    println!("rejection reasons:");
    for r in res {
        let rs: Vec<String> = r.reasons.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
        println!("  {:<28} {}", r.variant, rs.join(" "));
    }
}

fn csv(res: &[VariantResult], tag: &str) -> String {
    let mut s = String::new();
    for r in res {
        s.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            tag, r.variant, r.class, r.trials, r.rejected, r.accepted, r.control_ok, r.control_total
        ));
    }
    s
}

const CSV_HEADER: &str = "mode,variant,attack_class,trials,rejected,accepted,control_ok,control_total\n";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut p = Params::default();
    let mut csv_path: Option<String> = None;
    let mut mutate = false;
    let mut broken: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let val = |i: usize| args.get(i + 1).cloned().unwrap_or_else(|| {
            eprintln!("missing value for {}", args[i]);
            std::process::exit(2)
        });
        match args[i].as_str() {
            "--trials" => {
                p.trials = val(i).parse().expect("--trials N");
                i += 1;
            }
            "--seed" => {
                p.seed = val(i).parse().expect("--seed N");
                i += 1;
            }
            "--validators" => {
                p.n_validators = val(i).parse().expect("--validators N (>= 4)");
                i += 1;
            }
            "--csv" => {
                csv_path = Some(val(i));
                i += 1;
            }
            "--mutate" => mutate = true,
            "--break" => {
                broken = Some(val(i));
                i += 1;
            }
            o => {
                eprintln!("unknown argument {}\nusage: reject [--trials N] [--seed N] [--validators N] [--csv FILE] [--mutate]", o);
                std::process::exit(2);
            }
        }
        i += 1;
    }
    println!("reject: PROVISIONAL in-process ledger simulation (one process, no network); trials per attack = {}, validators = {}", p.trials, p.n_validators);
    let mut out_csv = String::from(CSV_HEADER);
    let t0 = Instant::now();
    let res = match &broken {
        None => attacks::run(&p),
        Some(_name) => {
            #[cfg(feature = "mutation")]
            {
                pqz_ledger::attacks::run_with(&p, pqz_ledger::contract::Defences::without(_name))
            }
            #[cfg(not(feature = "mutation"))]
            {
                eprintln!("--break needs a build with `--features mutation`");
                std::process::exit(2)
            }
        }
    };
    println!("== {} {:.1} s", match &broken { None => "production defences (all on),".to_string(), Some(n) => format!("DEFENCE {} SWITCHED OFF (test build),", n) }, t0.elapsed().as_secs_f64());
    print_table(&res);
    print_reasons(&res);
    out_csv.push_str(&csv(&res, "production"));
    let mut failed = false;
    for r in &res {
        if r.accepted > 0 {
            failed = true;
            println!("FAIL: {} accepted {} of {} attacks. Trace(s):", r.variant, r.accepted, r.trials);
            for t in &r.traces {
                println!("  {}", t);
            }
        }
        if r.control_ok != r.control_total {
            failed = true;
            println!("FAIL: {} control operations rejected ({} of {} ok): the harness itself is broken", r.variant, r.control_ok, r.control_total);
        }
    }
    if mutate {
        #[cfg(feature = "mutation")]
        {
            use pqz_ledger::contract::Defences;
            println!("== mutation tests: one defence off at a time; expected = exactly the listed variants accepted");
            for (name, flips) in attacks::EXPECTED_FLIPS {
                let r = attacks::run_with(&p, Defences::without(name));
                let accepted: Vec<&str> = r.iter().filter(|x| x.accepted > 0).map(|x| x.variant).collect();
                let all_flipped = r.iter().filter(|x| flips.contains(&x.variant)).all(|x| x.accepted == x.trials);
                let ok = all_flipped && accepted.len() == flips.len() && accepted.iter().all(|a| flips.contains(a));
                println!("-- defence off: {}", name);
                print_table(&r);
                println!("   expected accepted: {:?}; observed accepted: {:?} => {}", flips, accepted, if ok { "OK" } else { "MISMATCH" });
                out_csv.push_str(&csv(&r, &format!("without_{}", name)));
                if !ok {
                    failed = true;
                }
            }
        }
        #[cfg(not(feature = "mutation"))]
        {
            eprintln!("--mutate needs a build with `--features mutation`");
            std::process::exit(2);
        }
    }
    if let Some(p) = csv_path {
        std::fs::write(&p, out_csv).expect("write csv");
        println!("wrote {}", p);
    }
    if failed {
        println!("RESULT: FAIL");
        std::process::exit(1);
    }
    println!("RESULT: PASS (every attack rejected{})", if mutate { "; every mutation flips exactly its attacks" } else { "" });
}
