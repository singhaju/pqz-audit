//! w39zk: paired, interleaved plain vs hiding (zk) comparison for the PACKED format (fmt=p2r), R_Exec and R_RC, trace=seq.
//! usage: pzk3 <exec|rc> n=N [block=100] [fri=fast1] [reps=5] [fmt=p2r|p2]
//! Both configs run in ONE process, alternating run by run (plain, zk, plain, zk, ...), after 1 untimed warm-up pair.
//! Output: RUN,<rel>,<n>,<mode>,<rep>,<prove_s>,<verify_s>,<bytes>   (verify = parse + verify of the serialized proof)
//! Config-only change w.r.t. w38: the same AIR objects are proved with `c1zk::config` (HidingFriPcs + MerkleTreeHidingMmcs).
use pqz_plonky3_w38::data::Workload;
use pqz_plonky3_w38::pair::*;
use pqz_plonky3_w38::pchunk::plain as pc;
use pqz_plonky3_w38::{c1, c1zk, FriOpts};
use std::time::Instant;

fn arg(a: &[String], k: &str) -> Option<String> {
    a.iter().find_map(|x| x.strip_prefix(&format!("{k}=")).map(|s| s.to_string()))
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let rel = a.get(1).cloned().unwrap_or_default();
    let n: usize = arg(&a, "n").and_then(|s| s.parse().ok()).expect("n=N");
    let block: usize = arg(&a, "block").and_then(|s| s.parse().ok()).unwrap_or(100);
    let reps: usize = arg(&a, "reps").and_then(|s| s.parse().ok()).unwrap_or(5);
    let o = FriOpts::preset(&arg(&a, "fri").unwrap_or_else(|| "fast1".into())).expect("fri");
    let f = if arg(&a, "fmt").as_deref() == Some("p2") { Fmt::P2 } else { Fmt::P2r };
    assert!(rel == "exec" || rel == "rc");
    let wl = Workload::synthetic(n, block, 1);
    let words = pack_workload(&wl);
    let epub = pair_public(&wl, 1u64 << 31, [1, 2, 3, 4]);
    let (cpubs, _lists) = pc::honest_publics(&words, block, wl.n_blocks);
    let rpw = rows_per_block(block);
    for rep in 0..=reps {
        for mode in ["plain", "zk"] {
            let (prove_s, verify_s, bytes);
            if rel == "exec" {
                let air = pair_air(epub.theta, pair_n_words(epub.n_blocks, epub.block_size) as u64, f);
                let trace = air.build_trace(&c1::perm(), &words, epub.block_size);
                let pv = pair_values(&epub);
                let t = Instant::now();
                if mode == "plain" {
                    let p = p3_uni_stark::prove(&c1::config(&o), &air, trace, &pv).expect("prove");
                    prove_s = t.elapsed().as_secs_f64();
                    let b = c1::to_bytes(&p);
                    let t2 = Instant::now();
                    let q = c1::from_bytes(&b).unwrap();
                    verify_pair(&o, &q, &epub, f).expect("verify plain");
                    verify_s = t2.elapsed().as_secs_f64();
                    bytes = b.len();
                } else {
                    let p = p3_uni_stark::prove(&c1zk::config(&o), &air, trace, &pv).expect("prove zk");
                    prove_s = t.elapsed().as_secs_f64();
                    let b = c1zk::to_bytes(&p);
                    let t2 = Instant::now();
                    let q = c1zk::from_bytes(&b).unwrap();
                    p3_uni_stark::verify(&c1zk::config(&o), &air, &q, &pv).expect("verify zk");
                    verify_s = t2.elapsed().as_secs_f64();
                    bytes = b.len();
                }
            } else {
                let p = &cpubs[0];
                let air = pc::chunk_air(p).unwrap();
                let cw = &words[0..p.n_blocks_chunk * rpw];
                let trace = air.build_trace(&c1::perm(), cw, &p.s_in, &p.alpha, &p.beta, p.hdr_before as u64);
                let pv = pc::values(p);
                let t = Instant::now();
                if mode == "plain" {
                    let pr = p3_uni_stark::prove(&c1::config(&o), &air, trace, &pv).expect("prove");
                    prove_s = t.elapsed().as_secs_f64();
                    let b = c1::to_bytes(&pr);
                    let t2 = Instant::now();
                    let q = c1::from_bytes(&b).unwrap();
                    pc::verify_chunk(&o, &q, p).expect("verify plain");
                    verify_s = t2.elapsed().as_secs_f64();
                    bytes = b.len();
                } else {
                    let pr = p3_uni_stark::prove(&c1zk::config(&o), &air, trace, &pv).expect("prove zk");
                    prove_s = t.elapsed().as_secs_f64();
                    let b = c1zk::to_bytes(&pr);
                    let t2 = Instant::now();
                    let q = c1zk::from_bytes(&b).unwrap();
                    p3_uni_stark::verify(&c1zk::config(&o), &air, &q, &pv).expect("verify zk");
                    verify_s = t2.elapsed().as_secs_f64();
                    bytes = b.len();
                }
            }
            println!("RUN,{rel},{n},{mode},{},{prove_s:.6},{verify_s:.6},{bytes}", if rep == 0 { "warm".to_string() } else { rep.to_string() });
        }
    }
}
