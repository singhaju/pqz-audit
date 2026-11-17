//! w34 (C3): prints the proven security bits (conj / unique decoding / list decoding, `security.rs`) of the presets
//! `std` and `hi` for R_Exec, R_RC and R_Auth at N in {1e3 .. 1e5}, and finds the smallest num_queries (<= 255) for which the
//! proven unique-decoding bits are >= 100 for EVERY relation at EVERY N (plain mode). Estimator only; no proof is made.
//! usage: sectable            (prints the table and the search result)
//!
//! w36 (S2): also searches the speed presets. For log_blowup 2 (`fast2`) and 1 (`fast1`) it finds the SMALLEST num_queries q (<= 255) for which,
//! for R_Exec, R_RC and R_Auth at every N of the grid (plain mode, honest trace heights), conjectured >= 127, proven unique decoding >= 49 and
//! proven list decoding >= the `std` value at the same N and relation; it checks that every larger q <= 255 also passes, checks the constants
//! `FAST2_NUM_QUERIES` / `FAST1_NUM_QUERIES` of variants.rs against the search, prints the table, and exits with status 1 on any mismatch.
//! (zk mode, trace x2, is printed for information with the same three conditions against the zk `std` values; it does not choose q.)

use pqz_plonky3_w38::security::estimate;
use pqz_plonky3_w38::variants::{FAST1_NUM_QUERIES, FAST2_NUM_QUERIES, HI_NUM_QUERIES};
use pqz_plonky3_w38::{c1, c1zk, FriOpts};

const NS: [usize; 7] = [1000, 2000, 5000, 10000, 20000, 50000, 100000];
const BLOCK: usize = 100;
const DEPTH: usize = 10;

/// (relation, plain trace rows, zk trace rows used by the estimator = honest zk height x 2 is applied inside c1zk::sec_input)
fn rows(n: usize) -> [(&'static str, usize, usize); 3] {
    let n_words = (n / BLOCK) * (BLOCK + 1);
    let r = c1::n_rows(n_words);
    let ra = pqz_plonky3_w38::rel::plain::auth_rows(DEPTH);
    let rz = pqz_plonky3_w38::rel::zk::auth_rows(DEPTH).max(128);
    [("exec", r, r), ("rc", r, r), ("auth", ra, rz)]
}

fn bits(o: &FriOpts, plain_rows: usize) -> (u32, u32, u32) {
    let s = estimate(&c1::sec_input(o, plain_rows));
    (s.conjectured, s.proven_unique_decoding, s.proven_list_decoding)
}
fn bits_zk(o: &FriOpts, rows: usize) -> (u32, u32, u32) {
    let s = estimate(&c1zk::sec_input(o, rows));
    (s.conjectured, s.proven_unique_decoding, s.proven_list_decoding)
}

fn min_ud(o: &FriOpts, zk: bool) -> u32 {
    let mut m = u32::MAX;
    for &n in &NS {
        for (_, rp, rz) in rows(n) {
            m = m.min(if zk { bits_zk(o, rz).1 } else { bits(o, rp).1 });
        }
    }
    m
}

fn main() {
    let std_o = FriOpts::std();
    let hi_o = FriOpts::hi();
    println!("preset std: queries={} log_blowup={} pow={} final_poly=2^{} arity=2^{}", std_o.num_queries, std_o.log_blowup, std_o.query_pow_bits, std_o.log_final_poly_len, std_o.max_log_arity);
    println!("preset hi : queries={} log_blowup={} pow={} final_poly=2^{} arity=2^{}", hi_o.num_queries, hi_o.log_blowup, hi_o.query_pow_bits, hi_o.log_final_poly_len, hi_o.max_log_arity);
    println!("search (plain mode, proven unique decoding >= 100 for every relation and every N):");
    let mut best = (0u32, 0usize);
    let mut found = None;
    for q in 1..=255usize {
        let o = FriOpts { num_queries: q, ..FriOpts::default() };
        let m = min_ud(&o, false);
        if m > best.0 {
            best = (m, q);
        }
        if m >= 100 && found.is_none() {
            found = Some(q);
        }
    }
    match found {
        Some(q) => println!("  smallest num_queries with min udr >= 100: {q} (min udr there = {})", min_ud(&FriOpts { num_queries: q, ..FriOpts::default() }, false)),
        None => println!("  100 NOT reachable with num_queries <= 255; maximum min udr = {} at num_queries = {}", best.0, best.1),
    }
    println!("  (zk mode, trace x2, for information) min udr at std = {}, at hi = {}", min_ud(&std_o, true), min_ud(&hi_o, true));
    println!("  HI_NUM_QUERIES in variants.rs = {HI_NUM_QUERIES}");
    println!();
    println!("N,relation,rows_plain,std_conj,std_udr,std_ldr,hi_conj,hi_udr,hi_ldr,rows_zk,zk_std_conj,zk_std_udr,zk_std_ldr,zk_hi_conj,zk_hi_udr,zk_hi_ldr");
    for &n in &NS {
        for (name, rp, rz) in rows(n) {
            let (a, b) = (bits(&std_o, rp), bits(&hi_o, rp));
            let (c, d) = (bits_zk(&std_o, rz), bits_zk(&hi_o, rz));
            println!("{n},{name},{rp},{},{},{},{},{},{},{},{},{},{},{},{},{}", a.0, a.1, a.2, b.0, b.1, b.2, rz * 2, c.0, c.1, c.2, d.0, d.1, d.2);
        }
    }
    if !s2_main() {
        std::process::exit(1);
    }
}

/// w36 (S2) rule at one option set: for every N and relation (plain heights, or zk heights with `zk`), conj >= 127, udr >= 49, ldr >= std ldr.
fn rule_holds(o: &FriOpts, zk: bool) -> bool {
    let std_o = FriOpts::std();
    NS.iter().all(|&n| {
        rows(n).iter().all(|&(_, rp, rz)| {
            let (s, t) = if zk { (bits_zk(o, rz), bits_zk(&std_o, rz)) } else { (bits(o, rp), bits(&std_o, rp)) };
            s.0 >= 127 && s.1 >= 49 && s.2 >= t.2
        })
    })
}

fn preset_with(log_blowup: usize, q: usize) -> FriOpts {
    FriOpts { log_blowup, num_queries: q, ..FriOpts::default() }
}

/// Prints the S2 search for `log_blowup`; returns false if the constant `chosen` does not equal the smallest passing q or q is not monotone.
fn s2_search(name: &str, log_blowup: usize, chosen: usize) -> bool {
    let found = (1..=255usize).find(|&q| rule_holds(&preset_with(log_blowup, q), false));
    let mut ok = true;
    match found {
        Some(q) => {
            let mono = (q..=255).all(|x| rule_holds(&preset_with(log_blowup, x), false));
            let below = if q > 1 { rule_holds(&preset_with(log_blowup, q - 1), false) } else { false };
            println!("S2 {name} (log_blowup {log_blowup}): smallest q = {q}; every q in {q}..=255 passes: {mono}; q-1 passes: {below}; constant in variants.rs = {chosen}");
            ok &= mono && !below && q == chosen;
            let zk_ok = rule_holds(&preset_with(log_blowup, q), true);
            let zk_q = (1..=255usize).find(|&x| rule_holds(&preset_with(log_blowup, x), true));
            println!("   zk mode (information only, trace x2, same three conditions against zk std): holds at q = {q}: {zk_ok}; smallest q for zk = {zk_q:?}");
        }
        None => {
            println!("S2 {name}: no q <= 255 passes");
            ok = false;
        }
    }
    ok
}

/// Per-N table of the three presets (conj, udr, ldr) for the plain mode.
fn s2_table() {
    let (s, f2, f1) = (FriOpts::std(), FriOpts::fast2(), FriOpts::fast1());
    println!();
    println!("S2 table (plain mode): preset queries log_blowup: std {} {}, fast2 {} {}, fast1 {} {} (pow 16, final poly 2^5, arity 2^3)", s.num_queries, s.log_blowup, f2.num_queries, f2.log_blowup, f1.num_queries, f1.log_blowup);
    println!("N,relation,rows,std_conj,std_udr,std_ldr,fast2_conj,fast2_udr,fast2_ldr,fast1_conj,fast1_udr,fast1_ldr");
    for &n in &NS {
        for (name, rp, _) in rows(n) {
            let (a, b, c) = (bits(&s, rp), bits(&f2, rp), bits(&f1, rp));
            println!("{n},{name},{rp},{},{},{},{},{},{},{},{},{}", a.0, a.1, a.2, b.0, b.1, b.2, c.0, c.1, c.2);
        }
    }
}

fn s2_main() -> bool {
    println!();
    println!("--- w36 S2: speed presets (rule: conj >= 127, udr >= 49, ldr >= std at every N for exec, rc, auth) ---");
    let a = s2_search("fast2", 2, FAST2_NUM_QUERIES);
    let b = s2_search("fast1", 1, FAST1_NUM_QUERIES);
    s2_table();
    println!("S2 CHECK: {}", if a && b { "PASS" } else { "FAIL" });
    a && b
}
