//! w35 D4 tests: R_Exec over a run (public s_in / s_out), laptop, small sizes.
use pqz_plonky3_w36::chunk::plain::honest_publics;
use pqz_plonky3_w36::data::Workload;
use pqz_plonky3_w36::run::plain::*;
use pqz_plonky3_w36::run::RunPublic;
use pqz_plonky3_w36::{c1, FriOpts};

const BS: usize = 8;
const THETA: u64 = 1 << 31;

fn stream(g: usize, seed: u64) -> Vec<Vec<u64>> {
    let mut w = Workload::synthetic(g * BS, BS, seed);
    // make about a third of the records match (v >= THETA) so counts are non-trivial
    for (i, x) in w.words.iter_mut().enumerate() {
        if x[7] == 0 && i % 3 == 0 {
            x[4] = THETA + (i as u64 % 1000);
        } else if x[7] == 0 {
            x[4] %= THETA;
        }
    }
    c1::words(&w)
}

fn start_state(words: &[Vec<u64>], first_block: usize, total_blocks: usize) -> [u64; 12] {
    let mut s = pqz_plonky3_w36::chunk::iv_state((total_blocks * (BS + 1)) as u64);
    if first_block > 0 {
        s = pqz_plonky3_w36::chunk::state_after::<c1::Val, 12, _>(&c1::perm(), &s, &words[..first_block * (BS + 1)]);
    }
    s
}

#[test]
fn run_equals_reference_and_verifies() {
    let o = FriOpts::from_env();
    let g = 13;
    let words = stream(g, 7);
    let ctx = [1u64, 2, 3, 4];
    for (a, b) in [(0usize, 13usize), (0, 4), (4, 9), (9, 13), (5, 6)] {
        let rw = &words[a * (BS + 1)..b * (BS + 1)];
        let s_in = start_state(&words, a, g);
        let p = honest_public(rw, &s_in, BS, THETA, ctx);
        // reference over the words, plain integer code
        let (mut c, mut s) = (0u64, 0u64);
        for w in rw {
            if w[7] == 0 && w[4] >= THETA {
                c += 1;
                s += w[5];
            }
        }
        assert_eq!((p.count, p.sum), (c, s));
        let pr = prove_run(&o, rw, &p).expect("prove");
        verify_run(&o, &pr, &p).expect("honest run verifies");
    }
    // whole stream: s_out of the run = last chunk s_out of the chunk chain (same sponge)
    let (pubs, _) = honest_publics(&words, BS, 4);
    let p = honest_public(&words, &start_state(&words, 0, g), BS, THETA, ctx);
    assert_eq!(p.s_out, pubs.last().unwrap().s_out);
}

fn rej(label: &str, words: &[Vec<u64>], p: &RunPublic, mutate: impl FnOnce(&mut RunPublic)) {
    let o = FriOpts::from_env();
    let pr = prove_run(&o, words, p).expect("prove");
    verify_run(&o, &pr, p).expect("honest");
    let mut q = p.clone();
    mutate(&mut q);
    assert!(verify_run(&o, &pr, &q).is_err(), "{label}: must be rejected");
}

#[test]
fn run_statement_tampering_is_rejected() {
    let g = 8;
    let words = stream(g, 17);
    let (a, b) = (2usize, 6usize);
    let rw = &words[a * (BS + 1)..b * (BS + 1)];
    let s_in = start_state(&words, a, g);
    let p = honest_public(rw, &s_in, BS, THETA, [9, 8, 7, 6]);
    assert!(p.count > 0);
    rej("count", rw, &p, |q| q.count += 1);
    rej("sum", rw, &p, |q| q.sum += 1);
    rej("s_in", rw, &p, |q| q.s_in[9] ^= 1);
    rej("s_out", rw, &p, |q| q.s_out[3] ^= 1);
    rej("s_out cap", rw, &p, |q| q.s_out[8] ^= 1);
    rej("ctx", rw, &p, |q| q.ctx[0] ^= 1);
    rej("theta", rw, &p, |q| q.theta -= 1);
    rej("hdr_first", rw, &p, |q| q.hdr_first[1] += 1);
    rej("n_blocks", rw, &p, |q| q.n_blocks += 1);
    rej("block_size", rw, &p, |q| q.block_size += 1);
}

#[test]
fn run_over_foreign_stream_of_the_same_size_is_rejected() {
    let o = FriOpts::from_env();
    let g = 6;
    let a = stream(g, 1);
    let b = stream(g, 2);
    let s_in = start_state(&a, 1, g);
    let p = honest_public(&a[BS + 1..4 * (BS + 1)], &s_in, BS, THETA, [0; 4]);
    let foreign = &b[BS + 1..4 * (BS + 1)];
    if let Ok(pr) = prove_run(&o, foreign, &p) {
        assert!(verify_run(&o, &pr, &p).is_err());
    }
}

#[test]
fn run_that_does_not_start_at_a_header_is_rejected_by_the_grammar() {
    // words of a run begin in the middle of a block: row 0 must be the (public) header of a block
    let o = FriOpts::from_env();
    let words = stream(4, 3);
    let rw = &words[1..3 * (BS + 1)]; // starts at the first record
    let s_in = start_state(&words, 0, 4);
    let mut p = honest_public(rw, &s_in, BS, THETA, [0; 4]);
    p.n_blocks = 3; // statement claims 3 blocks, words are not block aligned
    match prove_run(&o, rw, &p) {
        Err(_) => {}
        Ok(pr) => assert!(verify_run(&o, &pr, &p).is_err()),
    }
}

#[test]
fn run_air_accepts_free_header_slots_5_and_6() {
    // w35 v3 (D1c): header slots 5-6 carry hd_g; the run AIR must not constrain them (they are part of the digest only)
    let o = FriOpts::from_env();
    let g = 6;
    let mut words = stream(g, 17);
    for b in 0..g {
        words[b * (BS + 1)][5] = 0x1234_5678_9ABC + b as u64;
        words[b * (BS + 1)][6] = 0xFEDC_BA98_7654 + b as u64;
    }
    let ctx = [1u64, 2, 3, 4];
    for (a, b) in [(0usize, 6usize), (2, 5)] {
        let rw = &words[a * (BS + 1)..b * (BS + 1)];
        let p = honest_public(rw, &start_state(&words, a, g), BS, THETA, ctx);
        let pr = prove_run(&o, rw, &p).expect("prove");
        verify_run(&o, &pr, &p).expect("a run whose headers carry nonzero slots 5-6 verifies");
    }
}
