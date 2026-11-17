//! w33 stage C attack / tamper experiment (correctness only, NO timing) on the Plonky3 C1 proofs.
//! Port of `bench/pqz-attack-w30-fixed/src/main.rs` (same attack names, same seeds, same instance generators, same trial plans,
//! same outcome rules). What changed: the prover and verifier calls (Plonky3 `plain::*` wrappers of `pqz-plonky3-w33`), field
//! elements are canonical `u64` (additions are done mod p), and the chunked forms and the sha3/blake3 split do not exist here
//! (one proof per relation over the whole stream; Blake3 only). See `README.md` of this crate for the list of attacks without
//! meaning in the new build.
//!
//! Usage (key=value arguments):
//!   attack run  [out=DIR] [attack_trials=20] [honest_trials=50] [n20k=4] [n50k=1] [h20k=5] [h50k=2]
//!               [forms=exec_single,rc_single,pair,bundle] [tag=NAME] [max_min=M] [only=SUBSTRING] [seed_base=30000]
//!   attack merge DIR          (merge every raw-*.csv into raw.csv, summary.csv and summary_variants.csv; the file raw-*-nochecks*.csv
//!                              (rows of the w34 forms with the native checks switched OFF) is merged separately into *_nochecks.csv)
//!   attack probe              (prints the security estimate for the weaker options)
//!
//! Outcomes: accepted | rejected | prover_refused | harness_error. Only a verifier that RETURNED an error counts as rejected
//! (including the verifier's own guard "rejected: verifier panicked on malformed input", flagged in column verifier_panic).
//! A panic anywhere else (the harness, the parser) is harness_error.

//! w38: this file is the w36 harness unchanged except for the crate name (`pqz_plonky3_w38`, whose old modes are untouched): it is the
//! DEFAULT (old format) path. The packed format (P2r) is in `p2r.rs` (child module, uses the private helpers of this file): `attack run fmt=p2r ...`.

use pqz_plonky3_w38::air::ExecPublic;
use pqz_plonky3_w38::auth::{honest_auth_instance, root_of, AuthPublic, AuthWitness};
use pqz_plonky3_w38::data::{Rng, Workload, GOLDILOCKS_P};
use pqz_plonky3_w38::rc::RcPublic;
use pqz_plonky3_w38::rel::plain;
use pqz_plonky3_w38::request::{exec_context, verify_bundle_with, verify_request, NativeChecks};
use pqz_plonky3_w38::security;
use pqz_plonky3_w38::variants::{c1, FriOpts};
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

#[path = "p2r.rs"]
mod p2r;

type Pf = c1::P;
type Val = c1::Val;

const BLOCK: usize = 100;
const AUTH_DEPTH: usize = 10;
/// routine request: RID_Q = 0
const RID: u64 = 0;
const HASH_NAME: &str = "blake3";

fn o() -> FriOpts {
    FriOpts::from_env() // w36: preset from PQZ_FRI (std if unset)
}
fn o_q(q: usize) -> FriOpts {
    FriOpts { num_queries: q, ..FriOpts::from_env() }
}

// ------------------------------------------------------------------------------------------------ outcome plumbing

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Out {
    Accepted,
    Rejected,
    ProverRefused,
    HarnessError,
    /// w38: attack without meaning in the packed format (a row with the reason; counted as `untested` by the merge)
    Untested,
}
impl Out {
    fn s(self) -> &'static str {
        match self {
            Out::Untested => "untested",
            Out::Accepted => "accepted",
            Out::Rejected => "rejected",
            Out::ProverRefused => "prover_refused",
            Out::HarnessError => "harness_error",
        }
    }
}

#[derive(Clone, Debug)]
struct V {
    variant: String,
    out: Out,
    text: String,
}

fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic".to_string()
    }
}

fn catch<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).map_err(panic_text)
}

fn vv(variant: &str, r: Result<(), String>) -> V {
    match r {
        Ok(()) => V { variant: variant.into(), out: Out::Accepted, text: "verifier accepted".into() },
        Err(e) => V { variant: variant.into(), out: Out::Rejected, text: e },
    }
}
fn refused(variant: &str, text: String) -> V {
    V { variant: variant.into(), out: Out::ProverRefused, text }
}
fn herr(variant: &str, text: String) -> V {
    V { variant: variant.into(), out: Out::HarnessError, text }
}
/// run a verifier call; a panic that escapes the verifier's own guard is a harness error, not a rejection
fn vcatch(variant: &str, f: impl FnOnce() -> Result<(), String>) -> V {
    match catch(f) {
        Ok(r) => vv(variant, r),
        Err(m) => herr(variant, format!("panic outside the verifier's own guard: {m}")),
    }
}
fn note(mut v: V, n: &str) -> V {
    v.text = format!("{n}; {}", v.text);
    v
}

// ------------------------------------------------------------------------------------------------ rng helpers (field = Goldilocks, canonical u64)

fn below(r: &mut Rng, n: usize) -> usize {
    (r.next_u64() % n as u64) as usize
}
fn frand(r: &mut Rng) -> u64 {
    r.next_u64() % GOLDILOCKS_P
}
fn delta(r: &mut Rng) -> u64 {
    1 + r.next_u64() % 1_000_000
}
/// field addition (canonical result)
fn fadd(a: u64, b: u64) -> u64 {
    ((a as u128 + b as u128) % GOLDILOCKS_P as u128) as u64
}
fn sub_rng(seed: u64, name: &str) -> Rng {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes() {
        h = (h ^ b as u64).wrapping_mul(0x100_0000_01b3);
    }
    Rng::new(seed ^ h)
}

// ------------------------------------------------------------------------------------------------ workload mutations

/// index of a random record word
fn rec_index(w: &Workload, r: &mut Rng) -> usize {
    let g = below(r, w.n_blocks);
    let k = below(r, w.block_size);
    g * (w.block_size + 1) + 1 + k
}

fn mutate(w: &Workload, kind: &str, r: &mut Rng) -> Workload {
    let mut m = w.clone();
    match kind {
        "changed_record_word" => {
            let i = rec_index(w, r);
            let j = below(r, 7); // pid, epoch, seq, id, v, b, tag (never the flag)
            let x = m.words[i][j];
            m.words[i][j] = match j {
                4 => x ^ (1u64 << below(r, 32)),
                5 => x ^ (1u64 << below(r, 20)),
                _ => fadd(x, delta(r)),
            };
        }
        "dropped_record" => {
            let i = rec_index(w, r);
            m.words.remove(i);
        }
        "duplicated_record" => {
            let i = rec_index(w, r);
            let x = m.words[i];
            m.words.insert(i, x);
        }
        "reordered_records" => {
            let i = rec_index(w, r);
            let mut j = rec_index(w, r);
            while j == i || m.words[i] == m.words[j] {
                j = rec_index(w, r);
            }
            m.words.swap(i, j);
        }
        "changed_block_header" => {
            let g = below(r, w.n_blocks);
            let j = below(r, 5); // e, g, m_b, pid, seq_start
            let i = g * (w.block_size + 1);
            m.words[i][j] = fadd(m.words[i][j], delta(r));
        }
        _ => panic!("unknown mutation {kind}"),
    }
    m
}
const STREAM_ATTACKS: [&str; 5] =
    ["changed_record_word", "dropped_record", "duplicated_record", "reordered_records", "changed_block_header"];

fn rnd_ctx(r: &mut Rng) -> [u64; 4] {
    [frand(r), frand(r), frand(r), frand(r)]
}
fn rnd_theta(r: &mut Rng) -> u64 {
    (1u64 << 28) + r.next_u64() % ((1u64 << 32) - (1u64 << 29))
}

// ------------------------------------------------------------------------------------------------ result sink

struct Raw {
    attack: String,
    form: String,
    hash: String,
    n_q: usize,
    seed: u64,
    outcome: String,
    error: String,
    variant: String,
    verifier_panic: u8,
}

fn clean(s: &str) -> String {
    let s: String = s.chars().map(|c| if c == '\n' || c == '\r' || c == '"' || c == ',' { ' ' } else { c }).collect();
    s.chars().take(240).collect()
}

const RAW_HEADER: &str = "attack,form,hash,n_q,seed,outcome,error,variant,verifier_panic";

fn raw_line(r: &Raw) -> String {
    format!("{},{},{},{},{},{},\"{}\",{},{}", r.attack, r.form, r.hash, r.n_q, r.seed, r.outcome, clean(&r.error), r.variant, r.verifier_panic)
}

struct Sink {
    file: std::fs::File,
    n_rows: usize,
}
impl Sink {
    fn emit(&mut self, attack: &str, form: &str, n_q: usize, seed: u64, vs: Vec<V>) {
        for v in vs {
            let r = Raw {
                attack: attack.into(),
                form: form.into(),
                hash: HASH_NAME.into(),
                n_q,
                seed,
                outcome: v.out.s().into(),
                verifier_panic: v.text.contains("verifier panicked") as u8,
                error: v.text,
                variant: v.variant,
            };
            writeln!(self.file, "{}", raw_line(&r)).unwrap();
            self.n_rows += 1;
        }
        self.file.flush().unwrap();
    }
}

type Attacks = Vec<(String, Vec<V>)>;

fn run_one(out: &mut Attacks, name: &str, seed: u64, only: &Option<String>, f: &mut dyn FnMut(&mut Rng) -> Vec<V>) {
    if let Some(o) = only {
        if !name.contains(o.as_str()) {
            return;
        }
    }
    let mut rng = sub_rng(seed, name);
    let vs = match catch(|| f(&mut rng)) {
        Ok(v) => v,
        Err(m) => vec![herr("harness", format!("attack code panicked: {m}"))],
    };
    out.push((name.to_string(), vs));
}

// ------------------------------------------------------------------------------------------------ proofs: helpers

type VerExec<'a> = &'a dyn Fn(&Pf, &ExecPublic) -> Result<(), String>;
type VerRc<'a> = &'a dyn Fn(&Pf, &RcPublic) -> Result<(), String>;
type VerAuth<'a> = &'a dyn Fn(&Pf, &AuthPublic) -> Result<(), String>;

fn parse(bytes: &[u8]) -> Result<Pf, String> {
    c1::from_bytes(bytes).map_err(|e| format!("parse: {e}"))
}

/// flip one bit of one random byte; returns (new bytes, position, mask)
fn flip(bytes: &[u8], r: &mut Rng) -> (Vec<u8>, usize, u8) {
    let mut b = bytes.to_vec();
    let pos = below(r, b.len());
    let mask = 1u8 << below(r, 8);
    b[pos] ^= mask;
    (b, pos, mask)
}

/// flip variant: parse failure is a rejection, parse panic is a harness error, otherwise verify
fn flip_variant(name: &str, bytes: &[u8], r: &mut Rng, verify: impl FnOnce(&Pf) -> Result<(), String>) -> V {
    let (b, pos, mask) = flip(bytes, r);
    let tag = format!("byte {pos} of {} xor {mask:#04x}", bytes.len());
    match catch(|| parse(&b)) {
        Err(m) => herr(name, format!("{tag}; parser panicked: {m}")),
        Ok(Err(e)) => note(vv(name, Err(e)), &tag),
        Ok(Ok(p)) => note(vcatch(name, || verify(&p)), &tag),
    }
}

/// security estimate of the Plonky3 proof with `q` queries and `rows` trace rows (the `security.rs` port)
fn bits_note(q: usize, rows: usize) -> String {
    let s = security::estimate(&c1::sec_input(&o_q(q), rows));
    format!("queries={q} conj_bits={} udr_bits={} ldr_bits={}", s.conjectured, s.proven_unique_decoding, s.proven_list_decoding)
}

fn ctx_of(a: &AuthPublic) -> [u64; 4] {
    exec_context(&c1::perm(), a.b_q, a.d_q, RID)
}

// ================================================================================================ single R_Exec

struct ExecCase {
    w: Workload,
    theta: u64,
    pubin: ExecPublic,
    proof: Pf,
    bytes: Vec<u8>,
    other_proof: Pf,
    other_pub: ExecPublic,
}

fn exec_case(n_q: usize, seed: u64, ctx_fixed: Option<[u64; 4]>, ctx_other: Option<[u64; 4]>) -> Result<ExecCase, String> {
    let mut r = Rng::new(seed);
    let wseed = r.next_u64();
    let theta = rnd_theta(&mut r);
    let ctx = ctx_fixed.unwrap_or_else(|| rnd_ctx(&mut r));
    let w = Workload::synthetic(n_q, BLOCK, wseed);
    let pubin = c1::public_for(&w, theta, ctx);
    let proof = plain::prove_exec(&o(), &w, &pubin)?;
    let bytes = c1::to_bytes(&proof);
    // a second, independent workload (same shape, same theta) for the "proof of another workload" attacks
    let w2 = Workload::synthetic(n_q, BLOCK, wseed ^ 0x5eed_0002);
    let ctx2 = ctx_other.unwrap_or_else(|| rnd_ctx(&mut r));
    let other_pub = c1::public_for(&w2, theta, ctx2);
    let other_proof = plain::prove_exec(&o(), &w2, &other_pub)?;
    Ok(ExecCase { w, theta, pubin, proof, bytes, other_proof, other_pub })
}

fn exec_ver_direct(p: &Pf, q: &ExecPublic) -> Result<(), String> {
    plain::verify_exec(&o(), p, q)
}

/// dishonest prover for R_Exec: witness from the words of `w` (honest trace of those words), public `prove_pub`; the verifier is then given `ver_pub`
fn p1_exec(variant: &str, w: &Workload, prove_pub: &ExecPublic, ver_pub: &ExecPublic, ver: VerExec) -> V {
    match catch(|| plain::prove_exec(&o(), w, prove_pub)) {
        Err(m) => refused(variant, format!("trace build or prover panicked: {m}")),
        Ok(Err(e)) => refused(variant, e),
        Ok(Ok(proof)) => vcatch(variant, || ver(&proof, ver_pub)),
    }
}

fn exec_suite(c: &ExecCase, seed: u64, ver: VerExec, only: &Option<String>) -> Attacks {
    let mut out = Attacks::new();
    for kind in STREAM_ATTACKS {
        run_one(&mut out, kind, seed, only, &mut |rng| {
            let w2 = mutate(&c.w, kind, rng);
            let p1 = p1_exec("dishonest_prover", &w2, &c.pubin, &c.pubin, ver);
            let pub2 = c1::public_for(&w2, c.theta, c.pubin.ctx);
            let p2 = vcatch("honest_proof_other_stream_public", || ver(&c.proof, &pub2));
            vec![p1, p2]
        });
    }
    run_one(&mut out, "wrong_claimed_count", seed, only, &mut |rng| {
        let mut pf = c.pubin.clone();
        pf.count += 1 + below(rng, 1000) as u64;
        let p1 = p1_exec("dishonest_prover", &c.w, &pf, &pf, ver);
        let p2 = vcatch("honest_proof_false_claim", || ver(&c.proof, &pf));
        vec![p1, p2]
    });
    run_one(&mut out, "wrong_claimed_sum", seed, only, &mut |rng| {
        let mut pf = c.pubin.clone();
        pf.sum[0] += 1 + below(rng, 1 << 20) as u64;
        let p1 = p1_exec("dishonest_prover", &c.w, &pf, &pf, ver);
        let p2 = vcatch("honest_proof_false_claim", || ver(&c.proof, &pf));
        vec![p1, p2]
    });
    run_one(&mut out, "wrong_digest", seed, only, &mut |rng| {
        let mut pf = c.pubin.clone();
        let j = below(rng, 4);
        pf.digest[j] = fadd(pf.digest[j], delta(rng));
        vec![vcatch("honest_proof_other_digest", || ver(&c.proof, &pf))]
    });
    run_one(&mut out, "other_workload_proof", seed, only, &mut |_| {
        vec![vcatch("proof_of_other_workload", || ver(&c.other_proof, &c.pubin))]
    });
    run_one(&mut out, "other_theta", seed, only, &mut |rng| {
        let t2 = ((c.theta + 1 + below(rng, 1 << 20) as u64) % (1u64 << 32)).max(1);
        let mut pt = c.pubin.clone();
        pt.theta = t2;
        // dishonest prover: the trace is the honest trace of the OTHER theta, the proof is made for the ORIGINAL public statement
        let n_words = c.pubin.n_words() as u64;
        let p1 = match catch(|| {
            let a = c1::air(c.pubin.theta, n_words);
            let a2 = c1::air(t2, n_words);
            let trace = a2.build_trace(&c1::perm(), &c1::words(&c.w));
            let pv = c.pubin.to_values::<Val>(&a.lay);
            p3_uni_stark::prove(&c1::config(&o()), &a, trace, &pv).map_err(|e| format!("{e:?}"))
        }) {
            Err(m) => refused("dishonest_prover_trace_of_other_theta", format!("trace build or prover panicked: {m}")),
            Ok(Err(e)) => refused("dishonest_prover_trace_of_other_theta", e),
            Ok(Ok(proof)) => vcatch("dishonest_prover_trace_of_other_theta", || ver(&proof, &c.pubin)),
        };
        let p2 = vcatch("honest_proof_other_theta_public", || ver(&c.proof, &pt));
        vec![p1, p2]
    });
    run_one(&mut out, "other_ctx", seed, only, &mut |rng| {
        let mut pc = c.pubin.clone();
        let j = below(rng, 4);
        pc.ctx[j] = fadd(pc.ctx[j], delta(rng));
        let p1 = p1_exec("proof_made_for_other_ctx", &c.w, &pc, &c.pubin, ver);
        let p2 = vcatch("honest_proof_other_ctx_public", || ver(&c.proof, &pc));
        vec![p1, p2]
    });
    run_one(&mut out, "flipped_proof_byte", seed, only, &mut |rng| {
        vec![flip_variant("flip", &c.bytes, rng, |p| ver(p, &c.pubin))]
    });
    let rows = c1::n_rows(c.pubin.n_words());
    run_one(&mut out, "weaker_options_below_floor", seed, only, &mut |rng| {
        let q = [5usize, 10, 15, 20][below(rng, 4)];
        match catch(|| plain::prove_exec(&o_q(q), &c.w, &c.pubin)) {
            Err(m) => vec![refused("weak_prover", m)],
            Ok(Err(e)) => vec![refused("weak_prover", e)],
            Ok(Ok(p)) => {
                let n = bits_note(q, rows);
                vec![note(vcatch("strict_options", || ver(&p, &c.pubin)), &n)]
            }
        }
    });
    run_one(&mut out, "weaker_options_above_floor", seed, only, &mut |rng| {
        let q = [30usize, 35][below(rng, 2)];
        match catch(|| plain::prove_exec(&o_q(q), &c.w, &c.pubin)) {
            Err(m) => vec![refused("weak_prover", m)],
            Ok(Err(e)) => vec![refused("weak_prover", e)],
            Ok(Ok(p)) => {
                let n = bits_note(q, rows);
                vec![note(vcatch("strict_options", || ver(&p, &c.pubin)), &n)]
            }
        }
    });
    out
}

// ================================================================================================ single R_RC

struct RcCase {
    w: Workload,
    pubin: RcPublic,
    proof: Pf,
    bytes: Vec<u8>,
    other_proof: Pf,
}

fn rc_prove(opts: &FriOpts, w: &Workload, p: &RcPublic) -> Result<Pf, String> {
    plain::prove_rc(opts, &c1::words(w), p)
}
fn rc_pub_of(w: &Workload) -> RcPublic {
    plain::rc_public(&c1::words(w), w.block_size)
}

fn rc_case(n_q: usize, seed: u64) -> Result<RcCase, String> {
    let mut r = Rng::new(seed);
    let wseed = r.next_u64();
    let w = Workload::synthetic(n_q, BLOCK, wseed);
    let pubin = rc_pub_of(&w);
    let proof = rc_prove(&o(), &w, &pubin)?;
    let bytes = c1::to_bytes(&proof);
    let w2 = Workload::synthetic(n_q, BLOCK, wseed ^ 0x5eed_0002);
    let other_proof = rc_prove(&o(), &w2, &rc_pub_of(&w2))?;
    Ok(RcCase { w, pubin, proof, bytes, other_proof })
}

fn p1_rc(variant: &str, w: &Workload, prove_pub: &RcPublic, ver_pub: &RcPublic, ver: VerRc) -> V {
    match catch(|| rc_prove(&o(), w, prove_pub)) {
        Err(m) => refused(variant, format!("trace build or prover panicked: {m}")),
        Ok(Err(e)) => refused(variant, e),
        Ok(Ok(proof)) => vcatch(variant, || ver(&proof, ver_pub)),
    }
}

fn rc_suite(c: &RcCase, seed: u64, ver: VerRc, only: &Option<String>) -> Attacks {
    let mut out = Attacks::new();
    for kind in STREAM_ATTACKS {
        run_one(&mut out, kind, seed, only, &mut |rng| {
            let w2 = mutate(&c.w, kind, rng);
            let p1 = p1_rc("dishonest_prover", &w2, &c.pubin, &c.pubin, ver);
            // as w30 `rc_public(&w2)`: n_blocks stays the original (the mutated Workload keeps its n_blocks field)
            let mut pub2 = rc_pub_of(&w2);
            pub2.n_blocks = c.pubin.n_blocks;
            let p2 = vcatch("honest_proof_other_stream_public", || ver(&c.proof, &pub2));
            vec![p1, p2]
        });
    }
    // claimed record count: the statement gives n_blocks (records = n_blocks * block_size)
    run_one(&mut out, "wrong_claimed_count", seed, only, &mut |rng| {
        let mut pf = c.pubin.clone();
        if below(rng, 2) == 0 {
            pf.n_blocks += 1 + below(rng, 5);
        } else {
            pf.n_blocks -= 1 + below(rng, 5).min(pf.n_blocks - 2);
        }
        let p1 = p1_rc("dishonest_prover", &c.w, &pf, &pf, ver);
        let p2 = vcatch("honest_proof_false_claim", || ver(&c.proof, &pf));
        vec![p1, p2]
    });
    run_one(&mut out, "wrong_digest", seed, only, &mut |rng| {
        let mut pf = c.pubin.clone();
        let j = below(rng, 4);
        pf.digest[j] = fadd(pf.digest[j], delta(rng));
        vec![vcatch("honest_proof_other_digest", || ver(&c.proof, &pf))]
    });
    run_one(&mut out, "other_workload_proof", seed, only, &mut |_| {
        vec![vcatch("proof_of_other_workload", || ver(&c.other_proof, &c.pubin))]
    });
    run_one(&mut out, "flipped_proof_byte", seed, only, &mut |rng| {
        vec![flip_variant("flip", &c.bytes, rng, |p| ver(p, &c.pubin))]
    });
    let rows = plain::rc_rows(c.pubin.n_words());
    for (name, qs) in [("weaker_options_below_floor", [5usize, 10, 15, 20]), ("weaker_options_above_floor", [30, 35, 30, 35])] {
        run_one(&mut out, name, seed, only, &mut |rng| {
            let q = qs[below(rng, 4)];
            match catch(|| rc_prove(&o_q(q), &c.w, &c.pubin)) {
                Err(m) => vec![refused("weak_prover", m)],
                Ok(Err(e)) => vec![refused("weak_prover", e)],
                Ok(Ok(p)) => {
                    let n = bits_note(q, rows);
                    vec![note(vcatch("strict_options", || ver(&p, &c.pubin)), &n)]
                }
            }
        });
    }
    out
}

// ================================================================================================ per-request pair (Auth + Exec)

struct AuthCase {
    pubin: AuthPublic,
    wit: AuthWitness,
    proof: Pf,
    bytes: Vec<u8>,
    other_proof: Pf,
}
fn auth_case(depth: usize, seed: u64) -> Result<AuthCase, String> {
    let perm = c1::perm();
    let (pubin, wit) = honest_auth_instance::<Val, _>(&perm, depth, seed);
    let proof = plain::prove_auth(&o(), &pubin, &wit)?;
    let bytes = c1::to_bytes(&proof);
    let (p2, w2) = honest_auth_instance::<Val, _>(&perm, depth, seed ^ 0x5eed_0003);
    let other_proof = plain::prove_auth(&o(), &p2, &w2)?;
    Ok(AuthCase { pubin, wit, proof, bytes, other_proof })
}

fn p1_auth(variant: &str, pub_prove: &AuthPublic, wit: &AuthWitness, pub_ver: &AuthPublic, ver: VerAuth) -> V {
    match catch(|| plain::prove_auth(&o(), pub_prove, wit)) {
        Err(m) => refused(variant, format!("trace build or prover panicked: {m}")),
        Ok(Err(e)) => refused(variant, e),
        Ok(Ok(proof)) => vcatch(variant, || ver(&proof, pub_ver)),
    }
}

/// mutate one public field; returns a short name
fn mutate_auth_public(p: &mut AuthPublic, which: usize, r: &mut Rng) -> String {
    match which {
        0 => {
            p.uid += 1 + below(r, 1000) as u64;
            "uid".into()
        }
        1 => {
            p.v_a += 1 + below(r, 1000) as u64;
            "v_a".into()
        }
        2 => {
            p.v_auth += 1 + below(r, 1000) as u64;
            "v_auth".into()
        }
        3 => {
            let j = below(r, 4);
            p.r_pol[j] = fadd(p.r_pol[j], delta(r));
            format!("r_pol[{j}]")
        }
        4 => {
            let j = below(r, 4);
            p.b_q[j] = fadd(p.b_q[j], delta(r));
            format!("b_q[{j}]")
        }
        5 => {
            let j = below(r, 4);
            p.d_q[j] = fadd(p.d_q[j], delta(r));
            format!("d_q[{j}]")
        }
        _ => {
            let j = below(r, 4);
            p.omega[j] = fadd(p.omega[j], delta(r));
            format!("omega[{j}]")
        }
    }
}

fn auth_suite(c: &AuthCase, seed: u64, ver: VerAuth, only: &Option<String>) -> Attacks {
    let mut out = Attacks::new();
    let fields = [("auth_changed_uid", 0usize), ("auth_changed_v_a", 1), ("auth_changed_v_auth", 2), ("auth_changed_r_pol", 3), ("auth_changed_b_q", 4), ("auth_changed_d_q", 5), ("auth_changed_omega", 6)];
    for (name, which) in fields {
        run_one(&mut out, name, seed, only, &mut |rng| {
            let mut pf = c.pubin.clone();
            let f = mutate_auth_public(&mut pf, which, rng);
            let p1 = note(p1_auth("dishonest_prover_false_public", &pf, &c.wit, &pf, ver), &f);
            let p2 = note(vcatch("honest_proof_tampered_public", || ver(&c.proof, &pf)), &f);
            vec![p1, p2]
        });
    }
    run_one(&mut out, "auth_changed_scope_field", seed, only, &mut |rng| {
        // may stay inside the policy: then a prover can honestly prove the NEW scope (not an attack); only the old proof is tested
        let mut pf = c.pubin.clone();
        let which = below(rng, 8);
        let d = 1 + below(rng, 50) as u64;
        let name = match which {
            0 => { pf.scope.s.0 += d; "s.0" }
            1 => { pf.scope.s.1 += d; "s.1" }
            2 => { pf.scope.e.0 += d; "e.0" }
            3 => { pf.scope.e.1 += d; "e.1" }
            4 => { pf.scope.t.0 += d; "t.0" }
            5 => { pf.scope.t.1 += d; "t.1" }
            6 => { pf.scope.p += d; "p" }
            _ => { pf.scope.level += d; "level" }
        };
        vec![note(vcatch("honest_proof_tampered_public", || ver(&c.proof, &pf)), name)]
    });
    run_one(&mut out, "auth_scope_outside_policy", seed, only, &mut |rng| {
        // the request scope leaves the policy leaf; the prover must be dishonest
        let l = &c.wit.leaf;
        let mut pf = c.pubin.clone();
        let d = 1 + below(rng, 50) as u64;
        let which = below(rng, 7);
        // t.0 and p.0 cannot go below the leaf's lower bound 0 (unsigned values), so those two cases are not attacks and are left out
        let name = match which {
            0 => { pf.scope.s.0 = l.s.0 - d; "s.0 below S_lo" }
            1 => { pf.scope.s.1 = l.s.1 + d; "s.1 above S_hi" }
            2 => { pf.scope.e.0 = l.e.0.saturating_sub(d).min(l.e.0 - 1); "e.0 below E_lo" }
            3 => { pf.scope.e.1 = l.e.1 + d; "e.1 above E_hi" }
            4 => { pf.scope.t.1 = l.t.1 + d; "t.1 above T_hi" }
            5 => { pf.scope.p = l.p.1 + d; "p above P_hi" }
            _ => { pf.scope.level = l.level + d; "level above level_a" }
        };
        let p1 = note(p1_auth("dishonest_prover", &pf, &c.wit, &pf, ver), name);
        let p2 = note(vcatch("honest_proof_tampered_public", || ver(&c.proof, &pf)), name);
        vec![p1, p2]
    });
    run_one(&mut out, "auth_wrong_sibling", seed, only, &mut |rng| {
        let mut w2 = c.wit.clone();
        let i = below(rng, w2.siblings.len());
        let j = below(rng, 4);
        w2.siblings[i][j] = fadd(w2.siblings[i][j], delta(rng));
        let p1 = note(p1_auth("dishonest_prover", &c.pubin, &w2, &c.pubin, ver), &format!("sibling {i}"));
        let mut pf = c.pubin.clone();
        pf.r_pol = root_of::<Val, _>(&c1::perm(), &w2.leaf, w2.index, &w2.siblings);
        let p2 = vcatch("honest_proof_root_of_other_path", || ver(&c.proof, &pf));
        vec![p1, p2]
    });
    run_one(&mut out, "auth_wrong_leaf_index", seed, only, &mut |rng| {
        let mut w2 = c.wit.clone();
        w2.index ^= 1u64 << below(rng, AUTH_DEPTH);
        let p1 = p1_auth("dishonest_prover", &c.pubin, &w2, &c.pubin, ver);
        let mut pf = c.pubin.clone();
        pf.r_pol = root_of::<Val, _>(&c1::perm(), &w2.leaf, w2.index, &w2.siblings);
        let p2 = vcatch("honest_proof_root_of_other_index", || ver(&c.proof, &pf));
        vec![p1, p2]
    });
    run_one(&mut out, "auth_wrong_leaf_uid", seed, only, &mut |rng| {
        // witness leaf of another user: public uid unchanged, root unchanged
        let mut w2 = c.wit.clone();
        w2.leaf.uid += 1 + below(rng, 1000) as u64;
        vec![p1_auth("dishonest_prover", &c.pubin, &w2, &c.pubin, ver)]
    });
    run_one(&mut out, "auth_changed_depth", seed, only, &mut |rng| {
        let mut pf = c.pubin.clone();
        pf.depth = if below(rng, 2) == 0 { pf.depth + 1 } else { pf.depth - 1 };
        vec![vcatch("honest_proof_other_depth", || ver(&c.proof, &pf))]
    });
    run_one(&mut out, "auth_other_request_proof", seed, only, &mut |_| {
        vec![vcatch("proof_of_other_request", || ver(&c.other_proof, &c.pubin))]
    });
    run_one(&mut out, "auth_flipped_proof_byte", seed, only, &mut |rng| {
        vec![flip_variant("flip", &c.bytes, rng, |p| ver(p, &c.pubin))]
    });
    let rows = plain::auth_rows(c.pubin.depth);
    run_one(&mut out, "auth_weaker_options_below_floor", seed, only, &mut |rng| {
        let q = [5usize, 10, 15, 20][below(rng, 4)];
        match catch(|| plain::prove_auth(&o_q(q), &c.pubin, &c.wit)) {
            Err(m) => vec![refused("weak_prover", m)],
            Ok(Err(e)) => vec![refused("weak_prover", e)],
            Ok(Ok(p)) => {
                let n = bits_note(q, rows);
                vec![note(vcatch("strict_options", || ver(&p, &c.pubin)), &n)]
            }
        }
    });
    out
}

// ================================================================================================ w34: bundle form (Auth + Exec + RC), native checks

/// The bundle is verified with `verify_bundle_with(nc, ...)`: nc = ON is the production verifier (`request::verify_bundle`),
/// nc = OFF switches the two w34 native checks (stream link C1, scope order C2) off. OFF exists only here, to show that the checks matter.
struct BundleCase {
    a: AuthCase,
    epub: ExecPublic,
    pe: Pf,
    rpub: RcPublic,
    pr: Pf,
    /// stream B (same shape, other data): honest R_Exec statement and proof
    epub_b: ExecPublic,
    pe_b: Pf,
}

fn bundle_case(n_q: usize, seed: u64) -> Result<BundleCase, String> {
    let a = auth_case(AUTH_DEPTH, seed)?;
    let mut r = Rng::new(seed ^ 0x2222);
    let wseed = r.next_u64();
    let theta = rnd_theta(&mut r);
    let w = Workload::synthetic(n_q, BLOCK, wseed);
    let ctx = ctx_of(&a.pubin);
    let epub = c1::public_for(&w, theta, ctx);
    let pe = plain::prove_exec(&o(), &w, &epub)?;
    let rpub = rc_pub_of(&w);
    let pr = rc_prove(&o(), &w, &rpub)?;
    let wb = Workload::synthetic(n_q, BLOCK, wseed ^ 0x5eed_0004);
    let epub_b = c1::public_for(&wb, theta, ctx);
    let pe_b = plain::prove_exec(&o(), &wb, &epub_b)?;
    Ok(BundleCase { a, epub, pe, rpub, pr, epub_b, pe_b })
}

fn bundle_ver(nc: NativeChecks, pa: &Pf, ap: &AuthPublic, pe: &Pf, ep: &ExecPublic, pr: &Pf, rp: &RcPublic) -> Result<(), String> {
    verify_bundle_with(nc, &o(), pa, ap, pe, ep, pr, rp, RID)
}

/// The two w34 attacks. Each closure returns the variants "checks_on" (production verifier) and "checks_off" (native checks off);
/// the caller sends the two kinds of variants to two different result files.
fn bundle_suite(c: &BundleCase, seed: u64, only: &Option<String>) -> Attacks {
    let mut out = Attacks::new();
    // stream_mismatch: honest R_RC proof of stream A + honest R_Exec proof of stream B (same shape), the Auth proof and the C_Q link honest
    run_one(&mut out, "stream_mismatch", seed, only, &mut |_| {
        let on = vcatch("checks_on", || bundle_ver(NativeChecks::ON, &c.a.proof, &c.a.pubin, &c.pe_b, &c.epub_b, &c.pr, &c.rpub));
        let off = vcatch("checks_off", || bundle_ver(NativeChecks::OFF, &c.a.proof, &c.a.pubin, &c.pe_b, &c.epub_b, &c.pr, &c.rpub));
        vec![on, off]
    });
    // inverted_scope: honest proofs of a statement whose scope has start > end (one of the ranges s, e, t, chosen at random, with both
    // ends inside the policy leaf so that the honest prover can prove it), Exec and RC honest
    run_one(&mut out, "inverted_scope", seed, only, &mut |rng| {
        let l = &c.a.wit.leaf;
        let mut pf = c.a.pubin.clone();
        let which = below(rng, 3);
        let (lo, hi) = match which {
            0 => l.s,
            1 => l.e,
            _ => l.t,
        };
        // two distinct values a < b inside [lo, hi]; the statement gets (b, a)
        let span = hi - lo + 1;
        let x = lo + (rng.next_u64() % span);
        let mut y = lo + (rng.next_u64() % span);
        if y == x {
            y = if x < hi { x + 1 } else { x - 1 };
        }
        let (a_, b_) = (x.min(y), x.max(y));
        let name = match which {
            0 => {
                pf.scope.s = (b_, a_);
                "s"
            }
            1 => {
                pf.scope.e = (b_, a_);
                "e"
            }
            _ => {
                pf.scope.t = (b_, a_);
                "t"
            }
        };
        match catch(|| plain::prove_auth(&o(), &pf, &c.a.wit)) {
            Err(m) => vec![refused("checks_on", format!("prover panicked: {m}")), refused("checks_off", format!("prover panicked: {m}"))],
            Ok(Err(e)) => vec![refused("checks_on", e.clone()), refused("checks_off", e)],
            Ok(Ok(proof)) => {
                let on = note(vcatch("checks_on", || bundle_ver(NativeChecks::ON, &proof, &pf, &c.pe, &c.epub, &c.pr, &c.rpub)), &format!("inverted range {name}"));
                let off = note(vcatch("checks_off", || bundle_ver(NativeChecks::OFF, &proof, &pf, &c.pe, &c.epub, &c.pr, &c.rpub)), &format!("inverted range {name}"));
                vec![on, off]
            }
        }
    });
    out
}

// ================================================================================================ driver

#[derive(Clone)]
struct Cfg {
    out: String,
    attack_trials: usize,
    honest_trials: usize,
    n20k: usize,
    n50k: usize,
    h20k: usize,
    h50k: usize,
    forms: Vec<String>,
    max_min: f64,
    only: Option<String>,
    seed_base: u64,
}

fn argv(args: &[String], key: &str) -> Option<String> {
    args.iter().find_map(|a| a.strip_prefix(&format!("{key}=")).map(|s| s.to_string()))
}
fn argn(args: &[String], key: &str, d: usize) -> usize {
    argv(args, key).map(|s| s.parse().unwrap()).unwrap_or(d)
}

/// sizes for `n` trials: `n50` of 50000, `n20` of 20000, the rest 5000, spread evenly (same as w30)
fn nq_plan(n: usize, n20: usize, n50: usize) -> Vec<usize> {
    let mut v = vec![5000usize; n];
    let spread = |v: &mut Vec<usize>, cnt: usize, val: usize, off: usize| {
        for t in 0..cnt {
            let pos = (off + t * n / cnt.max(1)) % n;
            let mut p = pos;
            while v[p] != 5000 {
                p = (p + 1) % n;
            }
            v[p] = val;
        }
    };
    spread(&mut v, n50, 50000, n / 3);
    spread(&mut v, n20, 20000, 1);
    v
}

fn form_enabled(cfg: &Cfg, f: &str) -> bool {
    cfg.forms.iter().any(|x| x == f)
}

fn emit_attacks(sink: &mut Sink, form: &str, n_q: usize, seed: u64, a: Attacks) {
    for (name, vs) in a {
        sink.emit(&name, form, n_q, seed, vs);
    }
}

fn honest_row(sink: &mut Sink, form: &str, n_q: usize, seed: u64, variant: &str, r: Result<(), String>, extra: &str) {
    let v = match r {
        Ok(()) => V { variant: variant.into(), out: Out::Accepted, text: format!("honest verified; {extra}") },
        Err(e) => V { variant: variant.into(), out: Out::Rejected, text: format!("HONEST REJECTED: {e}; {extra}") },
    };
    sink.emit("honest", form, n_q, seed, vec![v]);
}

fn vcatch_r(f: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
    match catch(f) {
        Ok(r) => r,
        Err(m) => Err(format!("harness panic {m}")),
    }
}

fn cmd_run(args: &[String]) {
    let cfg = Cfg {
        out: argv(args, "out").unwrap_or_else(|| "results/attack-w38-old".into()),
        attack_trials: argn(args, "attack_trials", 20),
        honest_trials: argn(args, "honest_trials", 50),
        n20k: argn(args, "n20k", 4),
        n50k: argn(args, "n50k", 1),
        h20k: argn(args, "h20k", 5),
        h50k: argn(args, "h50k", 2),
        forms: argv(args, "forms").unwrap_or_else(|| "exec_single,rc_single,pair,bundle".into()).split(',').map(|s| s.to_string()).collect(),
        max_min: argv(args, "max_min").map(|s| s.parse().unwrap()).unwrap_or(1e9),
        only: argv(args, "only"),
        seed_base: argn(args, "seed_base", 30000) as u64,
    };
    std::fs::create_dir_all(&cfg.out).unwrap();
    let tag = argv(args, "tag").map(|t| format!("-{t}")).unwrap_or_default();
    let path = format!("{}/raw-{HASH_NAME}{tag}.csv", cfg.out);
    let mut file = std::fs::File::create(&path).unwrap();
    writeln!(file, "{RAW_HEADER}").unwrap();
    let mut sink = Sink { file, n_rows: 0 };
    // rows of the w34 forms with the native checks OFF (separate file, merged separately, never counted in the totals with the checks on)
    let path_off = format!("{}/raw-{HASH_NAME}-nochecks{tag}.csv", cfg.out);
    let mut file_off = std::fs::File::create(&path_off).unwrap();
    writeln!(file_off, "{RAW_HEADER}").unwrap();
    let mut sink_off = Sink { file: file_off, n_rows: 0 };
    std::panic::set_hook(Box::new(|_| {}));
    let t0 = Instant::now();
    let over = |t0: &Instant| t0.elapsed().as_secs_f64() / 60.0 > cfg.max_min;
    let op = o();
    eprintln!("hash={HASH_NAME} queries={} log_blowup={} grind={} out={path}", op.num_queries, op.log_blowup, op.query_pow_bits);

    // ---------------- honest-only trials
    let hp = nq_plan(cfg.honest_trials, cfg.h20k, cfg.h50k);
    for (idx, &n_q) in hp.iter().enumerate() {
        if over(&t0) {
            eprintln!("time cap reached in honest trials at {idx}");
            break;
        }
        let seed = cfg.seed_base + 10_000 + idx as u64;
        if form_enabled(&cfg, "exec_single") {
            let r = catch(|| -> Result<(), String> {
                let mut g = Rng::new(seed);
                let w = Workload::synthetic(n_q, BLOCK, g.next_u64());
                let theta = rnd_theta(&mut g);
                let ctx = rnd_ctx(&mut g);
                let pubin = c1::public_for(&w, theta, ctx);
                let p = plain::prove_exec(&o(), &w, &pubin)?;
                let p = parse(&c1::to_bytes(&p))?;
                plain::verify_exec(&o(), &p, &pubin)
            });
            honest_row(&mut sink, "exec_single", n_q, seed, "serialise_parse_verify", r.unwrap_or_else(|m| Err(format!("harness panic {m}"))), "");
        }
        if form_enabled(&cfg, "rc_single") {
            let r = catch(|| -> Result<(), String> {
                let mut g = Rng::new(seed);
                let w = Workload::synthetic(n_q, BLOCK, g.next_u64());
                let pubin = rc_pub_of(&w);
                let p = rc_prove(&o(), &w, &pubin)?;
                let p = parse(&c1::to_bytes(&p))?;
                plain::verify_rc(&o(), &p, &pubin)
            });
            honest_row(&mut sink, "rc_single", n_q, seed, "serialise_parse_verify", r.unwrap_or_else(|m| Err(format!("harness panic {m}"))), "");
        }
        if form_enabled(&cfg, "pair") {
            let r = catch(|| -> Result<(), String> {
                let mut g = Rng::new(seed);
                let depth = [6usize, 10, 14][below(&mut g, 3)];
                let (ap, aw) = honest_auth_instance::<Val, _>(&c1::perm(), depth, g.next_u64());
                let ap_proof = parse(&c1::to_bytes(&plain::prove_auth(&o(), &ap, &aw)?))?;
                let w = Workload::synthetic(n_q, BLOCK, g.next_u64());
                let theta = rnd_theta(&mut g);
                let epub = c1::public_for(&w, theta, ctx_of(&ap));
                let ep = plain::prove_exec(&o(), &w, &epub)?;
                let ep = parse(&c1::to_bytes(&ep))?;
                verify_request(&o(), &ap_proof, &ap, &ep, &epub, RID)
            });
            honest_row(&mut sink, "pair", n_q, seed, "serialise_parse_verify_both", r.unwrap_or_else(|m| Err(format!("harness panic {m}"))), "auth depth random {6,10,14}");
        }
        if form_enabled(&cfg, "bundle") {
            let r = catch(|| -> Result<(), String> {
                let mut g = Rng::new(seed);
                let depth = [6usize, 10, 14][below(&mut g, 3)];
                let (ap, aw) = honest_auth_instance::<Val, _>(&c1::perm(), depth, g.next_u64());
                let pa = parse(&c1::to_bytes(&plain::prove_auth(&o(), &ap, &aw)?))?;
                let w = Workload::synthetic(n_q, BLOCK, g.next_u64());
                let theta = rnd_theta(&mut g);
                let epub = c1::public_for(&w, theta, ctx_of(&ap));
                let pe = parse(&c1::to_bytes(&plain::prove_exec(&o(), &w, &epub)?))?;
                let rpub = rc_pub_of(&w);
                let pr = parse(&c1::to_bytes(&rc_prove(&o(), &w, &rpub)?))?;
                bundle_ver(NativeChecks::ON, &pa, &ap, &pe, &epub, &pr, &rpub)
            });
            honest_row(&mut sink, "bundle", n_q, seed, "serialise_parse_verify_bundle", r.unwrap_or_else(|m| Err(format!("harness panic {m}"))), "auth depth random {6,10,14}; checks on");
        }
        eprintln!("[{:6.1}s] honest {}/{} n_q={n_q}", t0.elapsed().as_secs_f64(), idx + 1, hp.len());
    }

    // ---------------- attack trials
    let ap = nq_plan(cfg.attack_trials, cfg.n20k, cfg.n50k);
    for (idx, &n_q) in ap.iter().enumerate() {
        if over(&t0) {
            eprintln!("time cap reached before attack instance {idx}");
            break;
        }
        let seed = cfg.seed_base + idx as u64;
        if form_enabled(&cfg, "exec_single") {
            match catch(|| exec_case(n_q, seed, None, None)) {
                Ok(Ok(c)) => {
                    honest_row(&mut sink, "exec_single", n_q, seed, "attack_instance_honest", vcatch_r(|| exec_ver_direct(&c.proof, &c.pubin)), "");
                    let a = exec_suite(&c, seed, &exec_ver_direct, &cfg.only);
                    emit_attacks(&mut sink, "exec_single", n_q, seed, a);
                }
                Ok(Err(e)) => sink.emit("setup", "exec_single", n_q, seed, vec![herr("setup", e)]),
                Err(m) => sink.emit("setup", "exec_single", n_q, seed, vec![herr("setup", m)]),
            }
        }
        if form_enabled(&cfg, "rc_single") {
            match catch(|| rc_case(n_q, seed)) {
                Ok(Ok(c)) => {
                    let ver = |p: &Pf, q: &RcPublic| plain::verify_rc(&o(), p, q);
                    honest_row(&mut sink, "rc_single", n_q, seed, "attack_instance_honest", vcatch_r(|| ver(&c.proof, &c.pubin)), "");
                    let a = rc_suite(&c, seed, &ver, &cfg.only);
                    emit_attacks(&mut sink, "rc_single", n_q, seed, a);
                }
                Ok(Err(e)) => sink.emit("setup", "rc_single", n_q, seed, vec![herr("setup", e)]),
                Err(m) => sink.emit("setup", "rc_single", n_q, seed, vec![herr("setup", m)]),
            }
        }
        if form_enabled(&cfg, "pair") {
            let r = catch(|| -> Result<(AuthCase, ExecCase, AuthCase), String> {
                // request 1 and a second request (for the mix-and-match probes)
                let a1 = auth_case(AUTH_DEPTH, seed)?;
                let a2 = auth_case(AUTH_DEPTH, seed ^ 0x77)?;
                // Exec context of each request = exec_context(B_Q, Auth_Q, RID_Q) of ITS Auth statement
                let e1 = exec_case(n_q, seed ^ 0x1111, Some(ctx_of(&a1.pubin)), Some(ctx_of(&a2.pubin)))?;
                Ok((a1, e1, a2))
            });
            match r {
                Ok(Ok((a1, e1, a2))) => {
                    let n_form = "pair";
                    // Every pair check is `verify_request` (ctx binding, then Auth proof, then Exec proof; strict options).
                    // exec half attacked, auth half honest. The tag "[exec alone: ...]" says what the stand-alone
                    // `verify_exec` says about the same input (so a rejection by the binding check does not hide the STARK result).
                    let tag = |ok: bool| if ok { "accepted" } else { "rejected" };
                    let ver_e = |p: &Pf, q: &ExecPublic| -> Result<(), String> {
                        let alone = exec_ver_direct(p, q).is_ok();
                        verify_request(&o(), &a1.proof, &a1.pubin, p, q, RID).map_err(|e| format!("{e} [exec alone: {}]", tag(alone)))
                    };
                    let ver_a = |p: &Pf, q: &AuthPublic| -> Result<(), String> {
                        let alone = plain::verify_auth(&o(), p, q).is_ok();
                        verify_request(&o(), p, q, &e1.proof, &e1.pubin, RID).map_err(|e| format!("{e} [auth alone: {}]", tag(alone)))
                    };
                    let hon = vcatch_r(|| ver_e(&e1.proof, &e1.pubin));
                    honest_row(&mut sink, n_form, n_q, seed, "attack_instance_honest", hon, "exec ctx = exec_context(b_q, d_q, 0)");
                    let mut a = exec_suite(&e1, seed, &ver_e, &cfg.only);
                    a.extend(auth_suite(&a1, seed, &ver_a, &cfg.only));
                    // mix-and-match through verify_request (the library check must catch it; no harness-side link check)
                    let mut mix = Attacks::new();
                    run_one(&mut mix, "mix_exec_of_other_request", seed, &cfg.only, &mut |_| {
                        vec![vcatch("verify_request_auth1_exec2", || ver_e(&e1.other_proof, &e1.other_pub))]
                    });
                    run_one(&mut mix, "mix_auth_of_other_request", seed, &cfg.only, &mut |_| {
                        vec![vcatch("verify_request_auth2_exec1", || verify_request(&o(), &a2.proof, &a2.pubin, &e1.proof, &e1.pubin, RID))]
                    });
                    a.extend(mix);
                    emit_attacks(&mut sink, n_form, n_q, seed, a);
                }
                Ok(Err(e)) => sink.emit("setup", "pair", n_q, seed, vec![herr("setup", e)]),
                Err(m) => sink.emit("setup", "pair", n_q, seed, vec![herr("setup", m)]),
            }
        }
        if form_enabled(&cfg, "bundle") {
            match catch(|| bundle_case(n_q, seed)) {
                Ok(Ok(c)) => {
                    honest_row(&mut sink, "bundle", n_q, seed, "attack_instance_honest", vcatch_r(|| bundle_ver(NativeChecks::ON, &c.a.proof, &c.a.pubin, &c.pe, &c.epub, &c.pr, &c.rpub)), "checks on");
                    honest_row(&mut sink_off, "bundle", n_q, seed, "attack_instance_honest_checks_off", vcatch_r(|| bundle_ver(NativeChecks::OFF, &c.a.proof, &c.a.pubin, &c.pe, &c.epub, &c.pr, &c.rpub)), "checks off");
                    for (name, vs) in bundle_suite(&c, seed, &cfg.only) {
                        let (on, off): (Vec<V>, Vec<V>) = vs.into_iter().partition(|v| v.variant != "checks_off");
                        sink.emit(&name, "bundle", n_q, seed, on);
                        sink_off.emit(&name, "bundle", n_q, seed, off);
                    }
                }
                Ok(Err(e)) => sink.emit("setup", "bundle", n_q, seed, vec![herr("setup", e)]),
                Err(m) => sink.emit("setup", "bundle", n_q, seed, vec![herr("setup", m)]),
            }
        }
        eprintln!("[{:6.1}s] attack instance {}/{} n_q={n_q} rows={}", t0.elapsed().as_secs_f64(), idx + 1, ap.len(), sink.n_rows);
    }
    eprintln!("done in {:.1} s, rows {} (+ {} rows with the native checks off)", t0.elapsed().as_secs_f64(), sink.n_rows, sink_off.n_rows);
}

// ================================================================================================ merge + summary (as w30)

#[derive(Default, Clone)]
struct Agg {
    trials: usize,
    rejected: usize,
    accepted: usize,
    prover_refused: usize,
    harness_error: usize,
    untested: usize,
    verifier_panics: usize,
    n5k: usize,
    n20k: usize,
    n50k: usize,
}

fn split_csv(line: &str) -> Vec<String> {
    // fields: error is quoted and has no commas (clean())
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inq = false;
    for ch in line.chars() {
        match ch {
            '"' => inq = !inq,
            ',' if !inq => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    out.push(cur);
    out
}

fn cmd_merge(dir: &str) {
    let mut files: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().to_string()))
        .filter(|n| n.starts_with("raw-") && n.ends_with(".csv"))
        .collect();
    files.sort();
    let (off, on): (Vec<String>, Vec<String>) = files.into_iter().partition(|n| n.contains("-nochecks"));
    merge_files(dir, &on, "");
    if !off.is_empty() {
        merge_files(dir, &off, "_nochecks");
    }
}

fn merge_files(dir: &str, files: &[String], sfx: &str) {
    let mut lines: Vec<String> = Vec::new();
    for f in files {
        let p = format!("{dir}/{f}");
        if let Ok(s) = std::fs::read_to_string(&p) {
            for (i, l) in s.lines().enumerate() {
                if i == 0 || l.is_empty() {
                    continue;
                }
                lines.push(l.to_string());
            }
        } else {
            eprintln!("missing {p}");
        }
    }
    let mut raw = format!("{RAW_HEADER}\n");
    for l in &lines {
        raw.push_str(l);
        raw.push('\n');
    }
    std::fs::write(format!("{dir}/raw{sfx}.csv"), raw).unwrap();
    // trial verdicts: key (attack, form, hash, seed) -> outcomes
    use std::collections::BTreeMap;
    let mut trials: BTreeMap<(String, String, String, u64), (usize, Vec<String>, u32)> = BTreeMap::new();
    for l in &lines {
        let f = split_csv(l);
        let key = (f[0].clone(), f[1].clone(), f[2].clone(), f[4].parse::<u64>().unwrap());
        let e = trials.entry(key).or_insert((f[3].parse().unwrap(), vec![], 0));
        e.1.push(f[5].clone());
        e.2 += f[8].parse::<u32>().unwrap();
    }
    let mut agg: BTreeMap<(String, String, String), Agg> = BTreeMap::new();
    for ((attack, form, hash, _seed), (n_q, outs, vp)) in &trials {
        let a = agg.entry((attack.clone(), form.clone(), hash.clone())).or_default();
        a.trials += 1;
        match *n_q {
            5000 => a.n5k += 1,
            20000 => a.n20k += 1,
            50000 => a.n50k += 1,
            _ => {}
        }
        let has = |s: &str| outs.iter().any(|o| o == s);
        if has("accepted") {
            a.accepted += 1;
        } else if has("harness_error") {
            a.harness_error += 1;
        } else if has("rejected") {
            a.rejected += 1;
        } else {
            a.untested += 1;
        }
        if has("prover_refused") {
            a.prover_refused += 1;
        }
        a.verifier_panics += *vp as usize;
    }
    let mut s = String::from("attack,form,hash,trials,rejected,accepted,prover_refused,harness_error,untested,verifier_panic_rows,trials_n5000,trials_n20000,trials_n50000\n");
    for ((attack, form, hash), a) in &agg {
        s.push_str(&format!("{attack},{form},{hash},{},{},{},{},{},{},{},{},{},{}\n", a.trials, a.rejected, a.accepted, a.prover_refused, a.harness_error, a.untested, a.verifier_panics, a.n5k, a.n20k, a.n50k));
    }
    std::fs::write(format!("{dir}/summary{sfx}.csv"), s).unwrap();
    // per-variant counts (each variant is one verifier call): shows which check caught what
    let mut var: BTreeMap<(String, String, String, String), [usize; 4]> = BTreeMap::new();
    for l in &lines {
        let f = split_csv(l);
        let e = var.entry((f[0].clone(), f[1].clone(), f[2].clone(), f[7].clone())).or_default();
        match f[5].as_str() {
            "accepted" => e[0] += 1,
            "rejected" => e[1] += 1,
            "prover_refused" => e[2] += 1,
            "untested" => {}
            _ => e[3] += 1,
        }
    }
    let mut sv = String::from("attack,form,hash,variant,accepted,rejected,prover_refused,harness_error\n");
    for ((a, f, h, v), c) in &var {
        sv.push_str(&format!("{a},{f},{h},{v},{},{},{},{}\n", c[0], c[1], c[2], c[3]));
    }
    std::fs::write(format!("{dir}/summary_variants{sfx}.csv"), sv).unwrap();
    eprintln!("merged{sfx} {} raw rows, {} summary rows", lines.len(), agg.len());
}

fn cmd_probe() {
    let w = Workload::synthetic(1000, BLOCK, 1);
    let rows = c1::n_rows(w.n_words());
    for q in [5usize, 10, 15, 20, 25, 30, 35, 40] {
        println!("{}", bits_note(q, rows));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("run") if args.iter().any(|a| a == "fmt=p2r") => p2r::cmd_run_p(&args[1..]),
        Some("run") => cmd_run(&args[1..]),
        Some("merge") => cmd_merge(&args[1]),
        Some("probe") => cmd_probe(),
        _ => eprintln!("usage: attack run|merge DIR|probe  (see the header of src/main.rs)"),
    }
}
