//! w38: the attack test of the PACKED format P2r (two records per absorbed word; Exec proof without the v range check; the chunk / RC proofs
//! range-check v < 2^32 and b < 2^20). Child module of `main.rs` (uses its private helpers: outcome plumbing, rng helpers, Auth suite, merge).
//!
//! Same families, plan, seeds and outcome classes as the w36 harness. What differs:
//!  - the stream is the PACKED stream (`pair::pack_workload`); forging a record word means forging the packed word (either half);
//!  - the verifier is the one the P2r request / bundle verification uses: stream link (`check_stream_link_p`), sealed check (`check_sealed`
//!    against the AA's own lists), Exec proof (`verify_pair`, P2r), one chunk / RC proof per chunk (`pchunk::verify_chunk`), and for the
//!    forms with an Auth proof the C_Q link and scope check (`prequest::verify_bundle_p`). Forms:
//!      exec_single : Exec attacked, chunk proofs / statements / lists of the original stream honest (no Auth, so no C_Q link)
//!      rc_single   : one chunk (RC) proof attacked, Exec proof honest
//!      pair        : Auth + Exec + chunks through `verify_bundle_p` (Exec attacked, Auth attacked, mix-and-match)
//!      bundle      : stream_mismatch and inverted_scope, checks ON and OFF (OFF rows are not counted)
//!      packed      : the six packed-specific attacks (family "packed"), full bundle verification
//!  - each variant text starts with a short diagnostic `[exec alone: acc|rej; rc alone: acc|rej]` where useful: what the STARK check alone says
//!    about the same input, so that a rejection by a native check (link, lists) does not hide the STARK result.

use super::*;
use pqz_plonky3_w38::air::{native_digest, Layout};
use pqz_plonky3_w38::chunk::{state_after, ChunkLists, RcChunkPublic};
use pqz_plonky3_w38::pair::{honest_kinds, pack_workload, pair_air, pair_n_rows, pair_n_words, pair_public, pair_values, prove_pair_kinds, prove_pair_words, rows_per_block, verify_pair, Fmt, Kind};
use pqz_plonky3_w38::pchunk::{check_sealed, pc_n_words, plain as pc};
use pqz_plonky3_w38::prequest::{check_stream_link_p, verify_bundle_p};

/// the format under test
const FMT: Fmt = Fmt::P2r;
const BLOCK_ODD: usize = 99;
type Words = Vec<Vec<u64>>;

fn untested(variant: &str, text: &str) -> V {
    V { variant: variant.into(), out: Out::Untested, text: text.into() }
}

// ------------------------------------------------------------------------------------------------ cases

/// An honest packed stream with its Exec proof (P2r) and its chunk / RC proofs (one chunk with all blocks, unless `c_blocks` says otherwise).
struct PCase {
    w: Workload,
    words: Words,
    bsz: usize,
    epub: ExecPublic,
    pe: Pf,
    bytes: Vec<u8>,
    cps: Vec<RcChunkPublic>,
    lists: Vec<ChunkLists>,
    prs: Vec<Pf>,
    rc_bytes: Vec<u8>,
}

fn build_chunks(words: &Words, bsz: usize, n_blocks: usize, c: usize) -> Result<(Vec<RcChunkPublic>, Vec<ChunkLists>, Vec<Pf>), String> {
    let (cps, lists) = pc::honest_publics(words, bsz, c.clamp(1, n_blocks));
    let rpw = rows_per_block(bsz);
    let mut first = 0;
    let mut prs = Vec::new();
    for p in &cps {
        prs.push(pc::prove_chunk(&o(), &words[first * rpw..(first + p.n_blocks_chunk) * rpw], p)?);
        first += p.n_blocks_chunk;
    }
    Ok((cps, lists, prs))
}

fn pcase(n_q: usize, bsz: usize, wseed: u64, theta: u64, ctx: [u64; 4], c_blocks: Option<usize>) -> Result<PCase, String> {
    let w = Workload::synthetic(n_q, bsz, wseed);
    let words = pack_workload(&w);
    let epub = pair_public(&w, theta, ctx);
    let pe = prove_pair_words(&o(), &words, &epub, FMT)?;
    let bytes = c1::to_bytes(&pe);
    let (cps, lists, prs) = build_chunks(&words, bsz, w.n_blocks, c_blocks.unwrap_or(w.n_blocks))?;
    let rc_bytes = c1::to_bytes(&prs[0]);
    Ok(PCase { w, words, bsz, epub, pe, bytes, cps, lists, prs, rc_bytes })
}

fn roundtrip(p: &Pf) -> Result<Pf, String> {
    parse(&c1::to_bytes(p))
}

// ------------------------------------------------------------------------------------------------ the verifiers

fn acc_rej(r: &Result<(), String>) -> &'static str {
    if r.is_ok() {
        "acc"
    } else {
        "rej"
    }
}

/// Exec proof + chunk / RC proofs + stream link + sealed check (no Auth). `nc.link` switches link and sealed check.
fn ver_x(nc: NativeChecks, pe: &Pf, ep: &ExecPublic, prs: &[Pf], cps: &[RcChunkPublic], lists: &[ChunkLists]) -> Result<(), String> {
    if prs.len() != cps.len() {
        return Err("link: one proof per chunk statement required".into());
    }
    if nc.link {
        check_stream_link_p(ep, cps)?;
        if lists.len() != cps.len() {
            return Err("lists: one list per chunk required".into());
        }
        for (p, l) in cps.iter().zip(lists) {
            check_sealed::<Val>(p, l)?;
        }
    }
    verify_pair(&o(), pe, ep, FMT).map_err(|e| format!("exec: {e}"))?;
    for (i, (pr, p)) in prs.iter().zip(cps).enumerate() {
        pc::verify_chunk(&o(), pr, p).map_err(|e| format!("rc[{i}]: {e}"))?;
    }
    Ok(())
}

fn exec_alone(pe: &Pf, ep: &ExecPublic) -> Result<(), String> {
    verify_pair(&o(), pe, ep, FMT)
}
fn rc_alone(prs: &[Pf], cps: &[RcChunkPublic]) -> Result<(), String> {
    for (pr, p) in prs.iter().zip(cps) {
        pc::verify_chunk(&o(), pr, p)?;
    }
    if prs.len() != cps.len() {
        return Err("count".into());
    }
    Ok(())
}
fn diag(pe: &Pf, ep: &ExecPublic, prs: &[Pf], cps: &[RcChunkPublic]) -> String {
    format!("[exec alone: {}; rc alone: {}]", acc_rej(&exec_alone(pe, ep)), acc_rej(&rc_alone(prs, cps)))
}

// ------------------------------------------------------------------------------------------------ packed stream helpers

fn ref_packed(words: &Words, bsz: usize, theta: u64) -> (u64, u64) {
    let rpw = rows_per_block(bsz);
    let nrec = (bsz + 1) / 2;
    let (mut cnt, mut sum) = (0u64, 0u64);
    for (k, w) in words.iter().enumerate() {
        let pos = k % rpw;
        if pos == 0 {
            continue;
        }
        if w[1] >= theta {
            cnt += 1;
            sum += w[2];
        }
        if !(pos == nrec && bsz % 2 == 1) && w[5] >= theta {
            cnt += 1;
            sum += w[6];
        }
    }
    (cnt, sum)
}

/// statement of an arbitrary (possibly forged) packed stream: digest, count and sum of THOSE words, everything else as `base`
fn pub_of_words(base: &ExecPublic, words: &Words) -> ExecPublic {
    let lay0 = Layout::new(0, 12, 0);
    let digest = native_digest::<Val, 12, _>(&lay0, &c1::perm(), words);
    let (cnt, sum) = ref_packed(words, base.block_size, base.theta);
    let mut p = base.clone();
    p.digest = digest;
    p.count = cnt;
    p.sum = vec![sum];
    p
}

fn rh(bsz: usize, g: usize, k: usize) -> (usize, usize) {
    (g * rows_per_block(bsz) + 1 + k / 2, k % 2)
}
fn get_rec(w: &Words, bsz: usize, g: usize, k: usize) -> [u64; 4] {
    let (row, half) = rh(bsz, g, k);
    let mut r = [0u64; 4];
    r.copy_from_slice(&w[row][4 * half..4 * half + 4]);
    r
}
fn set_rec(w: &mut Words, bsz: usize, g: usize, k: usize, r: [u64; 4]) {
    let (row, half) = rh(bsz, g, k);
    w[row][4 * half..4 * half + 4].copy_from_slice(&r);
}

/// the five stream attacks on the PACKED words (a record is a half word [id, v, b, tag])
fn mutate_p(words: &Words, bsz: usize, nb: usize, kind: &str, r: &mut Rng) -> Words {
    let mut m = words.clone();
    match kind {
        "changed_record_word" => {
            let (g, k) = (below(r, nb), below(r, bsz));
            let (row, half) = rh(bsz, g, k);
            let j = below(r, 4); // id, v, b, tag (pid, epoch, seq are in the header now)
            let s = 4 * half + j;
            let x = m[row][s];
            m[row][s] = match j {
                1 => x ^ (1u64 << below(r, 32)),
                2 => x ^ (1u64 << below(r, 20)),
                _ => fadd(x, delta(r)),
            };
        }
        "dropped_record" => {
            let (g, k) = (below(r, nb), below(r, bsz));
            if below(r, 2) == 0 {
                // the whole packed word (two records) is dropped: the stream gets one row shorter
                let (row, _) = rh(bsz, g, k);
                m.remove(row);
            } else {
                // one record is dropped, the later records of the block move up, the last half is zero: same length
                let mut recs: Vec<[u64; 4]> = (0..bsz).map(|i| get_rec(&m, bsz, g, i)).collect();
                recs.remove(k);
                recs.push([0; 4]);
                for (i, rc) in recs.iter().enumerate() {
                    set_rec(&mut m, bsz, g, i, *rc);
                }
            }
        }
        "duplicated_record" => {
            let (g, k) = (below(r, nb), below(r, bsz));
            if below(r, 2) == 0 {
                let (row, _) = rh(bsz, g, k);
                let x = m[row].clone();
                m.insert(row, x);
            } else {
                let mut recs: Vec<[u64; 4]> = (0..bsz).map(|i| get_rec(&m, bsz, g, i)).collect();
                recs.insert(k, recs[k]);
                recs.truncate(bsz);
                for (i, rc) in recs.iter().enumerate() {
                    set_rec(&mut m, bsz, g, i, *rc);
                }
            }
        }
        "reordered_records" => {
            let pick = |r: &mut Rng| (below(r, nb), below(r, bsz));
            let (g1, k1) = pick(r);
            let mut p2 = pick(r);
            while p2 == (g1, k1) || get_rec(&m, bsz, g1, k1) == get_rec(&m, bsz, p2.0, p2.1) {
                p2 = pick(r);
            }
            let (a, b) = (get_rec(&m, bsz, g1, k1), get_rec(&m, bsz, p2.0, p2.1));
            set_rec(&mut m, bsz, g1, k1, b);
            set_rec(&mut m, bsz, p2.0, p2.1, a);
        }
        "changed_block_header" => {
            let g = below(r, nb);
            let j = below(r, 5); // e, g, m_g, pid, seq_start
            let row = g * rows_per_block(bsz);
            m[row][j] = fadd(m[row][j], delta(r));
        }
        _ => panic!("unknown mutation {kind}"),
    }
    m
}

// ------------------------------------------------------------------------------------------------ single R_Exec (P2r), chunks honest

struct ExecCaseP {
    c: PCase,
    other: PCase,
}

fn exec_case_p(n_q: usize, seed: u64, ctx_fixed: Option<[u64; 4]>, ctx_other: Option<[u64; 4]>) -> Result<ExecCaseP, String> {
    let mut r = Rng::new(seed);
    let wseed = r.next_u64();
    let theta = rnd_theta(&mut r);
    let ctx = ctx_fixed.unwrap_or_else(|| rnd_ctx(&mut r));
    let c = pcase(n_q, BLOCK, wseed, theta, ctx, None)?;
    let ctx2 = ctx_other.unwrap_or_else(|| rnd_ctx(&mut r));
    let other = pcase(n_q, BLOCK, wseed ^ 0x5eed_0002, theta, ctx2, None)?;
    Ok(ExecCaseP { c, other })
}

type VerE<'a> = &'a dyn Fn(&Pf, &ExecPublic) -> Result<(), String>;
type VerC<'a> = &'a dyn Fn(&Pf, &RcChunkPublic) -> Result<(), String>;

fn p1_exec_p(variant: &str, words: &Words, prove_pub: &ExecPublic, ver_pub: &ExecPublic, ver: VerE) -> V {
    match catch(|| prove_pair_words(&o(), words, prove_pub, FMT)) {
        Err(m) => refused(variant, format!("trace build or prover panicked: {m}")),
        Ok(Err(e)) => refused(variant, e),
        Ok(Ok(proof)) => vcatch(variant, || ver(&proof, ver_pub)),
    }
}

fn exec_suite_p(ec: &ExecCaseP, seed: u64, ver: VerE, only: &Option<String>) -> Attacks {
    let c = &ec.c;
    let nb = c.w.n_blocks;
    let mut out = Attacks::new();
    for kind in STREAM_ATTACKS {
        run_one(&mut out, kind, seed, only, &mut |rng| {
            let w2 = mutate_p(&c.words, c.bsz, nb, kind, rng);
            let p1 = p1_exec_p("dishonest_prover", &w2, &c.epub, &c.epub, ver);
            let pub2 = pub_of_words(&c.epub, &w2);
            let p2 = vcatch("honest_proof_other_stream_public", || ver(&c.pe, &pub2));
            let mut v = vec![p1, p2];
            if w2.len() == c.words.len() {
                // a prover that proves the forged stream under its own (consistent) statement; the chunk side stays the AA's honest one
                v.push(match catch(|| prove_pair_words(&o(), &w2, &pub2, FMT)) {
                    Err(m) => refused("consistent_exec_prover_honest_chunks", format!("prover panicked: {m}")),
                    Ok(Err(e)) => refused("consistent_exec_prover_honest_chunks", e),
                    Ok(Ok(pf)) => vcatch("consistent_exec_prover_honest_chunks", || ver(&pf, &pub2)),
                });
            }
            v
        });
    }
    run_one(&mut out, "wrong_claimed_count", seed, only, &mut |rng| {
        let mut pf = c.epub.clone();
        pf.count += 1 + below(rng, 1000) as u64;
        let p1 = p1_exec_p("dishonest_prover", &c.words, &pf, &pf, ver);
        let p2 = vcatch("honest_proof_false_claim", || ver(&c.pe, &pf));
        vec![p1, p2]
    });
    run_one(&mut out, "wrong_claimed_sum", seed, only, &mut |rng| {
        let mut pf = c.epub.clone();
        pf.sum[0] += 1 + below(rng, 1 << 20) as u64;
        let p1 = p1_exec_p("dishonest_prover", &c.words, &pf, &pf, ver);
        let p2 = vcatch("honest_proof_false_claim", || ver(&c.pe, &pf));
        vec![p1, p2]
    });
    run_one(&mut out, "wrong_digest", seed, only, &mut |rng| {
        let mut pf = c.epub.clone();
        let j = below(rng, 4);
        pf.digest[j] = fadd(pf.digest[j], delta(rng));
        vec![vcatch("honest_proof_other_digest", || ver(&c.pe, &pf))]
    });
    run_one(&mut out, "other_workload_proof", seed, only, &mut |_| {
        vec![vcatch("proof_of_other_workload", || ver(&ec.other.pe, &c.epub))]
    });
    run_one(&mut out, "other_theta", seed, only, &mut |rng| {
        let t2 = ((c.epub.theta + 1 + below(rng, 1 << 20) as u64) % (1u64 << 32)).max(1);
        let mut pt = c.epub.clone();
        pt.theta = t2;
        // dishonest prover: the trace is the honest trace of the OTHER theta, the proof is made for the ORIGINAL public statement
        let nw = pair_n_words(c.epub.n_blocks, c.epub.block_size) as u64;
        let p1 = match catch(|| {
            let a = pair_air(c.epub.theta, nw, FMT);
            let a2 = pair_air(t2, nw, FMT);
            let trace = a2.build_trace(&c1::perm(), &c.words, c.bsz);
            p3_uni_stark::prove(&c1::config(&o()), &a, trace, &pair_values(&c.epub)).map_err(|e| format!("{e:?}"))
        }) {
            Err(m) => refused("dishonest_prover_trace_of_other_theta", format!("trace build or prover panicked: {m}")),
            Ok(Err(e)) => refused("dishonest_prover_trace_of_other_theta", e),
            Ok(Ok(proof)) => vcatch("dishonest_prover_trace_of_other_theta", || ver(&proof, &c.epub)),
        };
        let p2 = vcatch("honest_proof_other_theta_public", || ver(&c.pe, &pt));
        vec![p1, p2]
    });
    run_one(&mut out, "other_ctx", seed, only, &mut |rng| {
        let mut pc_ = c.epub.clone();
        let j = below(rng, 4);
        pc_.ctx[j] = fadd(pc_.ctx[j], delta(rng));
        let p1 = p1_exec_p("proof_made_for_other_ctx", &c.words, &pc_, &c.epub, ver);
        let p2 = vcatch("honest_proof_other_ctx_public", || ver(&c.pe, &pc_));
        vec![p1, p2]
    });
    run_one(&mut out, "flipped_proof_byte", seed, only, &mut |rng| {
        vec![flip_variant("flip", &c.bytes, rng, |p| ver(p, &c.epub))]
    });
    let rows = pair_n_rows(pair_n_words(c.epub.n_blocks, c.epub.block_size));
    for (name, qs) in [("weaker_options_below_floor", [5usize, 10, 15, 20]), ("weaker_options_above_floor", [30, 35, 30, 35])] {
        run_one(&mut out, name, seed, only, &mut |rng| {
            let q = qs[below(rng, 4)];
            match catch(|| prove_pair_words(&o_q(q), &c.words, &c.epub, FMT)) {
                Err(m) => vec![refused("weak_prover", m)],
                Ok(Err(e)) => vec![refused("weak_prover", e)],
                Ok(Ok(p)) => {
                    let n = bits_note(q, rows);
                    vec![note(vcatch("strict_options", || ver(&p, &c.epub)), &n)]
                }
            }
        });
    }
    out
}

// ------------------------------------------------------------------------------------------------ single chunk / RC proof (P2r), Exec honest

struct RcCaseP {
    c: PCase,
    other: PCase,
}

fn rc_case_p(n_q: usize, seed: u64) -> Result<RcCaseP, String> {
    let mut r = Rng::new(seed);
    let wseed = r.next_u64();
    let theta = rnd_theta(&mut r);
    let ctx = rnd_ctx(&mut r);
    let c = pcase(n_q, BLOCK, wseed, theta, ctx, None)?;
    let other = pcase(n_q, BLOCK, wseed ^ 0x5eed_0002, theta, ctx, None)?;
    Ok(RcCaseP { c, other })
}

fn p1_rc_p(variant: &str, words: &Words, prove_pub: &RcChunkPublic, ver_pub: &RcChunkPublic, ver: VerC) -> V {
    match catch(|| pc::prove_chunk(&o(), words, prove_pub)) {
        Err(m) => refused(variant, format!("trace build or prover panicked: {m}")),
        Ok(Err(e)) => refused(variant, e),
        Ok(Ok(proof)) => vcatch(variant, || ver(&proof, ver_pub)),
    }
}

fn rc_suite_p(rc: &RcCaseP, seed: u64, ver: VerC, only: &Option<String>) -> Attacks {
    let c = &rc.c;
    let p0 = &c.cps[0];
    let nb = c.w.n_blocks;
    let mut out = Attacks::new();
    for kind in STREAM_ATTACKS {
        run_one(&mut out, kind, seed, only, &mut |rng| {
            let w2 = mutate_p(&c.words, c.bsz, nb, kind, rng);
            let p1 = p1_rc_p("dishonest_prover", &w2, p0, p0, ver);
            // the statement of the forged stream: end state and first header of THOSE words (alpha, beta, acc stay the AA's)
            let mut pub2 = p0.clone();
            pub2.s_out = state_after::<Val, 12, _>(&c1::perm(), &p0.s_in, &w2);
            pub2.hdr_first.copy_from_slice(&w2[0][..8]);
            let p2 = vcatch("honest_proof_other_stream_public", || ver(&c.prs[0], &pub2));
            vec![p1, p2]
        });
    }
    run_one(&mut out, "wrong_claimed_count", seed, only, &mut |rng| {
        let mut pf = p0.clone();
        if below(rng, 2) == 0 {
            pf.n_blocks_chunk += 1 + below(rng, 5);
        } else {
            pf.n_blocks_chunk -= 1 + below(rng, 5).min(pf.n_blocks_chunk - 2);
        }
        let p1 = p1_rc_p("dishonest_prover", &c.words, &pf, &pf, ver);
        let p2 = vcatch("honest_proof_false_claim", || ver(&c.prs[0], &pf));
        vec![p1, p2]
    });
    run_one(&mut out, "wrong_digest", seed, only, &mut |rng| {
        let mut pf = p0.clone();
        let j = below(rng, 4);
        pf.s_out[j] = fadd(pf.s_out[j], delta(rng));
        vec![vcatch("honest_proof_other_digest", || ver(&c.prs[0], &pf))]
    });
    run_one(&mut out, "other_workload_proof", seed, only, &mut |_| {
        vec![vcatch("proof_of_other_workload", || ver(&rc.other.prs[0], p0))]
    });
    run_one(&mut out, "flipped_proof_byte", seed, only, &mut |rng| {
        vec![flip_variant("flip", &c.rc_bytes, rng, |p| ver(p, p0))]
    });
    let rows = pc::chunk_rows(pc_n_words(p0));
    for (name, qs) in [("weaker_options_below_floor", [5usize, 10, 15, 20]), ("weaker_options_above_floor", [30, 35, 30, 35])] {
        run_one(&mut out, name, seed, only, &mut |rng| {
            let q = qs[below(rng, 4)];
            match catch(|| pc::prove_chunk(&o_q(q), &c.words, p0)) {
                Err(m) => vec![refused("weak_prover", m)],
                Ok(Err(e)) => vec![refused("weak_prover", e)],
                Ok(Ok(p)) => {
                    let n = bits_note(q, rows);
                    vec![note(vcatch("strict_options", || ver(&p, p0)), &n)]
                }
            }
        });
    }
    out
}

// ------------------------------------------------------------------------------------------------ bundle form: stream_mismatch, inverted_scope

struct BundleP {
    a: AuthCase,
    e: PCase,
    eb: PCase,
}

fn bundle_case_p(n_q: usize, seed: u64) -> Result<BundleP, String> {
    let a = auth_case(AUTH_DEPTH, seed)?;
    let mut r = Rng::new(seed ^ 0x2222);
    let wseed = r.next_u64();
    let theta = rnd_theta(&mut r);
    let ctx = ctx_of(&a.pubin);
    let e = pcase(n_q, BLOCK, wseed, theta, ctx, None)?;
    let eb = pcase(n_q, BLOCK, wseed ^ 0x5eed_0004, theta, ctx, None)?;
    Ok(BundleP { a, e, eb })
}

#[allow(clippy::too_many_arguments)]
fn bver<T>(nc: NativeChecks, a: &T, ap: &AuthPublic, pa: &Pf, pe: &Pf, ep: &ExecPublic, prs: &[Pf], cps: &[RcChunkPublic], lists: &[ChunkLists]) -> Result<(), String> {
    let _ = a;
    verify_bundle_p(nc, &o(), FMT, pa, ap, pe, ep, prs, cps, lists, RID)
}

fn bundle_suite_p(c: &BundleP, seed: u64, only: &Option<String>) -> Attacks {
    let mut out = Attacks::new();
    let e = &c.e;
    // stream_mismatch: honest chunk / RC proofs of stream A + honest Exec proof of stream B (same shape); Auth and C_Q link honest
    run_one(&mut out, "stream_mismatch", seed, only, &mut |_| {
        let on = vcatch("checks_on", || bver(NativeChecks::ON, &c.a, &c.a.pubin, &c.a.proof, &c.eb.pe, &c.eb.epub, &e.prs, &e.cps, &e.lists));
        let off = vcatch("checks_off", || bver(NativeChecks::OFF, &c.a, &c.a.pubin, &c.a.proof, &c.eb.pe, &c.eb.epub, &e.prs, &e.cps, &e.lists));
        vec![on, off]
    });
    run_one(&mut out, "inverted_scope", seed, only, &mut |rng| {
        let l = &c.a.wit.leaf;
        let mut pf = c.a.pubin.clone();
        let which = below(rng, 3);
        let (lo, hi) = match which {
            0 => l.s,
            1 => l.e,
            _ => l.t,
        };
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
            Ok(Err(er)) => vec![refused("checks_on", er.clone()), refused("checks_off", er)],
            Ok(Ok(proof)) => {
                let on = note(vcatch("checks_on", || bver(NativeChecks::ON, &c.a, &pf, &proof, &e.pe, &e.epub, &e.prs, &e.cps, &e.lists)), &format!("inverted range {name}"));
                let off = note(vcatch("checks_off", || bver(NativeChecks::OFF, &c.a, &pf, &proof, &e.pe, &e.epub, &e.prs, &e.cps, &e.lists)), &format!("inverted range {name}"));
                vec![on, off]
            }
        }
    });
    out
}

// ------------------------------------------------------------------------------------------------ packed-specific attacks

struct PackCase {
    a: AuthCase,
    e: PCase,
    eb: PCase,
    eo: PCase,
}

fn pack_case(n_q: usize, seed: u64) -> Result<PackCase, String> {
    let a = auth_case(AUTH_DEPTH, seed)?;
    let mut r = Rng::new(seed ^ 0x3333);
    let wseed = r.next_u64();
    let theta = rnd_theta(&mut r);
    let ctx = ctx_of(&a.pubin);
    let e = pcase(n_q, BLOCK, wseed, theta, ctx, None)?;
    let eb = pcase(n_q, BLOCK, wseed ^ 0x5eed_0006, theta, ctx, None)?;
    let n_odd = (n_q / BLOCK_ODD).max(1) * BLOCK_ODD;
    let eo = pcase(n_odd, BLOCK_ODD, wseed ^ 0x5eed_0007, theta, ctx, None)?;
    Ok(PackCase { a, e, eb, eo })
}

/// A consistent attacker: Exec proof (P2r) and chunk proofs over the FORGED packed words, statements recomputed from them, verified with the
/// full bundle verification. `aa_lists` = the AA's own lists (honest stream) or None (the verifier is given the attacker's lists, i.e. the
/// sealed check cannot catch anything). `kinds` = hand-made row kinds (a dishonest prover's own hdr / va / vb columns).
fn forge(a: &AuthCase, words: &Words, kinds: Option<&[Kind]>, bsz: usize, base: &ExecPublic, aa_lists: Option<&[ChunkLists]>, variant: &str) -> V {
    let epub = pub_of_words(base, words);
    let pe = match catch(|| match kinds {
        Some(k) => prove_pair_kinds(&o(), words, k, &epub, FMT),
        None => prove_pair_words(&o(), words, &epub, FMT),
    }) {
        Err(m) => return refused(variant, format!("exec prover panicked: {m}")),
        Ok(Err(e)) => return refused(variant, format!("exec prover: {e}")),
        Ok(Ok(p)) => p,
    };
    let rpw = rows_per_block(bsz);
    let nb = words.len() / rpw;
    let (cps, lists) = match catch(|| pc::honest_publics(words, bsz, nb)) {
        Err(m) => return refused(variant, format!("chunk statements panicked: {m}")),
        Ok(x) => x,
    };
    let mut prs = Vec::new();
    let mut first = 0;
    for p in &cps {
        let (lo, hi) = (first * rpw, (first + p.n_blocks_chunk) * rpw);
        let r = catch(|| match kinds {
            Some(k) => pc::prove_chunk_kinds(&o(), &words[lo..hi], &k[lo..hi], p),
            None => pc::prove_chunk(&o(), &words[lo..hi], p),
        });
        match r {
            Err(m) => return refused(variant, format!("chunk prover panicked: {m}")),
            Ok(Err(e)) => return refused(variant, format!("chunk prover: {e}")),
            Ok(Ok(pf)) => prs.push(pf),
        }
        first += p.n_blocks_chunk;
    }
    let d = diag(&pe, &epub, &prs, &cps);
    let lv: &[ChunkLists] = aa_lists.unwrap_or(&lists);
    let v = vcatch(variant, || bver(NativeChecks::ON, a, &a.pubin, &a.proof, &pe, &epub, &prs, &cps, lv));
    note(v, &d)
}

/// Exec proof over the forged stream (consistent statement), chunk side = the AA's honest set of the original stream
fn forge_exec_only(a: &AuthCase, c: &PCase, words: &Words, variant: &str) -> V {
    let pub2 = pub_of_words(&c.epub, words);
    match catch(|| prove_pair_words(&o(), words, &pub2, FMT)) {
        Err(m) => refused(variant, format!("exec prover panicked: {m}")),
        Ok(Err(e)) => refused(variant, format!("exec prover: {e}")),
        Ok(Ok(pe2)) => {
            let d = format!("[exec alone: {}]", acc_rej(&exec_alone(&pe2, &pub2)));
            note(vcatch(variant, || bver(NativeChecks::ON, a, &a.pubin, &a.proof, &pe2, &pub2, &c.prs, &c.cps, &c.lists)), &d)
        }
    }
}

fn packed_suite(pk: &PackCase, seed: u64, only: &Option<String>) -> Attacks {
    let mut out = Attacks::new();
    let (a, e, eo) = (&pk.a, &pk.e, &pk.eo);
    let nb = e.w.n_blocks;
    let theta = e.epub.theta;

    // (a) v = 2^32 or larger, either half. Window [2^32, 2^32 + theta): the Exec P2r predicate gadget still accepts (d = v - theta < 2^32), so only the chunk / RC range check can reject.
    run_one(&mut out, "packed_v_ge_2_32", seed, only, &mut |rng| {
        let (g, k) = (below(rng, nb), below(rng, BLOCK));
        let (row, half) = rh(BLOCK, g, k);
        let v1 = if below(rng, 4) == 0 { 1u64 << 32 } else { (1u64 << 32) + below(rng, theta as usize) as u64 };
        let v2 = (1u64 << 33) + rng.next_u64() % (1u64 << 40);
        let mut w1 = e.words.clone();
        w1[row][4 * half + 1] = v1;
        let mut w2 = e.words.clone();
        w2[row][4 * half + 1] = v2;
        let n = format!("half {} of row {row}", if half == 0 { "a" } else { "b" });
        vec![
            note(forge(a, &w1, None, BLOCK, &e.epub, Some(&e.lists), "v_in_exec_window"), &n),
            note(forge(a, &w2, None, BLOCK, &e.epub, Some(&e.lists), "v_large"), &n),
        ]
    });

    // (b) b = 2^20 or larger, either half (Exec P2r never range-checks b: only the chunk / RC proofs do)
    run_one(&mut out, "packed_b_ge_2_20", seed, only, &mut |rng| {
        let (g, k) = (below(rng, nb), below(rng, BLOCK));
        let (row, half) = rh(BLOCK, g, k);
        let b1 = if below(rng, 3) == 0 { 1u64 << 20 } else { (1u64 << 20) + below(rng, 1 << 20) as u64 };
        let b2 = (1u64 << 40) + rng.next_u64() % (1u64 << 30);
        let mut w1 = e.words.clone();
        w1[row][4 * half + 2] = b1;
        let mut w2 = e.words.clone();
        w2[row][4 * half + 2] = b2;
        let n = format!("half {} of row {row}", if half == 0 { "a" } else { "b" });
        vec![
            note(forge(a, &w1, None, BLOCK, &e.epub, Some(&e.lists), "b_2_20_or_just_above"), &n),
            note(forge(a, &w2, None, BLOCK, &e.epub, Some(&e.lists), "b_large"), &n),
        ]
    });

    // (c) non-zero second half in an odd block (block size 99: the last record word of every block has an empty half b)
    run_one(&mut out, "packed_nonzero_empty_half", seed, only, &mut |rng| {
        let nbo = eo.w.n_blocks;
        let g = below(rng, nbo);
        let rpw = rows_per_block(BLOCK_ODD);
        let row = g * rpw + (BLOCK_ODD + 1) / 2; // last record row of block g
        let slot = 4 + below(rng, 4);
        let mut w1 = eo.words.clone();
        w1[row][slot] = 1 + below(rng, 1 << 20) as u64;
        let mut w2 = eo.words.clone();
        for s in 4..8 {
            w2[row][s] = 1 + below(rng, 1 << 20) as u64;
        }
        // a prover that claims the empty half is a record (hand-made vb = 1): the countdown breaks
        let mut kinds = honest_kinds(nbo, BLOCK_ODD);
        kinds[row].vb = true;
        let n = format!("block {g}, slot {slot}");
        vec![
            note(forge(a, &w1, None, BLOCK_ODD, &eo.epub, Some(&eo.lists), "one_slot_nonzero"), &n),
            note(forge(a, &w2, None, BLOCK_ODD, &eo.epub, Some(&eo.lists), "all_four_slots_nonzero"), &n),
            note(forge(a, &eo.words, Some(&kinds), BLOCK_ODD, &eo.epub, Some(&eo.lists), "vb_claimed_on_empty_half"), &n),
        ]
    });

    // (d) countdown differs from m_g: the header of one block says m_g' = B +- 2 (AIR rule hdr*(w2 - B) of the real AIRs is violated).
    run_one(&mut out, "packed_mg_ne_B", seed, only, &mut |rng| {
        let g = below(rng, nb);
        let row = g * rows_per_block(BLOCK);
        let m2 = if below(rng, 2) == 0 { BLOCK as u64 + 2 } else { BLOCK as u64 - 2 };
        let mut w2 = e.words.clone();
        w2[row][2] = m2;
        let n = format!("block {g}: m_g = {m2}, B = {BLOCK}");
        vec![
            // the full bundle verification with the AA's own lists: alpha / beta / acc over the header words (slot 2 = m_g) differ
            note(forge(a, &w2, None, BLOCK, &e.epub, Some(&e.lists), "mg_changed_AA_lists_honest"), &n),
            // the sealed check is blinded (the verifier is given the attacker's lists): the AIRs must reject
            note(forge(a, &w2, None, BLOCK, &e.epub, None, "mg_changed_attacker_lists"), &n),
            // Exec over the forged stream, honest chunk side: the stream link (digest) must reject
            note(forge_exec_only(a, e, &w2, "mg_changed_exec_only_chunks_honest"), &n),
        ]
    });

    // (e) Exec proof over stream A with the chunk statements (and proofs) of stream B, stream link on
    run_one(&mut out, "packed_exec_A_chunks_B", seed, only, &mut |_| {
        let eb = &pk.eb;
        let b1 = vcatch("chunk_proofs_B_publics_B", || bver(NativeChecks::ON, a, &a.pubin, &a.proof, &e.pe, &e.epub, &eb.prs, &eb.cps, &eb.lists));
        let b2 = vcatch("chunk_proofs_A_publics_B", || bver(NativeChecks::ON, a, &a.pubin, &a.proof, &e.pe, &e.epub, &e.prs, &eb.cps, &eb.lists));
        let o1 = vcatch("chunk_proofs_B_publics_B_checks_off", || bver(NativeChecks::OFF, a, &a.pubin, &a.proof, &e.pe, &e.epub, &eb.prs, &eb.cps, &eb.lists));
        let o2 = vcatch("chunk_proofs_A_publics_B_checks_off", || bver(NativeChecks::OFF, a, &a.pubin, &a.proof, &e.pe, &e.epub, &e.prs, &eb.cps, &eb.lists));
        vec![b1, b2, o1, o2]
    });

    // (f) swap the two halves of a pair word
    run_one(&mut out, "packed_swap_halves", seed, only, &mut |rng| {
        let (mut g, mut k) = (below(rng, nb), below(rng, BLOCK));
        while get_rec(&e.words, BLOCK, g, k & !1) == get_rec(&e.words, BLOCK, g, k | 1) {
            g = below(rng, nb);
            k = below(rng, BLOCK);
        }
        let (row, _) = rh(BLOCK, g, k);
        let mut w2 = e.words.clone();
        let x = w2[row].clone();
        w2[row][..4].copy_from_slice(&x[4..]);
        w2[row][4..].copy_from_slice(&x[..4]);
        let n = format!("row {row}");
        let p3 = p1_exec_p("swap_dishonest_prover_original_statement", &w2, &e.epub, &e.epub, &|p: &Pf, q: &ExecPublic| {
            bver(NativeChecks::ON, a, &a.pubin, &a.proof, p, q, &e.prs, &e.cps, &e.lists)
        });
        vec![
            note(forge(a, &w2, None, BLOCK, &e.epub, Some(&e.lists), "swap_AA_lists"), &n),
            note(forge_exec_only(a, e, &w2, "swap_exec_only_chunks_honest"), &n),
            note(p3, &n),
        ]
    });
    out
}

// ------------------------------------------------------------------------------------------------ driver

fn emit_split(sink: &mut Sink, sink_off: &mut Sink, name: &str, form: &str, n_q: usize, seed: u64, vs: Vec<V>) {
    let (off, on): (Vec<V>, Vec<V>) = vs.into_iter().partition(|v| v.variant.ends_with("checks_off"));
    sink.emit(name, form, n_q, seed, on);
    if !off.is_empty() {
        sink_off.emit(name, form, n_q, seed, off);
    }
}

pub fn cmd_run_p(args: &[String]) {
    let cfg = Cfg {
        out: argv(args, "out").unwrap_or_else(|| "results/attack-w38-p2r".into()),
        attack_trials: argn(args, "attack_trials", 20),
        honest_trials: argn(args, "honest_trials", 50),
        n20k: argn(args, "n20k", 4),
        n50k: argn(args, "n50k", 1),
        h20k: argn(args, "h20k", 5),
        h50k: argn(args, "h50k", 2),
        forms: argv(args, "forms").unwrap_or_else(|| "exec_single,rc_single,pair,bundle,packed".into()).split(',').map(|s| s.to_string()).collect(),
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
    let path_off = format!("{}/raw-{HASH_NAME}-nochecks{tag}.csv", cfg.out);
    let mut file_off = std::fs::File::create(&path_off).unwrap();
    writeln!(file_off, "{RAW_HEADER}").unwrap();
    let mut sink_off = Sink { file: file_off, n_rows: 0 };
    std::panic::set_hook(Box::new(|_| {}));
    let t0 = Instant::now();
    let over = |t0: &Instant| t0.elapsed().as_secs_f64() / 60.0 > cfg.max_min;
    let op = o();
    eprintln!("fmt=p2r hash={HASH_NAME} queries={} log_blowup={} grind={} out={path}", op.num_queries, op.log_blowup, op.query_pow_bits);

    // ---------------- honest-only trials (odd trials split the chunk set into several chunks)
    let hp = nq_plan(cfg.honest_trials, cfg.h20k, cfg.h50k);
    for (idx, &n_q) in hp.iter().enumerate() {
        if over(&t0) {
            eprintln!("time cap reached in honest trials at {idx}");
            break;
        }
        let seed = cfg.seed_base + 10_000 + idx as u64;
        let split = idx % 2 == 1;
        let c_of = |nb: usize| if split { Some((nb / 3).max(1)) } else { None };
        if form_enabled(&cfg, "exec_single") || form_enabled(&cfg, "rc_single") {
            for form in ["exec_single", "rc_single"] {
                if !form_enabled(&cfg, form) {
                    continue;
                }
                let r = catch(|| -> Result<(), String> {
                    let mut g = Rng::new(seed);
                    let wseed = g.next_u64();
                    let theta = rnd_theta(&mut g);
                    let ctx = rnd_ctx(&mut g);
                    let c = pcase(n_q, BLOCK, wseed, theta, ctx, c_of(n_q / BLOCK))?;
                    let pe = roundtrip(&c.pe)?;
                    let prs: Result<Vec<Pf>, String> = c.prs.iter().map(roundtrip).collect();
                    ver_x(NativeChecks::ON, &pe, &c.epub, &prs?, &c.cps, &c.lists)
                });
                honest_row(&mut sink, form, n_q, seed, "serialise_parse_verify_exec_chunks", r.unwrap_or_else(|m| Err(format!("harness panic {m}"))), if split { "several chunks" } else { "one chunk" });
            }
        }
        for form in ["pair", "bundle"] {
            if !form_enabled(&cfg, form) {
                continue;
            }
            let r = catch(|| -> Result<(), String> {
                let mut g = Rng::new(seed);
                let depth = [6usize, 10, 14][below(&mut g, 3)];
                let (ap, aw) = honest_auth_instance::<Val, _>(&c1::perm(), depth, g.next_u64());
                let pa = parse(&c1::to_bytes(&plain::prove_auth(&o(), &ap, &aw)?))?;
                let wseed = g.next_u64();
                let theta = rnd_theta(&mut g);
                let c = pcase(n_q, BLOCK, wseed, theta, ctx_of(&ap), c_of(n_q / BLOCK))?;
                let pe = roundtrip(&c.pe)?;
                let prs: Result<Vec<Pf>, String> = c.prs.iter().map(roundtrip).collect();
                bver(NativeChecks::ON, &(), &ap, &pa, &pe, &c.epub, &prs?, &c.cps, &c.lists)
            });
            honest_row(&mut sink, form, n_q, seed, "serialise_parse_verify_bundle", r.unwrap_or_else(|m| Err(format!("harness panic {m}"))), if split { "auth depth random {6,10,14}; several chunks" } else { "auth depth random {6,10,14}; one chunk" });
        }
        if form_enabled(&cfg, "packed") {
            // honest streams of several block sizes (odd and even), through the full bundle verification
            let r = catch(|| -> Result<(), String> {
                let mut g = Rng::new(seed);
                let bsz = [100usize, 99, 7, 33][below(&mut g, 4)];
                let n = (n_q / bsz).max(1) * bsz;
                let (ap, aw) = honest_auth_instance::<Val, _>(&c1::perm(), 10, g.next_u64());
                let pa = parse(&c1::to_bytes(&plain::prove_auth(&o(), &ap, &aw)?))?;
                let wseed = g.next_u64();
                let theta = rnd_theta(&mut g);
                let c = pcase(n, bsz, wseed, theta, ctx_of(&ap), c_of(n / bsz))?;
                let pe = roundtrip(&c.pe)?;
                let prs: Result<Vec<Pf>, String> = c.prs.iter().map(roundtrip).collect();
                bver(NativeChecks::ON, &(), &ap, &pa, &pe, &c.epub, &prs?, &c.cps, &c.lists)
            });
            honest_row(&mut sink, "packed", n_q, seed, "serialise_parse_verify_bundle", r.unwrap_or_else(|m| Err(format!("harness panic {m}"))), "block size random {100,99,7,33}");
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
        const UNT: &str = "changed_record_word_pid_epoch_seq";
        const UNT_WHY: &str = "no meaning in the packed format: a packed record half is [id, v, b, tag]; pid, epoch and seq_start are in the header word (covered by changed_block_header)";
        if form_enabled(&cfg, "exec_single") {
            match catch(|| exec_case_p(n_q, seed, None, None)) {
                Ok(Ok(ec)) => {
                    let c = &ec.c;
                    let ver_e = |p: &Pf, q: &ExecPublic| -> Result<(), String> {
                        let alone = acc_rej(&exec_alone(p, q));
                        ver_x(NativeChecks::ON, p, q, &c.prs, &c.cps, &c.lists).map_err(|e| format!("{e} [exec alone: {alone}]"))
                    };
                    honest_row(&mut sink, "exec_single", n_q, seed, "attack_instance_honest", vcatch_r(|| ver_e(&c.pe, &c.epub)), "");
                    let a = exec_suite_p(&ec, seed, &ver_e, &cfg.only);
                    emit_attacks(&mut sink, "exec_single", n_q, seed, a);
                    sink.emit(UNT, "exec_single", n_q, seed, vec![untested("not_applicable", UNT_WHY)]);
                }
                Ok(Err(e)) => sink.emit("setup", "exec_single", n_q, seed, vec![herr("setup", e)]),
                Err(m) => sink.emit("setup", "exec_single", n_q, seed, vec![herr("setup", m)]),
            }
        }
        if form_enabled(&cfg, "rc_single") {
            match catch(|| rc_case_p(n_q, seed)) {
                Ok(Ok(rc)) => {
                    let c = &rc.c;
                    let ver_r = |p: &Pf, q: &RcChunkPublic| -> Result<(), String> {
                        let alone = acc_rej(&pc::verify_chunk(&o(), p, q));
                        ver_x(NativeChecks::ON, &c.pe, &c.epub, std::slice::from_ref(p), std::slice::from_ref(q), &c.lists).map_err(|e| format!("{e} [rc alone: {alone}]"))
                    };
                    honest_row(&mut sink, "rc_single", n_q, seed, "attack_instance_honest", vcatch_r(|| ver_r(&c.prs[0], &c.cps[0])), "");
                    let a = rc_suite_p(&rc, seed, &ver_r, &cfg.only);
                    emit_attacks(&mut sink, "rc_single", n_q, seed, a);
                    sink.emit(UNT, "rc_single", n_q, seed, vec![untested("not_applicable", UNT_WHY)]);
                }
                Ok(Err(e)) => sink.emit("setup", "rc_single", n_q, seed, vec![herr("setup", e)]),
                Err(m) => sink.emit("setup", "rc_single", n_q, seed, vec![herr("setup", m)]),
            }
        }
        if form_enabled(&cfg, "pair") {
            let r = catch(|| -> Result<(AuthCase, ExecCaseP, AuthCase, PCase), String> {
                let a1 = auth_case(AUTH_DEPTH, seed)?;
                let a2 = auth_case(AUTH_DEPTH, seed ^ 0x77)?;
                let e1 = exec_case_p(n_q, seed ^ 0x1111, Some(ctx_of(&a1.pubin)), Some(ctx_of(&a2.pubin)))?;
                // the other request's complete Exec side (Exec proof over its own stream with ITS ctx, plus its chunk proofs): a mix of
                // requests must be caught by the C_Q link and not hidden by the stream link
                let mut r2 = Rng::new(seed ^ 0x1111);
                let ws = r2.next_u64() ^ 0x5eed_0002;
                let e2 = pcase(n_q, BLOCK, ws, e1.c.epub.theta, ctx_of(&a2.pubin), None)?;
                Ok((a1, e1, a2, e2))
            });
            match r {
                Ok(Ok((a1, e1, a2, e2))) => {
                    let c = &e1.c;
                    let ver_e = |p: &Pf, q: &ExecPublic| -> Result<(), String> {
                        let alone = acc_rej(&exec_alone(p, q));
                        verify_bundle_p(NativeChecks::ON, &o(), FMT, &a1.proof, &a1.pubin, p, q, &c.prs, &c.cps, &c.lists, RID).map_err(|e| format!("{e} [exec alone: {alone}]"))
                    };
                    let ver_a = |p: &Pf, q: &AuthPublic| -> Result<(), String> {
                        let alone = acc_rej(&plain::verify_auth(&o(), p, q));
                        verify_bundle_p(NativeChecks::ON, &o(), FMT, p, q, &c.pe, &c.epub, &c.prs, &c.cps, &c.lists, RID).map_err(|e| format!("{e} [auth alone: {alone}]"))
                    };
                    honest_row(&mut sink, "pair", n_q, seed, "attack_instance_honest", vcatch_r(|| ver_e(&c.pe, &c.epub)), "exec ctx = exec_context(b_q, d_q, 0)");
                    let mut a = exec_suite_p(&e1, seed, &ver_e, &cfg.only);
                    a.extend(auth_suite(&a1, seed, &ver_a, &cfg.only));
                    let mut mix = Attacks::new();
                    run_one(&mut mix, "mix_exec_of_other_request", seed, &cfg.only, &mut |_| {
                        vec![vcatch("verify_bundle_auth1_exec2_chunks2", || {
                            verify_bundle_p(NativeChecks::ON, &o(), FMT, &a1.proof, &a1.pubin, &e2.pe, &e2.epub, &e2.prs, &e2.cps, &e2.lists, RID)
                        })]
                    });
                    run_one(&mut mix, "mix_auth_of_other_request", seed, &cfg.only, &mut |_| {
                        vec![vcatch("verify_bundle_auth2_exec1", || {
                            verify_bundle_p(NativeChecks::ON, &o(), FMT, &a2.proof, &a2.pubin, &c.pe, &c.epub, &c.prs, &c.cps, &c.lists, RID)
                        })]
                    });
                    a.extend(mix);
                    emit_attacks(&mut sink, "pair", n_q, seed, a);
                }
                Ok(Err(e)) => sink.emit("setup", "pair", n_q, seed, vec![herr("setup", e)]),
                Err(m) => sink.emit("setup", "pair", n_q, seed, vec![herr("setup", m)]),
            }
        }
        if form_enabled(&cfg, "bundle") {
            match catch(|| bundle_case_p(n_q, seed)) {
                Ok(Ok(c)) => {
                    let e = &c.e;
                    honest_row(&mut sink, "bundle", n_q, seed, "attack_instance_honest", vcatch_r(|| bver(NativeChecks::ON, &c.a, &c.a.pubin, &c.a.proof, &e.pe, &e.epub, &e.prs, &e.cps, &e.lists)), "checks on");
                    honest_row(&mut sink_off, "bundle", n_q, seed, "attack_instance_honest_checks_off", vcatch_r(|| bver(NativeChecks::OFF, &c.a, &c.a.pubin, &c.a.proof, &e.pe, &e.epub, &e.prs, &e.cps, &e.lists)), "checks off");
                    for (name, vs) in bundle_suite_p(&c, seed, &cfg.only) {
                        emit_split(&mut sink, &mut sink_off, &name, "bundle", n_q, seed, vs);
                    }
                }
                Ok(Err(e)) => sink.emit("setup", "bundle", n_q, seed, vec![herr("setup", e)]),
                Err(m) => sink.emit("setup", "bundle", n_q, seed, vec![herr("setup", m)]),
            }
        }
        if form_enabled(&cfg, "packed") {
            match catch(|| pack_case(n_q, seed)) {
                Ok(Ok(pk)) => {
                    let e = &pk.e;
                    honest_row(&mut sink, "packed", n_q, seed, "attack_instance_honest", vcatch_r(|| bver(NativeChecks::ON, &pk.a, &pk.a.pubin, &pk.a.proof, &e.pe, &e.epub, &e.prs, &e.cps, &e.lists)), "block 100");
                    let eo = &pk.eo;
                    honest_row(&mut sink, "packed", n_q, seed, "attack_instance_honest_odd", vcatch_r(|| bver(NativeChecks::ON, &pk.a, &pk.a.pubin, &pk.a.proof, &eo.pe, &eo.epub, &eo.prs, &eo.cps, &eo.lists)), "block 99");
                    for (name, vs) in packed_suite(&pk, seed, &cfg.only) {
                        emit_split(&mut sink, &mut sink_off, &name, "packed", n_q, seed, vs);
                    }
                }
                Ok(Err(e)) => sink.emit("setup", "packed", n_q, seed, vec![herr("setup", e)]),
                Err(m) => sink.emit("setup", "packed", n_q, seed, vec![herr("setup", m)]),
            }
        }
        eprintln!("[{:6.1}s] attack instance {}/{} n_q={n_q} rows={}", t0.elapsed().as_secs_f64(), idx + 1, ap.len(), sink.n_rows);
    }
    eprintln!("done in {:.1} s, rows {} (+ {} rows with the native checks off)", t0.elapsed().as_secs_f64(), sink.n_rows, sink_off.n_rows);
}
