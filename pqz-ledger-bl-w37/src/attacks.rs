//! Rejection harness: the four attack classes of the plan, run through the full
//! simulated ledger (signed transactions, block execution on every validator, QC).
//!
//! Attack classes (variants in brackets):
//!   1. replay of a consumed RID_Q   [replay_consume, reauthorize_after_consume, consume_unauthorized]
//!   2. wrong canonical state Omega_e [wrong_omega_flipbit, wrong_omega_other_epoch,
//!                                     wrong_omega_forked_policy, stale_epoch_current]
//!   3. predicate changed after authorization [predicate_changed]
//!   4. authenticated block omitted  [omit_block, forged_shorter_epoch]
//!
//! One "trial" = one attack transaction (or one forged response) with its own RID,
//! committed in batches of up to 100 per block; trials do not share RIDs, so they are
//! independent. Each variant also runs the matching honest operation as a CONTROL, so a
//! harness that rejects everything would be caught (control_ok must equal trials).
//! The attacker is a registered submitter (it holds a valid transaction key); transaction
//! signatures therefore do not stop it, only the contract rules and the verifier do.
//!
//! Mutation testing: with the `mutation` feature (or in unit tests) one defence at a time
//! is switched off; exactly the variants listed in `EXPECTED_FLIPS` must become accepted.

use crate::audit::{self, CoverReject};
use crate::contract::*;
use crate::hashing::*;
use crate::ledger::*;
use crate::sig::SigKeys;
use std::collections::BTreeMap;

pub struct Params {
    pub trials: usize,
    pub n_validators: usize,
    /// number of anchored epochs (>= 3)
    pub epochs: usize,
    /// blocks per epoch in the audit chain (G_e), records per block
    pub g_e: usize,
    pub recs_per_block: usize,
    pub seed: u64,
}

impl Default for Params {
    fn default() -> Self {
        Params { trials: 1000, n_validators: 4, epochs: 3, g_e: 16, recs_per_block: 4, seed: 1 }
    }
}

pub const VARIANTS: [(&str, &str); 11] = [
    ("replay_consume", "replay of a consumed RID_Q"),
    ("reauthorize_after_consume", "replay of a consumed RID_Q"),
    ("consume_unauthorized", "replay of a consumed RID_Q"),
    ("wrong_omega_flipbit", "wrong canonical state"),
    ("wrong_omega_other_epoch", "wrong canonical state"),
    ("wrong_omega_forked_policy", "wrong canonical state"),
    ("stale_epoch_current", "wrong canonical state"),
    ("predicate_changed", "predicate changed after authorization"),
    ("predicate_changed_new_rid", "predicate changed after authorization"),
    ("omit_block", "authenticated block omitted"),
    ("forged_shorter_epoch", "authenticated block omitted"),
];

/// defence switched off -> variants that must then be accepted (and no others)
pub const EXPECTED_FLIPS: [(&str, &[&str]); 7] = [
    ("reservation_unique", &["reauthorize_after_consume"]),
    ("single_use", &["replay_consume", "consume_unauthorized", "predicate_changed_new_rid"]),
    ("omega_equality", &["wrong_omega_flipbit", "wrong_omega_other_epoch", "wrong_omega_forked_policy"]),
    ("current_freshness", &["stale_epoch_current"]),
    ("predicate_binding", &["predicate_changed"]),
    ("block_cover", &["omit_block"]),
    ("anchor_binding", &["forged_shorter_epoch"]),
];

#[derive(Clone, Debug)]
pub struct VariantResult {
    pub variant: &'static str,
    pub class: &'static str,
    pub trials: usize,
    pub rejected: usize,
    pub accepted: usize,
    /// honest counterpart operations that were (correctly) accepted
    pub control_ok: usize,
    pub control_total: usize,
    /// rejection reasons (contract / verifier), counted
    pub reasons: BTreeMap<&'static str, usize>,
    /// up to 3 traces of ACCEPTED attacks
    pub traces: Vec<String>,
}

impl VariantResult {
    fn new(variant: &'static str) -> Self {
        let class = VARIANTS.iter().find(|v| v.0 == variant).unwrap().1;
        VariantResult { variant, class, trials: 0, rejected: 0, accepted: 0, control_ok: 0, control_total: 0, reasons: BTreeMap::new(), traces: vec![] }
    }
    fn record(&mut self, accepted: bool, reason: Option<&'static str>, trace: impl FnOnce() -> String) {
        self.trials += 1;
        if accepted {
            self.accepted += 1;
            if self.traces.len() < 3 {
                self.traces.push(trace());
            }
        } else {
            self.rejected += 1;
            *self.reasons.entry(reason.unwrap_or("?")).or_insert(0) += 1;
        }
    }
    fn control(&mut self, ok: bool) {
        self.control_total += 1;
        if ok {
            self.control_ok += 1;
        }
    }
}

#[cfg(any(test, feature = "mutation"))]
fn armed(c: Contract, d: Defences) -> Contract {
    c.with_defences(d)
}
#[cfg(not(any(test, feature = "mutation")))]
fn armed(c: Contract, d: Defences) -> Contract {
    assert!(d == Defences::all(), "defences can only be changed with the `mutation` feature");
    c
}

/// Production defences (what the paper's contract and verifier do).
pub fn run(p: &Params) -> Vec<VariantResult> {
    run_inner(p, Defences::all())
}

/// Same harness with some defences off (test-only).
#[cfg(any(test, feature = "mutation"))]
pub fn run_with(p: &Params, d: Defences) -> Vec<VariantResult> {
    run_inner(p, d)
}

struct Env {
    led: Ledger,
    csp: SigKeys,
    chain: audit::Chain,
    aa_vk: ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
    e_last: u64,
    omegas: Vec<Hash>,
    r_pol: Hash,
}

impl Env {
    fn submit(&mut self, txs: Vec<Tx>) -> Vec<Result<(), Reject>> {
        let signed: Vec<SignedTx> = txs.into_iter().map(|t| SignedTx::sign(t, 1, &self.csp, &self.led.cfg)).collect();
        self.led.submit(signed).receipts.into_iter().map(|r| r.result).collect()
    }
}

fn setup(p: &Params, d: Defences) -> Env {
    assert!(p.epochs >= 3 && p.g_e >= 2);
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&p.seed.to_be_bytes());
    let aa = SigKeys::from_seed(h(&[b"harness-aa", &seed]));
    let csp = SigKeys::from_seed(h(&[b"harness-csp", &seed]));
    let chain = audit::Chain::genesis(&aa);
    let genesis = armed(chain.genesis_contract(), d);
    let cfg = LedgerConfig { n_validators: p.n_validators, max_block_txs: 100, tx_auth: true };
    let vks = vec![aa.vk.clone(), csp.vk.clone()];
    let led = Ledger::new(cfg, genesis, vks, h(&[b"harness-validators", &seed]));
    let r_pol = chain.r_pol;
    let mut env = Env { led, csp, aa_vk: aa.vk.clone(), chain, e_last: 0, omegas: vec![], r_pol };
    env.omegas.push(env.chain.epoch(0).omega);
    for _ in 0..p.epochs {
        let tx = env.chain.next_anchor(&aa, p.g_e, p.recs_per_block);
        let r = env.submit(vec![tx]);
        assert_eq!(r[0], Ok(()), "setup anchor must be accepted");
        env.e_last += 1;
        env.omegas.push(env.chain.epoch(env.e_last).omega);
    }
    env
}

/// Everything one honest request needs.
struct Req {
    rid: Hash,
    pred: Hash,
}

fn make_req_with(env: &Env, qid: u64, e: u64, pred: Hash) -> Req {
    let om = env.omegas[e as usize];
    let b_q = binding_bq(&d_q(qid, &pred), 7, 1, &env.r_pol, 0, &om);
    let rid = derive_rid(qid, &b_q, &h(&[b"auth-tac", &u64b(qid)]));
    Req { rid, pred }
}

fn make_req(env: &Env, qid: u64, e: u64) -> Req {
    make_req_with(env, qid, e, h(&[b"predicate", &u64b(qid)]))
}

fn authorize(env: &Env, r: &Req, e: u64, mode: Mode) -> Tx {
    Tx::Authorize { rid: r.rid, pred_hash: r.pred, e, omega: env.omegas[e as usize], mode }
}

fn tx_name(t: &Tx) -> String {
    match t {
        Tx::Authorize { rid, e, mode, .. } => format!("authorize(rid={}, e={}, mode={:?})", short(rid), e, mode),
        Tx::Consume { rid, .. } => format!("consume(rid={})", short(rid)),
        _ => t.kind().to_string(),
    }
}

fn run_inner(p: &Params, d: Defences) -> Vec<VariantResult> {
    let mut env = setup(p, d);
    let mut out: Vec<VariantResult> = Vec::new();
    let last = env.e_last;
    let n = p.trials;
    let mut qid_base: u64 = p.seed.wrapping_mul(1_000_000_007);

    // ---- 1a replay_consume: authorize, consume (controls), consume again (attack)
    {
        let mut vr = VariantResult::new("replay_consume");
        let reqs: Vec<Req> = (0..n).map(|i| make_req(&env, qid_base + i as u64, last)).collect();
        qid_base += n as u64;
        for r in env.submit(reqs.iter().map(|q| authorize(&env, q, last, Mode::Current)).collect()) {
            vr.control(r.is_ok());
        }
        for r in env.submit(reqs.iter().map(|q| Tx::Consume { rid: q.rid, pred_hash: q.pred }).collect()) {
            vr.control(r.is_ok());
        }
        let res = env.submit(reqs.iter().map(|q| Tx::Consume { rid: q.rid, pred_hash: q.pred }).collect());
        for (q, r) in reqs.iter().zip(res) {
            vr.record(r.is_ok(), r.err().map(|e| e.reason()), || {
                format!("authorize ok; consume ok; consume(rid={}) AGAIN was accepted", short(&q.rid))
            });
        }
        out.push(vr);
    }
    // ---- 1b reauthorize_after_consume
    {
        let mut vr = VariantResult::new("reauthorize_after_consume");
        let reqs: Vec<Req> = (0..n).map(|i| make_req(&env, qid_base + i as u64, last)).collect();
        qid_base += n as u64;
        for r in env.submit(reqs.iter().map(|q| authorize(&env, q, last, Mode::Current)).collect()) {
            vr.control(r.is_ok());
        }
        for r in env.submit(reqs.iter().map(|q| Tx::Consume { rid: q.rid, pred_hash: q.pred }).collect()) {
            vr.control(r.is_ok());
        }
        let res = env.submit(reqs.iter().map(|q| authorize(&env, q, last, Mode::Current)).collect());
        for (q, r) in reqs.iter().zip(res) {
            vr.record(r.is_ok(), r.err().map(|e| e.reason()), || {
                format!("authorize ok; consume ok; authorize(rid={}) AGAIN was accepted (Consumed -> Authorized)", short(&q.rid))
            });
        }
        out.push(vr);
    }
    // ---- 1c consume_unauthorized (RID never authorized); control = honest authorize+consume
    {
        let mut vr = VariantResult::new("consume_unauthorized");
        let ctl: Vec<Req> = (0..n).map(|i| make_req(&env, qid_base + i as u64, last)).collect();
        qid_base += n as u64;
        for r in env.submit(ctl.iter().map(|q| authorize(&env, q, last, Mode::Current)).collect()) {
            vr.control(r.is_ok());
        }
        for r in env.submit(ctl.iter().map(|q| Tx::Consume { rid: q.rid, pred_hash: q.pred }).collect()) {
            vr.control(r.is_ok());
        }
        let reqs: Vec<Req> = (0..n).map(|i| make_req(&env, qid_base + i as u64, last)).collect();
        qid_base += n as u64;
        let res = env.submit(reqs.iter().map(|q| Tx::Consume { rid: q.rid, pred_hash: q.pred }).collect());
        for (q, r) in reqs.iter().zip(res) {
            vr.record(r.is_ok(), r.err().map(|e| e.reason()), || format!("consume(rid={}) accepted although never authorized", short(&q.rid)));
        }
        out.push(vr);
    }

    // ---- 2 wrong canonical state: attacker authorizes with a wrong Omega (control: right Omega)
    let wrong_omega_variants: [(&'static str, fn(&Env, u64, u64, usize) -> (u64, Hash, Mode)); 3] = [
        ("wrong_omega_flipbit", |env, last, _i, bit| {
            let mut o = env.omegas[last as usize];
            o[bit % 32] ^= 1 << (bit % 8);
            (last, o, Mode::Current)
        }),
        ("wrong_omega_other_epoch", |env, last, i, _| {
            // a genuine Omega, but of another epoch (never the current one)
            let other = (i % last) as usize; // 0..last-1
            (last, env.omegas[other], Mode::Current)
        }),
        ("wrong_omega_forked_policy", |env, last, i, _| {
            // Omega recomputed by the attacker over a stale/forked policy root and version
            let gamma = env.chain.epoch(last).gamma;
            let fake_pol = h(&[b"forked-policy", &u64b(i)]);
            (last, omega(last, &gamma, &fake_pol, 0), Mode::Current)
        }),
    ];
    for (name, make) in wrong_omega_variants {
        let mut vr = VariantResult::new(name);
        let reqs: Vec<Req> = (0..n).map(|i| make_req(&env, qid_base + i as u64, last)).collect();
        qid_base += n as u64;
        for r in env.submit(reqs.iter().map(|q| authorize(&env, q, last, Mode::Current)).collect()) {
            vr.control(r.is_ok());
        }
        let attacks: Vec<Req> = (0..n).map(|i| make_req(&env, qid_base + i as u64, last)).collect();
        qid_base += n as u64;
        let txs: Vec<Tx> = attacks
            .iter()
            .enumerate()
            .map(|(i, q)| {
                let (e, om, mode) = make(&env, last, i as u64, i);
                Tx::Authorize { rid: q.rid, pred_hash: q.pred, e, omega: om, mode }
            })
            .collect();
        let names: Vec<String> = txs.iter().take(3).map(tx_name).collect();
        let res = env.submit(txs);
        for (i, r) in res.into_iter().enumerate() {
            vr.record(r.is_ok(), r.err().map(|e| e.reason()), || {
                format!("{} accepted with an Omega that is not State[{}].Omega", names.get(i).cloned().unwrap_or_else(|| "authorize".into()), last)
            });
        }
        out.push(vr);
    }
    // ---- 2d stale_epoch_current: correct Omega of an old epoch, Current mode. Control: same in Historical mode.
    {
        let mut vr = VariantResult::new("stale_epoch_current");
        let old = last - 1;
        let ctl: Vec<Req> = (0..n).map(|i| make_req(&env, qid_base + i as u64, old)).collect();
        qid_base += n as u64;
        for r in env.submit(ctl.iter().map(|q| authorize(&env, q, old, Mode::Historical)).collect()) {
            vr.control(r.is_ok());
        }
        let reqs: Vec<Req> = (0..n).map(|i| make_req(&env, qid_base + i as u64, old)).collect();
        qid_base += n as u64;
        let res = env.submit(reqs.iter().map(|q| authorize(&env, q, old, Mode::Current)).collect());
        for (q, r) in reqs.iter().zip(res) {
            vr.record(r.is_ok(), r.err().map(|e| e.reason()), || {
                format!("authorize(rid={}, e={}, Current) accepted while e_last={}", short(&q.rid), old, last)
            });
        }
        out.push(vr);
    }

    // ---- 3 predicate_changed: authorize p; consume with p' != p. Control: consume with p.
    {
        let mut vr = VariantResult::new("predicate_changed");
        let ctl: Vec<Req> = (0..n).map(|i| make_req(&env, qid_base + i as u64, last)).collect();
        qid_base += n as u64;
        for r in env.submit(ctl.iter().map(|q| authorize(&env, q, last, Mode::Current)).collect()) {
            vr.control(r.is_ok());
        }
        for r in env.submit(ctl.iter().map(|q| Tx::Consume { rid: q.rid, pred_hash: q.pred }).collect()) {
            vr.control(r.is_ok());
        }
        let reqs: Vec<Req> = (0..n).map(|i| make_req(&env, qid_base + i as u64, last)).collect();
        qid_base += n as u64;
        for r in env.submit(reqs.iter().map(|q| authorize(&env, q, last, Mode::Current)).collect()) {
            vr.control(r.is_ok());
        }
        let res = env.submit(
            reqs.iter().enumerate().map(|(i, q)| Tx::Consume { rid: q.rid, pred_hash: h(&[b"changed-predicate", &u64b(i as u64)]) }).collect(),
        );
        for (q, r) in reqs.iter().zip(res) {
            vr.record(r.is_ok(), r.err().map(|e| e.reason()), || {
                format!("authorize(p) ok; consume(rid={}) with a different predicate hash was accepted", short(&q.rid))
            });
        }
        out.push(vr);
    }

    // ---- 3b predicate_changed_new_rid: the paper's own route. Changing the predicate changes d_Q, hence B_Q and
    // RID_Q = H(PRIV||QID||B_Q||Auth), so the contract sees a RID that was never authorized.
    // (The attacker reuses the old Auth_TAC; a fresh one for the new B_Q would need t TAC members.)
    {
        let mut vr = VariantResult::new("predicate_changed_new_rid");
        let qids: Vec<u64> = (0..n as u64).map(|i| qid_base + i).collect();
        let reqs: Vec<Req> = qids.iter().map(|&q| make_req(&env, q, last)).collect();
        for r in env.submit(reqs.iter().map(|q| authorize(&env, q, last, Mode::Current)).collect()) {
            vr.control(r.is_ok());
        }
        let forged: Vec<Req> = qids.iter().map(|&q| make_req_with(&env, q, last, h(&[b"changed-predicate", &u64b(q)]))).collect();
        let res = env.submit(forged.iter().map(|q| Tx::Consume { rid: q.rid, pred_hash: q.pred }).collect());
        for (q, r) in forged.iter().zip(res) {
            vr.record(r.is_ok(), r.err().map(|e| e.reason()), || {
                format!("consume(rid={}) accepted: RID re-derived for a changed predicate was never authorized", short(&q.rid))
            });
        }
        out.push(vr);
    }

    // ---- 4 omitted authenticated block. The verifier reads State[e] from the ledger with a QC proof.
    let e_check = last;
    let key = key_state(e_check);
    let rp = env.led.read_state(&key).expect("State[e] present");
    let read_ok = verify_read(&rp, &env.led.validator_vks, env.led.cfg.quorum());
    assert!(read_ok, "verified read of State[e] must succeed");
    let entry = dec_state(&rp.value);
    let ep = env.chain.epoch(e_check).clone();
    let honest = audit::honest_response(&ep);
    let defs = env.led.contract().defences();
    {
        let mut vr = VariantResult::new("omit_block");
        for i in 0..n {
            vr.control(audit::verify_response(&entry, e_check, &env.aa_vk, &honest, &defs).is_ok());
            let g = (i % p.g_e) as u64 + 1;
            let r = audit::drop_block(&honest, g);
            let res = audit::verify_response(&entry, e_check, &env.aa_vk, &r, &defs);
            vr.record(res.is_ok(), res.as_ref().err().map(CoverReject::reason), || {
                format!("response for epoch {} with block {} of {} left out was accepted", e_check, g, p.g_e)
            });
        }
        out.push(vr);
    }
    {
        let mut vr = VariantResult::new("forged_shorter_epoch");
        let forged = audit::forge_shorter_epoch(&ep);
        for _ in 0..n {
            vr.control(audit::verify_response(&entry, e_check, &env.aa_vk, &honest, &defs).is_ok());
            let res = audit::verify_response(&entry, e_check, &env.aa_vk, &forged, &defs);
            vr.record(res.is_ok(), res.as_ref().err().map(CoverReject::reason), || {
                format!("self-consistent epoch {} with G={} instead of {} (last block dropped, R_e recomputed) was accepted", e_check, p.g_e - 1, p.g_e)
            });
        }
        out.push(vr);
    }
    debug_assert!(env.led.replica_roots_agree());
    let _ = read_ok;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> Params {
        Params { trials: 30, ..Default::default() }
    }

    #[test]
    fn production_defences_reject_every_attack_and_accept_every_control() {
        let res = run(&small());
        assert_eq!(res.len(), VARIANTS.len());
        for r in &res {
            assert_eq!(r.trials, 30, "{}", r.variant);
            assert_eq!(r.accepted, 0, "{}: {:?}", r.variant, r.traces);
            assert_eq!(r.rejected, 30, "{}", r.variant);
            assert_eq!(r.control_ok, r.control_total, "{}", r.variant);
            assert!(r.control_total >= 30, "{} has a real control", r.variant);
        }
    }

    #[test]
    fn rejection_reasons_are_the_expected_ones() {
        let res = run(&small());
        let reason = |v: &str| res.iter().find(|r| r.variant == v).unwrap().reasons.clone();
        assert_eq!(reason("replay_consume").keys().copied().collect::<Vec<_>>(), vec!["rid_not_in_authorized_state"]);
        assert_eq!(reason("reauthorize_after_consume").keys().copied().collect::<Vec<_>>(), vec!["rid_already_reserved"]);
        assert_eq!(reason("consume_unauthorized").keys().copied().collect::<Vec<_>>(), vec!["rid_not_in_authorized_state"]);
        assert_eq!(reason("wrong_omega_flipbit").keys().copied().collect::<Vec<_>>(), vec!["omega_not_canonical_state"]);
        assert_eq!(reason("wrong_omega_other_epoch").keys().copied().collect::<Vec<_>>(), vec!["omega_not_canonical_state"]);
        assert_eq!(reason("wrong_omega_forked_policy").keys().copied().collect::<Vec<_>>(), vec!["omega_not_canonical_state"]);
        assert_eq!(reason("stale_epoch_current").keys().copied().collect::<Vec<_>>(), vec!["epoch_not_current"]);
        assert_eq!(reason("predicate_changed").keys().copied().collect::<Vec<_>>(), vec!["predicate_hash_mismatch"]);
        assert_eq!(reason("predicate_changed_new_rid").keys().copied().collect::<Vec<_>>(), vec!["rid_not_in_authorized_state"]);
        assert_eq!(reason("omit_block").keys().copied().collect::<Vec<_>>(), vec!["block_domain_not_covered"]);
        assert_eq!(reason("forged_shorter_epoch").keys().copied().collect::<Vec<_>>(), vec!["gamma_not_matching_ledger"]);
    }

    #[test]
    fn switching_off_one_defence_flips_exactly_its_attacks() {
        let p = Params { trials: 20, ..Default::default() };
        for (name, flips) in EXPECTED_FLIPS {
            let res = run_with(&p, Defences::without(name));
            for r in &res {
                let expect = flips.contains(&r.variant);
                if expect {
                    assert_eq!(r.accepted, p.trials, "defence {} off: {} must be accepted", name, r.variant);
                } else {
                    assert_eq!(r.accepted, 0, "defence {} off: {} must stay rejected", name, r.variant);
                }
                assert_eq!(r.control_ok, r.control_total, "defence {} off: controls", name);
            }
        }
    }

    #[test]
    fn every_defence_has_expected_flips_listed() {
        for n in Defences::NAMES {
            assert!(EXPECTED_FLIPS.iter().any(|(d, _)| *d == n), "{}", n);
        }
        for (_, fl) in EXPECTED_FLIPS {
            for v in fl {
                assert!(VARIANTS.iter().any(|x| x.0 == *v));
            }
        }
    }
}
