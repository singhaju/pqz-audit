//! Governance contract: the deterministic state machine that every validator
//! replicates. It implements the paper's Phase 4 anchor transition and the
//! single-use lifecycle  Priv[RID] : (none) -> Authorized -> Consumed
//! (Phase 5 step 3, Phase 7 step 3), plus a per-record commitment transaction
//! used only by the internal "per-record on-chain" baseline.
//!
//! Off-chain parts of the protocol (TAC approval, PQZK proofs) are NOT checked
//! here: the contract sees only the hashes the paper puts on-chain.
//!
//! Every check is guarded by a flag of `Defences`. In production code the flags
//! are always on (`Contract::genesis`); switching one off is possible only in
//! test builds or with the `mutation` feature, so that the rejection harness can
//! be shown to fail when a defence is removed.

use crate::hashing::*;
use crate::statemap::StateMap;

pub const LBL_CAAS: &[u8] = b"PQZA-CAAS";
pub const LBL_PRIV: &[u8] = b"PQZA-PRIV";
pub const LBL_AUTH: &[u8] = b"PQZA-AUTH";

/// Switches for single defences (mutation testing). All `true` = the real system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Defences {
    /// authorize requires Priv[RID] = none (no re-reservation of a used RID)
    pub reservation_unique: bool,
    /// consume requires Priv[RID] = Authorized (no second consume, no unknown RID)
    pub single_use: bool,
    /// authorize requires the presented Omega to equal the canonical State[e].Omega
    pub omega_equality: bool,
    /// authorize in mode Current requires e = e_last
    pub current_freshness: bool,
    /// consume requires the predicate hash to equal the one authorized
    pub predicate_binding: bool,
    /// verifier requires every authenticated block 1..G_e to be present (audit.rs)
    pub block_cover: bool,
    /// verifier binds A_e to the ledger (Gamma_e = H(A_e||sigma_e)) and checks the AA signature (audit.rs)
    pub anchor_binding: bool,
}

impl Defences {
    pub const fn all() -> Self {
        Defences {
            reservation_unique: true,
            single_use: true,
            omega_equality: true,
            current_freshness: true,
            predicate_binding: true,
            block_cover: true,
            anchor_binding: true,
        }
    }
    pub const NAMES: [&'static str; 7] = [
        "reservation_unique",
        "single_use",
        "omega_equality",
        "current_freshness",
        "predicate_binding",
        "block_cover",
        "anchor_binding",
    ];
    /// Copy with the defence called `name` switched off.
    pub fn without(name: &str) -> Self {
        let mut d = Self::all();
        match name {
            "reservation_unique" => d.reservation_unique = false,
            "single_use" => d.single_use = false,
            "omega_equality" => d.omega_equality = false,
            "current_freshness" => d.current_freshness = false,
            "predicate_binding" => d.predicate_binding = false,
            "block_cover" => d.block_cover = false,
            "anchor_binding" => d.anchor_binding = false,
            _ => panic!("unknown defence {}", name),
        }
        d
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Current = 0,
    Historical = 1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tx {
    /// Phase 4 step 3, Eq. (anchor-transaction), PLUS p_e (see DESIGN.md: the paper's
    /// Tx_e omits p_e although the contract is said to check p_e = Gamma_last).
    Anchor { e: u64, gamma: Hash, p_e: Hash, r_pol: Hash, v_auth: u64, omega: Hash, omega_prev: Hash },
    /// Phase 5 step 3: Priv[RID] := Authorized, bound to predicate hash and canonical state.
    Authorize { rid: Hash, pred_hash: Hash, e: u64, omega: Hash, mode: Mode },
    /// Phase 7 step 3: Priv[RID] : Authorized -> Consumed.
    Consume { rid: Hash, pred_hash: Hash },
    /// Internal baseline only: one record commitment on-chain.
    CommitRecord { e: u64, i: u64, c: Hash },
}

impl Tx {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Tx::Anchor { e, gamma, p_e, r_pol, v_auth, omega, omega_prev } => {
                b.push(1);
                b.extend_from_slice(&u64b(*e));
                b.extend_from_slice(gamma);
                b.extend_from_slice(p_e);
                b.extend_from_slice(r_pol);
                b.extend_from_slice(&u64b(*v_auth));
                b.extend_from_slice(omega);
                b.extend_from_slice(omega_prev);
            }
            Tx::Authorize { rid, pred_hash, e, omega, mode } => {
                b.push(2);
                b.extend_from_slice(rid);
                b.extend_from_slice(pred_hash);
                b.extend_from_slice(&u64b(*e));
                b.extend_from_slice(omega);
                b.push(*mode as u8);
            }
            Tx::Consume { rid, pred_hash } => {
                b.push(3);
                b.extend_from_slice(rid);
                b.extend_from_slice(pred_hash);
            }
            Tx::CommitRecord { e, i, c } => {
                b.push(4);
                b.extend_from_slice(&u64b(*e));
                b.extend_from_slice(&u64b(*i));
                b.extend_from_slice(c);
            }
        }
        b
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Tx::Anchor { .. } => "anchor",
            Tx::Authorize { .. } => "authorize",
            Tx::Consume { .. } => "consume",
            Tx::CommitRecord { .. } => "commit_record",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    BadSignature,
    BadEpoch,
    BadPredecessor,
    BadOmegaPrev,
    EpochExists,
    OmegaRecompute,
    RidExists,
    UnknownEpoch,
    OmegaNotCanonical,
    NotCurrent,
    NotAuthorized,
    PredicateMismatch,
    DuplicateRecord,
    NoQuorum,
}

impl Reject {
    pub fn reason(&self) -> &'static str {
        match self {
            Reject::BadSignature => "bad_tx_signature",
            Reject::BadEpoch => "epoch_not_last_plus_one",
            Reject::BadPredecessor => "predecessor_gamma_mismatch",
            Reject::BadOmegaPrev => "omega_prev_mismatch",
            Reject::EpochExists => "state_e_already_set",
            Reject::OmegaRecompute => "omega_recompute_mismatch",
            Reject::RidExists => "rid_already_reserved",
            Reject::UnknownEpoch => "unknown_epoch",
            Reject::OmegaNotCanonical => "omega_not_canonical_state",
            Reject::NotCurrent => "epoch_not_current",
            Reject::NotAuthorized => "rid_not_in_authorized_state",
            Reject::PredicateMismatch => "predicate_hash_mismatch",
            Reject::DuplicateRecord => "record_already_committed",
            Reject::NoQuorum => "no_quorum",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Authorized = 1,
    Consumed = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateEntry {
    pub gamma: Hash,
    pub r_pol: Hash,
    pub v_auth: u64,
    pub omega: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivEntry {
    pub status: Status,
    pub pred_hash: Hash,
    pub omega: Hash,
    pub e: u64,
    pub mode: Mode,
}

/// Paper Eq. (caas-state): Omega_e = H("PQZA-CAAS" || e || Gamma_e || R_pol || v_auth).
/// Integers are 8-byte big-endian (our encoding choice; the paper fixes none).
pub fn omega(e: u64, gamma: &Hash, r_pol: &Hash, v_auth: u64) -> Hash {
    h(&[LBL_CAAS, &u64b(e), gamma, r_pol, &u64b(v_auth)])
}

/// Paper Eq. (authorization-binding), simplified: d_Q is passed in, one canonical state.
pub fn binding_bq(d_q: &Hash, uid: u64, v_a: u64, r_pol: &Hash, v_auth: u64, omega_q: &Hash) -> Hash {
    h(&[LBL_AUTH, d_q, &u64b(uid), &u64b(v_a), r_pol, &u64b(v_auth), omega_q])
}

/// d_Q stand-in: the paper's d_Q = H(Q || H(TK_Q)); here H(QID || predicate hash).
pub fn d_q(qid: u64, pred_hash: &Hash) -> Hash {
    h(&[b"PQZA-Q", &u64b(qid), pred_hash])
}

/// Paper Eq. (privileged-request-id): RID_Q = H("PQZA-PRIV" || QID || B_Q || Auth_TAC).
pub fn derive_rid(qid: u64, b_q: &Hash, auth_tac: &Hash) -> Hash {
    h(&[LBL_PRIV, &u64b(qid), b_q, auth_tac])
}

pub fn key_state(e: u64) -> Vec<u8> {
    let mut k = b"state/".to_vec();
    k.extend_from_slice(&u64b(e));
    k
}
pub fn key_priv(rid: &Hash) -> Vec<u8> {
    let mut k = b"priv/".to_vec();
    k.extend_from_slice(rid);
    k
}
pub fn key_rec(e: u64, i: u64) -> Vec<u8> {
    let mut k = b"rec/".to_vec();
    k.extend_from_slice(&u64b(e));
    k.extend_from_slice(&u64b(i));
    k
}
const KEY_LAST: &[u8] = b"meta/last";

#[derive(Clone)]
pub struct Contract {
    pub state: StateMap,
    def: Defences,
}

pub fn enc_state(s: &StateEntry) -> Vec<u8> {
    let mut b = Vec::with_capacity(104);
    b.extend_from_slice(&s.gamma);
    b.extend_from_slice(&s.r_pol);
    b.extend_from_slice(&u64b(s.v_auth));
    b.extend_from_slice(&s.omega);
    b
}
pub fn dec_state(b: &[u8]) -> StateEntry {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[64..72]);
    StateEntry {
        gamma: b[0..32].try_into().unwrap(),
        r_pol: b[32..64].try_into().unwrap(),
        v_auth: u64::from_be_bytes(v),
        omega: b[72..104].try_into().unwrap(),
    }
}
fn enc_priv(p: &PrivEntry) -> Vec<u8> {
    let mut b = Vec::with_capacity(74);
    b.push(p.status as u8);
    b.extend_from_slice(&p.pred_hash);
    b.extend_from_slice(&p.omega);
    b.extend_from_slice(&u64b(p.e));
    b.push(p.mode as u8);
    b
}
fn dec_priv(b: &[u8]) -> PrivEntry {
    let mut e = [0u8; 8];
    e.copy_from_slice(&b[65..73]);
    PrivEntry {
        status: if b[0] == 1 { Status::Authorized } else { Status::Consumed },
        pred_hash: b[1..33].try_into().unwrap(),
        omega: b[33..65].try_into().unwrap(),
        e: u64::from_be_bytes(e),
        mode: if b[73] == 0 { Mode::Current } else { Mode::Historical },
    }
}

impl Contract {
    /// Genesis (paper Phase 1 step 4): State[0] and (e_last, Gamma_last, Omega_last) = (0, Gamma_0, Omega_0),
    /// empty Priv registry. Production defences.
    pub fn genesis(gamma0: Hash, r_pol0: Hash) -> Self {
        let mut c = Contract { state: StateMap::new(), def: Defences::all() };
        let om = omega(0, &gamma0, &r_pol0, 0);
        c.state.put(&key_state(0), &enc_state(&StateEntry { gamma: gamma0, r_pol: r_pol0, v_auth: 0, omega: om }));
        c.set_last(0, &gamma0, &om);
        c
    }

    #[cfg(any(test, feature = "mutation"))]
    pub fn with_defences(mut self, d: Defences) -> Self {
        self.def = d;
        self
    }

    pub fn defences(&self) -> Defences {
        self.def
    }

    fn set_last(&mut self, e: u64, gamma: &Hash, om: &Hash) {
        let mut b = Vec::with_capacity(72);
        b.extend_from_slice(&u64b(e));
        b.extend_from_slice(gamma);
        b.extend_from_slice(om);
        self.state.put(KEY_LAST, &b);
    }

    /// (e_last, Gamma_last, Omega_last)
    pub fn last(&self) -> (u64, Hash, Hash) {
        let b = self.state.get(KEY_LAST).expect("genesis missing");
        let mut e = [0u8; 8];
        e.copy_from_slice(&b[0..8]);
        (u64::from_be_bytes(e), b[8..40].try_into().unwrap(), b[40..72].try_into().unwrap())
    }

    pub fn state_entry(&self, e: u64) -> Option<StateEntry> {
        self.state.get(&key_state(e)).map(dec_state)
    }

    pub fn priv_entry(&self, rid: &Hash) -> Option<PrivEntry> {
        self.state.get(&key_priv(rid)).map(dec_priv)
    }

    /// Apply one transaction. Check-then-write: on Err nothing was written.
    pub fn apply(&mut self, tx: &Tx) -> Result<(), Reject> {
        match tx {
            Tx::Anchor { e, gamma, p_e, r_pol, v_auth, omega: om, omega_prev } => {
                let (e_last, g_last, om_last) = self.last();
                if *e != e_last + 1 {
                    return Err(Reject::BadEpoch);
                }
                if p_e != &g_last {
                    return Err(Reject::BadPredecessor);
                }
                if omega_prev != &om_last {
                    return Err(Reject::BadOmegaPrev);
                }
                if self.state_entry(*e).is_some() {
                    return Err(Reject::EpochExists);
                }
                if *om != omega(*e, gamma, r_pol, *v_auth) {
                    return Err(Reject::OmegaRecompute);
                }
                self.state.put(&key_state(*e), &enc_state(&StateEntry { gamma: *gamma, r_pol: *r_pol, v_auth: *v_auth, omega: *om }));
                self.set_last(*e, gamma, om);
                Ok(())
            }
            Tx::Authorize { rid, pred_hash, e, omega: om, mode } => {
                if self.def.reservation_unique && self.priv_entry(rid).is_some() {
                    return Err(Reject::RidExists);
                }
                let st = self.state_entry(*e).ok_or(Reject::UnknownEpoch)?;
                if self.def.omega_equality && &st.omega != om {
                    return Err(Reject::OmegaNotCanonical);
                }
                if *mode == Mode::Current && self.def.current_freshness && *e != self.last().0 {
                    return Err(Reject::NotCurrent);
                }
                let p = PrivEntry { status: Status::Authorized, pred_hash: *pred_hash, omega: *om, e: *e, mode: *mode };
                self.state.put(&key_priv(rid), &enc_priv(&p));
                Ok(())
            }
            Tx::Consume { rid, pred_hash } => {
                let cur = self.priv_entry(rid);
                if self.def.single_use {
                    match &cur {
                        Some(p) if p.status == Status::Authorized => {}
                        _ => return Err(Reject::NotAuthorized),
                    }
                }
                let (omega_b, e_b, mode_b) = match &cur {
                    Some(p) => {
                        if self.def.predicate_binding && &p.pred_hash != pred_hash {
                            return Err(Reject::PredicateMismatch);
                        }
                        (p.omega, p.e, p.mode)
                    }
                    None => ([0u8; 32], 0, Mode::Historical), // only reachable with single_use off
                };
                let p = PrivEntry { status: Status::Consumed, pred_hash: *pred_hash, omega: omega_b, e: e_b, mode: mode_b };
                self.state.put(&key_priv(rid), &enc_priv(&p));
                Ok(())
            }
            Tx::CommitRecord { e, i, c } => {
                let k = key_rec(*e, *i);
                if self.state.get(&k).is_some() {
                    return Err(Reject::DuplicateRecord);
                }
                self.state.put(&k, c);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> (Contract, Hash, Hash) {
        let g0 = h(&[b"gamma0"]);
        let rp = h(&[]);
        (Contract::genesis(g0, rp), g0, rp)
    }

    fn anchor(c: &Contract, e: u64, tag: &[u8]) -> Tx {
        let (_, g_last, om_last) = c.last();
        let gamma = h(&[b"gamma", &u64b(e), tag]);
        let r_pol = h(&[]);
        Tx::Anchor { e, gamma, p_e: g_last, r_pol, v_auth: 0, omega: omega(e, &gamma, &r_pol, 0), omega_prev: om_last }
    }

    #[test]
    fn anchor_chain_accepts_and_rejects_per_paper_eq_blockchain_transition() {
        let (mut c, _, _) = fresh();
        let a1 = anchor(&c, 1, b"x");
        assert_eq!(c.apply(&a1), Ok(()));
        assert_eq!(c.last().0, 1);
        // replay of the same anchor: epoch no longer last+1
        assert_eq!(c.apply(&a1), Err(Reject::BadEpoch));
        // skip an epoch
        let a3 = anchor(&c, 3, b"x");
        assert_eq!(c.apply(&a3), Err(Reject::BadEpoch));
        // wrong predecessor (fork)
        let mut a2 = anchor(&c, 2, b"x");
        if let Tx::Anchor { p_e, .. } = &mut a2 {
            p_e[0] ^= 1;
        }
        assert_eq!(c.apply(&a2), Err(Reject::BadPredecessor));
        // wrong omega_prev (rollback to a different canonical state)
        let mut a2 = anchor(&c, 2, b"x");
        if let Tx::Anchor { omega_prev, .. } = &mut a2 {
            omega_prev[0] ^= 1;
        }
        assert_eq!(c.apply(&a2), Err(Reject::BadOmegaPrev));
        // omega not matching recomputation
        let mut a2 = anchor(&c, 2, b"x");
        if let Tx::Anchor { omega: o, .. } = &mut a2 {
            o[0] ^= 1;
        }
        assert_eq!(c.apply(&a2), Err(Reject::OmegaRecompute));
        // failed applies wrote nothing
        assert_eq!(c.last().0, 1);
        assert!(c.state_entry(2).is_none());
        // good one still works
        assert_eq!(c.apply(&anchor(&c, 2, b"x")), Ok(()));
    }

    #[test]
    fn lifecycle_none_authorized_consumed() {
        let (mut c, _, _) = fresh();
        c.apply(&anchor(&c, 1, b"x")).unwrap();
        let om1 = c.state_entry(1).unwrap().omega;
        let rid = h(&[b"rid1"]);
        let p = h(&[b"pred"]);
        assert!(c.priv_entry(&rid).is_none());
        let auth = Tx::Authorize { rid, pred_hash: p, e: 1, omega: om1, mode: Mode::Current };
        assert_eq!(c.apply(&auth), Ok(()));
        assert_eq!(c.priv_entry(&rid).unwrap().status, Status::Authorized);
        assert_eq!(c.apply(&auth), Err(Reject::RidExists));
        let cons = Tx::Consume { rid, pred_hash: p };
        assert_eq!(c.apply(&cons), Ok(()));
        assert_eq!(c.priv_entry(&rid).unwrap().status, Status::Consumed);
        assert_eq!(c.apply(&cons), Err(Reject::NotAuthorized));
        assert_eq!(c.apply(&auth), Err(Reject::RidExists));
        // unknown RID
        assert_eq!(c.apply(&Tx::Consume { rid: h(&[b"nope"]), pred_hash: p }), Err(Reject::NotAuthorized));
    }

    #[test]
    fn authorize_checks_state_binding_and_freshness() {
        let (mut c, _, _) = fresh();
        c.apply(&anchor(&c, 1, b"x")).unwrap();
        c.apply(&anchor(&c, 2, b"x")).unwrap();
        let om1 = c.state_entry(1).unwrap().omega;
        let om2 = c.state_entry(2).unwrap().omega;
        let p = h(&[b"pred"]);
        let mk = |n: &[u8], e, o, m| Tx::Authorize { rid: h(&[n]), pred_hash: p, e, omega: o, mode: m };
        assert_eq!(c.apply(&mk(b"a", 2, om2, Mode::Current)), Ok(()));
        assert_eq!(c.apply(&mk(b"b", 2, om1, Mode::Current)), Err(Reject::OmegaNotCanonical));
        assert_eq!(c.apply(&mk(b"c", 1, om1, Mode::Current)), Err(Reject::NotCurrent));
        assert_eq!(c.apply(&mk(b"d", 1, om1, Mode::Historical)), Ok(()));
        assert_eq!(c.apply(&mk(b"e", 9, om1, Mode::Historical)), Err(Reject::UnknownEpoch));
    }

    #[test]
    fn consume_checks_predicate() {
        let (mut c, _, _) = fresh();
        c.apply(&anchor(&c, 1, b"x")).unwrap();
        let om1 = c.state_entry(1).unwrap().omega;
        let rid = h(&[b"r"]);
        c.apply(&Tx::Authorize { rid, pred_hash: h(&[b"p"]), e: 1, omega: om1, mode: Mode::Current }).unwrap();
        assert_eq!(c.apply(&Tx::Consume { rid, pred_hash: h(&[b"p2"]) }), Err(Reject::PredicateMismatch));
        assert_eq!(c.priv_entry(&rid).unwrap().status, Status::Authorized);
        assert_eq!(c.apply(&Tx::Consume { rid, pred_hash: h(&[b"p"]) }), Ok(()));
    }

    #[test]
    fn each_defence_flag_switches_exactly_its_check_off() {
        // sanity for the mutation hook: with the flag off the bad tx passes
        let (c0, _, _) = fresh();
        let mut c = c0.clone().with_defences(Defences::without("omega_equality"));
        c.apply(&anchor(&c, 1, b"x")).unwrap();
        let bad = Tx::Authorize { rid: h(&[b"q"]), pred_hash: h(&[b"p"]), e: 1, omega: h(&[b"junk"]), mode: Mode::Current };
        assert_eq!(c.apply(&bad), Ok(()));
        let mut c = c0.with_defences(Defences::all());
        c.apply(&anchor(&c, 1, b"x")).unwrap();
        assert_eq!(c.apply(&bad), Err(Reject::OmegaNotCanonical));
    }
}
