//! Minimal audit block chain (EAPAT stand-in), self-contained: only what the
//! "authenticated block omitted" rejection check needs.
//!
//! Follows the paper's Phase 3/4 formulas where they are explicit:
//!   B_{e,g} = H(e || g || q_g || q_{g+1} || |G_{e,g}| || R_rec_{e,g} || H(S_{e,g}))
//!   R_e     = MerkleRoot(B_{e,1}, ..., B_{e,G_e})
//!   A_e     = (e, R_e, N_e, G_e, t_e, p_e),  p_e = Gamma_{e-1}
//!   sigma_e = MLDSA.Sign_AA(H(A_e)),         Gamma_e = H(A_e || sigma_e)
//! Records are synthetic (leaf = H("rec"||e||seq)); the protected-search summary
//! S is replaced by a fixed hash since it plays no role in coverage. The PQZK
//! relation R_Exec (BlockCover) is NOT implemented: `verify_response` performs the
//! same coverage test directly on the headers a CSP presents. So this checks the
//! ledger/Merkle side of Corollary 1, not the proof system.

use crate::contract::*;
use crate::hashing::*;
use crate::sig::{self, SigKeys};
use ml_dsa::{MlDsa65, VerifyingKey};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditBlock {
    pub e: u64,
    pub g: u64,
    pub q_start: u64,
    pub q_next: u64,
    pub count: u64,
    pub r_rec: Hash,
    pub s_hash: Hash,
}

impl AuditBlock {
    pub fn commitment(&self) -> Hash {
        h(&[&u64b(self.e), &u64b(self.g), &u64b(self.q_start), &u64b(self.q_next), &u64b(self.count), &self.r_rec, &self.s_hash])
    }
    pub fn leaf(&self) -> Hash {
        leaf_hash(&self.commitment())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochA {
    pub e: u64,
    pub r_e: Hash,
    pub n_e: u64,
    pub g_e: u64,
    pub t_e: u64,
    pub p_e: Hash,
}

impl EpochA {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(96);
        b.extend_from_slice(&u64b(self.e));
        b.extend_from_slice(&self.r_e);
        b.extend_from_slice(&u64b(self.n_e));
        b.extend_from_slice(&u64b(self.g_e));
        b.extend_from_slice(&u64b(self.t_e));
        b.extend_from_slice(&self.p_e);
        b
    }
    pub fn digest(&self) -> Hash {
        h(&[&self.encode()])
    }
}

#[derive(Clone)]
pub struct AuditEpoch {
    pub a: EpochA,
    pub sigma: Vec<u8>,
    pub gamma: Hash,
    pub blocks: Vec<AuditBlock>,
    pub omega: Hash,
}

pub fn make_blocks(e: u64, g_e: usize, recs_per_block: usize, base_seq: u64) -> Vec<AuditBlock> {
    (0..g_e)
        .map(|i| {
            let q_start = base_seq + (i * recs_per_block) as u64;
            let q_next = q_start + recs_per_block as u64;
            let leaves: Vec<Hash> = (q_start..q_next).map(|s| leaf_hash(&h(&[b"rec", &u64b(e), &u64b(s)]))).collect();
            AuditBlock {
                e,
                g: i as u64 + 1,
                q_start,
                q_next,
                count: recs_per_block as u64,
                r_rec: merkle_root(&leaves),
                s_hash: h(&[b"PQZ-summary", &u64b(e), &u64b(i as u64 + 1)]),
            }
        })
        .collect()
}

pub fn epoch_root(blocks: &[AuditBlock]) -> Hash {
    let leaves: Vec<Hash> = blocks.iter().map(|b| b.leaf()).collect();
    merkle_root(&leaves)
}

fn seal(a: EpochA, blocks: Vec<AuditBlock>, aa: &SigKeys, r_pol: &Hash, v_auth: u64) -> AuditEpoch {
    let sigma = aa.sign(&a.digest());
    let gamma = h(&[&a.encode(), &sigma]);
    let omega = omega(a.e, &gamma, r_pol, v_auth);
    AuditEpoch { a, sigma, gamma, blocks, omega }
}

/// Simulated epoch for the "bytes per epoch vs N" experiment: only the epoch root is built
/// from N synthetic record commitments; nothing per-record goes to the ledger.
pub fn root_over_n_records(n: u64) -> Hash {
    let leaves: Vec<Hash> = (0..n).map(|s| leaf_hash(&h(&[b"rec", &u64b(s)]))).collect();
    merkle_root(&leaves)
}

pub struct Chain {
    pub epochs: Vec<AuditEpoch>,
    pub r_pol: Hash,
    pub v_auth: u64,
}

impl Chain {
    pub fn genesis(aa: &SigKeys) -> Chain {
        let r_pol = merkle_root(&[]);
        let a0 = EpochA {
            e: 0,
            r_e: h(&[b"PQZ-Audit-Genesis"]),
            n_e: 0,
            g_e: 0,
            t_e: 0,
            p_e: h(&[b"EAPAT-Genesis"]),
        };
        Chain { epochs: vec![seal(a0, vec![], aa, &r_pol, 0)], r_pol, v_auth: 0 }
    }
    pub fn genesis_contract(&self) -> Contract {
        let g = &self.epochs[0];
        Contract::genesis(g.gamma, self.r_pol)
    }
    /// Close the next epoch with `g_e` blocks of `m` records and return the anchor transaction.
    pub fn next_anchor(&mut self, aa: &SigKeys, g_e: usize, m: usize) -> Tx {
        let prev = self.epochs.last().unwrap().clone();
        let e = prev.a.e + 1;
        let base = prev.a.n_e + 1_000_000 * e; // distinct sequence space per epoch (synthetic)
        let blocks = make_blocks(e, g_e, m, base);
        let a = EpochA { e, r_e: epoch_root(&blocks), n_e: (g_e * m) as u64, g_e: g_e as u64, t_e: e, p_e: prev.gamma };
        let ep = seal(a, blocks, aa, &self.r_pol, self.v_auth);
        let tx = anchor_tx_of(&ep, &prev, &self.r_pol, self.v_auth);
        self.epochs.push(ep);
        tx
    }
    /// Anchor for an epoch whose content is only a root over `n` synthetic records
    /// (used for bytes-vs-N; blocks are not materialised).
    pub fn next_anchor_root_only(&mut self, aa: &SigKeys, root: Hash, n: u64, g_e: u64) -> Tx {
        let prev = self.epochs.last().unwrap().clone();
        let e = prev.a.e + 1;
        let a = EpochA { e, r_e: root, n_e: n, g_e, t_e: e, p_e: prev.gamma };
        let ep = seal(a, vec![], aa, &self.r_pol, self.v_auth);
        let tx = anchor_tx_of(&ep, &prev, &self.r_pol, self.v_auth);
        self.epochs.push(ep);
        tx
    }
    pub fn epoch(&self, e: u64) -> &AuditEpoch {
        &self.epochs[e as usize]
    }
}

fn anchor_tx_of(ep: &AuditEpoch, prev: &AuditEpoch, r_pol: &Hash, v_auth: u64) -> Tx {
    Tx::Anchor { e: ep.a.e, gamma: ep.gamma, p_e: prev.gamma, r_pol: *r_pol, v_auth, omega: ep.omega, omega_prev: prev.omega }
}

/// What a CSP hands a verifier for epoch e: A_e, sigma_e and a membership path per
/// block it claims covers the scope.
#[derive(Clone)]
pub struct Response {
    pub a: EpochA,
    pub sigma: Vec<u8>,
    pub blocks: Vec<(AuditBlock, Vec<Hash>)>,
}

pub fn honest_response(ep: &AuditEpoch) -> Response {
    let leaves: Vec<Hash> = ep.blocks.iter().map(|b| b.leaf()).collect();
    Response {
        a: ep.a.clone(),
        sigma: ep.sigma.clone(),
        blocks: ep.blocks.iter().enumerate().map(|(i, b)| (b.clone(), merkle_path(&leaves, i))).collect(),
    }
}

/// Attack A: present the honest A_e and sigma_e but silently leave block `g` (1-based) out.
pub fn drop_block(resp: &Response, g: u64) -> Response {
    let mut r = resp.clone();
    r.blocks.retain(|(b, _)| b.g != g);
    r
}

/// Attack B: drop the LAST block and present a self-consistent shorter epoch (G-1 blocks,
/// recomputed R_e and N_e) while reusing the genuine sigma_e (the attacker cannot sign).
pub fn forge_shorter_epoch(ep: &AuditEpoch) -> Response {
    let blocks: Vec<AuditBlock> = ep.blocks[..ep.blocks.len() - 1].to_vec();
    let a = EpochA {
        e: ep.a.e,
        r_e: epoch_root(&blocks),
        n_e: blocks.iter().map(|b| b.count).sum(),
        g_e: blocks.len() as u64,
        t_e: ep.a.t_e,
        p_e: ep.a.p_e,
    };
    let leaves: Vec<Hash> = blocks.iter().map(|b| b.leaf()).collect();
    Response {
        a,
        sigma: ep.sigma.clone(),
        blocks: blocks.iter().enumerate().map(|(i, b)| (b.clone(), merkle_path(&leaves, i))).collect(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoverReject {
    EpochMismatch,
    GammaMismatch,
    BadAaSignature,
    BlockForeign,
    BadMembership,
    Incomplete,
    Discontinuous,
    CountMismatch,
}

impl CoverReject {
    pub fn reason(&self) -> &'static str {
        match self {
            CoverReject::EpochMismatch => "epoch_id_mismatch",
            CoverReject::GammaMismatch => "gamma_not_matching_ledger",
            CoverReject::BadAaSignature => "bad_aa_signature",
            CoverReject::BlockForeign => "block_not_in_epoch",
            CoverReject::BadMembership => "bad_merkle_membership",
            CoverReject::Incomplete => "block_domain_not_covered",
            CoverReject::Discontinuous => "sequence_interval_gap",
            CoverReject::CountMismatch => "record_count_mismatch",
        }
    }
}

/// Verifier side. `entry` is State[e] read from the ledger (trusted, e.g. via verify_read).
pub fn verify_response(
    entry: &StateEntry,
    e: u64,
    pk_aa: &VerifyingKey<MlDsa65>,
    resp: &Response,
    def: &Defences,
) -> Result<(), CoverReject> {
    if resp.a.e != e {
        return Err(CoverReject::EpochMismatch);
    }
    if def.anchor_binding {
        // Gamma_e = H(A_e || sigma_e) must equal the ledger value; sigma_e a valid AA signature
        if h(&[&resp.a.encode(), &resp.sigma]) != entry.gamma {
            return Err(CoverReject::GammaMismatch);
        }
        if !sig::verify(pk_aa, &resp.a.digest(), &resp.sigma) {
            return Err(CoverReject::BadAaSignature);
        }
    }
    let g_e = resp.a.g_e as usize;
    for (b, path) in &resp.blocks {
        if b.e != e || b.g == 0 || (b.g as usize) > g_e {
            return Err(CoverReject::BlockForeign);
        }
        if !verify_path(&b.leaf(), b.g as usize - 1, g_e, path, &resp.a.r_e) {
            return Err(CoverReject::BadMembership);
        }
    }
    if def.block_cover {
        let mut gs: Vec<u64> = resp.blocks.iter().map(|(b, _)| b.g).collect();
        gs.sort_unstable();
        if gs.len() != g_e || gs.iter().enumerate().any(|(i, g)| *g != i as u64 + 1) {
            return Err(CoverReject::Incomplete);
        }
        let mut bl: Vec<&AuditBlock> = resp.blocks.iter().map(|(b, _)| b).collect();
        bl.sort_by_key(|b| b.g);
        if bl.windows(2).any(|w| w[0].q_next != w[1].q_start) {
            return Err(CoverReject::Discontinuous);
        }
        if bl.iter().map(|b| b.count).sum::<u64>() != resp.a.n_e {
            return Err(CoverReject::CountMismatch);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (SigKeys, Chain, Contract) {
        let aa = SigKeys::from_seed([1u8; 32]);
        let mut ch = Chain::genesis(&aa);
        let mut c = ch.genesis_contract();
        for _ in 0..3 {
            let tx = ch.next_anchor(&aa, 9, 4);
            c.apply(&tx).unwrap();
        }
        (aa, ch, c)
    }

    #[test]
    fn genesis_and_anchors_chain_through_the_contract() {
        let (_aa, ch, c) = setup();
        for e in 0..=3u64 {
            let st = c.state_entry(e).unwrap();
            assert_eq!(st.gamma, ch.epoch(e).gamma);
            assert_eq!(st.omega, ch.epoch(e).omega);
        }
        assert_eq!(ch.epoch(3).a.p_e, ch.epoch(2).gamma);
    }

    #[test]
    fn honest_response_is_accepted_for_all_epochs_and_sizes() {
        let aa = SigKeys::from_seed([1u8; 32]);
        for g in [1usize, 2, 3, 7, 16] {
            let mut ch = Chain::genesis(&aa);
            let mut c = ch.genesis_contract();
            let tx = ch.next_anchor(&aa, g, 3);
            c.apply(&tx).unwrap();
            let st = c.state_entry(1).unwrap();
            let r = honest_response(ch.epoch(1));
            assert_eq!(verify_response(&st, 1, &aa.vk, &r, &Defences::all()), Ok(()), "g={}", g);
        }
    }

    #[test]
    fn every_single_block_omission_is_rejected_and_accepted_without_block_cover() {
        let (aa, ch, c) = setup();
        let st = c.state_entry(2).unwrap();
        let honest = honest_response(ch.epoch(2));
        for g in 1..=9u64 {
            let r = drop_block(&honest, g);
            let err = verify_response(&st, 2, &aa.vk, &r, &Defences::all()).unwrap_err();
            assert!(matches!(err, CoverReject::Incomplete), "g={} err={:?}", g, err);
            assert_eq!(verify_response(&st, 2, &aa.vk, &r, &Defences::without("block_cover")), Ok(()), "g={}", g);
        }
    }

    #[test]
    fn shorter_forged_epoch_is_rejected_by_anchor_binding_only() {
        let (aa, ch, c) = setup();
        let st = c.state_entry(3).unwrap();
        let r = forge_shorter_epoch(ch.epoch(3));
        assert_eq!(verify_response(&st, 3, &aa.vk, &r, &Defences::all()), Err(CoverReject::GammaMismatch));
        // block_cover alone does not help: the forged epoch is self-consistent
        assert_eq!(verify_response(&st, 3, &aa.vk, &r, &Defences::without("anchor_binding")), Ok(()));
    }

    #[test]
    fn membership_and_epoch_tampering_rejected() {
        let (aa, ch, c) = setup();
        let st = c.state_entry(2).unwrap();
        let d = Defences::all();
        // wrong epoch id presented
        assert_eq!(verify_response(&st, 1, &aa.vk, &honest_response(ch.epoch(2)), &d), Err(CoverReject::EpochMismatch));
        // block content altered but path kept
        let mut r = honest_response(ch.epoch(2));
        r.blocks[3].0.count += 1;
        assert_eq!(verify_response(&st, 2, &aa.vk, &r, &d), Err(CoverReject::BadMembership));
        // a block of another epoch
        let mut r = honest_response(ch.epoch(2));
        r.blocks[0] = honest_response(ch.epoch(1)).blocks[0].clone();
        assert_eq!(verify_response(&st, 2, &aa.vk, &r, &d), Err(CoverReject::BlockForeign));
        // duplicate one block, drop another (same count of entries)
        let mut r = honest_response(ch.epoch(2));
        r.blocks[4] = r.blocks[3].clone();
        assert_eq!(verify_response(&st, 2, &aa.vk, &r, &d), Err(CoverReject::Incomplete));
        // wrong AA key
        let other = SigKeys::from_seed([77u8; 32]);
        assert_eq!(verify_response(&st, 2, &other.vk, &honest_response(ch.epoch(2)), &d), Err(CoverReject::BadAaSignature));
    }

    #[test]
    fn root_only_epoch_anchor_size_does_not_depend_on_n() {
        let aa = SigKeys::from_seed([1u8; 32]);
        let mut ch = Chain::genesis(&aa);
        let t1 = ch.next_anchor_root_only(&aa, root_over_n_records(10), 10, 1);
        let t2 = ch.next_anchor_root_only(&aa, root_over_n_records(1000), 1000, 2);
        assert_eq!(t1.encode().len(), t2.encode().len());
    }
}
