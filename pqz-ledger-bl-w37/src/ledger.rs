//! In-process permissioned-ledger SIMULATION: a BFT-style ordered log.
//!
//! WHAT IS SIMULATED: n validators, each with its own replica of the contract
//! state; a round-robin leader per height executes the transactions, proposes a
//! block (header with tx Merkle root and state Merkle root) and signs it with
//! ML-DSA-65; every other validator verifies the proposal signature and the
//! transaction signatures, re-executes the block on its own replica, compares
//! the state root and, if equal, signs a vote. A block is final once a quorum
//! (n - f with f = (n-1)/3 faults tolerated: 2f+1 for n = 3f+1) of valid votes
//! is held (the quorum certificate, QC).
//!
//! WHAT IS NOT: no network (zero latency, no loss, no reordering), no view change
//! or leader timeout, no mempool, no gossip, no real concurrency (validators run
//! one after another on one thread). Measured time is therefore computation
//! (hashing, state execution, ML-DSA sign/verify) only, and is NOT the latency
//! or throughput of consensus over a network. Faulty validators exist only as
//! the test switches `offline` and `tamper_state_root`.

use crate::contract::*;
use crate::hashing::*;
use crate::sig::{self, SigKeys, SIG_BYTES};
use crate::statemap::{leaf_of, Proof};
use ml_dsa::{MlDsa65, VerifyingKey};
use std::time::Instant;

pub const LBL_TX: &[u8] = b"PQZ-TX";
pub const LBL_BLK: &[u8] = b"PQZ-BLK";
pub const LBL_VOTE: &[u8] = b"PQZ-VOTE";

#[derive(Clone, Copy, Debug)]
pub struct LedgerConfig {
    pub n_validators: usize,
    pub max_block_txs: usize,
    /// every transaction carries a submitter ML-DSA-65 signature that validators verify
    pub tx_auth: bool,
}

impl LedgerConfig {
    pub fn f(&self) -> usize {
        (self.n_validators - 1) / 3
    }
    pub fn quorum(&self) -> usize {
        (self.n_validators + self.f()) / 2 + 1
    }
}

impl Default for LedgerConfig {
    fn default() -> Self {
        LedgerConfig { n_validators: 4, max_block_txs: 100, tx_auth: true }
    }
}

#[derive(Clone, Debug)]
pub struct SignedTx {
    pub tx: Tx,
    pub submitter: u16,
    pub sig: Vec<u8>,
}

impl SignedTx {
    fn msg(tx: &Tx, submitter: u16) -> Vec<u8> {
        let mut m = LBL_TX.to_vec();
        m.extend_from_slice(&submitter.to_be_bytes());
        m.extend_from_slice(&tx.encode());
        m
    }
    /// Client-side signing (excluded from ledger timings).
    pub fn sign(tx: Tx, submitter: u16, keys: &SigKeys, cfg: &LedgerConfig) -> Self {
        let sig = if cfg.tx_auth { keys.sign(&Self::msg(&tx, submitter)) } else { Vec::new() };
        SignedTx { tx, submitter, sig }
    }
    pub fn digest(&self) -> Hash {
        h(&[LBL_TX, &self.tx.encode()])
    }
    pub fn body_bytes(&self) -> usize {
        self.tx.encode().len() + 2
    }
    pub fn sig_bytes(&self) -> usize {
        self.sig.len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub height: u64,
    pub prev: Hash,
    pub tx_root: Hash,
    pub state_root: Hash,
    pub proposer: u16,
    pub n_txs: u32,
}

pub const HEADER_BYTES: usize = 8 + 32 + 32 + 32 + 2 + 4;

impl BlockHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEADER_BYTES);
        b.extend_from_slice(&u64b(self.height));
        b.extend_from_slice(&self.prev);
        b.extend_from_slice(&self.tx_root);
        b.extend_from_slice(&self.state_root);
        b.extend_from_slice(&self.proposer.to_be_bytes());
        b.extend_from_slice(&self.n_txs.to_be_bytes());
        b
    }
    pub fn hash(&self) -> Hash {
        h(&[LBL_BLK, &self.encode()])
    }
}

fn vote_msg(block_hash: &Hash) -> Vec<u8> {
    let mut m = LBL_VOTE.to_vec();
    m.extend_from_slice(block_hash);
    m
}

#[derive(Clone, Debug)]
pub struct Vote {
    pub validator: u16,
    pub sig: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<SignedTx>,
    /// the quorum certificate (includes the proposer's own vote)
    pub qc: Vec<Vote>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockBytes {
    pub header: usize,
    pub tx_body: usize,
    pub tx_sig: usize,
    pub qc: usize,
}

impl BlockBytes {
    pub fn total(&self) -> usize {
        self.header + self.tx_body + self.tx_sig + self.qc
    }
    pub fn add(&mut self, o: &BlockBytes) {
        self.header += o.header;
        self.tx_body += o.tx_body;
        self.tx_sig += o.tx_sig;
        self.qc += o.qc;
    }
}

impl Block {
    pub fn bytes(&self) -> BlockBytes {
        BlockBytes {
            header: HEADER_BYTES,
            tx_body: self.txs.iter().map(|t| t.body_bytes()).sum(),
            tx_sig: self.txs.iter().map(|t| t.sig_bytes()).sum(),
            qc: self.qc.iter().map(|v| 2 + v.sig.len()).sum(),
        }
    }
}

/// Phase times of one block, measured with `Instant`, all validators in sequence.
#[derive(Clone, Debug, Default)]
pub struct BlockTiming {
    pub txs_proposed: usize,
    pub committed: bool,
    /// leader: tx signature checks + execution + state root + proposal signature
    pub leader_ns: u64,
    /// each non-leader validator (index order): proposal verify + tx verify + re-execution + state root + vote signature
    pub validator_ns: Vec<u64>,
    /// leader: verification of the votes it needs to reach the quorum
    pub qc_verify_ns: u64,
    pub total_ns: u64,
}

impl BlockTiming {
    pub fn validator_sum_ns(&self) -> u64 {
        self.validator_ns.iter().sum()
    }
    /// Latency if validators ran in parallel with zero network delay: leader work, then the
    /// (quorum-1)-th fastest other validator, then the leader's QC verification. Derived from
    /// the measured per-validator times; NOT a measurement of a real deployment.
    pub fn crit_path_ns(&self, quorum: usize) -> u64 {
        let mut v = self.validator_ns.clone();
        v.sort_unstable();
        let need = quorum.saturating_sub(1);
        let wait = if need == 0 { 0 } else { v.get(need - 1).copied().unwrap_or(0) };
        self.leader_ns + wait + self.qc_verify_ns
    }
}

#[derive(Clone, Debug)]
pub struct TxReceipt {
    pub result: Result<(), Reject>,
    pub height: Option<u64>,
    /// ns from the start of `submit` to the moment the tx was committed or rejected
    pub latency_ns: u64,
}

#[derive(Debug)]
pub struct SubmitResult {
    pub receipts: Vec<TxReceipt>,
    pub blocks: Vec<BlockTiming>,
    pub total_ns: u64,
}

pub struct ReadProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub proof: Proof,
    pub header: BlockHeader,
    pub qc: Vec<Vote>,
}

pub struct Ledger {
    pub cfg: LedgerConfig,
    validators: Vec<SigKeys>,
    pub validator_vks: Vec<VerifyingKey<MlDsa65>>,
    submitter_vks: Vec<VerifyingKey<MlDsa65>>,
    replicas: Vec<Contract>,
    pub chain: Vec<Block>,
    genesis_header: BlockHeader,
    /// TEST SWITCH: validators that never answer
    pub offline: Vec<bool>,
    /// TEST SWITCH: the leader proposes a block whose state root is wrong
    pub tamper_state_root: bool,
}

impl Ledger {
    /// `seed` derives the validator keys (benchmarks only).
    pub fn new(cfg: LedgerConfig, genesis: Contract, submitter_vks: Vec<VerifyingKey<MlDsa65>>, seed: [u8; 32]) -> Self {
        assert!(cfg.n_validators >= 4, "need n >= 4 for f >= 1");
        let validators: Vec<SigKeys> =
            (0..cfg.n_validators).map(|j| SigKeys::from_seed(h(&[b"validator", &seed, &u64b(j as u64)]))).collect();
        let validator_vks = validators.iter().map(|k| k.vk.clone()).collect();
        let mut replicas = vec![genesis; cfg.n_validators];
        let root0 = replicas[0].state.root();
        let genesis_header = BlockHeader { height: 0, prev: [0u8; 32], tx_root: merkle_root(&[]), state_root: root0, proposer: 0, n_txs: 0 };
        let n = cfg.n_validators;
        Ledger { cfg, validators, validator_vks, submitter_vks, replicas, chain: vec![], genesis_header, offline: vec![false; n], tamper_state_root: false }
    }

    pub fn height(&self) -> u64 {
        self.chain.len() as u64
    }
    fn prev_hash(&self) -> Hash {
        match self.chain.last() {
            Some(b) => b.header.hash(),
            None => self.genesis_header.hash(),
        }
    }
    /// Read-only view of the canonical contract state (replica 0).
    pub fn contract(&self) -> &Contract {
        &self.replicas[0]
    }
    pub fn replica_roots_agree(&mut self) -> bool {
        let r0 = self.replicas[0].state.root();
        (1..self.replicas.len()).all(|j| self.replicas[j].state.root() == r0)
    }
    pub fn total_bytes(&self) -> BlockBytes {
        let mut t = BlockBytes::default();
        for b in &self.chain {
            t.add(&b.bytes());
        }
        t
    }

    fn check_tx_sig(&self, t: &SignedTx) -> bool {
        if !self.cfg.tx_auth {
            return true;
        }
        match self.submitter_vks.get(t.submitter as usize) {
            Some(vk) => sig::verify(vk, &SignedTx::msg(&t.tx, t.submitter), &t.sig),
            None => false,
        }
    }

    /// Order, execute and finalize `txs` (all submitted at the same instant).
    pub fn submit(&mut self, txs: Vec<SignedTx>) -> SubmitResult {
        let t0 = Instant::now();
        let mut receipts: Vec<Option<TxReceipt>> = vec![None; txs.len()];
        let mut blocks = Vec::new();
        let mut idx = 0usize;
        while idx < txs.len() {
            let end = (idx + self.cfg.max_block_txs).min(txs.len());
            let chunk: Vec<(usize, &SignedTx)> = (idx..end).map(|i| (i, &txs[i])).collect();
            idx = end;
            let (timing, results) = self.run_block(&chunk, t0);
            if let Some(bt) = timing {
                blocks.push(bt);
            }
            for (i, r) in results {
                receipts[i] = Some(r);
            }
        }
        let total_ns = t0.elapsed().as_nanos() as u64;
        SubmitResult { receipts: receipts.into_iter().map(|r| r.unwrap()).collect(), blocks, total_ns }
    }

    fn run_block(&mut self, chunk: &[(usize, &SignedTx)], t0: Instant) -> (Option<BlockTiming>, Vec<(usize, TxReceipt)>) {
        let n = self.cfg.n_validators;
        let height = self.height() + 1;
        let leader = (height as usize) % n;
        let mut out: Vec<(usize, TxReceipt)> = Vec::new();
        let tb = Instant::now();

        if self.offline[leader] {
            // no view change in this simulation: a dead leader stalls the height
            for (i, _) in chunk {
                out.push((*i, TxReceipt { result: Err(Reject::NoQuorum), height: None, latency_ns: t0.elapsed().as_nanos() as u64 }));
            }
            return (None, out);
        }

        // ---- leader: admission, execution, state root, proposal signature
        let tl = Instant::now();
        self.replicas[leader].state.begin();
        let mut accepted: Vec<&SignedTx> = Vec::new();
        let mut accepted_idx: Vec<usize> = Vec::new();
        for (i, t) in chunk {
            let res = if !self.check_tx_sig(t) { Err(Reject::BadSignature) } else { self.replicas[leader].apply(&t.tx) };
            match res {
                Ok(()) => {
                    accepted.push(*t);
                    accepted_idx.push(*i);
                }
                Err(r) => out.push((*i, TxReceipt { result: Err(r), height: None, latency_ns: t0.elapsed().as_nanos() as u64 })),
            }
        }
        if accepted.is_empty() {
            self.replicas[leader].state.rollback();
            return (None, out);
        }
        let mut state_root = self.replicas[leader].state.root();
        let tx_leaves: Vec<Hash> = accepted.iter().map(|t| leaf_hash(&t.digest())).collect();
        if self.tamper_state_root {
            state_root[0] ^= 1;
        }
        let header = BlockHeader { height, prev: self.prev_hash(), tx_root: merkle_root(&tx_leaves), state_root, proposer: leader as u16, n_txs: accepted.len() as u32 };
        let bh = header.hash();
        let leader_sig = self.validators[leader].sign(&vote_msg(&bh));
        let leader_ns = tl.elapsed().as_nanos() as u64;

        // ---- other validators
        let mut votes: Vec<Vote> = vec![Vote { validator: leader as u16, sig: leader_sig.clone() }];
        let mut validator_ns = Vec::new();
        let mut vote_valid_from: Vec<Option<Vote>> = vec![None; n];
        for j in 0..n {
            if j == leader || self.offline[j] {
                continue;
            }
            let tv = Instant::now();
            let ok = sig::verify(&self.validator_vks[leader], &vote_msg(&bh), &leader_sig)
                && accepted.iter().all(|t| self.check_tx_sig(t))
                && {
                    self.replicas[j].state.begin();
                    let all = accepted.iter().all(|t| self.replicas[j].apply(&t.tx).is_ok());
                    all && self.replicas[j].state.root() == header.state_root
                };
            if ok {
                let s = self.validators[j].sign(&vote_msg(&bh));
                vote_valid_from[j] = Some(Vote { validator: j as u16, sig: s });
            } else {
                // a replica that refused keeps its pre-block state
                self.replicas[j].state.rollback();
            }
            validator_ns.push(tv.elapsed().as_nanos() as u64);
        }

        // ---- leader collects votes until the quorum is reached and verifies each
        let tq = Instant::now();
        let quorum = self.cfg.quorum();
        for j in 0..n {
            if votes.len() >= quorum {
                break;
            }
            if let Some(v) = &vote_valid_from[j] {
                if sig::verify(&self.validator_vks[j], &vote_msg(&bh), &v.sig) {
                    votes.push(v.clone());
                }
            }
        }
        let qc_verify_ns = tq.elapsed().as_nanos() as u64;
        let committed = votes.len() >= quorum;

        if committed {
            for j in 0..n {
                // replicas that applied the block (leader, and validators that voted) finalize it
                if j == leader || vote_valid_from[j].is_some() {
                    self.replicas[j].state.commit();
                }
            }
            // validators that were offline or refused do not hold the block: in this
            // simulation they would catch up by state transfer; we apply it to keep
            // replicas aligned (not timed).
            for j in 0..n {
                if j != leader && vote_valid_from[j].is_none() {
                    self.replicas[j].state.begin();
                    for t in &accepted {
                        let _ = self.replicas[j].apply(&t.tx);
                    }
                    self.replicas[j].state.commit();
                }
            }
            let now = t0.elapsed().as_nanos() as u64;
            let blk = Block { header, txs: accepted.iter().map(|t| (*t).clone()).collect(), qc: votes };
            self.chain.push(blk);
            for i in accepted_idx {
                out.push((i, TxReceipt { result: Ok(()), height: Some(height), latency_ns: now }));
            }
        } else {
            for j in 0..n {
                if j == leader || vote_valid_from[j].is_some() {
                    self.replicas[j].state.rollback();
                }
            }
            let now = t0.elapsed().as_nanos() as u64;
            for i in accepted_idx {
                out.push((i, TxReceipt { result: Err(Reject::NoQuorum), height: None, latency_ns: now }));
            }
        }
        let timing = BlockTiming { txs_proposed: accepted.len(), committed, leader_ns, validator_ns, qc_verify_ns, total_ns: tb.elapsed().as_nanos() as u64 };
        (Some(timing), out)
    }

    /// Light-client read of one state entry with Merkle proof and the QC of the latest block.
    pub fn read_state(&self, key: &[u8]) -> Option<ReadProof> {
        let last = self.chain.last()?;
        let value = self.replicas[0].state.get(key)?.to_vec();
        let proof = self.replicas[0].state.prove(key)?;
        Some(ReadProof { key: key.to_vec(), value, proof, header: last.header.clone(), qc: last.qc.clone() })
    }
}

/// Client-side check: QC of >= quorum distinct validators over the header hash, then Merkle path
/// from the entry to the header's state root. The client trusts the validator keys.
pub fn verify_qc(header: &BlockHeader, qc: &[Vote], vks: &[VerifyingKey<MlDsa65>], quorum: usize) -> bool {
    let bh = header.hash();
    let msg = vote_msg(&bh);
    let mut seen = vec![false; vks.len()];
    let mut good = 0usize;
    for v in qc {
        let j = v.validator as usize;
        if j >= vks.len() || seen[j] {
            continue;
        }
        if sig::verify(&vks[j], &msg, &v.sig) {
            seen[j] = true;
            good += 1;
        }
    }
    good >= quorum
}

pub fn verify_read(p: &ReadProof, vks: &[VerifyingKey<MlDsa65>], quorum: usize) -> bool {
    if !verify_qc(&p.header, &p.qc, vks, quorum) {
        return false;
    }
    let leaf = leaf_of(&p.key, &p.value);
    verify_path(&leaf, p.proof.index, p.proof.size, &p.proof.path, &p.header.state_root)
}

/// Size of one block holding `m` transactions of given wire sizes, with a quorum certificate.
pub fn block_bytes_formula(m: usize, tx_body: usize, tx_sig: usize, quorum: usize) -> BlockBytes {
    BlockBytes { header: HEADER_BYTES, tx_body: m * tx_body, tx_sig: m * tx_sig, qc: quorum * (2 + SIG_BYTES) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit;

    pub fn setup(cfg: LedgerConfig) -> (Ledger, Vec<SigKeys>, audit::Chain) {
        let aa = SigKeys::from_seed([1u8; 32]);
        let lp = SigKeys::from_seed([2u8; 32]);
        let vks = vec![aa.vk.clone(), lp.vk.clone()];
        let ch = audit::Chain::genesis(&aa);
        let led = Ledger::new(cfg, ch.genesis_contract(), vks, [5u8; 32]);
        (led, vec![aa, lp], ch)
    }

    fn anchor_tx(led: &mut Ledger, ch: &mut audit::Chain, keys: &[SigKeys]) -> SignedTx {
        let tx = ch.next_anchor(&keys[0], 3, 4);
        SignedTx::sign(tx, 0, &keys[0], &led.cfg)
    }

    #[test]
    fn quorum_arithmetic() {
        let q = |n| LedgerConfig { n_validators: n, ..Default::default() }.quorum();
        assert_eq!((q(4), q(5), q(7), q(10), q(13)), (3, 4, 5, 7, 9));
    }

    #[test]
    fn blocks_commit_replicas_agree_qc_verifies() {
        let (mut led, keys, mut ch) = setup(LedgerConfig::default());
        for _ in 0..3 {
            let t = anchor_tx(&mut led, &mut ch, &keys);
            let r = led.submit(vec![t]);
            assert_eq!(r.receipts[0].result, Ok(()));
        }
        assert_eq!(led.height(), 3);
        assert!(led.replica_roots_agree());
        assert_eq!(led.contract().last().0, 3);
        // chain linkage and QCs
        let mut prev = led.genesis_header.hash();
        for b in &led.chain {
            assert_eq!(b.header.prev, prev);
            assert!(verify_qc(&b.header, &b.qc, &led.validator_vks, led.cfg.quorum()));
            assert_eq!(b.header.state_root.len(), 32);
            prev = b.header.hash();
        }
        // verified read
        let key = key_state(2);
        let rp = led.read_state(&key).unwrap();
        assert!(verify_read(&rp, &led.validator_vks, led.cfg.quorum()));
        let mut bad = led.read_state(&key).unwrap();
        bad.value[0] ^= 1;
        assert!(!verify_read(&bad, &led.validator_vks, led.cfg.quorum()));
        // QC with fewer than quorum signatures fails
        let b = &led.chain[0];
        assert!(!verify_qc(&b.header, &b.qc[..2], &led.validator_vks, led.cfg.quorum()));
        // duplicated votes do not add up
        let dup = vec![b.qc[0].clone(), b.qc[0].clone(), b.qc[0].clone()];
        assert!(!verify_qc(&b.header, &dup, &led.validator_vks, led.cfg.quorum()));
    }

    #[test]
    fn one_silent_validator_is_tolerated_two_are_not() {
        let (mut led, keys, mut ch) = setup(LedgerConfig::default());
        // height 1 -> leader 1. silence validator 3
        led.offline[3] = true;
        let t = anchor_tx(&mut led, &mut ch, &keys);
        assert_eq!(led.submit(vec![t]).receipts[0].result, Ok(()));
        assert!(led.replica_roots_agree());
        // two silent (f+1 = 2): no quorum, nothing finalizes, state rolled back
        // (height 2 has leader 2, so silencing validator 0 keeps the leader alive)
        led.offline[0] = true;
        let t = anchor_tx(&mut led, &mut ch, &keys);
        let r = led.submit(vec![t]);
        assert_eq!(r.receipts[0].result, Err(Reject::NoQuorum));
        assert_eq!(led.height(), 1);
        assert_eq!(led.contract().last().0, 1);
        assert!(led.replica_roots_agree());
    }

    #[test]
    fn wrong_state_root_from_leader_is_not_finalized() {
        let (mut led, keys, mut ch) = setup(LedgerConfig::default());
        led.tamper_state_root = true;
        let t = anchor_tx(&mut led, &mut ch, &keys);
        let r = led.submit(vec![t]);
        assert_eq!(r.receipts[0].result, Err(Reject::NoQuorum));
        assert_eq!(led.height(), 0);
        assert_eq!(led.contract().last().0, 0);
        assert!(led.replica_roots_agree());
    }

    #[test]
    fn bad_submitter_signature_is_dropped() {
        let (mut led, keys, mut ch) = setup(LedgerConfig::default());
        let tx = ch.next_anchor(&keys[0], 3, 4);
        let wrong_key = SignedTx::sign(tx.clone(), 0, &keys[1], &led.cfg); // signed by LP key, claims AA
        assert_eq!(led.submit(vec![wrong_key]).receipts[0].result, Err(Reject::BadSignature));
        let mut tampered = SignedTx::sign(tx, 0, &keys[0], &led.cfg);
        tampered.sig[5] ^= 1;
        assert_eq!(led.submit(vec![tampered]).receipts[0].result, Err(Reject::BadSignature));
        assert_eq!(led.height(), 0);
    }

    #[test]
    fn batching_splits_into_blocks_and_orders_in_block_conflicts() {
        let cfg = LedgerConfig { max_block_txs: 3, ..Default::default() };
        let (mut led, keys, _ch) = setup(cfg);
        let txs: Vec<SignedTx> = (0..7u64)
            .map(|i| SignedTx::sign(Tx::CommitRecord { e: 1, i, c: h(&[&u64b(i)]) }, 1, &keys[1], &cfg))
            .collect();
        let r = led.submit(txs);
        assert!(r.receipts.iter().all(|x| x.result.is_ok()));
        assert_eq!(r.blocks.len(), 3); // 3+3+1
        assert_eq!(led.height(), 3);
        // latency is non-decreasing across blocks
        let l: Vec<u64> = r.receipts.iter().map(|x| x.latency_ns).collect();
        assert!(l.windows(2).all(|w| w[0] <= w[1]));
        // duplicate record inside one block: second one rejected, first committed
        let dup = vec![
            SignedTx::sign(Tx::CommitRecord { e: 1, i: 100, c: [1; 32] }, 1, &keys[1], &cfg),
            SignedTx::sign(Tx::CommitRecord { e: 1, i: 100, c: [2; 32] }, 1, &keys[1], &cfg),
        ];
        let r = led.submit(dup);
        assert_eq!(r.receipts[0].result, Ok(()));
        assert_eq!(r.receipts[1].result, Err(Reject::DuplicateRecord));
        assert!(led.replica_roots_agree());
    }

    #[test]
    fn bytes_formula_matches_real_blocks() {
        let cfg = LedgerConfig { max_block_txs: 10, ..Default::default() };
        let (mut led, keys, _ch) = setup(cfg);
        let txs: Vec<SignedTx> = (0..25u64)
            .map(|i| SignedTx::sign(Tx::CommitRecord { e: 1, i, c: h(&[&u64b(i)]) }, 1, &keys[1], &cfg))
            .collect();
        led.submit(txs);
        let real = led.total_bytes();
        let mut want = BlockBytes::default();
        for m in [10usize, 10, 5] {
            want.add(&block_bytes_formula(m, 1 + 8 + 8 + 32 + 2, SIG_BYTES, cfg.quorum()));
        }
        assert_eq!(real, want);
    }

    fn v2(e: u64, i: u64) -> Tx {
        let ph = h(&[b"payload", &u64b(i)]);
        Tx::CommitRecordV2 { e, i, ph, c: record_commit(e, i, &ph) }
    }

    /// W37: CommitRecordV2 through the full simulated ledger (4 validators, quorum 3, ML-DSA tx signatures).
    #[test]
    fn w37_v2_through_ledger_signature_and_contract_checks() {
        let cfg = LedgerConfig { max_block_txs: 4, ..Default::default() };
        let (mut led, keys, mut ch) = setup(cfg);
        let a = anchor_tx(&mut led, &mut ch, &keys);
        assert_eq!(led.submit(vec![a]).receipts[0].result, Ok(()));
        // 10 honest records over 3 blocks; replicas agree afterwards
        let txs: Vec<SignedTx> = (0..10u64).map(|i| SignedTx::sign(v2(1, i), 1, &keys[1], &cfg)).collect();
        let r = led.submit(txs);
        assert!(r.receipts.iter().all(|x| x.result.is_ok()));
        assert_eq!(r.blocks.len(), 3);
        assert!(led.replica_roots_agree());
        // forged signature (signed by the AA key but claims submitter 1), and a flipped signature byte
        let forged = SignedTx::sign(v2(1, 10), 1, &keys[0], &cfg);
        assert_eq!(led.submit(vec![forged]).receipts[0].result, Err(Reject::BadSignature));
        let mut flipped = SignedTx::sign(v2(1, 10), 1, &keys[1], &cfg);
        flipped.sig[7] ^= 1;
        assert_eq!(led.submit(vec![flipped]).receipts[0].result, Err(Reject::BadSignature));
        // a body changed after signing is rejected by the signature check (descriptor tamper)
        let mut body = SignedTx::sign(v2(1, 10), 1, &keys[1], &cfg);
        body.tx = v2(1, 11);
        assert_eq!(led.submit(vec![body]).receipts[0].result, Err(Reject::BadSignature));
        // contract rules inside one block: duplicate, gap, bad commitment; the honest next record still commits
        let ph = h(&[b"payload", &u64b(10)]);
        let bad_c = Tx::CommitRecordV2 { e: 1, i: 10, ph, c: [0; 32] };
        let batch = vec![
            SignedTx::sign(v2(1, 3), 1, &keys[1], &cfg),
            SignedTx::sign(v2(1, 12), 1, &keys[1], &cfg),
            SignedTx::sign(bad_c, 1, &keys[1], &cfg),
            SignedTx::sign(v2(1, 10), 1, &keys[1], &cfg),
        ];
        let r = led.submit(batch);
        let res: Vec<_> = r.receipts.iter().map(|x| x.result).collect();
        assert_eq!(res, vec![Err(Reject::DuplicateRecord), Err(Reject::RecordSeq), Err(Reject::RecordCommitMismatch), Ok(())]);
        assert!(led.replica_roots_agree());
        // exact byte formula for 11 accepted v2 records in blocks of 4 (header, body 83 B, signature, QC)
        assert_eq!(led.contract().state.get(&key_cnt(1)).unwrap(), &u64b(11)[..]);
    }

    #[test]
    fn quorum_of_seven_validators_with_two_silent() {
        let cfg = LedgerConfig { n_validators: 7, ..Default::default() };
        let (mut led, keys, mut ch) = setup(cfg);
        led.offline[0] = true; // not the leader of height 1 (leader = 1)
        led.offline[6] = true;
        let t = anchor_tx(&mut led, &mut ch, &keys);
        assert_eq!(led.submit(vec![t]).receipts[0].result, Ok(()));
        assert_eq!(led.chain[0].qc.len(), cfg.quorum());
    }
}
