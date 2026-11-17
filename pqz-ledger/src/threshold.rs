//! Threshold layer: the three key domains of the paper, TA_PQ, HE_PQ and FD_PQ
//! (here called T_priv, T_rec, T_disc, see DESIGN.md: the paper does not use these names).
//!
//! Implemented: only the (t,n) secret-sharing part, Shamir over GF(2^127-1)
//! (src/shamir.rs), one independent dealing per domain, and a public check hash so
//! that Combine can tell a correct reconstruction from garbage.
//! NOT implemented (needs scheme choices the paper has not made): the threshold
//! signature behind TA_PQ.Approve/Combine, the HE scheme behind HE_PQ.PartDec/Combine,
//! the KEM/wrap behind FD_PQ.Protect/ShareOpen/Combine. In particular a Shamir
//! reconstruction hands the secret to the combiner; it is NOT a threshold signature or
//! threshold decryption (those never reveal the key). The timings are therefore the cost
//! of sharing and reconstruction only, a lower bound for the real operations.
//!
//! Provisional extra for T_priv: `multisig`, t-of-n approval as n independent ML-DSA-65
//! signatures over B_Q (vetted primitive, no Shamir). Signature size grows with t.

use crate::hashing::*;
use crate::shamir::{self, Share};
use crate::sig::{self, SigKeys};
use ml_dsa::{MlDsa65, VerifyingKey};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::Rng;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    /// TA_PQ: privileged authorization (TAC), paper Phase 1 step 3 and Phase 5 step 3
    Priv,
    /// HE_PQ.Share: aggregate recovery, paper Phase 1 step 3 and Phase 7 step 2
    Rec,
    /// FD_PQ: forensic disclosure, paper Phase 1 step 3 and Phase 7 step 3
    Disc,
}

impl Domain {
    pub const ALL: [Domain; 3] = [Domain::Priv, Domain::Rec, Domain::Disc];
    pub fn label(&self) -> &'static str {
        match self {
            Domain::Priv => "T_priv",
            Domain::Rec => "T_rec",
            Domain::Disc => "T_disc",
        }
    }
    pub fn paper_name(&self) -> &'static str {
        match self {
            Domain::Priv => "TA_PQ",
            Domain::Rec => "HE_PQ.Share",
            Domain::Disc => "FD_PQ",
        }
    }
}

/// Independent CSPRNG per domain from one benchmark seed (seeds are for benchmarks only).
pub fn domain_rng(domain: Domain, seed: &[u8; 32]) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(h(&[b"PQZ-THR-RNG", domain.label().as_bytes(), seed]))
}

/// Random secret of `len` bytes (stand-in for sk_TAC, sk_HE, sk_FD whose real form depends on the scheme).
pub fn random_secret(rng: &mut ChaCha20Rng, len: usize) -> Vec<u8> {
    let mut s = vec![0u8; len];
    rng.fill_bytes(&mut s);
    s
}

/// Public part of a dealing.
#[derive(Clone, Debug)]
pub struct PublicInfo {
    pub domain: Domain,
    pub t: usize,
    pub n: usize,
    pub secret_len: usize,
    /// H("PQZ-THR-CHECK" || domain || secret). Safe only for high-entropy secrets (they are random 32+ bytes).
    pub check: Hash,
}

pub fn check_hash(domain: Domain, secret: &[u8]) -> Hash {
    h(&[b"PQZ-THR-CHECK", domain.label().as_bytes(), secret])
}

/// Setup_{t,n}: deal `secret` into n shares. 1 < t <= n as in the paper.
pub fn setup(domain: Domain, t: usize, n: usize, secret: &[u8], rng: &mut ChaCha20Rng) -> (PublicInfo, Vec<Share>) {
    let shares = shamir::deal(secret, t, n, rng);
    (PublicInfo { domain, t, n, secret_len: secret.len(), check: check_hash(domain, secret) }, shares)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CombineError {
    TooFewShares,
    BadShareIndex,
    DuplicateShare,
    LengthMismatch,
    CheckFailed,
}

/// Combine: needs at least t distinct valid-index shares; the result must match the public check.
/// Uses exactly the first t shares given (extra shares are ignored).
pub fn combine(info: &PublicInfo, shares: &[Share]) -> Result<Vec<u8>, CombineError> {
    if shares.len() < info.t {
        return Err(CombineError::TooFewShares);
    }
    let used = &shares[..info.t];
    let chunks = shamir::chunks_for(info.secret_len);
    for (i, s) in used.iter().enumerate() {
        if s.x == 0 || s.x as usize > info.n {
            return Err(CombineError::BadShareIndex);
        }
        if s.y.len() != chunks {
            return Err(CombineError::LengthMismatch);
        }
        if used[..i].iter().any(|o| o.x == s.x) {
            return Err(CombineError::DuplicateShare);
        }
    }
    let secret = shamir::reconstruct(used, info.secret_len);
    if check_hash(info.domain, &secret) != info.check {
        return Err(CombineError::CheckFailed);
    }
    Ok(secret)
}

/// Bytes one member stores for its share.
pub fn share_bytes(shares: &[Share]) -> usize {
    shares.first().map(|s| s.bytes()).unwrap_or(0)
}

/// Provisional T_priv variant: t-of-n approval by n independent ML-DSA-65 signatures over B_Q.
pub mod multisig {
    use super::*;

    pub struct Committee {
        pub t: usize,
        pub n: usize,
        keys: Vec<SigKeys>,
        pub vks: Vec<VerifyingKey<MlDsa65>>,
    }

    #[derive(Clone)]
    pub struct Approval {
        pub member: usize,
        pub sig: Vec<u8>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Err {
        TooFew,
        BadMember,
        Duplicate,
        BadSignature,
    }

    impl Committee {
        /// Benchmark seeds only.
        pub fn setup(t: usize, n: usize, seed: &[u8; 32]) -> Self {
            assert!(1 < t && t <= n);
            let keys: Vec<SigKeys> = (0..n).map(|j| SigKeys::from_seed(h(&[b"PQZ-TAC-MS", seed, &u64b(j as u64)]))).collect();
            let vks = keys.iter().map(|k| k.vk.clone()).collect();
            Committee { t, n, keys, vks }
        }
        fn msg(b_q: &Hash) -> Vec<u8> {
            let mut m = b"PQZA-TAC-APPROVE".to_vec();
            m.extend_from_slice(b_q);
            m
        }
        /// TA_PQ.Approve(sk_j, B_Q)
        pub fn approve(&self, member: usize, b_q: &Hash) -> Approval {
            Approval { member, sig: self.keys[member].sign(&Self::msg(b_q)) }
        }
        /// TA_PQ.Combine + public verification: t distinct valid approvals -> Auth_TAC.
        pub fn combine(&self, b_q: &Hash, approvals: &[Approval]) -> Result<Hash, Err> {
            if approvals.len() < self.t {
                return Err(Err::TooFew);
            }
            let used = &approvals[..self.t];
            for (i, a) in used.iter().enumerate() {
                if a.member >= self.n {
                    return Err(Err::BadMember);
                }
                if used[..i].iter().any(|o| o.member == a.member) {
                    return Err(Err::Duplicate);
                }
                if !sig::verify(&self.vks[a.member], &Self::msg(b_q), &a.sig) {
                    return Err(Err::BadSignature);
                }
            }
            let mut parts: Vec<Vec<u8>> = vec![b"PQZA-TAC-AUTH".to_vec(), b_q.to_vec()];
            for a in used {
                parts.push(u64b(a.member as u64).to_vec());
                parts.push(a.sig.clone());
            }
            let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
            Ok(h(&refs))
        }
        /// Bytes of the Auth_TAC evidence a verifier must hold (t signatures + member indices).
        pub fn evidence_bytes(&self) -> usize {
            self.t * (sig::SIG_BYTES + 2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PANEL: [(usize, usize); 3] = [(3, 5), (5, 9), (7, 13)];

    #[test]
    fn every_domain_and_panel_point_round_trips_with_any_t_subset() {
        for d in Domain::ALL {
            for (t, n) in PANEL {
                let mut rng = domain_rng(d, &[7u8; 32]);
                let secret = random_secret(&mut rng, 32);
                let (info, shares) = setup(d, t, n, &secret, &mut rng);
                assert_eq!(shares.len(), n);
                // first t, last t, and a strided subset
                let last: Vec<Share> = shares[n - t..].to_vec();
                let strided: Vec<Share> = (0..t).map(|i| shares[(i * 2) % n].clone()).collect();
                assert_eq!(combine(&info, &shares[..t]).unwrap(), secret);
                assert_eq!(combine(&info, &last).unwrap(), secret);
                if (0..t).map(|i| (i * 2) % n).collect::<std::collections::BTreeSet<_>>().len() == t {
                    assert_eq!(combine(&info, &strided).unwrap(), secret);
                }
            }
        }
    }

    #[test]
    fn fewer_than_t_shares_are_refused_and_t_minus_1_interpolation_fails_the_check() {
        let mut rng = domain_rng(Domain::Priv, &[1u8; 32]);
        let secret = random_secret(&mut rng, 32);
        let (info, shares) = setup(Domain::Priv, 5, 9, &secret, &mut rng);
        assert_eq!(combine(&info, &shares[..4]), Err(CombineError::TooFewShares));
        // a sub-threshold coalition that forces interpolation (bypassing the count check)
        let wrong = shamir::reconstruct(&shares[..4], 32);
        assert_ne!(wrong, secret);
        assert_ne!(check_hash(Domain::Priv, &wrong), info.check);
    }

    #[test]
    fn bad_duplicate_and_foreign_shares_are_refused() {
        let mut rng = domain_rng(Domain::Rec, &[2u8; 32]);
        let secret = random_secret(&mut rng, 32);
        let (info, shares) = setup(Domain::Rec, 3, 5, &secret, &mut rng);
        let mut tampered = shares[..3].to_vec();
        tampered[1].y[0] = shamir::add(tampered[1].y[0], 1);
        assert_eq!(combine(&info, &tampered), Err(CombineError::CheckFailed));
        let dup = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
        assert_eq!(combine(&info, &dup), Err(CombineError::DuplicateShare));
        let mut idx = shares[..3].to_vec();
        idx[2].x = 99;
        assert_eq!(combine(&info, &idx), Err(CombineError::BadShareIndex));
        let mut short = shares[..3].to_vec();
        short[0].y.pop();
        assert_eq!(combine(&info, &short), Err(CombineError::LengthMismatch));
    }

    #[test]
    fn domains_are_independent() {
        let seed = [3u8; 32];
        let mut secrets = vec![];
        let mut dealt = vec![];
        for d in Domain::ALL {
            let mut rng = domain_rng(d, &seed);
            let s = random_secret(&mut rng, 32);
            let (info, sh) = setup(d, 3, 5, &s, &mut rng);
            secrets.push(s);
            dealt.push((info, sh));
        }
        assert_ne!(secrets[0], secrets[1]);
        assert_ne!(secrets[1], secrets[2]);
        // shares of one domain do not open another domain's dealing
        for a in 0..3 {
            for b in 0..3 {
                if a != b {
                    assert_eq!(combine(&dealt[b].0, &dealt[a].1[..3]), Err(CombineError::CheckFailed));
                }
            }
        }
        // the check hash is domain-separated even for equal secrets
        assert_ne!(check_hash(Domain::Priv, &secrets[0]), check_hash(Domain::Rec, &secrets[0]));
    }

    #[test]
    fn large_secrets_round_trip() {
        for len in [1usize, 15, 16, 32, 1024, 16384] {
            let mut rng = domain_rng(Domain::Rec, &[4u8; 32]);
            let s = random_secret(&mut rng, len);
            let (info, sh) = setup(Domain::Rec, 5, 9, &s, &mut rng);
            assert_eq!(combine(&info, &sh[2..7]).unwrap(), s, "len={}", len);
        }
    }

    #[test]
    fn multisig_t_of_n() {
        let c = multisig::Committee::setup(3, 5, &[9u8; 32]);
        let b_q = h(&[b"B_Q"]);
        let ap: Vec<_> = (0..5).map(|j| c.approve(j, &b_q)).collect();
        let a1 = c.combine(&b_q, &ap[1..4]).unwrap();
        // order of members changes the evidence hash but both are valid; same set same order is stable
        assert_eq!(a1, c.combine(&b_q, &ap[1..4]).unwrap());
        assert_eq!(c.combine(&b_q, &ap[..2]), Err(multisig::Err::TooFew));
        // approvals for another B_Q are refused
        let other = h(&[b"other"]);
        assert_eq!(c.combine(&other, &ap[..3]), Err(multisig::Err::BadSignature));
        // duplicate member counted once
        let dup = vec![ap[0].clone(), ap[0].clone(), ap[1].clone()];
        assert_eq!(c.combine(&b_q, &dup), Err(multisig::Err::Duplicate));
        // wrong member claim
        let mut forged = ap[..3].to_vec();
        forged[0].member = 4;
        assert_eq!(c.combine(&b_q, &forged), Err(multisig::Err::BadSignature));
        assert_eq!(c.evidence_bytes(), 3 * (3309 + 2));
    }
}
