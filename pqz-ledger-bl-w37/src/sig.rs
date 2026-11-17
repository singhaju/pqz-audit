//! ML-DSA-65 (FIPS 204) through the RustCrypto `ml-dsa` crate (version pinned in
//! Cargo.toml). Keys come from a 32-byte seed so that benchmark runs are
//! reproducible. SEEDS ARE FOR BENCHMARKS ONLY: a real validator or authority
//! key must come from the operating system CSPRNG.
//! The crate is un-audited (its own README says so).

use ml_dsa::{signature::Keypair, MlDsa65, Seed, Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const SIG_BYTES: usize = 3309; // FIPS 204, ML-DSA-65
pub const VK_BYTES: usize = 1952;

pub struct SigKeys {
    sk: SigningKey<MlDsa65>,
    pub vk: VerifyingKey<MlDsa65>,
}

impl SigKeys {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let sk = SigningKey::<MlDsa65>::from_seed(&Seed::from(seed));
        let vk = sk.verifying_key();
        SigKeys { sk, vk }
    }

    /// Deterministic ML-DSA-65 signature (empty context), encoded.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let s: Signature<MlDsa65> = self.sk.sign(msg);
        s.encode().to_vec()
    }
}

pub fn verify(vk: &VerifyingKey<MlDsa65>, msg: &[u8], sig: &[u8]) -> bool {
    match Signature::<MlDsa65>::try_from(sig) {
        Ok(s) => vk.verify(msg, &s).is_ok(),
        Err(_) => false,
    }
}

pub fn vk_encoded_len(vk: &VerifyingKey<MlDsa65>) -> usize {
    vk.encode().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_sizes() {
        let k = SigKeys::from_seed([7u8; 32]);
        let s = k.sign(b"hello");
        assert_eq!(s.len(), SIG_BYTES);
        assert_eq!(vk_encoded_len(&k.vk), VK_BYTES);
        assert!(verify(&k.vk, b"hello", &s));
        assert!(!verify(&k.vk, b"hellp", &s));
        let mut bad = s.clone();
        bad[10] ^= 1;
        assert!(!verify(&k.vk, b"hello", &bad));
        assert!(!verify(&k.vk, b"hello", &s[..100]));
        let other = SigKeys::from_seed([8u8; 32]);
        assert!(!verify(&other.vk, b"hello", &s));
    }
}
