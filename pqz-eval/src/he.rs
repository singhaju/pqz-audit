//! BFV aggregation.
//!
//! The paper stores one HE ciphertext of `b` per record. At 10^6 records that
//! is far beyond the memory budget, so the harness uses a pool of
//! [`POOL_SIZE`] pre-encrypted ciphertexts and cycles them over the records.
//! Addition time does not depend on the plaintext, so the `add` timing is
//! representative; the harness states this in its output header.
//!
//! Parameters: BFV, degree 8192, 41-bit plaintext modulus, five ciphertext
//! moduli of 43-44 bits (about 218 bits total). The sum of 10^6 values below
//! 2^20 is below 2^40, so a 41-bit plaintext modulus cannot wrap.
//!
//! Degree 2048 (one 54-bit modulus) and degree 4096 (three 36/37-bit moduli)
//! are not usable here: their individual RNS moduli are smaller than the
//! 41-bit plaintext modulus, and decryption produced garbage even for a single
//! addition (measured). Degree 8192 is the smallest default 128-bit parameter
//! set whose every ciphertext modulus exceeds the plaintext modulus; the
//! 10^6-addition test below checks noise headroom empirically.

use std::sync::Arc;

use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize};
use rand::SeedableRng;
use rand::rngs::StdRng;

/// Pool size from SPEC.md.
pub const POOL_SIZE: usize = 1024;
/// Plaintext modulus size in bits. Must exceed log2(10^6 * 2^20) ≈ 40.
const PLAINTEXT_BITS: usize = 41;
/// Degree used by the evaluation.
const DEGREE: usize = 8192;

/// A pool of pre-encrypted BFV ciphertexts plus the key needed to decrypt.
pub struct HePool {
    params: Arc<BfvParameters>,
    sk: SecretKey,
    cts: Vec<Ciphertext>,
    one: Ciphertext,
}

impl HePool {
    /// Build the evaluation pool (K = [`POOL_SIZE`]).
    pub fn new(seed: u64) -> Result<Self, String> {
        Self::with_pool_size(seed, POOL_SIZE)
    }

    /// Build a smaller pool for tests. The evaluation uses [`POOL_SIZE`].
    pub fn with_pool_size(seed: u64, k: usize) -> Result<Self, String> {
        assert!(k > 0);
        let params = BfvParameters::default_parameters_128(PLAINTEXT_BITS)
            .map_err(|e| e.to_string())?
            .find(|p| p.degree() == DEGREE)
            .ok_or_else(|| format!("no default BFV parameters at degree {DEGREE}"))?;

        let mut rng = StdRng::seed_from_u64(seed);
        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        let mut cts = Vec::with_capacity(k);
        for v in 0..k as u64 {
            let pt = Plaintext::try_encode(&[v], Encoding::poly(), &params)
                .map_err(|e| e.to_string())?;
            cts.push(pk.try_encrypt(&pt, &mut rng).map_err(|e| e.to_string())?);
        }
        let one_pt = Plaintext::try_encode(&[1u64], Encoding::poly(), &params)
            .map_err(|e| e.to_string())?;
        let one = pk.try_encrypt(&one_pt, &mut rng).map_err(|e| e.to_string())?;

        Ok(HePool {
            params,
            sk,
            cts,
            one,
        })
    }

    pub fn pool_len(&self) -> usize {
        self.cts.len()
    }

    pub fn params(&self) -> &Arc<BfvParameters> {
        &self.params
    }

    pub fn plaintext_modulus(&self) -> u64 {
        self.params.plaintext()
    }

    pub fn degree(&self) -> usize {
        self.params.degree()
    }

    pub fn zero(&self) -> Ciphertext {
        Ciphertext::zero(&self.params)
    }

    /// Ciphertext used for a record with value `b`. The plaintext encrypted in
    /// the pool slot is `b % pool_len`.
    pub fn ct_for_b(&self, b: u32) -> &Ciphertext {
        &self.cts[(b as usize) % self.cts.len()]
    }

    /// Ciphertext of plaintext 1, for COUNT.
    pub fn one(&self) -> &Ciphertext {
        &self.one
    }

    /// The plaintext value that `ct_for_b(b)` actually encrypts.
    pub fn pool_value(&self, b: u32) -> u64 {
        (b as usize % self.cts.len()) as u64
    }

    /// Decrypt and return the constant coefficient as a `u64`.
    pub fn decrypt(&self, ct: &Ciphertext) -> Result<u64, String> {
        let pt = self.sk.try_decrypt(ct).map_err(|e| e.to_string())?;
        let v = Vec::<u64>::try_decode(&pt, Encoding::poly()).map_err(|e| e.to_string())?;
        v.first().copied().ok_or_else(|| "empty plaintext".to_string())
    }

    /// Bytes of the serialized pool ciphertexts plus the secret key. This is a
    /// real measure of the stored representation, not the allocator's RSS.
    pub fn serialized_bytes(&self) -> usize {
        let cts: usize = self.cts.iter().map(|c| c.to_bytes().len()).sum();
        let one = self.one.to_bytes().len();
        let sk = self.sk.to_bytes().len();
        cts + one + sk
    }

    /// Human-readable parameter description for the output header.
    pub fn describe(&self) -> String {
        format!(
            "BFV degree={} plaintext_modulus={} ({} bits) moduli={:?} pool_K={}",
            self.degree(),
            self.plaintext_modulus(),
            PLAINTEXT_BITS,
            self.params.moduli(),
            self.pool_len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r#gen::r#gen;
    use crate::Layout;

    #[test]
    fn pool_size_is_1024() {
        assert_eq!(POOL_SIZE, 1024);
    }

    #[test]
    fn selected_sum_matches_plaintext_pool_values() {
        let pool = HePool::with_pool_size(7, 16).expect("pool");
        let recs = r#gen(500, 50, Layout::Scattered, 9);
        let selected: Vec<&crate::Record> = recs.iter().filter(|r| r.id % 7 == 0).collect();
        assert!(!selected.is_empty());

        let expected: u64 = selected.iter().map(|r| pool.pool_value(r.b)).sum();
        let mut acc = pool.zero();
        for r in &selected {
            acc += pool.ct_for_b(r.b);
        }
        assert_eq!(pool.decrypt(&acc).expect("decrypt"), expected);

        let mut count = pool.zero();
        for _ in &selected {
            count += pool.one();
        }
        assert_eq!(pool.decrypt(&count).expect("decrypt"), selected.len() as u64);
    }

    #[test]
    fn one_million_additions_do_not_overflow() {
        let pool = HePool::with_pool_size(11, 64).expect("pool");
        let n = 1_000_000u64;
        let b_at = |i: u64| (i % 64) as u32;
        let expected: u64 = (0..n).map(|i| pool.pool_value(b_at(i))).sum();
        let mut acc = pool.zero();
        for i in 0..n {
            acc += pool.ct_for_b(b_at(i));
        }
        let got = pool.decrypt(&acc).expect("decrypt after 10^6 additions");
        assert_eq!(got, expected, "noise overflow after 10^6 additions");
    }
}
