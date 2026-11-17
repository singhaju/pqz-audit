//! MiMC over the BN254 scalar field: x -> (x + k + c_i)^5, 110 rounds, Miyaguchi-Preneel hash.
//! 110 = ceil(log_5(r)) = ceil(254 / log2 5) rounds is the usual MiMC-e count for e = 5 (gcd(5, r-1) = 1 on BN254 Fr).
//! Round constants: Keccak-256 chain from our own seed (NOT the gnark constants).
use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, Zero};
use sha3::{Digest, Keccak256};

pub const ROUNDS: usize = 110;
pub const SEED: &[u8] = b"pqz-bl lhcpm MiMC-5 BN254 round constants v1";

pub struct Mimc {
    pub c: Vec<Fr>,
}

impl Mimc {
    pub fn new() -> Self {
        let mut h = Keccak256::digest(SEED).to_vec();
        let mut c = Vec::with_capacity(ROUNDS);
        for _ in 0..ROUNDS {
            h = Keccak256::digest(&h).to_vec();
            c.push(Fr::from_be_bytes_mod_order(&h));
        }
        Mimc { c }
    }

    #[inline]
    pub fn pow5(t: Fr) -> Fr {
        let t2 = t.square();
        let t4 = t2.square();
        t4 * t
    }

    /// MiMC block cipher E_k(x).
    pub fn encrypt(&self, mut x: Fr, k: Fr) -> Fr {
        for c in &self.c {
            x = Self::pow5(x + k + c);
        }
        x + k
    }

    /// Miyaguchi-Preneel: h <- E_h(m) + h + m, h_0 = 0.
    pub fn hash(&self, inputs: &[Fr]) -> Fr {
        let mut h = Fr::zero();
        for &m in inputs {
            h = self.encrypt(m, h) + h + m;
        }
        h
    }
}

impl Default for Mimc {
    fn default() -> Self {
        Self::new()
    }
}
