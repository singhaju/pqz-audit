//! Shamir secret sharing over GF(p), p = 2^127 - 1 (a Mersenne prime).
//!
//! PROVISIONAL choice (the paper fixes no field). A secret of any length is cut
//! into 15-byte chunks (120 bits < p); every chunk is shared with its own random
//! degree-(t-1) polynomial; share j is the evaluation at x = j (j = 1..n).
//! A 32-byte secret therefore costs 3 field elements per share.
//!
//! What this is NOT: no verifiable secret sharing (no robustness against bad
//! shares), no proactive refresh, not constant-time (benchmark code), and the
//! sharing is information-theoretic only for shares of a single polynomial set.
//! Randomness is a ChaCha20 CSPRNG seeded by the caller. SEEDS ARE FOR
//! BENCHMARKS (reproducibility) ONLY; real deployments seed from the OS.

use rand_core::Rng;

pub const P: u128 = (1u128 << 127) - 1;
pub const CHUNK_BYTES: usize = 15;

#[inline]
fn reduce(mut r: u128) -> u128 {
    r = (r & P) + (r >> 127);
    if r >= P {
        r -= P;
    }
    r
}

#[inline]
pub fn add(a: u128, b: u128) -> u128 {
    reduce(a + b) // a,b < 2^127 so a+b < 2^128
}

#[inline]
pub fn sub(a: u128, b: u128) -> u128 {
    reduce(a + P - b)
}

#[inline]
pub fn mul(a: u128, b: u128) -> u128 {
    let (a0, a1) = (a & 0xFFFF_FFFF_FFFF_FFFF, a >> 64);
    let (b0, b1) = (b & 0xFFFF_FFFF_FFFF_FFFF, b >> 64);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = p01 + p10; // each < 2^127
    let (lo, c) = p00.overflowing_add(mid << 64);
    let hi = p11 + (mid >> 64) + c as u128; // < 2^126
    // x = hi*2^128 + lo, with 2^127 = 1 (mod p) so 2^128 = 2
    reduce(2 * hi + (lo & P) + (lo >> 127))
}

pub fn pow(mut a: u128, mut e: u128) -> u128 {
    let mut r = 1u128;
    while e > 0 {
        if e & 1 == 1 {
            r = mul(r, a);
        }
        a = mul(a, a);
        e >>= 1;
    }
    r
}

pub fn inv(a: u128) -> u128 {
    assert!(a % P != 0, "inverse of zero");
    pow(a, P - 2)
}

/// Uniform element of [0, p): rejection sampling on 127 random bits.
pub fn rand_elem<R: Rng>(rng: &mut R) -> u128 {
    loop {
        let x = (((rng.next_u64() as u128) << 64) | rng.next_u64() as u128) & P;
        if x < P {
            return x;
        }
    }
}

pub fn chunks_for(len: usize) -> usize {
    (len + CHUNK_BYTES - 1) / CHUNK_BYTES
}

pub fn encode_secret(secret: &[u8]) -> Vec<u128> {
    secret
        .chunks(CHUNK_BYTES)
        .map(|c| {
            let mut x = 0u128;
            for &b in c {
                x = (x << 8) | b as u128;
            }
            x
        })
        .collect()
}

pub fn decode_secret(elems: &[u128], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut remaining = len;
    for &e in elems {
        let take = remaining.min(CHUNK_BYTES);
        for i in (0..take).rev() {
            out.push((e >> (8 * i)) as u8);
        }
        remaining -= take;
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub x: u64,
    pub y: Vec<u128>, // one element per chunk
}

impl Share {
    pub fn bytes(&self) -> usize {
        8 + 16 * self.y.len()
    }
}

/// Deal `n` shares, threshold `t` (1 < t <= n, as in the paper's notation table).
pub fn deal<R: Rng>(secret: &[u8], t: usize, n: usize, rng: &mut R) -> Vec<Share> {
    assert!(1 < t && t <= n, "need 1 < t <= n");
    let chunks = encode_secret(secret);
    let mut shares: Vec<Share> = (1..=n as u64).map(|x| Share { x, y: Vec::with_capacity(chunks.len()) }).collect();
    let mut coeffs = vec![0u128; t];
    for &c in &chunks {
        coeffs[0] = c;
        for a in coeffs.iter_mut().skip(1) {
            *a = rand_elem(rng);
        }
        for s in shares.iter_mut() {
            let x = s.x as u128;
            let mut y = 0u128;
            for a in coeffs.iter().rev() {
                y = add(mul(y, x), *a);
            }
            s.y.push(y);
        }
    }
    shares
}

/// Lagrange interpolation at 0 from the given shares (at least t distinct x).
/// With fewer than t shares the result is an unrelated value, not an error:
/// Shamir cannot tell. Caller checks the count (see threshold.rs).
pub fn reconstruct(shares: &[Share], secret_len: usize) -> Vec<u8> {
    assert!(!shares.is_empty());
    let chunks = shares[0].y.len();
    // Lagrange coefficients at 0
    let mut lambdas = Vec::with_capacity(shares.len());
    for (j, sj) in shares.iter().enumerate() {
        let mut num = 1u128;
        let mut den = 1u128;
        for (m, sm) in shares.iter().enumerate() {
            if m != j {
                num = mul(num, sm.x as u128);
                den = mul(den, sub(sm.x as u128, sj.x as u128));
            }
        }
        lambdas.push(mul(num, inv(den)));
    }
    let mut elems = Vec::with_capacity(chunks);
    for c in 0..chunks {
        let mut acc = 0u128;
        for (j, s) in shares.iter().enumerate() {
            acc = add(acc, mul(lambdas[j], s.y[c]));
        }
        elems.push(acc);
    }
    decode_secret(&elems, secret_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    /// Slow exact reference: double-and-add modular multiplication.
    fn mul_ref(a: u128, b: u128) -> u128 {
        let mut r = 0u128;
        let mut a = a % P;
        let mut b = b;
        while b > 0 {
            if b & 1 == 1 {
                r = (r + a) % P;
            }
            a = (a + a) % P;
            b >>= 1;
        }
        r
    }

    #[test]
    fn field_ops_match_reference() {
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let edge = [0u128, 1, 2, P - 1, P - 2, 1 << 64, (1 << 64) - 1, (1 << 126), P / 2];
        for &a in &edge {
            for &b in &edge {
                assert_eq!(mul(a, b), mul_ref(a, b), "a={} b={}", a, b);
                assert_eq!(add(a, b), (a + b) % P);
                assert_eq!(sub(a, b), (a + P - b) % P);
            }
        }
        for _ in 0..2000 {
            let (a, b) = (rand_elem(&mut rng), rand_elem(&mut rng));
            assert_eq!(mul(a, b), mul_ref(a, b));
        }
        for _ in 0..50 {
            let a = rand_elem(&mut rng);
            if a != 0 {
                assert_eq!(mul(a, inv(a)), 1);
            }
        }
        assert_eq!(pow(2, 127), 1); // 2^127 = 1 mod p
    }

    #[test]
    fn secret_encoding_roundtrip() {
        for len in [0usize, 1, 14, 15, 16, 31, 32, 33, 64] {
            let s: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let e = encode_secret(&s);
            assert_eq!(e.len(), chunks_for(len));
            assert!(e.iter().all(|&x| x < P));
            assert_eq!(decode_secret(&e, len), s);
        }
    }

    #[test]
    fn t_shares_reconstruct_for_every_subset_size_ge_t() {
        let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
        for &(t, n) in &[(2usize, 3usize), (3, 5), (5, 9), (7, 13)] {
            let secret: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(13).wrapping_add(5)).collect();
            let shares = deal(&secret, t, n, &mut rng);
            assert_eq!(shares.len(), n);
            // sliding windows and a reversed subset, sizes t..=n
            for size in t..=n {
                for start in 0..=(n - size) {
                    assert_eq!(reconstruct(&shares[start..start + size], 32), secret);
                }
                let rev: Vec<Share> = shares.iter().rev().take(size).cloned().collect();
                assert_eq!(reconstruct(&rev, 32), secret);
            }
        }
    }

    #[test]
    fn fewer_than_t_shares_do_not_give_the_secret() {
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        let secret = [0xABu8; 32];
        let (t, n) = (5, 9);
        let shares = deal(&secret, t, n, &mut rng);
        for k in 1..t {
            let got = reconstruct(&shares[..k], 32);
            assert_ne!(got, secret.to_vec(), "k={} shares revealed the secret", k);
        }
        // (Perfect secrecy of t-1 shares is the textbook property of Shamir over a
        // field; it is not something a unit test can show, so we only check that
        // sub-threshold reconstruction does not return the secret.)
    }

    #[test]
    fn tampered_share_gives_wrong_secret_not_error() {
        // Plain Shamir has no robustness: documented limitation, tested so nobody
        // assumes otherwise.
        let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
        let secret = [9u8; 32];
        let mut shares = deal(&secret, 3, 5, &mut rng);
        shares[0].y[0] = add(shares[0].y[0], 1);
        assert_ne!(reconstruct(&shares[..3], 32), secret.to_vec());
    }

    #[test]
    fn same_seed_same_shares() {
        let s = [5u8; 32];
        let a = deal(&s, 3, 5, &mut ChaCha20Rng::from_seed([9u8; 32]));
        let b = deal(&s, 3, 5, &mut ChaCha20Rng::from_seed([9u8; 32]));
        let c = deal(&s, 3, 5, &mut ChaCha20Rng::from_seed([10u8; 32]));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
