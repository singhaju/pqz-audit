//! Negacyclic NTT over Z_p[X]/(X^n+1), single thread, Shoup multiplication by constants.
//! Layout follows the standard Longa-Naehrig / SEAL scheme: Cooley-Tukey forward (bit-reversed
//! output), Gentleman-Sande inverse, twiddle tables in bit-reversed order.

pub fn mul_mod(a: u64, b: u64, p: u64) -> u64 {
    ((a as u128 * b as u128) % p as u128) as u64
}

pub fn pow_mod(mut a: u64, mut e: u64, p: u64) -> u64 {
    let mut r = 1u64;
    a %= p;
    while e > 0 {
        if e & 1 == 1 {
            r = mul_mod(r, a, p);
        }
        a = mul_mod(a, a, p);
        e >>= 1;
    }
    r
}

/// Deterministic Miller-Rabin for u64.
pub fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    for sp in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if n % sp == 0 {
            return n == sp;
        }
    }
    let mut d = n - 1;
    let mut s = 0;
    while d % 2 == 0 {
        d /= 2;
        s += 1;
    }
    'outer: for a in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let mut x = pow_mod(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 0..s - 1 {
            x = mul_mod(x, x, n);
            if x == n - 1 {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

/// The `count` largest primes p < 2^bits with p = 1 mod 2n (NTT friendly).
pub fn find_ntt_primes(n: usize, bits: u32, count: usize) -> Vec<u64> {
    let m = 2 * n as u64;
    let mut k = ((1u64 << bits) - 1) / m;
    let mut out = Vec::new();
    while out.len() < count {
        let p = k * m + 1;
        if is_prime(p) {
            out.push(p);
        }
        k -= 1;
    }
    out
}

#[inline(always)]
pub fn shoup_pre(w: u64, p: u64) -> u64 {
    (((w as u128) << 64) / p as u128) as u64
}

/// Lazy Shoup product: result in [0, 2p), any a < 2^64.
#[inline(always)]
pub fn shoup_lazy(a: u64, w: u64, wp: u64, p: u64) -> u64 {
    let q = ((a as u128 * wp as u128) >> 64) as u64;
    a.wrapping_mul(w).wrapping_sub(q.wrapping_mul(p))
}

/// a*w mod p with precomputed wp = floor(w*2^64/p); requires p < 2^63, a < p.
#[inline(always)]
pub fn shoup_mul(a: u64, w: u64, wp: u64, p: u64) -> u64 {
    let q = ((a as u128 * wp as u128) >> 64) as u64;
    let r = a.wrapping_mul(w).wrapping_sub(q.wrapping_mul(p));
    if r >= p {
        r - p
    } else {
        r
    }
}

fn bitrev(mut x: usize, bits: u32) -> usize {
    let mut r = 0;
    for _ in 0..bits {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

pub struct Prime {
    pub p: u64,
    pub n: usize,
    psi_rev: Vec<(u64, u64)>,
    psi_inv_rev: Vec<(u64, u64)>,
    n_inv: (u64, u64),
}

impl Prime {
    pub fn new(p: u64, n: usize) -> Self {
        assert!(n.is_power_of_two() && (p - 1) % (2 * n as u64) == 0 && p < (1 << 63));
        let mut psi = 0;
        for g in 2u64.. {
            let c = pow_mod(g, (p - 1) / (2 * n as u64), p);
            if pow_mod(c, n as u64, p) == p - 1 {
                psi = c;
                break;
            }
        }
        let psi_inv = pow_mod(psi, p - 2, p);
        let lg = n.trailing_zeros();
        let mut psi_rev = vec![(0, 0); n];
        let mut psi_inv_rev = vec![(0, 0); n];
        let mut pw = vec![1u64; n];
        let mut pwi = vec![1u64; n];
        for i in 1..n {
            pw[i] = mul_mod(pw[i - 1], psi, p);
            pwi[i] = mul_mod(pwi[i - 1], psi_inv, p);
        }
        for i in 0..n {
            let r = bitrev(i, lg);
            psi_rev[i] = (pw[r], shoup_pre(pw[r], p));
            psi_inv_rev[i] = (pwi[r], shoup_pre(pwi[r], p));
        }
        let ninv = pow_mod(n as u64, p - 2, p);
        Prime { p, n, psi_rev, psi_inv_rev, n_inv: (ninv, shoup_pre(ninv, p)) }
    }

    /// Forward transform, Harvey lazy butterflies (values kept in [0, 4p), as in SEAL); input in [0, p), output in [0, p).
    pub fn ntt_fwd(&self, a: &mut [u64]) {
        let n = self.n;
        let p = self.p;
        let p2 = 2 * p;
        assert_eq!(a.len(), n);
        let mut t = n;
        let mut m = 1;
        while m < n {
            t >>= 1;
            for i in 0..m {
                let (w, wp) = self.psi_rev[m + i];
                let j1 = 2 * i * t;
                let (lo, hi) = a[j1..j1 + 2 * t].split_at_mut(t);
                for (x, y) in lo.iter_mut().zip(hi.iter_mut()) {
                    let u = if *x >= p2 { *x - p2 } else { *x };
                    let v = shoup_lazy(*y, w, wp, p);
                    *x = u + v;
                    *y = u + p2 - v;
                }
            }
            m <<= 1;
        }
        for x in a.iter_mut() {
            let mut v = *x;
            if v >= p2 {
                v -= p2;
            }
            if v >= p {
                v -= p;
            }
            *x = v;
        }
    }

    /// Inverse transform including the n^-1 scaling; input in [0, p), output in [0, p).
    pub fn ntt_inv(&self, a: &mut [u64]) {
        let n = self.n;
        let p = self.p;
        let p2 = 2 * p;
        assert_eq!(a.len(), n);
        let mut t = 1;
        let mut m = n;
        while m > 1 {
            let h = m >> 1;
            let mut j1 = 0;
            for i in 0..h {
                let (w, wp) = self.psi_inv_rev[h + i];
                let (lo, hi) = a[j1..j1 + 2 * t].split_at_mut(t);
                for (x, y) in lo.iter_mut().zip(hi.iter_mut()) {
                    let u = *x;
                    let v = *y;
                    let s = u + v;
                    *x = if s >= p2 { s - p2 } else { s };
                    *y = shoup_lazy(u + p2 - v, w, wp, p);
                }
                j1 += 2 * t;
            }
            t <<= 1;
            m = h;
        }
        let (w, wp) = self.n_inv;
        for x in a.iter_mut() {
            *x = shoup_mul(*x, w, wp, p);
        }
    }

    /// Setup-only product (plain mulmod, not timed anywhere).
    pub fn poly_mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let mut x = a.to_vec();
        let mut y = b.to_vec();
        self.ntt_fwd(&mut x);
        self.ntt_fwd(&mut y);
        for i in 0..self.n {
            x[i] = mul_mod(x[i], y[i], self.p);
        }
        self.ntt_inv(&mut x);
        x
    }
}
