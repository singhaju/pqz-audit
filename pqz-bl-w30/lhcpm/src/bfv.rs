//! BFV-style RLWE encryption/decryption in RNS with two ~54-bit NTT primes.
//! Decryption: m = round(t/q * [c0 + c1*s]_q) mod t, with c1*s by NTT (single thread).
use crate::ring::*;
use rand::Rng;

pub struct Params {
    pub n: usize,
    pub primes: Vec<Prime>,
    pub q: u128,
    pub tlog: u32,
    pub sigma: f64,
    delta: u128,
    inv_p0_mod_p1: (u64, u64),
}

pub struct SecretKey {
    w: Vec<Vec<u64>>,
    wp: Vec<Vec<u64>>,
    pub s: Vec<i8>, // kept for tests
}

pub struct PublicKey {
    pub p0: Vec<Vec<u64>>,
    pub p1: Vec<Vec<u64>>,
}

#[derive(Clone)]
pub struct Ciphertext {
    pub c0: Vec<Vec<u64>>,
    pub c1: Vec<Vec<u64>>,
}

impl Ciphertext {
    pub fn bytes(&self) -> usize {
        (self.c0.iter().chain(self.c1.iter()).map(|v| v.len()).sum::<usize>()) * 8
    }
}

impl Params {
    /// n = ring degree, two primes < 2^54 (q about 2^108), t = 2^tlog.
    pub fn new(n: usize, tlog: u32, sigma: f64) -> Self {
        let ps = find_ntt_primes(n, 54, 2);
        let primes: Vec<Prime> = ps.iter().map(|&p| Prime::new(p, n)).collect();
        let q = ps[0] as u128 * ps[1] as u128;
        let delta = q >> tlog; // floor(q / 2^tlog)
        let inv = pow_mod(ps[0] % ps[1], ps[1] - 2, ps[1]);
        Params { n, primes, q, tlog, sigma, delta, inv_p0_mod_p1: (inv, shoup_pre(inv, ps[1])) }
    }

    pub fn log_q(&self) -> u32 {
        128 - self.q.leading_zeros()
    }

    fn gauss<R: Rng>(&self, rng: &mut R) -> i64 {
        // rounded Gaussian by Box-Muller, tail cut at 6 sigma
        loop {
            let u1: f64 = 1.0 - rng.gen::<f64>();
            let u2: f64 = rng.gen::<f64>();
            let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos() * self.sigma;
            let r = z.round();
            if r.abs() <= 6.0 * self.sigma {
                return r as i64;
            }
        }
    }

    fn to_rns(&self, v: &[i64]) -> Vec<Vec<u64>> {
        self.primes
            .iter()
            .map(|pr| v.iter().map(|&x| if x >= 0 { x as u64 % pr.p } else { pr.p - ((-x) as u64 % pr.p) }).map(|y| if y == pr.p { 0 } else { y }).collect())
            .collect()
    }

    fn ternary<R: Rng>(&self, rng: &mut R) -> Vec<i8> {
        (0..self.n).map(|_| rng.gen_range(-1i8..=1)).collect()
    }

    pub fn keygen<R: Rng>(&self, rng: &mut R) -> (SecretKey, PublicKey) {
        let s = self.ternary(rng);
        let s64: Vec<i64> = s.iter().map(|&x| x as i64).collect();
        let srns = self.to_rns(&s64);
        let mut w = vec![];
        let mut wp = vec![];
        for (i, pr) in self.primes.iter().enumerate() {
            let mut x = srns[i].clone();
            pr.ntt_fwd(&mut x);
            wp.push(x.iter().map(|&v| shoup_pre(v, pr.p)).collect());
            w.push(x);
        }
        // pk = (-(a s) + e, a)
        let e: Vec<i64> = (0..self.n).map(|_| self.gauss(rng)).collect();
        let ern = self.to_rns(&e);
        let mut p0 = vec![];
        let mut p1 = vec![];
        for (i, pr) in self.primes.iter().enumerate() {
            let a: Vec<u64> = (0..self.n).map(|_| rng.gen_range(0..pr.p)).collect();
            let asp = pr.poly_mul(&a, &srns[i]);
            let b: Vec<u64> = (0..self.n)
                .map(|j| {
                    let neg = if asp[j] == 0 { 0 } else { pr.p - asp[j] };
                    let sum = neg + ern[i][j];
                    if sum >= pr.p { sum - pr.p } else { sum }
                })
                .collect();
            p0.push(b);
            p1.push(a);
        }
        (SecretKey { w, wp, s }, PublicKey { p0, p1 })
    }

    /// m: n values in [0, t).
    pub fn encrypt<R: Rng>(&self, pk: &PublicKey, m: &[u64], rng: &mut R) -> Ciphertext {
        assert_eq!(m.len(), self.n);
        let u: Vec<i64> = self.ternary(rng).iter().map(|&x| x as i64).collect();
        let e1: Vec<i64> = (0..self.n).map(|_| self.gauss(rng)).collect();
        let e2: Vec<i64> = (0..self.n).map(|_| self.gauss(rng)).collect();
        let urns = self.to_rns(&u);
        let e1r = self.to_rns(&e1);
        let e2r = self.to_rns(&e2);
        let mut c0 = vec![];
        let mut c1 = vec![];
        for (i, pr) in self.primes.iter().enumerate() {
            let d = (self.delta % pr.p as u128) as u64;
            let a0 = pr.poly_mul(&pk.p0[i], &urns[i]);
            let a1 = pr.poly_mul(&pk.p1[i], &urns[i]);
            c0.push((0..self.n).map(|j| (a0[j] + e1r[i][j] + mul_mod(d, m[j], pr.p)) % pr.p).collect());
            c1.push((0..self.n).map(|j| (a1[j] + e2r[i][j]) % pr.p).collect());
        }
        Ciphertext { c0, c1 }
    }

    /// round(t * x / q) mod t, exact (f64 estimate corrected with exact 128-bit remainder).
    #[inline(always)]
    fn scale_round(&self, x: u128) -> u64 {
        let q = self.q;
        let t = 1u64 << self.tlog;
        let xt = x.wrapping_shl(self.tlog); // low 128 bits of x*t
        let mut d = ((x as f64) * (t as f64 / q as f64)) as u128;
        let mut r = xt.wrapping_sub(d.wrapping_mul(q)) as i128;
        let qi = q as i128;
        while r < 0 {
            d -= 1;
            r += qi;
        }
        while r >= qi {
            d += 1;
            r -= qi;
        }
        if 2 * r >= qi {
            d += 1;
        }
        (d as u64) & (t - 1)
    }

    /// BFV decryption.  c1*s is computed with the NTT (2 transforms per RNS prime).
    pub fn decrypt(&self, sk: &SecretKey, ct: &Ciphertext) -> Vec<u64> {
        let n = self.n;
        let mut res: Vec<Vec<u64>> = Vec::with_capacity(self.primes.len());
        for (i, pr) in self.primes.iter().enumerate() {
            let p = pr.p;
            let mut tmp = ct.c1[i].clone();
            pr.ntt_fwd(&mut tmp);
            for j in 0..n {
                tmp[j] = shoup_mul(tmp[j], sk.w[i][j], sk.wp[i][j], p);
            }
            pr.ntt_inv(&mut tmp);
            for j in 0..n {
                let s = tmp[j] + ct.c0[i][j];
                tmp[j] = if s >= p { s - p } else { s };
            }
            res.push(tmp);
        }
        let p0 = self.primes[0].p;
        let p1 = self.primes[1].p;
        let (iv, ivp) = self.inv_p0_mod_p1;
        (0..n)
            .map(|j| {
                let r0 = res[0][j];
                let r1 = res[1][j];
                // Garner: x = r0 + p0 * ((r1 - r0) * p0^-1 mod p1)
                let r0m = r0 % p1;
                let diff = if r1 >= r0m { r1 - r0m } else { r1 + p1 - r0m };
                let h = shoup_mul(diff, iv, ivp, p1);
                let x = r0 as u128 + p0 as u128 * h as u128;
                self.scale_round(x)
            })
            .collect()
    }
}
