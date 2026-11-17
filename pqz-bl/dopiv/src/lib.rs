//! DOPIV (Zhang et al., IEEE TSC 2022): Challenge, ProofGen, ProofVerify and delegation
//! verification, implemented from the algorithm text (Section 4.2, printed pp. 339-340).
//! See FIDELITY.md for what runs, what is simplified and what is not run.
//!
//! Notation follows the paper: Q_pro (proxy-oriented signing public key), Q_IDc (cloud server public
//! key), Q_IDo (owner public key), B = (lambda_1..lambda_n)^T with lambda_j = H5(ID_p || j),
//! eta_i = H4(N_i||i) + Q_IDc F_i, rho_i = B eta_i, Q_pro e_i = rho_i, Proof = (f, e, xi),
//! mu = B( sum beta_i H4(N_i||i) + Q_IDc f - xi H6(w||v_w||theta_w||xi) ), check Q_pro e = mu mod q
//! and 0 < ||e|| <= c sigma sqrt(m).

use sha3::{Digest, Sha3_256};

// ---------------------------------------------------------------- meters

/// Operation meter. `NoMeter` compiles to nothing (used for timing); `Counts` counts every operation
/// that is actually executed (used for the operation-count check).
pub trait Meter {
    #[inline(always)]
    fn mul(&mut self) {}
    #[inline(always)]
    fn sq(&mut self) {}
    #[inline(always)]
    fn hash(&mut self) {}
    #[inline(always)]
    fn sha3(&mut self, _n: u64) {}
    #[inline(always)]
    fn add(&mut self, _n: u64) {}
    #[inline(always)]
    fn mark(&mut self, _label: &'static str) {}
}

pub struct NoMeter;
impl Meter for NoMeter {}

#[derive(Default, Clone, Debug)]
pub struct Counts {
    /// modular multiplications in Z_q (the paper's `mul`)
    pub mul: u64,
    /// squarings for the norm check (NOT in the paper's formula)
    pub sq: u64,
    /// logical hash evaluations H_k(...) (the paper's `Hash`)
    pub hash: u64,
    /// SHA3-256 permutation calls actually executed (output expansion + long inputs)
    pub sha3: u64,
    /// vector-element additions in explicit vector loops (not inside mat-vec products)
    pub add: u64,
    /// snapshots (label, mul, sq, hash, sha3, add) taken after each step
    pub log: Vec<(&'static str, u64, u64, u64, u64, u64)>,
}
impl Meter for Counts {
    #[inline(always)]
    fn mul(&mut self) {
        self.mul += 1;
    }
    #[inline(always)]
    fn sq(&mut self) {
        self.sq += 1;
    }
    #[inline(always)]
    fn hash(&mut self) {
        self.hash += 1;
    }
    #[inline(always)]
    fn sha3(&mut self, n: u64) {
        self.sha3 += n;
    }
    #[inline(always)]
    fn add(&mut self, n: u64) {
        self.add += n;
    }
    fn mark(&mut self, label: &'static str) {
        self.log.push((label, self.mul, self.sq, self.hash, self.sha3, self.add));
    }
}
impl Counts {
    /// per-step deltas from the marks: (label, mul, sq, hash, sha3, add)
    pub fn deltas(&self) -> Vec<(&'static str, u64, u64, u64, u64, u64)> {
        let mut prev = (0, 0, 0, 0, 0);
        let mut out = vec![];
        for &(l, a, b, c, d, e) in &self.log {
            out.push((l, a - prev.0, b - prev.1, c - prev.2, d - prev.3, e - prev.4));
            prev = (a, b, c, d, e);
        }
        out
    }
}

// ---------------------------------------------------------------- rng (reproducible, not for security)

#[derive(Clone)]
pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed ^ 0x9E37_79B9_7F4A_7C15)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        // rejection sampling, unbiased
        let lim = u64::MAX - (u64::MAX % n);
        loop {
            let x = self.next_u64();
            if x < lim {
                return x % n;
            }
        }
    }
    pub fn zq(&mut self, q: u64) -> u32 {
        self.below(q) as u32
    }
}

// ---------------------------------------------------------------- parameters

#[derive(Clone, Debug)]
pub struct Params {
    pub n: usize,
    pub m: usize,
    pub q: u64,
}
impl Params {
    /// the paper's bound m >= ceil(2 n log2 q) (Lemma 2)
    pub fn m_bound(&self) -> usize {
        (2.0 * self.n as f64 * (self.q as f64).log2()).ceil() as usize
    }
    pub fn bound_ok(&self) -> bool {
        self.m >= self.m_bound()
    }
    pub fn label(&self, c: Option<usize>, lazy: bool) -> String {
        let mut s = format!("n={};m={};q={}", self.n, self.m, self.q);
        if let Some(c) = c {
            s.push_str(&format!(";c={}", c));
        }
        s.push_str(if self.bound_ok() { ";bound=ok" } else { ";bound=VIOLATED" });
        if lazy {
            s.push_str(";red=lazy");
        }
        s
    }
}

// ---------------------------------------------------------------- field helpers

#[inline(always)]
fn lift(x: u32, q: u64) -> i64 {
    let x = x as u64;
    if x > q / 2 {
        x as i64 - q as i64
    } else {
        x as i64
    }
}
#[inline(always)]
fn from_signed(x: i64, q: u64) -> u32 {
    x.rem_euclid(q as i64) as u32
}
fn powmod(mut a: u64, mut e: u64, q: u64) -> u64 {
    let mut r = 1u64;
    a %= q;
    while e > 0 {
        if e & 1 == 1 {
            r = r * a % q;
        }
        a = a * a % q;
        e >>= 1;
    }
    r
}

/// out = A x mod q, A is rows x cols row-major, every entry < q < 2^32.
/// `lazy = false`: one reduction per multiplication (the paper's `mul` = modular multiplication in Z_q).
/// `lazy = true`: products accumulated in u128 and reduced once per row (same number of multiplications).
pub fn matvec<M: Meter>(
    a: &[u32],
    rows: usize,
    cols: usize,
    x: &[u32],
    q: u64,
    lazy: bool,
    meter: &mut M,
    out: &mut [u32],
) {
    debug_assert_eq!(a.len(), rows * cols);
    debug_assert_eq!(x.len(), cols);
    debug_assert_eq!(out.len(), rows);
    if lazy {
        for r in 0..rows {
            let row = &a[r * cols..(r + 1) * cols];
            let mut acc: u128 = 0;
            for j in 0..cols {
                acc += (row[j] as u64 * x[j] as u64) as u128;
                meter.mul();
            }
            out[r] = (acc % q as u128) as u32;
        }
    } else {
        for r in 0..rows {
            let row = &a[r * cols..(r + 1) * cols];
            let mut acc: u64 = 0;
            for j in 0..cols {
                acc += (row[j] as u64 * x[j] as u64) % q;
                meter.mul();
            }
            out[r] = (acc % q) as u32;
        }
    }
}

fn matvec_setup(a: &[u32], rows: usize, cols: usize, x: &[u32], q: u64) -> Vec<u32> {
    let mut out = vec![0u32; rows];
    matvec(a, rows, cols, x, q, true, &mut NoMeter, &mut out);
    out
}

/// Gauss-Jordan inverse of an n x n matrix over Z_q (q prime). None if singular.
fn invert(b: &[u32], n: usize, q: u64) -> Option<Vec<u32>> {
    let w = 2 * n;
    let mut a = vec![0u64; n * w];
    for r in 0..n {
        for c in 0..n {
            a[r * w + c] = b[r * n + c] as u64;
        }
        a[r * w + n + r] = 1;
    }
    for col in 0..n {
        let p = (col..n).find(|&r| a[r * w + col] != 0)?;
        if p != col {
            for c in 0..w {
                a.swap(p * w + c, col * w + c);
            }
        }
        let inv = powmod(a[col * w + col], q - 2, q);
        for c in 0..w {
            a[col * w + c] = a[col * w + c] * inv % q;
        }
        for r in 0..n {
            if r != col {
                let f = a[r * w + col];
                if f != 0 {
                    for c in 0..w {
                        let t = f * a[col * w + c] % q;
                        a[r * w + c] = (a[r * w + c] + q - t) % q;
                    }
                }
            }
        }
    }
    let mut inv = vec![0u32; n * n];
    for r in 0..n {
        for c in 0..n {
            inv[r * n + c] = a[r * w + n + c] as u32;
        }
    }
    Some(inv)
}

// ---------------------------------------------------------------- hash functions H2, H4, H5, H6
// Hash = SHA3-256 (the paper says only "a general hash function"). A hash whose range is Z_q^k is
// built by counter-mode expansion with rejection (output word accepted iff < q), so one logical
// Hash = ceil(4k/32)+ SHA3-256 calls. Both numbers are counted.

fn u32s_to_bytes(v: &[u32]) -> Vec<u8> {
    let mut o = Vec::with_capacity(v.len() * 4);
    for x in v {
        o.extend_from_slice(&x.to_le_bytes());
    }
    o
}

/// logical hash `domain(parts) -> Z_q^len`
pub fn expand_zq<M: Meter>(domain: &[u8], parts: &[&[u8]], len: usize, q: u64, meter: &mut M) -> Vec<u32> {
    meter.hash();
    let mut out = Vec::with_capacity(len);
    let mut ctr = 0u32;
    while out.len() < len {
        let mut h = Sha3_256::new();
        h.update(domain);
        let mut total = 0usize;
        for p in parts {
            h.update((p.len() as u64).to_le_bytes());
            h.update(p);
            total += p.len() + 8;
        }
        h.update(ctr.to_le_bytes());
        let d = h.finalize();
        // Keccak-f[1600] permutations for this SHA3-256 call: rate 136 bytes, padding included
        let msg = domain.len() + total + 4;
        meter.sha3((msg / 136 + 1) as u64);
        for ch in d.chunks_exact(4) {
            let w = u32::from_le_bytes([ch[0], ch[1], ch[2], ch[3]]);
            if (w as u64) < q && out.len() < len {
                out.push(w);
            }
        }
        ctr += 1;
    }
    out
}

// ---------------------------------------------------------------- scheme data

pub const SHORT: i64 = 255; // our choice: tag/mask entries uniform in [-255, 255]

#[derive(Clone)]
pub struct Instance {
    pub p: Params,
    pub ell: usize,
    pub id_o: Vec<u8>,
    pub id_p: Vec<u8>,
    pub warrant: Vec<u8>,
    pub q_pro: Vec<u32>, // n x m
    pub q_idc: Vec<u32>, // n x m
    pub q_ido: Vec<u32>, // n x m
    pub v_w: Vec<u32>,   // n
    pub theta_w: Vec<u32>, // m (short, mod q)
    pub files: Vec<Vec<u32>>, // ell x m
    pub names: Vec<Vec<u8>>,
    pub tags: Vec<Vec<i16>>, // ell x m, short e_i
    pub sigma: u64,          // our sigma: ceil(max_i ||e_i|| / sqrt(m))
    pub lazy: bool,
}

pub struct Challenge {
    pub idx: Vec<usize>,
    pub beta: Vec<u8>,
}

pub struct Proof {
    pub f: Vec<u32>,
    pub e: Vec<u32>,
    pub xi: Vec<u32>,
}

fn h4<M: Meter>(inst: &Instance, i: usize, meter: &mut M) -> Vec<u32> {
    expand_zq(b"DOPIV-H4", &[&inst.names[i], &(i as u64).to_le_bytes()], inst.p.n, inst.p.q, meter)
}
fn h5<M: Meter>(id_p: &[u8], j: usize, n: usize, q: u64, meter: &mut M) -> Vec<u32> {
    expand_zq(b"DOPIV-H5", &[id_p, &(j as u64).to_le_bytes()], n, q, meter)
}
fn h2<M: Meter>(inst: &Instance, meter: &mut M) -> Vec<u32> {
    expand_zq(
        b"DOPIV-H2",
        &[&inst.id_o, &inst.id_p, &inst.warrant, &u32s_to_bytes(&inst.v_w)],
        inst.p.n,
        inst.p.q,
        meter,
    )
}
fn h6<M: Meter>(inst: &Instance, xi: &[u32], meter: &mut M) -> u64 {
    expand_zq(
        b"DOPIV-H6",
        &[&inst.warrant, &u32s_to_bytes(&inst.v_w), &u32s_to_bytes(&inst.theta_w), &u32s_to_bytes(xi)],
        1,
        inst.p.q,
        meter,
    )[0] as u64
}

impl Instance {
    /// Untimed set-up. Produces consistent keys, a delegation (w, v_w, theta_w) and `ell` data blocks
    /// with tags e_i such that Q_pro e_i = B (H4(N_i||i) + Q_IDc F_i) (mod q), e_i short.
    /// The trapdoor algorithms (TrapGen, NewBasisDel, SamplePre) are NOT run: see FIDELITY.md
    /// ("planting").
    pub fn setup(p: &Params, ell: usize, seed: u64, lazy: bool) -> Instance {
        let (n, m, q) = (p.n, p.m, p.q);
        assert!(q >= (1 << 31) && q < (1 << 32), "q must be a prime in [2^31, 2^32)");
        assert!(m > n, "need m > n");
        let mut rng = Rng::new(seed);
        let q_pro: Vec<u32> = (0..n * m).map(|_| rng.zq(q)).collect();
        // Q_IDc = [I_n | W]
        let mut q_idc = vec![0u32; n * m];
        for r in 0..n {
            q_idc[r * m + r] = 1;
            for c in n..m {
                q_idc[r * m + c] = rng.zq(q);
            }
        }
        // identities; B must be invertible mod q, so bump a salt in ID_p if not
        let id_o = b"ID_owner@example".to_vec();
        let mut salt = 0u32;
        let (id_p, binv) = loop {
            let id_p = format!("ID_proxy#{}@example", salt).into_bytes();
            let mut b = Vec::with_capacity(n * n);
            for j in 0..n {
                b.extend(h5(&id_p, j, n, q, &mut NoMeter));
            }
            if let Some(inv) = invert(&b, n, q) {
                break (id_p, inv);
            }
            salt += 1;
        };
        let warrant = [
            b"warrant|owner=".as_slice(),
            &id_o,
            b"|proxy=",
            &id_p,
            b"|policy=outsource-file0|valid=2027-12-31",
        ]
        .concat();
        let mut inst = Instance {
            p: p.clone(),
            ell,
            id_o,
            id_p,
            warrant,
            q_pro,
            q_idc,
            q_ido: vec![],
            v_w: (0..n).map(|_| rng.zq(q)).collect(),
            theta_w: vec![],
            files: Vec::with_capacity(ell),
            names: (0..ell).map(|i| format!("file0/blk{}", i).into_bytes()).collect(),
            tags: Vec::with_capacity(ell),
            sigma: 0,
            lazy,
        };
        // ---- delegation: Q_IDo theta_w = H2(IDo||IDp||w||v_w) with theta_w short (planted via column 0)
        let t = h2(&inst, &mut NoMeter);
        let mut theta = vec![0i64; m];
        for x in theta.iter_mut() {
            *x = rng.below(2 * SHORT as u64 + 1) as i64 - SHORT;
        }
        theta[0] = 1;
        let theta_q: Vec<u32> = theta.iter().map(|&x| from_signed(x, q)).collect();
        let mut q_ido: Vec<u32> = (0..n * m).map(|_| rng.zq(q)).collect();
        for r in 0..n {
            q_ido[r * m] = 0;
        }
        let s = matvec_setup(&q_ido, n, m, &theta_q, q);
        for r in 0..n {
            q_ido[r * m] = ((t[r] as u64 + q - s[r] as u64) % q) as u32;
        }
        inst.q_ido = q_ido;
        inst.theta_w = theta_q;
        // ---- tags and data
        let mut max_norm2: u128 = 0;
        for i in 0..ell {
            let e: Vec<i16> = (0..m).map(|_| (rng.below(2 * SHORT as u64 + 1) as i64 - SHORT) as i16).collect();
            let n2: u128 = e.iter().map(|&x| (x as i128 * x as i128) as u128).sum();
            max_norm2 = max_norm2.max(n2);
            let eq: Vec<u32> = e.iter().map(|&x| from_signed(x as i64, q)).collect();
            let rho = matvec_setup(&inst.q_pro, n, m, &eq, q); // Q_pro e_i
            let eta = matvec_setup(&binv, n, n, &rho, q); // B^{-1} rho_i
            let hh = h4(&inst, i, &mut NoMeter);
            let target: Vec<u64> = (0..n).map(|k| (eta[k] as u64 + q - hh[k] as u64) % q).collect();
            // F = [F_head | F_tail], Q_IDc F = F_head + W F_tail = target
            let mut f = vec![0u32; m];
            for c in n..m {
                f[c] = rng.zq(q);
            }
            let wf = matvec_setup(&inst.q_idc, n, m, &f, q); // F_head is still 0 here: = W F_tail
            for k in 0..n {
                f[k] = ((target[k] + q - wf[k] as u64) % q) as u32;
            }
            inst.files.push(f);
            inst.tags.push(e);
        }
        let mut sigma = ((max_norm2 as f64).sqrt() / (m as f64).sqrt()).ceil() as u64;
        if sigma == 0 {
            sigma = 1;
        }
        inst.sigma = sigma;
        inst
    }
}

// ---------------------------------------------------------------- Challenge (TPA)

/// random c-element subset V of {0..ell-1} and random binary beta in {0,1}^c (never all zero)
pub fn challenge(ell: usize, c: usize, rng: &mut Rng) -> Challenge {
    assert!(c <= ell);
    let mut pool: Vec<usize> = (0..ell).collect();
    for k in 0..c {
        let j = k + rng.below((ell - k) as u64) as usize;
        pool.swap(k, j);
    }
    let idx = pool[..c].to_vec();
    let mut beta: Vec<u8> = (0..c).map(|_| (rng.next_u64() & 1) as u8).collect();
    if beta.iter().all(|&b| b == 0) {
        beta[0] = 1;
    }
    Challenge { idx, beta }
}

// ---------------------------------------------------------------- ProofGen (cloud server)

/// f' = sum beta_i F_i, e = sum beta_i e_i, mask xi with signature h (Q_IDc h = xi), f = f' + h H6(...)
/// The paper runs SamplePre(Q_IDc, T_IDc, xi, sigma) to get h. We have no trapdoor, so h is a short
/// random vector and xi := Q_IDc h (n*m mul). SamplePre itself is NOT run (see FIDELITY.md).
pub fn proofgen<M: Meter>(inst: &Instance, chal: &Challenge, rng: &mut Rng, meter: &mut M) -> Proof {
    let (n, m, q) = (inst.p.n, inst.p.m, inst.p.q);
    let mut facc = vec![0u64; m];
    let mut eacc = vec![0i64; m];
    for (k, &i) in chal.idx.iter().enumerate() {
        if chal.beta[k] == 1 {
            let fi = &inst.files[i];
            let ei = &inst.tags[i];
            for j in 0..m {
                facc[j] += fi[j] as u64;
                eacc[j] += ei[j] as i64;
            }
            meter.add(2 * m as u64);
        }
    }
    let fprime: Vec<u32> = facc.iter().map(|&x| (x % q) as u32).collect();
    let e: Vec<u32> = eacc.iter().map(|&x| from_signed(x, q)).collect();
    meter.mark("proofgen: aggregate f', e");
    let h: Vec<u32> = (0..m)
        .map(|_| from_signed(rng.below(2 * SHORT as u64 + 1) as i64 - SHORT, q))
        .collect();
    let mut xi = vec![0u32; n];
    matvec(&inst.q_idc, n, m, &h, q, inst.lazy, meter, &mut xi);
    meter.mark("proofgen: xi = Q_IDc h (stand-in for SamplePre)");
    let t = h6(inst, &xi, meter);
    meter.mark("proofgen: H6");
    let mut f = vec![0u32; m];
    for j in 0..m {
        f[j] = ((fprime[j] as u64 + h[j] as u64 * t % q) % q) as u32;
        meter.mul();
    }
    meter.add(m as u64);
    meter.mark("proofgen: f = f' + h*H6");
    Proof { f, e, xi }
}

// ---------------------------------------------------------------- ProofVerify (TPA), steps 1-2

/// Step 1: B from H5, mu = B(sum beta_i H4(N_i||i) + Q_IDc f - xi H6(w||v_w||theta_w||xi)).
/// Step 2: Q_pro e == mu (mod q) and 0 < ||e|| <= c sigma sqrt(m) (compared squared, integers).
/// The validation of (w, v_w, theta_w) is `verify_delegation` (Table 2 lists it separately).
pub fn verify<M: Meter>(inst: &Instance, chal: &Challenge, pr: &Proof, meter: &mut M) -> bool {
    let (n, m, q) = (inst.p.n, inst.p.m, inst.p.q);
    if pr.f.len() != m || pr.e.len() != m || pr.xi.len() != n {
        return false;
    }
    // 1) lambda_j = H5(ID_p||j), B = (lambda_1..lambda_n)^T
    let mut bmat = Vec::with_capacity(n * n);
    for j in 0..n {
        bmat.extend(h5(&inst.id_p, j, n, q, meter));
    }
    meter.mark("H5 lambda_j (j=1..n)");
    // sum_i beta_i H4(N_i||i): every challenged index is hashed (the paper counts c Hash)
    let mut s = vec![0u64; n];
    for (k, &i) in chal.idx.iter().enumerate() {
        let hh = h4(inst, i, meter);
        if chal.beta[k] == 1 {
            for j in 0..n {
                s[j] += hh[j] as u64;
            }
            meter.add(n as u64);
        }
    }
    meter.mark("H4(N_i||i), i in V");
    let t = h6(inst, &pr.xi, meter);
    meter.mark("H6");
    let mut y = vec![0u32; n];
    matvec(&inst.q_idc, n, m, &pr.f, q, inst.lazy, meter, &mut y); // Q_IDc f
    meter.mark("mul: Q_IDc f");
    let mut v = vec![0u32; n];
    for j in 0..n {
        let z = pr.xi[j] as u64 * t % q; // xi * H6
        meter.mul();
        v[j] = ((s[j] % q + y[j] as u64 + q - z) % q) as u32;
    }
    meter.add(2 * n as u64);
    meter.mark("mul: xi*H6");
    let mut mu = vec![0u32; n];
    matvec(&bmat, n, n, &v, q, inst.lazy, meter, &mut mu); // mu = B v
    meter.mark("mul: B v");
    // 2) Q_pro e == mu
    let mut lhs = vec![0u32; n];
    matvec(&inst.q_pro, n, m, &pr.e, q, inst.lazy, meter, &mut lhs);
    meter.mark("mul: Q_pro e");
    let eq_ok = lhs == mu;
    // 0 < ||e|| <= c sigma sqrt(m)   <=>   0 < sum e_k^2 <= c^2 sigma^2 m
    let mut n2: u128 = 0;
    for &x in &pr.e {
        let l = lift(x, q) as i128;
        n2 += (l * l) as u128;
        meter.sq();
    }
    meter.mark("norm check (squares, not in paper formula)");
    let c = chal.idx.len() as u128;
    let bound = c * c * (inst.sigma as u128) * (inst.sigma as u128) * (m as u128);
    eq_ok && n2 > 0 && n2 <= bound
}

// ---------------------------------------------------------------- delegation verification

/// everybody can validate the signed warrant: Q_IDo theta_w == u_w = H2(ID_o||ID_p||w||v_w) (mod q),
/// and ID_p satisfies w (here: the warrant names ID_p and ID_o).
pub fn verify_delegation<M: Meter>(inst: &Instance, meter: &mut M) -> bool {
    let (n, m, q) = (inst.p.n, inst.p.m, inst.p.q);
    let u = h2(inst, meter);
    meter.mark("H2");
    let mut lhs = vec![0u32; n];
    matvec(&inst.q_ido, n, m, &inst.theta_w, q, inst.lazy, meter, &mut lhs);
    meter.mark("mul: Q_IDo theta_w");
    let contains = |h: &[u8], nd: &[u8]| h.windows(nd.len()).any(|w| w == nd);
    lhs == u && contains(&inst.warrant, &inst.id_p) && contains(&inst.warrant, &inst.id_o)
}

/// complete ProofVerify as the paper words it (validate warrant, then steps 1-2)
pub fn proof_verify_full<M: Meter>(inst: &Instance, chal: &Challenge, pr: &Proof, meter: &mut M) -> bool {
    verify_delegation(inst, meter) && verify(inst, chal, pr, meter)
}

/// the paper's Table 2 formulas, for the check only (never a result)
pub fn table2_integrity(n: u64, m: u64, c: u64) -> (u64, u64) {
    (n + c + 1, n * n + 2 * n * m + n)
}
pub fn table2_delegation(n: u64, m: u64) -> (u64, u64) {
    (1, n * m)
}

// ---------------------------------------------------------------- q independent audits (SPEC-w16 stage verify_q)

/// `q` independent audits: each item is one (challenge, proof) pair made before the timer; every pair is
/// verified with the full `verify` (H5 -> B is recomputed every time, as in a separate ProofVerify).
/// Returns true iff ALL verifications accept (no early exit, so the cost does not depend on a failure).
pub fn verify_many<M: Meter>(inst: &Instance, audits: &[(Challenge, Proof)], meter: &mut M) -> bool {
    let mut all = true;
    for (ch, pr) in audits {
        all &= verify(inst, ch, pr, meter);
    }
    all
}

/// `q` fresh challenges of size `c` and the honest proofs for them (untimed set-up of a `verify_q` run).
pub fn make_audits(inst: &Instance, c: usize, q_audits: usize, rng: &mut Rng) -> Vec<(Challenge, Proof)> {
    (0..q_audits)
        .map(|_| {
            let ch = challenge(inst.ell, c, rng);
            let pr = proofgen(inst, &ch, rng, &mut NoMeter);
            (ch, pr)
        })
        .collect()
}
