//! DART (Yu et al., IEEE TIFS 2025) auditing path, implemented from the paper's Eq. 4-9 and
//! Algorithms 1-2, WITHOUT the zk-SNARK (ZKP.Prove / ZKP.Verify / DIZK.*). See FIDELITY.md.
//!
//! Symmetric Type A pairing of the paper -> BLS12-381 (asymmetric):
//!   G1: u, v, rho_i, phi_i (for eta), tau_i, S_auth, eta_tau, Omega_f
//!   G2: h, phi_i (for H_Lambda)
//!   Eq. 8: e(S_auth, h) = e(eta_tau, H_Lambda)   with S_auth, eta_tau in G1 and h, H_Lambda in G2.

pub mod zk; // work39: Groth16 proof of the ZKP.Prove relation (new stages only)

use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use rand_core::RngCore;
use sha2::{Digest, Sha256, Sha512};

/// Counts of the operations that actually ran (incremented next to the real operation).
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Ops {
    pub g1_exp: u64,
    pub g1_add: u64,
    pub g2_exp: u64,
    pub g2_add: u64,
    pub pairing: u64,
    pub fr_mul: u64,
    pub fr_add: u64,
    pub sha256: u64,
    pub sha512: u64,
    pub prp_eval: u64,
}

impl Ops {
    pub fn rows(&self) -> Vec<(&'static str, u64)> {
        vec![
            ("g1_exp", self.g1_exp),
            ("g1_add", self.g1_add),
            ("g2_exp", self.g2_exp),
            ("g2_add", self.g2_add),
            ("pairing", self.pairing),
            ("fr_mul", self.fr_mul),
            ("fr_add", self.fr_add),
            ("sha256", self.sha256),
            ("sha512", self.sha512),
            ("prp_eval", self.prp_eval),
        ]
    }
}

/// Paper parameters M, N and our own number of chunks |D| (not in the paper).
#[derive(Clone, Copy, Debug)]
pub struct Params {
    /// M: encoded blocks per commitment gamma_{i,s} (paper: M = 10)
    pub m: usize,
    /// N: number of commitments per chunk = number of coefficients of f(x) (paper: N = 20, 40)
    pub n: usize,
    /// |D|: number of chunks of the stored file (NOT in the paper: ours)
    pub d: usize,
}

pub const BLOCK_BYTES: usize = 32;

/// Public values known to the storage node and the SC (no secrets).
pub struct Public {
    pub p: Params,
    /// rho_j = u^{chi^j}, j in [0, N-1]  (G1)
    pub rho: Vec<G1Affine>,
    /// phi_i = v^{zeta^i}, i in [0, |D|]  (G1; used by the storage node for eta_tau, Eq. 6)
    pub phi1: Vec<G1Affine>,
    /// phi_i = h^{zeta^i}, i in [0, z_max]  (G2; used by the SC for H_Lambda, Eq. 8)
    pub phi2: Vec<G2Affine>,
    /// S_auth = v^{prod_{i in D}(c_tau_i + zeta)}  (G1; stored in the SC)
    pub s_auth: G1Affine,
    /// h  (G2)
    pub h: G2Affine,
}

/// What the storage node holds: encoded data blocks, authenticators, and its table of c_tau.
#[derive(Clone)]
pub struct Node {
    /// |D| chunks, each N*M encoded blocks of 32 bytes, flat.
    pub blocks: Vec<u8>,
    /// tau_i = u^{f_i(chi)}  (G1)
    pub tau: Vec<G1Affine>,
    /// c_tau_i = C_G(tau_i), stored table (used for i in D \ Lambda)
    pub c_tau: Vec<Scalar>,
}

pub struct Prf {
    /// tau = {tau_i}_{i in Lambda}, in the order l = 1..z
    pub tau: Vec<G1Affine>,
    /// eta_tau (G1)
    pub eta: G1Affine,
    /// gamma_a = {gamma_{a,j}}_{j in [0,N-1]}  (the coefficients of f(x), Eq. 4)
    pub gamma_a: Vec<Scalar>,
    // pi (the zk-SNARK proof) is NOT produced: the ZKP is not run.
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// Eq. 8 (accumulator check, 2 pairings)
    pub eq8: bool,
    /// Eq. 9 / Algorithm 2 lines 14-15 (Omega_f check)
    pub eq9: bool,
    /// eq8 && eq9. The ZKP.Verify / DIZK.Verify of Algorithm 2 lines 6-9 is NOT run, so a true here is
    /// not "DART accepts".
    pub ok: bool,
}

// ---------------------------------------------------------------- primitives (ours; the paper names them only)

fn scalar_from_sha512(parts: &[&[u8]], ops: &mut Ops) -> Scalar {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    ops.sha512 += 1;
    let mut w = [0u8; 64];
    w.copy_from_slice(&out);
    Scalar::from_bytes_wide(&w)
}

/// COM.Commit over M encoded blocks (paper: a commitment, scheme not specified): SHA-512 hash commitment mapped to Z_p.
pub fn com_commit(blocks: &[u8], ops: &mut Ops) -> Scalar {
    scalar_from_sha512(&[b"DART-COM", blocks], ops)
}

/// C_G : G1 -> Z_p^*, "a commitment that commits an element in G1 to a value in Z_p^*" (scheme not specified): hash of the point.
pub fn c_g(t: &G1Affine, ops: &mut Ops) -> Scalar {
    let s = scalar_from_sha512(&[b"DART-CG", &t.to_compressed()], ops);
    // Z_p^*: zero has probability 2^-255; keep the type honest
    if bool::from(s.is_zero()) {
        Scalar::ONE
    } else {
        s
    }
}

/// PRG_{k2}(l) -> alpha_i in Z_p
pub fn prg(k2: &[u8; 32], l: u64, ops: &mut Ops) -> Scalar {
    scalar_from_sha512(&[b"DART-PRG", k2, &l.to_le_bytes()], ops)
}

/// PRP_{k1} on [0, n): 4-round Feistel over the smallest even-bit domain >= n, with cycle walking
/// (SHA-256 round function). A keyed permutation, so distinct l give distinct chunk indices.
pub struct Prp {
    key: [u8; 32],
    n: u64,
    half: u32,
}

impl Prp {
    pub fn new(key: &[u8; 32], n: u64) -> Self {
        assert!(n >= 2);
        let mut bits = 64 - (n - 1).leading_zeros();
        if bits % 2 == 1 {
            bits += 1;
        }
        Prp { key: *key, n, half: bits / 2 }
    }
    fn round_f(&self, round: u8, r: u64, ops: &mut Ops) -> u64 {
        let mut h = Sha256::new();
        h.update(b"DART-PRP");
        h.update(self.key);
        h.update([round]);
        h.update(r.to_le_bytes());
        let out = h.finalize();
        ops.sha256 += 1;
        u64::from_le_bytes(out[..8].try_into().unwrap())
    }
    fn feistel(&self, v: u64, ops: &mut Ops) -> u64 {
        let mask = (1u64 << self.half) - 1;
        let mut l = v >> self.half;
        let mut r = v & mask;
        for round in 0..4u8 {
            let f = self.round_f(round, r, ops) & mask;
            let nl = r;
            r = l ^ f;
            l = nl;
        }
        (l << self.half) | r
    }
    pub fn eval(&self, x: u64, ops: &mut Ops) -> u64 {
        assert!(x < self.n);
        ops.prp_eval += 1;
        let mut v = x;
        loop {
            v = self.feistel(v, ops);
            if v < self.n {
                return v;
            }
        }
    }
}

/// DART.Chal output expanded (Algorithm 1 lines 1-5 / Algorithm 2 lines 1-5):
/// Lambda = {(i, alpha_i)}, i = PRP_{k1}(l), alpha_i = PRG_{k2}(l), l = 1..z.
pub fn challenge_set(k1: &[u8; 32], k2: &[u8; 32], z: usize, d: usize, ops: &mut Ops) -> Vec<(usize, Scalar)> {
    assert!(z >= 1 && z <= d);
    let prp = Prp::new(k1, d as u64);
    let mut lam = Vec::with_capacity(z);
    for l in 1..=z as u64 {
        // PRP is defined on [0,d); we feed l-1 (l in [1,z] -> [0,z-1], z <= d)
        let i = prp.eval(l - 1, ops) as usize;
        let alpha = prg(k2, l, ops);
        lam.push((i, alpha));
    }
    lam
}

/// Coefficients beta_0..beta_n of prod_k (c_k + x) (n = number of factors), schoolbook O(n^2).
pub fn expand_product(cs: &[Scalar], ops: &mut Ops) -> Vec<Scalar> {
    let mut b = Vec::with_capacity(cs.len() + 1);
    b.push(Scalar::ONE);
    for c in cs {
        b.push(Scalar::ZERO);
        for k in (1..b.len()).rev() {
            b[k] = b[k] * c + b[k - 1];
        }
        b[0] *= c;
        ops.fr_mul += b.len() as u64;
        ops.fr_add += b.len() as u64 - 1;
    }
    b
}

fn msm_g1(bases: &[G1Affine], scalars: &[Scalar], ops: &mut Ops) -> G1Projective {
    assert_eq!(bases.len(), scalars.len());
    let mut acc = G1Projective::identity();
    for (b, s) in bases.iter().zip(scalars) {
        acc += b * s;
        ops.g1_exp += 1;
        ops.g1_add += 1;
    }
    acc
}

fn msm_g2(bases: &[G2Affine], scalars: &[Scalar], ops: &mut Ops) -> G2Projective {
    assert_eq!(bases.len(), scalars.len());
    let mut acc = G2Projective::identity();
    for (b, s) in bases.iter().zip(scalars) {
        acc += b * s;
        ops.g2_exp += 1;
        ops.g2_add += 1;
    }
    acc
}

// ---------------------------------------------------------------- Init + Store (outside every timed stage)

/// DART.Init + DART.Store. `z_max` bounds the number of public G2 values phi_i the SC needs (z + 1).
pub fn setup<R: RngCore>(p: Params, z_max: usize, rng: &mut R) -> (Public, Node) {
    let (a, b, _) = setup_with_trapdoor(p, z_max, rng);
    (a, b)
}

/// Secrets of DART.Init kept by the test/bench harness ONLY to build proofs quickly for the UNTIMED inputs of
/// `verify_nozk` / `verify_q` (see `prove_fast`). The timed `prove_nozk` never touches them.
#[derive(Clone, Copy)]
pub struct Trapdoor {
    pub zeta: Scalar,
    pub s_v: Scalar,
    /// prod_{i in D}(c_tau_i + zeta)  (the exponent of S_auth w.r.t. v)
    pub p_all: Scalar,
}

/// Same as `setup`, also returning the trapdoor.
pub fn setup_with_trapdoor<R: RngCore>(p: Params, z_max: usize, rng: &mut R) -> (Public, Node, Trapdoor) {
    let mut ops = Ops::default();
    let chi = Scalar::random(&mut *rng);
    let zeta = Scalar::random(&mut *rng);
    let s_v = Scalar::random(&mut *rng);
    let u = G1Projective::generator();
    let v = u * s_v;
    let h = G2Projective::generator();

    // rho_j = u^{chi^j}
    let mut chi_pow = Vec::with_capacity(p.n);
    let mut x = Scalar::ONE;
    for _ in 0..p.n {
        chi_pow.push(x);
        x *= chi;
    }
    let rho: Vec<G1Affine> = chi_pow.iter().map(|e| G1Affine::from(u * e)).collect();

    // phi_i = v^{zeta^i} (G1, i <= |D|) and h^{zeta^i} (G2, i <= z_max)
    let mut phi1 = Vec::with_capacity(p.d + 1);
    let mut phi2 = Vec::with_capacity(z_max + 1);
    let mut zp = Scalar::ONE;
    for i in 0..=p.d.max(z_max) {
        if i <= p.d {
            phi1.push(G1Affine::from(v * zp));
        }
        if i <= z_max {
            phi2.push(G2Affine::from(h * zp));
        }
        zp *= zeta;
    }

    // data: |D| chunks, each N*M encoded blocks (random; erasure coding is not modelled)
    let chunk_bytes = p.n * p.m * BLOCK_BYTES;
    let mut blocks = vec![0u8; p.d * chunk_bytes];
    rng.fill_bytes(&mut blocks);

    // Store: gamma_{i,s} = COM.Commit(M blocks); f_i(chi) = sum_s gamma_{i,s} chi^s; tau_i = u^{f_i(chi)}
    let mut tau = Vec::with_capacity(p.d);
    let mut c_tau = Vec::with_capacity(p.d);
    for i in 0..p.d {
        let gam = chunk_commitments(&blocks, &p, i, &mut ops);
        let mut fchi = Scalar::ZERO;
        for (g, cp) in gam.iter().zip(&chi_pow) {
            fchi += g * cp;
        }
        let t = G1Affine::from(u * fchi);
        c_tau.push(c_g(&t, &mut ops));
        tau.push(t);
    }

    // S_auth = BA.ACC({C_G(tau_i)}_{i in D}) = v^{prod (c_i + zeta)}
    let mut prod = Scalar::ONE;
    for c in &c_tau {
        prod *= c + zeta;
    }
    let s_auth = G1Affine::from(v * prod);

    (
        Public { p, rho, phi1, phi2, s_auth, h: G2Affine::from(h) },
        Node { blocks, tau, c_tau },
        Trapdoor { zeta, s_v, p_all: prod },
    )
}

/// gamma_{i,s} for s in [0, N-1]: commitment of the s-th group of M encoded blocks of chunk i.
pub fn chunk_commitments(blocks: &[u8], p: &Params, i: usize, ops: &mut Ops) -> Vec<Scalar> {
    let chunk_bytes = p.n * p.m * BLOCK_BYTES;
    let group_bytes = p.m * BLOCK_BYTES;
    let chunk = &blocks[i * chunk_bytes..(i + 1) * chunk_bytes];
    (0..p.n).map(|s| com_commit(&chunk[s * group_bytes..(s + 1) * group_bytes], ops)).collect()
}

// ---------------------------------------------------------------- stage proofgen_nozk (DART.Prv without ZKP.Prove)

/// Algorithm 1 without line 6 (the zk proof pi):
/// line 1-5 Lambda; Eq. 4 f(x) (gamma_a, N coefficients, from commitments recomputed from the stored blocks);
/// line 8 c_tau for i in Lambda; line 9 beta_k (expansion of prod_{i in D\Lambda}(c_i + zeta));
/// line 10 eta_tau = prod_k phi_k^{beta_k}.
pub fn prove_nozk(pubp: &Public, node: &Node, k1: &[u8; 32], k2: &[u8; 32], z: usize, ops: &mut Ops) -> Prf {
    let p = pubp.p;
    let lam = challenge_set(k1, k2, z, p.d, ops);

    // Eq. 4: f(x) = sum_j (sum_{i in Lambda} alpha_i gamma_{i,j}) x^j
    let mut gamma_a = vec![Scalar::ZERO; p.n];
    for (i, alpha) in &lam {
        let gam = chunk_commitments(&node.blocks, &p, *i, ops);
        for (ga, g) in gamma_a.iter_mut().zip(&gam) {
            *ga += alpha * g;
        }
        ops.fr_mul += p.n as u64;
        ops.fr_add += p.n as u64;
    }

    // line 8: c_tau_i = C_G(tau_i), i in Lambda (the node's stored table supplies i in D \ Lambda)
    let mut in_lam = vec![false; p.d];
    let mut tau = Vec::with_capacity(z);
    let mut c_lam = vec![Scalar::ZERO; p.d];
    for (i, _) in &lam {
        in_lam[*i] = true;
        tau.push(node.tau[*i]);
        c_lam[*i] = c_g(&node.tau[*i], ops);
    }
    std::hint::black_box(&c_lam);
    let cs: Vec<Scalar> = (0..p.d).filter(|i| !in_lam[*i]).map(|i| node.c_tau[i]).collect();

    // line 9: beta_k;  line 10 / Eq. 6: eta_tau = prod_{k=0}^{|D|-|Lambda|} phi_k^{beta_k}
    let beta = expand_product(&cs, ops);
    let eta = G1Affine::from(msm_g1(&pubp.phi1[..beta.len()], &beta, ops));

    Prf { tau, eta, gamma_a }
}

// ---------------------------------------------------------------- stage verify_nozk (DART.Aud without ZKP.Verify)

/// Algorithm 2 without lines 6-9 (ZKP.Verify / DIZK.Verify): Lambda; c_tau for i in Lambda; delta expansion;
/// H_Lambda = prod_{i=0}^{z} phi_i^{delta_i} (G2); Eq. 8 (2 pairings, compared in GT);
/// Omega_f = prod_j rho_j^{gamma_{a,j}} (line 14); Eq. 9 prod_{i in Lambda} tau_i^{alpha_i} (line 15).
pub fn verify_nozk(pubp: &Public, prf: &Prf, k1: &[u8; 32], k2: &[u8; 32], z: usize, ops: &mut Ops) -> Verdict {
    let p = pubp.p;
    let lam = challenge_set(k1, k2, z, p.d, ops);
    if prf.tau.len() != z || prf.gamma_a.len() != p.n || pubp.phi2.len() < z + 1 {
        return Verdict { eq8: false, eq9: false, ok: false };
    }

    // line 10: c_tau_i = C_G(tau_i) from the proof's tau
    let cs: Vec<Scalar> = prf.tau.iter().map(|t| c_g(t, ops)).collect();
    // line 11: delta_0..delta_z
    let delta = expand_product(&cs, ops);
    // line 12: H_Lambda (G2)
    let hl = G2Affine::from(msm_g2(&pubp.phi2[..delta.len()], &delta, ops));
    // line 13 / Eq. 8: e(S_auth, h) =? e(eta_tau, H_Lambda)
    let lhs = pairing(&pubp.s_auth, &pubp.h);
    let rhs = pairing(&prf.eta, &hl);
    ops.pairing += 2;
    let eq8 = lhs == rhs;

    // line 14: Omega_f = prod_{j<N} rho_j^{gamma_{a,j}}
    let omega = msm_g1(&pubp.rho, &prf.gamma_a, ops);
    // line 15 / Eq. 9: prod_{i in Lambda} tau_i^{alpha_i}
    let alphas: Vec<Scalar> = lam.iter().map(|(_, a)| *a).collect();
    let rhs9 = msm_g1(&prf.tau, &alphas, ops);
    let eq9 = G1Affine::from(omega) == G1Affine::from(rhs9);

    Verdict { eq8, eq9, ok: eq8 && eq9 }
}

// ---------------------------------------------------------------- untimed proof builder for verifier inputs

/// Builds EXACTLY the same `Prf` as `prove_nozk` (a test checks equality) but gets eta_tau from the setup trapdoor:
/// eta_tau = v^{prod_{i in D\Lambda}(c_i+zeta)} = v^{p_all / prod_{i in Lambda}(c_i+zeta)}, one G1 exponentiation instead of |D|-z+1.
/// Used ONLY to prepare the (untimed) input of `verify_nozk` / `verify_q` when |D| is large; it is never inside a timed stage.
pub fn prove_fast(pubp: &Public, node: &Node, trap: &Trapdoor, k1: &[u8; 32], k2: &[u8; 32], z: usize) -> Prf {
    let p = pubp.p;
    let mut ops = Ops::default();
    let lam = challenge_set(k1, k2, z, p.d, &mut ops);
    let mut gamma_a = vec![Scalar::ZERO; p.n];
    let mut prod_lam = Scalar::ONE;
    let mut tau = Vec::with_capacity(z);
    for (i, alpha) in &lam {
        let gam = chunk_commitments(&node.blocks, &p, *i, &mut ops);
        for (ga, g) in gamma_a.iter_mut().zip(&gam) {
            *ga += alpha * g;
        }
        prod_lam *= node.c_tau[*i] + trap.zeta;
        tau.push(node.tau[*i]);
    }
    let inv = Option::<Scalar>::from(prod_lam.invert()).expect("c_tau + zeta = 0 (probability 2^-255)");
    let e = trap.s_v * trap.p_all * inv;
    let eta = G1Affine::from(G1Projective::generator() * e);
    Prf { tau, eta, gamma_a }
}

/// Chunks of the stored file for `file_records` records: one chunk = N*M = 200 blocks (N=20, M=10), D = ceil(records / (N*M)).
pub fn chunks_for_records(file_records: u64, n: usize, m: usize) -> usize {
    let c = (n * m) as u64;
    file_records.div_ceil(c) as usize
}

/// z = max(1, ceil(cov / (N*M))): challenged chunks that cover `cov` records.
pub fn z_for_cov(cov: u64, n: usize, m: usize) -> usize {
    let c = (n * m) as u64;
    (cov.div_ceil(c)).max(1) as usize
}

/// q INDEPENDENT audits verified in one go (stage `verify_q`): proofs[k] was made for challenge keys[k].
/// Returns true iff all q verdicts are ok.
pub fn verify_q(pubp: &Public, proofs: &[Prf], keys: &[([u8; 32], [u8; 32])], z: usize, ops: &mut Ops) -> bool {
    assert_eq!(proofs.len(), keys.len());
    let mut all = true;
    for (prf, (k1, k2)) in proofs.iter().zip(keys) {
        let v = verify_nozk(pubp, prf, k1, k2, z, ops);
        all &= std::hint::black_box(v).ok;
    }
    all
}
