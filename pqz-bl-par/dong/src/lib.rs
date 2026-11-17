//! -par build: functions without suffix at the end of the file are the PARALLEL versions; `*_seq` are the original
//! sequential functions kept verbatim as the reference for the tests. See CHANGES-par.md.
//!
//! Dong et al., "Blockchain-Assisted Integrity Auditing Scheme With Key-Exposure Resistance in
//! Cloud Storage Setting" (IEEE TNSM 2026, vol. 23, pp. 5141-): Setup / Extract / KeyUpdate /
//! AuthGen (untimed set-up code here), Challenge, ProofGen (CSP) and ProofVerify (auditor, eq. (1)).
//! Written from the paper's equations (printed p. 5144-5145). See FIDELITY.md.
//!
//! Group mapping (Type A symmetric pairing -> BLS12-381, asymmetric):
//!   G  -> G1 for everything that is hashed, tagged or exponentiated (H1 outputs, u_j, sk, sigma, T);
//!   g, Y = g^x, R = g^r -> G2 (they only appear as the second pairing argument);
//!   G_T -> Gt. Pairing e(G1, G2) -> Gt. Multiplicative notation of the paper = additive notation of the
//!   crate (G1 `+` = M_G, G1 `* Scalar` = E_G; Gt `+` = M_GT, Gt `* Scalar` = E_GT).

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use digest09::generic_array::GenericArray as GA09;
use digest09::{BlockInput, FixedOutputDirty, Reset, Update};
use ff::Field;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rayon::prelude::*;
use sha2::Digest as _;

/// Sectors per block: the paper's setting (line 1059, "3 sectors").
pub const S: usize = 3;

// ---------------------------------------------------------------- hash to G1 (H1 : {0,1}* -> G)
// Same approach as bench/pqz-baselines/src/lib.rs: the RFC 9380 map of bls12_381 0.8.0 with a thin
// SHA-256 adapter (the crate's expand_message_xmd is written against the digest 0.9 traits).
#[derive(Clone, Default)]
pub struct Sha256Compat(sha2::Sha256);
impl Update for Sha256Compat {
    fn update(&mut self, data: impl AsRef<[u8]>) {
        sha2::Digest::update(&mut self.0, data.as_ref());
    }
}
impl BlockInput for Sha256Compat {
    type BlockSize = digest09::consts::U64;
}
impl FixedOutputDirty for Sha256Compat {
    type OutputSize = digest09::consts::U32;
    fn finalize_into_dirty(&mut self, out: &mut GA09<u8, digest09::consts::U32>) {
        let d = self.0.clone().finalize();
        out.copy_from_slice(&d);
    }
}
impl Reset for Sha256Compat {
    fn reset(&mut self) {
        self.0 = sha2::Sha256::new();
    }
}
/// Domain separation tag of this crate (OURS; the paper gives no hash construction).
pub const H2C_DST: &[u8] = b"PQZ-BL-DONG-V01-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

fn hash_to_g1(msg: &[u8]) -> G1Projective {
    <G1Projective as HashToCurve<ExpandMsgXmd<Sha256Compat>>>::hash_to_curve(msg, H2C_DST)
}

/// H1(fname || t || i): encoding is OURS (tag byte, length-prefixed fname, t, i).
fn enc_block(fname: &[u8], t: u64, i: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(1 + 8 + fname.len() + 16);
    m.push(0x01);
    m.extend_from_slice(&(fname.len() as u64).to_le_bytes());
    m.extend_from_slice(fname);
    m.extend_from_slice(&t.to_le_bytes());
    m.extend_from_slice(&i.to_le_bytes());
    m
}
/// H1(ID, t)
fn enc_id(id: &[u8], t: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(1 + 8 + id.len() + 8);
    m.push(0x02);
    m.extend_from_slice(&(id.len() as u64).to_le_bytes());
    m.extend_from_slice(id);
    m.extend_from_slice(&t.to_le_bytes());
    m
}

// ---------------------------------------------------------------- counted primitives
// Every group / field operation of ProofGen and ProofVerify goes through these wrappers. In normal
// builds they are plain inlined operations (no counting). Under `cfg(test)` they also bump a
// thread-local counter, which the test `op_counts_vs_paper_formula` compares with the paper's formulas.
pub mod prim {
    use super::*;

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Counts {
        pub mz: u64,  // multiplication in Z_q*
        pub az: u64,  // addition in Z_q*
        pub eg: u64,  // exponentiation in G (G1 scalar multiplication)
        pub mg: u64,  // multiplication in G (G1 point addition)
        pub egt: u64, // exponentiation in G_T
        pub mgt: u64, // multiplication in G_T
        pub p: u64,   // pairing (full: Miller loop + final exponentiation)
        pub h: u64,   // H1 (hash to G)
    }
    #[cfg(test)]
    thread_local! { pub static C: std::cell::Cell<Counts> = std::cell::Cell::new(Counts::default()); }
    #[cfg(test)]
    pub fn reset() {
        C.with(|c| c.set(Counts::default()));
    }
    #[cfg(test)]
    pub fn get() -> Counts {
        C.with(|c| c.get())
    }
    #[cfg(test)]
    #[inline(always)]
    fn bump(f: impl FnOnce(&mut Counts)) {
        C.with(|c| {
            let mut x = c.get();
            f(&mut x);
            c.set(x);
        });
    }
    #[cfg(not(test))]
    #[inline(always)]
    fn bump(_f: impl FnOnce(&mut Counts)) {}

    #[inline(always)]
    pub fn z_mul(a: &Scalar, b: &Scalar) -> Scalar {
        bump(|c| c.mz += 1);
        a * b
    }
    #[inline(always)]
    pub fn z_add(a: &Scalar, b: &Scalar) -> Scalar {
        bump(|c| c.az += 1);
        a + b
    }
    #[inline(always)]
    pub fn e_g(a: &G1Projective, k: &Scalar) -> G1Projective {
        bump(|c| c.eg += 1);
        a * k
    }
    #[inline(always)]
    pub fn m_g(a: &G1Projective, b: &G1Projective) -> G1Projective {
        bump(|c| c.mg += 1);
        a + b
    }
    #[inline(always)]
    pub fn e_gt(a: &Gt, k: &Scalar) -> Gt {
        bump(|c| c.egt += 1);
        a * k
    }
    #[inline(always)]
    pub fn m_gt(a: &Gt, b: &Gt) -> Gt {
        bump(|c| c.mgt += 1);
        a + b
    }
    /// One full pairing e(P, Q). The projective -> affine conversions of the G1 argument (one field
    /// inversion) are part of this call and are NOT in the paper's formula.
    #[inline(always)]
    pub fn pair(p: &G1Projective, q: &G2Affine) -> Gt {
        bump(|c| c.p += 1);
        pairing(&G1Affine::from(p), q)
    }
    #[inline(always)]
    pub fn h1(msg: &[u8]) -> G1Projective {
        bump(|c| c.h += 1);
        hash_to_g1(msg)
    }
}
use prim::*;

// ---------------------------------------------------------------- data types
/// Public parameters pp = (q, G, G_T, e, g, {u_1..u_s}, H1, Y).
pub struct Public {
    pub g: G2Affine,
    pub u: Vec<G1Projective>,
    pub y: G2Affine,
}

/// Per-file public data the verifier needs: (ID, fname, t) and R from the file tag tau
/// (the IBS signature on tau is not implemented, see FIDELITY.md).
pub struct FileInfo {
    pub id: Vec<u8>,
    pub fname: Vec<u8>,
    pub t: u64,
    pub r_pub: G2Affine,
}

/// What the CSP stores: file F (n blocks x s sectors, Z_q*) and the authenticators Phi.
pub struct Stored {
    pub s: usize,
    pub data: Vec<Vec<Scalar>>,
    pub tags: Vec<G1Projective>,
}

/// chal = {(k_l, v_l)}, indices 1-based as in the paper ([n]).
#[derive(Clone)]
pub struct Chal {
    pub k: Vec<usize>,
    pub v: Vec<Scalar>,
}

/// proof = (tau, {mu_j}, T); tau (the IBS-signed file tag) is not part of the timed code.
#[derive(Clone)]
pub struct Proof {
    pub mu: Vec<Scalar>,
    pub t: G1Projective,
}

pub struct Setup {
    pub pp: Public,
    pub info: FileInfo,
    pub stored: Stored,
    pub n: usize,
}

// ---------------------------------------------------------------- Setup / Extract / KeyUpdate / AuthGen (untimed)
/// Setup, Extract (initial key) / KeyUpdate (time period t, sk_{ID,t} = H1(ID,t)^x) and AuthGen for a
/// file of `n` random blocks with `s` sectors. Sectors are random scalars (OURS: the paper's sectors
/// are 160-bit elements of Z_q*).
pub fn setup_seq(n: usize, s: usize, rng: &mut ChaCha20Rng) -> Setup {
    let g = G2Affine::generator();
    let x = nonzero(rng); // msk
    let y = G2Affine::from(G2Projective::generator() * x);
    let u: Vec<G1Projective> = (0..s).map(|_| G1Projective::generator() * nonzero(rng)).collect(); // random elements of G
    let id = b"DO-identity".to_vec();
    let fname = b"file-0001".to_vec();
    let t: u64 = 1;
    // sk_{ID,t} = H1(ID,t)^x   (KeyUpdate; check e(g, sk) = e(Y, H1(ID,t)) as the paper does)
    let h_idt = hash_to_g1(&enc_id(&id, t));
    let sk = h_idt * x;
    assert_eq!(pairing(&G1Affine::from(sk), &g), pairing(&G1Affine::from(h_idt), &y));
    // AuthGen
    let r = nonzero(rng);
    let r_pub = G2Affine::from(G2Projective::generator() * r);
    let data: Vec<Vec<Scalar>> = (0..n).map(|_| (0..s).map(|_| nonzero(rng)).collect()).collect();
    let tags: Vec<G1Projective> = (0..n)
        .map(|i| {
            let mut inner = hash_to_g1(&enc_block(&fname, t, (i + 1) as u64)); // H1(fname||t||i)
            for j in 0..s {
                inner += u[j] * data[i][j]; // prod_j u_j^{m_ij}
            }
            sk + inner * r // sigma_i = sk_{ID,t} * (H1(..) * prod u_j^{m_ij})^r
        })
        .collect();
    Setup {
        pp: Public { g, u, y },
        info: FileInfo { id, fname, t, r_pub },
        stored: Stored { s, data, tags },
        n,
    }
}

fn nonzero(rng: &mut ChaCha20Rng) -> Scalar {
    loop {
        let x = Scalar::random(&mut *rng);
        if !bool::from(x.is_zero()) {
            return x;
        }
    }
}

// ---------------------------------------------------------------- Challenge (smart contract; untimed in the harness)
/// Challenge(tt) -> chal. pi = pseudorandom permutation (partial Fisher-Yates driven by a ChaCha20 stream
/// keyed with SHA-256("pi"||tt)), f = PRF (SHA-512("f"||tt||l) reduced mod q). c is an input (the paper
/// draws it at random in [n]; the experiments fix it, lines 1063-1066). Indices are sorted (k_1 < ... < k_c).
pub fn challenge_seq(tt: u64, n: usize, c: usize) -> Chal {
    assert!(c >= 1 && c <= n);
    let mut h = sha2::Sha256::new();
    h.update(b"pi");
    h.update(tt.to_le_bytes());
    let seed: [u8; 32] = h.finalize().into();
    let mut prng = ChaCha20Rng::from_seed(seed);
    let mut perm: Vec<usize> = (1..=n).collect();
    for i in 0..c {
        let span = (n - i) as u64;
        let j = i + (prng.next_u64() % span) as usize;
        perm.swap(i, j);
    }
    let mut k: Vec<usize> = perm[..c].to_vec();
    k.sort_unstable();
    let v: Vec<Scalar> = (0..c)
        .map(|l| {
            let mut h = sha2::Sha512::new();
            h.update(b"f");
            h.update(tt.to_le_bytes());
            h.update((l as u64).to_le_bytes());
            let d: [u8; 64] = h.finalize().into();
            Scalar::from_bytes_wide(&d)
        })
        .collect();
    Chal { k, v }
}

// ---------------------------------------------------------------- ProofGen (CSP)
/// mu_j = sum_l v_l * m_{k_l,j}  (1 <= j <= s),  T = prod_l sigma_{k_l}^{v_l}.
/// The first term of each sum / product is taken as is (no operation), so the counts are
/// s*c M_z + s*(c-1) A_z + c E_G + (c-1) M_G.
pub fn proof_gen_seq(chal: &Chal, st: &Stored) -> Proof {
    let c = chal.k.len();
    let mut mu = Vec::with_capacity(st.s);
    for j in 0..st.s {
        let mut acc = z_mul(&chal.v[0], &st.data[chal.k[0] - 1][j]);
        for l in 1..c {
            let term = z_mul(&chal.v[l], &st.data[chal.k[l] - 1][j]);
            acc = z_add(&acc, &term);
        }
        mu.push(acc);
    }
    let mut t = e_g(&st.tags[chal.k[0] - 1], &chal.v[0]);
    for l in 1..c {
        let term = e_g(&st.tags[chal.k[l] - 1], &chal.v[l]);
        t = m_g(&t, &term);
    }
    Proof { mu, t }
}

// ---------------------------------------------------------------- ProofVerify (auditor / smart contract SC_v)
/// Equation (1):
///   e(T, g) = e(H1(ID,t), Y)^{sum v_l} * e( prod_l H1(fname||t||k_l)^{v_l} * prod_j u_j^{mu_j}, R ).
/// The IBS check of tau is skipped, as in the paper's own cost formula (line 957).
pub fn proof_verify_seq(pp: &Public, info: &FileInfo, chal: &Chal, proof: &Proof) -> bool {
    let c = chal.k.len();
    // H1(ID, t)
    let h_idt = h1(&enc_id(&info.id, info.t));
    // sum_l v_l  (c-1 A_z)
    let mut sum_v = chal.v[0];
    for l in 1..c {
        sum_v = z_add(&sum_v, &chal.v[l]);
    }
    // prod_l H1(fname||t||k_l)^{v_l}  (c H, c E_G, c-1 M_G)
    let mut ph = e_g(&h1(&enc_block(&info.fname, info.t, chal.k[0] as u64)), &chal.v[0]);
    for l in 1..c {
        let hl = h1(&enc_block(&info.fname, info.t, chal.k[l] as u64));
        let term = e_g(&hl, &chal.v[l]);
        ph = m_g(&ph, &term);
    }
    // prod_j u_j^{mu_j}  (s E_G, s-1 M_G)
    let mut pu = e_g(&pp.u[0], &proof.mu[0]);
    for j in 1..pp.u.len() {
        let term = e_g(&pp.u[j], &proof.mu[j]);
        pu = m_g(&pu, &term);
    }
    // combine (1 M_G)
    let x = m_g(&ph, &pu);
    // 3 pairings, E_GT, M_GT
    let lhs = pair(&proof.t, &pp.g);
    let a = pair(&h_idt, &pp.y);
    let b = pair(&x, &info.r_pub);
    let rhs = m_gt(&e_gt(&a, &sum_v), &b);
    lhs == rhs
}

// ---------------------------------------------------------------- q independent audits (SPEC-w16 stage verify_q)
/// Makes q INDEPENDENT audits of the stored file: q different challenges (nonces drawn from `rng`), each with its own
/// honest proof from `proof_gen`. Untimed set-up of the stage `verify_q`.
pub fn make_audits_seq(su: &Setup, c: usize, q: usize, rng: &mut ChaCha20Rng) -> (Vec<Chal>, Vec<Proof>) {
    let chals: Vec<Chal> = (0..q).map(|_| challenge_seq(rng.next_u64(), su.n, c)).collect();
    let proofs: Vec<Proof> = chals.iter().map(|ch| proof_gen_seq(ch, &su.stored)).collect();
    (chals, proofs)
}

/// Stage `verify_q`: verifies q independent (challenge, proof) pairs one after the other, each with the full
/// `proof_verify` (no batching across audits, no early exit). True iff every audit verifies.
pub fn proof_verify_many_seq(pp: &Public, info: &FileInfo, chals: &[Chal], proofs: &[Proof]) -> bool {
    assert_eq!(chals.len(), proofs.len());
    let mut all = true;
    for (ch, pr) in chals.iter().zip(proofs.iter()) {
        all &= proof_verify_seq(pp, info, ch, pr); // `&=`: never short-circuits, so a failure costs the same work
    }
    all
}


// ================================================================================================
// PARALLEL VERSION (-par), see CHANGES-par.md.
// Everything above is the ORIGINAL sequential code (renamed `*_seq`, otherwise verbatim); the unit-test counts
// against the paper's formulas use these. Below: the same algorithm with the independent work on the rayon pool
// (threads: RAYON_NUM_THREADS, default all cores). Same parameters, same outputs: mu_j, setup values and every
// verdict are identical; T is the same group element (a different order of point additions can give a different
// projective representation, so T is compared by its compressed encoding).
// Sequential on purpose: the RNG stream of the (untimed) setup (rejection sampling, draw order), the Fisher-Yates
// swaps of the challenge (each swap uses the next ChaCha word), the single H1(ID,t) before the final pairing check.
// ================================================================================================

/// Setup / AuthGen, parallel in the n tags (hash to G1, s+1 exponentiations each). The RNG draws (x, u_j, r, then
/// the n*s data sectors) stay sequential in the original order, so the stream and the data are identical.
pub fn setup(n: usize, s: usize, rng: &mut ChaCha20Rng) -> Setup {
    let g = G2Affine::generator();
    let x = nonzero(rng);
    let y = G2Affine::from(G2Projective::generator() * x);
    let u: Vec<G1Projective> = (0..s).map(|_| G1Projective::generator() * nonzero(rng)).collect();
    let id = b"DO-identity".to_vec();
    let fname = b"file-0001".to_vec();
    let t: u64 = 1;
    let h_idt = hash_to_g1(&enc_id(&id, t));
    let sk = h_idt * x;
    assert_eq!(pairing(&G1Affine::from(sk), &g), pairing(&G1Affine::from(h_idt), &y));
    let r = nonzero(rng);
    let r_pub = G2Affine::from(G2Projective::generator() * r);
    let data: Vec<Vec<Scalar>> = (0..n).map(|_| (0..s).map(|_| nonzero(rng)).collect()).collect();
    let tags: Vec<G1Projective> = (0..n)
        .into_par_iter()
        .with_min_len(4)
        .map(|i| {
            let mut inner = hash_to_g1(&enc_block(&fname, t, (i + 1) as u64));
            for j in 0..s {
                inner += u[j] * data[i][j];
            }
            sk + inner * r
        })
        .collect();
    Setup {
        pp: Public { g, u, y },
        info: FileInfo { id, fname, t, r_pub },
        stored: Stored { s, data, tags },
        n,
    }
}

/// Challenge: the Fisher-Yates swaps are a chain over one ChaCha20 stream (sequential); the c values v_l (one
/// SHA-512 each) are independent and computed in parallel.
pub fn challenge(tt: u64, n: usize, c: usize) -> Chal {
    assert!(c >= 1 && c <= n);
    let mut h = sha2::Sha256::new();
    h.update(b"pi");
    h.update(tt.to_le_bytes());
    let seed: [u8; 32] = h.finalize().into();
    let mut prng = ChaCha20Rng::from_seed(seed);
    let mut perm: Vec<usize> = (1..=n).collect();
    for i in 0..c {
        let span = (n - i) as u64;
        let j = i + (prng.next_u64() % span) as usize;
        perm.swap(i, j);
    }
    let mut k: Vec<usize> = perm[..c].to_vec();
    k.sort_unstable();
    let v: Vec<Scalar> = (0..c)
        .into_par_iter()
        .with_min_len(256)
        .map(|l| {
            let mut h = sha2::Sha512::new();
            h.update(b"f");
            h.update(tt.to_le_bytes());
            h.update((l as u64).to_le_bytes());
            let d: [u8; 64] = h.finalize().into();
            Scalar::from_bytes_wide(&d)
        })
        .collect();
    Chal { k, v }
}

/// ProofGen, parallel over the challenged blocks l = 1..c: every term v_l * m_{k_l,j} and sigma_{k_l}^{v_l} is
/// independent; partial sums (Z_q and G additions are associative and commutative) are combined by rayon.
/// Scalar sums are exact, so mu is identical; T is the same group element.
pub fn proof_gen(chal: &Chal, st: &Stored) -> Proof {
    let c = chal.k.len();
    let s = st.s;
    let (mu, t) = (0..c)
        .into_par_iter()
        .with_min_len(16)
        .fold(
            || (vec![Scalar::ZERO; s], G1Projective::identity()),
            |(mut mu, mut t), l| {
                let v = &chal.v[l];
                let row = &st.data[chal.k[l] - 1];
                for j in 0..s {
                    mu[j] += v * row[j];
                }
                t += st.tags[chal.k[l] - 1] * v;
                (mu, t)
            },
        )
        .reduce(
            || (vec![Scalar::ZERO; s], G1Projective::identity()),
            |(mut a, ta), (b, tb)| {
                for (x, y) in a.iter_mut().zip(&b) {
                    *x += y;
                }
                (a, ta + tb)
            },
        );
    Proof { mu, t }
}

/// ProofVerify (eq. 1), parallel: the c+1 hashes to G and the c exponentiations of prod_l H1(..)^{v_l} are
/// independent (fold/reduce); the three pairings run concurrently (e(T,g), e(H1(ID,t),Y) and, after the products
/// are formed, e(x,R)); then one E_GT and one M_GT as in the original.
pub fn proof_verify(pp: &Public, info: &FileInfo, chal: &Chal, proof: &Proof) -> bool {
    let c = chal.k.len();
    let h_idt = hash_to_g1(&enc_id(&info.id, info.t));
    let sum_v = chal.v.iter().fold(Scalar::ZERO, |a, b| a + b);
    let ((lhs, a), b) = rayon::join(
        || {
            rayon::join(
                || pairing(&G1Affine::from(proof.t), &pp.g),
                || pairing(&G1Affine::from(h_idt), &pp.y),
            )
        },
        || {
            let ph = (0..c)
                .into_par_iter()
                .with_min_len(2)
                .fold(G1Projective::identity, |acc, l| {
                    let hl = hash_to_g1(&enc_block(&info.fname, info.t, chal.k[l] as u64));
                    acc + hl * chal.v[l]
                })
                .reduce(G1Projective::identity, |x, y| x + y);
            let mut pu = pp.u[0] * proof.mu[0];
            for j in 1..pp.u.len() {
                pu += pp.u[j] * proof.mu[j];
            }
            let x = ph + pu;
            pairing(&G1Affine::from(x), &info.r_pub)
        },
    );
    let rhs = (a * sum_v) + b;
    lhs == rhs
}

/// q audits made concurrently: the q nonces are drawn from `rng` first (same order as the original), then the
/// challenges and honest proofs of the q audits are independent.
pub fn make_audits(su: &Setup, c: usize, q: usize, rng: &mut ChaCha20Rng) -> (Vec<Chal>, Vec<Proof>) {
    let nonces: Vec<u64> = (0..q).map(|_| rng.next_u64()).collect();
    let chals: Vec<Chal> = nonces.par_iter().map(|&tt| challenge(tt, su.n, c)).collect();
    let proofs: Vec<Proof> = chals.par_iter().map(|ch| proof_gen(ch, &su.stored)).collect();
    (chals, proofs)
}

/// Stage `verify_q`: q INDEPENDENT audits verified concurrently, each with the full `proof_verify` (no batching
/// across audits, no early exit). True iff every audit verifies.
pub fn proof_verify_many(pp: &Public, info: &FileInfo, chals: &[Chal], proofs: &[Proof]) -> bool {
    assert_eq!(chals.len(), proofs.len());
    chals
        .par_iter()
        .zip(proofs.par_iter())
        .map(|(ch, pr)| proof_verify(pp, info, ch, pr))
        .fold(|| true, |a, b| a & b)
        .reduce(|| true, |a, b| a & b)
}

// ---------------------------------------------------------------- tests
#[cfg(test)]
mod tests {
    use super::*;
    use prim::Counts;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([7u8; 32])
    }

    #[test]
    fn honest_proof_verifies() {
        let mut r = rng();
        for (c, n) in [(1usize, 5usize), (10, 100), (30, 300)] {
            let su = setup(n, S, &mut r);
            let chal = challenge(12345 + c as u64, n, c);
            assert_eq!(chal.k.len(), c);
            assert!(chal.k.windows(2).all(|w| w[0] < w[1]) && chal.k[c - 1] <= n && chal.k[0] >= 1);
            let proof = proof_gen(&chal, &su.stored);
            assert!(proof_verify(&su.pp, &su.info, &chal, &proof), "c={c}");
        }
    }

    #[test]
    fn tampered_proof_rejected() {
        let mut r = rng();
        let (n, c) = (100usize, 10usize);
        let su = setup(n, S, &mut r);
        let chal = challenge(99, n, c);
        let proof = proof_gen(&chal, &su.stored);
        assert!(proof_verify(&su.pp, &su.info, &chal, &proof));
        // one sector aggregate changed
        for j in 0..S {
            let mut bad = proof.clone();
            bad.mu[j] += Scalar::one();
            assert!(!proof_verify(&su.pp, &su.info, &chal, &bad), "mu[{j}]");
        }
        // aggregated signature changed
        let mut bad = proof.clone();
        bad.t += G1Projective::generator();
        assert!(!proof_verify(&su.pp, &su.info, &chal, &bad), "T");
        // one challenge coefficient changed on the verifier side
        let mut badc = chal.clone();
        badc.v[3] += Scalar::one();
        assert!(!proof_verify(&su.pp, &su.info, &badc, &proof), "chal");
    }

    #[test]
    fn corrupted_stored_sector_rejected() {
        let mut r = rng();
        let (n, c) = (50usize, 50usize); // every block challenged, so the corrupted one is hit
        let mut su = setup(n, S, &mut r);
        su.stored.data[17][1] += Scalar::one();
        let chal = challenge(5, n, c);
        let proof = proof_gen(&chal, &su.stored);
        assert!(!proof_verify(&su.pp, &su.info, &chal, &proof));
    }

    #[test]
    fn challenge_is_deterministic_and_fresh() {
        let a = challenge(1, 100, 10);
        let b = challenge(1, 100, 10);
        let d = challenge(2, 100, 10);
        assert_eq!(a.k, b.k);
        assert!(a.v == b.v);
        assert!(a.k != d.k || a.v != d.v);
    }

    #[test]
    fn verify_q_honest_passes_tampered_fails() {
        let mut r = rng();
        let (n, c, q) = (60usize, 6usize, 4usize);
        let su = setup(n, S, &mut r);
        let (chals, proofs) = make_audits(&su, c, q, &mut r);
        assert_eq!(chals.len(), q);
        // the q challenges are really different
        for a in 0..q {
            for b in a + 1..q {
                assert!(chals[a].k != chals[b].k || chals[a].v != chals[b].v, "audits {a},{b} share a challenge");
            }
        }
        assert!(proof_verify_many(&su.pp, &su.info, &chals, &proofs), "honest q audits");
        // flip one value in each position of the batch, one at a time: the batch must be rejected
        for i in 0..q {
            let mut bad = proofs.clone();
            bad[i].mu[1] += Scalar::one();
            assert!(!proof_verify_many(&su.pp, &su.info, &chals, &bad), "mu of audit {i}");
            let mut bad = proofs.clone();
            bad[i].t += G1Projective::generator();
            assert!(!proof_verify_many(&su.pp, &su.info, &chals, &bad), "T of audit {i}");
        }
        // proofs matched with the wrong challenges are rejected
        let mut swapped = proofs.clone();
        swapped.swap(0, 1);
        assert!(!proof_verify_many(&su.pp, &su.info, &chals, &swapped), "swapped proofs");
        // q = 1 is the ordinary verify
        assert!(proof_verify_many(&su.pp, &su.info, &chals[..1], &proofs[..1]));
    }

    /// verify_q does q times the work of one verify (counts, c = 5, q = 3).
    #[test]
    fn verify_q_counts_are_q_times_one_verify() {
        let (c, q) = (5usize, 3usize);
        let mut r = rng();
        let su = setup(50, S, &mut r);
        let (chals, proofs) = make_audits(&su, c, q, &mut r);
        prim::reset();
        assert!(proof_verify_seq(&su.pp, &su.info, &chals[0], &proofs[0]));
        let one = prim::get();
        prim::reset();
        assert!(proof_verify_many_seq(&su.pp, &su.info, &chals, &proofs));
        let many = prim::get();
        let qq = q as u64;
        let want = Counts {
            mz: one.mz * qq, az: one.az * qq, eg: one.eg * qq, mg: one.mg * qq,
            egt: one.egt * qq, mgt: one.mgt * qq, p: one.p * qq, h: one.h * qq,
        };
        assert_eq!(many, want);
    }

    /// Counts the group / field operations executed by proof_gen and proof_verify for c = 10, s = 3 and
    /// compares them term by term with the paper's formulas (Sec. VI.B (3), Table V):
    ///   ProofGen = s*c*Mz + s*(c-1)*Az + c*EG + (c-1)*MG
    ///   Verify   = 3P + (c+1)H + (c-1)Az + (c+s)EG + (c+s-1)MG + EGT + MGT
    #[test]
    fn op_counts_vs_paper_formula() {
        let (c, s) = (10u64, S as u64);
        let mut r = rng();
        let su = setup(100, S, &mut r);
        let chal = challenge(777, 100, c as usize);

        prim::reset();
        let proof = proof_gen_seq(&chal, &su.stored);
        let got_pg = prim::get();
        let want_pg = Counts { mz: s * c, az: s * (c - 1), eg: c, mg: c - 1, ..Counts::default() };
        assert_eq!(got_pg, want_pg, "ProofGen counts differ from the paper's formula");

        prim::reset();
        let ok = proof_verify_seq(&su.pp, &su.info, &chal, &proof);
        let got_v = prim::get();
        assert!(ok);
        let want_v = Counts {
            p: 3,
            h: c + 1,
            az: c - 1,
            eg: c + s,
            mg: c + s - 1,
            egt: 1,
            mgt: 1,
            ..Counts::default()
        };
        assert_eq!(got_v, want_v, "Verify counts differ from the paper's formula");
        eprintln!("ProofGen counts (c=10,s=3): {:?}", got_pg);
        eprintln!("Verify   counts (c=10,s=3): {:?}", got_v);
    }

    fn tb(p: &Proof) -> ([[u8; 32]; S], [u8; 48]) {
        let mut m = [[0u8; 32]; S];
        for j in 0..S {
            m[j] = p.mu[j].to_bytes();
        }
        (m, G1Affine::from(p.t).to_compressed())
    }

    fn pool<T: Send>(k: usize, f: impl FnOnce() -> T + Send) -> T {
        rayon::ThreadPoolBuilder::new().num_threads(k).build().unwrap().install(f)
    }

    /// -par: parallel setup / challenge / proof_gen / proof_verify / verify_many are byte-identical to the
    /// original sequential functions for fixed seeds, at 1, 2 and 7 threads.
    #[test]
    fn par_identical_to_seq() {
        for (n, c) in [(5usize, 1usize), (60, 6), (300, 30), (1200, 100)] {
            let mut r = rng();
            let su = setup_seq(n, S, &mut r);
            let after = r.next_u64();
            for k in [1usize, 2, 7] {
                let mut r2 = rng();
                let sp = pool(k, || setup(n, S, &mut r2));
                assert_eq!(r2.next_u64(), after, "rng position");
                assert_eq!(su.stored.data, sp.stored.data);
                assert!(su.stored.tags.iter().zip(&sp.stored.tags).all(|(a, b)| G1Affine::from(a).to_compressed() == G1Affine::from(b).to_compressed()));
                assert_eq!(su.pp.u.iter().map(|u| G1Affine::from(u).to_compressed()).collect::<Vec<_>>(),
                           sp.pp.u.iter().map(|u| G1Affine::from(u).to_compressed()).collect::<Vec<_>>());
                assert_eq!(su.pp.y.to_compressed(), sp.pp.y.to_compressed());
                assert_eq!(su.info.r_pub.to_compressed(), sp.info.r_pub.to_compressed());
                for tt in [1u64, 99, 123456789] {
                    let cs = challenge_seq(tt, n, c);
                    let cp = pool(k, || challenge(tt, n, c));
                    assert_eq!(cs.k, cp.k);
                    assert!(cs.v == cp.v);
                    let ps = proof_gen_seq(&cs, &su.stored);
                    let pp = pool(k, || proof_gen(&cs, &sp.stored));
                    assert_eq!(tb(&ps), tb(&pp), "proof n={n} c={c} k={k}");
                    assert!(proof_verify_seq(&su.pp, &su.info, &cs, &ps));
                    assert!(pool(k, || proof_verify(&sp.pp, &sp.info, &cs, &pp)));
                    // tampered: both reject
                    let mut bad = pp.clone();
                    bad.mu[1] += Scalar::one();
                    assert!(!proof_verify_seq(&su.pp, &su.info, &cs, &bad));
                    assert!(!pool(k, || proof_verify(&sp.pp, &sp.info, &cs, &bad)));
                    let mut bad = pp.clone();
                    bad.t += G1Projective::generator();
                    assert!(!pool(k, || proof_verify(&sp.pp, &sp.info, &cs, &bad)));
                }
            }
        }
    }

    #[test]
    fn par_audits_identical_to_seq() {
        let (n, c, q) = (80usize, 8usize, 5usize);
        let mut r = rng();
        let su = setup_seq(n, S, &mut r);
        let mut rs = r.clone();
        let (cs, ps) = make_audits_seq(&su, c, q, &mut rs);
        for k in [1usize, 2, 7] {
            let mut rp = r.clone();
            let (cp, pp) = pool(k, || make_audits(&su, c, q, &mut rp));
            assert_eq!(rs.clone().next_u64(), rp.next_u64());
            for i in 0..q {
                assert_eq!(cs[i].k, cp[i].k);
                assert!(cs[i].v == cp[i].v);
                assert_eq!(tb(&ps[i]), tb(&pp[i]));
            }
            assert!(proof_verify_many_seq(&su.pp, &su.info, &cs, &ps));
            assert!(pool(k, || proof_verify_many(&su.pp, &su.info, &cp, &pp)));
            let mut bad = pp.clone();
            bad[3].mu[0] += Scalar::one();
            assert!(!proof_verify_many_seq(&su.pp, &su.info, &cp, &bad));
            assert!(!pool(k, || proof_verify_many(&su.pp, &su.info, &cp, &bad)));
        }
    }
}
