//! w30 (F1): Groth16 BATCH verification for k proofs of the SAME circuit (same prepared vk), beside the one-by-one
//! `Groth16::verify_with_processed_vk` path. See CHANGES-w30.md for the equation, the timer boundary and the RNG.
//!
//! Equation (pvk = (alpha_g1_beta_g2 = e(alpha, beta), -gamma_g2, -delta_g2, gamma_abc_g1), proofs (A_i, B_i, C_i), inputs x_i):
//!   IC_i = gamma_abc_g1[0] + sum_j x_ij * gamma_abc_g1[j+1]                       (as in `prepare_inputs`)
//!   one-by-one:  e(A_i, B_i) * e(IC_i, -gamma) * e(C_i, -delta) == e(alpha, beta)
//!   batch, r_i uniform nonzero 128-bit:
//!     FE( prod_i ML(r_i A_i, B_i) * ML(sum_i r_i IC_i, -gamma) * ML(sum_i r_i C_i, -delta) ) == e(alpha, beta)^(sum_i r_i)
//!   with sum_i r_i IC_i = (sum_i r_i) * gamma_abc_g1[0] + sum_j (sum_i r_i x_ij) * gamma_abc_g1[j+1]  (n+1 scalar mults, not k*n).
//! k + 2 Miller loops in ONE multi-Miller loop, ONE final exponentiation, one Fp12 exponentiation by the 128+log2(k)-bit integer sum r_i.
use crate::circuits::VerifySetup;
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInt, Field, PrimeField, Zero};
use ark_groth16::{PreparedVerifyingKey, Proof};
use ark_relations::r1cs::SynthesisError;
use rand::{rngs::OsRng, RngCore};
use std::ops::{AddAssign, Mul};

/// Below this many points `sum r_i C_i` uses plain double-and-add (128-bit scalars); from here arkworks' Pippenger `msm`.
/// 32 is arkworks' own switch to its larger window size; NOT tuned on timings.
pub const MSM_MIN: usize = 32;

/// k nonzero uniform 128-bit scalars from the OS CSPRNG (`OsRng`, getrandom(2)): one call for 16k bytes, redraw for any zero (prob 2^-128 each).
pub fn draw_scalars(k: usize) -> Vec<u128> {
    let mut bytes = vec![0u8; 16 * k];
    OsRng.fill_bytes(&mut bytes);
    let mut v: Vec<u128> = bytes.chunks_exact(16).map(|c| u128::from_le_bytes(c.try_into().unwrap())).collect();
    for r in v.iter_mut() {
        while *r == 0 {
            let mut b = [0u8; 16];
            OsRng.fill_bytes(&mut b);
            *r = u128::from_le_bytes(b);
        }
    }
    v
}

fn big128(r: u128) -> BigInt<4> {
    BigInt::new([r as u64, (r >> 64) as u64, 0, 0])
}

/// Exact integer sum of the r_i as 3 little-endian u64 limbs (k < 2^64 so 192 bits cannot overflow). NOT reduced mod the group order.
pub fn sum_u128(rs: &[u128]) -> [u64; 3] {
    let mut acc = [0u64; 3];
    for &r in rs {
        let (l0, c0) = acc[0].overflowing_add(r as u64);
        let (l1a, c1a) = acc[1].overflowing_add((r >> 64) as u64);
        let (l1, c1b) = l1a.overflowing_add(c0 as u64);
        acc = [l0, l1, acc[2] + (c1a as u64) + (c1b as u64)];
    }
    acc
}

/// sum_i r_i * C_i (r_i 128-bit).
fn combine_c(cs: &[G1Affine], rs: &[u128]) -> G1Projective {
    if cs.len() >= MSM_MIN {
        let sc: Vec<Fr> = rs.iter().map(|&r| Fr::from(r)).collect();
        G1Projective::msm(cs, &sc).expect("same lengths")
    } else {
        let mut acc = G1Projective::zero();
        for (c, &r) in cs.iter().zip(rs) {
            acc += c.mul_bigint(big128(r));
        }
        acc
    }
}

/// Batch verification with caller-supplied scalars (`rs[i]` nonzero 128-bit); the pure part, used by the tests with fixed scalars.
/// Same `MalformedVerifyingKey` check on the number of public inputs as `prepare_inputs`. Empty batch: Ok(true).
pub fn batch_verify_with_scalars(pvk: &PreparedVerifyingKey<Bn254>, items: &[(&Proof<Bn254>, &[Fr])], rs: &[u128]) -> Result<bool, SynthesisError> {
    let k = items.len();
    assert_eq!(rs.len(), k);
    if k == 0 {
        return Ok(true);
    }
    let abc = &pvk.vk.gamma_abc_g1;
    let n = abc.len() - 1;
    // coef[0] = sum r_i (in Fr), coef[j+1] = sum_i r_i x_ij
    let mut coef = vec![Fr::zero(); n + 1];
    for ((_, x), &r) in items.iter().zip(rs) {
        if x.len() != n {
            return Err(SynthesisError::MalformedVerifyingKey);
        }
        let rf = Fr::from(r);
        coef[0] += rf;
        for (cj, xj) in coef[1..].iter_mut().zip(x.iter()) {
            cj.add_assign(&rf.mul(xj));
        }
    }
    let mut ic = G1Projective::zero();
    for (b, c) in abc.iter().zip(&coef) {
        ic += b.mul_bigint(c.into_bigint());
    }
    let cs: Vec<G1Affine> = items.iter().map(|(p, _)| p.c).collect();
    let c_comb = combine_c(&cs, rs);
    let ra: Vec<G1Projective> = items.iter().zip(rs).map(|((p, _), &r)| p.a.mul_bigint(big128(r))).collect();
    let mut g1: Vec<G1Affine> = G1Projective::normalize_batch(&ra);
    g1.push(ic.into_affine());
    g1.push(c_comb.into_affine());
    let mut g2: Vec<<Bn254 as Pairing>::G2Prepared> = items.iter().map(|(p, _)| p.b.into()).collect();
    g2.push(pvk.gamma_g2_neg_pc.clone());
    g2.push(pvk.delta_g2_neg_pc.clone());
    let ml = Bn254::multi_miller_loop(g1.into_iter().map(<Bn254 as Pairing>::G1Prepared::from), g2);
    let fe = Bn254::final_exponentiation(ml).ok_or(SynthesisError::UnexpectedIdentity)?;
    let rhs = pvk.alpha_g1_beta_g2.pow(sum_u128(rs));
    Ok(fe.0 == rhs)
}

/// Batch verification, fresh random scalars from `OsRng` drawn inside the call.
pub fn batch_verify(pvk: &PreparedVerifyingKey<Bn254>, items: &[(&Proof<Bn254>, &[Fr])]) -> Result<bool, SynthesisError> {
    let rs = draw_scalars(items.len());
    batch_verify_with_scalars(pvk, items, &rs)
}

impl VerifySetup {
    /// Stage `groth16_verify_batch_q`: the SAME window of proofs as `verify_q(start, q)` (proof (start + k) mod len, k = 0..q, with its own
    /// public inputs) verified as one batch. Returns the batch verdict.
    pub fn verify_batch_q(&self, start: usize, q: usize) -> bool {
        let items: Vec<(&Proof<Bn254>, &[Fr])> = (0..q)
            .map(|k| {
                let (p, x) = &self.items[(start + k) % self.items.len()];
                (std::hint::black_box(p), std::hint::black_box(x.as_slice()))
            })
            .collect();
        batch_verify(&self.pvk, &items).unwrap()
    }
}
