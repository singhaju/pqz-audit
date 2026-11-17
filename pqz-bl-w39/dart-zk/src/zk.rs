//! work39: the zk-SNARK step of DART (ZKP.Prove, Eq. 5 / Algorithm 1 line 6; ZKP.Verify, Algorithm 2 lines 6-9),
//! as Groth16 over BN254 (arkworks 0.4). See SPEC-dart-zk.md and FIDELITY.md. Nothing here changes an existing stage.
//!
//! Relation (the local-challenge circuit Theta_Loc, our reading of Eq. 5 + l.500-506):
//!   public x = ({alpha_i}_{i in Lambda}, gamma_a = {gamma_{a,j}}_{j<N});   witness w = {D~_{i,k}} (z*N*M blocks)
//!   gamma_{i,j} = COM(D~_{i,jM}, ..., D~_{i,jM+M-1})   for i in Lambda, j < N       (z*N commitments)
//!   gamma_{a,j} = sum_{i in Lambda} alpha_i * gamma_{i,j}  for j < N                (Eq. 4 coefficients)
//! COM = Poseidon over the BN254 scalar field (our choice; the paper does not name COM), width M+1, one permutation,
//! x^5 S-box, R_F = 8, R_P = 66, parameters from ark-crypto-primitives' Grain-LFSR generator.
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;
use ark_ff::{Field, PrimeField, Zero};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_relations::lc;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, LinearCombination, SynthesisError, SynthesisMode, Variable,
};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use std::sync::Arc;
use std::time::Instant;

use crate::{Node, Params, Scalar, BLOCK_BYTES};

pub const RF: usize = 8;
pub const RP: usize = 66;

// ---------------------------------------------------------------- Poseidon (native)

pub struct Poseidon {
    pub t: usize,
    pub ark: Vec<Vec<Fr>>,
    pub mds: Vec<Vec<Fr>>,
}

impl Poseidon {
    /// Width t = m + 1 (rate m, capacity 1); one permutation hashes m field elements.
    pub fn new(m: usize) -> Self {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(254, m, RF as u64, RP as u64, 0);
        assert_eq!(mds.len(), m + 1);
        assert_eq!(ark.len(), RF + RP);
        Poseidon { t: m + 1, ark, mds }
    }
    #[inline]
    fn is_full(r: usize) -> bool {
        r < RF / 2 || r >= RF / 2 + RP
    }
    pub fn permute(&self, st: &mut [Fr]) {
        for r in 0..RF + RP {
            for (s, c) in st.iter_mut().zip(&self.ark[r]) {
                *s += c;
            }
            if Self::is_full(r) {
                for s in st.iter_mut() {
                    *s = pow5(*s);
                }
            } else {
                st[0] = pow5(st[0]);
            }
            let old = st.to_vec();
            for (i, s) in st.iter_mut().enumerate() {
                *s = self.mds[i].iter().zip(&old).map(|(a, b)| *a * b).sum();
            }
        }
    }
    /// COM.Commit(M field elements) = first state element after one permutation of [M, x_0..x_{M-1}].
    pub fn commit(&self, x: &[Fr]) -> Fr {
        assert_eq!(x.len() + 1, self.t);
        let mut st = Vec::with_capacity(self.t);
        st.push(Fr::from(x.len() as u64));
        st.extend_from_slice(x);
        self.permute(&mut st);
        st[0]
    }
}

#[inline]
fn pow5(x: Fr) -> Fr {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

// ---------------------------------------------------------------- the circuit

/// Theta_Loc. `None` values = setup mode (shape only).
#[derive(Clone)]
pub struct DartLocCircuit<'a> {
    pub z: usize,
    pub n: usize,
    pub m: usize,
    pub pos: Arc<Poseidon>,
    pub blocks: Option<&'a [Fr]>, // z*n*m witness
    pub alphas: Option<&'a [Fr]>, // z public
    pub gamma: Option<&'a [Fr]>,  // n public
}

type Lcv = (LinearCombination<Fr>, Option<Fr>);

fn sbox(cs: &ConstraintSystemRef<Fr>, x: &Lcv) -> Result<Lcv, SynthesisError> {
    let miss = || SynthesisError::AssignmentMissing;
    let v2 = x.1.map(|v| v.square());
    let t2 = cs.new_witness_variable(|| v2.ok_or_else(miss))?;
    cs.enforce_constraint(x.0.clone(), x.0.clone(), lc!() + t2)?;
    let v4 = v2.map(|v| v.square());
    let t4 = cs.new_witness_variable(|| v4.ok_or_else(miss))?;
    cs.enforce_constraint(lc!() + t2, lc!() + t2, lc!() + t4)?;
    let v5 = v4.zip(x.1).map(|(a, b)| a * b);
    let t5 = cs.new_witness_variable(|| v5.ok_or_else(miss))?;
    cs.enforce_constraint(lc!() + t4, x.0.clone(), lc!() + t5)?;
    Ok((lc!() + t5, v5))
}

impl<'a> ConstraintSynthesizer<Fr> for DartLocCircuit<'a> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let miss = || SynthesisError::AssignmentMissing;
        let (z, n, m) = (self.z, self.n, self.m);
        let alpha_v: Vec<Variable> = (0..z)
            .map(|i| cs.new_input_variable(|| self.alphas.map(|a| a[i]).ok_or_else(miss)))
            .collect::<Result<_, _>>()?;
        let gamma_v: Vec<Variable> = (0..n)
            .map(|j| cs.new_input_variable(|| self.gamma.map(|g| g[j]).ok_or_else(miss)))
            .collect::<Result<_, _>>()?;
        let p = &*self.pos;
        let t = p.t;
        let mut acc: Vec<LinearCombination<Fr>> = vec![lc!(); n];
        for i in 0..z {
            for j in 0..n {
                let base = (i * n + j) * m;
                // state = [M, blocks...]
                let mut st: Vec<Lcv> = Vec::with_capacity(t);
                st.push((lc!() + (Fr::from(m as u64), Variable::One), Some(Fr::from(m as u64))));
                for k in 0..m {
                    let val = self.blocks.map(|b| b[base + k]);
                    let v = cs.new_witness_variable(|| val.ok_or_else(miss))?;
                    st.push((lc!() + v, val));
                }
                for r in 0..RF + RP {
                    // add round constants, S-box, MDS
                    for (k, s) in st.iter_mut().enumerate() {
                        let c = p.ark[r][k];
                        s.0 = s.0.clone() + (c, Variable::One);
                        s.1 = s.1.map(|v| v + c);
                    }
                    if Poseidon::is_full(r) {
                        for s in st.iter_mut() {
                            *s = sbox(&cs, s)?;
                        }
                    } else {
                        st[0] = sbox(&cs, &st[0])?;
                    }
                    let old = st.clone();
                    for (row, s) in st.iter_mut().enumerate() {
                        let mut l = LinearCombination::<Fr>::zero();
                        let mut v = Some(Fr::zero());
                        for (c, o) in p.mds[row].iter().zip(&old) {
                            l = l + (&o.0 * *c);
                            v = v.zip(o.1).map(|(a, b)| a + *c * b);
                        }
                        *s = (l, v);
                    }
                }
                // H = gamma_{i,j} = st[0]; prod = alpha_i * H; acc_j += prod
                let h = &st[0];
                let prod_val = self.alphas.zip(h.1).map(|(a, hv)| a[i] * hv);
                let prod = cs.new_witness_variable(|| prod_val.ok_or_else(miss))?;
                cs.enforce_constraint(lc!() + alpha_v[i], h.0.clone(), lc!() + prod)?;
                acc[j] = acc[j].clone() + prod;
            }
        }
        for j in 0..n {
            cs.enforce_constraint(acc[j].clone(), lc!() + Variable::One, lc!() + gamma_v[j])?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- setup (one-time, outside every timer)

pub struct ZkCtx {
    pub z: usize,
    pub n: usize,
    pub m: usize,
    pub pos: Arc<Poseidon>,
    pub pk: ProvingKey<Bn254>,
    pub pvk: PreparedVerifyingKey<Bn254>,
    /// R1CS constraints of Theta_Loc as synthesized (before Groth16 adds one per public input)
    pub constraints: usize,
    pub public_inputs: usize,
    pub witness_vars: usize,
    pub setup_ms: f64,
    /// uncompressed serialized size of the proving key
    pub pk_bytes: usize,
    pub vk_bytes: usize,
}

pub fn zk_setup<R: RngCore + CryptoRng>(z: usize, n: usize, m: usize, rng: &mut R) -> ZkCtx {
    let pos = Arc::new(Poseidon::new(m));
    let blank = DartLocCircuit { z, n, m, pos: pos.clone(), blocks: None, alphas: None, gamma: None };
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    blank.clone().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let constraints = cs.num_constraints();
    let public_inputs = cs.num_instance_variables() - 1;
    let witness_vars = cs.num_witness_variables();
    drop(cs);
    let t = Instant::now();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(blank, rng).unwrap();
    let setup_ms = t.elapsed().as_secs_f64() * 1e3;
    let pk_bytes = pk.serialized_size(Compress::No);
    let vk_bytes = vk.serialized_size(Compress::No);
    let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
    ZkCtx { z, n, m, pos, pk, pvk, constraints, public_inputs, witness_vars, setup_ms, pk_bytes, vk_bytes }
}

// ---------------------------------------------------------------- untimed input preparation

/// Everything ZKP.Prove takes besides the keys, converted to BN254 (outside every timer).
#[derive(Clone)]
pub struct ZkInput {
    /// witness: the z*n*m challenged blocks, as BN254 field elements (block bytes reduced mod r)
    pub blocks: Vec<Fr>,
    /// public: alpha_i (the BLS12-381 PRG output reduced mod r_BN254)
    pub alphas: Vec<Fr>,
    /// public: gamma_{a,j} = sum_i alpha_i * Poseidon(blocks of (i, j)), computed natively (the circuit's own hash)
    pub gamma: Vec<Fr>,
}

fn fr_from_block(b: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(b)
}

fn alpha_to_bn(a: &Scalar) -> Fr {
    Fr::from_le_bytes_mod_order(&a.to_bytes())
}

/// lam = Lambda = [(i, alpha_i)] from `challenge_set`. Reads the stored blocks of the challenged chunks.
pub fn zk_prepare(ctx: &ZkCtx, p: &Params, node: &Node, lam: &[(usize, Scalar)]) -> ZkInput {
    assert_eq!((lam.len(), p.n, p.m), (ctx.z, ctx.n, ctx.m));
    let chunk_bytes = p.n * p.m * BLOCK_BYTES;
    let mut blocks = Vec::with_capacity(ctx.z * ctx.n * ctx.m);
    let mut alphas = Vec::with_capacity(ctx.z);
    let mut gamma = vec![Fr::zero(); ctx.n];
    for (i, a) in lam {
        let al = alpha_to_bn(a);
        alphas.push(al);
        let chunk = &node.blocks[i * chunk_bytes..(i + 1) * chunk_bytes];
        for j in 0..p.n {
            let start = blocks.len();
            for k in 0..p.m {
                let off = (j * p.m + k) * BLOCK_BYTES;
                blocks.push(fr_from_block(&chunk[off..off + BLOCK_BYTES]));
            }
            gamma[j] += al * ctx.pos.commit(&blocks[start..]);
        }
    }
    ZkInput { blocks, alphas, gamma }
}

// ---------------------------------------------------------------- timed pieces

/// ZKP.Prove: Groth16 prove (includes witness generation / circuit synthesis).
pub fn zk_prove<R: RngCore + CryptoRng>(ctx: &ZkCtx, inp: &ZkInput, rng: &mut R) -> Proof<Bn254> {
    let c = DartLocCircuit {
        z: ctx.z,
        n: ctx.n,
        m: ctx.m,
        pos: ctx.pos.clone(),
        blocks: Some(&inp.blocks),
        alphas: Some(&inp.alphas),
        gamma: Some(&inp.gamma),
    };
    Groth16::<Bn254>::prove(&ctx.pk, c, rng).unwrap()
}

/// ZKP.Verify: Groth16 verify with the prepared verification key; public inputs = alphas ++ gamma.
pub fn zk_verify(ctx: &ZkCtx, alphas: &[Fr], gamma: &[Fr], proof: &Proof<Bn254>) -> bool {
    let mut x = Vec::with_capacity(alphas.len() + gamma.len());
    x.extend_from_slice(alphas);
    x.extend_from_slice(gamma);
    Groth16::<Bn254>::verify_with_processed_vk(&ctx.pvk, &x, proof).unwrap_or(false)
}
