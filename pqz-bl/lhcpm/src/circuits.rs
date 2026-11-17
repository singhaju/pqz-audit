//! Stand-in Groth16 circuits over BN254 (arkworks 0.4, single thread).
//! The paper's own circuits are not available; this is a MiMC-style x^5 chain whose R1CS size is a parameter.
//! 3 constraints per round (t^2, t^4, t^4*t). Public inputs: x0, k, out (+ optional extra inputs).
use crate::mimc::Mimc;
use ark_bn254::{Bn254, Fr};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_groth16::{prepare_verifying_key, PreparedVerifyingKey, Proof, ProvingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use ark_snark::SNARK;
use ark_groth16::Groth16;
use crate::par::run_split;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use std::sync::Arc;

#[derive(Clone)]
pub struct Chain {
    pub consts: Arc<Vec<Fr>>,
    pub rounds: usize,
    pub bool_constraints: usize, // padding constraints b*b=b with b=0
    pub extra_pub: Vec<Fr>,      // additional public inputs p, each with a constraint p*p=sq
    pub x0: Fr,
    pub k: Fr,
}

pub fn chain_out(consts: &[Fr], rounds: usize, x0: Fr, k: Fr) -> Fr {
    let mut x = x0;
    for i in 0..rounds {
        x = Mimc::pow5(x + k + consts[i % consts.len()]);
    }
    x
}

impl Chain {
    pub fn out(&self) -> Fr {
        chain_out(&self.consts, self.rounds, self.x0, self.k)
    }
    pub fn public_inputs(&self) -> Vec<Fr> {
        let mut v = vec![self.x0, self.k, self.out()];
        v.extend(self.extra_pub.iter().copied());
        v
    }
    pub fn expected_constraints(&self) -> usize {
        3 * self.rounds + self.bool_constraints + self.extra_pub.len()
    }
}

impl ConstraintSynthesizer<Fr> for Chain {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let out_val = self.out();
        let x0v = cs.new_input_variable(|| Ok(self.x0))?;
        let kv = cs.new_input_variable(|| Ok(self.k))?;
        let outv = cs.new_input_variable(|| Ok(out_val))?;
        let mut cur_lc = LinearCombination::<Fr>::from(x0v);
        let mut cur_val = self.x0;
        for i in 0..self.rounds {
            let c = self.consts[i % self.consts.len()];
            let tval = cur_val + self.k + c;
            let t_lc = cur_lc.clone() + (Fr::one(), kv) + (c, Variable::One);
            let t2val = tval.square();
            let t4val = t2val.square();
            let t5val = t4val * tval;
            let t2 = cs.new_witness_variable(|| Ok(t2val))?;
            let t4 = cs.new_witness_variable(|| Ok(t4val))?;
            cs.enforce_constraint(t_lc.clone(), t_lc.clone(), LinearCombination::from(t2))?;
            cs.enforce_constraint(LinearCombination::from(t2), LinearCombination::from(t2), LinearCombination::from(t4))?;
            let nxt = if i + 1 == self.rounds { outv } else { cs.new_witness_variable(|| Ok(t5val))? };
            cs.enforce_constraint(LinearCombination::from(t4), t_lc, LinearCombination::from(nxt))?;
            cur_lc = LinearCombination::from(nxt);
            cur_val = t5val;
        }
        for _ in 0..self.bool_constraints {
            let b = cs.new_witness_variable(|| Ok(Fr::zero()))?;
            cs.enforce_constraint(LinearCombination::from(b), LinearCombination::from(b), LinearCombination::from(b))?;
        }
        for p in &self.extra_pub {
            let pv = cs.new_input_variable(|| Ok(*p))?;
            let sq = cs.new_witness_variable(|| Ok(p.square()))?;
            cs.enforce_constraint(LinearCombination::from(pv), LinearCombination::from(pv), LinearCombination::from(sq))?;
        }
        Ok(())
    }
}

pub fn new_chain<R: RngCore + Rng + rand::CryptoRng>(consts: &Arc<Vec<Fr>>, rounds: usize, bool_constraints: usize, extra_pub: usize, rng: &mut R) -> Chain {
    Chain {
        consts: consts.clone(),
        rounds,
        bool_constraints,
        extra_pub: (0..extra_pub).map(|_| Fr::rand(rng)).collect(),
        x0: Fr::rand(rng),
        k: Fr::rand(rng),
    }
}

/// Number of R1CS constraints the circuit really produces, and whether the witness satisfies it.
pub fn count_constraints(c: &Chain) -> (usize, bool) {
    let cs = ConstraintSystem::<Fr>::new_ref();
    c.clone().generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    (cs.num_constraints(), cs.is_satisfied().unwrap())
}

/// Circuit sizes treated as PARAMETERS (paper: Mint 2,676; Transfer 8,786). Returns (rounds, padding constraints).
pub fn size_for(target: usize) -> (usize, usize) {
    (target / 3, target % 3)
}

pub struct VerifySetup {
    pub pvk: PreparedVerifyingKey<Bn254>,
    pub items: Vec<(Proof<Bn254>, Vec<Fr>)>,
    pub public_inputs: usize,
}

impl VerifySetup {
    /// `public_inputs` >= 3. Circuit = 4-round chain plus extra public inputs.
    pub fn new<R: RngCore + Rng + rand::CryptoRng>(public_inputs: usize, count: usize, consts: &Arc<Vec<Fr>>, rng: &mut R) -> Self {
        assert!(public_inputs >= 3);
        let extra = public_inputs - 3;
        let c0 = new_chain(consts, 4, 0, extra, rng);
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(c0, rng).unwrap();
        let pvk = prepare_verifying_key(&vk);
        let items = (0..count)
            .map(|_| {
                let c = new_chain(consts, 4, 0, extra, rng);
                let inputs = c.public_inputs();
                let proof = Groth16::<Bn254>::prove(&pk, c, rng).unwrap();
                (proof, inputs)
            })
            .collect();
        VerifySetup { pvk, items, public_inputs }
    }
    pub fn verify(&self, i: usize) -> bool {
        let (proof, inputs) = &self.items[i % self.items.len()];
        Groth16::<Bn254>::verify_with_processed_vk(&self.pvk, inputs, proof).unwrap()
    }
}

impl VerifySetup {
    /// q independent Groth16 verifications in one call (stage `groth16_verify_q`): proof (start + k) mod len with its own
    /// public inputs, k = 0..q. Returns how many verified (no early exit, so all q run even if one fails).
    pub fn verify_q(&self, start: usize, q: usize) -> usize {
        let mut ok = 0usize;
        for k in 0..q {
            let (proof, inputs) = &self.items[(start + k) % self.items.len()];
            ok += Groth16::<Bn254>::verify_with_processed_vk(&self.pvk, std::hint::black_box(inputs), std::hint::black_box(proof)).unwrap() as usize;
        }
        ok
    }
}

pub struct ProveSetup {
    pub pk: ProvingKey<Bn254>,
    pub pvk: PreparedVerifyingKey<Bn254>,
    pub circuits: Vec<Chain>,
    pub constraints: usize,
}

impl ProveSetup {
    /// Circuit-specific trusted setup (untimed) and `count` fresh witnesses (one per run).
    pub fn new<R: RngCore + Rng + rand::CryptoRng>(target_constraints: usize, count: usize, consts: &Arc<Vec<Fr>>, rng: &mut R) -> Self {
        let (rounds, pad) = size_for(target_constraints);
        let c0 = new_chain(consts, rounds, pad, 0, rng);
        let (n, sat) = count_constraints(&c0);
        assert!(sat && n == target_constraints, "constraint count {n} != {target_constraints}");
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(c0, rng).unwrap();
        let pvk = prepare_verifying_key(&vk);
        let circuits = (0..count).map(|_| new_chain(consts, rounds, pad, 0, rng)).collect();
        ProveSetup { pk, pvk, circuits, constraints: n }
    }
    /// The timed operation: witness generation (synthesis) + Groth16.Prove with fresh randomness.
    pub fn prove<R: RngCore + Rng + rand::CryptoRng>(&self, i: usize, rng: &mut R) -> Proof<Bn254> {
        Groth16::<Bn254>::prove(&self.pk, self.circuits[i % self.circuits.len()].clone(), rng).unwrap()
    }
    pub fn check(&self, i: usize, proof: &Proof<Bn254>) -> bool {
        let inputs = self.circuits[i % self.circuits.len()].public_inputs();
        Groth16::<Bn254>::verify_with_processed_vk(&self.pvk, &inputs, proof).unwrap()
    }
    /// (w19, stage `groth16_prove_mint_q`) q proofs one after the other, one thread, in ONE call: proof k uses witness (start + k) mod len
    /// and its own fresh Groth16 randomness; nothing is batched or shared between the q proofs.
    pub fn prove_q<R: RngCore + Rng + rand::CryptoRng>(&self, start: usize, q: usize, rng: &mut R) -> Vec<Proof<Bn254>> {
        let mut out = Vec::with_capacity(q);
        for k in 0..q {
            out.push(self.prove(std::hint::black_box(start + k), rng));
        }
        out
    }
    /// (e405, `--threads T` > 1) Same q items as `prove_q(start, q, ..)`: proof k uses witness (start + k) mod len, witness synthesis inside
    /// the timer, fresh Groth16 randomness per proof, nothing batched or shared between proofs. The q items are split into `threads`
    /// contiguous ranges (sizes differ by at most 1) run by scoped workers, each with its OWN `StdRng::from_entropy()` made before the
    /// barrier (no shared lock). Returns (proofs in item order, wall ms from the barrier release to the last worker's end); the worker
    /// creation is not timed. Check the result with `check_q(start, ..)` after the timer, as for `prove_q`.
    pub fn prove_q_threads(&self, start: usize, q: usize, threads: usize) -> (Vec<Proof<Bn254>>, f64) {
        run_split(q, threads, StdRng::from_entropy, |rng, k| self.prove(std::hint::black_box(start + k), rng))
    }
    /// Untimed check: every one of the q proofs verifies against the public inputs of its own witness.
    pub fn check_q(&self, start: usize, proofs: &[Proof<Bn254>]) -> bool {
        proofs.iter().enumerate().all(|(k, p)| self.check(start + k, p))
    }
}
