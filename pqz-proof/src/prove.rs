//! Generic winterfell prover/verifier wiring shared by the three relations, and the proof options.

use crate::rescue::F;
use winterfell::{
    crypto::{hashers::Sha3_256, DefaultRandomCoin, MerkleTree},
    math::FieldElement,
    matrix::ColMatrix,
    Air, AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, ProverError,
    StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

pub type Hash = Sha3_256<F>;
pub type Coin = DefaultRandomCoin<Hash>;
pub type Vc = MerkleTree<Hash>;

/// Proof parameters used everywhere in this crate. Winterfell has no built-in default; these follow the
/// library's own examples (blowup 8, FRI folding 8, remainder degree 31, linear batching) with a quadratic
/// field extension (the base field is only 64 bits), 40 queries and 16 bits of grinding. The security level
/// printed by the benchmark is the library's estimate for exactly these options (`Proof::conjectured_security`).
pub fn default_options() -> ProofOptions {
    ProofOptions::new(
        40,
        8,
        16,
        FieldExtension::Quadratic,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

pub struct GenericProver<A: Air<BaseField = F>> {
    options: ProofOptions,
    pub_inputs: A::PublicInputs,
}

impl<A: Air<BaseField = F>> GenericProver<A> {
    pub fn new(options: ProofOptions, pub_inputs: A::PublicInputs) -> Self {
        Self { options, pub_inputs }
    }
}

impl<A> Prover for GenericProver<A>
where
    A: Air<BaseField = F> + 'static,
    A::PublicInputs: Clone + Send,
{
    type BaseField = F;
    type Air = A;
    type Trace = TraceTable<F>;
    type HashFn = Hash;
    type VC = Vc;
    type RandomCoin = Coin;
    type TraceLde<E: FieldElement<BaseField = F>> = DefaultTraceLde<E, Hash, Vc>;
    type ConstraintCommitment<E: FieldElement<BaseField = F>> =
        DefaultConstraintCommitment<E, Hash, Vc>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = F>> =
        DefaultConstraintEvaluator<'a, A, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> A::PublicInputs {
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = F>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<F>,
        domain: &StarkDomain<F>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = F>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<F>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = F>>(
        &self,
        air: &'a A,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

/// Prove with the given trace. A panic inside the prover (debug builds validate the trace) is turned into Err.
pub fn prove_trace<A>(
    trace: TraceTable<F>,
    pub_inputs: A::PublicInputs,
    options: ProofOptions,
) -> Result<Proof, String>
where
    A: Air<BaseField = F> + 'static,
    A::PublicInputs: Clone + Send,
{
    let prover = GenericProver::<A>::new(options, pub_inputs);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prover.prove(trace)));
    match r {
        Ok(Ok(p)) => Ok(p),
        Ok(Err(e)) => Err(format!("prover error: {:?}", e as ProverError)),
        Err(_) => Err("prover panicked (trace violates the AIR)".to_string()),
    }
}

/// Verify; accepts only proofs whose options give at least `min_bits` of conjectured security.
pub fn verify_proof<A>(proof: Proof, pub_inputs: A::PublicInputs, min_bits: u32) -> Result<(), String>
where
    A: Air<BaseField = F> + 'static,
{
    let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(min_bits);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        winterfell::verify::<A, Hash, Coin, Vc>(proof, pub_inputs, &acceptable)
    }));
    match r {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("rejected: {:?}", e)),
        Err(_) => Err("rejected: verifier panicked on malformed input".to_string()),
    }
}

/// Library estimates for this proof, using the hash that commits to it.
pub struct Security {
    pub conjectured_bits: u32,
    pub proven_unique_decoding_bits: u32,
    pub proven_list_decoding_bits: u32,
}

pub fn security_of(proof: &Proof) -> Security {
    let c = proof.conjectured_security::<Hash>().bits();
    let p = proof.proven_security::<Hash>();
    Security {
        conjectured_bits: c,
        proven_unique_decoding_bits: p.udr_bits(),
        proven_list_decoding_bits: p.ldr_bits(),
    }
}
