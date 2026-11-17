//! Generic winterfell prover/verifier wiring shared by the three relations, and the proof options.

use crate::rescue::F;
#[cfg(not(feature = "blake3"))]
use winterfell::crypto::hashers::Sha3_256 as CommitHash;
#[cfg(feature = "blake3")]
use winterfell::crypto::hashers::Blake3_256 as CommitHash;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::FieldElement,
    matrix::ColMatrix,
    Air, AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, ProverError,
    StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

/// Hash of the proof commitments (Merkle trees, Fiat-Shamir). w25: Sha3_256 by default, Blake3_256 with the cargo
/// feature `blake3`. The in-circuit hash (Rescue Prime Rp64_256, `rescue.rs`) is not affected.
pub type Hash = CommitHash<F>;
/// Name of the commitment hash this build uses (for result files).
pub const HASH_NAME: &str = if cfg!(feature = "blake3") { "Blake3_256" } else { "Sha3_256" };
pub type Coin = DefaultRandomCoin<Hash>;
pub type Vc = MerkleTree<Hash>;

/// Proof parameters used everywhere in this crate. Winterfell has no built-in default; these follow the
/// library's own examples (blowup 8, FRI folding 8, remainder degree 31, linear batching) with a quadratic
/// field extension (the base field is only 64 bits), 40 queries and 16 bits of grinding. The security level
/// printed by the benchmark is the library's estimate for exactly these options (`Proof::conjectured_security`).
///
/// w25 pilot: the number of queries, the blowup factor and the grinding bits can be overridden by the environment
/// variables PQZ_QUERIES, PQZ_BLOWUP, PQZ_GRIND (defaults 40, 8, 16). Everything else is unchanged. A value that is
/// set but cannot be parsed stops the program (no silent fallback).
pub fn default_options() -> ProofOptions {
    options_with(
        env_usize("PQZ_QUERIES", 40),
        env_usize("PQZ_BLOWUP", 8),
        env_usize("PQZ_GRIND", 16) as u32,
    )
}

/// The crate's options with the given queries, blowup and grinding bits (other fields as in `default_options`).
pub fn options_with(queries: usize, blowup: usize, grind: u32) -> ProofOptions {
    ProofOptions::new(
        queries,
        blowup,
        grind,
        FieldExtension::Quadratic,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

fn env_usize(key: &str, default: usize) -> usize {
    match std::env::var(key) {
        Ok(v) => v.trim().parse().unwrap_or_else(|_| panic!("{key}={v:?} is not a non-negative integer")),
        Err(_) => default,
    }
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

/// STRICT verifier (w30 lead fix e443): accepts ONLY proofs made with exactly `default_options()` (the same queries, blowup,
/// grinding, field extension, FRI folding, remainder degree and batching methods). Not a security floor: a proof with 30 or 35
/// queries is rejected (`UnacceptableProofOptions`), as is one with 80+ conjectured bits but different options.
/// Note: `default_options()` reads PQZ_QUERIES / PQZ_BLOWUP / PQZ_GRIND; a verifier process must not set them (or must set them
/// like the prover). Every production verify path of this crate goes through this function.
pub fn verify_proof<A>(proof: Proof, pub_inputs: A::PublicInputs) -> Result<(), String>
where
    A: Air<BaseField = F> + 'static,
{
    verify_with::<A>(proof, pub_inputs, winterfell::AcceptableOptions::OptionSet(vec![default_options()]))
}

/// WEAK verifier, kept only for code that deliberately verifies non-default options (bin `pilot` with PQZ_* sweeps, and the tests
/// of the minimum-bits rule): accepts every proof with at least `min_bits` of conjectured security. NOT for production paths.
pub fn verify_proof_min_bits<A>(proof: Proof, pub_inputs: A::PublicInputs, min_bits: u32) -> Result<(), String>
where
    A: Air<BaseField = F> + 'static,
{
    verify_with::<A>(proof, pub_inputs, winterfell::AcceptableOptions::MinConjecturedSecurity(min_bits))
}

fn verify_with<A>(proof: Proof, pub_inputs: A::PublicInputs, acceptable: winterfell::AcceptableOptions) -> Result<(), String>
where
    A: Air<BaseField = F> + 'static,
{
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
