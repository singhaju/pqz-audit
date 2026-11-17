//! w30 (Addendum A2): timing of the one-off key generation of the L-HCPM stand-in, mode `--only-setup`.
//! Stage `groth16_setup_mint`: the Groth16 circuit-specific setup (`Groth16::<Bn254>::circuit_specific_setup`) of the SAME Mint
//! stand-in circuit as `groth16_prove_mint` (`ProveSetup::new(2676, ..)`: 892 rounds, 2,676 constraints, 3 public inputs).
//! Stage `bfv_keygen_regulator`: `Params::new(4096, 28, 3.2).keygen` = the regulator key pair (pk_G, sk_G) of the audit stand-in
//! (the same call `AuditCtx::setup` makes). TrapGen (A_G, T_G) is NOT implemented in this crate and is not timed.
//! Single thread: arkworks 0.4.0 without the `parallel` feature, no thread is started here.
use crate::bfv::{Params, PublicKey};
use crate::circuits::{count_constraints, new_chain, size_for, Chain};
use crate::mimc::Mimc;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_snark::SNARK;
use rand::{rngs::StdRng, SeedableRng};
use std::sync::Arc;
use std::time::Instant;

/// The Mint stand-in size of the paper (same constant as the `groth16_prove_mint` stage).
pub const MINT_CONSTRAINTS: usize = 2676;

/// The circuit instance used for the setup: exactly the one `ProveSetup::new(MINT_CONSTRAINTS, ..)` builds its keys from
/// (rounds, padding from `size_for`, no extra public input). Checked (untimed): constraint count and satisfiability.
pub fn mint_setup_circuit(consts: &Arc<Vec<Fr>>, rng: &mut StdRng) -> Chain {
    let (rounds, pad) = size_for(MINT_CONSTRAINTS);
    let c0 = new_chain(consts, rounds, pad, 0, rng);
    let (n, sat) = count_constraints(&c0);
    assert!(sat && n == MINT_CONSTRAINTS, "constraint count {n} != {MINT_CONSTRAINTS}");
    c0
}

/// Compressed serialised sizes in bytes (ark-serialize `Compress::Yes`): (proving key, verifying key).
pub fn key_sizes(pk: &ProvingKey<Bn254>, vk: &VerifyingKey<Bn254>) -> (usize, usize) {
    (pk.serialized_size(Compress::Yes), vk.serialized_size(Compress::Yes))
}

/// One row of the output.
pub struct SetupRow {
    pub stage: &'static str,
    pub run: usize,
    pub secs: f64,
    pub pk_bytes: String,
    pub vk_bytes: String,
}

/// One timed Groth16 setup. Only the `circuit_specific_setup` call is inside the timer (circuit instance, rng, size counting and
/// the check are outside). Returns (seconds, pk, vk).
pub fn time_groth16_setup(c0: Chain, rng: &mut StdRng) -> (f64, ProvingKey<Bn254>, VerifyingKey<Bn254>) {
    let t = Instant::now();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(std::hint::black_box(c0), rng).unwrap();
    let secs = t.elapsed().as_secs_f64();
    let (pk, vk) = std::hint::black_box((pk, vk));
    (secs, pk, vk)
}

/// Untimed check: one proof made with `pk` for a fresh Mint witness verifies against `vk`, and a changed public input does not.
pub fn check_keys(pk: &ProvingKey<Bn254>, vk: &VerifyingKey<Bn254>, consts: &Arc<Vec<Fr>>, rng: &mut StdRng) -> bool {
    let (rounds, pad) = size_for(MINT_CONSTRAINTS);
    let w = new_chain(consts, rounds, pad, 0, rng);
    let inputs = w.public_inputs();
    let proof = Groth16::<Bn254>::prove(pk, w, rng).unwrap();
    let pvk = prepare_verifying_key(vk);
    let ok = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();
    let mut bad = inputs;
    bad[1] += Fr::from(1u64);
    ok && !Groth16::<Bn254>::verify_with_processed_vk(&pvk, &bad, &proof).unwrap()
}

/// Public-key size of the BFV stand-in in the layout the crate uses (2 polynomials x RNS limbs x n x 8 bytes).
pub fn bfv_pk_bytes(pk: &PublicKey) -> usize {
    pk.p0.iter().chain(pk.p1.iter()).map(|v| v.len() * 8).sum()
}

/// The `--only-setup` run: 1 warm-up (not written) and `runs` timed rounds of each stage, stage by stage. Every timed Groth16 setup is
/// followed (untimed) by `check_keys` on ITS keys. Returns the rows (Groth16 rows first, then BFV rows).
pub fn run_setup_mode(runs: usize, warmup: usize) -> Vec<SetupRow> {
    let consts = Arc::new(Mimc::new().c);
    let mut rows = Vec::new();
    // ---- groth16_setup_mint ----
    for i in 0..warmup + runs {
        let mut rng = StdRng::from_entropy();
        let c0 = mint_setup_circuit(&consts, &mut rng);
        let (secs, pk, vk) = time_groth16_setup(c0, &mut rng);
        assert!(check_keys(&pk, &vk, &consts, &mut rng), "groth16_setup_mint: keys of run {i} do not verify");
        if i >= warmup {
            let (pb, vb) = key_sizes(&pk, &vk);
            rows.push(SetupRow { stage: "groth16_setup_mint", run: i - warmup, secs, pk_bytes: pb.to_string(), vk_bytes: vb.to_string() });
        }
    }
    // ---- bfv_keygen_regulator ----
    let params = Params::new(4096, 28, 3.2);
    for i in 0..warmup + runs {
        let mut rng = StdRng::from_entropy();
        let t = Instant::now();
        let (sk, pk) = params.keygen(&mut rng);
        let secs = t.elapsed().as_secs_f64();
        let (sk, pk) = std::hint::black_box((sk, pk));
        // untimed check: the key pair decrypts what it encrypts
        let plain: Vec<u64> = (0..params.n as u64).map(|k| k % (1 << params.tlog)).collect();
        let ct = params.encrypt(&pk, &plain, &mut rng);
        assert_eq!(params.decrypt(&sk, &ct), plain, "bfv_keygen_regulator: key pair of run {i} does not decrypt");
        if i >= warmup {
            rows.push(SetupRow { stage: "bfv_keygen_regulator", run: i - warmup, secs, pk_bytes: bfv_pk_bytes(&pk).to_string(), vk_bytes: "NA".into() });
        }
    }
    rows
}

pub fn csv_text(rows: &[SetupRow]) -> String {
    let mut s = String::from("stage,run,secs,pk_bytes,vk_bytes\n");
    for r in rows {
        s.push_str(&format!("{},{},{:.9},{},{}\n", r.stage, r.run, r.secs, r.pk_bytes, r.vk_bytes));
    }
    s
}

fn json_str(x: &str) -> String {
    x.replace('\\', "\\\\").replace('"', "\\\"")
}

/// meta.json of the mode (hand-written JSON, no serde in this crate).
pub fn meta_json(runs: usize, warmup: usize, params_tag: &str) -> String {
    format!(
        "{{\n  \"mode\": \"only-setup\",\n  \"baseline\": \"lhcpm\",\n  \"crate\": \"pqz-bl-w30/lhcpm\",\n  \"runs\": {runs},\n  \"warmup\": {warmup},\n  \"params_tag\": \"{}\",\n  \"threads\": 1,\n  \"parallel_feature\": false,\n  \"stages\": {{\n    \"groth16_setup_mint\": \"Groth16::<Bn254>::circuit_specific_setup of the Mint stand-in (constraints={MINT_CONSTRAINTS}, 3 public inputs, arkworks =0.4.0); timer = that call only; pk_bytes/vk_bytes = ark-serialize compressed sizes of ProvingKey/VerifyingKey\",\n    \"bfv_keygen_regulator\": \"Params::new(4096,28,3.2).keygen (pk_G, sk_G of the audit stand-in); timer = that call only; pk_bytes = 2 polys x 2 RNS limbs x 4096 x 8 B, vk_bytes = NA\"\n  }},\n  \"not_measured\": \"TrapGen (A_G, T_G) is not implemented in this crate (the paper text gives about 3.4 s as one-time startup, not measured here); prepare_verifying_key is not part of the setup row\",\n  \"check\": \"after every timed round (untimed): a proof made with the new keys verifies and a changed public input is rejected (Groth16); the BFV key pair decrypts its own ciphertext\",\n  \"columns\": \"stage,run,secs,pk_bytes,vk_bytes\"\n}}\n",
        json_str(params_tag)
    )
}
