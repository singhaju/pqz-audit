# PQZ-Audit demo: code map

Real file:line of the key functions behind each demo phase and topic. Paths are relative to the `PQZ-Audit-code` folder.
Open one in VS Code: `bash demo/show.sh <key>` (e.g. `blockchain`, `p6`); in a terminal: `bash demo/show.sh <key> --term`; menu: `bash demo/show.sh list`.
`demo/show.sh` holds the same table; numbers were checked by grep against the source (`demo/show.sh check` re-checks them).

## Phase 1 Initialization  (`p1`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/lib.rs:617` | `ledger_setup` | Phase 1: AA key, 4-validator ledger, genesis chain (Gamma_0, Omega_0) |
| `pqz-ledger/src/audit.rs:120` | `genesis` | Chain::genesis: builds the genesis policy root and epoch-0 state |
| `pqz-eval/src/eapat.rs:27` | `from_seed` | EpochKeys::from_seed: AES key, tag key and block-signing key from one seed |

## Phase 2 Registration (plain log)  (`p2`)

| location | function / item | what it does |
|---|---|---|
| `pqz-eval/src/lib.rs:37` | `pub struct Record` | The record {id, ts, a, b, c, d} that the library audits |
| `pqz-eval/src/lib.rs:68` | `pub fn matches` | Predicate::matches: plaintext reference predicates (P1 is a = X) |
| `pqz-integrated-w46/src/bin/demo_scenarios.rs:194` | `fn make_records` | Demo only: seeded hospital log generator (xorshift), insider burst of EXPORT_RECORDS |
| `pqz-eval/src/gen.rs:15` | `pub fn r#gen` | Library benchmark log generator (not used by the demo) |

## Phase 3a Encrypt and tag  (`p3a`)

| location | function / item | what it does |
|---|---|---|
| `pqz-eval/src/eapat.rs:150` | `pub fn encrypt_record` | One record -> AES-256-GCM ciphertext + 45 keyed search tags |
| `pqz-eval/src/eapat.rs:100` | `pub fn aead_encrypt` | AES-256-GCM encryption of the record body |
| `pqz-eval/src/search.rs:40` | `pub fn eq_tag` | Keyed equality tag (the trapdoor value the cloud can match) |
| `pqz-integrated-w46/src/lib.rs:270` | `pub fn build_log` | Whole epoch: encrypt, tag, descriptors, Merkle leaves, Bloom filters, proof word stream |

## Phase 3b Blocks, R_RC proofs, AA check  (`p3b`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/w35.rs:285` | `pub fn build_block` | One skippable block: record Merkle root, Bloom summary, commitment |
| `pqz-integrated-w46/src/w35.rs:355` | `pub fn prepare_fmt` | World35 setup: blocks, chunk plan, proof word streams |
| `pqz-integrated-w46/src/w35.rs:396` | `pub fn prove_chunks` | R_RC STARK proofs, one per chunk of blocks |
| `pqz-integrated-w46/src/w35.rs:480` | `pub fn aa_finalize_fmt` | AA check: verify chunk proofs, rebuild blocks, output R_e, N_e, G_e |
| `pqz-integrated-w46/src/w35.rs:239` | `pub fn epoch_root35` | R_e = Merkle root over the block commitments |

## Phase 4 Blockchain anchor  (`p4`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/lib.rs:644` | `pub fn commit_epoch` | Build A_e, sign it, submit the Anchor tx, return Omega_e |
| `pqz-ledger/src/audit.rs:150` | `pub fn next_anchor_root_only` | Chain::next_anchor_root_only: A_e, sigma_e, Gamma_e, Omega_e |
| `pqz-ledger/src/contract.rs:208` | `pub fn omega` | Omega_e = H(label, e, Gamma_e, R_pol, v_auth) |
| `pqz-ledger/src/contract.rs:336` | `pub fn apply` | Contract::apply: checks every transaction (Anchor, Authorize, Consume) |
| `pqz-ledger/src/ledger.rs:279` | `pub fn submit` | Ledger::submit: leader block, 4 validator votes, quorum certificate (simulated) |
| `pqz-integrated-w46/src/lib.rs:666` | `pub fn ledger_read_gate` | Light-client read of State[e] and check of Omega |

## Phase 5 Authorization proof  (`p5`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/lib.rs:714` | `pub fn auth_stage` | R_Auth: authorization proof bound to Omega_e and the query |
| `pqz-integrated-w46/src/lib.rs:742` | `pub fn verify_auth_stage` | Verify the R_Auth proof |
| `pqz-plonky3-w46/src/auth.rs:180` | `pub struct AuthAir` | The R_Auth AIR (policy Merkle path, scope, binding B_Q) |
| `pqz-plonky3-w46/src/request.rs:41` | `pub fn check_ctx` | Link: exec context must equal H(B_Q, d_Q, RID) of the Auth statement |

## Phase 6 Pruning and execution  (`p6`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/lib.rs:771` | `pub fn search` | Search layer: bps_eval per block, rps_eval per record |
| `pqz-integrated-w46/src/w35.rs:640` | `pub fn plan_runs` | Which chunks must be proved (runs) and which blocks are skipped |
| `pqz-integrated-w46/src/w35.rs:741` | `pub fn openings_for_blocks` | Bloom openings (zero bits) for every skipped block |
| `pqz-integrated-w46/src/w35.rs:690` | `pub fn prove_runs` | R_Exec STARK proofs over the retained runs |
| `pqz-integrated-w46/src/w35.rs:773` | `pub fn respond` | Cloud response: blocks, runs, openings, claimed result |
| `pqz-integrated-w46/src/lib.rs:173` | `pub fn v_of` | Exec predicate is fixed here: value THETA iff a = X |

## Phase 7 Requester verification  (`p7`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/w35.rs:966` | `pub fn verify_requester35_fmt` | Requester: native checks + auth proof + run proofs |
| `pqz-integrated-w46/src/w35.rs:827` | `pub fn requester_native35_fmt` | The native checks: R_e, run shape, anchored states, PruneValid, claim |
| `pqz-integrated-w46/src/w35.rs:931` | `does not verify against MRoot` | PruneValid: Merkle path of each Bloom opening against MRoot(S) |
| `pqz-integrated-w46/src/w35.rs:937` | `do not show the query false` | PruneValid: opened bits must prove the query absent |
| `pqz-integrated-w46/src/bin/demo_scenarios.rs:250` | `fn plain_ref` | Demo: plaintext reference answer used for the MATCH line |

## blockchain  (`blockchain`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/lib.rs:617` | `pub fn ledger_setup` | Ledger and AA setup |
| `pqz-ledger/src/ledger.rs:231` | `pub fn new` | Ledger::new: 4 validators, quorum 3 (simulation, in one process) |
| `pqz-ledger/src/ledger.rs:279` | `pub fn submit` | Ledger::submit: block production and votes |
| `pqz-ledger/src/ledger.rs:427` | `pub fn read_state` | Light-client read proof (Merkle path + QC) |
| `pqz-ledger/src/ledger.rs:455` | `pub fn verify_read` | Verify a read proof against validator keys and quorum |
| `pqz-ledger/src/contract.rs:336` | `pub fn apply` | Smart-contract rules (Reject reasons) |
| `pqz-ledger/src/contract.rs:145` | `pub enum Reject` | All contract rejection reasons |

## predicate  (`predicate`)

| location | function / item | what it does |
|---|---|---|
| `pqz-eval/src/lib.rs:68` | `pub fn matches` | Predicate P1..P4 on plaintext |
| `pqz-eval/src/search.rs:118` | `pub enum Formula` | Formula tree (leaf / and / or) over search tags |
| `pqz-eval/src/search.rs:164` | `pub fn formula_for` | Formula of P1..P4 |
| `pqz-eval/src/search.rs:96` | `pub fn range_tags` | Range predicate as a set of prefix tags |
| `pqz-eval/src/search.rs:186` | `pub fn rps_eval` | Exact record-level evaluation on tags |
| `pqz-integrated-w46/src/lib.rs:751` | `pub fn predicate_formula` | The proved predicate (a = X) |
| `pqz-integrated-w46/src/lib.rs:173` | `pub fn v_of` | Why only a = X can be proved end to end |
| `pqz-integrated-w46/src/bin/demo_scenarios.rs:912` | `fn search_scenario` | Demo: compound predicates, search layer only |

## pruning  (`pruning`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/w35.rs:640` | `pub fn plan_runs` | Choose runs from the Bloom flags |
| `pqz-integrated-w46/src/w35.rs:160` | `pub fn plan_absent` | Bloom positions that must be 0 to show a block empty |
| `pqz-integrated-w46/src/w35.rs:741` | `pub fn openings_for_blocks` | Openings for the skipped blocks |
| `pqz-integrated-w46/src/w35.rs:918` | `outside the runs and has no Bloom opening` | Requester rejects a skipped block without openings |
| `pqz-eval/src/search.rs:293` | `pub fn bps_eval` | Block-level Bloom evaluation (no false negatives) |

## bloom  (`bloom`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/w35.rs:29` | `pub fn bloom_params` | Bloom size and k for a block |
| `pqz-integrated-w46/src/w35.rs:41` | `pub fn bloom_positions` | Bit positions of a tag |
| `pqz-integrated-w46/src/w35.rs:82` | `pub struct Bloom35` | Bloom filter with a Merkle tree over its words (MRoot(S)) |
| `pqz-integrated-w46/src/w35.rs:139` | `pub fn open_many` | Open Bloom words with Merkle paths |
| `pqz-eval/src/search.rs:293` | `pub fn bps_eval` | Evaluate a formula on a Bloom filter |

## merkle  (`merkle`)

| location | function / item | what it does |
|---|---|---|
| `pqz-eval/src/eapat.rs:174` | `pub fn merkle_root` | Binary Merkle root of record leaves |
| `pqz-ledger/src/audit.rs:94` | `pub fn epoch_root` | Epoch root over block commitments (ledger-side model) |
| `pqz-integrated-w46/src/w35.rs:239` | `pub fn epoch_root35` | R_e over Block35 commitments |
| `pqz-integrated-w46/src/w35.rs:139` | `pub fn open_many` | Bloom leaf opening paths |
| `pqz-ledger/src/ledger.rs:455` | `pub fn verify_read` | State Merkle path to the QC-signed state_root |

## stark-rc  (`stark-rc`)

| location | function / item | what it does |
|---|---|---|
| `pqz-plonky3-w46/src/rc.rs:104` | `pub struct RcAir` | R_RC AIR: record commitments and block structure |
| `pqz-plonky3-w46/src/pchunk.rs:50` | `pub struct PcLayout` | Chunk AIR layout (packed stream format) |
| `pqz-plonky3-w46/src/pchunk.rs:182` | `pub fn check_sealed` | Check the sealed chunk public values |
| `pqz-integrated-w46/src/w35.rs:396` | `pub fn prove_chunks` | Prove all chunks |
| `pqz-integrated-w46/src/w35.rs:480` | `pub fn aa_finalize_fmt` | AA verifies the chunk proofs |

## stark-exec  (`stark-exec`)

| location | function / item | what it does |
|---|---|---|
| `pqz-plonky3-w46/src/air.rs:156` | `pub struct ExecAir` | R_Exec AIR: count and sum of records with a = X |
| `pqz-plonky3-w46/src/run.rs:126` | `pub struct RunAir` | Run AIR: a chunk run linked to anchored states |
| `pqz-plonky3-w46/src/prun.rs:108` | `pub struct PRunAir` | Run AIR for the packed stream format used by the demo |
| `pqz-plonky3-w46/src/air.rs:408` | `pub fn sponge_iv` | Sponge IV of the exec stream |
| `pqz-integrated-w46/src/w35.rs:690` | `pub fn prove_runs` | Prove the retained runs |
| `pqz-plonky3-w46/src/request.rs:23` | `pub fn exec_context` | Exec context H(B_Q, d_Q, RID) tying the proof to the authorization |

## auth  (`auth`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/lib.rs:714` | `pub fn auth_stage` | Build and prove R_Auth |
| `pqz-integrated-w46/src/lib.rs:742` | `pub fn verify_auth_stage` | Verify R_Auth |
| `pqz-plonky3-w46/src/auth.rs:180` | `pub struct AuthAir` | R_Auth AIR |
| `pqz-plonky3-w46/src/auth.rs:122` | `pub struct PolicyLeaf` | Policy leaf (synthetic in the prototype) |
| `pqz-plonky3-w46/src/request.rs:69` | `pub fn check_scope` | Scope check on the Auth statement |
| `pqz-ledger/src/contract.rs:213` | `pub fn binding_bq` | B_Q binding of query, policy and Omega |

## he  (`he`)

| location | function / item | what it does |
|---|---|---|
| `pqz-eval/src/he.rs:35` | `pub struct HePool` | BFV pool (1024 pre-encrypted values) |
| `pqz-eval/src/he.rs:49` | `pub fn with_pool_size` | Pool setup (the slow part) |
| `pqz-eval/src/he.rs:100` | `pub fn ct_for_b` | Ciphertext of (b mod 1024): the SUM limit is here |
| `pqz-eval/src/he.rs:115` | `pub fn decrypt` | Decrypt an accumulated ciphertext |
| `pqz-ledger/src/threshold.rs:96` | `pub fn combine` | Shamir 3-of-5 combine (stand-in, not threshold decryption) |

## mldsa  (`mldsa`)

| location | function / item | what it does |
|---|---|---|
| `pqz-ledger/src/sig.rs:12` | `pub struct SigKeys` | ML-DSA-65 key pair |
| `pqz-ledger/src/sig.rs:25` | `pub fn sign` | ML-DSA-65 sign |
| `pqz-ledger/src/sig.rs:31` | `pub fn verify` | ML-DSA-65 verify |
| `pqz-ledger/src/ledger.rs:68` | `pub fn sign` | SignedTx::sign: transaction signature |
| `pqz-eval/src/eapat.rs:57` | `pub fn sign_header` | Block header signature |

## attacks  (`attacks`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/bin/demo_scenarios.rs:672` | `fn attack` | Demo: attacks A1..A7, each changes ONE thing |
| `pqz-integrated-w46/src/bin/demo_scenarios.rs:664` | `fn drop_run_of` | Demo: cloud removes the run that holds the matches |
| `pqz-ledger/src/audit.rs:187` | `pub fn drop_block` | Library attack: drop a block from the response |
| `pqz-ledger/src/audit.rs:195` | `pub fn forge_shorter_epoch` | Library attack: shorter epoch |
| `pqz-ledger/src/attacks.rs:128` | `pub fn run_with` | Library attack suite on the contract |
| `pqz-attack-w38/src/main.rs:110` | `fn vcatch` | Proof-level attack harness (tampered proofs) |
| `pqz-attack-w38/src/p2r.rs:87` | `fn ver_x` | Verifier used by the packed-format attacks |

## attack-a1  (`attack-a1`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/bin/demo_scenarios.rs:681` | `"a1" => {` | Demo scenario A1: cloud changes the result |
| `pqz-integrated-w46/src/w35.rs:945` | `differs from the sum over the runs` | The check that rejects A1a/A1b |

## attack-a2  (`attack-a2`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/bin/demo_scenarios.rs:706` | `"a2" => {` | Demo scenario A2: cloud hides a block that has matches |
| `pqz-integrated-w46/src/w35.rs:918` | `outside the runs and has no Bloom opening` | The check that rejects A2 |

## attack-a3  (`attack-a3`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/bin/demo_scenarios.rs:717` | `"a3" => {` | Demo scenario A3: bad or missing Bloom opening |
| `pqz-integrated-w46/src/w35.rs:937` | `do not show the query false` | The check that rejects A3b |

## attack-a4  (`attack-a4`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/bin/demo_scenarios.rs:766` | `"a4" => {` | Demo scenario A4: stored record changed after anchoring |
| `pqz-integrated-w46/src/w35.rs:855` | `rebuilt from the blocks differs` | The check that rejects A4a |

## attack-a5  (`attack-a5`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/bin/demo_scenarios.rs:801` | `"a5" => {` | Demo scenario A5: authorization for another epoch / Omega |
| `pqz-ledger/src/contract.rs:173` | `Reject::OmegaNotCanonical` | The contract rule that rejects A5d |
| `pqz-integrated-w46/src/lib.rs:666` | `pub fn ledger_read_gate` | Gate that rejects A5c |

## attack-a6  (`attack-a6`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/bin/demo_scenarios.rs:832` | `"a6" => {` | Demo scenario A6: authorization for another query |
| `pqz-plonky3-w46/src/request.rs:41` | `pub fn check_ctx` | The link check that rejects A6a |
| `pqz-ledger/src/contract.rs:176` | `Reject::PredicateMismatch` | The contract rule that rejects A6b |

## attack-a7  (`attack-a7`)

| location | function / item | what it does |
|---|---|---|
| `pqz-integrated-w46/src/bin/demo_scenarios.rs:849` | `"a7" => {` | Demo scenario A7: forged ledger anchor |
| `pqz-ledger/src/ledger.rs:455` | `pub fn verify_read` | Rejects A7a to A7c |
| `pqz-ledger/src/contract.rs:170` | `Reject::OmegaRecompute` | Rejects A7d |
