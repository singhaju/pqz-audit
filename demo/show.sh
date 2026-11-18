#!/usr/bin/env bash
# Open the code behind a demo phase or topic.
#   bash demo/show.sh list                 menu of keys
#   bash demo/show.sh <key> [N]            open row N (default 1) of <key> in VS Code at file:line
#   bash demo/show.sh <key> [N] --term     print it with bat (falls back to less) instead of VS Code
#   bash demo/show.sh <key> --all          list every row of <key>
#   bash demo/show.sh check                verify that every file:line still holds its function name
# Table = demo/CODE-MAP.md (same rows). Columns: key, file, line, end, name, explanation.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

table() { sed -n '/^__TABLE__$/,$p' "${BASH_SOURCE[0]}" | tail -n +2; }

keys() { table | cut -f1 | awk '!s[$0]++'; }

list() {
  echo "show.sh keys (phases p1..p7, topics, attacks):"
  for k in $(keys); do
    n=$(table | awk -F'\t' -v k="$k" '$1==k' | wc -l)
    first=$(table | awk -F'\t' -v k="$k" '$1==k{print $6; exit}')
    printf '  %-12s %2d rows  %s\n' "$k" "$n" "$first"
  done
}

check() {
  bad=0
  while IFS=$'\t' read -r key file line end name ex; do
    if ! sed -n "${line}p" "$ROOT/$file" | grep -qF -e "$name"; then echo "STALE  $key $file:$line  ($name)"; bad=1; fi
  done < <(table)
  [ $bad = 0 ] && echo "all $(table | wc -l) rows OK"
  return $bad
}

[ $# -eq 0 ] && { list; exit 0; }
case "$1" in
  list|-h|--help) list; exit 0 ;;
  check) check; exit $? ;;
esac

key="$1"; shift
n=1; term=0; all=0
for a in "$@"; do
  case "$a" in
    --term) term=1 ;;
    --all) all=1 ;;
    [0-9]*) n="$a" ;;
  esac
done
rows=$(table | awk -F'\t' -v k="$key" '$1==k')
[ -z "$rows" ] && { echo "unknown key '$key'"; list; exit 1; }
if [ $all = 1 ]; then
  echo "$rows" | awk -F'\t' '{printf "%2d  %s:%s  %s\n      %s\n", NR, $2, $3, $5, $6}'
  exit 0
fi
row=$(echo "$rows" | sed -n "${n}p")
[ -z "$row" ] && { echo "no row $n for '$key'"; exit 1; }
IFS=$'\t' read -r _ file line end name ex <<<"$row"
echo "$key #$n: $file:$line  $name"
echo "  $ex"
if [ $term = 1 ]; then
  if command -v bat >/dev/null 2>&1; then
    bat --paging=${BAT_PAGING:-always} --style=numbers,header --highlight-line "$line" -r "$line:$end" "$ROOT/$file"
  else
    less +"$line" "$ROOT/$file"
  fi
else
  if command -v code >/dev/null 2>&1; then
    code "$ROOT" -g "$ROOT/$file:$line"
  else
    echo "VS Code ('code') not found; use --term"; exit 1
  fi
fi
exit 0
__TABLE__
p1	pqz-integrated-w46/src/lib.rs	617	647	ledger_setup	Phase 1: AA key, 4-validator ledger, genesis chain (Gamma_0, Omega_0)
p1	pqz-ledger/src/audit.rs	120	150	genesis	Chain::genesis: builds the genesis policy root and epoch-0 state
p1	pqz-eval/src/eapat.rs	27	57	from_seed	EpochKeys::from_seed: AES key, tag key and block-signing key from one seed
p2	pqz-eval/src/lib.rs	49	79	pub struct Record	The record {id, ts, a, b, c, d} that the library audits
p2	pqz-eval/src/lib.rs	80	110	pub fn matches	Predicate::matches: plaintext reference predicates (P1 is a = X)
p2	pqz-integrated-w46/src/bin/demo_scenarios.rs	201	231	fn make_records	Demo only: seeded hospital log generator (xorshift), insider burst of EXPORT_RECORDS
p2	pqz-eval/src/gen.rs	15	45	pub fn r#gen	Library benchmark log generator (not used by the demo)
p3a	pqz-eval/src/eapat.rs	150	180	pub fn encrypt_record	One record -> AES-256-GCM ciphertext + 45 keyed search tags
p3a	pqz-eval/src/eapat.rs	100	130	pub fn aead_encrypt	AES-256-GCM encryption of the record body
p3a	pqz-eval/src/search.rs	40	70	pub fn eq_tag	Keyed equality tag (the trapdoor value the cloud can match)
p3a	pqz-integrated-w46/src/lib.rs	270	300	pub fn build_log	Whole epoch: encrypt, tag, descriptors, Merkle leaves, Bloom filters, proof word stream
p3b	pqz-integrated-w46/src/w35.rs	285	315	pub fn build_block	One skippable block: record Merkle root, Bloom summary, commitment
p3b	pqz-integrated-w46/src/w35.rs	355	385	pub fn prepare_fmt	World35 setup: blocks, chunk plan, proof word streams
p3b	pqz-integrated-w46/src/w35.rs	396	426	pub fn prove_chunks	R_RC STARK proofs, one per chunk of blocks
p3b	pqz-integrated-w46/src/w35.rs	480	510	pub fn aa_finalize_fmt	AA check: verify chunk proofs, rebuild blocks, output R_e, N_e, G_e
p3b	pqz-integrated-w46/src/w35.rs	239	269	pub fn epoch_root35	R_e = Merkle root over the block commitments
p4	pqz-integrated-w46/src/lib.rs	644	674	pub fn commit_epoch	Build A_e, sign it, submit the Anchor tx, return Omega_e
p4	pqz-ledger/src/audit.rs	150	180	pub fn next_anchor_root_only	Chain::next_anchor_root_only: A_e, sigma_e, Gamma_e, Omega_e
p4	pqz-ledger/src/contract.rs	208	238	pub fn omega	Omega_e = H(label, e, Gamma_e, R_pol, v_auth)
p4	pqz-ledger/src/contract.rs	336	366	pub fn apply	Contract::apply: checks every transaction (Anchor, Authorize, Consume)
p4	pqz-ledger/src/ledger.rs	279	309	pub fn submit	Ledger::submit: leader block, 4 validator votes, quorum certificate (simulated)
p4	pqz-integrated-w46/src/lib.rs	666	696	pub fn ledger_read_gate	Light-client read of State[e] and check of Omega
p5	pqz-integrated-w46/src/lib.rs	714	744	pub fn auth_stage	R_Auth: authorization proof bound to Omega_e and the query
p5	pqz-integrated-w46/src/lib.rs	742	772	pub fn verify_auth_stage	Verify the R_Auth proof
p5	pqz-plonky3-w46/src/auth.rs	180	210	pub struct AuthAir	The R_Auth AIR (policy Merkle path, scope, binding B_Q)
p5	pqz-plonky3-w46/src/request.rs	41	71	pub fn check_ctx	Link: exec context must equal H(B_Q, d_Q, RID) of the Auth statement
p6	pqz-integrated-w46/src/lib.rs	771	801	pub fn search	Search layer: bps_eval per block, rps_eval per record
p6	pqz-integrated-w46/src/w35.rs	640	670	pub fn plan_runs	Which chunks must be proved (runs) and which blocks are skipped
p6	pqz-integrated-w46/src/w35.rs	741	771	pub fn openings_for_blocks	Bloom openings (zero bits) for every skipped block
p6	pqz-integrated-w46/src/w35.rs	690	720	pub fn prove_runs	R_Exec STARK proofs over the retained runs
p6	pqz-integrated-w46/src/w35.rs	773	803	pub fn respond	Cloud response: blocks, runs, openings, claimed result
p6	pqz-integrated-w46/src/lib.rs	173	203	pub fn v_of	Exec predicate is fixed here: value THETA iff a = X
p7	pqz-integrated-w46/src/w35.rs	966	996	pub fn verify_requester35_fmt	Requester: native checks + auth proof + run proofs
p7	pqz-integrated-w46/src/w35.rs	827	857	pub fn requester_native35_fmt	The native checks: R_e, run shape, anchored states, PruneValid, claim
p7	pqz-integrated-w46/src/w35.rs	931	961	does not verify against MRoot	PruneValid: Merkle path of each Bloom opening against MRoot(S)
p7	pqz-integrated-w46/src/w35.rs	937	967	do not show the query false	PruneValid: opened bits must prove the query absent
p7	pqz-integrated-w46/src/bin/demo_scenarios.rs	257	287	fn plain_ref	Demo: plaintext reference answer used for the MATCH line
blockchain	pqz-integrated-w46/src/lib.rs	617	647	pub fn ledger_setup	Ledger and AA setup
blockchain	pqz-ledger/src/ledger.rs	231	261	pub fn new	Ledger::new: 4 validators, quorum 3 (simulation, in one process)
blockchain	pqz-ledger/src/ledger.rs	279	309	pub fn submit	Ledger::submit: block production and votes
blockchain	pqz-ledger/src/ledger.rs	427	457	pub fn read_state	Light-client read proof (Merkle path + QC)
blockchain	pqz-ledger/src/ledger.rs	455	485	pub fn verify_read	Verify a read proof against validator keys and quorum
blockchain	pqz-ledger/src/contract.rs	336	366	pub fn apply	Smart-contract rules (Reject reasons)
blockchain	pqz-ledger/src/contract.rs	145	175	pub enum Reject	All contract rejection reasons
predicate	pqz-eval/src/lib.rs	80	110	pub fn matches	Predicate P1..P4 on plaintext
predicate	pqz-eval/src/search.rs	118	148	pub enum Formula	Formula tree (leaf / and / or) over search tags
predicate	pqz-eval/src/search.rs	164	194	pub fn formula_for	Formula of P1..P4
predicate	pqz-eval/src/search.rs	96	126	pub fn range_tags	Range predicate as a set of prefix tags
predicate	pqz-eval/src/search.rs	186	216	pub fn rps_eval	Exact record-level evaluation on tags
predicate	pqz-integrated-w46/src/lib.rs	751	781	pub fn predicate_formula	The proved predicate (a = X)
predicate	pqz-integrated-w46/src/lib.rs	173	203	pub fn v_of	Why only a = X can be proved end to end
predicate	pqz-integrated-w46/src/bin/demo_scenarios.rs	919	949	fn search_scenario	Demo: compound predicates, search layer only
predicate	pqz-integrated-w46/src/bin/demo_scenarios.rs	1005	1051	fn custom_case	Demo menu 5: the audience's own query as a search formula
predicate	pqz-eval/src/lib.rs	29	37	pub fn x() -> u32 {	Demo menu 6: the action code x of P1 (default 7); set_x_for_demo changes it before the log is built
pruning	pqz-integrated-w46/src/w35.rs	640	670	pub fn plan_runs	Choose runs from the Bloom flags
pruning	pqz-integrated-w46/src/w35.rs	160	190	pub fn plan_absent	Bloom positions that must be 0 to show a block empty
pruning	pqz-integrated-w46/src/w35.rs	741	771	pub fn openings_for_blocks	Openings for the skipped blocks
pruning	pqz-integrated-w46/src/w35.rs	918	948	outside the runs and has no Bloom opening	Requester rejects a skipped block without openings
pruning	pqz-eval/src/search.rs	293	323	pub fn bps_eval	Block-level Bloom evaluation (no false negatives)
bloom	pqz-integrated-w46/src/w35.rs	29	59	pub fn bloom_params	Bloom size and k for a block
bloom	pqz-integrated-w46/src/w35.rs	41	71	pub fn bloom_positions	Bit positions of a tag
bloom	pqz-integrated-w46/src/w35.rs	82	112	pub struct Bloom35	Bloom filter with a Merkle tree over its words (MRoot(S))
bloom	pqz-integrated-w46/src/w35.rs	139	169	pub fn open_many	Open Bloom words with Merkle paths
bloom	pqz-eval/src/search.rs	293	323	pub fn bps_eval	Evaluate a formula on a Bloom filter
merkle	pqz-eval/src/eapat.rs	174	204	pub fn merkle_root	Binary Merkle root of record leaves
merkle	pqz-ledger/src/audit.rs	94	124	pub fn epoch_root	Epoch root over block commitments (ledger-side model)
merkle	pqz-integrated-w46/src/w35.rs	239	269	pub fn epoch_root35	R_e over Block35 commitments
merkle	pqz-integrated-w46/src/w35.rs	139	169	pub fn open_many	Bloom leaf opening paths
merkle	pqz-ledger/src/ledger.rs	455	485	pub fn verify_read	State Merkle path to the QC-signed state_root
stark-rc	pqz-plonky3-w46/src/rc.rs	104	134	pub struct RcAir	R_RC AIR: record commitments and block structure
stark-rc	pqz-plonky3-w46/src/pchunk.rs	50	80	pub struct PcLayout	Chunk AIR layout (packed stream format)
stark-rc	pqz-plonky3-w46/src/pchunk.rs	182	212	pub fn check_sealed	Check the sealed chunk public values
stark-rc	pqz-integrated-w46/src/w35.rs	396	426	pub fn prove_chunks	Prove all chunks
stark-rc	pqz-integrated-w46/src/w35.rs	480	510	pub fn aa_finalize_fmt	AA verifies the chunk proofs
stark-exec	pqz-plonky3-w46/src/air.rs	156	186	pub struct ExecAir	R_Exec AIR: count and sum of records with a = X
stark-exec	pqz-plonky3-w46/src/run.rs	126	156	pub struct RunAir	Run AIR: a chunk run linked to anchored states
stark-exec	pqz-plonky3-w46/src/prun.rs	108	138	pub struct PRunAir	Run AIR for the packed stream format used by the demo
stark-exec	pqz-plonky3-w46/src/air.rs	408	438	pub fn sponge_iv	Sponge IV of the exec stream
stark-exec	pqz-integrated-w46/src/w35.rs	690	720	pub fn prove_runs	Prove the retained runs
stark-exec	pqz-plonky3-w46/src/request.rs	23	53	pub fn exec_context	Exec context H(B_Q, d_Q, RID) tying the proof to the authorization
auth	pqz-integrated-w46/src/lib.rs	714	744	pub fn auth_stage	Build and prove R_Auth
auth	pqz-integrated-w46/src/lib.rs	742	772	pub fn verify_auth_stage	Verify R_Auth
auth	pqz-plonky3-w46/src/auth.rs	180	210	pub struct AuthAir	R_Auth AIR
auth	pqz-plonky3-w46/src/auth.rs	122	152	pub struct PolicyLeaf	Policy leaf (synthetic in the prototype)
auth	pqz-plonky3-w46/src/request.rs	69	99	pub fn check_scope	Scope check on the Auth statement
auth	pqz-ledger/src/contract.rs	213	243	pub fn binding_bq	B_Q binding of query, policy and Omega
he	pqz-eval/src/he.rs	35	65	pub struct HePool	BFV pool (1024 pre-encrypted values)
he	pqz-eval/src/he.rs	49	79	pub fn with_pool_size	Pool setup (the slow part)
he	pqz-eval/src/he.rs	100	130	pub fn ct_for_b	Ciphertext of (b mod 1024): the SUM limit is here
he	pqz-eval/src/he.rs	115	145	pub fn decrypt	Decrypt an accumulated ciphertext
he	pqz-ledger/src/threshold.rs	96	126	pub fn combine	Shamir 3-of-5 combine (stand-in, not threshold decryption)
mldsa	pqz-ledger/src/sig.rs	12	42	pub struct SigKeys	ML-DSA-65 key pair
mldsa	pqz-ledger/src/sig.rs	25	55	pub fn sign	ML-DSA-65 sign
mldsa	pqz-ledger/src/sig.rs	31	61	pub fn verify	ML-DSA-65 verify
mldsa	pqz-ledger/src/ledger.rs	68	98	pub fn sign	SignedTx::sign: transaction signature
mldsa	pqz-eval/src/eapat.rs	57	87	pub fn sign_header	Block header signature
attacks	pqz-integrated-w46/src/bin/demo_scenarios.rs	679	709	fn attack	Demo: attacks A1..A7, each changes ONE thing
attacks	pqz-integrated-w46/src/bin/demo_scenarios.rs	671	701	fn drop_run_of	Demo: cloud removes the run that holds the matches
attacks	pqz-ledger/src/audit.rs	187	217	pub fn drop_block	Library attack: drop a block from the response
attacks	pqz-ledger/src/audit.rs	195	225	pub fn forge_shorter_epoch	Library attack: shorter epoch
attacks	pqz-ledger/src/attacks.rs	128	158	pub fn run_with	Library attack suite on the contract
attacks	pqz-attack-w38/src/main.rs	110	140	fn vcatch	Proof-level attack harness (tampered proofs)
attacks	pqz-attack-w38/src/p2r.rs	87	117	fn ver_x	Verifier used by the packed-format attacks
attack-a1	pqz-integrated-w46/src/bin/demo_scenarios.rs	688	718	"a1" => {	Demo scenario A1: cloud changes the result
attack-a1	pqz-integrated-w46/src/w35.rs	945	975	differs from the sum over the runs	The check that rejects A1a/A1b
attack-a2	pqz-integrated-w46/src/bin/demo_scenarios.rs	713	743	"a2" => {	Demo scenario A2: cloud hides a block that has matches
attack-a2	pqz-integrated-w46/src/w35.rs	918	948	outside the runs and has no Bloom opening	The check that rejects A2
attack-a3	pqz-integrated-w46/src/bin/demo_scenarios.rs	724	754	"a3" => {	Demo scenario A3: bad or missing Bloom opening
attack-a3	pqz-integrated-w46/src/w35.rs	937	967	do not show the query false	The check that rejects A3b
attack-a4	pqz-integrated-w46/src/bin/demo_scenarios.rs	773	803	"a4" => {	Demo scenario A4: stored record changed after anchoring
attack-a4	pqz-integrated-w46/src/w35.rs	855	885	rebuilt from the blocks differs	The check that rejects A4a
attack-a5	pqz-integrated-w46/src/bin/demo_scenarios.rs	808	838	"a5" => {	Demo scenario A5: authorization for another epoch / Omega
attack-a5	pqz-ledger/src/contract.rs	173	203	Reject::OmegaNotCanonical	The contract rule that rejects A5d
attack-a5	pqz-integrated-w46/src/lib.rs	666	696	pub fn ledger_read_gate	Gate that rejects A5c
attack-a6	pqz-integrated-w46/src/bin/demo_scenarios.rs	839	869	"a6" => {	Demo scenario A6: authorization for another query
attack-a6	pqz-plonky3-w46/src/request.rs	41	71	pub fn check_ctx	The link check that rejects A6a
attack-a6	pqz-ledger/src/contract.rs	176	206	Reject::PredicateMismatch	The contract rule that rejects A6b
attack-a7	pqz-integrated-w46/src/bin/demo_scenarios.rs	856	886	"a7" => {	Demo scenario A7: forged ledger anchor
attack-a7	pqz-ledger/src/ledger.rs	455	485	pub fn verify_read	Rejects A7a to A7c
attack-a7	pqz-ledger/src/contract.rs	170	200	Reject::OmegaRecompute	Rejects A7d
