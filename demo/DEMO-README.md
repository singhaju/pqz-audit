# PQZ-Audit live demo

Use case: hospital EHR access-log audit (insider data theft). Audit question: how many EXPORT_RECORDS actions in this
epoch, and how many patient records in total? (COUNT and SUM(b) where a = 7.)

## Run (from the `PQZ-Audit-code` folder; any other folder also works)
```
bash demo/demo.sh                    # TALK mode (about 3 min): intro, 8 phase panels (ENTER after each), then a menu
bash demo/demo.sh --no-pause         # talk mode without pauses: intro, phases, attack A2, then exit (no menu)
bash demo/demo.sh --full             # the long view: every table of S1, ENTER pauses, then one attack from a menu
bash demo/demo.sh --scenario a2      # one scenario, full view, no menu: s1 a1 a2 a3 a4 a5 a6 a7 search
bash demo/demo.sh --all-attacks      # A1..A7, one results table
bash demo/demo.sh --n 2000           # smaller log (default N = 10000, as on slide 27)
bash demo/show.sh list               # code browser menu (VS Code at file:line); add --term for bat in the terminal
```
Talk-mode menu after the phases: [1] attack A2 (Enter), [2] other attacks a1..a7 (table in plain words: what the
cheater does, what catches it), [3] predicate examples (Q1..Q5, search layer only, no proof; hits, blocks opened of 20,
plaintext check), [4] all attacks in one table, [5] your own query (action, staff, department, patients; search layer;
`demo_scenarios --scenario custom --q a=7,d=417,bmin=101`), [q] quit. Each attack screen starts with a card: what the
cheater does, why, what should catch it. After each choice the menu returns.
First run builds once (`cargo build --release --locked --bin demo_scenarios`, with a spinner). Needs cargo, python3 with `rich`.
Saved output in case the live run fails: `demo/fallback/*.txt` (plain) and `*.ansi.txt` (colour; view with `cat`):
`talk-nopause`, `talk-menu` (scripted: A2, a5, predicates, all attacks; older layout), `s1`, `a1`..`a7`, `search`, `all-attacks`,
`attack-list`, `custom-a7-staff417`, `custom-view-b50`.

## What is real and what is simulated
- Real: all numbers, hashes, proof sizes, ACCEPT/REJECT and error texts come from the library code run by
  `pqz-integrated-w46/src/bin/demo_scenarios.rs` (JSON Lines). `demo.py` only draws them. Nothing is hard-coded.
- Real: AES-256-GCM, keyed search tags, Bloom filters with Merkle openings, R_RC / R_Auth / R_Exec STARK proofs and their verifiers,
  ML-DSA-65 signatures, BFV homomorphic additions, the requester checks.
- Simulated: the blockchain is an in-process simulation (4 validators, quorum 3, no network, no real consensus latency).
- STARK proofs are plain mode, not zero-knowledge.
- The R_Auth policy leaf and scope are fixed synthetic values (`auth_stage`), not a real hospital policy.
- HE: ciphertexts come from a pool of 1024 pre-encrypted values; value b uses (b mod 1024). The encrypted COUNT is exact; the encrypted
  SUM is the sum of (b mod 1024). The exact SUM(b) comes from the proved result.
- Threshold recovery: only a Shamir 3-of-5 stand-in exists (reconstruct hands over the key; not a threshold decryption).
- Timings: this laptop, one run, not a paper number. The log is 10,000 records by default (`--n 2000` for a shorter screen), blocks of 500, chunk 2; the insider burst sits in one block.

## Scenarios (what each shows)
- S1: phases 1 (init), 2 (plain log, mapping table), 3a (ciphertext and tags), 3b (blocks, R_RC proofs, AA check), 4 (anchor: A_e, Gamma, Omega,
  ledger block height, 3 of 4 votes, light-client read), 5 (R_Auth), 6 (pruning, R_Exec, HE), 7 (requester ACCEPT, result, MATCH with the plaintext).
- A1 cloud changes the result: claim +1 (count, sum), and a consistent edit of the run statement.
- A2 cloud hides a block that has matches: the honest opening function refuses; dropping the run is rejected (no Bloom opening).
- A3 bad or missing Bloom opening: foreign openings, genuine openings that show 1 bits, flipped word, missing openings.
- A4 stored record changed after anchoring: all data rebuilt from the edited record; rejected against the anchored R_e; also edited proofs under the honest block list.
- A5 authorization for another epoch / Omega: stale Omega_0 (requester link check, ledger gate, contract `omega_not_canonical_state`).
  An information step shows that re-proved runs alone are internally consistent, which is why the ledger gate exists (not counted).
- A6 authorization for another query: different d_Q (requester link check) and a Consume with another predicate hash (contract `predicate_hash_mismatch`).
- A7 forged or tampered anchor: edited block header, QC with too few votes, edited State[e] entry (the library returns only `false`), forged Anchor tx (`omega_recompute_mismatch`).
- search: compound predicates (and / or, equality and range tags) with bps_eval / rps_eval. Search only, no proof.

## What was not done, and why
- No attack was dropped: A1 to A7 all run through public functions. Every attack runs the honest setup and changes ONE thing
  (A5/A6 and A7 also change a ledger transaction or the ledger state, each in its own check). Attacks are listed as REJECTED only if every counted check returned an error.
- A second equality predicate cannot be proved end to end: the R_Exec predicate is fixed at log build time (`v_of`: THETA iff a = X), and
  `prove_runs` / `verify_requester35_fmt` take no predicate. So compound predicates are shown at the search layer only (scenario `search`), labelled as such.
- A7c: `verify_read` returns a bool, so no error text exists; the demo says so.

## Files added (nothing existing was changed)
`pqz-integrated-w46/src/bin/demo_scenarios.rs`, `demo/demo.py`, `demo/demo.sh`, `demo/show.sh`, `demo/CODE-MAP.md`, `demo/DEMO-README.md`, `demo/fallback/`.
`demo/CODE-MAP.md` and `demo/show.sh` hold the same table; `bash demo/show.sh check` re-checks every file:line.
