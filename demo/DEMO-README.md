# PQZ-Audit live demo

Use case: hospital EHR access-log audit (insider data theft by staff 417). Audit question: how many
EXPORT_RECORDS actions in this epoch, and how many patient records in total? (COUNT and SUM(patients) where action = 7;
in this log every export is part of staff 417's burst.)
Record fields on screen: action (code 1-7), patients (number of patient records touched), dept, staff. The Rust
program and its JSON use the short names a, b, c, d; `demo.py` only renames them for display.

## Run (from the `PQZ-Audit-code` folder; any other folder also works)
```
bash demo/demo.sh                    # TALK mode (about 3 min): ONE audit menu first; choose 1 for the 8 phase panels (ENTER after each)
bash demo/demo.sh --no-pause         # talk mode without pauses: intro, phases, attack A2, then exit (no menu)
bash demo/demo.sh --full             # the long view: every table of S1, ENTER pauses, then one attack from a menu
bash demo/demo.sh --scenario a2      # one scenario, full view, no menu: s1 a1 a2 a3 a4 a5 a6 a7 search
bash demo/demo.sh --all-attacks      # A1..A7, one results table
bash demo/demo.sh --n 2000           # smaller log (default N = 10000, as on slide 27)
bash demo/show.sh list               # code browser menu (VS Code at file:line); add --term for bat in the terminal
```
Talk mode has ONE audit menu on one page, shown FIRST and redrawn after every answer. Items 1-10 are the
10 normal cases; 11-15 are extras:
[1] the insider question (proved, full Phases 1-7); [2]-[5] follow-ups on the insider (search layer, no proof);
[6]-[8] normal activity for contrast (search layer); [9]-[10] other proved audits; [11] any action code you choose
(proved); [12]-[14] attacks; [15] your own query; [q] quit. Enter = question 1.
Every question goes phase by phase like question 1: 2-8 and 15 show Phases 1-4 (the same log as question 1) and then
Phases 5-7 of the search query (no proof on that path, said on screen); 9-11 rebuild and prove Phases 1-7 for action = x
(11 then offers attack A1); 12-13 show Phases 1-7 of the honest audit with red panels where the attacker acts and where
each check rejects; 14 shows one table of attacks x phases (ATTACK / REJECT). Questions 2-8 then show "Auditor asks:" and "What
this shows:"; question 15 first prints the query syntax and examples. Proved and attack panels end with the verdict.
First run builds once (`cargo build --release --locked --bin demo_scenarios`, with a spinner). Needs cargo, python3 with `rich`.
Saved output in case the live run fails: `demo/fallback/*.txt` (plain) and `*.ansi.txt` (colour; view with `cat`):
`talk-nopause`, `q01-story`, `q02-10-questions`, `q11-proved-print-then-a1`, `q12-attack-a2`, `q13-attacks-a1-a7`,
`q14-all-attacks-matrix`, `q15-custom-export-psychiatry`, and the raw scenario runs `s1`, `a1`..`a7`, `all-attacks`.

Menu answers (N = 10,000, this laptop; the program prints what each run returns):

| # | Question | Query | Answer | Blocks opened |
|---|---|---|---|---|
| 1 | the main question (proved) | proved: action = 7 | ACCEPT, COUNT 20, SUM 6,324, MATCH | 2 of 20 |
| 2 | big exports, more than 100 patients each | action = 7, patients >= 101 | 14 records, 6,213 patients | 1 of 20 |
| 3 | small exports, 100 patients or fewer | action = 7, patients <= 100 | 6 records, 111 patients | 1 of 20 |
| 4 | what else did the insider, staff 417, do | staff = 417 | 27 records, 6,329 patients | 1 of 20 |
| 5 | did the insider export Psychiatry records | action = 7, dept = 500 | 0 records | 0 of 20 |
| 6 | an ordinary staff member | staff = 123 | 15 records, 135 patients | 9 of 20 |
| 7 | who opened Psychiatry records | dept = 500 | 3 records, 3 patients | 1 of 20 |
| 8 | chart views touching 50+ patients | action = 1, patients >= 50 | 281 records, 18,162 patients | 20 of 20 |
| 9 | prints (proved) | proved: action = 3 | ACCEPT, COUNT 401, SUM 590, MATCH | 20 of 20 |
| 10 | logins (proved) | proved: action = 4 | ACCEPT, COUNT 1,152, SUM 0, MATCH | 20 of 20 |
| 11 | any action code you choose (proved) | proved: action = x | phases 1-7 again for x | depends on x |
| 12 | A2: the cloud hides a block with matches | attack a2 | REJECTED, 2 of 2 counted checks, in phase 6 and 7 | - |
| 13 | choose another attack | attack a1..a7 | each REJECTED; acts / rejected in phase: A1 6/7, A3 6/7, A4 3a/7, A5 5/5+7, A6 5/7, A7 4/4 | - |
| 14 | all seven attacks, attacks x phases table | all attacks | A1..A7 all rejected | - |
| 15 | your own query | action, staff, dept, patients | search layer, checked against the plain log | varies |

Questions 1-10 are the 10 normal cases; 11-15 are extras. Questions 2-8 and 15 are search layer only (no proof); every
one is checked against the same condition on the plain log (MATCH). Questions 1, 9, 10 and 11 are proved runs (phases 1-7).

## What is real and what is simulated
- Real: all numbers, hashes, proof sizes, ACCEPT/REJECT and error texts come from the library code run by
  `pqz-integrated-w46/src/bin/demo_scenarios.rs` (JSON Lines). `demo.py` only draws them. Nothing is hard-coded.
- Real: AES-256-GCM, keyed search tags, Bloom filters with Merkle openings, R_RC / R_Auth / R_Exec STARK proofs and their verifiers,
  ML-DSA-65 signatures, BFV homomorphic additions, the requester checks.
- Simulated: the blockchain is an in-process simulation (4 validators, quorum 3, no network, no real consensus latency).
- STARK proofs are plain mode, not zero-knowledge.
- The R_Auth policy leaf and scope are fixed synthetic values (`auth_stage`), not a real hospital policy.
- HE: ciphertexts come from a pool of 1024 pre-encrypted values; a value of patients p uses (p mod 1024). The encrypted COUNT is exact; the encrypted
  SUM is the sum of (patients mod 1024). The exact SUM(patients) comes from the proved result.
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

## Demo files
`pqz-integrated-w46/src/bin/demo_scenarios.rs`, `demo/demo.py`, `demo/demo.sh`, `demo/show.sh`, `demo/CODE-MAP.md`, `demo/DEMO-README.md`, `demo/fallback/`.
`demo/CODE-MAP.md` and `demo/show.sh` hold the same table; `bash demo/show.sh check` re-checks every file:line.
