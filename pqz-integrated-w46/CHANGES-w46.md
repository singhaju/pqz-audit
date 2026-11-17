# CHANGES w46 (integrated): P2r packed format in Exp 7 (w35) and Exp 6 (w34 whole)

Default `--fmt old` is unchanged (old signatures kept; `*_fmt` variants added). Laptop only, no cloud.

## Flags
- `w35 ... --fmt old|p2r` (child arg `fmt=`), CSV column `fmt` (last column).
- `w34 ... --fmt old|p2r`, same column. p2r supports only `--exec-stream whole`; `retained` + p2r exits with code 2.

## Old check -> P2r check (all switches kept, same names)
| Check (switch) | Old | P2r |
|---|---|---|
| chunk proofs (`proofs`) | src/w35.rs:559 `chunk::plain::verify_chunk` | src/w35.rs:560 `pchunk::plain::verify_chunk` (iv-off case: 550 / 554 `verify_chunk_with`) |
| statement meta (`meta`) | w35.rs:493,514 total_words = g*(B+1) | same lines, total_words = g*rows_per_block |
| IV of chunk 0 (`iv`) | w35.rs:535 `iv_state(total)` | same line, packed total |
| chunk links (`links`) | w35.rs:528 | unchanged |
| alpha / beta (`d1b_alpha`) | w35.rs:580 `alphas_of/betas_of` | w35.rs:581 `pchunk::alpha_of/beta_of` |
| acc (`d1b_acc`) | w35.rs:593 `acc_native` | w35.rs:594 `pchunk::acc_native_p` |
| tag/hdr lists (`d1c_hdr`, tag slots) | w35.rs:573 | same AA lists (layout = packed lists) |
| sigma, summaries | w35.rs:603, 612 | unchanged |
| requester IV of first run | w35.rs:885 `iv_state(total)` (860) | packed total words |
| run proofs | w35.rs:985 `run::plain::verify_run` | w35.rs:986 `prun::plain::verify_run` |
| w34 stream link | plonky3 request.rs:81 `check_stream_link`, bundle :96 | plonky3 prequest.rs:14 `check_stream_link_p`, bundle :52 `native_bundle_checks_p` (link + `check_sealed` + C_Q + scope); lib.rs `requester_native_checks_p` |
| w34 gates | lib.rs `gates` | lib.rs:988 `gates_p2r` (packed reference chain digests, all-blocks, link) |

## Tests (cargo test --release, all pass; smoke/test-all-2.log)
Old suite 52 (w34 20, w35_attacks 16, w35_bloom 5, w35_honest 9, w36_s3_openings 2). New 34:
- tests/w46_p2r.rs 13: e2e N=5000/10000, default fmt old, honest c=1/4/16 both layouts, empty and all-retained, gap_merge, tampered chunk proof bytes, statement changed after proving, wrong sigma, run statement count/sum/hdr/proof/theta/n_blocks/ctx tampered, old-words run does not verify as P2r, format mixing, v>=2^32 and b>=2^20 not provable by the packed chunk, pack_raw consistency.
- tests/w46_p2r_attacks.rs 16 (p2r_a1..a16): every old attack A1-A16 against P2r.
- tests/w46_w34_p2r.rs 5: whole honest both layouts, run_one old==p2r result, retained+p2r code 2, foreign Exec digest rejected by the link, tampered exec stmt (n_blocks, digest, theta, count, proof bytes) and RC lists/hdr/digest/proof bytes rejected.

## Smoke (laptop, N=20000, P3, fast defaults of the library; smoke/)
w35 (chunk 4, gap 1) total_s old/p2r: clustered 1.044/0.939, scattered 1.399/1.067; result identical. rc proof bytes 1370098 / 1671698 (clustered), rc rows 20480 / 10240.
w34 whole total_s old/p2r: clustered 1.081/0.828, scattered 1.086/0.814 (p3b 0.305/0.204, p6b 0.354/0.180).

## Not done / concerns
- w34 `retained` has no P2r arm (by order).
- PRUN-DONE (bench/pqz-plonky3-w46) was not present when the last test run was made; rerun the suite once it appears.
- P2r Exec and runs have no v range check by design; soundness of v comes from the packed chunk proofs (tested: p2r v>=2^32 cannot be proven).
