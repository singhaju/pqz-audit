# CHANGES w46 (exp9 PQZ child)
Copy of pqz-exp9-w45. Cargo: `pqz_int` -> pqz-integrated-w46, `pqz_p3` -> pqz-plonky3-w46; `pqz_p3b` (w39zk) removed (one dependency; the p2r module now uses pqz_p3 `pair`).

## CLI (child)
`child whole|cover n= layout= preset= zk=0|1 [vreps= chunk= gap= run=] [fmt=old|p2r] [rcgate=0|1]`. Default fmt=old, rcgate=0. Row column `fmt` now also in cover rows; whole p2r + rcgate=1 adds `rcgate, rcgate_ok, rcgate_bytes, rcgate_prove_s`. `exp9_run_one.sh` (ZKSQL side) untouched.

## WHOLE p2r
- Prepare time (in `ingest_stmt_ledger_s`, not per query): packed R_RC statement = ONE pchunk chunk with all blocks (`pchunk::plain::honest_publics`).
- Per-query requester check: theta + `prequest::native_bundle_checks_p` (= `check_stream_link_p` Exec digest vs chunk chain, `check_sealed` lists, C_Q link, scope). The w45 note "digest link not applied" no longer holds for p2r.
- `rcgate=1` (untimed): proves and verifies the packed RC chunk once with library opts.
## COVER p2r
Restriction removed. Uses integrated-w46 P2r arm: `World35::prepare_fmt`, `aa_finalize_fmt`, `requester_native35_fmt`, `verify_requester35_fmt`; runs via `prun::plain|zk::honest_public`, `prove_run_bytes_par`, `verify_run_bytes`. Same timing columns and requester checks. (zk runs are padded to >= 512 rows by prun::zk.)

## Laptop matrix (preset fast1, vreps=3; smoke/matrix.rows, 32 rows, 0 failures)
whole/cover x old/p2r x zk 0/1 x n 10000/20000 x both layouts: all exit 0, result == reference, (count,sum) identical across fmts (n=10000: 100/78435187 clustered, 100/79035157 scattered; n=20000: 200/152082824, 200/157851532).
prove_s old -> p2r (n=20000 clustered): whole zk0 0.198 -> 0.100, whole zk1 0.709 -> 0.381, cover zk0 0.040 -> 0.027, cover zk1 0.107 -> 0.064. bytes_requester whole zk0 620714 -> 607594; cover zk0 587738 -> 572922.
rcgate=1 (n=20000, zk0, fast1): rcgate_ok=1, rc chunk proof 194117 B (clustered) / 194949 B (scattered), prove_s 0.168 (smoke/rcgate.rows).

## Not done
- No cloud run. Final rerun of integrated tests pending PRUN-DONE (see integrated CHANGES).
