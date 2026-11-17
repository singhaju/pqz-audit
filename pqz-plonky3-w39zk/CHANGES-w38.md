# w38 stage 2: P2 "two records per absorbed word" (2026-11-16, laptop)

Copy of pqz-plonky3-w36 (no target/). Package pqz-plonky3-w38, lib pqz_plonky3_w38. New: src/pair.rs, src/bin/pchild_p2.rs, tests/w38_pair.rs. Old modes untouched.

## Format
Header word unchanged (absorbed alone, slot 7 = 1). Records: [id_a,v_a,b_a,tag_a,id_b,v_b,b_b,tag_b]. Odd m_g: last word's half b is zero, not counted.
Rows per block = 1 + ceil(m_g/2). Columns: Poseidon2 + word 8 + ma, mb, cnt, sum, idx, inv, last, seen, hdr, va, vb, rem, zr, rinv + 32 bits d per half (+32 bits v per half in P2).
Width 327 (w36) -> 398 (P2) / 334 (P2r). Height halves (131072 -> 65536 at N=1e5).
AIR: hdr+va+pad=1; vb<=va; header row rem=m_g=public B; record row rem'=rem-1-vb'; next row is header iff rem=0; short row (va, not vb) needs rem=0 and half b zero; last real row rem=0; first row header. Degree <= 3.
P2r drops the v bits (no v < 2^32 check in Exec).

## Tests (cargo test, x86-64-v3)
Old suite of the copy: 82/82 pass. New w38_pair: 13/13 pass (honest P2/P2r for N/blocks 1000/100, 700/7, 990/99, 10/1, 20/2, 30/3, 35/5, 64/64, 101/101, theta 1 and 2^32-1; dimensions; parallel trace = sequential; tamper suite; formats do not cross-verify; v range check; non-canonical structure). Total 95.
Rejected: wrong count, sum, theta, ctx, block size, n_blocks; other stream digest; changed v/b/tag/id in half a or b; swapped halves; swapped words; header changes; moved header; non-zero padded half; empty half mid-block; unequal m_g (102/98) with recomputed digest.
Mutation checks: dropping the empty-half-zero rule, the next-header rule, or short*rem is caught. Dropping hdr*(w2-B) is NOT caught by any test (m_g then bound only by the digest and the next-header rule).

## Timing (1 thread, taskset cpu 1, fast1, trace=seq, block 100, 1 warm-up + 10 timed, interleaved; r = w36/this)
| N | fmt | height x width | trace+prove s med [min-max] | verify ms | proof bytes | r |
|---|---|---|---|---|---|---|
| 1e4 | w36 | 16384x327 | 0.325 [0.323-0.332] | 2.50 | 479125 | 1.00 |
| 1e4 | P2 | 8192x398 | 0.193 [0.191-0.194] | 2.66 | 527013 | 1.68 |
| 1e4 | P2r | 8192x334 | 0.165 [0.164-0.168] | 2.33 | 458885 | 1.97 |
| 1e5 | w36 | 131072x327 | 2.929 [2.871-2.959] | 2.87 | 541893 | 1.00 |
| 1e5 | P2 | 65536x398 | 1.664 [1.640-1.698] | 3.02 | 591253 | 1.76 |
| 1e5 | P2r | 65536x334 | 1.420 [1.402-1.453] | 2.77 | 525205 | 2.06 |
All threads, 1e5, trace=par, 3 timed: w36 0.543 s, P2 0.290 s (1.87x), P2r 0.258 s (2.11x).
Count/sum identical across formats (1e5: 50172 / 26372973748). Gate (>= 1.4x at 1e5, 1 core): PASS.
Logs and raw results: bench/w38-exp4/logs/stage2-*, results/s2-*.json.

## Not done / concerns
- Chunk/RC AIR not ported. P2r soundness depends on an unbuilt chunk-side v < 2^32 check: P2r Exec accepts v = 2^32+5 as a match (tested).
- The 34-attack suite was not run on the new format.
- AIR does not enforce g/seq_start/e/pid continuity; the digest and the AA do. b is not range-checked (as in MODE 0).
- Proof grows 9% (P2) at the same security settings; verify time unchanged.
