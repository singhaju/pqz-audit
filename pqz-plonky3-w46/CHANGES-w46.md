# CHANGES-w46 (laptop only, 2026-11-17)
Copy of pqz-plonky3-w39zk (src, tests, examples, Cargo.*, *.md; no target/, no results/), package renamed pqz-plonky3-w46. New: src/prun.rs, tests/w46_prun.rs, examples/prun_time.rs. No existing source file changed except src/lib.rs (+ pub mod prun).

## prun constraint table (degree <= 3; see module doc of src/prun.rs)
R1 Poseidon2 per row [3]; R2 row0 inputs = s_in (+word in rate), transitions inputs = out + word [1]; G0 row0 word = hdr_first, hdr=1 [1];
G1 hdr/va/vb/ma/mb boolean [2], hdr+va+pad=1 [1], vb(1-va)=0, ma(1-va)=0, mb(1-vb)=0 [2]; G2 header row w7=1, w2=block_size, rem=w2 [2];
G3 short row (va,!vb): rem=0 and half b = 0 [3]; G4 rem*rinv=1-zr, zr*rem=0 [2]; G5 next row header iff zr (non-pad) [2], va'(rem'-rem+1+vb')=0 [2];
E3 bits of d boolean [2], va/vb*(sum 2^k bit - d)=0 [3] (no bits of v); E4 cnt/sum from 0 inclusive of row 0 [3]; E5 idx/last/seen [2];
E6 at last: out[0..12]=s_out, cnt=count, sum=sum, zr=1 [2]. Trace: sequential (as run.rs); build_trace_par + prove_run_bytes_par additive.
zk module pads every trace to >= 512 rows (fast1 hiding budget, as rel.rs).

## Soundness dependency
v < 2^32 and b < 2^20 are NOT checked here (P2r); the packed chunk proofs check them and bind to the run through s_in / s_out = anchored chunk-end states.
Likewise the record grammar inside a block (ids / seq) is the chunk proofs job. Public sum is a field sum (integer sum only while n_records*2^20 < p).
Documented by tests: v = 2^32+5 and v = p-1 (m=0 witness) are ACCEPTED by prun alone and REJECTED by the pchunk proof. b = 2^20 / 2^40+3 range rejection is covered by existing tests/w38_pchunk.rs range_check_rejects_v_2_32_and_b_2_20.
ctx is native-only: a different ctx is accepted by the AIR (asserted, as run.rs).

## Tests (tests/w46_prun.rs, 13 tests x {plain, zk} = 26, all pass)
honest_whole_stream_matches_pair (digest and count/sum equal pair.rs; blocks 100,7,1,2,5,99,64; theta 1, 2^31, 2^32-1); honest_subruns_link_to_chunk_states (b 100,7,1,2,3,5,500; n_blocks 1,2,4,9; s_out == chunk-end state; partitions sum to whole);
rejects_wrong_statements (count+-1, sum+1, theta changed, s_in[0], s_in[9], s_out[0,3,8,11] incl. capacity, hdr_first[0,3], block_size+1, n_blocks+-1: each both as honest proof under wrong statement and prover+verifier on the wrong statement, plain kinds and honest kinds);
rejects_tampered_words (each of 8 slots +1 -> rejected under honest statement; with a recomputed statement the AIR ACCEPTS value changes inside the grammar but s_out differs from the anchored chunk state, asserted; swapped halves; non-zero empty half b, 4 slots; moved header incl. matching kinds; run starting mid-block; record word removed incl. matching kinds);
v_2_32_accepted_by_prun_rejected_by_chunk_range; prun_range_wrap_false_negative; bytes_api_par_trace_and_cross_pcs (plain proof bytes fail under zk and vice versa); par_trace_equals_seq_trace;
power_of_two_unpadded_trace (b=14, 128 / 512 rows, no pad; count+-1, sum+1 rejected); rejects_short_row_in_middle; rejects_extra_record_rows_and_header_relabelled;
rejects_early_pad_and_last_selector_tampering (seen edits, last=0, last=1 twice, edited traces); rejects_count_selector_tampering (count a header, skip a match, double count, mb on a header).
No extra test was ACCEPTED when it should be rejected. Two of my own test bugs were fixed (not weakened): v=p-1 needs a hand-edited m=0 witness; the header-lookalike word cannot be honestly parsed.
Whole suite (cargo test --release): 119 pass / 0 fail before the 12 extra tests; w46_prun alone now 26. Total 131 (suite not re-run in full after adding the extra tests; only the test file and a doc comment changed).

## Mutation check (each mutant reverted; src/prun.rs restored, byte-identical)
a) removed E6 s_out line  -> FAILED: {plain,zk}_rejects_wrong_statements, rejects_tampered_words (4 tests)
b) removed G0 hdr_first line -> FAILED: {plain,zk}_rejects_wrong_statements (hdr_first cases)
c) removed G5 next-header rule -> FAILED: {plain,zk}_rejects_tampered_words (moved header / removed record)
No mutant survived. Mutants a-c were run before the 12 extra tests were added.

## Timing smoke (LAPTOP SMOKE, informational; n=1e5, block 500, fast1, whole stream, plain)
old run.rs: 131072 rows, width 333; 22 threads prove_s 0.671 (includes trace), 549221 B; 1 thread 3.198 s, 553445 B.
prun: 65536 rows, width 334; 22 threads trace 0.166 s + prove 0.198 s, 525909 B; 1 thread trace 0.224 + prove 1.304 s, 525621 B. (par trace: no gain at 1 thread, 0.159+0.192 at 22.)
Not a benchmark: single run, laptop. old prove_s includes its trace, prun lists them apart.
