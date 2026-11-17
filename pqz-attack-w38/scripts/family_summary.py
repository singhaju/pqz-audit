#!/usr/bin/env python3
"""Per-family summary of results/attack-w33/summary.csv. The family grouping is ours (6 groups); the 42 = exec 14 + rc 11 + auth 17."""
import csv, sys, collections
d = sys.argv[1] if len(sys.argv) > 1 else "results/attack-w33"
FAM = {}
for a in ["changed_record_word", "dropped_record", "duplicated_record", "reordered_records", "changed_block_header"]:
    FAM[a] = "F1 stream tampering"
for a in ["wrong_claimed_count", "wrong_claimed_sum", "wrong_digest", "other_theta", "other_ctx"]:
    FAM[a] = "F2 false public statement (Exec/RC)"
for a in ["other_workload_proof", "auth_other_request_proof", "mix_exec_of_other_request", "mix_auth_of_other_request"]:
    FAM[a] = "F3 proof of another workload or request and mix-and-match"
for a in ["flipped_proof_byte", "auth_flipped_proof_byte"]:
    FAM[a] = "F4 flipped proof byte"
for a in ["weaker_options_below_floor", "weaker_options_above_floor", "auth_weaker_options_below_floor"]:
    FAM[a] = "F5 weaker FRI options"
for a in ["stream_mismatch", "inverted_scope"]:
    FAM[a] = "F7 native checks (w34: stream link, scope order)"
for a in ["packed_v_ge_2_32", "packed_b_ge_2_20", "packed_nonzero_empty_half", "packed_mg_ne_B", "packed_exec_A_chunks_B", "packed_swap_halves"]:
    FAM[a] = "F8 packed format (w38)"
FAM["changed_record_word_pid_epoch_seq"] = "F1 stream tampering"
rows = list(csv.DictReader(open(f"{d}/summary.csv")))
agg = collections.OrderedDict()
names = collections.defaultdict(set)
for r in rows:
    a, form = r["attack"], r["form"]
    if a == "honest":
        continue
    fam = FAM.get(a, "F6 Auth statement / witness (Auth)")  # checks on; the checks-off rows are in summary_nochecks.csv
    rel = {"exec_single": "exec", "rc_single": "rc", "bundle": "bundle"}.get(form, "auth" if a.startswith("auth_") else ("mix" if a.startswith("mix_") else "exec-in-pair"))
    key = (form, fam)
    e = agg.setdefault(key, [0, 0, 0, 0, 0, 0, 0])
    e[0] += 1; e[1] += int(r["trials"]); e[2] += int(r["rejected"]); e[3] += int(r["accepted"]); e[4] += int(r["prover_refused"]); e[5] += int(r["harness_error"]); e[6] += int(r.get("untested", 0))
out = ["form,family,attack_types,trials,rejected,accepted,prover_refused,harness_error,untested"]
for (form, fam), e in sorted(agg.items()):
    out.append(f"{form},{fam},{e[0]},{e[1]},{e[2]},{e[3]},{e[4]},{e[5]},{e[6]}")
open(f"{d}/summary_by_family.csv", "w").write("\n".join(out) + "\n")
print("\n".join(out))
tot = [sum(e[i] for e in agg.values()) for i in range(7)]
print("TOTAL attack types(form-level)=%d trials=%d rejected=%d accepted=%d refused=%d harness_error=%d untested=%d" % tuple(tot))
hon = [(r["form"], r["trials"], r["accepted"], r["rejected"]) for r in rows if r["attack"] == "honest"]
print("honest rows (form, rows, accepted, rejected):", hon)

# w34: the two new attacks with the native checks switched OFF (separate files, not part of the totals above)
import os
if os.path.exists(f"{d}/summary_nochecks.csv"):
    print("--- native checks OFF (test-only switch) ---")
    for r in csv.DictReader(open(f"{d}/summary_nochecks.csv")):
        print(r["attack"], r["form"], "trials", r["trials"], "accepted", r["accepted"], "rejected", r["rejected"], "refused", r["prover_refused"], "harness_error", r["harness_error"])
