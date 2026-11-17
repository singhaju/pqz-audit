import csv, os
D = "fixtures"
NOTE = "FIXTURE: hand-made test row, not measured"
H3 = "exp,series,n,mb,sigma,layout,predicate,agg,approach,run,warmup,time_ns,n_blocks,n_retained_blocks,n_cand,n_sel,bytes,fixture_note".split(",")

def exp3c(name, he_scattered_flat):
    rows = []
    for layout in ("clustered", "scattered"):
        for n in (10000, 50000, 100000):
            nsel = n // 100
            for approach in ("plain_agg", "full_he", "pqz"):
                for run in range(4):
                    warm = 1 if run == 0 else 0
                    jitter = 1.0 + 0.01 * run
                    if approach == "plain_agg":
                        t = n * 10 * jitter
                    elif approach == "full_he":
                        t = (5e6 if (he_scattered_flat and layout == "scattered") else n * 1000) * jitter
                    else:
                        t = nsel * 5000 * jitter
                    rows.append(dict(exp="exp3c", series="n_sweep", n=n, mb=500, sigma=nsel,
                                     layout=layout, predicate="P1", agg="SUM", approach=approach,
                                     run=run, warmup=warm, time_ns=int(t), n_blocks=n // 500,
                                     n_retained_blocks=2, n_cand=nsel, n_sel=nsel, bytes=0,
                                     fixture_note=NOTE))
    with open(os.path.join(D, name), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=H3); w.writeheader(); w.writerows(rows)

exp3c("FIXTURE_exp3c_pass.csv", False)
exp3c("FIXTURE_exp3c_he_flat.csv", True)

HA = "experiment,rel,n_records,block_size,config,g,run,warmup,prove_s,verify_s,total_verify_s,proof_bytes,fixture_note".split(",")
def abl(name, bad_g):
    rows = []
    for g in (1, 4, 16, 64):
        for config in ("batched", "per_block"):
            for run in range(4):
                warm = 1 if run == 0 else 0
                base = 0.1 * g
                if config == "batched":
                    t, v, b = base * 0.5, 0.002, 70000
                else:
                    t = base * (0.5 if g == 1 else 1.5)
                    if g == bad_g:
                        t = base * 0.3
                    v, b = 0.002 * g, 70000 * g
                rows.append(dict(experiment="ablation", rel="rc", n_records=g * 500, block_size=500,
                                 config=config, g=g, run=run, warmup=warm,
                                 prove_s=round(t * (1 + 0.01 * run), 6), verify_s=v,
                                 total_verify_s=v, proof_bytes=b, fixture_note=NOTE))
    with open(os.path.join(D, name), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=HA); w.writeheader(); w.writerows(rows)

abl("FIXTURE_ablation_pass.csv", None)
abl("FIXTURE_ablation_fail_g16.csv", 16)
open(os.path.join(D, "README-FIXTURE.txt"), "w").write(
"FIXTURES: hand-made files that only exercise the --exp3c and --ablation code paths of\n"
"hypotheses.py. The numbers are made up by a formula (see make_fixtures.py). They are NOT results.\n"
"Never cite them, never copy them to a results folder. Outputs of test runs go to fixtures/out/.\n"
"FIXTURE_exp3c_pass.csv     : full_he linear in N, pqz follows n_sel (expected: HE slope 1.0)\n"
"FIXTURE_exp3c_he_flat.csv  : scattered full_he flat in N (expected: HE component REFUTED)\n"
"FIXTURE_ablation_pass.csv  : per_block > batched for G>1 (G=1 equal by construction)\n"
"FIXTURE_ablation_fail_g16.csv : per_block < batched at G=16 (expected: REFUTED)\n")

# exp3-style fixture with COUNT (flat) and SUM (linear in n_sel) so that the full H3 status path can be exercised
rows = []
for agg in ("COUNT", "SUM"):
    for nsel in (10000, 50000, 100000):
        for approach in ("pqz", "full_he", "plain_agg"):
            for run in range(4):
                warm = 1 if run == 0 else 0
                if approach == "pqz":
                    t = 2e6 if agg == "COUNT" else nsel * 5000
                elif approach == "full_he":
                    t = 1e9
                else:
                    t = nsel * 10
                rows.append(dict(exp="exp3b", series="agg", n=1000000, mb=500, sigma=nsel // 10000,
                                 layout="clustered", predicate="P1", agg=agg, approach=approach,
                                 run=run, warmup=warm, time_ns=int(t * (1 + 0.01 * run)),
                                 n_blocks=2000, n_retained_blocks=2, n_cand=nsel, n_sel=nsel, bytes=0,
                                 fixture_note=NOTE))
with open(os.path.join(D, "FIXTURE_exp3_count_sum.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=H3); w.writeheader(); w.writerows(rows)
open(os.path.join(D, "README-FIXTURE.txt"), "a").write(
"FIXTURE_exp3_count_sum.csv : COUNT flat, SUM linear in n_sel (used as --exp3 to exercise the H3 status path)\n")
