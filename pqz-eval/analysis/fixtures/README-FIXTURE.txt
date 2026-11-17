FIXTURES: hand-made files that only exercise the --exp3c and --ablation code paths of
hypotheses.py. The numbers are made up by a formula (see make_fixtures.py). They are NOT results.
Never cite them, never copy them to a results folder. Outputs of test runs go to fixtures/out/.
FIXTURE_exp3c_pass.csv     : full_he linear in N, pqz follows n_sel (expected: HE slope 1.0)
FIXTURE_exp3c_he_flat.csv  : scattered full_he flat in N (expected: HE component REFUTED)
FIXTURE_ablation_pass.csv  : per_block > batched for G>1 (G=1 equal by construction)
FIXTURE_ablation_fail_g16.csv : per_block < batched at G=16 (expected: REFUTED)
FIXTURE_exp3_count_sum.csv : COUNT flat, SUM linear in n_sel (used as --exp3 to exercise the H3 status path)
