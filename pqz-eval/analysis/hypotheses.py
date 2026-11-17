"""Evaluate the section-1 hypotheses of journal2/EXPERIMENT-PLAN-main11.md."""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys

import common


PLAN_REFERENCE = "journal2/EXPERIMENT-PLAN-main11.md section 1"

HYPOTHESES = {
    "H1": {
        "name": "Query Scalability",
        "exp": "exp1",
        "statement": "record-level time follows N_Q, n_Q; only the G*T_BPS term follows N",
        "metric": "online query time = block summaries + exact evaluation + "
                  "result construction; no proof, no setup",
        "threshold": "fixed-n_Q series: slope of time vs N below 10% of the "
                     "1%-series slope",
        "threshold_kind": "PROPOSAL",
        "source": PLAN_REFERENCE,
    },
    "H2": {
        "name": "Private Predicate",
        "exp": "exp2",
        "statement": "PQZ-Audit beats Protected Full Scan only where blocks are "
                     "pruned; gap closes as eta_Q -> 1",
        "metric": "query time per approach, eta_Q = N_Q/N, layouts clustered and scattered",
        "threshold": "measured time vs N_Q*T_RPS + G*T_BPS has R^2 >= 0.95",
        "threshold_kind": "PROPOSAL",
        "source": PLAN_REFERENCE,
    },
    "H3": {
        "name": "Private Aggregation",
        "exp": "exp3",
        "statement": "COUNT flat in n_Q; SUM/AVG linear in n_Q; Full-Domain HE linear in N",
        "metric": "aggregation time; R_HE = 1 - T_PQZ/T_FullHE",
        "threshold": "slope check on log-log fit",
        "threshold_kind": "PROPOSAL; the plan writes no numeric tolerance",
        "source": PLAN_REFERENCE,
    },
    "H4": {
        "name": "Proof gen/verify",
        "exp": "exp4",
        "statement": "prove time grows with N_Q; verify per request constant",
        "metric": "prove time, verify time, proof size, peak prover RAM",
        "threshold": "verify time at q=200 within 10% of 200x single verify",
        "threshold_kind": "PROPOSAL",
        "source": PLAN_REFERENCE,
    },
    "H5": {
        "name": "Blockchain",
        "exp": "exp5",
        "statement": "on-chain bytes per epoch do not grow with N; governance ops constant",
        "metric": "tx latency, throughput, bytes per epoch",
        "threshold": "bytes per epoch constant within 5%",
        "threshold_kind": "PROPOSAL",
        "source": PLAN_REFERENCE,
    },
    "H6": {
        "name": "Ablation",
        "exp": "exp6",
        "statement": "each removal costs what its term predicts "
                     "(N_Q -> N; n_Q -> N; G -> N proofs)",
        "metric": "query, aggregation, proof time per configuration",
        "threshold": "relative overhead has the sign and order predicted",
        "threshold_kind": "PROPOSAL; qualitative",
        "source": PLAN_REFERENCE,
    },
    "H7": {
        "name": "Rejection checks",
        "exp": "rejection",
        "statement": "every attack is rejected",
        "metric": "accepted/rejected out of 1000 per attack",
        "threshold": "0 accepted",
        "threshold_kind": "PROPOSAL",
        "source": PLAN_REFERENCE,
    },
}

SLOPE_TOLERANCE = {
    "COUNT": 0.10,
    "SUM": 0.10,
    "AVG": 0.10,
    "HE_N": 0.10,   # Full-Domain HE log-log slope vs N must be within 0.10 of 1 (task, not the plan)
}

H4_VERIFY_TOLERANCE = 0.10    # plan: verify at q=200 within 10% of 200 x single verify
H4_Q_LARGE = 200
H5_BYTES_TOLERANCE = 0.05     # plan: bytes per epoch constant (max/min - 1 <= 5%)
H5_N_LOW, H5_N_HIGH = 10_000, 1_000_000
H7_TRIALS = 1000              # plan: out of 1000 per attack


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exp1", nargs="*", default=None)
    parser.add_argument("--exp2", nargs="*", default=None)
    parser.add_argument("--exp3", nargs="*", default=None)
    parser.add_argument("--exp3c", nargs="*", default=None,
                        help="H3 N sweep (exp3c.csv: exp3a columns, series n_sweep)")
    parser.add_argument("--exp4", default=None,
                        help="H4: pqz-proof raw.csv (q experiment rows)")
    parser.add_argument("--exp5", nargs="*", default=None,
                        help="H5: one or more exp5c_bytes_per_epoch.csv files")
    parser.add_argument("--reject", default=None, help="H7: reject-1000.txt")
    parser.add_argument("--reject-mutation", default=None,
                        help="H7: reject-mutation-200.txt (only its RESULT line is reported)")
    parser.add_argument("--ablation", default=None,
                        help="H6: ablation.csv of `proofbench ablation` (raw.csv style)")
    parser.add_argument("--out", default=None)
    parser.add_argument("--min-runs", type=int, default=3)
    return parser.parse_args()


def _load_many(paths, required, group_keys, min_runs):
    rows = []
    provisional = False
    for path in paths:
        loaded, meta = common.load_csv(
            path, required=required, min_runs=min_runs, group_keys=group_keys
        )
        rows.extend(loaded)
        provisional = provisional or meta["provisional"]
    return rows, provisional


def _is_fixture(paths):
    return any("fixture" in os.path.abspath(path).lower() for path in paths)


def _fixture_tag(paths):
    return " [FIXTURE INPUT: hand-made test file, not real data]" if _is_fixture(paths) else ""


def _fmt(value, spec=".4g"):
    return "n/a" if value is None else format(value, spec)


def _exp1_series_slopes(rows):
    stats = common.group_stats(rows, ("series", "n"))
    slopes = {}
    for series in sorted({key[0] for key in stats}):
        entries = sorted(
            ((key[1], value) for key, value in stats.items() if key[0] == series),
            key=lambda item: common.sort_key(item[0]),
        )
        xs = [n for n, _ in entries]
        ys = [common.to_ms(entry["median"]) for _, entry in entries]
        slopes[series] = common.loglog_fit(xs, ys)
    return slopes


def _exp2_points(rows):
    """One point per (layout, predicate, approach, sigma) group median, as in the pooled fit."""
    keys = ("layout", "predicate", "approach", "sigma")
    stats = common.group_stats(rows, keys)
    n_cand = common.group_stats(rows, keys, value="n_cand")
    n_blocks = common.group_stats(rows, keys, value="n_blocks")
    points = []
    for key, entry in stats.items():
        approach = key[2]
        if approach not in ("prot_full_scan", "pqz"):
            continue
        if key not in n_cand:
            continue
        g_value = 0.0 if approach == "prot_full_scan" else float(n_blocks[key]["median"])
        points.append({
            "layout": key[0], "predicate": key[1], "approach": approach, "sigma": key[3],
            "g": g_value, "nq": float(n_cand[key]["median"]), "time": entry["median"],
        })
    return points


def _fit_points(points):
    return common.least_squares_costs(
        [p["g"] for p in points], [p["nq"] for p in points], [p["time"] for p in points]
    )


def _exp2_fit(rows):
    return _fit_points(_exp2_points(rows))


def _exp2_per_predicate(rows):
    """EXPLORATORY (post hoc): the H2 cost model fitted to each predicate separately."""
    points = _exp2_points(rows)
    lines = [
        "EXPLORATORY per-predicate fit (post hoc, NOT a hypothesis test; status above is unchanged):",
        "  model t = G*T_BPS + N_Q*T_RPS, no intercept, fitted to each predicate alone on its "
        "group medians",
        "  (few points per fit: 2 parameters, so R^2 is a descriptive number only)",
        "  predicate  points  R^2      T_RPS (ns/record)  T_BPS (ns/block)",
    ]
    for predicate in sorted({p["predicate"] for p in points}, key=str):
        subset = [p for p in points if p["predicate"] == predicate]
        fit = _fit_points(subset)
        if fit["r2"] is None:
            lines.append(f"  {predicate!s:<10} {len(subset):<7} not identifiable")
        else:
            lines.append(
                f"  {predicate!s:<10} {fit['points']:<7} {fit['r2']:<8.4f} "
                f"{fit['t_rps_ns']:<18.4g} {fit['t_bps_ns']:.4g}"
                + ("  (negative: unphysical)" if fit["t_bps_ns"] < 0 else "")
            )
    return lines


def _exp3_slopes(rows):
    stats = common.group_stats(rows, ("agg", "approach", "n_sel"))
    slopes = {}
    for agg in sorted({key[0] for key in stats}):
        for approach in sorted({key[1] for key in stats if key[0] == agg}):
            entries = sorted(
                (
                    (key[2], value) for key, value in stats.items()
                    if key[0] == agg and key[1] == approach
                ),
                key=lambda item: common.sort_key(item[0]),
            )
            xs = [n_sel for n_sel, _ in entries]
            ys = [common.to_ms(entry["median"]) for _, entry in entries]
            slopes[(agg, approach)] = common.loglog_fit(xs, ys)
    return stats, slopes


def _exp3c_fits(rows):
    """Per (layout, approach): log-log slope of median time vs N and vs n_Q (= n_sel)."""
    rows = [row for row in rows if row.get("series") == "n_sweep"]
    if not rows:
        sys.exit("refusing exp3c input: no rows with series == n_sweep")
    keys = ("layout", "approach", "n")
    times = common.group_stats(rows, keys)
    n_q = common.group_stats(rows, keys, value="n_sel")
    fits = {}
    for layout in sorted({key[0] for key in times}, key=str):
        for approach in sorted({key[1] for key in times if key[0] == layout}, key=str):
            entries = sorted(
                (key[2], entry) for key, entry in times.items()
                if key[0] == layout and key[1] == approach
            )
            xs = [n for n, _ in entries]
            ys = [common.to_ms(entry["median"]) for _, entry in entries]
            qs = [n_q[(layout, approach, n)]["median"] for n, _ in entries]
            fits[(layout, approach)] = {
                "vs_n": common.loglog_fit(xs, ys),
                "vs_nq": common.loglog_fit(qs, ys),
                "points": len(entries),
            }
    return fits


def _status(provisional, enough, condition):
    if provisional or not enough:
        return "NOT-ENOUGH-DATA"
    if condition is None:
        return "NOT-ENOUGH-DATA"
    return "SUPPORTED" if condition else "REFUTED"


# ---------------------------------------------------------------- H4

def _h4(path, min_runs):
    rows, meta = common.load_csv(
        path,
        required=("experiment", "rel", "q", "mode", "run", "warmup", "total_verify_s"),
        min_runs=min_runs,
        group_keys=("experiment", "rel", "n_records", "depth", "q", "mode"),
    )
    q_rows = [row for row in rows if row.get("experiment") == "q"]
    if not q_rows:
        sys.exit(f"refusing {path}: no rows with experiment == q")
    stats = common.group_stats(q_rows, ("rel", "depth", "mode", "q"), value="total_verify_s")
    parts, lines = [], []
    conditions = []
    enough = True
    lines.append(
        f"verify time at q={H4_Q_LARGE} (total_verify_s median) against {H4_Q_LARGE} x single "
        "verify (q=1 median), per relation and mode:"
    )
    lines.append("  rel     mode      single(q=1) ms   q=200 ms   200 x single ms   ratio   |ratio-1|<=0.10")
    for rel, depth, mode in sorted({k[:3] for k in stats}, key=str):
        one = stats.get((rel, depth, mode, 1))
        big = stats.get((rel, depth, mode, H4_Q_LARGE))
        if one is None or big is None:
            enough = False
            lines.append(f"  {rel!s:<7} {mode!s:<9} missing q=1 or q={H4_Q_LARGE}")
            continue
        single_ms = one["median"] * 1e3
        big_ms = big["median"] * 1e3
        ratio = big["median"] / (H4_Q_LARGE * one["median"])
        ok = abs(ratio - 1.0) <= H4_VERIFY_TOLERANCE
        conditions.append(ok)
        parts.append(f"{rel}/{mode} ratio={ratio:.3f} ({'ok' if ok else 'outside'})")
        lines.append(
            f"  {rel!s:<7} {mode!s:<9} {single_ms:<16.4f} {big_ms:<10.3f} "
            f"{H4_Q_LARGE * single_ms:<17.3f} {ratio:<7.3f} {'yes' if ok else 'NO'}"
        )
    # information only: first half of the statement, no threshold is written for it
    scale = common.group_stats(
        [r for r in rows if r.get("experiment") == "scale" and r.get("rel") in ("rc", "exec")],
        ("rel", "n_records"), value="prove_s",
    )
    for rel in sorted({k[0] for k in scale}):
        entries = sorted((k[1], v["median"]) for k, v in scale.items() if k[0] == rel)
        fit = common.loglog_fit([n for n, _ in entries], [t for _, t in entries])
        lines.append(
            f"  info only (no threshold in the plan): {rel} prove_s median vs n_records "
            f"{', '.join(f'{n}:{t:.3f}s' for n, t in entries)}; log-log slope={_fmt(fit['slope'])}"
        )
    condition = all(conditions) if conditions and enough else None
    measured = (
        "; ".join(parts) + f" (ratio = verify(q={H4_Q_LARGE}) / ({H4_Q_LARGE} x verify(q=1)); "
        f"two-sided tolerance {H4_VERIFY_TOLERANCE:.0%})"
        if parts else "no (rel, mode) pair has both q=1 and q=200"
    )
    return measured, _status(meta["provisional"], enough and bool(conditions), condition), \
        meta["provisional"], lines


# ---------------------------------------------------------------- H5

def _read_rows(path):
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        sys.exit(f"refusing to continue: input CSV not found: {path}")
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        header = reader.fieldnames or []
        rows = [{k: common._to_number(v) for k, v in row.items()} for row in reader]
    return path, header, rows


def _env_status_line(path):
    env_path = os.path.join(os.path.dirname(path), "env.txt")
    if os.path.isfile(env_path):
        with open(env_path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.startswith("status:"):
                    return line.strip()
    return None


def _h5(paths):
    lines = [
        "on-chain bytes per epoch (column bytes_total of system=pqz, kind=timed rows) over N:",
        "  variant        N          timed rows   bytes_total (min..max)   per_record_baseline bytes_total (info)",
    ]
    parts, conditions = [], []
    enough = True
    provisional = False
    notes = []
    for path in paths:
        path, header, rows = _read_rows(path)
        missing = [c for c in ("system", "N", "kind", "bytes_total") if c not in header]
        if missing:
            sys.exit(f"refusing {path}: missing required columns {missing}; header is {header}")
        label = os.path.basename(os.path.dirname(path)) or path
        if "smoke" in path.lower():
            provisional = True
        status_line = _env_status_line(path)
        if status_line:
            notes.append(f"{label}: {status_line}")
        pqz = [r for r in rows if r["system"] == "pqz" and r["kind"] == "timed"]
        if not pqz:
            enough = False
            lines.append(f"  {label}: no system=pqz kind=timed rows")
            continue
        base = {}
        for r in rows:
            if (r["system"] == "per_record_baseline" and r["kind"] in ("timed", "formula")
                    and isinstance(r.get("bytes_total"), (int, float))):
                base.setdefault(r["N"], []).append((r["bytes_total"], r["kind"]))
        values = []
        for n in sorted({r["N"] for r in pqz}):
            vals = [r["bytes_total"] for r in pqz if r["N"] == n]
            values.extend(vals)
            b = base.get(n)
            lines.append(
                f"  {label:<14} {n:<10} {len(vals):<12} {min(vals)}..{max(vals)}"
                f"{'':<14}{(str(min(x for x, _ in b)) + ' (' + b[0][1] + ')') if b else 'n/a'}"
            )
        ns = {r["N"] for r in pqz}
        covers = min(ns) <= H5_N_LOW and max(ns) >= H5_N_HIGH
        spread = max(values) / min(values) - 1.0
        ok = spread <= H5_BYTES_TOLERANCE
        if not covers:
            enough = False
        conditions.append(ok)
        parts.append(
            f"{label}: pqz bytes_total {min(values)}..{max(values)} over N={min(ns)}..{max(ns)}, "
            f"max/min-1={spread:.4f} ({'ok' if ok else 'outside'})"
        )
        lines.append(f"  {label}: max/min-1 = {spread:.6f} (limit {H5_BYTES_TOLERANCE})")
    lines.extend(f"  note: {n}" for n in notes)
    measured = "; ".join(parts) if parts else "no usable rows"
    if notes:
        measured += " [" + " | ".join(notes) + "]"
    condition = all(conditions) if conditions and enough else None
    return measured, _status(provisional, enough and bool(conditions), condition), \
        provisional, lines


# ---------------------------------------------------------------- H7

_REJECT_ROW = re.compile(
    r"^(\S+)\s+(.+?)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/(\d+)\s*$"
)


def _h7(path, mutation_path):
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        sys.exit(f"refusing to continue: input file not found: {path}")
    section = None
    attacks = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if line.startswith("==") or line.startswith("--"):
                section = line
                continue
            match = _REJECT_ROW.match(line)
            if match is None:
                continue
            attacks.append({
                "section": section, "variant": match.group(1), "attack": match.group(2),
                "trials": int(match.group(3)), "rejected": int(match.group(4)),
                "accepted": int(match.group(5)),
                "control": (int(match.group(6)), int(match.group(7))),
            })
    if not attacks:
        sys.exit(f"refusing {path}: no attack table rows parsed")
    production = [a for a in attacks if a["section"] and "production" in a["section"]]
    used = production or attacks
    lines = [
        f"parsed {len(used)} attack variants from {os.path.basename(path)} "
        f"(section: {used[0]['section']})",
        "  variant                      trials  rejected  accepted  control_ok",
    ]
    for a in used:
        lines.append(
            f"  {a['variant']:<28} {a['trials']:<7} {a['rejected']:<9} {a['accepted']:<9} "
            f"{a['control'][0]}/{a['control'][1]}"
        )
    total = sum(a["trials"] for a in used)
    rejected = sum(a["rejected"] for a in used)
    accepted = sum(a["accepted"] for a in used)
    consistent = all(a["rejected"] + a["accepted"] == a["trials"] for a in used)
    full_trials = all(a["trials"] >= H7_TRIALS for a in used)
    controls_ok = all(a["control"][0] == a["control"][1] for a in used)
    mutation_result = None
    if mutation_path:
        mutation_path = os.path.abspath(mutation_path)
        if not os.path.isfile(mutation_path):
            sys.exit(f"refusing to continue: input file not found: {mutation_path}")
        with open(mutation_path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.startswith("RESULT:"):
                    mutation_result = line.strip()
        lines.append(f"mutation file {os.path.basename(mutation_path)}: "
                     f"{mutation_result or 'no RESULT line found'}")
    measured = (
        f"{len(used)} attack variants, {total} trials, {rejected} rejected, {accepted} accepted; "
        f"all controls passed: {'yes' if controls_ok else 'NO'}; "
        f"mutation file {mutation_result or 'not given'}"
    )
    provisional = "smoke" in path.lower()
    enough = consistent and full_trials
    condition = accepted == 0 if enough else None
    return measured, _status(provisional, enough, condition), provisional, lines


# ---------------------------------------------------------------- H6

_ABL_CONFIG_COLUMNS = ("config", "variant", "approach", "series", "mode")
_ABL_G_COLUMNS = ("g", "G", "g_blocks", "n_blocks", "blocks")


def _ablation_table(path, min_runs):
    """Read `proofbench ablation` rows (raw.csv style plus a config and a G column).

    Format assumed (TASK-ablation.md; the crate code did not exist when this was written):
    raw.csv columns plus a column naming the configuration (one of config/variant/approach/
    series/mode) with values `batched` and `per_block`, and a column G (g/n_blocks/blocks) with
    the number of blocks. prove_s is the TOTAL prove time of the configuration for that G.
    """
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        sys.exit(f"refusing to continue: input CSV not found: {path}")
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        header = csv.DictReader(handle).fieldnames or []
    config_col = next((c for c in _ABL_CONFIG_COLUMNS if c in header), None)
    g_col = next((c for c in _ABL_G_COLUMNS if c in header), None)
    if config_col is None or g_col is None or "prove_s" not in header:
        sys.exit(
            f"refusing {path}: need a config column {list(_ABL_CONFIG_COLUMNS)}, a G column "
            f"{list(_ABL_G_COLUMNS)} and prove_s; header is {header}"
        )
    rows, meta = common.load_csv(
        path, required=("warmup", "prove_s", config_col, g_col), min_runs=min_runs,
        group_keys=(g_col, config_col),
    )
    return rows, meta, config_col, g_col


def _ablation_summary(path, min_runs):
    rows, meta, config_col, g_col = _ablation_table(path, min_runs)
    prove = common.group_stats(rows, (g_col, config_col), value="prove_s")
    verify_col = "total_verify_s" if any(
        isinstance(r.get("total_verify_s"), (int, float)) for r in rows) else "verify_s"
    verify = common.group_stats(rows, (g_col, config_col), value=verify_col)
    size = common.group_stats(rows, (g_col, config_col), value="proof_bytes")
    lines = [
        "(iii) w/o Batched RC: per_block total vs batched (median over timed runs):",
        f"  G     batched prove s   per_block prove s   ratio   verify ratio ({verify_col})   "
        "proof bytes ratio",
    ]
    checks = []
    for g in sorted({k[0] for k in prove}, key=common.sort_key):
        batched = prove.get((g, "batched"))
        per_block = prove.get((g, "per_block"))
        if batched is None or per_block is None:
            lines.append(f"  {g!s:<5} missing batched or per_block")
            continue
        ratio = per_block["median"] / batched["median"]
        v_ratio = (verify[(g, "per_block")]["median"] / verify[(g, "batched")]["median"]
                   if (g, "per_block") in verify and (g, "batched") in verify else None)
        s_ratio = (size[(g, "per_block")]["median"] / size[(g, "batched")]["median"]
                   if (g, "per_block") in size and (g, "batched") in size else None)
        lines.append(
            f"  {g!s:<5} {batched['median']:<17.4f} {per_block['median']:<19.4f} {ratio:<7.3f} "
            f"{_fmt(v_ratio, '.3f'):<26} {_fmt(s_ratio, '.3f')}"
        )
        # G=1: both configurations are the same single R_RC proof, so no sign is predicted
        if isinstance(g, (int, float)) and g > 1:
            checks.append(ratio > 1.0)
    lines.append("  rule: per_block prove time > batched for every G > 1 (at G=1 both configurations "
                 "are one identical proof, reported only)")
    condition = all(checks) if checks else None
    return condition, meta["provisional"], lines


def _ratio_components(rows, approach_a, approach_b, keys):
    """Median(approach_a)/median(approach_b) per layout over the groups in `keys`."""
    stats = common.group_stats(rows, ("layout",) + keys + ("approach",))
    out = {}
    for key, entry in stats.items():
        if key[-1] != approach_a:
            continue
        other = stats.get(key[:-1] + (approach_b,))
        if other is None:
            continue
        out.setdefault(key[0], []).append((key[1:-1], entry["median"] / other["median"]))
    return out


def _h6_components(exp2_rows, exp3_rows, exp3c_rows):
    """(i) prot_full_scan vs pqz (exp2a), (ii) full_he vs pqz from exp3a and from exp3c."""
    part_i = _ratio_components(exp2_rows, "prot_full_scan", "pqz", ("predicate", "sigma"))
    part_ii = _ratio_components(exp3_rows, "full_he", "pqz", ("agg", "n", "sigma"))
    part_ii_c = (
        _ratio_components(exp3c_rows, "full_he", "pqz", ("agg", "n", "sigma"))
        if exp3c_rows else {}
    )
    return part_i, part_ii, part_ii_c


def _h6_lines_components(part_i, part_ii, part_ii_c):
    lines = []
    for title, part, label in (
        ("(i) w/o Block Filtering = prot_full_scan / pqz query time (exp2a)", part_i,
         "predicate, sigma"),
        ("(ii) w/o Selective HE = full_he / pqz aggregation time (exp3a, the n_Q sweep)",
         part_ii, "agg, n, sigma"),
        ("(ii, exp3c N sweep) the same full_he / pqz comparison at varying N",
         part_ii_c, "agg, n, sigma"),
    ):
        lines.append(f"{title}; ratio > 1 means the removal costs more:")
        if not part:
            lines.append("  no data")
            continue
        for layout in sorted(part, key=str):
            cells = ", ".join(
                f"{'/'.join(str(x) for x in key)}={ratio:.3f}"
                for key, ratio in sorted(part[layout], key=lambda item: str(item[0]))
            )
            lines.append(f"  {layout} [{label}]: {cells}")
    return lines


def _h6_layout_status(layouts, part_i, part_ii, part_ii_c, condition_iii):
    """Per layout: REFUTED if any removal does not cost more, SUPPORTED if all three do."""
    lines = []
    statuses = {}
    for layout in layouts:
        checks = {}
        for name, part in (("i", part_i), ("ii", part_ii)):
            entries = part.get(layout)
            checks[name] = None if not entries else all(r > 1.0 for _, r in entries)
        combined_ii = part_ii.get(layout, []) + part_ii_c.get(layout, [])
        if combined_ii:
            checks["ii"] = all(r > 1.0 for _, r in combined_ii)
        checks["iii"] = condition_iii
        values = list(checks.values())
        if any(v is False for v in values):
            status = "REFUTED"
        elif all(v is True for v in values):
            status = "SUPPORTED"
        else:
            status = "NOT-ENOUGH-DATA"
        statuses[layout] = status
        text = ", ".join(
            f"({k}) " + ("no data" if v is None else "costs more" if v else "does NOT cost more")
            for k, v in checks.items()
        )
        lines.append(f"  layout {layout}: {text} -> {status}")
    return statuses, lines


def _bool_text(value):
    return "no data" if value is None else ("yes" if value else "no")


def main():
    args = parse_args()
    exp1_paths = args.exp1 or [common.default_csv("smoke/s1/exp1.csv")]
    exp2_paths = args.exp2 or [common.default_csv("smoke/s2/exp2a.csv")]
    exp3_paths = args.exp3 or [common.default_csv("smoke/s3/exp3a.csv")]

    results = []   # (id, measured, status, provisional, detail lines)

    exp1_rows, exp1_provisional = _load_many(
        exp1_paths, ("series", "n", "time_ns", "warmup"), ("series", "n"), args.min_runs
    )
    exp1_slopes = _exp1_series_slopes(exp1_rows)
    sigma_fit = exp1_slopes.get("sigma1pct", {})
    fixed_fit = exp1_slopes.get("fixed_nq1000", {})
    slope_sigma = sigma_fit.get("slope")
    slope_fixed = fixed_fit.get("slope")
    h1_enough = slope_sigma is not None and slope_fixed is not None
    h1_condition = (
        slope_fixed < 0.10 * slope_sigma
        if h1_enough and slope_sigma is not None else None
    )
    h1_measured = (
        f"fixed_nq1000 slope={slope_fixed:.4g}, sigma1pct slope={slope_sigma:.4g}, "
        f"ratio={(slope_fixed / slope_sigma):.4g}"
        if h1_enough else
        "slopes not estimable (need >=2 distinct N per series)"
    )
    results.append(("H1", h1_measured, _status(exp1_provisional, h1_enough, h1_condition),
                    exp1_provisional, []))

    exp2_rows, exp2_provisional = _load_many(
        exp2_paths,
        ("approach", "layout", "predicate", "sigma", "time_ns", "warmup"),
        ("layout", "predicate", "approach", "sigma"),
        args.min_runs,
    )
    fit = _exp2_fit(exp2_rows)
    h2_enough = fit["r2"] is not None
    h2_condition = fit["r2"] >= 0.95 if h2_enough else None
    h2_measured = (
        f"R^2={fit['r2']:.4f} on {fit['points']} group medians "
        f"(T_BPS={fit['t_bps_ns']:.4g} ns/block, T_RPS={fit['t_rps_ns']:.4g} ns/record)"
        if h2_enough else
        "cost model not identifiable (fewer than 2 usable groups)"
    )
    if h2_enough and fit["t_bps_ns"] is not None and fit["t_bps_ns"] < 0:
        h2_measured += "; WARNING: negative T_BPS is unphysical (collinear/noisy points)"
    results.append(("H2", h2_measured, _status(exp2_provisional, h2_enough, h2_condition),
                    exp2_provisional, _exp2_per_predicate(exp2_rows)))

    exp3_rows, exp3_provisional = _load_many(
        exp3_paths,
        ("agg", "approach", "n_sel", "time_ns", "warmup"),
        ("agg", "approach", "n_sel"),
        args.min_runs,
    )
    _, exp3_slopes = _exp3_slopes(exp3_rows)
    slope_parts = []
    h3_enough = True
    for (agg, approach), entry in sorted(exp3_slopes.items(), key=lambda item: str(item[0])):
        if entry["slope"] is None:
            h3_enough = False
            slope_parts.append(f"{agg}/{approach}: NOT-ENOUGH-DATA")
        else:
            slope_parts.append(f"{agg}/{approach}: slope={entry['slope']:.4g}")
    count_slopes = [entry["slope"] for (agg, approach), entry in exp3_slopes.items()
                    if agg == "COUNT" and approach == "pqz"
                    and entry["slope"] is not None]
    sum_avg_slopes = [entry["slope"] for (agg, approach), entry in exp3_slopes.items()
                      if agg in ("SUM", "AVG") and approach == "pqz"
                      and entry["slope"] is not None]
    count_ok = all(abs(slope) <= SLOPE_TOLERANCE["COUNT"] for slope in count_slopes)
    sum_avg_ok = all(
        abs(slope - 1.0) <= SLOPE_TOLERANCE["SUM"] for slope in sum_avg_slopes
    )
    h3_condition = None
    if h3_enough and count_slopes and sum_avg_slopes:
        h3_condition = count_ok and sum_avg_ok
        h3_enough = True
    else:
        h3_enough = False
    h3_measured = (
        "; ".join(slope_parts) + " (local tolerance: COUNT |slope|<=0.10, "
        "SUM/AVG pqz |slope-1|<=0.10; not written in the plan)"
    )
    h3_measured += _fixture_tag(list(exp3_paths) + list(args.exp3c or []))
    h3_details = []
    h3_provisional = exp3_provisional
    exp3c_fits = None
    exp3c_rows = None
    if args.exp3c:
        exp3c_rows, exp3c_provisional = _load_many(
            args.exp3c,
            ("series", "n", "layout", "approach", "n_sel", "time_ns", "warmup"),
            ("layout", "approach", "n"),
            args.min_runs,
        )
        exp3c_fits = _exp3c_fits(exp3c_rows)
        h3_provisional = h3_provisional or exp3c_provisional
        he_slopes = {layout: fit_["vs_n"]["slope"] for (layout, approach), fit_ in
                     exp3c_fits.items() if approach == "full_he"}
        he_enough = bool(he_slopes) and all(s is not None for s in he_slopes.values())
        he_ok = he_enough and all(
            abs(s - 1.0) <= SLOPE_TOLERANCE["HE_N"] for s in he_slopes.values())
        h3_measured += (
            "; Full-Domain HE vs N (exp3c, log-log slope of median time): "
            + ", ".join(f"{layout}={_fmt(s)}" for layout, s in sorted(he_slopes.items(), key=str))
            + f" (local tolerance |slope-1|<={SLOPE_TOLERANCE['HE_N']:.2f})"
        )
        pqz_vs_n = {layout: fit_["vs_n"]["slope"] for (layout, approach), fit_ in
                    exp3c_fits.items() if approach == "pqz"}
        pqz_vs_nq = {layout: fit_["vs_nq"]["slope"] for (layout, approach), fit_ in
                     exp3c_fits.items() if approach == "pqz"}
        h3_measured += (
            "; pqz SUM vs N (exp3c): "
            + ", ".join(f"{layout}={_fmt(s)}" for layout, s in sorted(pqz_vs_n.items(), key=str))
            + " (vs n_Q: "
            + ", ".join(f"{layout}={_fmt(s)}" for layout, s in sorted(pqz_vs_nq.items(), key=str))
            + ")"
        )
        h3_details.append(
            "exp3c N sweep, log-log slope of median time (ms) per layout and approach"
            + _fixture_tag(args.exp3c) + ":"
        )
        h3_details.append("  layout     approach    points  slope vs N  R^2     slope vs n_Q")
        for (layout, approach), fit_ in sorted(exp3c_fits.items(), key=str):
            h3_details.append(
                f"  {layout!s:<10} {approach!s:<11} {fit_['points']:<7} "
                f"{_fmt(fit_['vs_n']['slope']):<11} {_fmt(fit_['vs_n']['r2'], '.4f'):<7} "
                f"{_fmt(fit_['vs_nq']['slope'])}"
            )
        n_sel_over_n = {
            row["n_sel"] / row["n"] for row in exp3c_rows
            if isinstance(row.get("n"), (int, float)) and isinstance(row.get("n_sel"), (int, float))
            and row["n"]
        }
        if len(n_sel_over_n) == 1:
            h3_details.append(
                f"  note: in exp3c n_Q = {next(iter(n_sel_over_n)):.4g} * N, so the vs-N and vs-n_Q "
                "fits use collinear points and give the same slope; the independent n_Q sweep "
                "is exp3a"
            )
        if h3_condition is not None and he_enough:
            h3_condition = h3_condition and he_ok
        elif not he_enough:
            h3_enough = False
            h3_condition = None
    else:
        he_enough = he_ok = None
        h3_measured += (
            "; Full-Domain HE linear-in-N cannot be checked: no varying-N exp3 file "
            "(pass --exp3c)"
        )
    # component view (informational; the overall status above keeps the written rule)
    count_status = _status(exp3_provisional, bool(count_slopes),
                           count_ok if count_slopes else None)
    sum_status = _status(exp3_provisional, bool(sum_avg_slopes),
                         sum_avg_ok if sum_avg_slopes else None)
    h3_details.append("components:")
    h3_details.append(
        f"  COUNT flat in n_Q (pqz |slope|<=0.10): {count_status}"
        + ("" if count_slopes else " (no COUNT series with >=2 n_sel values in the exp3 files)")
    )
    h3_details.append(f"  SUM/AVG linear in n_Q (pqz |slope-1|<=0.10): {sum_status}")
    if exp3c_fits is not None:
        h3_details.append(
            "  Full-Domain HE linear in N (|slope-1|<=0.10, each layout): "
            f"{_status(exp3c_provisional, he_enough, he_ok)}"
        )
    h3_details.append(
        "  overall H3 status needs all three components; COUNT has no n_Q sweep in the "
        "current data, so the overall status stays NOT-ENOUGH-DATA until it exists"
        if not count_slopes else
        "  overall H3 status needs all components"
    )
    results.append(("H3", h3_measured, _status(h3_provisional, h3_enough, h3_condition),
                    h3_provisional, h3_details))

    # H4
    if args.exp4:
        measured, status, provisional, lines = _h4(args.exp4, args.min_runs)
        results.append(("H4", measured, status, provisional, lines))
    else:
        results.append(("H4", "no result CSV supplied for this hypothesis",
                        "NOT-ENOUGH-DATA", False, []))

    # H5
    if args.exp5:
        measured, status, provisional, lines = _h5(args.exp5)
        results.append(("H5", measured, status, provisional, lines))
    else:
        results.append(("H5", "no result CSV supplied for this hypothesis",
                        "NOT-ENOUGH-DATA", False, []))

    # H6
    part_i, part_ii, part_ii_c = _h6_components(exp2_rows, exp3_rows, exp3c_rows)
    if args.ablation:
        condition_iii, abl_prov, abl_lines = _ablation_summary(args.ablation, args.min_runs)
        layouts = sorted(set(part_i) | set(part_ii) | set(part_ii_c) | {
            r.get("layout") for r in exp2_rows if r.get("layout") is not None}, key=str)
        statuses, layout_lines = _h6_layout_status(
            layouts, part_i, part_ii, part_ii_c, condition_iii)
        h6_provisional = exp2_provisional or exp3_provisional or abl_prov or (
            h3_provisional if exp3c_rows else False)
        if any(s == "REFUTED" for s in statuses.values()):
            raw_status = "REFUTED"
        elif statuses and all(s == "SUPPORTED" for s in statuses.values()):
            raw_status = "SUPPORTED"
        else:
            raw_status = "NOT-ENOUGH-DATA"
        status = "NOT-ENOUGH-DATA" if h6_provisional else raw_status
        measured = "; ".join(f"{layout}: {s}" for layout, s in statuses.items())
        measured += (
            "; (i) from --exp2 (exp2a), (ii) from --exp3 (exp3a) with the --exp3c N sweep "
            "reported separately, (iii) from --ablation: ratios in the detail lines"
            + _fixture_tag([args.ablation] + list(exp2_paths) + list(exp3_paths)
                           + list(args.exp3c or []))
        )
        lines = (_h6_lines_components(part_i, part_ii, part_ii_c) + abl_lines
                 + ["per-layout status by the written rule (REFUTED if any removal does not "
                    "cost more, SUPPORTED if each does):"] + layout_lines)
        results.append(("H6", measured, status, h6_provisional, lines))
    else:
        info = _h6_lines_components(part_i, part_ii, part_ii_c)
        results.append((
            "H6",
            "no ablation CSV supplied (pass --ablation); (i) and (ii) ratios are listed "
            "below for information only",
            "NOT-ENOUGH-DATA", False,
            ["informational only; H6 needs component (iii) from the ablation file:"] + info,
        ))

    # H7
    if args.reject:
        measured, status, provisional, lines = _h7(args.reject, args.reject_mutation)
        results.append(("H7", measured, status, provisional, lines))
    else:
        results.append(("H7", "no result CSV supplied for this hypothesis",
                        "NOT-ENOUGH-DATA", False, []))

    out_lines = [f"source: {PLAN_REFERENCE} (thresholds are PROPOSALS)", ""]
    output_rows = []
    for hypothesis_id, measured, status, provisional, details in results:
        spec = HYPOTHESES[hypothesis_id]
        out_lines.append(f"{hypothesis_id} {spec['name']} (source: {spec['source']})")
        out_lines.append(f"  measured: {measured}")
        out_lines.append(f"  threshold: {spec['threshold']} [{spec['threshold_kind']}]")
        out_lines.append(f"  status: {status}")
        for line in details:
            out_lines.append(f"  | {line}")
        out_lines.append("")
        output_rows.append({
            "hypothesis": hypothesis_id,
            "name": spec["name"],
            "exp": spec["exp"],
            "statement": spec["statement"],
            "metric": spec["metric"],
            "measured": measured,
            "threshold": spec["threshold"],
            "threshold_kind": spec["threshold_kind"],
            "source": spec["source"],
            "provisional": int(provisional),
            "status": status,
            "details": " | ".join(details),
        })

    directory = common.out_dir(args.out)
    csv_path = os.path.join(directory, "hypotheses.csv")
    txt_path = os.path.join(directory, "hypotheses.txt")
    common.save_csv(csv_path, list(output_rows[0].keys()), output_rows)
    out_lines.append(f"wrote {csv_path}")
    out_lines.append(f"wrote {txt_path}")
    text = "\n".join(out_lines) + "\n"
    with open(txt_path, "w", encoding="utf-8") as handle:
        handle.write(text)
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
