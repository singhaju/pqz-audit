"""Shared helpers of the work18 analysis scripts (new file; the w15/w17 helpers are untouched).

Used by summary_w18.py, paper_numbers_w18.py, make_figs_w18.py and the fig_*_w18.py copies.

Results folder (one folder, one sub-folder per job): --results DIR, else env W18_RESULTS,
else bench/pqz-eval/results/cloud-w18.  Output folder: --out DIR, else env W18_OUT (or the
script's own default).

Refusal rules (nothing is invented, nothing is defaulted):
  * a needed job folder or file is missing or empty            -> list all of them, exit 2
  * a needed job has exit_code.txt missing or not 0            -> exit 2 (a failed first attempt is
    kept by the run as <name>.failed1 and is never read here)
  * a needed job has a non-empty failures.txt                  -> exit 2
  * a row of a csv has note starting with FAILED               -> exit 2
Optional jobs (the alone-checks) are skipped with a message when missing.
"""
import csv
import os
import statistics as st
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)                      # bench/pqz-eval
ROOT = os.path.dirname(os.path.dirname(BASE))     # repository root
DEFAULT_RESULTS = os.path.join(BASE, "results", "cloud-w18")

# every job folder of the w18 run (see bench/cloud-w18/remote_w18.sh)
ALONE_CHECKS = ["ac-exp3c-n10000", "ac-dong", "ac-dart", "ac-dopiv"]


def results_dir(cli=None):
    p = cli or os.environ.get("W18_RESULTS") or DEFAULT_RESULTS
    p = os.path.abspath(p)
    if not os.path.isdir(p):
        sys.exit(f"REFUSING: results folder not found: {p}")
    return p


def out_dir(cli, default):
    p = os.path.abspath(cli or os.environ.get("W18_OUT") or default)
    os.makedirs(p, exist_ok=True)
    return p


def _nonempty(path):
    return os.path.isfile(path) and os.path.getsize(path) > 0


class Results:
    """Access to one results folder with the refusal rules above."""

    def __init__(self, path):
        self.path = path
        self._checked = {}

    def p(self, job, fname=None):
        return os.path.join(self.path, job) if fname is None else os.path.join(self.path, job, fname)

    def job_problems(self, job):
        """List of reasons why the job folder cannot be used (empty list = fine)."""
        d = self.p(job)
        if not os.path.isdir(d):
            return [f"job folder missing: {d}"]
        out = []
        rc = self.p(job, "exit_code.txt")
        if not os.path.isfile(rc):
            out.append(f"{job}: exit_code.txt missing")
        else:
            v = open(rc).read().strip()
            if v != "0":
                out.append(f"{job}: exit_code.txt = {v!r} (job failed)")
        fl = self.p(job, "failures.txt")
        if os.path.isfile(fl) and open(fl, errors="replace").read().strip():
            out.append(f"{job}: failures.txt is not empty")
        return out

    def preflight(self, required, optional=()):
        """required: list of (job, file-or-None). Refuse (exit 2) listing every problem.

        optional: list of (job, file) that are checked and the usable ones returned as a set of jobs.
        Prints warnings about FAILED_JOBS.txt and DONE.
        """
        problems = []
        seen_jobs = {}
        for job, fname in required:
            if job not in seen_jobs:
                seen_jobs[job] = self.job_problems(job)
                problems += seen_jobs[job]
            folder_ok = not any("folder missing" in x for x in seen_jobs[job])
            if fname and folder_ok and not _nonempty(self.p(job, fname)):
                problems.append(f"{job}/{fname}: missing or empty")
        if problems:
            print("REFUSING: input is incomplete or failed:", file=sys.stderr)
            for x in sorted(set(problems)):
                print("  - " + x, file=sys.stderr)
            print(f"results folder: {self.path}", file=sys.stderr)
            sys.exit(2)
        ff = os.path.join(self.path, "FAILED_JOBS.txt")
        if os.path.isfile(ff) and open(ff).read().strip():
            print("WARNING: FAILED_JOBS.txt lists jobs (not needed by this script, or it would have been refused):",
                  file=sys.stderr)
            for ln in open(ff).read().strip().splitlines():
                print("   " + ln, file=sys.stderr)
        if not os.path.exists(os.path.join(self.path, "DONE")):
            print("WARNING: no DONE marker in the results folder (run not finished or not fully pulled?)", file=sys.stderr)
        ok = set()
        for job, fname in optional:
            pr = self.job_problems(job)
            if not pr and (not fname or _nonempty(self.p(job, fname))):
                ok.add(job)
            else:
                why = pr[0] if pr else f"{job}/{fname}: missing or empty"
                print(f"SKIP (optional) {job}: {why}")
        return ok

    def rd(self, job, fname):
        path = self.p(job, fname)
        if not _nonempty(path):
            sys.exit(f"REFUSING: {job}/{fname} missing or empty ({path})")
        with open(path, newline="") as fh:
            rows = list(csv.DictReader(fh))
        if not rows:
            sys.exit(f"REFUSING: {job}/{fname} has a header but no rows")
        bad = [r for r in rows if str(r.get("note", "")).startswith("FAILED")]
        if bad:
            sys.exit(f"REFUSING: {job}/{fname} contains {len(bad)} row(s) with note starting FAILED")
        return rows


def is_timed(r):
    """Timed row of any of the program's csv files (warmup column or kind column)."""
    if r.get("warmup", "0") not in ("0", ""):
        return False
    if r.get("kind", "timed") != "timed":
        return False
    return True


def S(v):
    """(median, min, max, n)"""
    if not v:
        raise ValueError("empty cell")
    return st.median(v), min(v), max(v), len(v)


def parse_params(s):
    """'s=3;c=1000;n=10000;runs=30;alone-check' -> ({'s':'3',...}, ['alone-check'])"""
    d, tags = {}, []
    for tok in s.split(";"):
        if "=" in tok:
            k, v = tok.split("=", 1)
            d[k] = v
        elif tok:
            tags.append(tok)
    return d, tags


def cell_key(params, drop=("runs",)):
    """Key of a baseline cell without the run count and without the tag tokens."""
    d, _ = parse_params(params)
    return tuple(sorted((k, v) for k, v in d.items() if k not in drop))


# ---------------------------------------------------------------- shared cell builders and the alone-check comparison
EXP_KEYS = ["exp", "series", "n", "mb", "sigma", "layout", "predicate", "agg", "approach"]
ALONE_RULE_PCT = 10.0


def exp_groups(rows, keys=EXP_KEYS):
    """Timed rows of an exp* csv grouped by configuration; each group is a list of rows."""
    g = {}
    for r in rows:
        if is_timed(r):
            g.setdefault(tuple(r[k] for k in keys), []).append(r)
    return g


def ms_of(rs):
    """(median, min, max, n) in ms of a list of exp* rows (time_ns column)."""
    return S([float(r["time_ns"]) / 1e6 for r in rs])


def base_groups(rows):
    """Baseline raw_runs rows -> {(baseline, stage, params): [ms,...]}"""
    g = {}
    for r in rows:
        g.setdefault((r["baseline"], r["stage"], r["params"]), []).append(float(r["ms"]))
    return g


def _row(key, s2job, s2, al):
    d = (s2[0] - al[0]) / al[0] * 100 if al[0] else float("nan")
    return list(key) + [s2job, s2[3], s2[0], al[3], al[0], d, abs(d) > ALONE_RULE_PCT]


# family -> (alone job, [S2 jobs], stages); baselines only
ALONE_BASE = {
    "dong": ("ac-dong", ["dong-e1"], ("proofgen", "verify")),
    "dart": ("ac-dart", ["dart-e4a"], ("proofgen_nozk", "verify_nozk")),
    "dopiv": ("ac-dopiv", ["dopiv-e1"], ("proofgen", "verify")),
}


def alone_compare(R, ok_ac):
    """Compare the S2 value with the alone value for every alone-check present in ok_ac.

    Returns {family: (key_column_names, rows)}, rows = key... + [s2_job, s2_runs, s2_median_ms,
    alone_runs, alone_median_ms, diff_pct, over_10pct]; diff_pct = (S2 - alone) / alone * 100.
    A cell of the alone job without exactly one matching S2 cell -> exit 2.
    """
    out = {}
    if "ac-exp3c-n10000" in ok_ac:
        s2g = exp_groups(R.rd("exp3c", "exp3c.csv"))
        rows = []
        for k, rs in exp_groups(R.rd("ac-exp3c-n10000", "exp3c.csv")).items():
            if k[2] != "10000":
                print(f"NOTE ac-exp3c-n10000: cell with n={k[2]} ignored")
                continue
            if k not in s2g:
                sys.exit(f"REFUSING: alone cell {k} of ac-exp3c-n10000 has no S2 cell in exp3c")
            rows.append(_row(k, "exp3c", ms_of(s2g[k]), ms_of(rs)))
        if not rows:
            sys.exit("REFUSING: ac-exp3c-n10000 has no n=10000 cells")
        out["exp3c"] = (EXP_KEYS, rows)
    for fam, (acj, s2jobs, stages) in ALONE_BASE.items():
        if acj not in ok_ac:
            continue
        s2 = {sj: base_groups(R.rd(sj, "raw_runs.csv")) for sj in s2jobs}
        rows = []
        for (b, stg, prm), v in sorted(base_groups(R.rd(acj, "raw_runs.csv")).items()):
            if stg not in stages:
                continue
            want = cell_key(prm)
            hits = [(sj, v2) for sj, g in s2.items() for (b2, st2, p2), v2 in g.items()
                    if b2 == b and st2 == stg and cell_key(p2) == want]
            if len(hits) != 1:
                sys.exit(f"REFUSING: alone cell {fam} {stg} {prm}: {len(hits)} matching S2 cells in {s2jobs} (need exactly 1)")
            rows.append(_row([stg, prm], hits[0][0], S(hits[0][1]), S(v)))
        if not rows:
            sys.exit(f"REFUSING: {acj}: none of the stages {stages} present")
        out[fam] = (["stage", "alone_params"], rows)
    return out
