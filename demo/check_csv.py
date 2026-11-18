#!/usr/bin/env python3
"""Independent check of a question-15 answer: COUNT, SUM and AVG computed with plain Python over the
plaintext CSV of the demo log (no PQZ-Audit code is used here).

Make the CSV once (the same seeded 10,000 records every demo run builds in memory):
    pqz-integrated-w46/target/release/demo_scenarios --scenario dump --n 10000 > demo/data/log-10000.csv
Then:
    python3 demo/check_csv.py "action = EXPORT AND patients > 100"
    python3 demo/check_csv.py "staff = 417" --show
Fields: action (code or name), staff, dept (code or name), patients. Operators: = >= > <= <. AND only.
"""
import csv
import operator
import re
import sys
from pathlib import Path

OPS = {"=": operator.eq, ">=": operator.ge, ">": operator.gt, "<=": operator.le, "<": operator.lt}
COL = {"action": "action_code", "staff": "staff", "dept": "dept_code", "department": "dept_code", "patients": "patients"}


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    show = "--show" in sys.argv
    if not args:
        sys.exit(__doc__)
    path = Path(__file__).resolve().parent / "data" / "log-10000.csv"
    rows = list(csv.DictReader(open(path, newline="")))
    names = {}
    for r in rows:  # names -> codes, read from the CSV itself
        names[("action_code", r["action"].lower())] = r["action_code"]
        names[("action_code", r["action"].lower().replace("_records", ""))] = r["action_code"]
        names[("dept_code", r["dept"].lower().replace(" ", ""))] = r["dept_code"]
        names[("dept_code", r["dept"].lower().split("(")[0].replace(" ", ""))] = r["dept_code"]
        names[("dept_code", r["dept"].lower().split("/")[0].split("(")[0].replace(" ", ""))] = r["dept_code"]
    conds = []
    text = args[0].replace("≥", ">=").replace("≤", "<=").replace("==", "=")
    for part in re.split(r"\s+and\s+|,", text, flags=re.I):
        m = re.fullmatch(r"\s*([A-Za-z_]+)\s*(>=|<=|=|>|<)\s*(.+?)\s*", part)
        if not m or m.group(1).lower() not in COL:
            sys.exit(f"cannot read {part!r}; use action/staff/dept/patients with = >= > <= <")
        col, op, val = COL[m.group(1).lower()], m.group(2), m.group(3)
        if not val.isdigit():
            val = names.get((col, val.lower().replace(" ", "")))
            if val is None:
                sys.exit(f"unknown name in {part!r}")
        conds.append((col, OPS[op], int(val)))
    hit = [r for r in rows if all(f(int(r[c]), v) for c, f, v in conds)]
    count, total = len(hit), sum(int(r["patients"]) for r in hit)
    avg = f"{total / count:,.1f}" if count else "undefined"
    print(f"{len(rows):,} plaintext records read from {path.name}")
    print(f"query: {args[0]}")
    print(f"COUNT = {count:,}   SUM(patients) = {total:,}   AVG = {avg}")
    if show:
        for r in hit[:30]:
            print("  ", r["id"], r["time"], r["action"], r["patients"], r["dept"], r["staff"])
        if count > 30:
            print(f"   ... {count - 30} more")


if __name__ == "__main__":
    main()
