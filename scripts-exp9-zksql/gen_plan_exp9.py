#!/usr/bin/env python3
"""Exp 9 (w36): the ZKSQL plan of the w35 query. stdlib only.  usage: gen_plan_exp9.py <outdir> [--a-type INTEGER|LONG]
Table auditlog(id INT, a INT|BIGINT, v BIGINT, b INT)  -> column ordinals id=0 a=1 v=2 b=3.
Plan: JdbcTableScan -> LogicalFilter( a = 7  AND  v >= 2147483648 ) -> LogicalAggregate( COUNT(*), SUM(b) ).
The filter is the FULL private predicate (tag test AND the R_Exec threshold test); ZKSQL gets the whole table, nothing pre-filtered.
Written to <outdir>/zk-exp9_q.json (the plan name is exp9_q; ZKSQL reads conf/plans/zk-<name>.json)."""
import json, os, sys

PID_A = 7              # Predicate::P1 is a == 7 (pqz-eval/src/lib.rs:70)
THETA = 1 << 31        # pqz_int::THETA


def lit(v, t):
    return {"literal": v, "type": {"type": t, "nullable": False}}


def agg(kind, syntax, operands, name, nullable):
    return {"agg": {"name": kind, "kind": kind, "syntax": syntax}, "type": {"type": "LONG", "nullable": nullable},
            "distinct": False, "operands": operands, "name": name}


def main():
    out = sys.argv[1]
    at = "INTEGER"
    if "--a-type" in sys.argv:
        at = sys.argv[sys.argv.index("--a-type") + 1]
    os.makedirs(out, exist_ok=True)
    eq = {"op": {"name": "=", "kind": "EQUALS", "syntax": "BINARY"}, "operands": [{"input": 1, "name": "$1"}, lit(PID_A, at)]}
    ge = {"op": {"name": ">=", "kind": "GREATER_THAN_OR_EQUAL", "syntax": "BINARY"}, "operands": [{"input": 2, "name": "$2"}, lit(THETA, "LONG")]}
    plan = {"rels": [
        {"id": "0", "relOp": "JdbcTableScan", "table": ["auditlog"], "inputs": []},
        {"id": "1", "relOp": "LogicalFilter", "condition": {"op": {"name": "AND", "kind": "AND", "syntax": "BINARY"}, "operands": [eq, ge]}},
        {"id": "2", "relOp": "LogicalAggregate", "group": [], "aggs": [agg("COUNT", "FUNCTION_STAR", [], "cnt", False), agg("SUM", "FUNCTION", [3], "total", True)]}]}
    fn = os.path.join(out, "zk-exp9_q.json")
    with open(fn, "w") as f:
        json.dump(plan, f, indent=1)
    print("plan written:", fn, "(a literal type %s)" % at)


main()
