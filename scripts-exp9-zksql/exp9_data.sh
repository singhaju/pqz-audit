#!/bin/bash
# Exp 9 (w36), ZKSQL side, part 1: plan + PostgreSQL databases of the SAME records the PQZ driver uses.
# usage: bash exp9_data.sh <csv dir> <N list> [layouts]     <csv dir> = output of `pqz-exp9-w36 export <n> <layout> <dir>` (auditlog_n<N>_<layout>.csv, reference.tsv)
# Creates one database per (layout, N) = exp9_<layout>_<N> for Alice and ONE empty schema-only database exp9_bob for Bob. Loads the FULL table (nothing pre-filtered).
# Then asks PostgreSQL itself for COUNT(*), SUM(b) WHERE a = 7 AND v >= theta and compares with the reference of the PQZ side: ANY difference exits 1 (loud).
# Env: the W32_* overrides of kit/lib_w32.sh (paths, pins, port). A_TYPE (INT|BIGINT, default INT) must agree with the plan literal type (INTEGER|LONG).
set -uo pipefail
E9_HERE=$(cd "$(dirname "$0")" && pwd)
source "$E9_HERE/lib_w32.sh"
zk_pgenv
CSV=${1:?csv dir}; NS=${2:?N list (comma)}; LAYS=${3:-clustered,scattered}
A_TYPE=${A_TYPE:-INT}; case "$A_TYPE" in INT) AL=INTEGER ;; BIGINT) AL=LONG ;; *) echo "A_TYPE INT|BIGINT"; exit 2 ;; esac
mkdir -p "$ZK_DATA" "$ZK_LOGS"
python3 -I "$E9_HERE/gen_plan_exp9.py" "$ZK_DATA/conf/plans" --a-type "$AL" || exit 1
bash "$W32_HERE/zksql_pg.sh" start || exit 1
DDL="CREATE TABLE auditlog (id INT, a $A_TYPE, v BIGINT, b INT);"
dropdb --if-exists exp9_bob; createdb exp9_bob || exit 1; psql -q exp9_bob -c "$DDL" || exit 1
: > "$ZK_LOGS/exp9_loadcheck.txt"; BAD=0
for L in ${LAYS//,/ }; do for N in ${NS//,/ }; do
  f="$CSV/auditlog_n${N}_${L}.csv"; [ -s "$f" ] || { echo "missing $f"; exit 1; }
  read -r _n _l cnt sumb sigma theta < <(awk -v n="$N" -v l="$L" '$1==n && $2==l {print}' "$CSV/reference.tsv" | tail -1)
  [ -n "${cnt:-}" ] || { echo "no reference for N=$N $L in $CSV/reference.tsv"; exit 1; }
  db=exp9_${L}_${N}
  dropdb --if-exists "$db"; createdb "$db" || exit 1
  psql -q "$db" -c "$DDL" || exit 1
  psql -q "$db" -c "\\copy auditlog FROM '$f' WITH (FORMAT csv)" || exit 1
  psql -q "$db" -c "ANALYZE auditlog" > /dev/null
  got=$(psql -At -F' ' "$db" -c "SELECT COUNT(*), SUM(b) FROM auditlog WHERE a = 7 AND v >= $theta")
  rows=$(psql -At "$db" -c "SELECT COUNT(*) FROM auditlog")
  tags=$(psql -At "$db" -c "SELECT COUNT(*) FROM auditlog WHERE a = 7")
  if [ "$got" = "$cnt $sumb" ] && [ "$rows" = "$N" ]; then st=OK; else st=MISMATCH; BAD=1; fi
  echo "N=$N layout=$L rows=$rows postgres=($got) pqz_reference=($cnt $sumb) rows_with_a7=$tags selectivity=$(awk -v t="$tags" -v n="$N" 'BEGIN{printf "%.4f", t/n}') $st" | tee -a "$ZK_LOGS/exp9_loadcheck.txt"
done; done
[ "$BAD" = 0 ] || { echo "LOAD CHECK FAILED (see $ZK_LOGS/exp9_loadcheck.txt)"; exit 1; }
say "exp9_data: loaded and checked (PostgreSQL equals the PQZ reference for every (layout, N))"
