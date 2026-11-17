#!/bin/bash
# Exp 9 (w36), ZKSQL side, part 2: ONE run = fresh pair of processes Bob (verifier) and Alice (prover), each pinned to its own physical core.
# usage: bash exp9_run_one.sh <N> <layout> <run dir> <port> <csv dir (reference.tsv)> [phase warm|timed]
# ok = 1 only if: both rc 0, both gtests passed (cheat check of finalize included), Alice's result == PostgreSQL (RESULT_MATCHES_PLAINTEXT 1), Bob revealed the same,
#      AND the revealed (count, sum) equals the PQZ reference of the same records (checked by revealed_check.py). Any difference: ok = 0 with the reason (never ignored).
set -uo pipefail
E9_HERE=$(cd "$(dirname "$0")" && pwd)
source "$E9_HERE/lib_w32.sh"
N=${1:?N}; L=${2:?layout}; R=${3:?run dir}; PORT=${4:?port}; CSV=${5:?csv dir}; PHASE=${6:-timed}
zk_pgenv; zk_pins || exit 2
read -r _n _l CNT SUMB SIGMA THETA < <(awk -v n="$N" -v l="$L" '$1==n && $2==l {print}' "$CSV/reference.tsv" | tail -1)
[ -n "${CNT:-}" ] || { echo "no reference for N=$N $L"; exit 2; }
PLAN=exp9_q
SQL="SELECT COUNT(*)::BIGINT AS cnt, SUM(b)::BIGINT AS total FROM auditlog WHERE a = 7 AND v >= $THETA"
case "$N" in 1000000) TMO=${W32_RUN_TIMEOUT_1E6:-1800} ;; 100000) TMO=900 ;; 50000) TMO=450 ;; *) TMO=${W32_RUN_TIMEOUT_SMALL:-240} ;; esac
mkdir -p "$R/alice" "$R/bob"
for w in alice bob; do ln -sfn "$ZK_DATA/conf" "$R/$w/conf"; done
{ echo "N=$N layout=$L theta=$THETA plan=$PLAN phase=$PHASE port=$PORT ref_count=$CNT ref_sum_b=$SUMB sigma=$SIGMA"
  echo "alice_cpu=$W32_ALICE_CPU (physical core $(core_of "$W32_ALICE_CPU")) bob_cpu=$W32_BOB_CPU (physical core $(core_of "$W32_BOB_CPU")) pg_cpu=$W32_PG_CPU"
  echo "load1_before=$(cut -d' ' -f1 /proc/loadavg) mem_avail_MB=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo) start=$(now)"
  echo "sql=$SQL"; } > "$R/meta.txt"
[ "$(core_of "$W32_ALICE_CPU")" != "$(core_of "$W32_BOB_CPU")" ] || { echo "same physical core: refused" | tee -a "$R/meta.txt"; echo "0 same_core" > "$R/ok"; exit 3; }
( cd "$R/bob" && ZK_DB=exp9_bob ZK_PLAN=$PLAN timeout -k 20 "$TMO" $NICE taskset -c "$W32_BOB_CPU" python3 -I "$W32_HERE/tm_w32.py" bob env LD_LIBRARY_PATH="$ZK_LD" "$ZK_BIN" --party=2 --port="$PORT" --alice_host=127.0.0.1 > "$R/bob.out" 2> "$R/bob.err" ) &
PB=$!
sleep 1
( cd "$R/alice" && ZK_DB=exp9_${L}_$N ZK_PLAN=$PLAN ZK_SQL="$SQL" timeout -k 20 "$TMO" $NICE taskset -c "$W32_ALICE_CPU" python3 -I "$W32_HERE/tm_w32.py" alice env LD_LIBRARY_PATH="$ZK_LD" "$ZK_BIN" --party=1 --port="$PORT" --alice_host=127.0.0.1 > "$R/alice.out" 2> "$R/alice.err" ) &
PA=$!
wait "$PA"; wait "$PB"
why=""
for p in alice bob; do
  rc=$(grep -a -h -o 'rc=[0-9-]*' "$R/$p.err" | tail -1 | cut -d= -f2)
  [ "$rc" = 0 ] || why="$why $p:rc=${rc:-none}"
  grep -a -q '^RESULT_GTEST_PASSED 1' "$R/$p.out" || why="$why $p:gtest_not_passed"
done
grep -a -q '^RESULT_MATCHES_PLAINTEXT 1' "$R/alice.out" || why="$why alice:no_plaintext_match"
ra=$(grep -a -h '^RESULT_REVEALED' "$R/alice.out" | tr -s ' \n' ' '); rb=$(grep -a -h '^RESULT_REVEALED' "$R/bob.out" | tr -s ' \n' ' ')
[ -n "$ra" ] && [ "$ra" = "$rb" ] || why="$why revealed_differs"
chk=$(python3 -I "$E9_HERE/revealed_check.py" "$R/alice.out" "$CNT" "$SUMB" 2>&1); [ "$?" = 0 ] || why="$why pqz_reference_differs($chk)"
echo "revealed_check: $chk" >> "$R/meta.txt"
for p in alice bob; do [ -d "$R/$p/data" ] && { echo "ot_cache_kb_$p: $(du -sk "$R/$p/data" | cut -f1)" >> "$R/meta.txt"; rm -rf "$R/$p/data"; }; done
if [ -z "$why" ]; then echo "1 ok" > "$R/ok"; else echo "0$why" > "$R/ok"; fi
cat "$R/ok"
