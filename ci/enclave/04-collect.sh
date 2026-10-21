#!/usr/bin/env bash
#
# 04-collect.sh [outdir] — parse per-run timing logs into a CSV (and print a table).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTDIR="${1:-$HERE/enclave-out}"
CSV="$OUTDIR/timings.csv"

echo "run,vcpkg_fetch_s,pure_build_s,zk_overhead_s,total_s" > "$CSV"
for log in "$OUTDIR"/run-*.log; do
  [ -e "$log" ] || continue
  n=$(basename "$log" .log | sed 's/run-//')
  vcpkg=$(grep -E 'vcpkg registry fetch' "$log" | grep -oE '[0-9]+\.[0-9]+' | tail -1)
  pure=$(grep  -E 'Pure build time'      "$log" | grep -oE '[0-9]+\.[0-9]+' | tail -1)
  zk=$(grep    -E 'ZK overhead'          "$log" | grep -oE '[0-9]+\.[0-9]+' | tail -1)
  total=$(grep -E 'Total tee_build'      "$log" | grep -oE '[0-9]+\.[0-9]+' | tail -1)
  echo "$n,${vcpkg:-},${pure:-},${zk:-},${total:-}" >> "$CSV"
done

echo "Wrote $CSV"
column -t -s, "$CSV"
