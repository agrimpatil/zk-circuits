#!/usr/bin/env bash
#
# 03-run-measured.sh [N] — N real (non-debug) runs with genuine PCR measurements.
# No console in non-debug mode, so each run's outputs (witnesses, tee_report.json,
# attestation.cbor, and the timing block) come back over vsock into enclave-out/.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EIF="$HERE/tee-build.eif"
RUNS="${1:-10}"
OUTDIR="$HERE/enclave-out"
mkdir -p "$OUTDIR"

for i in $(seq 1 "$RUNS"); do
  echo "=== run $i/$RUNS ==="
  nitro-cli terminate-enclave --all >/dev/null 2>&1 || true

  python3 "$HERE/host-listener.py" 5005 "$OUTDIR/run-$i.tar.gz" &
  LPID=$!
  sleep 1

  nitro-cli run-enclave \
    --eif-path "$EIF" \
    --cpu-count 2 \
    --memory 3072 \
    --enclave-cid 16

  # Block until the enclave finishes sending its bundle.
  wait "$LPID"
  nitro-cli terminate-enclave --all >/dev/null 2>&1 || true

  # Pull out the stdout log (holds the timing block) for a quick view.
  tar -xzf "$OUTDIR/run-$i.tar.gz" -C "$OUTDIR" tee-build/tee_build_stdout.log 2>/dev/null || true
  if [ -f "$OUTDIR/tee-build/tee_build_stdout.log" ]; then
    mv "$OUTDIR/tee-build/tee_build_stdout.log" "$OUTDIR/run-$i.log"
    rm -rf "$OUTDIR/tee-build"
    echo "--- run $i timing ---"
    grep -E 'fetch time|Pure build|ZK overhead|Total' "$OUTDIR/run-$i.log" || true
  fi
done

echo "All runs saved under $OUTDIR"
