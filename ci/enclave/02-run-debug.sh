#!/usr/bin/env bash
#
# 02-run-debug.sh — sanity run in DEBUG mode (PCRs are ZERO here — logs only).
# Starts the vsock listener in the background (so the output bundle is still
# captured) and attaches the console so you can watch the build + timing block.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EIF="$HERE/tee-build.eif"
OUTDIR="$HERE/enclave-out"
mkdir -p "$OUTDIR"

nitro-cli terminate-enclave --all >/dev/null 2>&1 || true

python3 "$HERE/host-listener.py" 5005 "$OUTDIR/debug-run.tar.gz" &
LPID=$!
sleep 1

nitro-cli run-enclave \
  --eif-path "$EIF" \
  --cpu-count 2 \
  --memory 3072 \
  --enclave-cid 16 \
  --debug-mode

EID=$(nitro-cli describe-enclaves | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d[0]["EnclaveID"])')
echo "[run-debug] console (Ctrl-C to detach). PCRs are ZERO in debug mode."
nitro-cli console --enclave-id "$EID" || true

wait "$LPID" 2>/dev/null || true
nitro-cli terminate-enclave --all >/dev/null 2>&1 || true
echo "[run-debug] bundle (if captured): $OUTDIR/debug-run.tar.gz"
