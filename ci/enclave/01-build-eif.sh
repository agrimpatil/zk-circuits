#!/usr/bin/env bash
#
# 01-build-eif.sh — build the enclave Docker image and convert it to an .eif.
# Prints the real PCR0/1/2 measurements; pin PCR0 into
# zk-src-repo/policy_register/tee_measurement_policy.json for genuine verification.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"   # .../zk-POCs/zk-CICDv3 (contains zk-circuits + zk-src-repo)

IMAGE=tee-build-enclave:latest
EIF="$HERE/tee-build.eif"

echo "[build-eif] docker build (context=$ROOT)"
docker build --platform linux/amd64 \
  -f "$HERE/Dockerfile.enclave" \
  -t "$IMAGE" \
  "$ROOT"

echo "[build-eif] nitro-cli build-enclave"
nitro-cli build-enclave --docker-uri "$IMAGE" --output-file "$EIF" \
  | tee "$HERE/eif-measurements.json"

echo
echo "[build-eif] EIF: $EIF"
echo "[build-eif] PCR measurements saved to $HERE/eif-measurements.json"
echo "[build-eif] Pin PCR0 into zk-src-repo/policy_register/tee_measurement_policy.json"
