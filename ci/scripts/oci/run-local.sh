#!/usr/bin/env bash
#
# Local end-to-end driver for one OCI ladder image (default: haproxy).
#
#   compile circuits (once) → Party A policy register → Party B build-tee
#   → zk-proof (6 circuits + report_data binding) → reproducibility check
#
# Usage:  ci/scripts/oci/run-local.sh [image]
# Env:    FORCE_COMPILE=1 to recompile circuits even if compiled/ exists.
#
set -euo pipefail

IMAGE="${1:-haproxy}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"            # zk-circuits/
SRC_REPO="$(cd "$ROOT/../zk-src-repo" && pwd)"
SCRIPTS="$ROOT/ci/scripts"
RUN_DIR="$ROOT/.oci-run/$IMAGE"

export IMAGE SRC_REPO
export COMPILED_DIR="$ROOT/compiled"

echo "### image=$IMAGE  src_repo=$SRC_REPO"

# 0. deps for the JS scripts (circomlibjs + snarkjs)
[ -d "$SCRIPTS/node_modules" ] || (cd "$SCRIPTS" && npm install --no-audit --no-fund)
[ -d "$ROOT/zk/node_modules" ] || (cd "$ROOT/zk" && npm install --no-audit --no-fund)

# 1. compile circuits once
if [ "${FORCE_COMPILE:-0}" = "1" ] || [ ! -d "$COMPILED_DIR/f_packages" ]; then
  bash "$HERE/compile-circuits-oci.sh"
else
  echo "### circuits already compiled (compiled/); set FORCE_COMPILE=1 to redo"
fi

# 2. Party A — policy register (reference build)
echo "### Party A: register_declared_oci.js"
OUT_DIR="$RUN_DIR/partyA" node "$HERE/register_declared_oci.js"

# 3. Party B — build-tee (independent build + scan + witnesses)
echo "### Party B: tee_build_oci.js"
OUT_DIR="$RUN_DIR/partyB" node "$HERE/tee_build_oci.js"

# 4. reproducibility: Party A declared vs Party B produced manifest digest
#    (checked before proving so a mismatch gives a clear message, not a cryptic
#    f_artifact proof failure)
echo "### reproducibility check (A vs B manifest digest)"
A_DIGEST=$(node -e "console.log(require('$SRC_REPO/policy_register/$IMAGE/declared_artifact.json').manifest_digest)")
B_DIGEST=$(node -e "console.log(require('$RUN_DIR/partyB/public_inputs.json').manifest_digest)")
echo "    A: $A_DIGEST"
echo "    B: $B_DIGEST"
if [ "$A_DIGEST" = "$B_DIGEST" ]; then
  echo "### REPRODUCIBLE ✓  (independent A and B builds produced the same OCI digest)"
else
  echo "### NON-REPRODUCIBLE ✗  — digests differ; tighten pinning / SOURCE_DATE_EPOCH"
  echo "### (f_artifact would fail to prove; stopping here for a clear diagnostic)"
  exit 2
fi

# 5. zk-proof — 6 circuits + report_data binding
echo "### zk_proof_oci.js"
TEE_DIR="$RUN_DIR/partyB" node "$HERE/zk_proof_oci.js"

echo "### DONE: $IMAGE end-to-end OK"
