#!/bin/sh
# Enclave entrypoint. Runs tee_build.js with real NSM attestation, then ships
# the outputs (private witnesses, tee_report.json, attestation.cbor, and the
# captured stdout containing the timing block) back to the parent EC2 instance
# over vsock. A non-debug enclave has no console, so vsock is the only way out.
set -eu

# Parent (host) always has vsock CID 3. host-listener.py binds VSOCK_PORT.
PARENT_CID="${PARENT_CID:-3}"
VSOCK_PORT="${VSOCK_PORT:-5005}"

OUT_DIR="/work/tee-build"
S3_OUT_DIR="$OUT_DIR/s3-output"

export REPO_DIR=/work/src-repo
export OUT_DIR
export S3_OUT_DIR
export VCPKG_ROOT=/opt/vcpkg
export VCPKG_INSTALLED_DIR=/opt/vcpkg-installed
export NSM_ATTEST=1
export NSM_ATTEST_BIN=/usr/local/bin/nsm-attest

mkdir -p "$OUT_DIR"

# Capture stdout+stderr; the "--- Time Measurements ---" block lives here.
LOG="$OUT_DIR/tee_build_stdout.log"
node /work/cicd-repo/ci/scripts/tee_build.js 2>&1 | tee "$LOG"

# Bundle the whole output tree (pvt-witness + s3-output + log) and send it.
BUNDLE=/work/enclave-out.tar.gz
tar -czf "$BUNDLE" -C /work tee-build

echo "[enclave-run] sending $(wc -c < "$BUNDLE") bytes to parent CID ${PARENT_CID}:${VSOCK_PORT}"
python3 /work/vsock-send.py "$PARENT_CID" "$VSOCK_PORT" "$BUNDLE"
echo "[enclave-run] done"
