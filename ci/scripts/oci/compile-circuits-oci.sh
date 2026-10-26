#!/usr/bin/env bash
#
# Compile the 6 OCI circuits once and stage wasm + zkey + vkey into compiled/.
# Reused across all ladder images (the circuits are build-independent).
#
# ptau: f_source/f_artifact/f_base_image/f_build/f_scan -> pot12 (all small);
#       f_packages -> pot16 (~28k constraints).
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"        # zk-circuits/
ZK="$ROOT/zk"
PTAU="$ZK/ptau_keys"
OUT="$ROOT/compiled"
SNARKJS="$ZK/node_modules/.bin/snarkjs"

[ -x "$SNARKJS" ] || { echo "snarkjs not found at $SNARKJS — run 'npm install' in $ZK"; exit 1; }
command -v circom >/dev/null || { echo "circom not on PATH"; exit 1; }

mkdir -p "$OUT"

compile_circuit() {
  local name="$1" ptau="$2"
  local dir="$ZK/$name"
  echo "=== compile $name (ptau=$ptau) ==="
  ( cd "$dir"
    mkdir -p build
    circom "circuits/$name.circom" --r1cs --wasm --sym -o build
    "$SNARKJS" groth16 setup "build/$name.r1cs" "$PTAU/$ptau" "build/${name}_0000.zkey"
    "$SNARKJS" zkey contribute "build/${name}_0000.zkey" "build/${name}_final.zkey" \
      --name="oci-contribution" -v -e="$(head -c 32 /dev/urandom | base64)"
    "$SNARKJS" zkey export verificationkey "build/${name}_final.zkey" "build/verification_key.json"
  )
  mkdir -p "$OUT/$name"
  cp "$dir/build/${name}_js/${name}.wasm" "$OUT/$name/"
  cp "$dir/build/${name}_final.zkey"      "$OUT/$name/"
  cp "$dir/build/verification_key.json"   "$OUT/$name/"
  echo "    staged → compiled/$name/"
}

compile_circuit f_source     pot12_final.ptau
compile_circuit f_artifact   pot12_final.ptau
compile_circuit f_base_image pot12_final.ptau
compile_circuit f_build      pot12_final.ptau
compile_circuit f_scan       pot12_final.ptau
compile_circuit f_packages   pot16_final.ptau

echo "=== all 6 circuits compiled → $OUT ==="
