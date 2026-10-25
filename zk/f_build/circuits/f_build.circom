pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";

/*
  F_build

  The TEE computes SHA-256(full_build_log) and splits the 32-byte digest into
  two 128-bit BN254 field elements:
    sha256_hi = bytes  0-15 interpreted as a big-endian 128-bit integer
    sha256_lo = bytes 16-31 interpreted as a big-endian 128-bit integer

  128 bits is well within the BN254 scalar field prime (~2^254), so no modular
  reduction occurs and the encoding is a bijection — all SHA-256 security
  properties (collision resistance, preimage resistance) are preserved.

  SHA-256 is computed inside the attested enclave; the circuit binds the digest
  to the public commitment and enforces exit_code == 0 in-circuit.

  Private:
    sha256_hi         bytes  0-15 of SHA-256(full build log)
    sha256_lo         bytes 16-31 of SHA-256(full build log)
    build_exit_code   Kaniko exit code (constrained to 0)

  Public:
    build_log_hash = Poseidon(sha256_hi, sha256_lo, build_exit_code)
*/

template FBuild() {
    signal input sha256_hi;
    signal input sha256_lo;
    signal input build_exit_code;
    signal input build_log_hash;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== sha256_hi;
    hasher.inputs[1] <== sha256_lo;
    hasher.inputs[2] <== build_exit_code;

    hasher.out === build_log_hash;
    build_exit_code === 0;
}

component main { public [build_log_hash] } = FBuild();
