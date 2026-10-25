pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";

/*
  F_scan

  The TEE runs Trivy against the produced OCI image and computes
  SHA-256(full_scan_log), splitting the 32-byte digest into two 128-bit
  BN254 field elements:
    sha256_hi = bytes  0-15 interpreted as a big-endian 128-bit integer
    sha256_lo = bytes 16-31 interpreted as a big-endian 128-bit integer

  128 bits is well within the BN254 scalar field prime (~2^254), so no modular
  reduction occurs and the encoding is a bijection — all SHA-256 security
  properties (collision resistance, preimage resistance) are preserved.

  SHA-256 is computed inside the attested enclave; the circuit binds the digest
  to the public commitment and enforces scan_exit_code == 0 in-circuit.
  Trivy exit 0 means no CRITICAL CVEs were found in the produced OCI image.

  Replaces the C++ pipeline's f_test: for containers, "passed a vulnerability
  scan" is the policy a sovereign operator actually needs.

  Private:
    sha256_hi        bytes  0-15 of SHA-256(full Trivy scan log)
    sha256_lo        bytes 16-31 of SHA-256(full Trivy scan log)
    scan_exit_code   Trivy exit code (constrained to 0 = no CRITICAL CVEs)

  Public:
    scan_log_hash = Poseidon(sha256_hi, sha256_lo, scan_exit_code)
*/

template FScan() {
    signal input sha256_hi;
    signal input sha256_lo;
    signal input scan_exit_code;
    signal input scan_log_hash;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== sha256_hi;
    hasher.inputs[1] <== sha256_lo;
    hasher.inputs[2] <== scan_exit_code;

    hasher.out === scan_log_hash;
    scan_exit_code === 0;
}

component main { public [scan_log_hash] } = FScan();
