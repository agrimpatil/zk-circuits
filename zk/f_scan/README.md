# F_scan Circuit

Proves that a private Trivy vulnerability-scan log matches a public commitment and that the scan exited with code 0 (no CRITICAL CVEs in the produced OCI image).

Replaces the C++ pipeline's `f_test`: for containers, "passed a vulnerability scan" is the policy a sovereign operator actually needs, not "unit tests passed".

## Design

The TEE runs Trivy against the produced OCI image and computes `SHA-256(full_scan_log)`, splitting the 32-byte digest into two 128-bit BN254 field elements. 128 bits fits comfortably within the BN254 scalar field prime (~2^254), so no modular reduction occurs and the encoding is a bijection over all SHA-256 outputs.

```
sha256_hi = bytes  0-15  (big-endian 128-bit integer)
sha256_lo = bytes 16-31  (big-endian 128-bit integer)
```

SHA-256 is computed inside the attested enclave. The circuit binds the digest to the public commitment and enforces `scan_exit_code == 0` in-circuit.

## Claim

The prover knows:

```text
private sha256_hi         bytes  0-15 of SHA-256(full Trivy scan log)
private sha256_lo         bytes 16-31 of SHA-256(full Trivy scan log)
private scan_exit_code
```

such that:

```
Poseidon(sha256_hi, sha256_lo, scan_exit_code) == public scan_log_hash
scan_exit_code == 0        # Trivy exit 0 = no CRITICAL CVEs
```

## Public input

`scan_log_hash` — all other signals are private witnesses, so the scan log stays confidential while Party C still learns the image passed.

