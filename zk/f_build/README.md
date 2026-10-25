# F_build Circuit

Proves that a private Kaniko build log matches a public commitment and that the build exited with code 0.

## Design

The TEE computes `SHA-256(full_build_log)` and splits the 32-byte digest into two 128-bit BN254 field elements. 128 bits fits comfortably within the BN254 scalar field prime (~2^254), so no modular reduction occurs and the encoding is a bijection over all SHA-256 outputs.

```
sha256_hi = bytes  0-15  (big-endian 128-bit integer)
sha256_lo = bytes 16-31  (big-endian 128-bit integer)
```

SHA-256 is computed inside the attested enclave. The circuit binds the digest to the public commitment and enforces `exit_code == 0` in-circuit.

## Claim

The prover knows:

```text
private sha256_hi         bytes  0-15 of SHA-256(full build log)
private sha256_lo         bytes 16-31 of SHA-256(full build log)
private build_exit_code
```

such that:

```
Poseidon(sha256_hi, sha256_lo, build_exit_code) == public build_log_hash
build_exit_code == 0
```

## Public input

`build_log_hash` — all other signals are private witnesses.

