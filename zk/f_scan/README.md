# F_scan Circuit

This circuit proves that a private Trivy vulnerability-scan log matches a public scan log hash and that the scan exited with code 0 (no CRITICAL CVEs in the produced OCI image).

Replaces the C++ pipeline's `f_test`: for containers, "passed a vulnerability scan" is the policy a sovereign operator actually needs, not "unit tests passed".

## Claim

The prover knows:

```text
private scan_log_chunks[16]
private scan_exit_code
```
such that:

```
h0     = Poseidon(scan_log_chunks[0], scan_log_chunks[1])
h_i    = Poseidon(h_{i-1}, scan_log_chunks[i+1])   for i = 1..14
final  = Poseidon(h_last, scan_exit_code)

final == public scan_log_hash
scan_exit_code == 0        # Trivy exit 0 = no CRITICAL CVEs
```

Public input: `scan_log_hash`. All chunks and the exit code are private witnesses, so the scan log stays confidential while Party C still learns the image passed.
