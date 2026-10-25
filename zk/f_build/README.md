# F_build Circuit

This circuit proves that a private build log record matches a public build log hash and that the build exited with code 0.

## Claim

The prover knows:

```text
private build_log_chunks[16]
private build_exit_code
```
such that:

```
h0        = Poseidon(build_log_chunks[0], build_log_chunks[1])
h_i       = Poseidon(h_{i-1}, build_log_chunks[i+1])   for i = 1..14
final     = Poseidon(h_last, build_exit_code)

final == public build_log_hash
build_exit_code == 0
```

## Single exit code

For OCI image builds the build is a single Kaniko invocation, so one exit code is
bound into the final hash (the C++ pipeline bound three stage exit codes via an
arity-4 final Poseidon). This keeps the operational build log confidential while
proving the build completed successfully.

Public input: `build_log_hash`. All chunks and the exit code are private witnesses.
