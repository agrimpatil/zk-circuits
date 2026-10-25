# F_source Poseidon Equality Circuit

This circuit proves:

1. `declared_commitment = Poseidon(declared_source_root, r_src_decl)`
2. `used_commitment = Poseidon(used_source_root, r_src_used)`
3. `declared_source_root == used_source_root`

Public inputs:

- `declared_commitment`
- `used_commitment`

Private witnesses:

- `declared_source_root`
- `used_source_root`
- `r_src_decl` — Party A's blinding factor (declared/policy side)
- `r_src_used` — Party B's blinding factor (used/TEE side)

Meaning:

The prover proves that the policy-registered source root and the TEE-used source root are equal, without revealing the root itself.

## OCI source witness

For OCI image builds the source Merkle root is computed over the **Kaniko build
context directory only** — the version-specific subdirectory passed to
`--context=dir:///src/<project>` (e.g. `docker-library/haproxy/3.2/alpine/`), not the
full upstream repo. The docker-library repos render `.template` files into concrete
Dockerfiles; the **rendered** Dockerfile at a pinned git commit is what enters the
build context and the source commitment.

Each commitment uses its own independent blinding factor (`r_src_decl` / `r_src_used`);
salts are never shared across circuits.
