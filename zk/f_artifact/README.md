# F_artifact Poseidon Equality Circuit

This circuit proves:

1. `declared_commitment = Poseidon(declared_artifact_hash, r_art_decl)`
2. `used_commitment = Poseidon(built_artifact_hash, r_art_used)`
3. `declared_artifact_hash == built_artifact_hash`

Public inputs:

- `declared_commitment`
- `used_commitment`

Private witnesses:

- `declared_artifact_hash`
- `built_artifact_hash`
- `r_art_decl` — Party A's blinding factor (declared/policy side)
- `r_art_used` — Party B's blinding factor (built/TEE side)

Meaning:

The prover proves that the artifact hash declared in the policy registry equals the artifact hash produced by the TEE build, without revealing the artifact hash itself.

## OCI artifact witness

The circuit is unchanged from the C++ pipeline — only the witness meaning changes.
For OCI builds, `declared_artifact_hash` / `built_artifact_hash` are the SHA256 digest
of the **OCI image manifest** (the `sha256:...` read from `manifest.json` inside the
Kaniko-produced `image.tar`), field-reduced into BN254.

Party A establishes `declared_artifact_hash` from a canonical reference build and commits
it to the policy register — the same model as a published `SHA256SUMS` for a Linux ISO.
This requires a deterministic build: base image pinned by digest
(`FROM alpine:X.Y@sha256:...`) and apk package versions pinned (`apk add pkg=X.Y.Z-rN`).

Each commitment uses its own independent blinding factor (`r_art_decl` / `r_art_used`).
