# F_packages Merkle Membership Circuit

Proves that every runtime package installed in Party B's final-stage OCI image is a member of Party A's approved package allowlist, without revealing either the approved set or the used set.

Scope of the used package set: packages read from `/lib/apk/db/installed` in the final
image, limited to **explicitly-installed packages + scanelf-resolved runtime deps**
(the ~15 base-alpine packages, identical across every Alpine image, are excluded).
This fits the whole 5-build ladder within 16 slots.

Mirrors the (now-removed) C++ `f_deps_membership`, scaled `MAX_DEPS 8 → MAX_PACKAGES 16`.

## Claim

```
approved_pkgs_commitment = Poseidon(approved_pkgs_root, r_pkgs_decl)
used_pkgs_commitment     = Poseidon(used_pkgs_root,     r_pkgs_used)
used_pkgs_count <= 16
for each enabled slot i (i < used_pkgs_count):
    pkgs[i] ∈ Merkle tree rooted at approved_pkgs_root
disabled slots: pkgs[i] == 0
UsedPackagesRoot16(pkgs[0..15]) == used_pkgs_root
```

Public inputs:

- `approved_pkgs_commitment`
- `used_pkgs_commitment`

Private witnesses:

- `approved_pkgs_root`, `r_pkgs_decl` — policy side (Party A)
- `used_pkgs_root`, `r_pkgs_used`, `used_pkgs_count` — TEE side (Party B)
- `pkgs[16]` — each `= Poseidon(encode(name), encode(version))` (computed off-circuit), unused slots padded with 0
- `merkle_path_elements[16][DEPTH]`, `merkle_path_indices[16][DEPTH]`

## Parameters

`FPackages(APPROVED_TREE_DEPTH)` — compiled at **depth 6** (64-slot approved allowlist),
with a fixed `MAX_PACKAGES = 16` used-package capacity and a depth-4 `UsedPackagesRoot16`
for the used-set commitment.

`APPROVED_TREE_DEPTH` is a template parameter so the circuit can be recompiled at depths
4 / 8 / 16 / 32 for the proof-time-vs-depth experiment (directly addressing the
static-circuit-bounds limitation).

## Files

- `f_packages.circom` — top-level circuit
- `merkle_membership.circom` — `MerkleMembershipMasked(DEPTH)` (shared masked path verifier)
- `used_packages_root.circom` — `UsedPackagesRoot16()` (fixed depth-4 / 16-leaf used-set root)
