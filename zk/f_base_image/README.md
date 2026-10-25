# F_base_image Merkle Membership Circuit

Proves the final-stage base image digest used by Party B's TEE build is a member of Party A's approved base-image allowlist, without revealing which approved base it is.

Unlike `f_packages`, the used side is a **single** digest (one final-stage `FROM`), so there is no used-side subtree — the used commitment blinds the digest directly, and the membership check runs with `enabled` hardwired to 1.

## Claim

```
approved_base_commitment = Poseidon(approved_base_root, r_base_decl)
used_base_commitment     = Poseidon(used_base_digest,   r_base_used)
used_base_digest ∈ Merkle tree rooted at approved_base_root
```

Public inputs:

- `approved_base_commitment`
- `used_base_commitment`

Private witnesses:

- `approved_base_root`, `r_base_decl` — policy side (Party A)
- `merkle_path_elements[DEPTH]`, `merkle_path_indices[DEPTH]` — membership path
- `used_base_digest`, `r_base_used` — TEE side (Party B); the single sha256 base digest, field-reduced to BN254

## Parameters

`FBaseImage(APPROVED_TREE_DEPTH)` — compiled at **depth 3** (8-slot approved tree).
Across the 5-build ladder only ~2 distinct Alpine digests appear
(`alpine:3.24` for haproxy/httpd/postgres, `alpine:3.21` for redis), so 8 slots leave
room for Party A to approve additional patched Alpine versions without recompiling.

The leaf is the base image sha256 digest itself (field-reduced) — a base image is one
atomic digest, not a `Poseidon(name, version)` pair.

The `MerkleMembershipMasked` template is shared (copied) from the same source as
`f_packages`; the difference-trick node ordering and `pathIndices ∈ {0,1}` checks are identical.
