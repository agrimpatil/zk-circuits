pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";

include "./merkle_membership.circom";

/*
  F_base_image

  Proves the final-stage base image digest actually used by Party B's TEE build
  is a member of Party A's approved base-image allowlist (Merkle tree), without
  revealing which approved base it is.

  Unlike f_packages, the used side is a SINGLE digest (one final-stage FROM),
  so there is no used-side subtree: the used commitment blinds the digest directly.

  Public:
    approved_base_commitment   = Poseidon(approved_base_root, r_base_decl)
    used_base_commitment       = Poseidon(used_base_digest, r_base_used)

  Private (approved / policy side):
    approved_base_root         Merkle root over approved Alpine base digests
    r_base_decl                Party A's blinding factor
    merkle_path_elements[DEPTH]
    merkle_path_indices[DEPTH]

  Private (used / TEE side):
    used_base_digest           the single sha256 base digest, field-reduced to BN254
    r_base_used                Party B's blinding factor
*/

template FBaseImage(APPROVED_TREE_DEPTH) {
    // -------------------------------------------------
    // Public inputs
    // -------------------------------------------------
    signal input approved_base_commitment;
    signal input used_base_commitment;

    // -------------------------------------------------
    // Private inputs from policy side
    // -------------------------------------------------
    signal input approved_base_root;
    signal input r_base_decl;

    signal input merkle_path_elements[APPROVED_TREE_DEPTH];
    signal input merkle_path_indices[APPROVED_TREE_DEPTH];

    // -------------------------------------------------
    // Private inputs from TEE side
    // -------------------------------------------------
    signal input used_base_digest;
    signal input r_base_used;

    // -------------------------------------------------
    // 1. approved_base_commitment = Poseidon(approved_base_root, r_base_decl)
    // -------------------------------------------------
    component approvedCommitmentHasher = Poseidon(2);
    approvedCommitmentHasher.inputs[0] <== approved_base_root;
    approvedCommitmentHasher.inputs[1] <== r_base_decl;

    approvedCommitmentHasher.out === approved_base_commitment;

    // -------------------------------------------------
    // 2. used_base_commitment = Poseidon(used_base_digest, r_base_used)
    // -------------------------------------------------
    component usedCommitmentHasher = Poseidon(2);
    usedCommitmentHasher.inputs[0] <== used_base_digest;
    usedCommitmentHasher.inputs[1] <== r_base_used;

    usedCommitmentHasher.out === used_base_commitment;

    // -------------------------------------------------
    // 3. used_base_digest is a member of approved_base_root
    //    enabled hardwired to 1 (there is always exactly one base image)
    // -------------------------------------------------
    component membership = MerkleMembershipMasked(APPROVED_TREE_DEPTH);
    membership.leaf <== used_base_digest;
    membership.root <== approved_base_root;
    membership.enabled <== 1;

    for (var j = 0; j < APPROVED_TREE_DEPTH; j++) {
        membership.pathElements[j] <== merkle_path_elements[j];
        membership.pathIndices[j] <== merkle_path_indices[j];
    }
}

component main { public [approved_base_commitment, used_base_commitment] } = FBaseImage(3);
