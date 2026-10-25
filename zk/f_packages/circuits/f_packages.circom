pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

include "./merkle_membership.circom";
include "./used_packages_root.circom";

/*
  F_packages

  Proves that every runtime package installed in Party B's final-stage OCI image
  (read from /lib/apk/db/installed, scope = explicitly-added + scanelf rundeps,
  base-alpine packages excluded) is a member of Party A's approved package
  allowlist, without revealing either the approved set or the used set.

  Mirrors the C++ pipeline's f_deps_membership, scaled MAX_DEPS 8 -> MAX_PACKAGES 16.

  Public:
    approved_pkgs_commitment = Poseidon(approved_pkgs_root, r_pkgs_decl)
    used_pkgs_commitment     = Poseidon(used_pkgs_root, r_pkgs_used)

  Private (policy side):
    approved_pkgs_root, r_pkgs_decl
    merkle_path_elements[16][APPROVED_TREE_DEPTH]
    merkle_path_indices[16][APPROVED_TREE_DEPTH]

  Private (TEE side):
    used_pkgs_root, r_pkgs_used
    used_pkgs_count
    pkgs[16]   each = Poseidon(encode(name), encode(version)), computed off-circuit;
               unused slots padded with 0
*/

template FPackages(APPROVED_TREE_DEPTH) {
    // -------------------------------------------------
    // Public inputs
    // -------------------------------------------------
    signal input approved_pkgs_commitment;
    signal input used_pkgs_commitment;

    // -------------------------------------------------
    // Private inputs from policy side
    // -------------------------------------------------
    signal input approved_pkgs_root;
    signal input r_pkgs_decl;

    // -------------------------------------------------
    // Private inputs from TEE side
    // -------------------------------------------------
    signal input used_pkgs_root;
    signal input r_pkgs_used;

    signal input used_pkgs_count;

    // MAX_PACKAGES = 16
    signal input pkgs[16];

    // Membership paths against approved_pkgs_root
    signal input merkle_path_elements[16][APPROVED_TREE_DEPTH];
    signal input merkle_path_indices[16][APPROVED_TREE_DEPTH];

    // -------------------------------------------------
    // 1. approved_pkgs_commitment = Poseidon(approved_pkgs_root, r_pkgs_decl)
    // -------------------------------------------------
    component approvedCommitmentHasher = Poseidon(2);
    approvedCommitmentHasher.inputs[0] <== approved_pkgs_root;
    approvedCommitmentHasher.inputs[1] <== r_pkgs_decl;

    approvedCommitmentHasher.out === approved_pkgs_commitment;

    // -------------------------------------------------
    // 2. used_pkgs_commitment = Poseidon(used_pkgs_root, r_pkgs_used)
    // -------------------------------------------------
    component usedCommitmentHasher = Poseidon(2);
    usedCommitmentHasher.inputs[0] <== used_pkgs_root;
    usedCommitmentHasher.inputs[1] <== r_pkgs_used;

    usedCommitmentHasher.out === used_pkgs_commitment;

    // -------------------------------------------------
    // 3. Enforce used_pkgs_count <= 16   (LessThan: count < 17)
    // -------------------------------------------------
    component countLt17 = LessThan(5);
    countLt17.in[0] <== used_pkgs_count;
    countLt17.in[1] <== 17;
    countLt17.out === 1;

    // -------------------------------------------------
    // 4. Compute enabled[i] = i < used_pkgs_count
    // -------------------------------------------------
    component isEnabled[16];
    signal enabled[16];

    for (var i = 0; i < 16; i++) {
        isEnabled[i] = LessThan(5);
        isEnabled[i].in[0] <== i;
        isEnabled[i].in[1] <== used_pkgs_count;

        enabled[i] <== isEnabled[i].out;

        // If slot disabled, package leaf must be zero.
        (1 - enabled[i]) * pkgs[i] === 0;
    }

    // -------------------------------------------------
    // 5. Verify every enabled package belongs to approved root
    // -------------------------------------------------
    component membership[16];

    for (var i = 0; i < 16; i++) {
        membership[i] = MerkleMembershipMasked(APPROVED_TREE_DEPTH);

        membership[i].leaf <== pkgs[i];
        membership[i].root <== approved_pkgs_root;
        membership[i].enabled <== enabled[i];

        for (var j = 0; j < APPROVED_TREE_DEPTH; j++) {
            membership[i].pathElements[j] <== merkle_path_elements[i][j];
            membership[i].pathIndices[j] <== merkle_path_indices[i][j];
        }
    }

    // -------------------------------------------------
    // 6. Compute MerkleRoot(padded pkgs[16]) == used_pkgs_root
    // -------------------------------------------------
    component usedRootComputer = UsedPackagesRoot16();

    for (var i = 0; i < 16; i++) {
        usedRootComputer.pkgs[i] <== pkgs[i];
    }

    usedRootComputer.root === used_pkgs_root;
}

component main { public [approved_pkgs_commitment, used_pkgs_commitment] } = FPackages(6);
