pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";

template FArtifact() {
    // Public inputs
    signal input declared_commitment;
    signal input used_commitment;

    // Private witnesses
    signal input declared_artifact_hash;
    signal input built_artifact_hash;
    signal input r_art_decl;   // Party A's blinding factor for the declared artifact commitment
    signal input r_art_used;   // Party B's blinding factor for the built artifact commitment

    // Commit(declared_artifact_hash, r_art_decl)
    component declaredHasher = Poseidon(2);
    declaredHasher.inputs[0] <== declared_artifact_hash;
    declaredHasher.inputs[1] <== r_art_decl;

    // Commit(built_artifact_hash, r_art_used)
    component usedHasher = Poseidon(2);
    usedHasher.inputs[0] <== built_artifact_hash;
    usedHasher.inputs[1] <== r_art_used;

    // Check commitment openings
    declaredHasher.out === declared_commitment;
    usedHasher.out === used_commitment;

    // Core equality constraint
    declared_artifact_hash === built_artifact_hash;
}

component main { public [declared_commitment, used_commitment] } = FArtifact();
