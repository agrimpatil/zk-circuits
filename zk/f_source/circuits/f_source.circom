pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";

template FSource() {
    // Public inputs
    signal input declared_commitment;
    signal input used_commitment;

    // Private witnesses
    signal input declared_source_root;
    signal input used_source_root;
    signal input r_src_decl;   // Party A's blinding factor for the declared source commitment
    signal input r_src_used;   // Party B's blinding factor for the used source commitment

    // Commit(declared_source_root, r_src_decl)
    component declaredHasher = Poseidon(2);
    declaredHasher.inputs[0] <== declared_source_root;
    declaredHasher.inputs[1] <== r_src_decl;

    // Commit(used_source_root, r_src_used)
    component usedHasher = Poseidon(2);
    usedHasher.inputs[0] <== used_source_root;
    usedHasher.inputs[1] <== r_src_used;

    // Check commitment openings
    declaredHasher.out === declared_commitment;
    usedHasher.out === used_commitment;

    // Core equality constraint
    declared_source_root === used_source_root;
}

component main { public [declared_commitment, used_commitment] } = FSource();
