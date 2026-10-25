pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";

/*
  UsedPackagesRoot16

  Fixed depth-4 binary Merkle tree over 16 padded package leaves, built
  bottom-up with arity-2 Poseidon on each pair. Same shape as the C++
  pipeline's UsedDepsRoot8, one level deeper (8 -> 16 leaves).

    16 leaves -> 8 nodes -> 4 nodes -> 2 nodes -> root
*/

template UsedPackagesRoot16() {
    signal input pkgs[16];
    signal output root;

    component h0[8];
    signal level1[8];

    component h1[4];
    signal level2[4];

    component h2[2];
    signal level3[2];

    component h3;

    for (var i = 0; i < 8; i++) {
        h0[i] = Poseidon(2);
        h0[i].inputs[0] <== pkgs[2 * i];
        h0[i].inputs[1] <== pkgs[2 * i + 1];
        level1[i] <== h0[i].out;
    }

    for (var i = 0; i < 4; i++) {
        h1[i] = Poseidon(2);
        h1[i].inputs[0] <== level1[2 * i];
        h1[i].inputs[1] <== level1[2 * i + 1];
        level2[i] <== h1[i].out;
    }

    for (var i = 0; i < 2; i++) {
        h2[i] = Poseidon(2);
        h2[i].inputs[0] <== level2[2 * i];
        h2[i].inputs[1] <== level2[2 * i + 1];
        level3[i] <== h2[i].out;
    }

    h3 = Poseidon(2);
    h3.inputs[0] <== level3[0];
    h3.inputs[1] <== level3[1];

    root <== h3.out;
}
