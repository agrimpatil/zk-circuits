pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";

/*
  F_scan

  Private:
    scan_log_chunks[MAX_LOG_CHUNKS]
    scan_exit_code

  Public:
    scan_log_hash

  Hash style:
    h0 = Poseidon(chunk_1, chunk_2)
    h1 = Poseidon(h0, chunk_3)
    ...
    final_hash = Poseidon(h_last, scan_exit_code)

  Claim:
    Poseidon-chained private Trivy scan log == public scan_log_hash
    scan_exit_code == 0   (Trivy exit 0 = no CRITICAL CVEs in the produced image)

  Replaces the C++ pipeline's f_test. Operationally meaningful for containers:
  proves the produced OCI image passed a vulnerability scan with no critical findings,
  while keeping the scan log confidential.
*/

template FScan(MAX_LOG_CHUNKS) {
    signal input scan_log_chunks[MAX_LOG_CHUNKS];

    signal input scan_exit_code;

    signal input scan_log_hash;

    // Need at least 2 chunks: h0 = Poseidon(chunk_1, chunk_2)
    component chunk_hashes[MAX_LOG_CHUNKS - 1];

    // h0 = Poseidon(chunk_1, chunk_2)
    chunk_hashes[0] = Poseidon(2);
    chunk_hashes[0].inputs[0] <== scan_log_chunks[0];
    chunk_hashes[0].inputs[1] <== scan_log_chunks[1];

    // h_i = Poseidon(h_{i-1}, chunk_{i+2})
    for (var i = 1; i < MAX_LOG_CHUNKS - 1; i++) {
        chunk_hashes[i] = Poseidon(2);
        chunk_hashes[i].inputs[0] <== chunk_hashes[i - 1].out;
        chunk_hashes[i].inputs[1] <== scan_log_chunks[i + 1];
    }

    // final_hash = Poseidon(h_last, scan_exit_code)
    component final_hasher = Poseidon(2);
    final_hasher.inputs[0] <== chunk_hashes[MAX_LOG_CHUNKS - 2].out;
    final_hasher.inputs[1] <== scan_exit_code;

    // Public hash check
    scan_log_hash === final_hasher.out;

    // Exit-code constraint (0 = no critical CVEs)
    scan_exit_code === 0;
}

component main { public [scan_log_hash] } = FScan(16);
