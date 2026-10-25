const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { buildPoseidon } = require("circomlibjs");

/*
  Encodes a 32-byte SHA-256 digest as two 128-bit BN254 field elements.

  The BN254 scalar field prime is ~2^254. Splitting into two 16-byte (128-bit)
  halves guarantees both values are well below the field prime, so no modular
  reduction occurs and the encoding is a bijection over all SHA-256 outputs.

    sha256_hi = bytes  0-15 as a big-endian 128-bit integer
    sha256_lo = bytes 16-31 as a big-endian 128-bit integer
*/
function sha256ToFieldElements(digest) {
  const sha256_hi = BigInt("0x" + digest.slice(0, 16).toString("hex")).toString();
  const sha256_lo = BigInt("0x" + digest.slice(16, 32).toString("hex")).toString();
  return { sha256_hi, sha256_lo };
}

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  /*
    Mock TEE Trivy scan log.

    In the real pipeline:
      - TEE runs: trivy image --input /output/image.tar --severity CRITICAL --exit-code 1
      - TEE captures stdout+stderr to /tmp/scan.log
      - TEE computes SHA-256(/tmp/scan.log) → 32-byte digest
      - TEE reads exit code from /tmp/scan_exit_code
      - TEE encodes digest as (sha256_hi, sha256_lo) field elements
      - TEE computes scan_log_hash = Poseidon(sha256_hi, sha256_lo, exit_code)
      - TEE places scan_log_hash in report_data for TEE attestation
  */
  const rawScanLog = `
2024-01-15T10:23:45.123Z INFO    Vulnerability scanning is enabled
2024-01-15T10:23:45.234Z INFO    Secret scanning is enabled
2024-01-15T10:23:46.001Z INFO    Loading /output/image.tar
2024-01-15T10:23:47.500Z INFO    Detected OS: alpine 3.19.0
2024-01-15T10:23:48.200Z INFO    Scanning for vulnerabilities...
2024-01-15T10:23:49.800Z INFO    No critical vulnerabilities found.

alpine:3.19.0 (alpine 3.19.0)
=================================
Total: 0 (CRITICAL: 0)
`;

  const digest = crypto.createHash("sha256").update(rawScanLog, "utf8").digest();
  const { sha256_hi, sha256_lo } = sha256ToFieldElements(digest);

  const scan_exit_code = "0";

  // scan_log_hash = Poseidon(sha256_hi, sha256_lo, scan_exit_code)
  const scan_log_hash = F.toString(
    poseidon([BigInt(sha256_hi), BigInt(sha256_lo), BigInt(scan_exit_code)])
  );

  const input = {
    sha256_hi,
    sha256_lo,
    scan_exit_code,
    scan_log_hash,
  };

  const outPath = path.join(__dirname, "..", "inputs", "input.json");
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(input, null, 2));

  console.log("Generated inputs/input.json");
  console.log("sha256_hi (bytes 0-15):", sha256_hi);
  console.log("sha256_lo (bytes 16-31):", sha256_lo);
  console.log("Public scan_log_hash:", scan_log_hash);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
