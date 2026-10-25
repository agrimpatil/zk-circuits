const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { buildPoseidon } = require("circomlibjs");

/*
  Encodes a 32-byte SHA-256 digest as two 128-bit BN254 field elements.

  The BN254 scalar field prime is ~2^254. Splitting into two 16-byte (128-bit)
  halves guarantees both values are well below the field prime, so no modular
  reduction occurs and the encoding is a bijection.

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
    Mock TEE Kaniko build log.

    In the real pipeline:
      - TEE runs Kaniko, captures stdout+stderr to /tmp/build.log
      - TEE computes SHA-256(/tmp/build.log) → 32-byte digest
      - TEE reads exit code from /tmp/build_exit_code
      - TEE encodes digest as (sha256_hi, sha256_lo) field elements
      - TEE computes build_log_hash = Poseidon(sha256_hi, sha256_lo, exit_code)
      - TEE places build_log_hash in report_data for TEE attestation
  */
  const rawBuildLog = `
INFO[0000] Retrieving image manifest alpine:3.19
INFO[0001] Unpacking rootfs as cmd RUN apk add --no-cache gcc musl-dev make
INFO[0005] Taking snapshot of full filesystem...
INFO[0010] RUN wget https://download.redis.io/redis-7.2.4.tar.gz
INFO[0045] RUN tar xzf redis-7.2.4.tar.gz
INFO[0046] RUN make -C redis-7.2.4 -j4
INFO[0120] Build complete.
`;

  const digest = crypto.createHash("sha256").update(rawBuildLog, "utf8").digest();
  const { sha256_hi, sha256_lo } = sha256ToFieldElements(digest);

  const build_exit_code = "0";

  // build_log_hash = Poseidon(sha256_hi, sha256_lo, build_exit_code)
  const build_log_hash = F.toString(
    poseidon([BigInt(sha256_hi), BigInt(sha256_lo), BigInt(build_exit_code)])
  );

  const input = {
    sha256_hi,
    sha256_lo,
    build_exit_code,
    build_log_hash,
  };

  const outPath = path.join(__dirname, "..", "inputs", "input.json");
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(input, null, 2));

  console.log("Generated inputs/input.json");
  console.log("sha256_hi (bytes 0-15):", sha256_hi);
  console.log("sha256_lo (bytes 16-31):", sha256_lo);
  console.log("Public build_log_hash:", build_log_hash);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});