"use strict";

/**
 * Shared cryptographic helpers for the OCI ZK build-verification pipeline.
 *
 * Ported verbatim (where noted) from the retired C++ ci/scripts/tee_build.js and
 * f_deps_membership/scripts/generate_input.js so Party A (register_declared_oci.js),
 * Party B (tee_build_oci.js) and the verifier (zk_proof_oci.js) all compute the
 * exact same field elements the compiled circuits expect.
 */

const crypto = require("crypto");
const fs     = require("fs");
const path   = require("path");
const { buildPoseidon } = require("circomlibjs");

// BN254 scalar field prime.
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ---------------------------------------------------------------------------
// SHA-256 helpers
// ---------------------------------------------------------------------------

// sha256 over the "|"-joined string of items (matches old tee_build.js H()).
function H(...items) {
  return crypto.createHash("sha256").update(items.join("|")).digest("hex");
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function fileHash(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

// ---------------------------------------------------------------------------
// Field helpers
// ---------------------------------------------------------------------------

// A non-zero random element of the BN254 field — a blinding factor.
function randomFieldElement() {
  let r;
  do {
    r = BigInt("0x" + crypto.randomBytes(32).toString("hex")) % FIELD_PRIME;
  } while (r === 0n);
  return r;
}

// Reduce a hex digest into the field (matches old artifact/source reduction).
function fieldReduce(hex) {
  return (BigInt("0x" + hex) % FIELD_PRIME).toString();
}

// Horner base-257 string encoding (matches encodeToField in the old pipeline).
function encodeToField(s) {
  let acc = 0n;
  for (let i = 0; i < s.length; i++) {
    acc = acc * 257n + BigInt(s.charCodeAt(i));
  }
  return acc % FIELD_PRIME;
}

// Split a 32-byte SHA-256 hex digest into two big-endian 128-bit field elements.
// bytes 0-15 -> hi, bytes 16-31 -> lo. 128 bits << BN254, so no reduction; bijective.
// Matches f_build/f_scan {sha256_hi, sha256_lo}.
function digestToHiLo(hex) {
  if (hex.length !== 64) throw new Error(`expected 64-hex-char sha256, got ${hex.length}`);
  const hi = BigInt("0x" + hex.slice(0, 32)).toString();
  const lo = BigInt("0x" + hex.slice(32, 64)).toString();
  return [hi, lo];
}

// ---------------------------------------------------------------------------
// Poseidon-bound helpers (pass a `poseidon` from initPoseidon())
// ---------------------------------------------------------------------------

async function initPoseidon() {
  return buildPoseidon();
}

// Poseidon(inputs) -> decimal string.
function poseidon(pos, inputs) {
  return pos.F.toObject(pos(inputs.map((x) => BigInt(x)))).toString();
}

// Commitment C = Poseidon(value, r).
function poseidonCommit(pos, value, r) {
  return poseidon(pos, [value, r]);
}

// Package/dependency leaf = Poseidon(encode(name), encode(version)).
function depLeaf(pos, name, version) {
  return poseidon(pos, [encodeToField(name), encodeToField(version)]);
}

// Log commitment = Poseidon(sha256_hi, sha256_lo, exit_code)  (f_build / f_scan).
function poseidonLogCommit(pos, hi, lo, exit) {
  return poseidon(pos, [hi, lo, exit]);
}

// ---------------------------------------------------------------------------
// SHA-256 Merkle root over the build-context tree (f_source "used/declared root")
// Matches old tee_build.js merkleRoot(): sorted leaves H(relpath, filehash),
// then unsorted pairwise H(left,right), odd node duplicated.
// ---------------------------------------------------------------------------

function walkFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkFiles(full));
    else if (entry.isFile()) out.push(full);
  }
  return out;
}

function merkleRootSha256(leaves) {
  let level = [...leaves];
  if (level.length === 0) return H("EMPTY");
  while (level.length > 1) {
    const nxt = [];
    for (let i = 0; i < level.length; i += 2) {
      const left  = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      nxt.push(H(left, right));
    }
    level = nxt;
  }
  return level[0];
}

// SHA-256 Merkle root over every file under contextDir (excluding .DS_Store).
function sourceTreeRoot(contextDir) {
  const entries = walkFiles(contextDir)
    .filter((p) => path.basename(p) !== ".DS_Store")
    .map((p) => [path.relative(contextDir, p), fileHash(p)])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const leaves = entries.map(([rel, fh]) => H(rel, fh));
  return { root: merkleRootSha256(leaves), filesHashed: entries.length };
}

// ---------------------------------------------------------------------------
// Poseidon Merkle tree (approved allowlists) — matches f_deps generate_input.js
// ---------------------------------------------------------------------------

// Build a fixed-depth Poseidon Merkle tree over `leaves` (padded to 2^depth with "0").
function buildMerkleTree(pos, leaves, depth) {
  const leafCount = 2 ** depth;
  if (leaves.length > leafCount) {
    throw new Error(`too many leaves (${leaves.length}) for depth ${depth} (max ${leafCount})`);
  }
  const padded = [...leaves];
  while (padded.length < leafCount) padded.push("0");
  const levels = [padded];
  for (let d = 0; d < depth; d++) {
    const prev = levels[d];
    const next = [];
    for (let i = 0; i < prev.length; i += 2) next.push(poseidon(pos, [prev[i], prev[i + 1]]));
    levels.push(next);
  }
  return { root: levels[depth][0], levels };
}

function getMerklePath(tree, leafIndex, depth) {
  const pathElements = [];
  const pathIndices  = [];
  let index = leafIndex;
  for (let d = 0; d < depth; d++) {
    pathElements.push(tree.levels[d][index ^ 1]);
    pathIndices.push(index % 2);
    index = Math.floor(index / 2);
  }
  return { pathElements, pathIndices };
}

// Fixed depth-4 / 16-leaf Poseidon root — matches UsedPackagesRoot16() in
// f_packages/circuits/used_packages_root.circom. Input must be length 16.
function computeUsedPackagesRoot16(pos, leaves16) {
  if (leaves16.length !== 16) throw new Error(`expected 16 leaves, got ${leaves16.length}`);
  let level = [...leaves16];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(poseidon(pos, [level[i], level[i + 1]]));
    level = next;
  }
  return level[0];
}

module.exports = {
  FIELD_PRIME,
  H, sha256Hex, fileHash,
  randomFieldElement, fieldReduce, encodeToField, digestToHiLo,
  initPoseidon, poseidon, poseidonCommit, depLeaf, poseidonLogCommit,
  walkFiles, merkleRootSha256, sourceTreeRoot,
  buildMerkleTree, getMerklePath, computeUsedPackagesRoot16,
};
