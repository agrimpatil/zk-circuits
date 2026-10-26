#!/usr/bin/env node
"use strict";

/**
 * Party A (Vendor) — reference build → policy register.
 *
 * Builds the image once (reference build), then derives and writes the declared
 * commitments + approved allowlists the verifier checks against:
 *
 *   <SRC_REPO>/policy_register/<image>/declared_source.json
 *   <SRC_REPO>/policy_register/<image>/declared_artifact.json
 *   <SRC_REPO>/policy_register/<image>/approved_base_images.json
 *   <SRC_REPO>/policy_register/<image>/approved_packages.json
 *
 * For this first green run the approved sets = the reference build's actual base
 * digest and package set (self-consistent). Curated supersets come later.
 *
 * Env:
 *   IMAGE      image key (default: haproxy)
 *   SRC_REPO   src repo root (default: ../../../../zk-src-repo from this file)
 *   OUT_DIR    scratch build dir (default: <cwd>/.oci-run/<image>/partyA)
 */

const fs   = require("fs");
const path = require("path");
const P      = require("./lib/poseidon");
const img    = require("./lib/images");
const measure = require("./lib/measure");

async function main() {
  const image   = process.env.IMAGE || "haproxy";
  const cfg      = img.imageConfig(image);
  const srcRepo  = process.env.SRC_REPO ||
    path.resolve(__dirname, "../../../../zk-src-repo");
  const outDir   = process.env.OUT_DIR ||
    path.resolve(process.cwd(), ".oci-run", image, "partyA");

  const contextDir = path.resolve(srcRepo, cfg.contextRel);
  const policyDir  = path.resolve(srcRepo, "policy_register", image);
  fs.mkdirSync(outDir, { recursive: true });
  fs.mkdirSync(policyDir, { recursive: true });

  console.log(`[A] image=${image} context=${contextDir}`);
  console.log(`[A] policy_register → ${policyDir}`);

  const pos = await P.initPoseidon();

  // ---- declared_source: Merkle(sha256) over the build context ----
  const { sourceRootHex, filesHashed } = measure.measureSource(contextDir);
  const declared_source_root_poseidon = P.fieldReduce(sourceRootHex);
  const r_src_decl = P.randomFieldElement().toString();
  const declared_source_commitment = P.poseidonCommit(pos, declared_source_root_poseidon, r_src_decl);
  fs.writeFileSync(path.join(policyDir, "declared_source.json"), JSON.stringify({
    source_root_sha256: sourceRootHex,
    files_hashed: filesHashed,
    declared_source_root_poseidon,
    r_src_decl,
    declared_source_commitment,
  }, null, 2));
  console.log(`[A] declared_source: ${filesHashed} files, root=${sourceRootHex.slice(0, 16)}…`);

  // ---- reference build ----
  console.log(`[A] building reference image with Kaniko…`);
  const b = measure.buildAndInspect({ contextDir, dockerfile: cfg.dockerfile, outDir });
  if (!b.ok) throw new Error(`[A] reference build failed (exit ${b.buildExit}) — see ${b.buildLogPath}`);
  console.log(`[A] manifest digest = ${b.manifestDigestRef}`);
  console.log(`[A] base digest     = sha256:${b.baseDigestHex}`);
  console.log(`[A] used packages (${b.packages.usedPackages.length}): ` +
    b.packages.usedPackages.map((p) => `${p.name}@${p.version}`).join(", "));

  // ---- declared_artifact: OCI manifest digest ----
  const declared_artifact_root_poseidon = P.fieldReduce(b.manifestDigestHex);
  const r_art_decl = P.randomFieldElement().toString();
  const declared_artifact_commitment = P.poseidonCommit(pos, declared_artifact_root_poseidon, r_art_decl);
  fs.writeFileSync(path.join(policyDir, "declared_artifact.json"), JSON.stringify({
    manifest_digest: b.manifestDigestRef,
    declared_artifact_root_poseidon,
    r_art_decl,
    declared_artifact_commitment,
  }, null, 2));

  // ---- approved_base_images: depth-3 tree over approved base digests ----
  const baseLeaf = P.fieldReduce(b.baseDigestHex);
  const baseTree = P.buildMerkleTree(pos, [baseLeaf], cfg.approvedBaseDepth);
  const r_base_decl = P.randomFieldElement().toString();
  const approved_base_commitment = P.poseidonCommit(pos, baseTree.root, r_base_decl);
  const basePath = P.getMerklePath(baseTree, 0, cfg.approvedBaseDepth);
  fs.writeFileSync(path.join(policyDir, "approved_base_images.json"), JSON.stringify({
    tree_depth: cfg.approvedBaseDepth,
    approved_base_root: baseTree.root,
    r_base_decl,
    approved_base_commitment,
    bases: {
      [b.baseDigestHex]: {
        leaf: baseLeaf,
        pathElements: basePath.pathElements,
        pathIndices: basePath.pathIndices,
      },
    },
  }, null, 2));

  // ---- approved_packages: depth-6 tree over approved package leaves ----
  const used = b.packages.usedPackages; // sorted by name
  const pkgLeaves = used.map((p) => P.depLeaf(pos, p.name, p.version));
  const pkgTree = P.buildMerkleTree(pos, pkgLeaves, cfg.approvedPkgsDepth);
  const r_pkgs_decl = P.randomFieldElement().toString();
  const approved_pkgs_commitment = P.poseidonCommit(pos, pkgTree.root, r_pkgs_decl);
  const packages = {};
  used.forEach((p, i) => {
    const mp = P.getMerklePath(pkgTree, i, cfg.approvedPkgsDepth);
    packages[`${p.name}@${p.version}`] = {
      leaf: pkgLeaves[i],
      pathElements: mp.pathElements,
      pathIndices: mp.pathIndices,
    };
  });
  fs.writeFileSync(path.join(policyDir, "approved_packages.json"), JSON.stringify({
    tree_depth: cfg.approvedPkgsDepth,
    max_packages: cfg.maxPackages,
    approved_pkgs_root: pkgTree.root,
    r_pkgs_decl,
    approved_pkgs_commitment,
    packages,
  }, null, 2));

  console.log(`[A] policy register written for '${image}'.`);
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
