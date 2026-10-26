#!/usr/bin/env node
"use strict";

/**
 * Party B (Operator) — build-tee. Runs inside the TEE in production; here it runs
 * locally with Docker-driven Kaniko + Trivy.
 *
 * Builds the image, scans it, extracts the private witnesses, computes the used-side
 * commitments (fresh random blinders), assembles report_data, and writes:
 *
 *   <OUT_DIR>/pvt-witness/f_{source,artifact,base_image,packages,build,scan}_witness.json
 *   <OUT_DIR>/public_inputs.json
 *   <OUT_DIR>/tee_report.json
 *
 * report_data = SHA256( used_source_commitment | used_base_commitment |
 *                       used_pkgs_commitment | build_log_hash | scan_log_hash |
 *                       used_artifact_commitment )
 *
 * Env:
 *   IMAGE     image key (default: haproxy)
 *   SRC_REPO  src repo root (default: ../../../../zk-src-repo)
 *   OUT_DIR   output dir (default: <cwd>/.oci-run/<image>/partyB)
 */

const fs   = require("fs");
const path = require("path");
const P       = require("./lib/poseidon");
const img     = require("./lib/images");
const measure = require("./lib/measure");

async function main() {
  const image  = process.env.IMAGE || "haproxy";
  const cfg     = img.imageConfig(image);
  const srcRepo = process.env.SRC_REPO || path.resolve(__dirname, "../../../../zk-src-repo");
  const outDir  = process.env.OUT_DIR || path.resolve(process.cwd(), ".oci-run", image, "partyB");

  const contextDir = path.resolve(srcRepo, cfg.contextRel);
  const pvtDir     = path.join(outDir, "pvt-witness");
  fs.mkdirSync(pvtDir, { recursive: true });

  console.log(`[B] image=${image} context=${contextDir} out=${outDir}`);
  const pos = await P.initPoseidon();

  // ---- build + scan ----
  console.log(`[B] building image with Kaniko…`);
  const b = measure.buildAndInspect({ contextDir, dockerfile: cfg.dockerfile, outDir });
  if (!b.ok) throw new Error(`[B] build failed (exit ${b.buildExit}) — see ${b.buildLogPath}`);
  console.log(`[B] manifest digest = ${b.manifestDigestRef}`);

  console.log(`[B] scanning image with Trivy…`);
  const s = measure.scan({ imageTarPath: b.imageTarPath, outDir });
  console.log(`[B] trivy exit = ${s.scanExit} (0 = no CRITICAL CVEs)`);

  // ---- used-side witnesses + commitments (fresh random blinders) ----

  // f_source
  const { sourceRootHex } = measure.measureSource(contextDir);
  const used_source_root_poseidon = P.fieldReduce(sourceRootHex);
  const r_src_used = P.randomFieldElement().toString();
  const used_source_commitment = P.poseidonCommit(pos, used_source_root_poseidon, r_src_used);

  // f_artifact
  const built_artifact_root_poseidon = P.fieldReduce(b.manifestDigestHex);
  const r_art_used = P.randomFieldElement().toString();
  const built_artifact_commitment = P.poseidonCommit(pos, built_artifact_root_poseidon, r_art_used);

  // f_base_image
  const used_base_digest = P.fieldReduce(b.baseDigestHex);
  const r_base_used = P.randomFieldElement().toString();
  const used_base_commitment = P.poseidonCommit(pos, used_base_digest, r_base_used);

  // f_packages
  const used = b.packages.usedPackages;
  if (used.length > cfg.maxPackages) {
    throw new Error(`[B] ${used.length} runtime packages exceeds MAX_PACKAGES=${cfg.maxPackages}`);
  }
  const pkgLeaves = used.map((p) => P.depLeaf(pos, p.name, p.version));
  const pkgs16 = [...pkgLeaves];
  while (pkgs16.length < cfg.maxPackages) pkgs16.push("0");
  const used_pkgs_root_poseidon = P.computeUsedPackagesRoot16(pos, pkgs16);
  const r_pkgs_used = P.randomFieldElement().toString();
  const used_pkgs_commitment = P.poseidonCommit(pos, used_pkgs_root_poseidon, r_pkgs_used);

  // f_build  (SHA256(build.log) → hi/lo; exit must be 0)
  const [bHi, bLo] = P.digestToHiLo(P.fileHash(b.buildLogPath));
  const build_exit_code = String(b.buildExit);
  const build_log_hash = P.poseidonLogCommit(pos, bHi, bLo, build_exit_code);

  // f_scan   (SHA256(scan.log) → hi/lo; exit must be 0)
  const [sHi, sLo] = P.digestToHiLo(P.fileHash(s.scanLogPath));
  const scan_exit_code = String(s.scanExit);
  const scan_log_hash = P.poseidonLogCommit(pos, sHi, sLo, scan_exit_code);

  // ---- report_data (6 commitments, fixed order) ----
  const reportData = P.H(
    used_source_commitment,
    used_base_commitment,
    used_pkgs_commitment,
    build_log_hash,
    scan_log_hash,
    built_artifact_commitment,
  );

  // ---- write witnesses ----
  const W = (name, obj) =>
    fs.writeFileSync(path.join(pvtDir, name), JSON.stringify(obj, null, 2));

  W("f_source_witness.json",  { used_source_root_poseidon, r_src_used, used_source_commitment });
  W("f_artifact_witness.json", { built_artifact_root_poseidon, r_art_used, built_artifact_commitment });
  W("f_base_image_witness.json", {
    used_base_digest, used_base_digest_hex: b.baseDigestHex, r_base_used, used_base_commitment,
  });
  W("f_packages_witness.json", {
    pkgs: pkgs16,
    used_pkgs_count: String(used.length),
    used_pkgs_names: used.map((p) => `${p.name}@${p.version}`),
    used_pkgs_root_poseidon,
    r_pkgs_used,
    used_pkgs_commitment,
  });
  W("f_build_witness.json", { sha256_hi: bHi, sha256_lo: bLo, build_exit_code, build_log_hash });
  W("f_scan_witness.json",  { sha256_hi: sHi, sha256_lo: sLo, scan_exit_code, scan_log_hash });

  fs.writeFileSync(path.join(outDir, "public_inputs.json"), JSON.stringify({
    used_source_commitment,
    used_base_commitment,
    used_pkgs_commitment,
    build_log_hash,
    scan_log_hash,
    used_artifact_commitment: built_artifact_commitment,
    manifest_digest: b.manifestDigestRef,
  }, null, 2));

  fs.writeFileSync(path.join(outDir, "tee_report.json"), JSON.stringify({
    image,
    report_data: "sha256:" + reportData,
    // mocked attestation envelope for local runs; real NSM COSE doc in the enclave deliverable
    measurement: "sha256:MOCK-PCR0",
    nonce: "dummy-nonce",
    signature: "dummy-signature",
    certificate_chain: ["dummy-certificate"],
  }, null, 2));

  console.log(`[B] used packages (${used.length}): ` +
    used.map((p) => `${p.name}@${p.version}`).join(", "));
  console.log(`[B] report_data = sha256:${reportData}`);
  console.log(`[B] witnesses → ${pvtDir}`);
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
