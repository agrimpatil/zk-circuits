#!/usr/bin/env node
"use strict";

/**
 * Party C (Verifier) — prove + verify all 6 OCI circuits, then check the
 * TEE report_data binding (Layer 3).
 *
 * Inputs:
 *   COMPILED_DIR   compiled circuits: <dir>/<name>/{<name>.wasm,<name>_final.zkey,verification_key.json}
 *                  (default: <repo>/compiled)
 *   TEE_DIR        Party B output (pvt-witness/, tee_report.json)  (default: <cwd>/.oci-run/<image>/partyB)
 *   SRC_REPO       src repo root (default: ../../../../zk-src-repo)
 *   IMAGE          image key (default: haproxy)
 *   OUT_DIR        proof bundle output (default: <TEE_DIR>/zk-proofs)
 */

const fs      = require("fs");
const path    = require("path");
const snarkjs = require("snarkjs");
const P       = require("./lib/poseidon");
const img     = require("./lib/images");

const IMAGE    = process.env.IMAGE || "haproxy";
const cfg       = img.imageConfig(IMAGE);
const repoRoot  = path.resolve(__dirname, "../../..");            // zk-circuits/
const COMPILED  = process.env.COMPILED_DIR || path.join(repoRoot, "compiled");
const TEE_DIR   = process.env.TEE_DIR || path.resolve(process.cwd(), ".oci-run", IMAGE, "partyB");
const SRC_REPO  = process.env.SRC_REPO || path.resolve(__dirname, "../../../../zk-src-repo");
const OUT_DIR   = process.env.OUT_DIR || path.join(TEE_DIR, "zk-proofs");

const CIRCUITS = ["f_source", "f_artifact", "f_base_image", "f_packages", "f_build", "f_scan"];

function loadJSON(p) {
  if (!fs.existsSync(p)) throw new Error(`not found: ${p}`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function artifacts(name) {
  const dir = path.join(COMPILED, name);
  const a = {
    wasm: path.join(dir, `${name}.wasm`),
    zkey: path.join(dir, `${name}_final.zkey`),
    vkey: path.join(dir, "verification_key.json"),
  };
  for (const [k, v] of Object.entries(a)) {
    if (!fs.existsSync(v)) throw new Error(`missing ${k} for ${name}: ${v} (run compile-circuits-oci.sh)`);
  }
  return a;
}

function assembleInputs() {
  const pvt = (n) => loadJSON(path.join(TEE_DIR, "pvt-witness", `${n}_witness.json`));
  const pol = (n) => loadJSON(path.join(SRC_REPO, "policy_register", IMAGE, `${n}.json`));

  const wSrc = pvt("f_source"), wArt = pvt("f_artifact"), wBase = pvt("f_base_image");
  const wPkg = pvt("f_packages"), wBuild = pvt("f_build"), wScan = pvt("f_scan");
  const dSrc = pol("declared_source"), dArt = pol("declared_artifact");
  const aBase = pol("approved_base_images"), aPkg = pol("approved_packages");

  // f_base_image path for the used base digest
  const baseEntry = aBase.bases[wBase.used_base_digest_hex];
  if (!baseEntry) throw new Error(`used base digest ${wBase.used_base_digest_hex} not in approved_base_images`);

  // f_packages paths: slot i < count → path for used_pkgs_names[i]; else zeros
  const depth = aPkg.tree_depth;
  const count = parseInt(wPkg.used_pkgs_count, 10);
  const mpe = [], mpi = [];
  for (let i = 0; i < cfg.maxPackages; i++) {
    if (i < count) {
      const key = wPkg.used_pkgs_names[i];
      const e = aPkg.packages[key];
      if (!e) throw new Error(`used package '${key}' not in approved_packages`);
      mpe.push([...e.pathElements]); mpi.push([...e.pathIndices]);
    } else {
      mpe.push(Array(depth).fill("0")); mpi.push(Array(depth).fill(0));
    }
  }

  return {
    f_source: {
      declared_commitment: dSrc.declared_source_commitment,
      used_commitment: wSrc.used_source_commitment,
      declared_source_root: dSrc.declared_source_root_poseidon,
      used_source_root: wSrc.used_source_root_poseidon,
      r_src_decl: dSrc.r_src_decl,
      r_src_used: wSrc.r_src_used,
    },
    f_artifact: {
      declared_commitment: dArt.declared_artifact_commitment,
      used_commitment: wArt.built_artifact_commitment,
      declared_artifact_hash: dArt.declared_artifact_root_poseidon,
      built_artifact_hash: wArt.built_artifact_root_poseidon,
      r_art_decl: dArt.r_art_decl,
      r_art_used: wArt.r_art_used,
    },
    f_base_image: {
      approved_base_commitment: aBase.approved_base_commitment,
      used_base_commitment: wBase.used_base_commitment,
      approved_base_root: aBase.approved_base_root,
      r_base_decl: aBase.r_base_decl,
      merkle_path_elements: baseEntry.pathElements,
      merkle_path_indices: baseEntry.pathIndices,
      used_base_digest: wBase.used_base_digest,
      r_base_used: wBase.r_base_used,
    },
    f_packages: {
      approved_pkgs_commitment: aPkg.approved_pkgs_commitment,
      used_pkgs_commitment: wPkg.used_pkgs_commitment,
      approved_pkgs_root: aPkg.approved_pkgs_root,
      r_pkgs_decl: aPkg.r_pkgs_decl,
      used_pkgs_root: wPkg.used_pkgs_root_poseidon,
      r_pkgs_used: wPkg.r_pkgs_used,
      used_pkgs_count: wPkg.used_pkgs_count,
      pkgs: wPkg.pkgs,
      merkle_path_elements: mpe,
      merkle_path_indices: mpi,
    },
    f_build: {
      build_log_hash: wBuild.build_log_hash,
      sha256_hi: wBuild.sha256_hi,
      sha256_lo: wBuild.sha256_lo,
      build_exit_code: wBuild.build_exit_code,
    },
    f_scan: {
      scan_log_hash: wScan.scan_log_hash,
      sha256_hi: wScan.sha256_hi,
      sha256_lo: wScan.sha256_lo,
      scan_exit_code: wScan.scan_exit_code,
    },
    _public: {
      used_source_commitment: wSrc.used_source_commitment,
      used_base_commitment: wBase.used_base_commitment,
      used_pkgs_commitment: wPkg.used_pkgs_commitment,
      build_log_hash: wBuild.build_log_hash,
      scan_log_hash: wScan.scan_log_hash,
      used_artifact_commitment: wArt.built_artifact_commitment,
    },
  };
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const inputs = assembleInputs();

  console.log(`\n=== Proving 6 circuits for '${IMAGE}' ===`);
  const results = {};
  for (const name of CIRCUITS) {
    const { wasm, zkey, vkey } = artifacts(name);
    const input = inputs[name];
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
    const valid = await snarkjs.groth16.verify(loadJSON(vkey), publicSignals, proof);
    if (!valid) throw new Error(`proof verification FAILED for ${name}`);
    const dir = path.join(OUT_DIR, name);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "proof.json"), JSON.stringify(proof, null, 2));
    fs.writeFileSync(path.join(dir, "public.json"), JSON.stringify(publicSignals, null, 2));
    fs.copyFileSync(vkey, path.join(dir, "verification_key.json"));
    results[name] = publicSignals;
    console.log(`  [OK] ${name}: proof verified`);
  }

  // ---- Layer 3: TEE report_data binding ----
  console.log(`\n=== Layer 3: report_data binding ===`);
  const p = inputs._public;
  const recomputed = P.H(
    p.used_source_commitment,
    p.used_base_commitment,
    p.used_pkgs_commitment,
    p.build_log_hash,
    p.scan_log_hash,
    p.used_artifact_commitment,
  );
  const tee = loadJSON(path.join(TEE_DIR, "tee_report.json"));
  const expected = "sha256:" + recomputed;
  if (tee.report_data !== expected) {
    throw new Error(`report_data MISMATCH\n  tee_report: ${tee.report_data}\n  recomputed: ${expected}`);
  }
  console.log(`  [OK] report_data matches: ${expected}`);

  console.log(`\n=== ALL 6 PROOFS VERIFIED + report_data bound ===`);
  console.log(`Bundle: ${OUT_DIR}`);
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
