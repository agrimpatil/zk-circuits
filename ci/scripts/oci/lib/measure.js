"use strict";

/**
 * Shared measurement used by both Party A (register_declared_oci.js) and
 * Party B (tee_build_oci.js): build the image with Kaniko and extract the raw
 * (pre-commitment) measurements. Party A and Party B each call this on their own
 * build so the artifact-digest reproducibility can be checked.
 */

const path   = require("path");
const P       = require("./poseidon");
const kaniko  = require("./kaniko");
const imgTar  = require("./image_tar");

// Pure: SHA-256 Merkle root over the build-context tree (no build needed).
function measureSource(contextDir) {
  const { root, filesHashed } = P.sourceTreeRoot(contextDir);
  return { sourceRootHex: root, filesHashed };
}

/**
 * Build with Kaniko and extract: manifest digest, base digest, package sets.
 * Returns everything both parties need from a build (no scan here).
 */
function buildAndInspect({ contextDir, dockerfile, outDir }) {
  const build = kaniko.buildImage({ contextDir, dockerfile, outDir });
  if (build.exitCode !== 0) {
    return { buildExit: build.exitCode, buildLogPath: build.logPath, ok: false };
  }

  const manifest = imgTar.ociManifestDigest(build.ociDir);
  const baseHex  = imgTar.usedBaseDigestFromDockerfile(path.join(contextDir, dockerfile));
  const pkgs     = imgTar.extractPackages(build.imageTarPath);

  return {
    ok: true,
    buildExit: 0,
    buildLogPath: build.logPath,
    imageTarPath: build.imageTarPath,
    ociDir: build.ociDir,
    manifestDigestHex: manifest.hex,
    manifestDigestRef: manifest.ref,
    baseDigestHex: baseHex,
    packages: pkgs, // { basePackages, finalPackages, usedPackages }
  };
}

function scan({ imageTarPath, outDir }) {
  const r = kaniko.scanImage({ imageTarPath, outDir });
  return { scanExit: r.exitCode, scanLogPath: r.logPath, scanJsonPath: r.jsonPath };
}

module.exports = { measureSource, buildAndInspect, scan };
