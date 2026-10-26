"use strict";

/**
 * Parse Kaniko build output (docker-save image.tar + OCI layout dir) to extract
 * the witnesses that are not derivable from the source alone:
 *   - usedBaseDigestFromDockerfile: the pinned FROM @sha256 digest
 *   - ociManifestDigest:            the canonical OCI image manifest digest
 *   - extractPackages:              runtime packages via layer diff (final - base)
 *
 * Pure tar/JSON parsing (no docker daemon) so the same code runs in the enclave.
 */

const fs            = require("fs");
const os            = require("os");
const path          = require("path");
const { spawnSync } = require("child_process");

function sh(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: "utf8", maxBuffer: 256 * 1024 * 1024, ...opts });
  if (r.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} failed (exit ${r.status}): ${r.stderr || r.stdout}`);
  }
  return r.stdout;
}

// Parse "FROM <ref>@sha256:<64hex>" from the Dockerfile -> 64-hex digest.
function usedBaseDigestFromDockerfile(dockerfilePath) {
  const text = fs.readFileSync(dockerfilePath, "utf8");
  const m = text.match(/^\s*FROM\s+\S+@sha256:([0-9a-f]{64})/im);
  if (!m) throw new Error(`no pinned 'FROM ...@sha256:<digest>' in ${dockerfilePath}`);
  return m[1];
}

// Read the OCI image manifest digest from a kaniko --oci-layout-path dir.
function ociManifestDigest(ociLayoutDir) {
  const index = JSON.parse(fs.readFileSync(path.join(ociLayoutDir, "index.json"), "utf8"));
  if (!index.manifests || !index.manifests.length) {
    throw new Error(`no manifests in ${ociLayoutDir}/index.json`);
  }
  const d = index.manifests[0].digest; // "sha256:<hex>"
  const m = d.match(/^sha256:([0-9a-f]{64})$/);
  if (!m) throw new Error(`unexpected manifest digest: ${d}`);
  return { ref: d, hex: m[1] };
}

// Parse an apk "installed" DB into [{name, version}, ...].
// Stanzas are separated by blank lines; P: = name, V: = version.
function parseApkInstalled(dbText) {
  const pkgs = [];
  for (const stanza of dbText.split(/\n\n+/)) {
    let name = null, version = null;
    for (const line of stanza.split("\n")) {
      if (line.startsWith("P:")) name = line.slice(2).trim();
      else if (line.startsWith("V:")) version = line.slice(2).trim();
    }
    if (name && version) pkgs.push({ name, version });
  }
  return pkgs;
}

const APK_DB_REL = path.join("lib", "apk", "db", "installed");

function readApkDbFromRoot(rootDir) {
  const p = path.join(rootDir, APK_DB_REL);
  if (!fs.existsSync(p)) return [];
  return parseApkInstalled(fs.readFileSync(p, "utf8"));
}

/**
 * Extract the runtime package set from a docker-save image.tar.
 *   basePackages  = apk DB in layer 0 (the single alpine base layer)
 *   finalPackages = apk DB after overlaying all layers in order
 *   usedPackages  = finalPackages whose name is NOT in basePackages
 *                   (= explicitly-added + scanelf rundeps; base-alpine excluded)
 * Returns { basePackages, finalPackages, usedPackages } (used sorted by name).
 */
function extractPackages(imageTarPath) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "oci-img-"));
  try {
    const unpack = path.join(work, "unpack");
    fs.mkdirSync(unpack);
    sh("tar", ["-xf", imageTarPath, "-C", unpack]);

    const manifest = JSON.parse(fs.readFileSync(path.join(unpack, "manifest.json"), "utf8"));
    const layers = manifest[0].Layers;
    if (!layers || !layers.length) throw new Error("no Layers in image.tar manifest.json");

    // base = layer 0 only
    const baseRoot = path.join(work, "base");
    fs.mkdirSync(baseRoot);
    sh("tar", ["-xf", path.join(unpack, layers[0]), "-C", baseRoot]);
    const basePackages = readApkDbFromRoot(baseRoot);

    // final = all layers overlaid in order (last writer of the apk DB wins)
    const finalRoot = path.join(work, "final");
    fs.mkdirSync(finalRoot);
    for (const layer of layers) {
      sh("tar", ["-xf", path.join(unpack, layer), "-C", finalRoot]);
    }
    const finalPackages = readApkDbFromRoot(finalRoot);

    const baseNames = new Set(basePackages.map((p) => p.name));
    const usedPackages = finalPackages
      // exclude base-alpine packages (identical across every alpine image) and apk
      // virtual meta-packages (names starting with "."), whose versions are
      // wall-clock timestamps and thus non-reproducible.
      .filter((p) => !baseNames.has(p.name) && !p.name.startsWith("."))
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

    return { basePackages, finalPackages, usedPackages };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

module.exports = {
  usedBaseDigestFromDockerfile,
  ociManifestDigest,
  parseApkInstalled,
  extractPackages,
};
