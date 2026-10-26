"use strict";

/**
 * Local Kaniko + Trivy wrappers (run via the Docker daemon on the laptop).
 *
 * In the later Nitro-Enclave deliverable these become in-enclave process calls;
 * here they run as containers so we can prove the witness flow end-to-end.
 */

const fs            = require("fs");
const path          = require("path");
const { spawnSync } = require("child_process");

const KANIKO_IMAGE = process.env.KANIKO_IMAGE || "gcr.io/kaniko-project/executor:latest";
const TRIVY_IMAGE  = process.env.TRIVY_IMAGE  || "aquasec/trivy:latest";
// Optional platform override (the real enclave is linux/amd64).
const PLATFORM     = process.env.OCI_PLATFORM || ""; // e.g. "linux/amd64"

function platformArgs() {
  return PLATFORM ? ["--platform", PLATFORM] : [];
}

// Run a command, tee combined stdout+stderr to logPath, return { exitCode, output }.
function runToLog(cmd, args, logPath) {
  const r = spawnSync(cmd, args, { encoding: "utf8", maxBuffer: 512 * 1024 * 1024 });
  const output = [(r.stdout || ""), (r.stderr || "")].filter(Boolean).join("\n");
  fs.writeFileSync(logPath, output);
  return { exitCode: r.status ?? 1, output, spawnError: r.error };
}

/**
 * Build the OCI image with Kaniko.
 *   contextDir  absolute path to the build context (Dockerfile + aux files)
 *   outDir      absolute path for outputs (image.tar, oci/, build.log)
 * Returns { exitCode, logPath, imageTarPath, ociDir }.
 */
function buildImage({ contextDir, dockerfile = "Dockerfile", outDir }) {
  fs.mkdirSync(outDir, { recursive: true });
  const imageTarPath = path.join(outDir, "image.tar");
  const ociDir       = path.join(outDir, "oci");
  const logPath      = path.join(outDir, "build.log");

  const args = [
    "run", "--rm", ...platformArgs(),
    "-v", `${contextDir}:/workspace:ro`,
    "-v", `${outDir}:/output`,
    KANIKO_IMAGE,
    "--context", "dir:///workspace",
    "--dockerfile", `/workspace/${dockerfile}`,
    "--no-push",
    "--tar-path", "/output/image.tar",
    "--oci-layout-path", "/output/oci",
    "--reproducible",
  ];

  console.log(`[kaniko] docker ${args.join(" ")}`);
  const { exitCode, output } = runToLog("docker", args, logPath);
  // surface the tail so failures are visible in the console too
  if (exitCode !== 0) console.error(output.split("\n").slice(-25).join("\n"));
  return { exitCode, logPath, imageTarPath, ociDir };
}

/**
 * Scan the produced image with Trivy (CRITICAL severity; exit 1 if any found).
 *   imageTarPath  docker-save tar to scan
 *   outDir        where to write scan.json + scan.log
 * Returns { exitCode, logPath, jsonPath }.
 */
function scanImage({ imageTarPath, outDir }) {
  fs.mkdirSync(outDir, { recursive: true });
  const logPath  = path.join(outDir, "scan.log");
  const jsonPath = path.join(outDir, "scan.json");

  const args = [
    "run", "--rm", ...platformArgs(),
    "-v", `${outDir}:/out`,
    "-v", `${path.dirname(imageTarPath)}:/in:ro`,
    TRIVY_IMAGE,
    "image",
    "--input", `/in/${path.basename(imageTarPath)}`,
    "--severity", "CRITICAL",
    "--exit-code", "1",
    "--format", "json",
    "--output", "/out/scan.json",
  ];

  console.log(`[trivy] docker ${args.join(" ")}`);
  const { exitCode } = runToLog("docker", args, logPath);
  return { exitCode, logPath, jsonPath };
}

module.exports = { buildImage, scanImage, KANIKO_IMAGE, TRIVY_IMAGE };
