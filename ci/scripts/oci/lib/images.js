"use strict";

/**
 * Per-image configuration for the OCI ladder. Only haproxy is wired up for the
 * first deliverable; the others follow the same shape once their Dockerfiles +
 * GPG mitigations land.
 *
 *   contextRel        build-context dir, relative to the src repo root
 *   dockerfile        Dockerfile name within the context
 *   approvedBaseDepth f_base_image approved-tree depth (compiled circuit = 3)
 *   approvedPkgsDepth f_packages approved-tree depth   (compiled circuit = 6)
 *   maxPackages       f_packages used-slot capacity     (compiled circuit = 16)
 */

const MAX_PACKAGES       = 16; // must match FPackages pkgs[16] / UsedPackagesRoot16
const APPROVED_BASE_DEPTH = 3; // must match FBaseImage(3)
const APPROVED_PKGS_DEPTH = 6; // must match FPackages(6)

const IMAGES = {
  haproxy: {
    contextRel: "oci/haproxy",
    dockerfile: "Dockerfile",
    approvedBaseDepth: APPROVED_BASE_DEPTH,
    approvedPkgsDepth: APPROVED_PKGS_DEPTH,
    maxPackages: MAX_PACKAGES,
  },
};

function imageConfig(name) {
  const cfg = IMAGES[name];
  if (!cfg) throw new Error(`unknown image '${name}'. known: ${Object.keys(IMAGES).join(", ")}`);
  return cfg;
}

module.exports = { IMAGES, imageConfig, MAX_PACKAGES, APPROVED_BASE_DEPTH, APPROVED_PKGS_DEPTH };
