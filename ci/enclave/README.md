# Running `build-tee` inside a real AWS Nitro Enclave

This directory runs the `build-tee` step (witness generation + **real** NSM
attestation) inside an actual AWS Nitro Enclave, to obtain a genuine attestation
document and real timing readings. `zk-proof` is **not** run in the enclave — the
attestation binds the witnesses, so proving them outside is sound.

## Why this is standalone (not Concourse)

A Nitro Enclave is not a Concourse-schedulable container. It is an `.eif` image
run via `nitro-cli`, with **no network, no disk, no filesystem passthrough** — it
talks to its parent EC2 instance only over **vsock**. So this runs manually on a
Nitro-enabled EC2 instance. `pipeline.yaml` is unchanged.

## Pieces

| File | Where it runs | Purpose |
|------|---------------|---------|
| `nsm-attest/` | enclave (built in image) | Rust helper: calls NSM, returns the COSE_Sign1 attestation doc with `report_data` as `user_data` |
| `Dockerfile.enclave` | build host | Enclave image (mirrors `Dockerfile.tee` + Rust helper + baked-in source) |
| `enclave-run.sh` | enclave | Entrypoint: runs `tee_build.js` with `NSM_ATTEST=1`, ships outputs over vsock |
| `vsock-send.py` | enclave | Streams the output bundle to the parent |
| `host-listener.py` | parent EC2 | Receives the bundle (vsock server, CID 3) |
| `00-setup-host.sh` | parent EC2 | Install nitro-cli/docker, configure allocator |
| `01-build-eif.sh` | parent EC2 | Build image + `.eif`, print real PCRs |
| `02-run-debug.sh` | parent EC2 | Debug run (zero PCRs) — watch console logs |
| `03-run-measured.sh [N]` | parent EC2 | N real runs (genuine PCRs); outputs via vsock |
| `04-collect.sh` | parent EC2 | Parse timing logs → `enclave-out/timings.csv` |

## Quick start (on a Nitro-enabled EC2 instance, AL2023)

```bash
cd zk-circuits/ci/enclave
./00-setup-host.sh         # then log out/in for group membership
./01-build-eif.sh          # build .eif; note PCR0
./02-run-debug.sh          # sanity: watch the build + timing block
./03-run-measured.sh 10    # 10 real runs → enclave-out/run-*.tar.gz + run-*.log
./04-collect.sh            # → enclave-out/timings.csv
```

The `NSM_ATTEST=1` flag only triggers the real attestation path in
`ci/scripts/tee_build.js`; without it (local dev, Concourse) the original mocked
`tee_report` is produced, so existing pipelines are unaffected.

## Verifying the attestation (optional)

Each bundle contains `tee-build/s3-output/build/attestation.cbor`. Decode it to
confirm `user_data` equals the run's `report_data` and that PCR0 is non-zero in a
measured (non-debug) run:

```python
import cbor2  # the outer COSE_Sign1 is a CBOR array; payload[idx] holds the map
```
A full COSE signature + cert-chain + PCR-policy verifier is intentionally out of
scope for this PoC (that was the "full integration" option).
