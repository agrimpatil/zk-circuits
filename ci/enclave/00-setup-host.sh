#!/usr/bin/env bash
#
# 00-setup-host.sh — one-time setup on a Nitro-enabled EC2 instance.
# Target OS: Amazon Linux 2023. Instance must be launched with
# --enclave-options Enabled=true on a Nitro-based type (e.g. m5.xlarge / c5.xlarge,
# 4 vCPU / >=8 GB).
set -euo pipefail

sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker

sudo usermod -aG ne "$USER"
sudo usermod -aG docker "$USER"

# Allocator: dedicate 2 vCPUs and 3072 MiB to enclaves (leaves 2 vCPU for the host).
sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null <<'EOF'
---
memory_mib: 3072
cpu_count: 2
EOF

sudo systemctl enable --now docker
sudo systemctl enable --now nitro-enclaves-allocator.service

echo
echo "Setup complete. Log out and back in (or run: newgrp ne; newgrp docker)"
echo "so the 'ne' and 'docker' group memberships take effect."
nitro-cli --version
