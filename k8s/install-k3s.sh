#!/bin/bash
set -euo pipefail

echo "[+] Installing k3s agent binaries..."
curl -sfL https://get.k3s.io | \
  INSTALL_K3S_SKIP_ENABLE="${INSTALL_K3S_SKIP_ENABLE:-true}" \
  INSTALL_K3S_SKIP_START="${INSTALL_K3S_SKIP_START:-true}" \
  INSTALL_K3S_EXEC="${INSTALL_K3S_EXEC:---docker}" \
  sh -

if [ -f /etc/rancher/k3s/k3s.yaml ]; then
  chmod 555 /etc/rancher/k3s/k3s.yaml
fi
