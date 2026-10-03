#!/bin/bash
# ROCm-install.sh - Install AMD GPU drivers and ROCm
# For Ryzen AI or AMD GPU workstations (amd64 only). Reboot required after running.

set -euo pipefail

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; }
warn()  { echo "[WARN]  $*"; }
die()   { echo "[ERROR] $*" >&2; exit 1; }

[[ "$OSTYPE" == "linux-gnu" || "$OSTYPE" == "linux-gnueabihf" ]] || die "This script is for Linux only."

command -v apt-get &>/dev/null || die "This script requires apt (Debian/Ubuntu)."

ARCH="$(dpkg --print-architecture)"
[[ "$ARCH" == "amd64" ]] || die "AMD ROCm install is amd64 only (detected: $ARCH)."

# ---------------------------------------------------------------------------
# AMD ROCm / amdgpu (Ryzen AI / workstation GPU)
# ---------------------------------------------------------------------------

AMDGPU_VERSION="6.4.60401-1"

info "Installing AMD GPU drivers and ROCm..."
wget -q "https://repo.radeon.com/amdgpu-install/6.4.1/ubuntu/noble/amdgpu-install_${AMDGPU_VERSION}_all.deb" \
    -O /tmp/amdgpu-install.deb
sudo apt-get install -y /tmp/amdgpu-install.deb
amdgpu-install -y --usecase=workstation,rocm
sudo usermod -aG render,video "$USER"
ok "AMD GPU drivers installed. Reboot required."
