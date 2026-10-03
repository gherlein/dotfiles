#!/usr/bin/env bash
#
# install-software-factory.sh
# Installs and configures Docker CE + Dagger CLI on Ubuntu.
#
# Usage: sudo ./install-software-factory.sh [DAGGER_VERSION]
#   DAGGER_VERSION - optional, e.g. v0.14.0 (defaults to latest)

set -euo pipefail

DAGGER_VERSION="${1:-}"
BIN_DIR="/usr/local/bin"
REAL_USER="${SUDO_USER:-$USER}"

log() { printf '\n\033[1;32m==> %s\033[0m\n' "$1"; }
fail() { printf '\033[1;31mERROR: %s\033[0m\n' "$1" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "Run this script with sudo/root."
command -v apt-get >/dev/null || fail "This script is for Ubuntu/Debian (apt-get not found)."

# ---------------------------------------------------------------------------
# Docker CE
# ---------------------------------------------------------------------------
if command -v docker >/dev/null 2>&1; then
    log "Docker already installed ($(docker --version)); skipping install"
else
    log "Installing prerequisites"
    apt-get update
    apt-get install -y ca-certificates curl gnupg

    log "Adding Docker's official GPG key and apt repo"
    install -m 0755 -d /etc/apt/keyrings
    if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
    fi

    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list

    log "Installing Docker CE"
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

log "Enabling and starting docker service"
systemctl enable --now docker

if id -nG "$REAL_USER" | grep -qw docker; then
    log "$REAL_USER already in docker group"
else
    log "Adding $REAL_USER to docker group"
    usermod -aG docker "$REAL_USER"
    echo "NOTE: $REAL_USER must log out/in (or run 'newgrp docker') for group membership to take effect."
fi

log "Verifying docker"
docker run --rm hello-world >/dev/null && echo "docker: OK"

# ---------------------------------------------------------------------------
# Dagger CLI
# ---------------------------------------------------------------------------
if command -v dagger >/dev/null 2>&1; then
    log "Dagger already installed ($(dagger version)); skipping install"
else
    log "Installing Dagger CLI${DAGGER_VERSION:+ ($DAGGER_VERSION)}"
    if [[ -n "$DAGGER_VERSION" ]]; then
        DAGGER_VERSION="$DAGGER_VERSION" BIN_DIR="$BIN_DIR" \
            sh -c "curl -sfL https://raw.githubusercontent.com/dagger/dagger/main/install.sh | sh"
    else
        BIN_DIR="$BIN_DIR" \
            sh -c "curl -sfL https://raw.githubusercontent.com/dagger/dagger/main/install.sh | sh"
    fi
fi

log "Verifying dagger (this starts the engine over the docker socket)"
sudo -u "$REAL_USER" dagger version

cat <<EOF

$(printf '\033[1;32mDone.\033[0m')
Docker : $(docker --version)
Dagger : $(dagger version)

If this was the first time $REAL_USER was added to the docker group, run:
  newgrp docker
or log out/in before using 'docker'/'dagger' without sudo.

Dagger will auto-detect Docker via /var/run/docker.sock — no DAGGER_RUNNER_HOST needed.
EOF
