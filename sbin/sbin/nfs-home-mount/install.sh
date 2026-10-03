#!/usr/bin/env bash
#
# Install the system-level pieces of nfs-home-mount: the systemd service+timer
# (into /etc/systemd/system) and a default config (into /etc, only if absent).
# The script itself stays in dotfiles and is reached via the user's ~/sbin
# symlink -- this installer only points systemd at that path.
#
# Run with sudo AFTER the dotfiles `sbin` package has been stowed.
#
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

# Template source = the directory this installer lives in (resolve symlinks so
# it works whether called via the ~/sbin symlink or the real dotfiles path).
SRC_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

# Resolve the stowed script path for the invoking (non-root) user.
TARGET_USER="${SUDO_USER:-$USER}"
USER_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
SCRIPT_PATH="${USER_HOME}/sbin/nfs-home-mount.sh"

[[ -e "$SCRIPT_PATH" ]] || {
    echo "expected script at $SCRIPT_PATH" >&2
    echo "stow it first:  cd ~/dotfiles && stow -v sbin" >&2
    exit 1
}

UNIT_DIR="/etc/systemd/system"
CONFIG="/etc/nfs-home-mount.conf"

# Render the service with the resolved absolute script path.
sed "s|__SCRIPT__|${SCRIPT_PATH}|g" "${SRC_DIR}/nfs-home-mount.service" \
    > "${UNIT_DIR}/nfs-home-mount.service"
chmod 0644 "${UNIT_DIR}/nfs-home-mount.service"

install -m 0644 "${SRC_DIR}/nfs-home-mount.timer" "${UNIT_DIR}/nfs-home-mount.timer"

if [[ -e "$CONFIG" ]]; then
    echo "keeping existing $CONFIG"
else
    install -m 0644 "${SRC_DIR}/nfs-home-mount.conf" "$CONFIG"
    echo "installed default $CONFIG -- edit it before starting"
fi

systemctl daemon-reload
systemctl enable --now nfs-home-mount.timer

echo "timer enabled. Add the fstab line (see ${SRC_DIR}/fstab.snippet),"
echo "then reconcile now with:  sudo systemctl start nfs-home-mount.service"
