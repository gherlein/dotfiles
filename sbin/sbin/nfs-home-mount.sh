#!/usr/bin/env bash
#
# Reconcile a home-only NFS mount against server reachability.
# Run on a timer: if the NFS server answers, ensure the share is mounted;
# if it does not, ensure the share is unmounted. Idempotent by design so a
# 30s cadence produces no churn while nothing changes, and a brief link flap
# on the home LAN is invisible (the next tick still sees the server).
#
# Lives in dotfiles (~/dotfiles/sbin/sbin/), stowed to ~/sbin/nfs-home-mount.sh.
# Invoked by the root systemd service installed via nfs-home-mount/install.sh.
#
set -euo pipefail

CONFIG_FILE="/etc/nfs-home-mount.conf"
[[ -r "$CONFIG_FILE" ]] || { echo "missing config: $CONFIG_FILE" >&2; exit 1; }
# shellcheck source=/dev/null
source "$CONFIG_FILE"

: "${NFS_SERVER:?NFS_SERVER must be set in $CONFIG_FILE}"
: "${MOUNT_POINT:?MOUNT_POINT must be set in $CONFIG_FILE}"
NFS_PORT="${NFS_PORT:-2049}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-2}"

server_reachable() {
    # WHY: probing the NFS port directly answers "will a mount actually succeed",
    # which SSID/subnet heuristics only approximate. A short flap on the home LAN
    # still returns reachable on the next tick, so nothing gets unmounted.
    timeout "$PROBE_TIMEOUT" bash -c ": </dev/tcp/${NFS_SERVER}/${NFS_PORT}" 2>/dev/null
}

is_mounted() {
    # WHY: read the kernel mount table instead of stat-ing the path. A stale NFS
    # mount returns EIO on stat, so `mountpoint -q` would wrongly report "not
    # mounted" and we'd never clean it up. The mount table lists it regardless,
    # and reading it never touches the dead filesystem. Field 5 is the mount point.
    awk -v mp="$MOUNT_POINT" '$5 == mp {found=1} END {exit !found}' /proc/self/mountinfo
}

if server_reachable; then
    if is_mounted; then
        exit 0
    fi
    echo "NFS ${NFS_SERVER}:${NFS_PORT} reachable; mounting ${MOUNT_POINT}"
    mount "$MOUNT_POINT"
else
    if ! is_mounted; then
        exit 0
    fi
    echo "NFS ${NFS_SERVER}:${NFS_PORT} unreachable; unmounting ${MOUNT_POINT}"
    # WHY: -f -l so a hung/blipped mount still detaches without blocking the timer
    # or wedging processes; the lazy detach releases the tree once callers let go.
    umount -f -l "$MOUNT_POINT"
fi
