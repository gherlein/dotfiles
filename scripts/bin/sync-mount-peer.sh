#!/usr/bin/env bash
#
# sync-mount-peer.sh - Mount/unmount the peer notebook's home dir over NFS
# based on live reachability. Invoked frequently (NetworkManager dispatcher
# event + systemd timer), not meant to be run interactively.
#
# Requires root (mount/umount) - invoked as root by the dispatcher and the
# systemd service, so there's no explicit privilege check here.
#
# Host mapping:
#   europa mounts helios:/home/gherlein onto ~/b
#   helios mounts europa:/home/gherlein onto ~/h
#
# See setup-nfs-peer-mount.sh for the matching /etc/exports and /etc/fstab
# setup this script depends on.

set -euo pipefail

HOST="$(hostname -s)"

case "$HOST" in
    europa) PEER=helios; MOUNTPOINT="/home/gherlein/b" ;;
    helios) PEER=europa; MOUNTPOINT="/home/gherlein/h" ;;
    *)
        echo "sync-mount-peer: unrecognized host '$HOST' (expected europa or helios)" >&2
        exit 1
        ;;
esac

if ping -c1 -W2 "$PEER" >/dev/null 2>&1; then
    if ! mountpoint -q "$MOUNTPOINT"; then
        mount "$MOUNTPOINT"
    fi
else
    if mountpoint -q "$MOUNTPOINT"; then
        umount -l "$MOUNTPOINT"
    fi
fi
