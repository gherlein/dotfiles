#!/usr/bin/env bash
#
# setup-nfs-peer-mount.sh - Configure the NFS export and fstab entry for the
# europa/helios home-directory cross-mount (see sync-mount-peer.sh, which
# does the actual mounting based on reachability).
#
# Detects which of the two hosts it's running on and writes the matching
# /etc/exports and /etc/fstab lines. Idempotent: safe to re-run.
#
# Usage:
#   sudo ./setup-nfs-peer-mount.sh
#
# Installs nfs-kernel-server and nfs-common if missing. Requires europa/helios
# to resolve to each other (/etc/hosts, mDNS, or DNS).

set -euo pipefail

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; }
warn()  { echo "[WARN]  $*"; }
die()   { echo "[ERROR] $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must be run as root (sudo)."

HOME_DIR="/home/gherlein"
HOST="$(hostname -s)"

# WHY subnet, not hostname: europa and helios each have multiple NICs on this
# LAN, and whichever interface actually carries the outbound connection may
# not match what the peer's /etc/hosts resolves the bare hostname to - that
# mismatch makes nfsd reject the mount with "access denied by server".
LAN_SUBNET="192.168.2.0/24"

case "$HOST" in
    europa) PEER=helios; MOUNTPOINT="$HOME_DIR/b" ;;
    helios) PEER=europa; MOUNTPOINT="$HOME_DIR/h" ;;
    *)      die "unrecognized host '$HOST' (expected europa or helios)." ;;
esac

# append_line <file> <line> - append, first adding a newline if the file
# doesn't already end in one (a bare append otherwise glues onto the last line)
append_line() {
    local file="$1" line="$2"
    if [[ -s "$file" && -n "$(tail -c1 "$file")" ]]; then
        echo >> "$file"
    fi
    echo "$line" >> "$file"
}

# --- ensure NFS server + client tools are installed --------------------------
if ! command -v exportfs &>/dev/null || ! command -v mount.nfs &>/dev/null; then
    info "Installing nfs-kernel-server and nfs-common..."
    apt-get update -qq
    apt-get install -y nfs-kernel-server nfs-common
    ok "NFS packages installed"
else
    ok "NFS packages already installed"
fi

# --- export our home dir to the peer ---------------------------------------
EXPORT_LINE="$HOME_DIR $LAN_SUBNET(rw,sync,no_subtree_check,root_squash)"
if grep -qxF "$EXPORT_LINE" /etc/exports 2>/dev/null; then
    ok "export already present in /etc/exports"
else
    append_line /etc/exports "$EXPORT_LINE"
    ok "added export: $EXPORT_LINE"
fi
if exportfs -ra; then
    ok "exportfs reloaded"
else
    warn "exportfs reported a problem (see above) - likely an unrelated stale entry in /etc/exports; continuing"
fi

# --- mount point + fstab entry for the peer's home dir ----------------------
mkdir -p "$MOUNTPOINT"
ok "mount point ready: $MOUNTPOINT"

FSTAB_LINE="$PEER:$HOME_DIR $MOUNTPOINT nfs noauto,soft,timeo=30,retrans=2,_netdev 0 0"
if grep -qxF "$FSTAB_LINE" /etc/fstab 2>/dev/null; then
    ok "fstab entry already present"
else
    append_line /etc/fstab "$FSTAB_LINE"
    ok "added fstab entry: $FSTAB_LINE"
fi

info "Done. $HOST now exports $HOME_DIR to $PEER and will mount $PEER:$HOME_DIR at $MOUNTPOINT."
info "Run sync-mount-peer.sh (or wait for the dispatcher/timer) to mount it."
