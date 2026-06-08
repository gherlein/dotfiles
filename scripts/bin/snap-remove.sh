#!/bin/bash
# snap-remove.sh - Remove all snap packages and permanently disable snapd
# Debian/Ubuntu only. Run this before installing anything else if you don't want snap.

set -euo pipefail

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; }
warn()  { echo "[WARN]  $*"; }
die()   { echo "[ERROR] $*" >&2; exit 1; }

[[ "$OSTYPE" == "linux-gnu" || "$OSTYPE" == "linux-gnueabihf" ]] || die "This script is for Linux only."

command -v apt-get &>/dev/null || die "This script requires apt (Debian/Ubuntu)."

# ---------------------------------------------------------------------------
# REMOVE SNAP COMPLETELY
# ---------------------------------------------------------------------------

info "Removing ALL snap packages and disabling snap permanently..."

# WHY: Remove all installed snap packages before purging snapd
if command -v snap &>/dev/null; then
    info "Removing all installed snap packages..."
    while read -r snapname _; do
        if [[ -n "$snapname" && "$snapname" != "Name" ]]; then
            info "Removing snap package: $snapname"
            sudo snap remove --purge "$snapname" 2>/dev/null || true
        fi
    done < <(snap list 2>/dev/null || true)
fi

# WHY: Purge snapd and all related packages
info "Purging snapd and related packages..."
sudo apt-get purge -y snapd gnome-software-plugin-snap 2>/dev/null || true
sudo apt-get autoremove -y 2>/dev/null || true

# WHY: Remove all snap directories and cached data
info "Removing snap directories..."
sudo rm -rf ~/snap /snap /var/snap /var/lib/snapd /var/cache/snapd 2>/dev/null || true

# WHY: Prevent snapd from ever being reinstalled
info "Preventing snapd reinstallation..."
sudo tee /etc/apt/preferences.d/nosnap.pref > /dev/null <<'EOF'
Package: snapd
Pin: release a=*
Pin-Priority: -1
EOF

ok "Snap completely removed and permanently disabled."
