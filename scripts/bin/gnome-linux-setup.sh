#!/bin/bash
# gnome-linux-setup.sh - Install GNOME Shell extensions via gnome-extensions-cli (gext)
# Requires: GNOME Shell, pipx or pip

set -euo pipefail

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; }
warn()  { echo "[WARN]  $*"; }
die()   { echo "[ERROR] $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

command -v gnome-shell &>/dev/null || die "GNOME Shell is not installed."

# ---------------------------------------------------------------------------
# Install gnome-extensions-cli (gext) if not present
# ---------------------------------------------------------------------------

if ! command -v gext &>/dev/null; then
    info "Installing gnome-extensions-cli (gext)..."
    command -v uv &>/dev/null || die "uv is not installed. Run: curl -LsSf https://astral.sh/uv/install.sh | sh"
    uv tool install gnome-extensions-cli
fi

command -v gext &>/dev/null || die "gext not found on PATH after install."

# ---------------------------------------------------------------------------
# Extensions to install (extensions.gnome.org UUIDs)
# ---------------------------------------------------------------------------

EXTENSIONS=(
    "clipboard-indicator@tudmotu.com"
    "caffeine@patapon.info"
    "Vitals@CoreCoding.com"
    "auto-move-windows@gnome-shell-extensions.gcampax.github.com"
)

# ---------------------------------------------------------------------------
# Install and enable each extension
# ---------------------------------------------------------------------------

for ext in "${EXTENSIONS[@]}"; do
    info "Installing extension: $ext"
    if gext install "$ext"; then
        gext enable "$ext"
        ok "Enabled: $ext"
    else
        warn "Failed to install: $ext"
    fi
done

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo "================================================================"
echo "GNOME extensions installed and enabled."
echo ""
echo "Installed extensions:"
for ext in "${EXTENSIONS[@]}"; do
    echo "  - $ext"
done
echo ""
echo "You may need to log out and back in (or restart GNOME Shell"
echo "with Alt+F2 → 'r') for extensions to fully activate."
echo "================================================================"
