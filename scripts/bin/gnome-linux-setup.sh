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
    "dash-to-panel@jderose9.github.com"
)

# ---------------------------------------------------------------------------
# Extensions to disable
# ---------------------------------------------------------------------------

DISABLE_EXTENSIONS=(
    "ubuntu-dock@ubuntu.com"
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
# Disable unwanted extensions
# ---------------------------------------------------------------------------

for ext in "${DISABLE_EXTENSIONS[@]}"; do
    info "Disabling extension: $ext"
    if gnome-extensions disable "$ext" 2>/dev/null; then
        ok "Disabled: $ext"
    else
        warn "Could not disable: $ext (may not be installed)"
    fi
done

# ---------------------------------------------------------------------------
# Virtual desktops: 4 static workspaces with Ctrl+Arrow navigation
# ---------------------------------------------------------------------------

info "Configuring 4 static virtual desktops..."
gsettings set org.gnome.mutter dynamic-workspaces false
gsettings set org.gnome.desktop.wm.preferences num-workspaces 4
ok "Set 4 static workspaces."

info "Mapping Ctrl+Left/Right to switch workspaces..."
gsettings set org.gnome.desktop.wm.keybindings switch-to-workspace-left "['<Control>Left']"
gsettings set org.gnome.desktop.wm.keybindings switch-to-workspace-right "['<Control>Right']"
ok "Ctrl+Left/Right mapped to workspace navigation."

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
echo "Disabled extensions:"
for ext in "${DISABLE_EXTENSIONS[@]}"; do
    echo "  - $ext"
done
echo ""
echo "You may need to log out and back in (or restart GNOME Shell"
echo "with Alt+F2 → 'r') for extensions to fully activate."
echo "================================================================"
