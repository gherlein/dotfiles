#!/bin/bash
# ubuntu-setup-vdesktop - Configure 4 static virtual desktops with Ctrl+Arrow navigation

set -euo pipefail

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; }
die()   { echo "[ERROR] $*" >&2; exit 1; }

command -v gsettings &>/dev/null || die "gsettings not found. Is GNOME installed?"

info "Disabling dynamic workspaces..."
gsettings set org.gnome.mutter dynamic-workspaces false

info "Setting 4 static workspaces..."
gsettings set org.gnome.desktop.wm.preferences num-workspaces 4

info "Mapping Ctrl+Left to switch workspace left..."
gsettings set org.gnome.desktop.wm.keybindings switch-to-workspace-left "['<Control>Left']"

info "Mapping Ctrl+Right to switch workspace right..."
gsettings set org.gnome.desktop.wm.keybindings switch-to-workspace-right "['<Control>Right']"

ok "Virtual desktop configuration complete."
echo ""
echo "  Workspaces: 4 (static)"
echo "  Ctrl+Left:  switch to workspace left"
echo "  Ctrl+Right: switch to workspace right"
