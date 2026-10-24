#!/bin/bash
# ubuntu-setup-vdesktop - Configure 9 static virtual desktops with Ctrl+Arrow
# navigation and Ctrl+Shift+<keypad N> to jump directly to a workspace.

set -euo pipefail

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; }
die()   { echo "[ERROR] $*" >&2; exit 1; }

command -v gsettings &>/dev/null || die "gsettings not found. Is GNOME installed?"

info "Disabling dynamic workspaces..."
gsettings set org.gnome.mutter dynamic-workspaces false

readonly NUM_WORKSPACES=9

info "Setting ${NUM_WORKSPACES} static workspaces..."
gsettings set org.gnome.desktop.wm.preferences num-workspaces "$NUM_WORKSPACES"

info "Mapping Ctrl+Left to switch workspace left..."
gsettings set org.gnome.desktop.wm.keybindings switch-to-workspace-left "['<Control>Left']"

info "Mapping Ctrl+Right to switch workspace right..."
gsettings set org.gnome.desktop.wm.keybindings switch-to-workspace-right "['<Control>Right']"

# KP_N keysyms are only emitted while Num Lock is on, which is the normal
# way the number pad is used.
info "Mapping Ctrl+Shift+<keypad N> to jump directly to workspace N..."
for n in $(seq 1 "$NUM_WORKSPACES"); do
    gsettings set org.gnome.desktop.wm.keybindings "switch-to-workspace-$n" "['<Control><Shift>KP_$n']"
done

ok "Virtual desktop configuration complete."
echo ""
echo "  Workspaces:         ${NUM_WORKSPACES} (static)"
echo "  Ctrl+Left:          switch to workspace left"
echo "  Ctrl+Right:         switch to workspace right"
echo "  Ctrl+Shift+KP_1..${NUM_WORKSPACES}: jump directly to workspace (Num Lock on)"
