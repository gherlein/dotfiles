#!/usr/bin/env bash
# Rebind Ctrl-Alt-T to the resolution-aware big-terminal launcher.
# Idempotent: preserves any other existing custom keybindings.
set -euo pipefail

SCRIPT_TARGET="$HOME/.local/bin/big-terminal.sh"
SLUG="big-terminal"
KEY="/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/${SLUG}/"
SCHEMA_MEDIA="org.gnome.settings-daemon.plugins.media-keys"
SCHEMA_CUSTOM="org.gnome.settings-daemon.plugins.media-keys.custom-keybinding"

if [ ! -x "$SCRIPT_TARGET" ]; then
  echo "error: launcher not found or not executable: $SCRIPT_TARGET" >&2
  echo "install it first (copy big-terminal.sh there and chmod +x)." >&2
  exit 1
fi

# 1. Free Ctrl-Alt-T from GNOME's built-in terminal launcher.
gsettings set "$SCHEMA_MEDIA" terminal "[]"

# 2. Add our key to the custom-keybindings list without dropping existing ones.
current=$(gsettings get "$SCHEMA_MEDIA" custom-keybindings)
if printf '%s' "$current" | grep -q "$KEY"; then
  new_list="$current"
elif [ "$current" = "@as []" ] || [ "$current" = "[]" ]; then
  new_list="['$KEY']"
else
  # Insert before the closing bracket, keeping prior entries.
  new_list="${current%]}, '$KEY']"
fi
gsettings set "$SCHEMA_MEDIA" custom-keybindings "$new_list"

# 3. Configure the shortcut.
path="${SCHEMA_CUSTOM}:${KEY}"
gsettings set "$path" name 'Big Terminal'
gsettings set "$path" command "$SCRIPT_TARGET"
gsettings set "$path" binding '<Control><Alt>t'

echo "Done. Ctrl-Alt-T now runs: $SCRIPT_TARGET"
echo "custom-keybindings = $(gsettings get "$SCHEMA_MEDIA" custom-keybindings)"
