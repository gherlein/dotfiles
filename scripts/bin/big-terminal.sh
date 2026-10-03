#!/usr/bin/env bash
# Open kitty sized to a fraction of the primary monitor.
# Wayland: size is honored; window position is chosen by the compositor.
set -euo pipefail

# These require org.gnome.mutter auto-maximize=false (set by the installer);
# otherwise GNOME snaps a near-monitor-sized new window to full screen.
FRACTION_W=0.95   # target width  as fraction of screen
FRACTION_H=0.90   # target height as fraction of screen
CELL_W=10         # approx character cell width in px (tune to your font)

# Absolute path: GNOME custom keybindings launch with a minimal PATH that may
# omit ~/.local/bin, so resolving kitty by name would fail from the shortcut.
KITTY="$HOME/.local/bin/kitty"
[ -x "$KITTY" ] || KITTY=kitty

# Resolution of the primary monitor (falls back to first connected).
res=$(xrandr --query | awk '/ connected primary/{print $4} ' | grep -oE '^[0-9]+x[0-9]+' || true)
[ -z "${res:-}" ] && res=$(xrandr --query | awk '/ connected/{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+x[0-9]+\+/){print $i; exit}}' | grep -oE '^[0-9]+x[0-9]+')

px_w=${res%x*}; px_h=${res#*x}

cols=$(awk -v w="$px_w" -v f="$FRACTION_W" -v c="$CELL_W" 'BEGIN{printf "%d", (w*f)/c}')

# Height is sized in pixels rather than cells (the cell-height estimate is
# unreliable and undershot the target). Base it on the work area, not the raw
# monitor: the top bar plus kitty's title bar push a raw-height window to the
# usable ceiling, which makes GNOME maximize it.
workarea_h=$(xprop -root _NET_WORKAREA 2>/dev/null | grep -oE '[0-9]+' | sed -n '4p' || true)
[ -z "${workarea_h:-}" ] && workarea_h=$px_h
px_h_target=$(awk -v h="$workarea_h" -v f="$FRACTION_H" 'BEGIN{printf "%d", h*f}')

# remember_window_size defaults to yes, which makes kitty restore its last size
# and ignore the initial_window_* values after the first launch; disable it so
# the requested size is always honored.
exec "$KITTY" --start-as=normal \
  -o "remember_window_size=no" \
  -o "initial_window_width=${cols}c" \
  -o "initial_window_height=${px_h_target}"
