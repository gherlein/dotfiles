#!/usr/bin/env bash
# Open gnome-terminal sized to a fraction of the primary monitor.
# Wayland: size is honored; window position is chosen by the compositor.
set -euo pipefail

FRACTION_W=0.80   # target width  as fraction of screen
FRACTION_H=0.80   # target height as fraction of screen
CELL_W=10         # approx character cell width  in px (tune to your font)
CELL_H=24         # approx character cell height in px (tune to your font)

# Resolution of the primary monitor (falls back to first connected).
res=$(xrandr --query | awk '/ connected primary/{print $4} ' | grep -oE '^[0-9]+x[0-9]+' || true)
[ -z "${res:-}" ] && res=$(xrandr --query | awk '/ connected/{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+x[0-9]+\+/){print $i; exit}}' | grep -oE '^[0-9]+x[0-9]+')

px_w=${res%x*}; px_h=${res#*x}

cols=$(awk -v w="$px_w" -v f="$FRACTION_W" -v c="$CELL_W" 'BEGIN{printf "%d", (w*f)/c}')
rows=$(awk -v h="$px_h" -v f="$FRACTION_H" -v c="$CELL_H" 'BEGIN{printf "%d", (h*f)/c}')

exec gnome-terminal --geometry="${cols}x${rows}"
