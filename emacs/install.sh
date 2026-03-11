#!/bin/bash
# Install emacs config to ~/.emacs.d
# Backs up existing config before overwriting.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="$HOME/.emacs.d"
BACKUP_DIR="$HOME/.emacs.d.bak.$(date +%Y%m%d%H%M%S)"

# Back up existing ~/.emacs if present
if [ -f "$HOME/.emacs" ]; then
    echo "Moving ~/.emacs -> $BACKUP_DIR/.emacs"
    mkdir -p "$BACKUP_DIR"
    mv "$HOME/.emacs" "$BACKUP_DIR/.emacs"
fi

# Back up existing ~/.emacs.d if present
if [ -d "$TARGET_DIR" ]; then
    echo "Moving ~/.emacs.d -> $BACKUP_DIR"
    mv "$TARGET_DIR" "$BACKUP_DIR"
fi

mkdir -p "$TARGET_DIR"

cp "$SCRIPT_DIR/init.el" "$TARGET_DIR/init.el"

# Install the straight.el lockfile if present, to reproduce exact package versions
LOCKFILE="$SCRIPT_DIR/straight-versions.el"
if [ -f "$LOCKFILE" ]; then
    mkdir -p "$TARGET_DIR/straight/versions"
    cp "$LOCKFILE" "$TARGET_DIR/straight/versions/default.el"
    echo "Installed straight.el lockfile — packages will be pinned to recorded versions."
else
    echo "No lockfile found — packages will install at latest versions."
    echo "After first launch, run M-x straight-freeze-versions, then:"
    echo "  cp ~/.emacs.d/straight/versions/default.el $SCRIPT_DIR/straight-versions.el"
    echo "  git add $SCRIPT_DIR/straight-versions.el && git commit"
fi

echo ""
echo "Installed to $TARGET_DIR"
echo "On first launch, Emacs will bootstrap straight.el and install all packages."
echo "Run: emacs"
