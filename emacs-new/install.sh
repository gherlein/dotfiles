#!/bin/bash
# Install emacs-new config to ~/.emacs.d
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

mkdir -p "$TARGET_DIR/lisp"

cp "$SCRIPT_DIR/init.el" "$TARGET_DIR/init.el"
cp "$SCRIPT_DIR/lisp/brightscript-mode.el" "$TARGET_DIR/lisp/brightscript-mode.el"
cp "$SCRIPT_DIR/lisp/scad-mode.el" "$TARGET_DIR/lisp/scad-mode.el"

echo "Installed to $TARGET_DIR"
echo ""
echo "On first launch, Emacs will install packages from MELPA."
echo "Run: emacs"
