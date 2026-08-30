#!/bin/bash
# install-tmux.sh - Install tmux and TPM (Tmux Plugin Manager), then bootstrap plugins.
#
# Idempotent: safe to re-run. Installs tmux via the platform package manager if
# missing, clones TPM into ~/.tmux/plugins/tpm, and installs the plugins declared
# in ~/.tmux.conf non-interactively (so you don't have to press prefix+I on first
# launch).
#
# The tmux config itself lives in this repo (tmux/.tmux.conf) and is deployed via
# GNU Stow. This script only installs software and plugins — it does not edit the
# config. Deploy the dotfiles first (make stow) so ~/.tmux.conf exists with its
# @plugin declarations before running the plugin bootstrap.

set -euo pipefail

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; }
warn()  { echo "[WARN]  $*"; }
die()   { echo "[ERROR] $*" >&2; exit 1; }

TPM_DIR="$HOME/.tmux/plugins/tpm"

# ---------------------------------------------------------------------------
# Install tmux
# ---------------------------------------------------------------------------

install_tmux() {
    if command -v tmux &>/dev/null; then
        info "tmux already installed: $(tmux -V)"
        return
    fi
    info "Installing tmux..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y tmux
    elif command -v brew &>/dev/null; then
        brew install tmux
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y tmux
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm tmux
    else
        die "No supported package manager (apt/brew/dnf/pacman) found to install tmux."
    fi
    ok "tmux installed: $(tmux -V)"
}

# ---------------------------------------------------------------------------
# Install TPM (Tmux Plugin Manager)
# ---------------------------------------------------------------------------

install_tpm() {
    if [[ -d "$TPM_DIR/.git" ]]; then
        info "TPM already present at $TPM_DIR — pulling latest"
        git -C "$TPM_DIR" pull --ff-only \
            || warn "Could not fast-forward TPM — leaving it as-is"
    else
        info "Cloning TPM into $TPM_DIR"
        mkdir -p "$(dirname "$TPM_DIR")"
        git clone https://github.com/tmux-plugins/tpm "$TPM_DIR"
        ok "TPM cloned."
    fi
}

# ---------------------------------------------------------------------------
# Install the plugins declared in ~/.tmux.conf
# ---------------------------------------------------------------------------

install_plugins() {
    if [[ ! -f "$HOME/.tmux.conf" ]]; then
        warn "~/.tmux.conf not found — deploy dotfiles first (make stow). Skipping plugin install."
        warn "Once deployed, run this script again or press prefix+I inside tmux."
        return
    fi
    if [[ ! -x "$TPM_DIR/bin/install_plugins" ]]; then
        warn "TPM installer not found at $TPM_DIR/bin/install_plugins — open tmux and press prefix+I."
        return
    fi

    # TPM reads the @plugin declarations from a tmux server that has sourced
    # ~/.tmux.conf. Start a throwaway detached session so the config (and thus
    # the plugin list) is loaded, install, then tear that session down. This
    # does not disturb an already-running server or the user's own sessions.
    info "Installing tmux plugins via TPM..."
    tmux new-session -d -s __tpm_bootstrap 2>/dev/null || true
    "$TPM_DIR/bin/install_plugins" \
        || warn "TPM plugin install reported an error — retry with prefix+I inside tmux."
    tmux kill-session -t __tpm_bootstrap 2>/dev/null || true
    ok "tmux plugins installed."
}

install_tmux
install_tpm
install_plugins

echo ""
echo "================================================================"
ok "tmux + TPM setup complete."
echo ""
echo "  Inside tmux (prefix is Ctrl-b):"
echo "    prefix + I   install / refresh plugins"
echo "    prefix + U   update plugins"
echo "    prefix + C-s save session   |   prefix + C-r restore session"
echo "================================================================"
