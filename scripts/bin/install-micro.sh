#!/bin/bash
# Install micro editor to ~/bin and configure plugins.
# Uses eget if available; falls back to direct GitHub release download.

set -euo pipefail

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; }
warn()  { echo "[WARN]  $*"; }
die()   { echo "[ERROR] $*" >&2; exit 1; }

INSTALL_DIR="$HOME/bin"
PLUGINS=(lsp comment autofmt filemanager)

mkdir -p "$INSTALL_DIR"

# ---------------------------------------------------------------------------
# Install micro binary
# ---------------------------------------------------------------------------

install_micro_direct() {
    local arch
    arch="$(uname -m)"

    local asset_pattern
    case "$arch" in
        x86_64)        asset_pattern="linux64.tar.gz" ;;
        aarch64)       asset_pattern="linux-arm64.tar.gz" ;;
        armv7l|armv6l) asset_pattern="linux-arm.tar.gz" ;;
        *)             die "Unsupported architecture: $arch" ;;
    esac

    info "Fetching latest micro release info..."
    local release_url
    release_url=$(curl -sL "https://api.github.com/repositories/53632140/releases/latest" \
        | grep browser_download_url \
        | grep "${asset_pattern}\"" \
        | grep -v '\.sha"' \
        | head -1 \
        | cut -d '"' -f 4)

    [[ -n "$release_url" ]] || die "Could not find micro release asset matching: $asset_pattern"

    info "Downloading $release_url..."
    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    curl -sL "$release_url" -o "$tmpdir/micro.tar.gz"
    tar -xzf "$tmpdir/micro.tar.gz" -C "$tmpdir"

    local micro_bin
    micro_bin=$(find "$tmpdir" -maxdepth 2 -name "micro" -type f | head -1)
    [[ -n "$micro_bin" ]] || die "micro binary not found in archive"

    mv "$micro_bin" "$INSTALL_DIR/micro"
    chmod +x "$INSTALL_DIR/micro"
    trap - EXIT
    rm -rf "$tmpdir"
}

if command -v eget &>/dev/null; then
    info "Installing micro via eget..."
    eget zyedidia/micro --to "$INSTALL_DIR"
    ok "micro installed via eget to $INSTALL_DIR/micro"
else
    warn "eget not found — falling back to direct download."
    install_micro_direct
    ok "micro installed to $INSTALL_DIR/micro"
fi

MICRO_BIN="$INSTALL_DIR/micro"
[[ -x "$MICRO_BIN" ]] || die "micro binary not found at $MICRO_BIN after install."
info "Installed: $("$MICRO_BIN" --version 2>/dev/null | head -1)"

# ---------------------------------------------------------------------------
# Install plugins
# ---------------------------------------------------------------------------

info "Installing micro plugins..."
for plugin in "${PLUGINS[@]}"; do
    info "  Installing plugin: $plugin"
    if "$MICRO_BIN" -plugin install "$plugin" 2>/dev/null; then
        ok "  $plugin installed."
    else
        warn "  $plugin: already installed or failed — continuing."
    fi
done

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo "================================================================"
ok "micro installation complete."
echo ""
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    warn "$INSTALL_DIR is not in your PATH."
    echo "      Add to ~/.bashrc or ~/.zshrc:"
    echo "        export PATH=\"\$HOME/bin:\$PATH\""
fi
echo "================================================================"
