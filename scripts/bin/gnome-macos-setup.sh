#!/bin/bash
# gnome-macos-setup.sh
# Automates setting up a macOS-like GNOME desktop on Ubuntu 24.04
# Uses WhiteSur theme, icons, cursors, and wallpapers
#
# Usage:
#   ./gnome-macos-setup.sh           # full setup
#   ./gnome-macos-setup.sh --theme   # theme only
#   ./gnome-macos-setup.sh --dock    # dock only
#   ./gnome-macos-setup.sh --apply   # apply settings only (themes already installed)

set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
info() { echo -e "${BLUE}[i]${NC} $*"; }

# ─── Config ───────────────────────────────────────────────────────────────────
THEME_VARIANT="Dark"          # Dark or Light
THEME_STYLE="monterey"        # monterey or default (Big Sur)
DOCK_POSITION="BOTTOM"        # BOTTOM, LEFT, RIGHT
DOCK_ICON_SIZE=32
WALLPAPER_DIR="$HOME/Pictures/WhiteSur"
SRC_DIR="$HOME/src"

# ─── Prereqs ──────────────────────────────────────────────────────────────────
install_deps() {
    log "Installing dependencies..."
    sudo apt install -y \
        git \
        gnome-tweaks \
        gnome-shell-extension-manager \
        sassc \
        libglib2.0-dev-bin \
        libxml2-utils \
        curl
}

# ─── WhiteSur GTK Theme ───────────────────────────────────────────────────────
install_gtk_theme() {
    log "Installing WhiteSur GTK theme..."
    mkdir -p "$SRC_DIR"

    if [[ ! -d "$SRC_DIR/WhiteSur-gtk-theme" ]]; then
        git clone https://github.com/vinceliuice/WhiteSur-gtk-theme \
            "$SRC_DIR/WhiteSur-gtk-theme"
    else
        git -C "$SRC_DIR/WhiteSur-gtk-theme" pull
    fi

    cd "$SRC_DIR/WhiteSur-gtk-theme"

    # Install GTK theme + libadwaita support
    if [[ "$THEME_STYLE" == "monterey" ]]; then
        ./install.sh -m -t default -l
    else
        ./install.sh -t default -l
    fi

    # Install wallpapers
    log "Installing WhiteSur wallpapers..."
    ./install.sh -w
    mkdir -p "$WALLPAPER_DIR"

    # GDM lock screen theme
    if [[ "${INSTALL_GDM:-false}" == "true" ]]; then
        log "Installing GDM theme (lock screen)..."
        sudo ./tweaks.sh -g
    fi

    # Firefox theme (optional)
    if command -v firefox &>/dev/null && [[ "${INSTALL_FIREFOX:-false}" == "true" ]]; then
        log "Installing Firefox WhiteSur theme..."
        ./tweaks.sh -f
    fi

    cd - >/dev/null
}

# ─── WhiteSur Icons ───────────────────────────────────────────────────────────
install_icons() {
    log "Installing WhiteSur icon theme..."

    if [[ ! -d "$SRC_DIR/WhiteSur-icon-theme" ]]; then
        git clone https://github.com/vinceliuice/WhiteSur-icon-theme \
            "$SRC_DIR/WhiteSur-icon-theme"
    else
        git -C "$SRC_DIR/WhiteSur-icon-theme" pull
    fi

    cd "$SRC_DIR/WhiteSur-icon-theme"
    ./install.sh
    cd - >/dev/null
}

# ─── WhiteSur Cursors ─────────────────────────────────────────────────────────
install_cursors() {
    log "Installing WhiteSur cursor theme..."

    if [[ ! -d "$SRC_DIR/WhiteSur-cursors" ]]; then
        git clone https://github.com/vinceliuice/WhiteSur-cursors \
            "$SRC_DIR/WhiteSur-cursors"
    else
        git -C "$SRC_DIR/WhiteSur-cursors" pull
    fi

    cd "$SRC_DIR/WhiteSur-cursors"
    sudo ./install.sh
    cd - >/dev/null
}

# ─── Apply GNOME Settings ─────────────────────────────────────────────────────
apply_appearance() {
    log "Applying appearance settings..."

    local scheme
    if [[ "$THEME_VARIANT" == "Dark" ]]; then
        scheme="prefer-dark"
    else
        scheme="prefer-light"
    fi

    # Color scheme
    gsettings set org.gnome.desktop.interface color-scheme "$scheme"

    # GTK theme
    gsettings set org.gnome.desktop.interface gtk-theme "WhiteSur-${THEME_VARIANT}"

    # Icons
    gsettings set org.gnome.desktop.interface icon-theme "WhiteSur-${THEME_VARIANT}"

    # Cursors
    gsettings set org.gnome.desktop.interface cursor-theme "WhiteSur-cursors"
    gsettings set org.gnome.desktop.interface cursor-size 24

    # Shell theme (requires User Themes extension)
    gsettings set org.gnome.shell.extensions.user-theme name \
        "WhiteSur-${THEME_VARIANT}" 2>/dev/null \
        || warn "Shell theme not applied — enable 'User Themes' extension first"

    # Fonts (macOS-like)
    gsettings set org.gnome.desktop.interface font-name 'Cantarell 11'
    gsettings set org.gnome.desktop.interface document-font-name 'Cantarell 11'
    gsettings set org.gnome.desktop.interface monospace-font-name 'Source Code Pro 10'

    # Window buttons on left like macOS
    gsettings set org.gnome.desktop.wm.preferences button-layout \
        'close,minimize,maximize:'

    # Center new windows
    gsettings set org.gnome.mutter center-new-windows true

    # Flatpak theme support
    if command -v flatpak &>/dev/null; then
        log "Applying theme to Flatpak apps..."
        sudo flatpak override --filesystem=xdg-config/gtk-3.0 || true
        sudo flatpak override --filesystem=xdg-config/gtk-4.0 || true
    fi
}

apply_wallpaper() {
    log "Applying wallpaper..."

    # Find a wallpaper — prefer WhiteSur, fall back to any jpg in the dir
    local light_wall dark_wall
    light_wall=$(find "$WALLPAPER_DIR" -name "*light*" -o -name "*Light*" \
        2>/dev/null | head -1)
    dark_wall=$(find "$WALLPAPER_DIR" -name "*dark*" -o -name "*Dark*" \
        2>/dev/null | head -1)

    # Fall back to first image found
    if [[ -z "$light_wall" ]]; then
        light_wall=$(find "$WALLPAPER_DIR" -name "*.jpg" -o -name "*.png" \
            2>/dev/null | head -1)
    fi
    [[ -z "$dark_wall" ]] && dark_wall="$light_wall"

    if [[ -n "$light_wall" ]]; then
        gsettings set org.gnome.desktop.background picture-uri \
            "file://$light_wall"
        gsettings set org.gnome.desktop.background picture-uri-dark \
            "file://$dark_wall"
        gsettings set org.gnome.desktop.background picture-options 'zoom'
        gsettings set org.gnome.screensaver picture-uri \
            "file://$light_wall"
        info "Wallpaper set to: $light_wall"
    else
        warn "No wallpaper found in $WALLPAPER_DIR — skipping"
    fi
}

apply_dock() {
    log "Configuring dock..."

    # Ubuntu's built-in dash-to-dock
    local dock_schema="org.gnome.shell.extensions.dash-to-dock"

    gsettings set $dock_schema dock-position     "$DOCK_POSITION"
    gsettings set $dock_schema autohide          true
    gsettings set $dock_schema intellihide       true
    gsettings set $dock_schema extend-height     false
    gsettings set $dock_schema dash-max-icon-size "$DOCK_ICON_SIZE"
    gsettings set $dock_schema click-action      'minimize-or-previews'
    gsettings set $dock_schema show-mounts       true
    gsettings set $dock_schema show-trash        true
    gsettings set $dock_schema multi-monitor     false

    # Dock appearance
    gsettings set $dock_schema transparency-mode 'FIXED'
    gsettings set $dock_schema background-opacity 0.8

    # Hide dock when window touches it
    gsettings set $dock_schema intellihide-mode 'FOCUS_APPLICATION_WINDOWS'
}

apply_scaling() {
    log "Enabling fractional scaling (Wayland)..."
    gsettings set org.gnome.mutter experimental-features \
        "['scale-monitor-framebuffer']"
    info "Fractional scaling enabled — set scale in Settings → Displays"
}

apply_misc() {
    log "Applying misc GNOME settings..."

    # Show battery percentage
    gsettings set org.gnome.desktop.interface show-battery-percentage true

    # Clock format
    gsettings set org.gnome.desktop.interface clock-format '12h'
    gsettings set org.gnome.desktop.interface clock-show-weekday true

    # Hot corners off (more macOS-like, use dock instead)
    gsettings set org.gnome.desktop.interface enable-hot-corners false

    # Natural scrolling
    gsettings set org.gnome.desktop.peripherals.mouse natural-scroll false
    gsettings set org.gnome.desktop.peripherals.touchpad natural-scroll true
    gsettings set org.gnome.desktop.peripherals.touchpad tap-to-click true

    # Workspaces
    gsettings set org.gnome.mutter dynamic-workspaces true
    gsettings set org.gnome.desktop.wm.preferences num-workspaces 4
}

dump_settings() {
    local out="${1:-$HOME/.config/dconf/gnome-backup.ini}"
    mkdir -p "$(dirname "$out")"
    log "Dumping current GNOME settings to $out..."
    dconf dump / > "$out"
    info "Restore with: dconf load / < $out"
}

# ─── Main ─────────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  (no args)       Full setup: install themes + apply all settings
  --theme         Install/reinstall themes only (GTK + icons + cursors)
  --apply         Apply settings only (themes already installed)
  --dock          Configure dock only
  --dump [file]   Dump current dconf settings to file
  --dark          Use dark theme variant (default)
  --light         Use light theme variant
  --gdm           Also install GDM (lock screen) theme (requires sudo)
  --firefox       Also install Firefox WhiteSur theme
  --help          Show this help

Examples:
  $0                        # full setup, dark theme
  $0 --light                # full setup, light theme
  $0 --apply --light        # apply settings only, light theme
  $0 --dump ~/my-backup.ini # backup current settings
EOF
}

main() {
    local do_install=true
    local do_apply=true
    local do_dock=true
    local only_theme=false
    local only_apply=false
    local only_dock=false
    local do_dump=false
    local dump_file=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --theme)   only_theme=true; do_apply=false; do_dock=false ;;
            --apply)   only_apply=true; do_install=false ;;
            --dock)    only_dock=true; do_install=false; do_apply=false ;;
            --dump)    do_dump=true; dump_file="${2:-}"; shift || true ;;
            --dark)    THEME_VARIANT="Dark" ;;
            --light)   THEME_VARIANT="Light" ;;
            --gdm)     export INSTALL_GDM=true ;;
            --firefox) export INSTALL_FIREFOX=true ;;
            --help)    usage; exit 0 ;;
            *)         err "Unknown option: $1"; usage; exit 1 ;;
        esac
        shift
    done

    if [[ "$do_dump" == "true" ]]; then
        dump_settings "$dump_file"
        exit 0
    fi

    if [[ "$only_dock" == "true" ]]; then
        apply_dock
        exit 0
    fi

    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   GNOME macOS Setup — Ubuntu 24.04     ║${NC}"
    echo -e "${BLUE}║   Theme variant: ${THEME_VARIANT}                  ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo ""

    if [[ "$do_install" == "true" ]]; then
        install_deps
        install_gtk_theme
        install_icons
        install_cursors
    fi

    if [[ "$do_apply" == "true" ]] || [[ "$only_apply" == "true" ]]; then
        apply_appearance
        apply_wallpaper
        apply_misc
        apply_scaling
    fi

    if [[ "$do_dock" == "true" ]] || [[ "$only_apply" == "true" ]]; then
        apply_dock
    fi

    echo ""
    log "Setup complete!"
    warn "Log out and back in for all changes to take effect."
    echo ""
    info "Useful commands:"
    info "  ghostty +list-themes        — browse terminal themes"
    info "  gnome-tweaks                — fine-tune appearance"
    info "  $0 --dump                   — backup your settings"
    info "  dconf load / < backup.ini   — restore settings on new machine"
}

main "$@"
