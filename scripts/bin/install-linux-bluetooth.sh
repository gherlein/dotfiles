#!/bin/bash
# install-linux-bluetooth.sh - Install the Bluetooth stack, desktop tools,
#                              audio support, and development headers on Ubuntu.
# Requires: apt (Debian/Ubuntu), sudo

set -euo pipefail

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; }
warn()  { echo "[WARN]  $*"; }
die()   { echo "[ERROR] $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

command -v apt-get &>/dev/null || die "apt-get not found. This script targets Debian/Ubuntu."

if [[ $EUID -eq 0 ]]; then
    SUDO=""
else
    command -v sudo &>/dev/null || die "sudo not found and not running as root."
    SUDO="sudo"
fi

# ---------------------------------------------------------------------------
# Package groups
# ---------------------------------------------------------------------------

# Core Bluetooth stack and command-line tooling.
#   bluez        - core stack: bluetoothd, bluetoothctl, btmon, hcitool, gatttool
#   bluez-tools  - extra helpers: bt-adapter, bt-device, bt-agent, ...
#   bluez-obexd  - OBEX object push / file transfer daemon
#   rfkill       - enable/disable and query radio blocks
CORE_PKGS=(
    bluez
    bluez-tools
    bluez-obexd
    rfkill
)

# Desktop / GUI management.
#   blueman         - GTK Bluetooth manager (applet + settings)
#   gnome-bluetooth - GNOME integration and the libgnome-bluetooth stack
DESKTOP_PKGS=(
    blueman
    gnome-bluetooth
)

# Development toolchain for building Bluetooth software.
#   libbluetooth-dev - BlueZ headers/libs (bluetooth/bluetooth.h, -lbluetooth)
#   libdbus-1-dev    - D-Bus (BlueZ's primary API surface is D-Bus)
#   libglib2.0-dev   - GLib/GDBus, needed by most BlueZ client code
#   pkg-config       - resolve include/link flags for the above
#   build-essential  - gcc, make, headers
#   python3-dbus     - Python D-Bus bindings (talk to bluetoothd)
#   python3-gi       - PyGObject / GLib bindings
#   bluez-hcidump    - hcidump (packet-level HCI debugging)
DEV_PKGS=(
    libbluetooth-dev
    libdbus-1-dev
    libglib2.0-dev
    pkg-config
    build-essential
    python3-dbus
    python3-gi
    bluez-hcidump
)

# ---------------------------------------------------------------------------
# Audio backend: detect PipeWire vs PulseAudio and pick the right BT module
# ---------------------------------------------------------------------------

AUDIO_PKGS=()
if dpkg -s pipewire &>/dev/null || systemctl --user is-active --quiet pipewire 2>/dev/null; then
    info "PipeWire detected; using libspa-0.2-bluetooth for Bluetooth audio."
    AUDIO_PKGS=( libspa-0.2-bluetooth )
elif dpkg -s pulseaudio &>/dev/null; then
    info "PulseAudio detected; using pulseaudio-module-bluetooth."
    AUDIO_PKGS=( pulseaudio-module-bluetooth )
else
    info "No PipeWire/PulseAudio detected; defaulting to PipeWire Bluetooth support."
    AUDIO_PKGS=( libspa-0.2-bluetooth )
fi

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

ALL_PKGS=( "${CORE_PKGS[@]}" "${DESKTOP_PKGS[@]}" "${DEV_PKGS[@]}" "${AUDIO_PKGS[@]}" )

info "Updating package index..."
$SUDO apt-get update

info "Installing ${#ALL_PKGS[@]} packages..."
$SUDO apt-get install -y "${ALL_PKGS[@]}"

# ---------------------------------------------------------------------------
# Enable and start the Bluetooth service
# ---------------------------------------------------------------------------

if command -v systemctl &>/dev/null; then
    info "Enabling and starting the bluetooth service..."
    $SUDO systemctl enable bluetooth
    $SUDO systemctl start bluetooth || warn "Could not start bluetooth service (no adapter, or headless?)."
else
    warn "systemctl not found; skipping service enable/start."
fi

# Unblock the radio if rfkill reports it soft-blocked.
if command -v rfkill &>/dev/null; then
    if rfkill list bluetooth 2>/dev/null | grep -q "Soft blocked: yes"; then
        info "Bluetooth is soft-blocked; unblocking..."
        $SUDO rfkill unblock bluetooth
    fi
fi

# ---------------------------------------------------------------------------
# Status report
# ---------------------------------------------------------------------------

echo ""
echo "================================================================"
echo "Bluetooth installation complete."
echo ""

if command -v bluetoothctl &>/dev/null; then
    echo "Adapters seen by BlueZ:"
    bluetoothctl list 2>/dev/null | sed 's/^/  /' || echo "  (none reported)"
    echo ""
fi

echo "Verify the dev toolchain:"
echo "  pkg-config --cflags --libs bluez"
echo "  echo '#include <bluetooth/bluetooth.h>' | gcc -E -x c - >/dev/null && echo OK"
echo ""
echo "Manage devices:"
echo "  bluetoothctl              # interactive: power on, scan on, pair, connect"
echo "  systemctl status bluetooth"
echo "  btmon                     # live HCI trace (needs sudo)"
echo ""
echo "You may need to log out/in (or start the Blueman applet) for the"
echo "desktop Bluetooth tray icon to appear."
echo "================================================================"
