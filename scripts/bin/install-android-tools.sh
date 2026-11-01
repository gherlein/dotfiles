#!/bin/bash
# install-android-tools.sh - Install a CLI-only Android development toolchain on
#                            Ubuntu/Debian: the Android SDK (command-line tools,
#                            platform-tools, build-tools, a platform, emulator +
#                            system image, NDK), an emulator AVD, USB device udev
#                            rules, gomobile, and the Capacitor CLI.
#
# Target: phone/tablet development without Android Studio. Everything lands in a
# self-contained SDK under $HOME so nothing but the udev rules needs root.
#
# Requires: apt (Debian/Ubuntu), sudo, wget, unzip. Go and Node are needed only
#           for the gomobile and Capacitor steps respectively (auto-skipped if
#           absent, with a warning).
#
# Idempotent: safe to re-run. Already-installed SDK packages are left alone, the
# env block is written once (marker-guarded), and the AVD is only created if new.
#
# Toggle any stage off with an env var, e.g.:
#   WITH_EMULATOR=0 WITH_GOMOBILE=0 ./install-android-tools.sh

set -euo pipefail

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; }
warn()  { echo "[WARN]  $*"; }
die()   { echo "[ERROR] $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Configuration (override via environment)
# ---------------------------------------------------------------------------

# Where the self-contained SDK lives.
SDK_ROOT="${ANDROID_HOME:-$HOME/Android/Sdk}"

# Component versions. Bump these as new stable releases land; query options with
#   $SDK_ROOT/cmdline-tools/latest/bin/sdkmanager --list
API_LEVEL="${ANDROID_API_LEVEL:-36}"          # Android 16 == API 36
BUILD_TOOLS="${ANDROID_BUILD_TOOLS:-36.0.0}"
NDK_VERSION="${ANDROID_NDK_VERSION:-27.3.13750724}"   # r27 LTS, well-tested by gomobile
SYSIMG_TAG="${ANDROID_SYSIMG_TAG:-google_apis}"
SYSIMG_ABI="${ANDROID_SYSIMG_ABI:-x86_64}"
AVD_NAME="${ANDROID_AVD_NAME:-pixel_api36}"
AVD_DEVICE="${ANDROID_AVD_DEVICE:-pixel_7}"

# Command-line tools bootstrap archive. The sha256 pins THIS build; if you change
# the URL to a newer build you MUST update the checksum (find it on
# https://developer.android.com/studio#command-line-tools-only). Set
# CMDLINE_TOOLS_SHA256=skip to bypass verification (not recommended).
CMDLINE_TOOLS_URL="${CMDLINE_TOOLS_URL:-https://dl.google.com/android/repository/commandlinetools-linux-14742923_latest.zip}"
CMDLINE_TOOLS_SHA256="${CMDLINE_TOOLS_SHA256:-04453066b540409d975c676d781da1477479dde3761310f1a7eb92a1dfb15af7}"

# Shell file that gets the env block. Defaults to the host-specific private file
# if present (so it does not leak to other machines), else ~/.config/android-sdk.env.
if [[ -z "${ANDROID_ENV_FILE:-}" ]]; then
    if [[ -f "$HOME/.config/work.local.env" ]]; then
        ANDROID_ENV_FILE="$HOME/.config/work.local.env"
    else
        ANDROID_ENV_FILE="$HOME/.config/android-sdk.env"
    fi
fi

# Stage toggles (1 = on).
WITH_EMULATOR="${WITH_EMULATOR:-1}"
WITH_UDEV="${WITH_UDEV:-1}"
WITH_GOMOBILE="${WITH_GOMOBILE:-1}"
WITH_CAPACITOR="${WITH_CAPACITOR:-1}"

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

command -v apt-get &>/dev/null || die "apt-get not found. This script targets Debian/Ubuntu."
command -v wget   &>/dev/null || die "wget not found. Install it: sudo apt install wget"
command -v unzip  &>/dev/null || die "unzip not found. Install it: sudo apt install unzip"

if [[ $EUID -eq 0 ]]; then
    SUDO=""
else
    command -v sudo &>/dev/null || die "sudo not found and not running as root."
    SUDO="sudo"
fi

# A JDK (17+) is required by sdkmanager, Gradle, and Capacitor. Install JDK 21 if
# none is present, then resolve JAVA_HOME from the running java.
if ! command -v java &>/dev/null; then
    info "No JDK found; installing openjdk-21-jdk..."
    $SUDO apt-get update
    $SUDO apt-get install -y openjdk-21-jdk
fi
JAVA_BIN="$(readlink -f "$(command -v java)")"
export JAVA_HOME="${JAVA_HOME:-${JAVA_BIN%/bin/java}}"
info "Using JAVA_HOME=$JAVA_HOME"

# Tools inside the SDK, referenced by FULL PATH throughout. This matters because
# some machines (e.g. with NVIDIA JetPack) ship an UNRELATED /usr/bin/sdkmanager;
# never trust a bare 'sdkmanager' on PATH.
SDKMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
AVDMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/avdmanager"

# ---------------------------------------------------------------------------
# 1. Android SDK command-line tools (bootstrap)
# ---------------------------------------------------------------------------

if [[ -x "$SDKMANAGER" ]]; then
    ok "cmdline-tools already present at $SDK_ROOT/cmdline-tools/latest"
else
    info "Bootstrapping Android command-line tools into $SDK_ROOT ..."
    mkdir -p "$SDK_ROOT/cmdline-tools"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    wget -q -O "$tmp/cmdline-tools.zip" "$CMDLINE_TOOLS_URL"

    if [[ "$CMDLINE_TOOLS_SHA256" != "skip" ]]; then
        info "Verifying checksum..."
        got="$(sha256sum "$tmp/cmdline-tools.zip" | awk '{print $1}')"
        [[ "$got" == "$CMDLINE_TOOLS_SHA256" ]] \
            || die "Checksum mismatch: got $got, expected $CMDLINE_TOOLS_SHA256"
    fi

    unzip -q "$tmp/cmdline-tools.zip" -d "$tmp/extract"
    # Use the freshly-unzipped tools to install the sdkmanager-managed copy at the
    # canonical path. Installing it via sdkmanager (rather than leaving the raw
    # unzip in place) avoids a later 'inconsistent location' dup at latest-2.
    yes | "$tmp/extract/cmdline-tools/bin/sdkmanager" --sdk_root="$SDK_ROOT" \
        "cmdline-tools;latest" >/dev/null
    rm -rf "$tmp"; trap - EXIT
    [[ -x "$SDKMANAGER" ]] || die "cmdline-tools install failed; $SDKMANAGER not found."
    ok "cmdline-tools installed."
fi

# ---------------------------------------------------------------------------
# 2. Accept licenses and install SDK packages
# ---------------------------------------------------------------------------

info "Accepting SDK licenses..."
yes | "$SDKMANAGER" --sdk_root="$SDK_ROOT" --licenses >/dev/null

PACKAGES=(
    "platform-tools"
    "platforms;android-${API_LEVEL}"
    "build-tools;${BUILD_TOOLS}"
    "ndk;${NDK_VERSION}"
)
if [[ "$WITH_EMULATOR" == "1" ]]; then
    PACKAGES+=( "emulator" "system-images;android-${API_LEVEL};${SYSIMG_TAG};${SYSIMG_ABI}" )
fi

info "Installing SDK packages: ${PACKAGES[*]}"
yes | "$SDKMANAGER" --sdk_root="$SDK_ROOT" "${PACKAGES[@]}" >/dev/null
ok "SDK packages installed."

# ---------------------------------------------------------------------------
# 3. Emulator AVD
# ---------------------------------------------------------------------------

if [[ "$WITH_EMULATOR" == "1" ]]; then
    if "$AVDMANAGER" list avd 2>/dev/null | grep -q "Name: ${AVD_NAME}$"; then
        ok "AVD '$AVD_NAME' already exists."
    else
        info "Creating AVD '$AVD_NAME' ($AVD_DEVICE, API $API_LEVEL)..."
        echo "no" | "$AVDMANAGER" create avd \
            -n "$AVD_NAME" \
            -k "system-images;android-${API_LEVEL};${SYSIMG_TAG};${SYSIMG_ABI}" \
            -d "$AVD_DEVICE" >/dev/null
        ok "AVD created."
    fi

    # Hardware acceleration needs /dev/kvm and membership in the kvm group.
    if [[ -e /dev/kvm ]]; then
        if ! id -nG "$USER" | grep -qw kvm; then
            info "Adding $USER to the kvm group (log out/in to take effect)..."
            $SUDO usermod -aG kvm "$USER"
        fi
    else
        warn "/dev/kvm not present; the emulator will run without hardware acceleration."
    fi
fi

# ---------------------------------------------------------------------------
# 4. USB device support (udev rules) for physical phones/tablets
# ---------------------------------------------------------------------------

if [[ "$WITH_UDEV" == "1" ]]; then
    if dpkg -s android-sdk-platform-tools-common &>/dev/null; then
        ok "udev rules (android-sdk-platform-tools-common) already installed."
    else
        info "Installing udev rules for USB devices..."
        $SUDO apt-get update
        $SUDO apt-get install -y android-sdk-platform-tools-common
    fi
    # The udev package creates the plugdev group and the 51-android.rules; add the
    # user so adb can claim a plugged-in device without root.
    if ! id -nG "$USER" | grep -qw plugdev; then
        info "Adding $USER to the plugdev group (log out/in to take effect)..."
        $SUDO usermod -aG plugdev "$USER"
    fi
fi

# ---------------------------------------------------------------------------
# 5. Environment block (marker-guarded, written once)
# ---------------------------------------------------------------------------

ENV_MARKER_START="# >>> android-tools (install-android-tools.sh) >>>"
ENV_MARKER_END="# <<< android-tools <<<"

mkdir -p "$(dirname "$ANDROID_ENV_FILE")"
touch "$ANDROID_ENV_FILE"

if grep -qF "$ENV_MARKER_START" "$ANDROID_ENV_FILE"; then
    ok "Env block already present in $ANDROID_ENV_FILE"
else
    info "Writing env block to $ANDROID_ENV_FILE"
    cat >> "$ANDROID_ENV_FILE" <<EOF

$ENV_MARKER_START
# CLI-only Android SDK. Guarded so it is inert if the SDK is removed.
# PATH is PREPENDED so this sdkmanager wins over any unrelated /usr/bin/sdkmanager
# (NVIDIA JetPack ships one by that name).
if [[ -d "\$HOME/Android/Sdk" ]]; then
    export ANDROID_HOME="\$HOME/Android/Sdk"
    export ANDROID_SDK_ROOT="\$ANDROID_HOME"
    export JAVA_HOME="\${JAVA_HOME:-$JAVA_HOME}"
    _ndk="\$(ls -d "\$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1)"
    [[ -n "\$_ndk" ]] && export ANDROID_NDK_HOME="\$_ndk" && export ANDROID_NDK_ROOT="\$_ndk"
    unset _ndk
    export PATH="\$ANDROID_HOME/cmdline-tools/latest/bin:\$ANDROID_HOME/platform-tools:\$ANDROID_HOME/emulator:\$PATH"
fi
$ENV_MARKER_END
EOF
    ok "Env block written. Open a new shell (or source the file) to load it."
fi

# Export for the remainder of this run so gomobile init sees the NDK.
export ANDROID_HOME="$SDK_ROOT"
export ANDROID_SDK_ROOT="$SDK_ROOT"
export ANDROID_NDK_HOME="$SDK_ROOT/ndk/$NDK_VERSION"
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
export PATH="$SDK_ROOT/cmdline-tools/latest/bin:$SDK_ROOT/platform-tools:$SDK_ROOT/emulator:$PATH"

# ---------------------------------------------------------------------------
# 6. gomobile (Go -> Android libraries/apps)
# ---------------------------------------------------------------------------

if [[ "$WITH_GOMOBILE" == "1" ]]; then
    if ! command -v go &>/dev/null; then
        warn "Go not found; skipping gomobile. Install Go, then re-run or:"
        warn "  go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init"
    else
        GOBIN="$(go env GOBIN)"; GOBIN="${GOBIN:-$(go env GOPATH)/bin}"
        info "Installing gomobile and gobind into $GOBIN ..."
        GOBIN="$GOBIN" go install golang.org/x/mobile/cmd/gomobile@latest
        GOBIN="$GOBIN" go install golang.org/x/mobile/cmd/gobind@latest
        info "Running gomobile init (builds the NDK-backed toolchain cache)..."
        "$GOBIN/gomobile" init
        ok "gomobile ready."
    fi
fi

# ---------------------------------------------------------------------------
# 7. Capacitor CLI (web -> native Android)
# ---------------------------------------------------------------------------

if [[ "$WITH_CAPACITOR" == "1" ]]; then
    if ! command -v npm &>/dev/null; then
        warn "npm not found; skipping Capacitor. Install Node, then re-run or:"
        warn "  npm install -g @capacitor/cli native-run"
    else
        info "Installing @capacitor/cli and native-run globally..."
        npm install -g @capacitor/cli native-run
        ok "Capacitor CLI ready."
    fi
fi

# ---------------------------------------------------------------------------
# Status report
# ---------------------------------------------------------------------------

echo ""
echo "================================================================"
echo "Android toolchain installation complete."
echo ""
echo "SDK:        $SDK_ROOT"
echo "Env file:   $ANDROID_ENV_FILE  (open a NEW shell to load it)"
echo ""
echo "Verify in a fresh shell:"
echo "  adb version"
echo "  sdkmanager --version          # must resolve to the Android one, not NVIDIA's"
echo "  avdmanager list avd"
[[ "$WITH_GOMOBILE"  == "1" ]] && echo "  gomobile version"
[[ "$WITH_CAPACITOR" == "1" ]] && echo "  cap --version"
echo ""
[[ "$WITH_EMULATOR" == "1" ]] && cat <<EOF
Start the emulator (headless):
  emulator @$AVD_NAME -no-window -no-audio -no-snapshot &
  adb wait-for-device && adb shell getprop sys.boot_completed

EOF
[[ "$WITH_UDEV" == "1" ]] && cat <<EOF
Physical devices: enable USB debugging on the device, plug it in, then:
  adb devices
(If it shows 'no permissions', log out/in so the plugdev group applies.)

EOF
echo "================================================================"
