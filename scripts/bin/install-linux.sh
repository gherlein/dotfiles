#!/bin/bash
# install-linux.sh - Bootstrap a Linux (Debian/Ubuntu) development environment
# Edit out any sections or packages you no longer want before running.

set -euo pipefail

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; }
warn()  { echo "[WARN]  $*"; }
die()   { echo "[ERROR] $*" >&2; exit 1; }

[[ "$OSTYPE" == "linux-gnu" || "$OSTYPE" == "linux-gnueabihf" ]] || die "This script is for Linux only."

command -v apt-get &>/dev/null || die "This script requires apt (Debian/Ubuntu)."

ARCH="$(dpkg --print-architecture)"
info "Detected architecture: $ARCH"

# ---------------------------------------------------------------------------
# Platform detection (Raspberry Pi / headless)
# ---------------------------------------------------------------------------

# A Pi cannot be identified by arch alone (a cloud ARM VM is also arm64), so
# key off the board model. Device-tree is authoritative on modern Pi OS; the
# cpuinfo grep is a fallback for older/32-bit images.
is_raspberry_pi() {
    if [[ -r /proc/device-tree/model ]] \
        && tr -d '\0' < /proc/device-tree/model | grep -qi "raspberry pi"; then
        return 0
    fi
    grep -qi "raspberry pi" /proc/cpuinfo 2>/dev/null
}

# True only when an active local graphical session is present. We key off
# session env vars, not installed binaries: a headless Pi may have a desktop
# installed but boot to console (gnome-shell present, no session). DISPLAY
# alone is untrustworthy because `ssh -X` forwards it onto a headless box, so
# it only counts when this is not an SSH session.
has_desktop() {
    [[ -n "${XDG_CURRENT_DESKTOP:-}" || -n "${WAYLAND_DISPLAY:-}" ]] && return 0
    [[ -n "${DISPLAY:-}" && -z "${SSH_CONNECTION:-}" && -z "${SSH_TTY:-}" ]] && return 0
    return 1
}

if is_raspberry_pi; then IS_RPI=true; info "Raspberry Pi detected."; else IS_RPI=false; fi

# ---------------------------------------------------------------------------
# REMOVE SNAP COMPLETELY - Do this FIRST before installing anything
# ---------------------------------------------------------------------------

# Moved to ./snap-remove.sh — run that script first if you want snap removed
# and permanently disabled.

# ---------------------------------------------------------------------------
# Section selection
# ---------------------------------------------------------------------------

# ASSUME is "" (prompt interactively), "yes", or "no". In unattended runs every
# section not preset via its INSTALL_* environment variable takes this default.
ASSUME=""

usage() {
    cat <<EOF
Usage: $(basename "$0") [-y|--yes] [-n|--no] [-h|--help]

  -y, --yes   Unattended: install every section (except those disabled by
              hardware/desktop detection). Overridable per section via env vars.
  -n, --no    Unattended: install only the always-on base; skip every optional
              section unless its env var is set to true.
  -h, --help  Show this help and exit.

Per-section env overrides (set to true or false to skip that prompt):
  INSTALL_DEV INSTALL_PYTHON INSTALL_AMD INSTALL_CONTAINERS
  INSTALL_NETWORK INSTALL_MONITORING INSTALL_AI INSTALL_GUI

Example (headless install of dev tools only):
  INSTALL_DEV=true $(basename "$0") -n
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes)  ASSUME=yes ;;
        -n|--no)   ASSUME=no ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown argument: $1 (try --help)" ;;
    esac
    shift
done

# A non-interactive stdin (piped install, cron, CI) cannot answer prompts, so
# fall back to a safe default of "no" unless the caller picked a mode.
if [[ -z "$ASSUME" && ! -t 0 ]]; then
    ASSUME=no
    warn "Non-interactive shell — defaulting optional sections to 'no'. Use -y or INSTALL_* env vars to enable them."
fi

ask() {
    local prompt="$1" reply
    while true; do
        read -rp "$prompt [y/n]: " reply
        case "$reply" in
            [Yy]*) return 0 ;;
            [Nn]*) return 1 ;;
            *) echo "Please answer y or n." ;;
        esac
    done
}

# resolve VAR "prompt" — set INSTALL_* to true/false. Precedence: an existing
# environment value wins (validated); then the unattended ASSUME default;
# otherwise prompt interactively.
resolve() {
    local var="$1" prompt="$2" val
    # Assign val on its own line: bash rejects `${!var}` on the same `local`
    # line that first sets var ("invalid indirect expansion").
    val="${!var:-}"
    if [[ -n "$val" ]]; then
        [[ "$val" == "true" || "$val" == "false" ]] || die "$var must be 'true' or 'false', got '$val'."
        info "$var=$val (from environment)"
    elif [[ "$ASSUME" == "yes" ]]; then
        printf -v "$var" true
    elif [[ "$ASSUME" == "no" ]]; then
        printf -v "$var" false
    elif ask "$prompt"; then
        printf -v "$var" true
    else
        printf -v "$var" false
    fi
}

echo "Select which sections to install (the base system/apt packages always run):"
echo ""

resolve INSTALL_DEV "Development toolchains (Go, TinyGo, Rust, protoc-gen-go, Node/npm, pnpm, AWS CLI)?"

if [[ "$IS_RPI" == "true" ]]; then
    warn "Python/ML stack is heavy and CPU-only on a Pi (torch, transformers, jupyter) — say no unless you really need it."
fi
resolve INSTALL_PYTHON "Python/ML stack (uv, torch/transformers/jupyter venv, pdf2md)?"

# AMD GPU tools have no meaning on a Pi (Broadcom VideoCore, no AMD hardware).
if [[ "$IS_RPI" == "true" ]]; then
    INSTALL_AMD=false
    info "Raspberry Pi — skipping AMD GPU tools (no AMD hardware)."
else
    resolve INSTALL_AMD "AMD GPU tools (amdgpu_top, ROCm drivers)?"
fi

resolve INSTALL_CONTAINERS "Container tooling (Docker, localdev/podman)?"
resolve INSTALL_NETWORK "Networking/VPN (Tailscale, ZeroTier)?"
resolve INSTALL_MONITORING "Monitoring stack (Prometheus, node_exporter, Grafana)?"

if [[ "$IS_RPI" == "true" ]]; then
    warn "Ollama models generally exceed a Pi's memory — expect it to be slow or OOM."
fi
resolve INSTALL_AI "AI tools (Ollama)?"

# GUI apps need a desktop session; a headless box (typical Pi) has none. The
# Kitty gsettings step in particular fails without a dconf/GNOME session. This
# gate wins over any INSTALL_GUI env value — the apps cannot run without a
# display.
if has_desktop; then
    resolve INSTALL_GUI "GUI/desktop apps (Signal Desktop, Kitty terminal)?"
else
    INSTALL_GUI=false
    info "No desktop environment detected — skipping GUI/desktop apps."
fi

echo ""

# ---------------------------------------------------------------------------
# System update
# ---------------------------------------------------------------------------

info "Updating package lists..."
sudo apt-get update

# ---------------------------------------------------------------------------
# Core apt packages
# ---------------------------------------------------------------------------

info "Installing core apt packages..."
sudo apt-get install -y \
    apt-transport-https \
    build-essential \
    ca-certificates \
    curl \
    direnv \
    emacs-nox \
    expect \
    ffmpeg \
    git \
    git-lfs \
    gnupg \
    jq \
    keychain \
    libdrm-dev \
    libstdc++6 \
    lsb-release \
    mg \
    micro \
    podman \
    protobuf-compiler \
    python3-setuptools \
    python3-wheel \
    ripgrep \
    socat \
    stow \
    tree \
    unzip \
    usbutils \
    wget \
    zip

# ---------------------------------------------------------------------------
# keychain
# ---------------------------------------------------------------------------

# Key file is named after the login user. Override with SSH_KEY=/path/to/key.
# id -un is the reliable fallback when $USER is unset (cron/non-interactive).
SSH_KEY="${SSH_KEY:-$HOME/.ssh/${USER:-$(id -un)}}"

info "Configuring keychain..."
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
if [[ -f "$SSH_KEY" ]]; then
    chmod 600 "$SSH_KEY"
    keychain "$SSH_KEY"
    # shellcheck source=/dev/null
    [[ -f "$HOME/.keychain/$HOSTNAME-sh" ]] && source "$HOME/.keychain/$HOSTNAME-sh"
    ok "keychain initialized with $SSH_KEY"
else
    warn "SSH key $SSH_KEY not found — copy it to this host then run: keychain $SSH_KEY"
fi

# ---------------------------------------------------------------------------
# Development toolchains (Go, TinyGo, Rust, protoc-gen-go, Node, pnpm, AWS CLI)
# ---------------------------------------------------------------------------

if [[ "$INSTALL_DEV" == "true" ]]; then

GO_VERSION="1.25.4"
TINYGO_VERSION="0.33.0"

info "Installing Go $GO_VERSION..."
if [[ "$ARCH" == "amd64" ]]; then
    GO_URL="https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
elif [[ "$ARCH" == "arm64" ]]; then
    GO_URL="https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz"
elif [[ "$ARCH" == "armhf" ]]; then
    GO_URL="https://go.dev/dl/go${GO_VERSION}.linux-armv6l.tar.gz"
else
    warn "Unknown architecture $ARCH — skipping Go install."
    GO_URL=""
fi

if [[ -n "$GO_URL" ]]; then
    wget -q "$GO_URL" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    ok "Go installed to /usr/local/go"
fi

info "Installing TinyGo $TINYGO_VERSION..."
if [[ "$ARCH" == "amd64" ]]; then
    TINYGO_URL="https://github.com/tinygo-org/tinygo/releases/download/v${TINYGO_VERSION}/tinygo_${TINYGO_VERSION}_amd64.deb"
elif [[ "$ARCH" == "arm64" ]]; then
    TINYGO_URL="https://github.com/tinygo-org/tinygo/releases/download/v${TINYGO_VERSION}/tinygo_${TINYGO_VERSION}_arm64.deb"
elif [[ "$ARCH" == "armhf" ]]; then
    TINYGO_URL="https://github.com/tinygo-org/tinygo/releases/download/v${TINYGO_VERSION}/tinygo_${TINYGO_VERSION}_armhf.deb"
    sudo apt-get install -y libstdc++6:armhf
else
    warn "Unknown architecture $ARCH — skipping TinyGo install."
    TINYGO_URL=""
fi

if [[ -n "$TINYGO_URL" ]]; then
    wget -q "$TINYGO_URL" -O /tmp/tinygo.deb
    sudo dpkg -i /tmp/tinygo.deb
    rm /tmp/tinygo.deb
fi

info "Installing Rust via rustup..."
if ! command -v cargo &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
    rustup update stable
    ok "Rust installed."
else
    info "Rust already installed: $(cargo --version)"
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
    rustup update stable
fi

info "Installing protoc-gen-go..."
if command -v go &>/dev/null || [[ -x /usr/local/go/bin/go ]]; then
    export PATH="$PATH:/usr/local/go/bin"
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
else
    warn "Go not found — skipping protoc-gen-go install."
fi

info "Installing nvm..."
if [[ ! -s "$HOME/.nvm/nvm.sh" ]]; then
    # The nvm-sh/nvm clone is public and read-only; bypass the global
    # "https://github.com/ -> ssh://git@github.com/" rewrite (~/.gitconfig)
    # so it doesn't require SSH auth to GitHub.
    (
        export GIT_CONFIG_GLOBAL=/dev/null
        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
    )
fi

export NVM_DIR="$HOME/.nvm"

# nvm scripts use unbound variables internally; suspend -u around them
set +u
# shellcheck source=/dev/null
[[ -s "$NVM_DIR/nvm.sh" ]] && source "$NVM_DIR/nvm.sh"

info "Installing Node.js LTS..."
nvm install --lts
nvm use --lts
set -u

info "Installing global npm packages..."
npm install -g typescript aws-cdk @anthropic-ai/claude-code

info "Installing pnpm..."
if ! command -v pnpm &>/dev/null; then
    curl -fsSL https://get.pnpm.io/install.sh | sh -
else
    info "pnpm already installed."
fi

info "Installing AWS CLI v2..."
if ! command -v aws &>/dev/null; then
    if [[ "$ARCH" == "amd64" ]]; then
        curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
    elif [[ "$ARCH" == "arm64" ]]; then
        curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o /tmp/awscliv2.zip
    else
        warn "Unknown architecture $ARCH — skipping AWS CLI install."
    fi
    if [[ -f /tmp/awscliv2.zip ]]; then
        unzip -q /tmp/awscliv2.zip -d /tmp/awscli
        sudo /tmp/awscli/aws/install
        rm -rf /tmp/awscliv2.zip /tmp/awscli
    fi
else
    info "AWS CLI already installed: $(aws --version)"
fi

else
    info "Skipping development toolchains."
fi

# ---------------------------------------------------------------------------
# Python / ML stack (uv, torch/transformers venv, pdf2md)
# ---------------------------------------------------------------------------

if [[ "$INSTALL_PYTHON" == "true" ]]; then

info "Installing uv..."
if ! command -v uv &>/dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
else
    info "uv already installed."
fi

VENV="$HOME/.venv"
UV=$(command -v uv || echo "$HOME/.local/bin/uv")

info "Creating Python venv at $VENV..."
"$UV" venv "$VENV"

info "Installing Python ML packages into $VENV..."
if command -v nvidia-smi &>/dev/null && nvidia-smi &>/dev/null; then
    info "GPU detected — installing CUDA torch."
    "$UV" pip install --python "$VENV" torch torchvision torchaudio
else
    info "No GPU detected — installing CPU-only torch."
    "$UV" pip install --python "$VENV" \
        --index-url https://download.pytorch.org/whl/cpu \
        torch torchvision torchaudio
fi
"$UV" pip install --python "$VENV" \
    numpy pandas scikit-learn matplotlib seaborn \
    pillow opencv-python \
    jupyter notebook ipython \
    transformers datasets accelerate timm \
    tqdm wandb tensorboard \
    albumentations imgaug torchmetrics

info "Installing pymupdf4llm into ~/.local/share/pdf2md..."
"$UV" venv "$HOME/.local/share/pdf2md"
"$UV" pip install --python "$HOME/.local/share/pdf2md" pymupdf4llm

else
    info "Skipping Python/ML stack."
fi

# ---------------------------------------------------------------------------
# AMD GPU tools (amdgpu_top, ROCm drivers)
# ---------------------------------------------------------------------------

if [[ "$INSTALL_AMD" == "true" ]]; then

info "Installing amdgpu_top..."
if ! command -v cargo &>/dev/null && [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi
if command -v cargo &>/dev/null; then
    if ! command -v amdgpu_top &>/dev/null; then
        cargo install amdgpu_top
        ok "amdgpu_top installed."
    else
        info "amdgpu_top already installed."
    fi
else
    warn "cargo not found — enable the development toolchains section to install Rust. Skipping amdgpu_top."
fi

if [[ "$ARCH" == "amd64" ]]; then
    ROCM_SCRIPT="$(dirname "$0")/ROCm-install.sh"
    if [[ -x "$ROCM_SCRIPT" ]]; then
        info "Running ROCm-install.sh (AMD GPU drivers / ROCm)..."
        "$ROCM_SCRIPT"
    else
        warn "ROCm-install.sh not found next to this script — skipping ROCm driver install."
    fi
else
    info "ROCm driver install: skipping (amd64 only)."
fi

else
    info "Skipping AMD GPU tools."
fi

# ---------------------------------------------------------------------------
# Container tooling (Docker, localdev)
# ---------------------------------------------------------------------------

if [[ "$INSTALL_CONTAINERS" == "true" ]]; then

info "Installing Docker..."
if ! command -v docker &>/dev/null; then
    sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg \
        | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$ARCH signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
https://download.docker.com/linux/$(. /etc/os-release && echo "$ID") \
$(lsb_release -cs) stable" \
        | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io
    sudo usermod -aG docker "$USER"
    ok "Docker installed. Log out and back in for group membership to take effect."
else
    info "Docker already installed."
fi

info "Installing localdev..."
curl -fsSL https://raw.githubusercontent.com/gherlein/localdev/main/install.sh | bash
# The localdev image may not publish an arch matching this host (e.g. arm64 on
# a Pi). Don't let a missing image abort the whole run under `set -e`.
if podman pull "ghcr.io/gherlein/localdev:latest"; then
    ok "localdev installed."
else
    warn "Could not pull ghcr.io/gherlein/localdev:latest for $ARCH — image may not exist for this architecture. localdev CLI is installed; the container image was skipped."
fi

else
    info "Skipping container tooling."
fi

# ---------------------------------------------------------------------------
# Networking / VPN (Tailscale, ZeroTier)
# ---------------------------------------------------------------------------

if [[ "$INSTALL_NETWORK" == "true" ]]; then

info "Installing Tailscale..."
if ! command -v tailscale &>/dev/null; then
    curl -fsSL https://tailscale.com/install.sh | sh
else
    info "Tailscale already installed."
fi

info "Installing ZeroTier..."
if ! command -v zerotier-cli &>/dev/null; then
    curl -s https://install.zerotier.com | sudo bash
else
    info "ZeroTier already installed."
fi

else
    info "Skipping networking/VPN tools."
fi

# ---------------------------------------------------------------------------
# Monitoring stack (Prometheus, node_exporter, Grafana)
# ---------------------------------------------------------------------------

if [[ "$INSTALL_MONITORING" == "true" ]]; then

info "Installing Prometheus..."
if ! command -v prometheus &>/dev/null; then
    PROM_URL=$(curl -s https://api.github.com/repos/prometheus/prometheus/releases/latest \
        | grep browser_download_url \
        | grep "linux-${ARCH}" \
        | cut -d '"' -f 4)
    wget -q "$PROM_URL" -O /tmp/prometheus.tar.gz
    sudo groupadd --system prometheus 2>/dev/null || true
    sudo useradd -s /sbin/nologin --system -g prometheus prometheus 2>/dev/null || true
    sudo mkdir -p /var/lib/prometheus /etc/prometheus/rules /etc/prometheus/rules.d /etc/prometheus/files_sd
    tar xf /tmp/prometheus.tar.gz -C /tmp
    PROM_DIR=$(tar tf /tmp/prometheus.tar.gz | head -1 | cut -d/ -f1)
    sudo mv "/tmp/${PROM_DIR}/prometheus" "/tmp/${PROM_DIR}/promtool" /usr/local/bin/
    sudo mv "/tmp/${PROM_DIR}/prometheus.yml" /etc/prometheus/
    sudo mv "/tmp/${PROM_DIR}/consoles" "/tmp/${PROM_DIR}/console_libraries" /etc/prometheus/
    sudo chown -R prometheus:prometheus /etc/prometheus /var/lib/prometheus
    rm -rf /tmp/prometheus.tar.gz "/tmp/${PROM_DIR}"
    sudo tee /etc/systemd/system/prometheus.service > /dev/null <<EOF
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=prometheus
Group=prometheus
ExecStart=/usr/local/bin/prometheus \\
  --config.file=/etc/prometheus/prometheus.yml \\
  --storage.tsdb.path=/var/lib/prometheus \\
  --web.console.templates=/etc/prometheus/consoles \\
  --web.console.libraries=/etc/prometheus/console_libraries \\
  --web.listen-address=0.0.0.0:9090
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable --now prometheus
    ok "Prometheus installed and started."
else
    info "Prometheus already installed."
fi

info "Installing Prometheus node_exporter..."
if ! command -v node_exporter &>/dev/null; then
    NE_URL=$(curl -s https://api.github.com/repos/prometheus/node_exporter/releases/latest \
        | grep browser_download_url \
        | grep "linux-${ARCH}" \
        | cut -d '"' -f 4)
    wget -q "$NE_URL" -O /tmp/node_exporter.tar.gz
    tar xf /tmp/node_exporter.tar.gz -C /tmp
    NE_DIR=$(tar tf /tmp/node_exporter.tar.gz | head -1 | cut -d/ -f1)
    sudo mv "/tmp/${NE_DIR}/node_exporter" /usr/local/bin/
    sudo useradd -rs /bin/false node_exporter 2>/dev/null || true
    rm -rf /tmp/node_exporter.tar.gz "/tmp/${NE_DIR}"
    sudo tee /etc/systemd/system/node_exporter.service > /dev/null <<EOF
[Unit]
Description=Prometheus Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable --now node_exporter
    ok "node_exporter installed and started."
else
    info "node_exporter already installed."
fi

info "Installing Grafana..."
if ! command -v grafana-server &>/dev/null; then
    curl -fsSL https://apt.grafana.com/gpg.key \
        | sudo gpg --dearmor -o /usr/share/keyrings/grafana.gpg
    echo "deb [signed-by=/usr/share/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
        | sudo tee /etc/apt/sources.list.d/grafana.list
    sudo apt-get update
    sudo apt-get install -y grafana
    sudo systemctl enable --now grafana-server
    ok "Grafana installed and started."
else
    info "Grafana already installed."
fi

else
    info "Skipping monitoring stack."
fi

# ---------------------------------------------------------------------------
# AI tools (Ollama)
# ---------------------------------------------------------------------------

if [[ "$INSTALL_AI" == "true" ]]; then

info "Installing Ollama..."
if ! command -v ollama &>/dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
else
    info "Ollama already installed."
fi

else
    info "Skipping AI tools."
fi

# ---------------------------------------------------------------------------
# GUI / desktop apps (Signal Desktop, Kitty terminal, PipeWire)
# ---------------------------------------------------------------------------

if [[ "$INSTALL_GUI" == "true" ]]; then

if [[ "$ARCH" == "amd64" ]]; then
    info "Installing Signal Desktop..."
    if ! command -v signal-desktop &>/dev/null; then
        wget -O- https://updates.signal.org/desktop/apt/keys.asc \
            | gpg --dearmor \
            | sudo tee /usr/share/keyrings/signal-desktop-keyring.gpg > /dev/null
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/signal-desktop-keyring.gpg] \
https://updates.signal.org/desktop/apt xenial main" \
            | sudo tee /etc/apt/sources.list.d/signal-xenial.list
        sudo apt-get update
        sudo apt-get install -y signal-desktop
    else
        info "Signal Desktop already installed."
    fi
else
    info "Signal Desktop: skipping (amd64 only)."
fi

info "Installing Kitty..."
if ! command -v kitty &>/dev/null; then
    /bin/sh -c "$(curl -fsSL https://sw.kovidgoyal.net/kitty/installer.sh)"
    mkdir -p "$HOME/.local/bin" "$HOME/.local/share/applications"
    ln -sf "$HOME/.local/kitty.app/bin/kitty" "$HOME/.local/bin/kitty"
    ln -sf "$HOME/.local/kitty.app/bin/kitten" "$HOME/.local/bin/kitten"
    cp "$HOME/.local/kitty.app/share/applications/kitty.desktop" "$HOME/.local/share/applications/"
    cp "$HOME/.local/kitty.app/share/applications/kitty-open.desktop" "$HOME/.local/share/applications/"
    sed -i "s|Icon=kitty|Icon=$HOME/.local/kitty.app/share/icons/hicolor/256x256/apps/kitty.png|g" \
        "$HOME/.local/share/applications/kitty.desktop" \
        "$HOME/.local/share/applications/kitty-open.desktop"
    sed -i "s|Exec=kitty|Exec=$HOME/.local/kitty.app/bin/kitty|g" \
        "$HOME/.local/share/applications/kitty.desktop" \
        "$HOME/.local/share/applications/kitty-open.desktop"
    ok "Kitty installed."
else
    info "Kitty already installed."
fi

# Set Kitty as the default terminal for GNOME desktop (right-click → Open Terminal)
if command -v kitty &>/dev/null && command -v gsettings &>/dev/null; then
    info "Setting Kitty as GNOME default terminal..."
    gsettings set org.gnome.desktop.default-applications.terminal exec "$(which kitty)"
    gsettings set org.gnome.desktop.default-applications.terminal exec-arg ''
    ok "Kitty set as GNOME default terminal."
fi

# ---------------------------------------------------------------------------
# PipeWire (replace PulseAudio — desktop systems only)
# ---------------------------------------------------------------------------

# Uncomment on desktop systems where you want PipeWire instead of PulseAudio.
#
# info "Installing PipeWire..."
# sudo add-apt-repository ppa:pipewire-debian/pipewire-upstream
# sudo apt-get update
# sudo apt-get install -y pipewire libspa-0.2-bluetooth pipewire-audio-client-libraries
# systemctl --user daemon-reload
# systemctl --user --now disable pulseaudio.service pulseaudio.socket
# systemctl --user mask pulseaudio
# systemctl --user --now enable pipewire-media-session.service
# systemctl --user restart pipewire

else
    info "Skipping GUI/desktop apps."
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo "================================================================"
echo "Installation complete."
echo ""
echo "Next steps:"
if [[ "$INSTALL_DEV" == "true" ]]; then
    echo "  - Add to ~/.bash_profile if not present:"
    echo "      export PATH=\$PATH:/usr/local/go/bin"
    echo "      export PATH=\$PATH:\$HOME/go/bin"
    echo "      source \$HOME/.cargo/env"
fi
if [[ "$INSTALL_CONTAINERS" == "true" ]]; then
    echo "  - Log out and back in for Docker group membership"
fi
if [[ "$INSTALL_NETWORK" == "true" ]]; then
    echo "  - Log in to Tailscale:   sudo tailscale up"
    echo "  - Join ZeroTier network: sudo zerotier-cli join <network-id>"
fi
if [[ "$INSTALL_MONITORING" == "true" ]]; then
    echo "  - Prometheus UI:         http://localhost:9090"
    echo "  - Grafana UI:            http://localhost:3000"
fi
if [[ "$INSTALL_AMD" == "true" ]]; then
    echo "  - Reboot to load AMD GPU drivers/ROCm (if installed)"
fi
echo "================================================================"
