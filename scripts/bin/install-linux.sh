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
# Go version - update this to the latest stable release
# ---------------------------------------------------------------------------

GO_VERSION="1.25.4"

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
    tree \
    unzip \
    usbutils \
    wget \
    zip

# ---------------------------------------------------------------------------
# keychain
# ---------------------------------------------------------------------------

SSH_KEY="$HOME/.ssh/gherlein"

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
# Remove snap (optional - comment out if you want to keep snap)
# ---------------------------------------------------------------------------

info "Removing snapd..."
sudo snap remove snap-store       2>/dev/null || true
sudo snap remove gtk-common-themes 2>/dev/null || true
sudo snap remove gnome-3-34-1804  2>/dev/null || true
sudo snap remove core18           2>/dev/null || true
sudo apt-get purge -y snapd       2>/dev/null || true
sudo rm -rf ~/snap /snap /var/snap /var/lib/snapd 2>/dev/null || true

# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# TinyGo (Go compiler for microcontrollers)
# ---------------------------------------------------------------------------

TINYGO_VERSION="0.33.0"

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

# ---------------------------------------------------------------------------
# protoc-gen-go
# ---------------------------------------------------------------------------

info "Installing protoc-gen-go..."
if command -v go &>/dev/null || [[ -x /usr/local/go/bin/go ]]; then
    export PATH="$PATH:/usr/local/go/bin"
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
else
    warn "Go not found — skipping protoc-gen-go install."
fi

# ---------------------------------------------------------------------------
# uv (fast Python package manager)
# ---------------------------------------------------------------------------

info "Installing uv..."
if ! command -v uv &>/dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
else
    info "uv already installed."
fi

# ---------------------------------------------------------------------------
# Python ML stack (via uv venv at ~/.venv)
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Node.js via nvm
# ---------------------------------------------------------------------------

info "Installing nvm..."
if [[ ! -d "$HOME/.nvm" ]]; then
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
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
npm install -g typescript aws-cdk

# ---------------------------------------------------------------------------
# pnpm
# ---------------------------------------------------------------------------

info "Installing pnpm..."
if ! command -v pnpm &>/dev/null; then
    curl -fsSL https://get.pnpm.io/install.sh | sh -
else
    info "pnpm already installed."
fi

# ---------------------------------------------------------------------------
# AWS CLI v2
# ---------------------------------------------------------------------------

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

# Homebrew is macOS tooling and not installed on Linux.

# ---------------------------------------------------------------------------
# Tailscale
# ---------------------------------------------------------------------------

info "Installing Tailscale..."
if ! command -v tailscale &>/dev/null; then
    curl -fsSL https://tailscale.com/install.sh | sh
else
    info "Tailscale already installed."
fi

# ---------------------------------------------------------------------------
# ZeroTier
# ---------------------------------------------------------------------------

info "Installing ZeroTier..."
if ! command -v zerotier-cli &>/dev/null; then
    curl -s https://install.zerotier.com | sudo bash
else
    info "ZeroTier already installed."
fi

# ---------------------------------------------------------------------------
# Signal Desktop (amd64 only)
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Docker (Debian/Ubuntu)
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Prometheus (manual install from GitHub releases)
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Node Exporter (manual install from GitHub releases)
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Grafana
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------

info "Installing Ollama..."
if ! command -v ollama &>/dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
else
    info "Ollama already installed."
fi

# ---------------------------------------------------------------------------
# localdev container environment
# ---------------------------------------------------------------------------

info "Installing localdev..."
curl -fsSL https://raw.githubusercontent.com/gherlein/localdev/main/install.sh | bash
podman pull ghcr.io/gherlein/localdev:latest
ok "localdev installed."

# ---------------------------------------------------------------------------
# AMD ROCm / amdgpu (Ryzen AI / workstation GPU — amd64 only)
# ---------------------------------------------------------------------------

# Uncomment this section on Ryzen AI or AMD GPU workstations.
#
# AMDGPU_VERSION="6.4.60401-1"
# info "Installing AMD GPU drivers and ROCm..."
# wget -q "https://repo.radeon.com/amdgpu-install/6.4.1/ubuntu/noble/amdgpu-install_${AMDGPU_VERSION}_all.deb" \
#     -O /tmp/amdgpu-install.deb
# sudo apt-get install -y ./tmp/amdgpu-install.deb
# amdgpu-install -y --usecase=workstation,rocm
# sudo usermod -aG render,video "$USER"
# info "AMD GPU drivers installed. Reboot required."

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

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo "================================================================"
echo "Installation complete."
echo ""
echo "Next steps:"
echo "  - Add to ~/.bash_profile if not present:"
echo "      export PATH=\$PATH:/usr/local/go/bin"
echo "      export PATH=\$PATH:\$HOME/go/bin"
echo "  - Log out and back in for Docker group membership"
echo "  - Log in to Tailscale:   sudo tailscale up"
echo "  - Join ZeroTier network: sudo zerotier-cli join <network-id>"
echo "  - Prometheus UI:         http://localhost:9090"
echo "  - Grafana UI:            http://localhost:3000"
echo "================================================================"
