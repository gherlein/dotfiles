#!/bin/bash
# install-mac.sh - Bootstrap a Mac development environment
# Edit out any sections or packages you no longer want before running.

set -euo pipefail

info()  { echo "[INFO]  $*"; }
ok()    { echo "[OK]    $*"; }
warn()  { echo "[WARN]  $*"; }
die()   { echo "[ERROR] $*" >&2; exit 1; }

[[ "$OSTYPE" == "darwin"* ]] || die "This script is for macOS only."

# ---------------------------------------------------------------------------
# Homebrew
# ---------------------------------------------------------------------------

if ! command -v brew &>/dev/null; then
    info "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # Apple Silicon path
    if [[ -f /opt/homebrew/bin/brew ]]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    fi
else
    info "Homebrew already installed, updating..."
    brew update
fi

# ---------------------------------------------------------------------------
# Homebrew taps
# ---------------------------------------------------------------------------

taps=(
    atlassian/acli
    charmbracelet/tap
    dagger/tap
    opencode-ai/tap
    tinygo-org/tools
)

for tap in "${taps[@]}"; do
    info "Tapping $tap..."
    brew tap "$tap" || warn "Failed to tap $tap"
done

# ---------------------------------------------------------------------------
# Homebrew packages
# ---------------------------------------------------------------------------

packages=(
    atlassian/acli/acli           # Atlassian CLI
    cmake                         # Build system
    coreutils                     # GNU core utilities
    curl                          # HTTP client
    direnv                        # Per-directory environment variables
    emacs                         # Editor
    ffmpeg                        # Audio/video processing
    fzf                           # Fuzzy finder
    gh                            # GitHub CLI
    git                           # Version control
    git-filter-repo               # Git history rewriting
    git-lfs                       # Git large file storage
    gnu-sed                       # GNU sed
    grafana                       # Metrics dashboard
    libmarpa                      # Parsing library
    marp-cli                      # Markdown presentations
    mediamtx                      # Media/RTSP server
    mg                            # Micro Emacs
    node_exporter                 # Prometheus node metrics exporter
    ollama                        # Local LLM runner
    opencode-ai/tap/opencode      # AI coding tool
    p7zip                         # Archive tool
    pandoc                        # Document format converter
    pipx                          # Python application installer
    podman                        # Container runtime
    poppler                       # PDF tools
    prometheus                    # Metrics collection
    protobuf-c                    # Protocol Buffers C library
    putty                         # SSH client
    pyenv                         # Python version manager
    qpdf                          # PDF manipulation
    ripgrep                       # Fast grep
    socat                         # Socket relay
    squashfs                      # SquashFS filesystem tools
    texlive                       # LaTeX distribution
    tinygo-org/tools/tinygo       # Go compiler for microcontrollers
    tree                          # Directory tree viewer
    usbutils                      # USB device utilities
    uv                            # Fast Python package manager
    w3m                           # Terminal web browser
    wget                          # File downloader
    wireshark                     # Network packet analyzer
    yt-dlp                        # Video downloader
)

info "Installing Homebrew packages..."
for pkg in "${packages[@]}"; do
    # Strip inline comment
    pkg="${pkg%%#*}"
    pkg="${pkg%"${pkg##*[![:space:]]}"}"
    if brew list --formula "$pkg" &>/dev/null 2>&1; then
        info "Already installed: $pkg"
    else
        info "Installing $pkg..."
        brew install "$pkg" && ok "$pkg" || warn "Failed to install $pkg"
    fi
done

# ---------------------------------------------------------------------------
# Python via pyenv
# ---------------------------------------------------------------------------

PYTHON_VERSION="3.11.11"

info "Setting up Python $PYTHON_VERSION via pyenv..."
if pyenv versions | grep -q "$PYTHON_VERSION"; then
    info "Python $PYTHON_VERSION already installed."
else
    pyenv install "$PYTHON_VERSION"
fi
pyenv global "$PYTHON_VERSION"

# ---------------------------------------------------------------------------
# Node.js via nvm
# ---------------------------------------------------------------------------

if [[ ! -d "$HOME/.nvm" ]]; then
    info "Installing nvm..."
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
fi

export NVM_DIR="$HOME/.nvm"
# shellcheck source=/dev/null
[[ -s "$NVM_DIR/nvm.sh" ]] && source "$NVM_DIR/nvm.sh"

info "Installing Node.js LTS..."
nvm install --lts
nvm use --lts

info "Installing global npm packages..."
npm install -g typescript aws-cdk

# ---------------------------------------------------------------------------
# pnpm
# ---------------------------------------------------------------------------

if ! command -v pnpm &>/dev/null; then
    info "Installing pnpm..."
    curl -fsSL https://get.pnpm.io/install.sh | sh -
else
    info "pnpm already installed."
fi

# ---------------------------------------------------------------------------
# AWS CLI v2
# ---------------------------------------------------------------------------

if ! command -v aws &>/dev/null; then
    info "Installing AWS CLI v2..."
    curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "/tmp/AWSCLIV2.pkg"
    sudo installer -pkg /tmp/AWSCLIV2.pkg -target /
    rm /tmp/AWSCLIV2.pkg
else
    info "AWS CLI already installed: $(aws --version)"
fi

# ---------------------------------------------------------------------------
# Python ML stack (via uv)
# ---------------------------------------------------------------------------

info "Installing Python ML packages via uv..."
uv pip install \
    torch torchvision torchaudio \
    numpy pandas scikit-learn matplotlib seaborn \
    pillow opencv-python \
    jupyter notebook ipython \
    transformers datasets accelerate timm \
    tqdm wandb tensorboard \
    albumentations imgaug torchmetrics

# ---------------------------------------------------------------------------
# Tailscale
# ---------------------------------------------------------------------------

if ! command -v tailscale &>/dev/null; then
    info "Installing Tailscale..."
    curl -fsSL https://tailscale.com/install.sh | sh
else
    info "Tailscale already installed."
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo "================================================================"
echo "Installation complete."
echo ""
echo "Next steps:"
echo "  - Add pyenv init to your shell profile if not already present"
echo "  - Add nvm source lines to your shell profile if not already present"
echo "  - Run 'brew doctor' to check for any Homebrew issues"
echo "  - Log in to Tailscale: sudo tailscale up"
echo "================================================================"
