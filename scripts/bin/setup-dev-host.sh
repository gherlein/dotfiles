#!/usr/bin/env bash
#
# setup-dev-host.sh — provision a fresh Ubuntu dev host and configure
# GitHub SSH access for cloning private repos.
#
# Idempotent: safe to re-run. It will not overwrite an existing SSH key
# or clobber existing git config unless you pass --force-identity.
#
# Usage:
#   ./setup-dev-host.sh                       # interactive prompts
#   GIT_NAME="Greg Herlein" GIT_EMAIL="you@example.com" ./setup-dev-host.sh
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Config (override via environment)
# ---------------------------------------------------------------------------
GIT_NAME="${GIT_NAME:-}"
GIT_EMAIL="${GIT_EMAIL:-}"
KEY_FILE="${KEY_FILE:-$HOME/.ssh/id_ed25519_github}"
KEY_COMMENT="${KEY_COMMENT:-$(whoami)@$(hostname -s)-$(date +%Y%m%d)}"
FORCE_IDENTITY=0

for arg in "$@"; do
  case "$arg" in
    --force-identity) FORCE_IDENTITY=1 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -20
      exit 0
      ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------------------
# 1. Base system
# ---------------------------------------------------------------------------
info "Updating apt and installing base packages"
sudo apt update
sudo apt upgrade -y
sudo apt install -y git curl build-essential

# ---------------------------------------------------------------------------
# 2. Git identity
# ---------------------------------------------------------------------------
if [ -z "$GIT_NAME" ]; then
  read -rp "Git user.name (e.g. Greg Herlein): " GIT_NAME
fi
if [ -z "$GIT_EMAIL" ]; then
  read -rp "Git user.email (a verified GitHub email): " GIT_EMAIL
fi

existing_name="$(git config --global user.name  || true)"
existing_email="$(git config --global user.email || true)"

if [ -n "$existing_name" ] && [ "$FORCE_IDENTITY" -eq 0 ]; then
  info "Git identity already set: $existing_name <$existing_email> (use --force-identity to override)"
else
  info "Setting global git identity"
  git config --global user.name  "$GIT_NAME"
  git config --global user.email "$GIT_EMAIL"
fi
git config --global init.defaultBranch main
git config --global pull.rebase false
ok "git identity: $(git config --global user.name) <$(git config --global user.email)>"

# ---------------------------------------------------------------------------
# 3. SSH key (one per host, ed25519, passphrase-protected)
# ---------------------------------------------------------------------------
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

if [ -f "$KEY_FILE" ]; then
  info "SSH key already exists at $KEY_FILE — reusing it (not overwriting)"
else
  info "Generating ed25519 SSH key at $KEY_FILE"
  warn "You will be prompted for a passphrase — use one; ssh-agent caches it per session."
  ssh-keygen -t ed25519 -C "$KEY_COMMENT" -f "$KEY_FILE"
fi
chmod 600 "$KEY_FILE"
chmod 644 "$KEY_FILE.pub"

# ---------------------------------------------------------------------------
# 4. ssh-agent + config
# ---------------------------------------------------------------------------
info "Starting ssh-agent and adding the key"
eval "$(ssh-agent -s)"
ssh-add "$KEY_FILE"

SSH_CONFIG="$HOME/.ssh/config"
if grep -qs "IdentityFile $KEY_FILE" "$SSH_CONFIG" 2>/dev/null; then
  info "SSH config for github.com already present — leaving it alone"
else
  info "Adding github.com stanza to $SSH_CONFIG"
  cat >> "$SSH_CONFIG" <<EOF

Host github.com
    HostName github.com
    User git
    IdentityFile $KEY_FILE
    IdentitiesOnly yes
    AddKeysToAgent yes
EOF
fi
chmod 600 "$SSH_CONFIG"

# ---------------------------------------------------------------------------
# 5. Show the public key to register on GitHub
# ---------------------------------------------------------------------------
echo
info "Add this PUBLIC key to GitHub → Settings → SSH and GPG keys → New SSH key:"
echo "-------------------------------------------------------------------"
cat "$KEY_FILE.pub"
echo "-------------------------------------------------------------------"
echo
read -rp "Press Enter once you've added the key to GitHub to test the connection... " _

# ---------------------------------------------------------------------------
# 6. Verify
# ---------------------------------------------------------------------------
info "Testing SSH auth to GitHub"
# ssh -T returns exit code 1 even on success, so check the message instead.
if ssh -o StrictHostKeyChecking=accept-new -T git@github.com 2>&1 | grep -q "successfully authenticated"; then
  ok "GitHub SSH authentication works. You can now: git clone git@github.com:owner/repo.git"
else
  warn "Could not confirm authentication. Check that the key was added to GitHub"
  warn "(and 'Configure SSO / Authorize' if your org uses SAML SSO)."
  exit 1
fi
