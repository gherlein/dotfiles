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
existing_name="$(git config --global user.name  || true)"
existing_email="$(git config --global user.email || true)"

if [ -n "$existing_name" ] && [ "$FORCE_IDENTITY" -eq 0 ]; then
  # Identity already configured — don't prompt for name/email at all.
  info "Git identity already set: $existing_name <$existing_email> (use --force-identity to override)"
else
  if [ -z "$GIT_NAME" ]; then
    read -rp "Git user.name (e.g. Greg Herlein): " GIT_NAME
  fi
  if [ -z "$GIT_EMAIL" ]; then
    read -rp "Git user.email (a verified GitHub email): " GIT_EMAIL
  fi
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

# ssh-agent is started here (before detection) so that a candidate key is
# loaded into the agent once and reused for both the test and the final
# clone — otherwise the passphrase would be prompted for twice.
info "Starting ssh-agent"
eval "$(ssh-agent -s)"

# Test whether a given private key authenticates to GitHub. We load the key
# into the agent first (one passphrase prompt); the subsequent `ssh -i` then
# uses the agent copy without prompting again.
# ssh -T returns exit code 1 even on success, so we grep the message instead.
key_authenticates() {
  ssh-add "$1" || true   # prompts for passphrase once, loads into the agent
  # `ssh -T` always exits 1, and `set -o pipefail` would make a
  # `ssh ... | grep` pipeline inherit that 1 even when grep matches. So
  # capture the output first, then grep the captured string.
  local output
  output="$(ssh -i "$1" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
      -T git@github.com 2>&1 || true)"
  grep -q "successfully authenticated" <<<"$output"
}

# Before creating anything, look for an existing key in ~/.ssh whose name
# contains "github" and check whether it already works. If so, reuse it and
# skip key creation entirely.
WORKING_KEY=""
info "Looking for an existing GitHub SSH key in $HOME/.ssh"
shopt -s nullglob
for candidate in "$HOME"/.ssh/*github*; do
  case "$candidate" in
    *.pub) continue ;;   # skip public keys
  esac
  [ -f "$candidate" ] || continue
  info "Testing existing key: $candidate"
  if key_authenticates "$candidate"; then
    ok "Existing key authenticates to GitHub — reusing $candidate"
    WORKING_KEY="$candidate"
    KEY_FILE="$candidate"
    break
  else
    warn "Key $candidate did not authenticate to GitHub"
  fi
done
shopt -u nullglob

if [ -n "$WORKING_KEY" ]; then
  info "Skipping SSH key creation — a working GitHub key is already present"
elif [ -f "$KEY_FILE" ]; then
  info "SSH key already exists at $KEY_FILE — reusing it (not overwriting)"
else
  info "Generating ed25519 SSH key at $KEY_FILE"
  warn "You will be prompted for a passphrase — use one; ssh-agent caches it per session."
  ssh-keygen -t ed25519 -C "$KEY_COMMENT" -f "$KEY_FILE"
fi
chmod 600 "$KEY_FILE"
[ -f "$KEY_FILE.pub" ] && chmod 644 "$KEY_FILE.pub"

# ---------------------------------------------------------------------------
# 4. ssh-agent + config
# ---------------------------------------------------------------------------
# The agent was started in section 3. A working key found during detection is
# already loaded; only add the key here if it isn't already in the agent.
if ssh-add -l 2>/dev/null | grep -qF "$(ssh-keygen -lf "$KEY_FILE" 2>/dev/null | awk '{print $2}')"; then
  info "Key already loaded into ssh-agent"
else
  info "Adding the key to ssh-agent"
  ssh-add "$KEY_FILE"
fi

SSH_CONFIG="$HOME/.ssh/config"
# Leave the config alone if the user already has ANY github.com stanza —
# appending our own would create a second, conflicting block (e.g. clobbering
# a curated ssh.github.com:443 setup with HostName github.com on port 22).
if grep -Eqs '^[[:space:]]*Host([[:space:]].*)?[[:space:]]github\.com([[:space:]]|$)' "$SSH_CONFIG" 2>/dev/null; then
  info "A github.com stanza already exists in $SSH_CONFIG — leaving it alone"
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
if [ -z "$WORKING_KEY" ]; then
  echo
  info "Add this PUBLIC key to GitHub → Settings → SSH and GPG keys → New SSH key:"
  echo "-------------------------------------------------------------------"
  cat "$KEY_FILE.pub"
  echo "-------------------------------------------------------------------"
  echo
  read -rp "Press Enter once you've added the key to GitHub to test the connection... " _
fi

# ---------------------------------------------------------------------------
# 6. Verify
# ---------------------------------------------------------------------------
if [ -n "$WORKING_KEY" ]; then
  ok "GitHub SSH authentication already confirmed during detection ($KEY_FILE)."
  ok "You can now: git clone git@github.com:owner/repo.git"
else
  info "Testing SSH auth to GitHub"
  # Test with -i/IdentitiesOnly (via key_authenticates) so only this key is
  # offered — a bare `ssh -T` can offer many keys and hit GitHub's
  # "Too many authentication failures" before reaching the right one.
  if key_authenticates "$KEY_FILE"; then
    ok "GitHub SSH authentication works. You can now: git clone git@github.com:owner/repo.git"
  else
    warn "Could not confirm authentication. Check that the key was added to GitHub"
    warn "(and 'Configure SSO / Authorize' if your org uses SAML SSO)."
    exit 1
  fi
fi
