#!/usr/bin/env bash
#
# setup-dev-host.sh — provision a fresh Ubuntu dev host and configure
# GitHub SSH access for cloning private repos.
#
# Idempotent: safe to re-run. It will not overwrite an existing SSH key
# or clobber existing git config unless you pass --force-identity.
#
# Usage:
#   ./setup-dev-host.sh                       # full provisioning
#   ./setup-dev-host.sh -k | --keys           # ONLY import GitHub public keys
#   GIT_NAME="Greg Herlein" GIT_EMAIL="you@example.com" ./setup-dev-host.sh
#
# With -k/--keys the script does nothing except step 7: fetch your GitHub
# public keys and append them to ~/.ssh/authorized_keys. The GitHub username
# is taken from $GITHUB_USER if set, otherwise auto-detected via an existing
# GitHub SSH key in ~/.ssh.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Config (override via environment)
# ---------------------------------------------------------------------------
GIT_NAME="${GIT_NAME:-}"
GIT_EMAIL="${GIT_EMAIL:-}"
GITHUB_USER="${GITHUB_USER:-}"   # auto-detected from SSH auth if left empty
KEY_FILE="${KEY_FILE:-$HOME/.ssh/id_ed25519_github}"
KEY_COMMENT="${KEY_COMMENT:-$(whoami)@$(hostname -s)-$(date +%Y%m%d)}"
FORCE_IDENTITY=0
KEYS_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --force-identity) FORCE_IDENTITY=1 ;;
    -k|--keys) KEYS_ONLY=1 ;;
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

AGENT_STARTED=0
start_agent() {
  [ "$AGENT_STARTED" -eq 1 ] && return 0
  info "Starting ssh-agent"
  eval "$(ssh-agent -s)"
  AGENT_STARTED=1
}

# Test whether a given private key authenticates to GitHub. Loads the key into
# the agent first (one passphrase prompt); the subsequent `ssh -i` reuses the
# agent copy without prompting again. On success, capture the GitHub username
# from the "Hi <user>!" greeting into GITHUB_USER.
# ssh -T always exits 1, and `set -o pipefail` would make a `ssh ... | grep`
# pipeline inherit that 1 even when grep matches — so capture the output first,
# then grep the captured string.
key_authenticates() {
  ssh-add "$1" || true   # prompts for passphrase once, loads into the agent
  local output
  output="$(ssh -i "$1" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
      -T git@github.com 2>&1 || true)"
  if grep -q "successfully authenticated" <<<"$output"; then
    GITHUB_USER="$(sed -n 's/^Hi \([^!]*\)!.*/\1/p' <<<"$output" | head -1)"
    return 0
  fi
  return 1
}

# Look for an existing key in ~/.ssh whose name contains "github" and check
# whether it authenticates. Sets WORKING_KEY (and KEY_FILE + GITHUB_USER) on
# the first one that works.
WORKING_KEY=""
find_working_github_key() {
  start_agent
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
}

# Fetch the user's public keys from GitHub and append any new ones to
# authorized_keys (lets you SSH INTO this host with any key registered on your
# GitHub account).
import_github_keys() {
  if [ -z "$GITHUB_USER" ]; then
    warn "Could not determine your GitHub username — skipping authorized_keys import"
    return 0
  fi
  info "Fetching public keys for GitHub user '$GITHUB_USER' (https://github.com/$GITHUB_USER.keys)"
  local fetched
  fetched="$(curl -fsSL "https://github.com/$GITHUB_USER.keys" || true)"
  if [ -z "$fetched" ]; then
    warn "No public keys returned for $GITHUB_USER (fetch failed or none published)"
    return 0
  fi
  local auth_keys="$HOME/.ssh/authorized_keys"
  mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
  touch "$auth_keys"; chmod 600 "$auth_keys"
  local added=0 pubkey
  while IFS= read -r pubkey; do
    [ -z "$pubkey" ] && continue
    # Dedup on the key body (GitHub returns keys without a comment), so we
    # don't re-add one that's already present under any comment.
    if grep -qF -- "$pubkey" "$auth_keys"; then
      continue
    fi
    printf '%s github:%s\n' "$pubkey" "$GITHUB_USER" >> "$auth_keys"
    added=$((added + 1))
  done <<<"$fetched"
  ok "Imported $added new key(s) into $auth_keys for GitHub user '$GITHUB_USER'"
}

# ---------------------------------------------------------------------------
# Keys-only mode (-k/--keys): import GitHub public keys and exit, skipping
# apt, git identity, and SSH key creation.
# ---------------------------------------------------------------------------
if [ "$KEYS_ONLY" -eq 1 ]; then
  if [ -z "$GITHUB_USER" ]; then
    info "No GITHUB_USER set — auto-detecting via an existing GitHub SSH key"
    find_working_github_key
  fi
  import_github_keys
  exit 0
fi

# ---------------------------------------------------------------------------
# 1. Base system
# ---------------------------------------------------------------------------
info "Updating apt and installing base packages"
sudo apt update
sudo apt upgrade -y
sudo apt install -y git curl build-essential stow

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

# Before creating anything, reuse an existing working GitHub key if present.
find_working_github_key

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
# The agent was started during detection. A working key found there is already
# loaded; only add the key here if it isn't already in the agent.
start_agent
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

# ---------------------------------------------------------------------------
# 7. Import the user's public keys from GitHub into authorized_keys
#    (lets you SSH INTO this host with any key registered on your GitHub acct)
# ---------------------------------------------------------------------------
import_github_keys

# ---------------------------------------------------------------------------
# 8. Claude Code (native installer -> ~/.local/bin/claude, self-updating)
# ---------------------------------------------------------------------------
if command -v claude >/dev/null 2>&1 || [ -x "$HOME/.local/bin/claude" ]; then
  info "Claude Code already installed — skipping"
else
  info "Installing Claude Code (https://claude.ai/install.sh)"
  curl -fsSL https://claude.ai/install.sh | bash
fi
if command -v claude >/dev/null 2>&1 || [ -x "$HOME/.local/bin/claude" ]; then
  ok "Claude Code ready. If 'claude' isn't found, add ~/.local/bin to PATH, then run: claude"
else
  warn "Claude Code install did not produce a 'claude' binary — check the output above"
fi
