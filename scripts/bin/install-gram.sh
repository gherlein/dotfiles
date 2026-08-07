#!/usr/bin/env bash
#
# Install the Gram editor from Codeberg's apt repository on Debian/Ubuntu.
#
#   ./install-gram.sh            # install 3.2.0-1 (the version you asked for)
#   ./install-gram.sh latest     # install whatever the repo currently ships
#   ./install-gram.sh 3.0.1-1    # install a specific version
#
set -euo pipefail

VERSION="${1:-3.2.0-1}"
KEYRING=/etc/apt/keyrings/forgejo-GramEditor.asc
LISTFILE=/etc/apt/sources.list.d/gram.list
KEY_URL=https://codeberg.org/api/packages/GramEditor/debian/repository.key
REPO_URL=https://codeberg.org/api/packages/GramEditor/debian

die() { echo "error: $*" >&2; exit 1; }

command -v apt-get >/dev/null || die "this script is for Debian/Ubuntu (no apt-get found)"
command -v curl    >/dev/null || die "curl is required: sudo apt install curl"
[[ "$(dpkg --print-architecture)" == amd64 ]] \
  || die "Codeberg's Gram repo only publishes amd64; this machine is $(dpkg --print-architecture)"

if [[ $EUID -eq 0 ]]; then SUDO=(); else
  command -v sudo >/dev/null || die "not root and sudo not available"
  SUDO=(sudo)
fi

echo "==> Installing repository key -> $KEYRING"
"${SUDO[@]}" install -d -m 0755 /etc/apt/keyrings
# Download to a temp file first so a failed fetch can't truncate a working keyring.
tmpkey="$(mktemp)"
trap 'rm -f "$tmpkey"' EXIT
curl -fsSL "$KEY_URL" -o "$tmpkey"
[[ -s "$tmpkey" ]] || die "downloaded key is empty"
"${SUDO[@]}" install -m 0644 "$tmpkey" "$KEYRING"

echo "==> Writing $LISTFILE"
# One line, no continuations: a wrapped URI is what apt rejects as "Malformed entry".
printf 'deb [arch=amd64 signed-by=%s] %s gram release\n' "$KEYRING" "$REPO_URL" \
  | "${SUDO[@]}" tee "$LISTFILE" >/dev/null

echo "==> apt update"
"${SUDO[@]}" apt-get update

if [[ "$VERSION" == latest ]]; then
  echo "==> Installing gram (latest available)"
  "${SUDO[@]}" apt-get install -y gram
else
  echo "==> Installing gram=$VERSION"
  # Advisory only. apt-get itself is the authority on whether the version exists,
  # so a wrong answer here must not block the install.
  avail="$(apt-cache madison gram | awk '{print $3}')"
  if ! grep -qxF -- "$VERSION" <<<"$avail"; then
    echo "warning: '$VERSION' not spotted in the repo index; letting apt decide." >&2
    echo "         versions seen: $(tr '\n' ' ' <<<"$avail")" >&2
  fi
  "${SUDO[@]}" apt-get install -y "gram=$VERSION"
fi

echo
echo "==> Installed: $(dpkg-query -W -f='${Version}' gram)"
echo "    Binary:    $(command -v gram || echo 'not on PATH')"
echo
echo "Gram renders via Vulkan. If it fails to open a window, check your driver with:"
echo "    sudo apt install vulkan-tools && vkcube"
