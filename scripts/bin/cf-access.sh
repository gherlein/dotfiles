#!/usr/bin/env bash
#
# Authenticate to hosts behind Cloudflare Access using cloudflared.
# Companion to ~/gch-notes/cloudflare-notes.md (route 1).
#
# Usage:
#   cf-access.sh install
#   cf-access.sh setup <app-url>
#   cf-access.sh login <app-url>
#   cf-access.sh token <app-url>
#   cf-access.sh fetch <url> [extra curl args...]
#   cf-access.sh logout <app-url>

set -euo pipefail

readonly CLOUDFLARED_KEYRING="/usr/share/keyrings/cloudflare-main.gpg"
readonly CLOUDFLARED_APT_LIST="/etc/apt/sources.list.d/cloudflared.list"
readonly CLOUDFLARED_GPG_URL="https://pkg.cloudflare.com/cloudflare-main.gpg"
readonly CLOUDFLARED_APT_REPO="https://pkg.cloudflare.com/cloudflared"
readonly CLOUDFLARED_RELEASE_BASE="https://github.com/cloudflare/cloudflared/releases/latest/download"

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '%s\n' "$*" >&2
}

# Reduce a full request URL to the scheme://host origin that Cloudflare Access
# issues tokens against. Access tokens are scoped per application hostname, not
# per path, so the query string and path must be stripped before asking for one.
applicationOrigin() {
    local url="$1"
    local withoutScheme="${url#*://}"
    local scheme="${url%%://*}"
    local hostAndPort="${withoutScheme%%/*}"

    [ "$scheme" != "$url" ] || die "URL must include a scheme: $url"
    [ -n "$hostAndPort" ] || die "could not parse host from URL: $url"

    printf '%s://%s' "$scheme" "$hostAndPort"
}

cloudflaredInstalled() {
    command -v cloudflared >/dev/null 2>&1
}

installViaApt() {
    info "Installing cloudflared from the Cloudflare apt repository (sudo required)."
    curl -fsSL "$CLOUDFLARED_GPG_URL" | sudo tee "$CLOUDFLARED_KEYRING" >/dev/null
    printf 'deb [signed-by=%s] %s any main\n' "$CLOUDFLARED_KEYRING" "$CLOUDFLARED_APT_REPO" \
        | sudo tee "$CLOUDFLARED_APT_LIST" >/dev/null
    sudo apt-get update
    sudo apt-get install -y cloudflared
}

# Fallback for non-apt systems: the project publishes per-architecture .deb and
# raw binaries on every release.
installViaBinary() {
    local architecture downloadUrl temporaryBinary
    case "$(uname -m)" in
        x86_64)  architecture="amd64" ;;
        aarch64) architecture="arm64" ;;
        armv7l)  architecture="arm" ;;
        *)       die "unsupported architecture: $(uname -m)" ;;
    esac

    downloadUrl="${CLOUDFLARED_RELEASE_BASE}/cloudflared-linux-${architecture}"
    temporaryBinary="$(mktemp)"
    info "Downloading $downloadUrl"
    curl -fsSL "$downloadUrl" -o "$temporaryBinary"
    chmod +x "$temporaryBinary"
    sudo install -m 0755 "$temporaryBinary" /usr/local/bin/cloudflared
    rm -f "$temporaryBinary"
}

commandInstall() {
    if cloudflaredInstalled; then
        info "cloudflared already installed: $(cloudflared --version 2>&1 | head -1)"
        return 0
    fi

    if command -v apt-get >/dev/null 2>&1; then
        installViaApt
    else
        installViaBinary
    fi

    cloudflaredInstalled || die "installation completed but cloudflared is not on PATH"
    info "Installed: $(cloudflared --version 2>&1 | head -1)"
}

commandLogin() {
    local appUrl origin
    appUrl="${1:?usage: cf-access.sh login <app-url>}"
    origin="$(applicationOrigin "$appUrl")"

    cloudflaredInstalled || die "cloudflared not installed -- run: $0 install"

    info "Opening a browser to authenticate against $origin"
    info "If no browser opens, copy the printed URL into one manually."
    cloudflared access login "$origin"
}

# Prints the cached JWT, or nothing (non-zero exit) when no valid token exists.
# cloudflared reports a missing token on stdout in some versions rather than
# failing, so the value is validated as a JWT before being accepted.
cachedToken() {
    local origin="$1"
    local token

    token="$(cloudflared access token -app="$origin" 2>/dev/null || true)"
    token="$(printf '%s' "$token" | tr -d '[:space:]')"

    case "$token" in
        eyJ*) printf '%s' "$token" ;;
        *)    return 1 ;;
    esac
}

commandToken() {
    local appUrl origin
    appUrl="${1:?usage: cf-access.sh token <app-url>}"
    origin="$(applicationOrigin "$appUrl")"

    cloudflaredInstalled || die "cloudflared not installed -- run: $0 install"
    cachedToken "$origin" || die "no cached token for $origin -- run: $0 login $origin"
    printf '\n'
}

commandFetch() {
    local url origin token
    url="${1:?usage: cf-access.sh fetch <url> [curl args...]}"
    shift
    origin="$(applicationOrigin "$url")"

    cloudflaredInstalled || die "cloudflared not installed -- run: $0 install"

    if ! token="$(cachedToken "$origin")"; then
        info "No valid token cached for $origin -- starting login."
        cloudflared access login "$origin"
        token="$(cachedToken "$origin")" || die "login did not produce a token for $origin"
    fi

    # The token is passed as a header rather than on the command line of a
    # subprocess so it does not leak into the process table via curl's argv.
    curl -sS --fail-with-body \
        -H @<(printf 'cf-access-token: %s\n' "$token") \
        "$@" \
        "$url"
}

# cloudflared caches app tokens as files under ~/.cloudflared named after the
# hostname; the exact suffix has varied across releases, so every cache file for
# the host is removed rather than one guessed filename.
commandLogout() {
    local appUrl origin hostname removedCount
    appUrl="${1:?usage: cf-access.sh logout <app-url>}"
    origin="$(applicationOrigin "$appUrl")"
    hostname="${origin#*://}"
    removedCount=0

    for cacheFile in "$HOME/.cloudflared/$hostname"*; do
        [ -e "$cacheFile" ] || continue
        rm -f "$cacheFile"
        removedCount=$((removedCount + 1))
    done

    info "Removed $removedCount cached credential file(s) for $hostname."
}

usage() {
    cat <<'USAGE'
cf-access.sh -- authenticate to Cloudflare Access protected hosts via cloudflared

  install                        Install cloudflared (apt repo, or direct binary)
  setup  <app-url>               install + login in one step
  login  <app-url>               Interactive browser login; caches a JWT in ~/.cloudflared
  token  <app-url>               Print the cached JWT for scripting
  fetch  <url> [curl args...]    Authenticated curl; logs in first if needed
  logout <app-url>               Drop the cached credential

Examples:
  ./cf-access.sh setup https://crashdump-prod.brightsign.io
  ./cf-access.sh fetch 'https://crashdump-prod.brightsign.io/crash-list/?device_name=UJE04P002358'
  ./cf-access.sh fetch 'https://crashdump-prod.brightsign.io/api/foo' -H 'Accept: application/json' | jq .
  export CF_JWT="$(./cf-access.sh token https://crashdump-prod.brightsign.io)"
USAGE
}

main() {
    local subcommand="${1:-help}"
    shift || true

    case "$subcommand" in
        install) commandInstall "$@" ;;
        login)   commandLogin "$@" ;;
        token)   commandToken "$@" ;;
        fetch)   commandFetch "$@" ;;
        logout)  commandLogout "$@" ;;
        setup)
            commandInstall
            commandLogin "$@"
            ;;
        help|-h|--help) usage ;;
        *)
            usage >&2
            die "unknown subcommand: $subcommand"
            ;;
    esac
}

main "$@"
