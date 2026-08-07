#!/usr/bin/env bash
# Remove Tailscale (apt-installed) from this host.
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive

say() { printf '\n=== %s ===\n' "$1"; }

say "1. Bring down and disable the daemon"
tailscale down 2>&1 || echo "(tailscale down skipped - already logged out)"
systemctl stop tailscaled 2>&1 || echo "(stop failed or already stopped)"
systemctl disable tailscaled 2>&1 || echo "(disable failed or already disabled)"

say "2. Purge packages"
apt-get purge -y --autoremove tailscale tailscale-archive-keyring

say "3. Remove apt repo and keyring"
rm -f /etc/apt/sources.list.d/tailscale.list
rm -f /usr/share/keyrings/tailscale-archive-keyring.gpg
apt-get update

say "4. Clean leftover state"
rm -rf /var/lib/tailscale
rm -rf /var/cache/tailscale
rm -f  /etc/default/tailscaled
# per-user CLI config for the invoking user, not root
rm -rf "/home/${SUDO_USER:-$USER}/.config/tailscale"

say "5. Verify"
echo "-- binaries (want: not found) --"
command -v tailscale tailscaled || echo "none remaining"
echo "-- dpkg (want: empty) --"
dpkg -l 2>/dev/null | grep -i tailscale || echo "no packages"
echo "-- systemd units (want: empty) --"
systemctl list-unit-files 2>/dev/null | grep -i tailscale || echo "no units"
echo "-- interface (want: does not exist) --"
ip -brief addr show tailscale0 2>&1 || true
echo "-- leftover paths (want: empty) --"
ls -d /var/lib/tailscale /etc/apt/sources.list.d/tailscale.list \
      /usr/share/keyrings/tailscale-archive-keyring.gpg 2>/dev/null \
  || echo "all clear"

say "DONE - now delete this machine in the admin console:"
echo "https://login.tailscale.com/admin/machines"
