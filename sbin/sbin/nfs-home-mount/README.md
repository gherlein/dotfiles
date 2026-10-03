# nfs-home-mount

Mount a home-only NFS share when the server is reachable, unmount it when it is
not. Driven by a systemd timer that probes the NFS port every 30s, so it is
immune to ethernet flapping: a brief link blip on the home LAN is invisible
because the next tick still finds the server.

Disclaimer: This works for me -- that's the entire guarantee. Built with AI in
the loop, so check your own biases before you love it or hate it on principle.
Use at your own risk, fork freely, and don't @ me when it explodes. (But do drop
me a note if it helps -- pay it forward.)

## Layout

Part of the `sbin` stow package.

- `~/sbin/nfs-home-mount.sh` -- the reconcile script (stowed, on PATH)
- `~/sbin/nfs-home-mount/` -- these templates (stowed)
  - `nfs-home-mount.service` -- oneshot unit (`ExecStart` is templated as `__SCRIPT__`)
  - `nfs-home-mount.timer` -- 30s cadence, measured from last completion
  - `nfs-home-mount.conf` -- config template, installed to `/etc/nfs-home-mount.conf`
  - `fstab.snippet` -- the `noauto` line to add to `/etc/fstab`
  - `install.sh` -- copies units+conf into `/etc`, enables the timer

## Install

```bash
# 1. Stow the package (creates the ~/sbin symlinks)
cd ~/dotfiles && stow -v sbin

# 2. Add the fstab line (edit paths first)
cat ~/sbin/nfs-home-mount/fstab.snippet   # copy into /etc/fstab

# 3. Install the system pieces and enable the timer
sudo ~/sbin/nfs-home-mount/install.sh

# 4. Set your server/mount point, then reconcile now
sudo $EDITOR /etc/nfs-home-mount.conf
sudo systemctl start nfs-home-mount.service
```

## Operate

```bash
systemctl list-timers nfs-home-mount.timer
journalctl -u nfs-home-mount.service -n 20
```

## Detection

Reachability is a direct TCP probe of `NFS_SERVER:2049` (via bash `/dev/tcp`, no
`nc`/`date` deps). That answers "will a mount actually work" better than SSID or
subnet heuristics. To key off the gateway MAC instead, replace `server_reachable`
in `nfs-home-mount.sh`.

## Security note

The root systemd service executes the script through the user's `~/sbin` symlink
into this (user-writable) dotfiles repo. Fine for a personal laptop; on a shared
host, copy the script to a root-owned path instead and point `ExecStart` there.
