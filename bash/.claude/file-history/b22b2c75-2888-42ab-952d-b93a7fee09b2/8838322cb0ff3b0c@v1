# localdev VM

Disclaimer: This works for me — that's the entire guarantee. Built with AI in the loop, so check your own biases before you love it or hate it on principle. Use at your own risk, fork freely, and don't @ me when it explodes. (But do drop me a note if it helps — pay it forward.)

---

A local development VM provisioned by [goloo](https://github.com/emergingrobotics/goloo) using Multipass. It runs Ubuntu 24.04 and comes with the full dev toolchain pre-installed, plus an NFS shadow-mount system that makes the host filesystem visible inside the VM with selectable read-write paths.

## What's inside the VM

| Tool | Version |
|------|---------|
| Go | 1.25.0 |
| TinyGo | 0.40.1 |
| pi-go | 0.0.32 |
| Node.js | LTS (via nvm) |
| Python / uv | latest |
| Claude Code | latest |
| opencode | latest |
| GitHub CLI (`gh`) | latest |
| Podman | latest (rootless) |
| Go tools | goimports, golangci-lint, dlv, kit |
| npm globals | typescript, ts-node, pnpm, eslint, prettier |
| WeasyPrint | latest (via uv, for pandoc PDF output) |
| Editor | mg (aliased as `emacs`) |

Plus the usual suspects: git, tmux, fzf, ripgrep, fd, jq, tree, direnv, zoxide, keychain, stow, ffmpeg, imagemagick, pandoc.

## Host filesystem shadow mount

The VM can mount a read-only shadow of the entire host filesystem at `/mnt/host`, with specific directories promoted to read-write. Writes on the RW paths go directly to the host. See [`VM-SHARED-MOUNTS.md`](VM-SHARED-MOUNTS.md) for the full design.

Default RW paths (configured in `/etc/host-shadow-paths` on both host and VM):

```
/localdev
/home/greg/projects
```

### Usage inside the VM

```bash
sudo shadow-mount          # mount: RO shadow at /mnt/host, RW overlays on top
ls /mnt/host/etc           # browse host filesystem read-only
cd /mnt/host/localdev/my-project && claude  # run Claude Code against a host project
sudo shadow-umount         # tear down all mounts cleanly
```

The `host-shadow.service` systemd unit is enabled and will auto-mount on boot if the host NFS server is reachable.

## Prerequisites

- [goloo](https://github.com/emergingrobotics/goloo) installed and on PATH
- [Multipass](https://multipass.run/) installed
- SSH public keys on GitHub (used by goloo for passwordless VM access)

## Quickstart

### Step 1 — Set up the host (once)

```bash
make host-setup
```

This installs `nfs-kernel-server`, writes `/etc/host-shadow-paths`, installs the `shadow-export-gen` script, generates `/etc/exports`, and starts the NFS server.

If `ufw` is active on your host, also run:

```bash
make ufw-allow
```

### Step 2 — Create the VM

```bash
make create-vm
```

goloo fetches your SSH public keys from GitHub, injects them into the cloud-init template, and launches a Multipass VM. First boot takes 5–10 minutes while cloud-init installs everything.

### Step 3 — Connect

```bash
make ssh-vm
# or: goloo ssh localdev
```

## VM lifecycle

```bash
make create-vm     # goloo create localdev
make ssh-vm        # goloo ssh localdev
make status-vm     # goloo status localdev
make delete-vm     # goloo delete localdev
```

## Customising RW paths

To add or remove a read-write path:

**On the host:**

```bash
# Add a path
echo '/home/greg/new-thing' | sudo tee -a /etc/host-shadow-paths
sudo shadow-export-gen

# Remove a path: edit /etc/host-shadow-paths, then:
sudo shadow-export-gen
```

**In the VM:**

```bash
sudo shadow-sync              # pull updated list from host
sudo shadow-umount && sudo shadow-mount   # remount with new paths
```

## Dotfiles

If your dotfiles repo is structured for [stow](https://www.gnu.org/software/stow/) and lives at `/home/greg/dotfiles` on the host, add it to `config.json`:

```json
"mounts": [
  {"source": "/home/greg/dotfiles", "target": "/external/dotfiles"}
]
```

The VM's `.bashrc.d/dev-env.sh` automatically stows every package from `/external/dotfiles` (except `bash`, which it sources directly) on each shell login.

## Resizing

To change CPU, memory, or disk allocation, edit `~/.config/goloo/stacks/localdev/config.json`, then delete and recreate:

```bash
make delete-vm
make create-vm
```

## Repository layout

```
.
├── Makefile                    Host setup and VM lifecycle targets
├── README.md                   This file
├── REQUIREMENTS.md             Full specification for the VM and all its files
├── VM-SHARED-MOUNTS.md         NFS shadow-mount design and reference
├── example-Containerfile       Container equivalent (reference; not used by the VM)
└── host-setup/
    ├── shadow-export-gen       Script installed to /usr/local/bin on the host
    └── host-shadow-paths       Template for /etc/host-shadow-paths on the host

~/.config/goloo/stacks/localdev/
    ├── config.json             goloo VM spec (8 CPU / 8G / 80G / Ubuntu 24.04)
    └── cloud-init.yaml         Full provisioning script run on first boot
```
