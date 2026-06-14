# Requirements: goloo Local Development VM

Disclaimer: This works for me — that's the entire guarantee. Built with AI in the loop, so check your own biases before you love it or hate it on principle. Use at your own risk, fork freely, and don't @ me when it explodes. (But do drop me a note if it helps — pay it forward.)

---

## 1. Overview

Create a local development VM using [goloo](https://github.com/emergingrobotics/goloo) and Multipass that:

1. Has the full development tool stack from `example-Containerfile` installed (Go, Node.js, Python/uv, Claude Code, opencode, TinyGo, pi-go, Podman, GitHub CLI, and all supporting tooling).
2. Can mount a shadow of the host filesystem via NFS (as specified in `VM-SHARED-MOUNTS.md`), giving the VM read-only access to the entire host filesystem with selective read-write overlays for designated project directories.
3. Runs locally only — no AWS or DigitalOcean configuration is required.

The VM is provisioned by running:

```bash
goloo create localdev
```

where `localdev` is the stack name.

---

## 2. Stack Directory Structure

goloo expects this layout (default base: `~/.config/goloo/stacks/`):

```
~/.config/goloo/stacks/
└── localdev/
    ├── config.json          # VM spec — you write this
    └── cloud-init.yaml      # Provisioning script — you write this
```

Both files must exist before running `goloo create localdev`.

---

## 3. `config.json` Specification

### 3.1 File Location

```
~/.config/goloo/stacks/localdev/config.json
```

### 3.2 Required Content

```json
{
  "vm": {
    "name": "localdev",
    "cpus": 8,
    "memory": "8G",
    "disk": "80G",
    "image": "24.04",
    "users": [
      {"username": "ubuntu", "github_username": "gherlein"}
    ],
    "mounts": [
      {"source": "/localdev", "target": "/mnt/localdev"},
      {"source": "/home/greg/projects", "target": "/mnt/projects"}
    ]
  }
}
```

### 3.3 Field Notes

| Field | Value | Rationale |
|-------|-------|-----------|
| `name` | `localdev` | Matches the stack folder name; used by goloo for all operations |
| `cpus` | `8` | Claude Code and Go compilation are CPU-hungry; tune to host capacity |
| `memory` | `8G` | Node.js + Go + Claude Code need headroom; minimum 4G, recommend 8G |
| `disk` | `80G` | Go toolchain, Docker/Podman images, node_modules; minimum 40G |
| `image` | `24.04` | Ubuntu 24.04 LTS — matches host and all tooling targets in the Containerfile |
| `users[0].github_username` | `gherlein` | goloo fetches SSH public keys from `https://github.com/gherlein.keys` and injects them into cloud-init via `${SSH_PUBLIC_KEY}` |
| `mounts` | see above | Optional Multipass bind mounts for host directories directly into the VM; complement to (not a replacement for) the NFS shadow mount |

### 3.4 Mounts Note

The `mounts` array tells Multipass to bind-mount host directories into the VM at launch time. These are separate from the NFS shadow system:

- Use `mounts` for any host directory you always want available immediately on boot without any mount command.
- Use the NFS shadow system (`shadow-mount`) for on-demand, broad access to the host filesystem tree.

If the NFS shadow mount is the only mechanism needed, the `mounts` array may be omitted.

---

## 4. `cloud-init.yaml` Specification

### 4.1 File Location

```
~/.config/goloo/stacks/localdev/cloud-init.yaml
```

### 4.2 Structure Overview

The file must be a valid cloud-config YAML document with the following top-level sections:

```
#cloud-config
users:        — ubuntu user with SSH keys
package_update / package_upgrade:  — update before installing
packages:     — apt packages installed first
write_files:  — scripts, configs, and service files written to disk
runcmd:       — all installation commands executed in order
```

### 4.3 `users` Section

```yaml
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - ${SSH_PUBLIC_KEY}
```

- `${SSH_PUBLIC_KEY}` is substituted by goloo with the SSH public keys fetched from `https://github.com/gherlein.keys` before passing the file to Multipass.
- This is the only user. UID/GID 1000 is assigned by Ubuntu automatically (matches the `developer` user UID in the Containerfile).

### 4.4 Package Updates

```yaml
package_update: true
package_upgrade: true
```

### 4.5 `packages` Section

All packages that can be installed via `apt` before `runcmd` runs. Install them here rather than in `runcmd` to take advantage of cloud-init's retry logic.

**Required packages:**

```yaml
packages:
  # Core build tools
  - build-essential
  - cmake
  - make
  - pkg-config

  # Shell utilities
  - curl
  - wget
  - git
  - unzip
  - zip
  - file
  - xxd
  - jq
  - tree
  - rsync
  - tmux
  - mg
  - zoxide
  - keychain
  - direnv
  - stow
  - zstd
  - squashfs-tools

  # Media/document processing
  - ffmpeg
  - qpdf
  - imagemagick
  - pandoc

  # WeasyPrint runtime dependencies (for pandoc PDF output)
  - libpango-1.0-0
  - libpangoft2-1.0-0
  - libharfbuzz0b
  - libcairo2
  - libgdk-pixbuf-2.0-0
  - libffi8
  - shared-mime-info
  - fonts-dejavu
  - fonts-liberation

  # Python runtime
  - python3
  - python3-pip
  - python3-venv
  - python3-dev

  # USB / hardware access
  - libpcap-dev
  - libusb-1.0-0
  - libusb-1.0-0-dev
  - usbutils
  - udev

  # Podman and rootless container support
  - podman
  - uidmap
  - fuse-overlayfs
  - slirp4netns

  # NFS client (for host shadow filesystem)
  - nfs-common

  # CA certificates and HTTPS tooling
  - ca-certificates
  - gnupg
  - lsb-release
  - software-properties-common
  - apt-transport-https

  # Search / navigation tools
  - ripgrep
  - fd-find
  - fzf
```

**Note on `gosu`:** `gosu` is a container-specific UID-remapping helper. It is not needed in a VM and must NOT be installed.

### 4.6 `write_files` Section

Write these files to disk during cloud-init (before `runcmd` executes):

#### 4.6.1 Podman Configuration

```
path: /etc/containers/containers.conf
```

Content (rootless-friendly defaults matching the Containerfile):

```ini
[containers]
netns="host"
userns="host"
ipcns="host"
utsns="host"
cgroupns="host"
cgroups="disabled"
devices=["/dev/null"]

[engine]
cgroup_manager="cgroupfs"
events_logger="file"
runtime="crun"
```

#### 4.6.2 NFS Shadow Mount Script

```
path: /usr/local/bin/shadow-mount
permissions: '0755'
```

Content: the `shadow-mount` script from `VM-SHARED-MOUNTS.md` Part 2 §2.4, with `HOST` set to the Multipass host bridge IP (see §7 below for IP determination).

**Key behavior:**
- Mounts the NFS RO root of the host at `/mnt/host`
- For each RW path in `/etc/host-shadow-paths`, mounts the NFS RW export at `/mnt/rw/<path>` and bind-mounts it over `/mnt/host/<path>`

#### 4.6.3 NFS Shadow Unmount Script

```
path: /usr/local/bin/shadow-umount
permissions: '0755'
```

Content: the `shadow-umount` script from `VM-SHARED-MOUNTS.md` Part 2 §2.5.

#### 4.6.4 NFS Shadow Sync Script

```
path: /usr/local/bin/shadow-sync
permissions: '0755'
```

Content: the `shadow-sync` script from `VM-SHARED-MOUNTS.md` Part 2 §2.6, with `HOST` set to the Multipass host bridge IP and `user` replaced with `ubuntu`.

#### 4.6.5 RW Paths List

```
path: /etc/host-shadow-paths
permissions: '0644'
```

Content: one absolute path per line; blank lines and `#` comments ignored. Initial value:

```
/localdev
/home/greg/projects
```

Customise this list to match the actual RW directories you want inside the VM. This file must match the host's `/etc/host-shadow-paths` exactly.

#### 4.6.6 Systemd Service for Auto-Mount (Optional)

```
path: /etc/systemd/system/host-shadow.service
permissions: '0644'
```

Content: the systemd unit from `VM-SHARED-MOUNTS.md` Part 5.

Enable it in `runcmd` with:

```bash
systemctl daemon-reload
systemctl enable host-shadow.service
```

Only include this if you want the NFS shadow mounted automatically every time the VM boots. The service will fail silently on boot if the NFS server on the host is not running — acceptable for a development VM.

#### 4.6.7 Bash Environment File for ubuntu User

```
path: /home/ubuntu/.bashrc.d/dev-env.sh
owner: ubuntu:ubuntu
permissions: '0644'
```

Content:

```bash
# Go
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"

# NVM lazy-load
export NVM_DIR="$HOME/.nvm"
nvm() { unset -f nvm node npm npx; . "$NVM_DIR/nvm.sh"; nvm "$@"; }
node() { unset -f nvm node npm npx; . "$NVM_DIR/nvm.sh"; node "$@"; }
npm()  { unset -f nvm node npm npx; . "$NVM_DIR/nvm.sh"; npm "$@"; }
npx()  { unset -f nvm node npm npx; . "$NVM_DIR/nvm.sh"; npx "$@"; }
# Make node available immediately without the lazy-load wrapper
export PATH="$NVM_DIR/default/bin:$PATH" 2>/dev/null || true

# npm global binaries
export PATH="$HOME/.npm-global/bin:$PATH"

# uv / Python local tools
export PATH="$HOME/.local/bin:$PATH"

# opencode
export PATH="$HOME/.opencode/bin:$PATH"

# Aliases
alias emacs=mg
alias clauded='claude --dangerously-skip-permissions'
alias ll='ls -alF'
alias gs='git status'
alias gd='git diff'
alias gl='git log --oneline -20'
```

### 4.7 `runcmd` Section

Commands run in order as root unless prefixed with `sudo -u ubuntu`. All commands must be idempotent where possible.

#### 4.7.1 Create Required Directories

```bash
# NFS shadow mount points
mkdir -p /mnt/host
mkdir -p /mnt/rw

# Ubuntu user directory structure
sudo -u ubuntu mkdir -p /home/ubuntu/go/{bin,src,pkg}
sudo -u ubuntu mkdir -p /home/ubuntu/.npm-global
sudo -u ubuntu mkdir -p /home/ubuntu/.bashrc.d

# fd alias (fd-find installs as fdfind)
ln -sf /usr/bin/fdfind /usr/local/bin/fd
```

#### 4.7.2 Source `.bashrc.d` from `.bashrc`

```bash
cat >> /home/ubuntu/.bashrc << 'EOF'

# Source all files in .bashrc.d
if [ -d ~/.bashrc.d ]; then
  for f in ~/.bashrc.d/*.sh; do
    [ -r "$f" ] && . "$f"
  done
fi
EOF
chown ubuntu:ubuntu /home/ubuntu/.bashrc
```

#### 4.7.3 Install GitHub CLI

Use the official GitHub CLI apt repository:

```bash
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] \
  https://cli.github.com/packages stable main" \
  > /etc/apt/sources.list.d/github-cli.list
apt-get update
apt-get install -y gh
```

#### 4.7.4 Install Go

Target version: **1.25.0**. Detect architecture at runtime:

```bash
GOARCH=$(dpkg --print-architecture)
curl -fsSL "https://dl.google.com/go/go1.25.0.linux-${GOARCH}.tar.gz" \
  | tar --no-same-permissions --no-same-owner -xzC /usr/local
```

Set `GOROOT=/usr/local/go`, `GOPATH=/home/ubuntu/go` (done via the `.bashrc.d` file above).

#### 4.7.5 Install NVM and Node.js LTS

Install as the `ubuntu` user:

```bash
NVM_DIR=/home/ubuntu/.nvm
mkdir -p $NVM_DIR
sudo -u ubuntu bash -c '
  export NVM_DIR=/home/ubuntu/.nvm
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
  . "$NVM_DIR/nvm.sh"
  nvm install --lts
  nvm alias default node
  ln -s "$NVM_DIR/versions/node/$(. $NVM_DIR/nvm.sh && nvm version default)" \
    "$NVM_DIR/default"
'
```

Create a system-level symlink so non-interactive scripts can resolve `node` and `npm`:

```bash
ln -sf $(sudo -u ubuntu bash -c '. /home/ubuntu/.nvm/nvm.sh && which node') \
  /usr/local/bin/node
ln -sf $(sudo -u ubuntu bash -c '. /home/ubuntu/.nvm/nvm.sh && which npm') \
  /usr/local/bin/npm
```

#### 4.7.6 Configure npm Global Prefix

```bash
sudo -u ubuntu npm config set prefix '/home/ubuntu/.npm-global'
```

#### 4.7.7 Install Global npm Packages

```bash
sudo -u ubuntu bash -c '
  export NVM_DIR=/home/ubuntu/.nvm
  . "$NVM_DIR/nvm.sh"
  NODE_OPTIONS="--max-old-space-size=4096" npm install -g \
    typescript \
    ts-node \
    pnpm \
    eslint \
    prettier
  npm cache clean --force
'
```

#### 4.7.8 Install TinyGo

Target version: **0.40.1**. Detect architecture:

```bash
TINYGO_ARCH=$(dpkg --print-architecture)
curl -fsSL \
  "https://github.com/tinygo-org/tinygo/releases/download/v0.40.1/tinygo_0.40.1_${TINYGO_ARCH}.deb" \
  -o /tmp/tinygo.deb
dpkg -i /tmp/tinygo.deb
rm /tmp/tinygo.deb
```

#### 4.7.9 Install pi-go

Target version: **0.0.32**. Detect architecture:

```bash
PI_GO_ARCH=$(dpkg --print-architecture)
curl -fsSL \
  "https://github.com/dimetron/pi-go/releases/download/v0.0.32/pi-go_0.0.32_linux_${PI_GO_ARCH}.tar.gz" \
  -o /tmp/pi-go.tar.gz
mkdir -p /tmp/pi-go-extract
tar -xzf /tmp/pi-go.tar.gz -C /tmp/pi-go-extract
mv /tmp/pi-go-extract/pi /usr/local/bin/pi
chmod +x /usr/local/bin/pi
rm -rf /tmp/pi-go.tar.gz /tmp/pi-go-extract
```

#### 4.7.10 Install uv (Python package manager)

```bash
sudo -u ubuntu bash -c '
  for i in 1 2 3; do
    curl -LsSf https://astral.sh/uv/install.sh | sh && break || \
      (echo "Attempt $i failed, retrying..." && sleep 5)
  done
'
```

#### 4.7.11 Install WeasyPrint via uv

```bash
sudo -u ubuntu /home/ubuntu/.local/bin/uv tool install weasyprint
```

#### 4.7.12 Install Claude Code

```bash
sudo -u ubuntu bash -c '
  export PATH="/home/ubuntu/.npm-global/bin:$PATH"
  export NVM_DIR=/home/ubuntu/.nvm
  . "$NVM_DIR/nvm.sh"
  curl -fsSL https://claude.ai/install.sh | bash
'
```

#### 4.7.13 Install opencode

```bash
sudo -u ubuntu bash -c 'curl -fsSL https://opencode.ai/install | bash'
```

#### 4.7.14 Install Go Tools

```bash
sudo -u ubuntu bash -c '
  export GOROOT=/usr/local/go
  export GOPATH=/home/ubuntu/go
  export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"
  go install golang.org/x/tools/cmd/goimports@latest
  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
  go install github.com/go-delve/delve/cmd/dlv@latest
  go install github.com/mark3labs/kit/cmd/kit@latest
'
```

#### 4.7.15 Fix Ownership

```bash
chown -R ubuntu:ubuntu /home/ubuntu
```

#### 4.7.16 Enable Optional Auto-Mount Service

If the systemd unit was written in §4.6.6:

```bash
systemctl daemon-reload
systemctl enable host-shadow.service
```

#### 4.7.17 Completion Marker

```bash
echo "localdev cloud-init complete" >> /var/log/cloud-init-custom.log
```

---

## 5. Host Setup Requirements

Before `goloo create localdev` is run, the host machine must be prepared to export its filesystem via NFS to the VM.

### 5.1 Required Packages on Host

```bash
sudo apt update
sudo apt install -y nfs-kernel-server
```

### 5.2 Create the RW Paths List on Host

```bash
sudo tee /etc/host-shadow-paths << 'EOF'
/localdev
/home/greg/projects
EOF
```

This file is the single source of truth. It must list the same paths as the `/etc/host-shadow-paths` inside the VM (written by cloud-init in §4.6.5).

### 5.3 Install the Export Generator Script on Host

Write `/usr/local/bin/shadow-export-gen` with the content from `VM-SHARED-MOUNTS.md` Part 1 §1.3, then run it:

```bash
sudo chmod +x /usr/local/bin/shadow-export-gen
sudo shadow-export-gen
```

### 5.4 Determine the VM Network

Multipass on Linux creates a KVM bridge. The host IP as seen from the VM is the gateway address of that bridge, not `10.0.2.2` (which is the QEMU NAT default — Multipass does not use QEMU NAT by default on Linux).

**To find the correct host IP:**

```bash
# On the host, after the VM is running:
multipass exec localdev -- ip route show default
# Output: default via <HOST_IP> dev ens3
```

Or from the host:

```bash
ip addr show $(multipass info localdev --format json \
  | jq -r '.info.localdev.ipv4[0]' \
  | xargs -I{} ip route get {} | awk '{print $5; exit}')
```

The simplest reliable method: SSH into the VM and run `ip route | grep default`. The gateway address is the host NFS server address.

**Update the VM's shadow scripts** with this address. Either:
- Patch the `HOST=` line in `/usr/local/bin/shadow-mount` and `/usr/local/bin/shadow-sync` after the VM is created, or
- Hard-code the correct bridge IP in the `write_files` section of `cloud-init.yaml` before running `goloo create`.

To find the bridge IP before creating the VM (it is stable once Multipass is installed):

```bash
ip addr show mpqemubr0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1
# If the above returns nothing, try:
ip addr show | grep -A2 'multipass' | grep 'inet ' | awk '{print $2}' | cut -d/ -f1
```

### 5.5 NFS VM Network (Export Target)

The export generator script from §5.3 exports to `10.0.2.0/24` (the QEMU NAT network assumed in VM-SHARED-MOUNTS.md). For Multipass on Linux with its own bridge, the VM network is different.

**Find the Multipass VM network:**

```bash
# Get the VM's IP once launched, then derive its /24 subnet:
VM_IP=$(multipass info localdev --format json | jq -r '.info.localdev.ipv4[0]')
VM_NETWORK="${VM_IP%.*}.0/24"
echo $VM_NETWORK
```

Update `shadow-export-gen` (or `/etc/exports` directly) to use this network instead of `10.0.2.0/24`.

### 5.6 Firewall Configuration on Host

If `ufw` is active, allow NFS and the portmapper from the VM network:

```bash
VM_NETWORK="<the /24 subnet from §5.5>"
sudo ufw allow from $VM_NETWORK to any port nfs
sudo ufw allow from $VM_NETWORK to any port 111
sudo ufw reload
```

### 5.7 Enable NFS Server

```bash
sudo systemctl enable --now nfs-kernel-server
sudo systemctl status nfs-kernel-server
```

---

## 6. Complete File List

These are all files that must exist, grouped by where they live:

### On the Host (before `goloo create`)

| Path | Purpose |
|------|---------|
| `~/.config/goloo/stacks/localdev/config.json` | goloo VM spec |
| `~/.config/goloo/stacks/localdev/cloud-init.yaml` | Provisioning script |
| `/etc/host-shadow-paths` | RW path list (source of truth) |
| `/etc/exports` | Generated by `shadow-export-gen` |
| `/usr/local/bin/shadow-export-gen` | Regenerates `/etc/exports` |

### Written Inside the VM by cloud-init

| Path | Purpose |
|------|---------|
| `/etc/containers/containers.conf` | Podman rootless config |
| `/etc/host-shadow-paths` | RW path list (must match host) |
| `/usr/local/bin/shadow-mount` | Mount RO shadow + RW overlays |
| `/usr/local/bin/shadow-umount` | Unmount all shadow mounts |
| `/usr/local/bin/shadow-sync` | Pull updated path list from host |
| `/etc/systemd/system/host-shadow.service` | Optional auto-mount on boot |
| `/home/ubuntu/.bashrc.d/dev-env.sh` | PATH, aliases, lazy NVM |
| `/mnt/host/` | Shadow root (created empty; mounted at runtime) |
| `/mnt/rw/` | RW NFS staging area (created empty) |

---

## 7. Version Pinning

| Tool | Version | Install Method |
|------|---------|---------------|
| Ubuntu | 24.04 LTS | Multipass image |
| Go | 1.25.0 | Direct download from `dl.google.com` |
| TinyGo | 0.40.1 | `.deb` from GitHub releases |
| pi-go | 0.0.32 | Tarball from GitHub releases |
| nvm | v0.39.0 | Install script from GitHub |
| Node.js | LTS (current at install time) | via nvm |
| npm global tools | latest at install time | npm install -g |
| uv | latest at install time | astral.sh install script |
| WeasyPrint | latest at install time | uv tool install |
| Claude Code | latest at install time | claude.ai install script |
| opencode | latest at install time | opencode.ai install script |
| Go tools (goimports, golangci-lint, dlv, kit) | latest at install time | go install ...@latest |

---

## 8. Architecture Notes

All download steps that are architecture-specific must detect the architecture at runtime using `dpkg --print-architecture`, which returns `amd64` or `arm64`. The cloud-init YAML should not hardcode an architecture.

Go's archive uses the same strings (`amd64`, `arm64`). TinyGo's release filenames use the same strings. pi-go's release filenames use the same strings.

---

## 9. Dotfiles Integration

The Containerfile stows dotfiles from `/external/dotfiles` inside the container. In the VM context, there is no automatic `/external/dotfiles` path. Two options:

**Option A — Multipass bind mount:** Add to `config.json`:

```json
"mounts": [
  {"source": "/home/greg/dotfiles", "target": "/external/dotfiles"}
]
```

Then add to `runcmd` in `cloud-init.yaml` (to run at each login, place in `.bashrc.d`):

```bash
# In /home/ubuntu/.bashrc.d/dev-env.sh:
if [[ -d /external/dotfiles ]]; then
  for _dotpkg_dir in /external/dotfiles/*/; do
    _dotpkg=$(basename "$_dotpkg_dir")
    [[ "$_dotpkg" == "bash" ]] && continue
    stow --no-folding --dir=/external/dotfiles --target="$HOME" "$_dotpkg" 2>/dev/null || true
  done
  unset _dotpkg_dir _dotpkg
  [[ -f /external/dotfiles/bash/.bashrc ]] && source /external/dotfiles/bash/.bashrc
  [[ -f /external/dotfiles/bash/.bash_profile ]] && source /external/dotfiles/bash/.bash_profile
fi
```

**Option B — Git clone during cloud-init:** Add a `runcmd` step to clone the dotfiles repo and run stow.

Option A is preferred because it keeps the VM in sync with host dotfile edits without any additional steps.

---

## 10. What Is Not Included

These items from `example-Containerfile` are container-specific and deliberately excluded from the VM configuration:

| Container Item | Reason Excluded |
|----------------|-----------------|
| `gosu` | UID-remapping helper for container entrypoints; irrelevant in a VM |
| `docker-entrypoint.sh` | Container startup hook; VMs boot normally |
| `COPY localdev localdevnet localdevpull /opt/localdev/bin/` | Container launcher scripts; not applicable |
| `USER developer` / `WORKDIR /home/developer` | Container Dockerfile directives; VM uses ubuntu user natively |
| Multi-arch `ARG TARGETARCH` logic | Multipass always creates VMs matching the host arch; arch detection uses `dpkg --print-architecture` instead |
| OCI image labels | Container metadata; no equivalent in a VM |

---

## 11. Validation Checklist

After `goloo create localdev` completes and the VM is running (`goloo status localdev`):

- [ ] `goloo ssh localdev` connects successfully using the GitHub SSH key
- [ ] `go version` returns `go1.25.0`
- [ ] `tinygo version` returns `tinygo version 0.40.1`
- [ ] `node --version` returns a current LTS version
- [ ] `npm --version` returns a current version
- [ ] `gh --version` returns a current version
- [ ] `claude --version` returns a current version
- [ ] `opencode --version` (or `~/.opencode/bin/opencode --version`) runs
- [ ] `uv --version` returns a current version
- [ ] `podman --version` returns a current version
- [ ] `pi --version` returns `0.0.32`
- [ ] `goimports -version` and `dlv version` run without error
- [ ] `/usr/local/bin/shadow-mount`, `shadow-umount`, `shadow-sync` exist and are executable
- [ ] `/etc/host-shadow-paths` exists with the expected RW paths
- [ ] `/mnt/host` and `/mnt/rw` directories exist
- [ ] `sudo shadow-mount` succeeds after the host NFS server is running (see §5)
- [ ] `ls /mnt/host/etc` lists host `/etc` read-only
- [ ] Writing to a designated RW path inside `/mnt/host` succeeds and the change is visible on the host
