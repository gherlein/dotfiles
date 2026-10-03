# Dotfiles

Personal configuration and a toolbox of helper scripts, managed with [GNU Stow](https://www.gnu.org/software/stow/).

This repo does two things: it stows shared config files into `$HOME`, and it exposes a folder of standalone command-line tools (under `scripts/bin`) that get symlinked onto your `PATH`. Host-specific config and anything secret lives in a separate private companion repo (see below).

## Prerequisites

- **GNU Stow** and **git** (required).
- Individual tools pull in their own dependencies (e.g. `kitten`/kitty, `jq`, `aws`, `cloudflared`, `ffmpeg`, `docker`/`podman`). Each tool fails with a clear message when a dependency is missing.
- Primary target is Linux (Debian/Ubuntu); many tools also work on macOS.

## Quick start

```bash
git clone <this-repo-url> ~/dotfiles
cd ~/dotfiles
make install          # regenerate the package list, then stow shared + this host's packages
```

Then clone the private companion repo and install it too (see [Private companion repo](#private-companion-repo)).

## Managing packages (Stow)

Each top-level directory is a "package" whose contents mirror your home directory. `make install` runs `refresh` (rescan directories into `.stow-packages`) then `stow`.

| Command | What it does |
|---|---|
| `make install` | Refresh the package list, then stow shared + this host's packages |
| `make stow` | Stow shared packages + this host's packages |
| `make unstow` | Remove the symlinks for the active packages |
| `make restow` | Re-stow (refresh symlinks) |
| `make list` | List active packages for this host (and skipped ones) |
| `make refresh` | Regenerate `.stow-packages` from the directories |
| `make adopt` | Adopt existing files into the repo, then stow (use on a new host with existing configs) |

Host-specific packages are named `<tool>-<host>` (e.g. `omp-helios`). Each host stows the shared packages plus only the packages matching its own `hostname -s` (`io`, `europa`, `helios`); other hosts' packages are skipped. Those host packages live in the private repo.

## Repository structure

### Config packages (stowed into `$HOME`)

| Package | Contents |
|---|---|
| `bash` | `.bashrc`, `.bash_profile`, `.bash_common`; sources `~/.config/work.env` (private) |
| `git` | `.gitconfig`; includes `~/.gitconfig.local` and `~/.gitconfig.host` (private) |
| `ssh` | SSH client `config`; host-specific entries come from `~/.ssh/config.local` (private) |
| `kitty` | kitty terminal config |
| `emacs`, `micro`, `zed`, `gram` | Editor configs (editor runtime/build output is gitignored) |
| `zellij` | zellij multiplexer config |
| `fzf` | fzf config and shell integration |
| `containers` | podman/containers config (`registries`, `policy`, `storage`) |
| `ollama` | Ollama environment config |
| `erg`, `kit`, `pi-go` | AI coding-agent configs, skills, and prompts (session/history state gitignored) |
| `dev-tools` | `.aider.conf.yml`, `.mcphost.yml`, `.yarnrc` |
| `x11` | X11 session config |
| `sbin` | System helper scripts, incl. the `nfs-home-mount` systemd unit, stowed to `~/sbin` |
| `docs` | Design docs and specs under `docs/superpowers/` |
| `scripts` | The command-line toolbox — `scripts/bin` is symlinked onto your `PATH` (see below) |

### Tools (`scripts/bin`)

These are standalone scripts symlinked into `~/bin` (which is on `PATH`), so they run as plain commands. Grouped by purpose:

#### Terminal & clipboard

| Tool | Purpose |
|---|---|
| `cb` | Copy to the system clipboard — works locally, over SSH, and from herdr panes (see [cb](#cb)) |
| `c` | Clear the screen and scrollback |
| `big-terminal.sh` | Open kitty sized to a fraction of the primary monitor |
| `install-big-terminal-shortcut.sh` | Bind Ctrl+Shift+K to the resolution-aware big-terminal launcher |
| `set-remote-kitty` | Install kitty terminfo on a remote host (so kitty features work over SSH) |

#### Editors & documents

| Tool | Purpose |
|---|---|
| `mt` | Open a file/folder in the Marktext markdown editor (new window) |
| `zeds` | Launch the Zed editor on a target |
| `md2pdf` / `pdf2md` | Convert Markdown to PDF / PDF to Markdown |
| `build-pdfs` | Build PDFs from Markdown (installs the Montserrat font if missing) |
| `gramr` | Run the Gram editor on a remote host over SSH |
| `grams` | Install/sync the Gram binary to a remote host over SSH |

#### GPU & local AI

| Tool | Purpose |
|---|---|
| `gpu-info.sh` | Colorized summary of the local GPU |
| `gpu-load.sh` | Live GPU load, auto-detecting AMD (ROCm/amdgpu) or NVIDIA |
| `verify-gpu` | Validate a Strix Halo (gfx1151) iGPU setup for local LLM workloads |
| `gx10-healthcheck.sh` | Assert an ASUS Ascent GX10 (GB10 / DGX Spark-class) box is at full power |
| `install-ai-host-stuff.sh` | Install and configure the AI-host stack (Ollama + LiteLLM) |
| `ROCm-install.sh` | Install AMD GPU drivers and ROCm |
| `otest` | Smoke-test an Ollama model by name |
| `genimg` | Generate an image locally via OpenVINO GenAI on the Intel iGPU |
| `genimg-openai` | Generate an image via OpenAI's Images API (`OPENAI_API_KEY`) |
| `genimg-remote` | Generate an image via Replicate's flux-schnell model (`REPLICATE_API_TOKEN`) |

#### Cameras & media

| Tool | Purpose |
|---|---|
| `play-reo1` | Play the low-latency RTSP preview from a Reolink camera (`REO_HOST`/`REO_PASS`) |
| `reo1-motion-probe.sh` | Discover what motion/event sources a camera exposes |
| `hdmiplay` | Detect active V4L2 capture devices and play one with low latency |
| `fffplay` | Low-latency RTSP playback via ffplay |

#### Home automation

| Tool | Purpose |
|---|---|
| `lights-meeting.sh` | Set a meeting-status Kauf RGBWW bulb from device state |
| `shellyctl` | Control a Shelly Plug (Gen2+ RPC) over local HTTP |

#### Networking & remote mounts

| Tool | Purpose |
|---|---|
| `add-dns-record.sh` | Create/update an A record in a Route 53 public hosted zone |
| `cf-access.sh` | Authenticate to hosts behind Cloudflare Access using `cloudflared` |
| `bounce-zerotier` | Restart zerotier-one and show its bind/info/networks |
| `remove-tailscale.sh` | Remove an apt-installed Tailscale |
| `http-scan.sh` | HTTP GET every host in a subnet on port 80 and report responders |
| `mountbs` | Mount a CIFS/SMB share to `~/bs` |
| `setup-nfs-peer-mount.sh` | Configure the NFS export + fstab entry for the europa/helios home cross-mount |
| `sync-mount-peer.sh` | Mount/unmount the peer host's home dir over NFS by reachability |
| `sshr` | Remove a host's key from `known_hosts` (`ssh-keygen -R`) |

#### Cloud, GitHub & Claude Code

| Tool | Purpose |
|---|---|
| `aws-whoami` | Export the current AWS account/user/ARN/region (source it) |
| `gplogin` | Log in to the GitHub Container Registry with podman (`GH_TOKEN`) |
| `check-org-repos.sh` | Find repos in a GitHub org that are not cloned locally |
| `claude-whoami` | Print the Claude Code logged-in organization name |
| `claude-plugin-reinstall` | Force a clean reinstall of one Claude Code plugin |
| `claude-skill-nuke` | Uninstall one Claude Code plugin and delete its persistent data |

#### Provisioning & desktop setup

| Tool | Purpose |
|---|---|
| `install-linux.sh` | Bootstrap a Linux (Debian/Ubuntu) development environment |
| `install-linux-headless.sh` | Bootstrap a headless Linux dev host |
| `install-mac.sh` | Bootstrap a Mac development environment |
| `setup-dev-host.sh` | Provision a fresh Ubuntu dev host and configure it |
| `install-linux-bluetooth.sh` | Install the Bluetooth stack and desktop tools |
| `install-software-factory.sh` | Install Docker CE + Dagger CLI on Ubuntu |
| `install-micro.sh` / `install-gram.sh` / `install-tmux.sh` | Install the micro / Gram / tmux editors and tooling |
| `gnome-linux-setup.sh` | Install GNOME Shell extensions via `gext` |
| `gnome-macos-setup.sh` | Set up a macOS-like GNOME desktop (WhiteSur theme) |
| `gnome-setup-vdesktop.sh` | Configure 4 static virtual desktops with Ctrl+Arrow navigation |
| `snap-remove.sh` | Remove all snap packages and disable snapd |
| `fix-mouse.sh` | Apply USB-mouse fixes for the HP ZBook Ultra G1a |
| `enable-ubuntu-keyboard-wakeup.sh` | Enable USB-keyboard wake-from-suspend via a udev rule |
| `venva` | Activate the default Python venv |
| `whatami` | Print the machine's DMI product name |

#### Disk & imaging

| Tool | Purpose |
|---|---|
| `blanksd.sh` | Wipe/blank an SD card or disk (destructive — requires a typed confirmation) |
| `iso2usb` | Write an ISO image to a USB drive as a raw, bootable copy |
| `make-rpi-toml.sh` | Generate Raspberry Pi cloud-init user-data |

**Caveats for the tools:**
- Several `install-*.sh` / `setup-*.sh` scripts run vendor `curl … | sh` installers. They are trust-on-first-use; pin versions yourself if that matters to you.
- `blanksd.sh`, `iso2usb`, and `snap-remove.sh` are destructive. Read them before running.
- Device scripts (`play-reo1`, `reo1-motion-probe.sh`, `shellyctl`, `lights-meeting.sh`) target LAN devices and read credentials from the environment (e.g. `REO_HOST`, `REO_PASS`) — never hardcoded.

### cb

`cb` copies text to the system clipboard and is the one tool worth knowing in detail.

```bash
cb                  # copy this terminal's screen + scrollback
cb [source]         # inside a herdr pane, pick the snapshot source
                    #   (visible|recent|recent-unwrapped|detection; default recent-unwrapped)
cb --current [src]  # copy herdr's focused pane even when cb is launched outside it
some-command | cb   # copy piped text (works anywhere, including over SSH)
```

How it picks the text:
- **In a herdr pane** (detected via `$HERDR_PANE_ID`, which is set when you type `cb` at the prompt): it reads that pane's logical buffer with `herdr pane read`. This is necessary because kitty only sees herdr's single composited surface, so `kitten @ get-text` would grab the whole window instead of the focused pane. `--current` covers the key-launch case, where `cb` runs as a child of kitty and doesn't inherit the env var.
- **In a plain kitty terminal**: it uses `kitten @ get-text` over kitty's remote-control socket (local only — over SSH, pipe text in instead).
- **Piped input**: it copies stdin verbatim.

How it copies: it prefers `kitten clipboard` (an OSC 52 escape that routes to the real terminal in front of you, so it works locally, over SSH, and through tmux), falling back to `wl-copy`/`pbcopy`/`xclip`, and finally to a hand-written OSC 52 sequence.

## Private companion repo

Host-specific packages and local/include files (SSH `config.local`, `work.env`, `.gitconfig.local`, and per-host overrides) live in a separate **private** repo that stows into `$HOME` the same way. On a new machine:

```bash
git clone <public-url>  ~/dotfiles         && make -C ~/dotfiles install
git clone <private-url> ~/dotfiles-private && make -C ~/dotfiles-private install
```

The public base degrades gracefully if the private repo is absent — missing SSH includes, git includes, and env sources are all optional.

## Adding a new config

1. Create the package directory mirroring `$HOME`: `mkdir -p ~/dotfiles/mypkg/.config/mypkg`
2. Move the config file in: `mv ~/.config/mypkg/config ~/dotfiles/mypkg/.config/mypkg/`
3. Refresh and stow: `cd ~/dotfiles && make refresh && make stow`

## Notes

- **SSH keys are not stored here** — only `~/.ssh/config`.
- **Secrets are not stored here** — they live in the private companion repo or in environment files (`~/.config/work.env`) that are never tracked.
- Files at the repo root (`README.md`, `Makefile`, `.stowrc`) are not stowed.

## Troubleshooting

**Conflict errors.** If stow reports a conflict, a real (non-symlink) file already exists at the target. Remove it (`rm ~/.myconfig`) or unstow first (`stow -D mypkg`), then re-stow. `make stow` auto-removes conflicting plain files for you before stowing.

**Wrong or stale symlinks.** Refresh them all: `make restow`.
