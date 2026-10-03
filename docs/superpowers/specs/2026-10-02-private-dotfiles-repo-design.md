# Private dotfiles repo — design

Date: 2026-10-02
Status: approved, pending implementation plan

## Purpose

Split the single public dotfiles repo into two independently-managed GNU Stow
repos so the public one can go public while host-specific configuration and
local/include files are kept private and still centrally managed.

Today the public repo references several deliberately-untracked files
(`~/.config/work.env`, `~/.ssh/config.local`, `~/.gitconfig.local`,
`~/.omp/agent/config.local.yml`) and also carries host-specific stow packages
(`<tool>-<host>`). The goal is to move both categories into a private repo that
stows into `$HOME` the same way, leaving the public repo clean and generic.

## Decisions

These were settled during brainstorming and are fixed for this design:

- **Secrets storage:** plaintext in the private repo. No encryption machinery;
  security rests on the repo remaining private.
- **Topology:** two independent sibling repos — `~/dotfiles` (public) and
  `~/dotfiles-private` (private). The public repo contains nothing that names or
  references the private remote.
- **Per-host variance:** local/include files are mostly shared with some
  per-host overrides, so the private repo uses the same `-<host>` host-scoping
  the public repo already uses.
- **Makefile engine:** the private repo carries a self-contained copy of the
  stow + host-scoping engine, so it installs standalone with no dependency on the
  public repo. The ~40 stable engine lines are duplicated by design; this is the
  accepted cost of full independence.

## Current system (reference)

- GNU Stow, everything targets `$HOME`. `make install` = `refresh` (rescan
  top-level dirs into `.stow-packages`) then `stow`.
- Host-specific packages are named `<tool>-<host>`; `HOSTS := io europa helios`.
  Each host stows the shared packages plus only the packages whose suffix matches
  `hostname -s`. Other hosts' packages are skipped.
- Local/include files referenced but untracked:
  - `~/.config/work.env` — sourced by `bash/.bash_common` (holds `REO_PASS`,
    `REO_HOST`, `GERRIT_HOST`, `LAN_SUBNET`, etc.)
  - `~/.ssh/config.local` — pulled in by `ssh/.ssh/config` via `Include`
  - `~/.gitconfig.local` — pulled in by `git/.gitconfig` via `include.path`
  - `~/.omp/agent/config.local.yml` — presence-detected overlay in `bash_common`
- Nothing is committed yet (0 commits), so relocation is a plain filesystem move
  with no git history to rewrite.

## Architecture

```
~/dotfiles/           PUBLIC  — shared, generic tool configs
~/dotfiles-private/   PRIVATE — host-specific packages + local/include files (plaintext)
```

Both are independent stow repos targeting `$HOME`, each with its own
`make install`. New-host flow:

1. Clone public → `cd ~/dotfiles && make install`
2. Clone private → `cd ~/dotfiles-private && make install`

Order is forgiving (see Error handling) but documented as public-then-private.

## Private repo package layout

Same conventions as the public repo: one package dir per concern, package path
mirrors the `$HOME` target, host-specific packages suffixed `-<host>`,
`HOSTS := io europa helios`.

### Moved host tool packages (relocated unchanged)

`hax-<host>`, `kit-<host>`, `omp-<host>`, `pi-<host>` for each of
`io`, `europa`, `helios` (12 packages total).

The omp per-host overlay `config.local.yml` folds into its matching `omp-<host>`
package (`omp-<host>/.omp/agent/config.local.yml`). `bash/.bash_common` already
activates it by presence check, so no public edit is needed for omp.

### `local/` (shared; stowed on every host)

- `local/.config/work.env`
- `local/.ssh/config.local`
- `local/.gitconfig.local`

### `local-<host>/` (per-host overrides; only the matching host stows)

- `local-<host>/.config/work.local.env` — host env overrides
- `local-<host>/.ssh/config.d/<host>.conf` — host SSH entries
- `local-<host>/.gitconfig.host` — host git overrides

A host only needs the files it actually uses; a package may carry a subset.

## Public repo edits

Small changes so the public base consumes both the shared and the per-host local
files:

- `bash/.bash_common`: after `source ~/.config/work.env`, add
  `[[ -f ~/.config/work.local.env ]] && source ~/.config/work.local.env`.
- `git/.gitconfig`: add a second include entry, `path = ~/.gitconfig.host`,
  after the existing `~/.gitconfig.local` include.
- `ssh/.ssh/config`: add `Include ~/.ssh/config.d/*.conf` immediately after the
  existing `Include ~/.ssh/config.local`, near the top of the file so
  host-specific entries win under SSH first-match semantics.

## Makefile

The private repo gets a copy of the public stow + host-scoping engine with one
difference: the public-only bootstrap line in the `stow` target
(`curl … localdev/install.sh | bash`) is omitted. All of
`refresh`/`list`/`stow`/`unstow`/`restow`/`adopt` operate on the private repo's
own directories.

The public Makefile is unchanged. With the host packages relocated, its
host-scoping branch is dormant but retained — it is the shared engine and may
host public per-host packages in future.

## Error handling / edge cases

- **Private repo absent:** the public repo still works. `ssh` silently ignores
  missing `Include` targets, `git include.path` ignores a missing file, and the
  `work.env`/`work.local.env` sources are `[[ -f ]]`-guarded. Graceful
  degradation, no errors.
- **No stow conflicts between `local/` and `local-<host>/`:** they own distinct
  filenames (`work.env` vs `work.local.env`, `config.local` vs
  `config.d/<host>.conf`, `.gitconfig.local` vs `.gitconfig.host`), so no two
  packages claim the same `$HOME` target.
- **Empty glob:** `Include ~/.ssh/config.d/*.conf` matching nothing is not an
  error in SSH.

## Migration (clean move; 0 commits)

1. `make unstow` in the public repo (removes the existing symlinks).
2. Create `~/dotfiles-private` with `git init`. Move the 12 host dirs into it.
   Build `local/` and `local-<host>/` from the current real files in `$HOME`
   (`~/.config/work.env`, `~/.ssh/config.local`, `~/.gitconfig.local`), which are
   plain files today and become stow-managed symlinks after install.
3. Apply the public-repo edits above; place the engine-copy Makefile in the
   private repo.
4. `make install` in each repo; verify.

## Verification

- `make list` in each repo shows the correct active/skipped packages for the
  current host.
- `stow -n` reports no conflicts.
- Post-install, the merged local files resolve:
  - `ssh -G <somehost>` reflects entries from `config.local` / `config.d`.
  - `bash -lc 'echo $GERRIT_HOST'` shows `work.env` was loaded.
  - `git config --get <key>` returns a value defined in `.gitconfig.local`.
- `grep` confirms no private content (host IPs, secrets, host-specific packages)
  remains in the public repo.

## Out of scope

- Encryption of secrets (explicitly chosen against).
- Submodule / nested-clone topologies (chose independent siblings).
- Sharing the Makefile engine via `include` across repos (chose self-contained
  copies).
- Migrating away from GNU Stow (e.g. to chezmoi).
