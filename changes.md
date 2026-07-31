# changes.md

Log of config changes made by Claude, with revert instructions for each, so
anything that turns out to be unwanted can be backed out without archaeology.

---

## 2026-07-30 — kitty: copy scrollback to clipboard without the mouse

### The problem

Selecting text with the mouse stops working while a TUI is running. Claude Code
(and vim, htop, agent-manager, anything Ink-based) turns on DEC mouse tracking
(`\033[?1000h` plus a motion mode and `\033[?1006h`). Once an application asserts
that, kitty considers the mouse **grabbed** and routes press/drag/release to the
app as escape sequences instead of driving its own selection. Every terminal
behaves this way; the app asked for the events.

`shift+drag` is the documented bypass (`mouse_map shift+left press grabbed
mouse_selection normal`), but it only reaches what is currently on screen, and
dragging across a TUI picks up sidebar and border columns.

`ctrl+shift+h` (`show_scrollback`) is **not** a solution — it opens the buffer in
`less` for *viewing*. It has no path to the clipboard.

### The change

Two keybindings that copy the buffer straight to the clipboard — no pager, no
mouse, unaffected by whether an app has grabbed the mouse:

| Key | Copies |
|-----|--------|
| `ctrl+shift+p` then `y` | main screen + scrollback |
| `ctrl+shift+p` then `a` | alternate screen + its scrollback |

**Why two.** A full-screen application renders on the *alternate* screen, whose
buffer is separate from the main screen's scrollback. Inside such an app,
`@screen_scrollback` returns your shell history from before you launched it —
not what you are looking at. Which one you need depends on whether the program
uses the alternate screen, so both are bound.

**Why the `ctrl+shift+p` prefix.** kitty already reserves it as the chord prefix
for text-grabbing kittens (`p>f` path, `p>l` line, `p>w` word, `p>h` hash,
`p>n` line number). These belong in the same family, and `y`/`a` are unused
there. Every single-letter `ctrl+shift+<x>` is already taken by a kitty default,
so a chord avoids silently clobbering one.

Output is plain text — `--stdin-add-formatting` would be required to include
ANSI codes, and it is not set.

### Revert

Delete the `CLIPBOARD` block at the end of
`kitty/.config/kitty/kitty.conf`, or:

```sh
git -C ~/dotfiles checkout -- kitty/.config/kitty/kitty.conf
```

Then `ctrl+shift+F5` in kitty to reload, or restart it. Nothing else depends on
these bindings.

### Considered and rejected

- **Custom `mouse_map` entries for rectangle select.** Unnecessary — kitty
  already binds `ctrl+shift+alt+left` drag to `mouse_selection rectangle` in the
  `grabbed` state, along with `shift+left` double-click (word) and triple-click
  (line). Adding maps here risked overriding
  `ctrl+shift+left press grabbed discard_event`, which exists so the *release*
  can open links.
- **Changing the bypass modifier away from shift.** Whatever modifier is chosen
  gets taken away from the running application in that state.
- **Replacing the `scrollback_pager` with nvim** to enable yanking. Works, but
  the invocation is long and fragile, and the keybindings above solve the actual
  need in one keypress.

---

## 2026-07-30 — `cb`: use OSC 52 so it works over SSH

`scripts/bin/cb` piped `kitty @ get-text` into `wl-copy`/`pbcopy`/`xclip`. Those
talk to the local display server, so over SSH they target the *remote* machine's
clipboard, or fail outright where there is no display. `wl-copy` is not even
installed on this host, so it was silently falling through to `xclip`.

Rewritten to send text via `kitten clipboard`, which writes an OSC 52 escape to
the tty — that travels back over the SSH connection to the terminal actually in
front of you. Also now accepts piped stdin (`some-command | cb`), which is the
only mode that can work on a remote host, since `kitty @ get-text` needs a
control socket that a remote host does not have.

**Revert:** `git -C ~/dotfiles checkout -- scripts/bin/cb`
(`~/bin/cb` is a stow symlink to it, so no redeploy needed.)

---

## 2026-07-30 — kitty: one install, from apt

### The problem

Two kitty installs shadowing each other:

| | Version | Source | Installed |
|---|---|---|---|
| `~/.local/kitty.app` | 0.47.3 | upstream `installer.sh` via `install-linux.sh` | Jun 11–13 |
| `/usr/bin/kitty` | 0.45.0 | apt package (marked manual) | Jun 14 19:22 |

`install-linux.sh` guarded its install with `if ! command -v kitty`, which cannot
see an `apt install kitty` that happens a day *later*. Neither installer knew
about the other. `~/.local/bin` precedes `/usr/bin` on PATH, so the upstream
0.47.3 build was the one actually running while the apt package sat unused.

### Why apt won

The version gap looked like the deciding factor and wasn't. **0.45.0 supports
every feature this config depends on** — verified directly, not assumed:

```sh
/usr/bin/kitten @ launch --help | grep -E 'clipboard, primary|@alternate_scrollback'
```

Both `--type=clipboard` and `@alternate_scrollback` are present, so the
`ctrl+shift+p>y` / `>a` bindings work unchanged. The whole config was also
parsed under 0.45 with kitty's own loader and both chords registered.

With no functional difference, the tiebreakers all point one way: apt gets
security updates for the Ubuntu 26.04 LTS lifetime, while `~/.local/kitty.app`
only updates when you remember `kitten update-self` — nothing nags you. It also
reclaims 110 MB and matches how everything else on these boxes is managed.

### Fixing another host

Safe to re-run; does nothing if the host is already clean.

**1. Diagnose.** A host has this problem if `type -a` lists two of each and
`~/.local/kitty.app` exists:

```sh
type -a kitty kitten
ls -d "$HOME/.local/kitty.app" 2>/dev/null
dpkg -s kitty >/dev/null 2>&1 && echo "apt kitty: installed" || echo "apt kitty: MISSING"
```

**2. Remediate.**

```sh
#!/usr/bin/env bash
set -euo pipefail

# Guard: never remove the .local tree unless the apt package is really there,
# or the host is left with no kitty at all.
if ! dpkg -s kitty >/dev/null 2>&1; then
    echo "apt kitty missing. Run: sudo apt-get install -y kitty" >&2
    exit 1
fi

if [[ -d "$HOME/.local/kitty.app" ]]; then
    rm -rf "$HOME/.local/kitty.app"
    # The symlinks matter most: ~/.local/bin precedes /usr/bin on PATH, so
    # leaving them dangling shadows the working apt binary and kitty stops
    # resolving entirely.
    rm -f "$HOME/.local/bin/kitty" "$HOME/.local/bin/kitten"
    # install-linux.sh rewrote these to hardcode the .local path, and being in
    # the user applications dir they shadow /usr/share/applications/kitty.desktop.
    rm -f "$HOME/.local/share/applications/kitty.desktop" \
          "$HOME/.local/share/applications/kitty-open.desktop"
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "$HOME/.local/share/applications" || true
    fi
    echo "removed legacy ~/.local/kitty.app"
else
    echo "no ~/.local/kitty.app — nothing to do"
fi
```

**3. Verify.** Expect `/usr/bin/...` for both, and an empty dangling-link list:

```sh
command -v kitty; command -v kitten; kitty --version
find "$HOME/.local/bin" -maxdepth 1 -xtype l      # must print nothing
ls "$HOME/.local/share/applications"/kitty*.desktop 2>/dev/null || echo "system entry active"
```

**4. Restart open kitty windows — this step is not optional.**

Running processes hold the deleted binary's inode, so nothing crashes
mid-session. But every shell they spawn afterwards loses its bash config, with
this signature:

```
bash-5.3$            # instead of  europa:~/src/foo>
```

**Why.** kitty runs bash as `/bin/bash --posix` with
`ENV=$KITTY_INSTALLATION_DIR/shell-integration/bash/kitty.bash`. In posix mode
bash sources `$ENV` and deliberately does *not* read `~/.bashrc` —
`kitty.bash` is what turns posix mode back off and sources the user's rc files
itself. A kitty process started before the cleanup still exports the deleted
`~/.local/kitty.app/...` path, so `$ENV` resolves to nothing, no rc is loaded,
and bash falls back to its built-in `PS1='\s-\v\$ '`.

Confirm it in one line — if this prints a path under `~/.local`, the window is
stale:

```sh
echo "$KITTY_INSTALLATION_DIR"; [ -d "$KITTY_INSTALLATION_DIR" ] || echo "STALE"
```

Two ways out:

- **Proper fix:** close every kitty window and reopen. New processes get
  `KITTY_INSTALLATION_DIR=/usr/lib/kitty`, which exists.
- **In-place rescue,** for a window you are not ready to lose (a long-running
  agent, an ssh session): `exec bash`. `ENV` is only consulted in posix mode, so
  a plain interactive bash reads `~/.bashrc` directly and the prompt returns
  immediately. The window is still running the old kitty binary — this only
  fixes the shell.

Find every stale window:

```sh
for p in $(pgrep -x kitty); do
  readlink /proc/$p/exe | grep -q deleted && echo "stale: pid $p"
done
```

### Also changed

- `install-linux.sh` now runs `sudo apt-get install -y kitty` instead of piping
  upstream's `installer.sh`, and self-heals: if it finds `~/.local/kitty.app`
  from an earlier run, it removes it and the shadowing symlinks/desktop files.
  So on a fresh or a poorly-set-up host, running the script is sufficient.
- Dropped `resize_draw_strategy static` from `kitty.conf`. It was logging
  `Ignoring unknown config key` under **both** 0.45 and 0.47 — a genuinely
  obsolete option, not a version artifact. `focus_follows_mouse` moved up into
  the MOUSE section, since removing the dead option emptied the PERFORMANCE one.

### Note on `apt autoremove`

Not relevant while the apt package stays installed — `kitty-terminfo`,
`kitty-shell-integration` and `kitty-doc` remain its dependencies. It would only
matter if you ever `apt remove kitty`: keep `kitty-terminfo` (114 KB), because
`/usr/share/terminfo/x/xterm-kitty` is what `sudo -i`, systemd units, and other
env-scrubbing contexts fall back on when they do not inherit kitty's `TERMINFO`.

### Revert

To go back to the upstream build:

```sh
/bin/sh -c "$(curl -fsSL https://sw.kovidgoyal.net/kitty/installer.sh)"
ln -sf "$HOME/.local/kitty.app/bin/kitty"  "$HOME/.local/bin/kitty"
ln -sf "$HOME/.local/kitty.app/bin/kitten" "$HOME/.local/bin/kitten"
```

and `git -C ~/dotfiles checkout -- scripts/bin/install-linux.sh kitty/.config/kitty/kitty.conf`.

---

## 2026-07-30 — untrack `emacs/.emacs.d/straight/build-cache.el`

`.gitignore` already listed `emacs/.emacs.d/straight/`, but the file predated
that rule. Ignore rules do not apply to files already in the index, so it kept
showing as modified on every emacs start.

Untracked with `git rm --cached` — the file stays on disk, git just stops
watching it.

**Revert:** `git -C ~/dotfiles add -f emacs/.emacs.d/straight/build-cache.el`
