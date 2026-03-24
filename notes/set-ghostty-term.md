Set `TERM=xterm-256color` on the remote host, since most remotes don't have the `ghostty` terminfo entry.

**Options:**

1. **SSH config** (preferred) — forces it per-host:
   ```
   # ~/.ssh/config
   Host *
       SetEnv TERM=xterm-256color
   ```
   Note: server must have `AcceptEnv TERM` in `sshd_config` (not always allowed).

2. **SSH flag** at connect time:
   ```sh
   ssh -o SetEnv=TERM=xterm-256color user@host
   ```

3. **Remote shell rc** — on the remote host:
   ```sh
   # ~/.bashrc or ~/.zshrc
   [ "$TERM" = "xterm-ghostty" ] && export TERM=xterm-256color
   ```

4. **Install ghostty terminfo on remote** — if you want full fidelity:
   ```sh
   # On local machine, copy terminfo to remote
   infocmp -x | ssh user@host -- tic -x -
   ```
   After this, `TERM=ghostty` or `TERM=xterm-ghostty` works natively.

Option 4 is the cleanest if you control the remote. Option 1/2 is easiest if you don't.
