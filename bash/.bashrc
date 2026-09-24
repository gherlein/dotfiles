# Guard: exit if not interactive
[ -n "$PS1" ] || return

# Source shared environment
[[ -z "$_BASH_COMMON_LOADED" ]] && [ -f ~/.bash_common ] && source ~/.bash_common

# history
HISTCONTROL=ignoredups:erasedups
HISTSIZE=10000
HISTFILESIZE=20000
shopt -s histappend
PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND;}history -a"

# prompt
if [ $(id -u) -ne 0 ]
then
  PS1="\h:\w> "
else
  PS1="\e[1;31m[\u@\h \W]\$ \e[0m>"
fi

# Terminal background color per hostname (OSC 11 — works in kitty, ghostty, xterm, wezterm)
term_bg() { printf '\e]11;%s\a' "$1"; }
term_bg_reset() {
    if [[ -n "$TERM_HOST_COLOR" ]]; then
        term_bg "$TERM_HOST_COLOR"
    else
        printf '\e]111\a'
    fi
}

# Set terminal background color based on hostname.
# Each machine gets a distinct color so you always know which host you are on.
# Run 'hostname -s' on a machine to find its short name, then add it here.
TERM_HOST_COLOR='#4f4f4f'
case "$(hostname -s)" in
    jupiter3)  TERM_HOST_COLOR='#0d1f0d' ;;  # dark green  - local workstation
    io)        TERM_HOST_COLOR='#0d0d1f' ;;  # dark blue   - SBC / edge node
    helios)    TERM_HOST_COLOR='#0d0d1f' ;;  # dark blue
    ai2)       TERM_HOST_COLOR='#1f0d0d' ;;  # dark red    - GPU / AI server
    builder)   TERM_HOST_COLOR='#1f1a0d' ;;  # dark amber  - build server
    jumpbox)   TERM_HOST_COLOR='#1f0d1a' ;;  # dark rose   - bastion host
    *)         TERM_HOST_COLOR='#1a1a1a' ;;  # unknown host - default dark grey
esac
# Guard on stdout being a tty: Zed/gram SSH remoting runs an interactive shell
# and reads its stdout as a binary protocol stream, so an OSC escape here corrupts
# the channel and the connection reconnect-loops until it times out.
[[ -t 1 ]] && term_bg "$TERM_HOST_COLOR"

# WHY the wrapper: the remote shell sets its own background via OSC 11 and never
# restores it on exit, so repaint this host's color when the session ends.
# WHY 'kitten ssh': it installs kitty's shell integration and terminfo on the
# remote, so the remote cwd is reported as file://host/path. Without that kitty
# cannot follow you across the connection and ctrl+shift+t splits into a local
# shell at the local cwd instead of the remote host and directory.
ssh() {
    if command -v kitten >/dev/null 2>&1; then
        kitten ssh "$@"
    else
        command ssh "$@"
    fi
    term_bg "$TERM_HOST_COLOR"
}

# WHY: the kitten's terminfo bootstrap fails on minimal remote shells (busybox,
# BrightSign players) — use 'sshp' for those.
sshp() {
    command ssh "$@"
    term_bg "$TERM_HOST_COLOR"
}

# fzf
[ -f ~/.fzf.bash ] && source ~/.fzf.bash

[ -f "$HOME/.local/bin/env" ] && . "$HOME/.local/bin/env"

# opencode
export PATH=/home/gherlein/.opencode/bin:$PATH

# Added by codebase-memory-mcp install
export PATH="/home/gherlein/.local/bin:$PATH"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

# codg
export PATH=/home/gherlein/.codg/bin:$PATH

eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv bash)"

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion
