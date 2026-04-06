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

# Ghostty terminal background color per hostname
ghostty_bg() { printf '\e]11;%s\a' "$1"; }
ghostty_bg_reset() {
    if [[ -n "$GHOSTTY_HOST_COLOR" ]]; then
        ghostty_bg "$GHOSTTY_HOST_COLOR"
    else
        printf '\e]111\a'
    fi
}

# Set terminal background color based on hostname.
# Each machine gets a distinct color so you always know which host you are on.
# Run 'hostname -s' on a machine to find its short name, then add it here.
GHOSTTY_HOST_COLOR='#4f4f4f'
case "$(hostname -s)" in
    jupiter3)  GHOSTTY_HOST_COLOR='#0d1f0d' ;;  # dark green  - local workstation
    io)        GHOSTTY_HOST_COLOR='#0d0d1f' ;;  # dark blue   - SBC / edge node
    helios)    GHOSTTY_HOST_COLOR='#0d0d1f' ;;  # dark blue
    ai2)       GHOSTTY_HOST_COLOR='#1f0d0d' ;;  # dark red    - GPU / AI server
    builder)   GHOSTTY_HOST_COLOR='#1f1a0d' ;;  # dark amber  - build server
    jumpbox)   GHOSTTY_HOST_COLOR='#1f0d1a' ;;  # dark rose   - bastion host
    *)         GHOSTTY_HOST_COLOR='#3d3d3d' ;;  # unknown host - default grey
esac
ghostty_bg "$GHOSTTY_HOST_COLOR"

ssh() {
    command ssh "$@"
    ghostty_bg "$GHOSTTY_HOST_COLOR"
}

# fzf
[ -f ~/.fzf.bash ] && source ~/.fzf.bash

. "$HOME/.local/bin/env"

# opencode
export PATH=/home/gherlein/.opencode/bin:$PATH
