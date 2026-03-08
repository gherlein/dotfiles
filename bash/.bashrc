# Guard: exit if not interactive
[ -n "$PS1" ] || return

# history
HISTCONTROL=ignoredups:erasedups
HISTSIZE=10000
HISTFILESIZE=20000
shopt -s histappend
PROMPT_COMMAND="history -a"

[ -f ~/.fzf.bash ] && source ~/.fzf.bash
