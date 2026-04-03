# Login shell: load shared environment, then interactive bits
[ -f ~/.bash_common ] && source ~/.bash_common
[ -f ~/.bashrc ] && source ~/.bashrc

. "$HOME/.local/bin/env"
