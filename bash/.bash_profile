# Login shell: load shared environment, then interactive bits
[ -f ~/.bash_common ] && source ~/.bash_common
[ -f ~/.bashrc ] && source ~/.bashrc

[ -f "$HOME/.local/bin/env" ] && . "$HOME/.local/bin/env"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

# bun
export BUN_INSTALL="$HOME/.bun"
export PATH="$BUN_INSTALL/bin:$PATH"
