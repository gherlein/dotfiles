
test -e "${HOME}/.iterm2_shell_integration.zsh" && source "${HOME}/.iterm2_shell_integration.zsh"


[ -f ~/.fzf.zsh ] && source ~/.fzf.zsh

# nanobrew
export PATH="/opt/nanobrew/prefix/bin:$PATH"

. "$HOME/.local/bin/env"
