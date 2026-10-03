# Setup fzf
# ---------
# Add Homebrew fzf to PATH on macOS if not already present
if [[ "$(uname -s)" == "Darwin" ]] && [[ ! "$PATH" == */opt/homebrew/opt/fzf/bin* ]]; then
  PATH="${PATH:+${PATH}:}/opt/homebrew/opt/fzf/bin"
fi

[[ -x "$(command -v fzf)" ]] && eval "$(fzf --bash)"
