# Dotfiles

Personal configuration files managed with [GNU Stow](https://www.gnu.org/software/stow/).

## Structure

Each directory is a "package" that contains config files organized to mirror your home directory structure:

```
~/dotfiles/
├── bash/           # Bash configs (.bashrc, .bash_profile)
├── zsh/            # Zsh configs (.zshrc)
├── fzf/            # FZF configs and shell integration
├── git/            # Git global config
├── tmux/           # Tmux config
├── alacritty/      # Alacritty terminal config
├── emacs/          # Emacs config
├── zed/            # Zed editor config
├── ssh/            # SSH config (NOT keys!)
└── ...
```

## Usage

### Stow all packages
```bash
make stow
```

### Stow specific package
```bash
stow bash
stow git
```

### Unstow (remove symlinks)
```bash
stow -D bash
# or unstow all:
make unstow
```

### Restow (refresh symlinks)
```bash
make restow
```

### List packages
```bash
make list
```

### Refresh package list
After adding or removing package directories, regenerate `.stow-packages`:
```bash
make refresh
```

## Installation

1. Clone this repo:
   ```bash
   git clone <repo-url> ~/dotfiles
   cd ~/dotfiles
   ```

2. Run migration (first time only):
   ```bash
   ./migrate.sh
   ```

3. Or manually stow packages:
   ```bash
   make stow
   ```

## Adding New Configs

1. Create package directory:
   ```bash
   mkdir -p ~/dotfiles/mypackage
   ```

2. Move config file(s) to mirror home structure:
   ```bash
   mv ~/.myconfig ~/dotfiles/mypackage/
   ```

3. Refresh the package list:
   ```bash
   cd ~/dotfiles
   make refresh
   ```

4. Stow it:
   ```bash
   make stow
   # or just the new package:
   stow mypackage
   ```

## Important Notes

- **SSH keys are NOT stored here** - only `.ssh/config`
- **Secrets/credentials are NOT stored here** - use environment variables or separate tools
- Files at dotfiles root (README.md, Makefile, migrate.sh) are **not stowed**
- Each package mirrors your home directory structure

## Troubleshooting

### Conflict errors
If stow complains about conflicts, the file already exists. Either:
- Delete the existing file: `rm ~/.myconfig`
- Or unstow first: `stow -D mypackage`

### Wrong symlinks
To refresh all symlinks:
```bash
make restow
```
