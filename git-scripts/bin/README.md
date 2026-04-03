# Script Descriptions

## gg — Git Gather

Batch git operations across all repositories in the current directory. Iterates over every subdirectory that contains a `.git` folder and pulls (with rebase), stages all changes, commits with a provided message (default: "interim commit"), and pushes. With `-s` / `--status` it prints a summary of each repo's branch, number of uncommitted changes, and ahead/behind counts without modifying anything.

**Usage:** `gg ["commit message"]` or `gg -s`

## gopen — Open GitHub Repo in Browser

Reads the `remote.origin.url` from a git repository (passed as an argument or the current directory), converts it to an HTTPS GitHub URL, and opens it in the default browser (`open` on macOS, `xdg-open` on Linux).

**Usage:** `gopen [repo-dir]`

## gp — Git Push (single repo)

Quick add-commit-push for the current git repository. Fetches first and checks whether the remote is ahead of local; if so, it aborts with an error telling the user to pull/rebase. Otherwise it runs `git add .`, commits with the provided message (default: "interim commit"), and pushes with `-u`.

**Usage:** `gp ["commit message"]`

## gp-all — Git Push All

Runs `gp` in every git-repo subdirectory under the script's own directory. For subdirectories that are not git repos, it interactively asks whether to initialize a new repo and create a matching private GitHub repository via `gh repo create`, then pushes.

**Usage:** `gp-all`

## gpnew — Create New GitHub Repo

Creates a new private repository under a specified GitHub organization using the `gh` CLI. Initializes git locally, commits all files, sets the default branch to `main`, adds the remote, and pushes.

**Usage:** `gpnew <org> <repo-name>`

## grelease — Git Release

Creates an annotated git tag, pushes it to origin, and then creates a GitHub release (via `gh release create`) with the given version and description. Validates that the tag does not already exist and that `gh` is installed.

**Usage:** `grelease <version> <description>`

## gtag — Git Tag

Creates an annotated git tag with a description and pushes all tags to origin. Similar to `grelease` but does not create a GitHub release — it only tags and pushes.

**Usage:** `gtag <short-tag> <long-description>`
