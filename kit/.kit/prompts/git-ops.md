---
description: Git workflow management and commit operations
---
Git operation: $@

## Commit Rules

- Present-tense verb, 60-120 chars, single line, end with period
- No praise adjectives ("great", "awesome")
- One logical change per commit
- Never commit secrets, credentials, or API keys
- If fixing a compiler/linter error, use `fixup!` prefix

## Branch Rules

- Feature branches from main
- Descriptive branch names: `feature/add-user-auth`, `fix/null-pointer-in-parser`
- Rebase onto main before merge (no merge commits)

## Pre-commit Checks

Before committing, verify:
1. `make test` passes
2. `go vet ./...` clean (for Go projects)
3. No secrets in `git diff --staged`
4. `.gitignore` is present and correct

## Operations

- Show the command and confirm with the user before running destructive git operations
- Never force push to main/master
- Never use `git reset --hard` without user confirmation
