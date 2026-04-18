---
description: Guide completion of development work with merge, PR, or cleanup options
---
Finish the current development branch: $@

## Pre-completion Checklist

1. [ ] All tests pass (`make test`)
2. [ ] Build succeeds (`make build`)
3. [ ] Linters clean (`go vet ./...`)
4. [ ] No uncommitted changes (`git status`)
5. [ ] Commit history is clean and logical
6. [ ] No secrets or credentials in any commit

## Options

Present these options to the user:

### Option A: Merge to main
- Rebase onto main
- Fast-forward merge
- Delete feature branch

### Option B: Create PR
- Push branch to remote
- Create PR with summary of changes
- List files changed and test coverage

### Option C: Cleanup only
- Squash fixup commits
- Reword commit messages if needed
- Leave branch for later

## Rules

- Always show the options and let the user choose.
- Never force push or merge without confirmation.
- Show `git log --oneline main..HEAD` so the user sees what will be merged.
