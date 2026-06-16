---
name: git-ops
description: Cherry-pick via inspect-and-recreate and rebase conflict resolution workflows
disable-model-invocation: true
---

# Git Operations

## Cherry-Pick (Inspect and Recreate)

Instead of `git cherry-pick <SHA>`:

1. Inspect the commit: `git show <SHA>`
2. Understand the changes and their intent
3. Recreate the same changes on the current HEAD
4. Commit using `git commit -c <SHA>` to preserve the original message and authorship

This avoids merge conflicts and gives you control over how changes apply to the current state.

## Rebase Conflict Resolution

When resolving conflicts during a rebase:

1. Read the conflict markers in each file
2. Resolve by choosing the correct version or merging both
3. Run `just precommit` if a justfile with that recipe exists
4. Stage resolved files with `git add <file>`
5. Continue with `git rebase --continue`
6. Repeat if more conflicts arise in subsequent commits

Never use `git rebase --abort` unless the user requests it. Never use `--no-verify`.
