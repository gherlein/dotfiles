---
name: using-git-worktrees
description: Use when starting feature work that needs isolation from current workspace or before executing implementation plans - creates isolated git worktrees with smart directory selection and safety verification
---

# Using Git Worktrees

## Overview

Git worktrees create isolated workspaces sharing the same repository, allowing work on multiple branches simultaneously without switching.

**Core principle:** Systematic directory selection + safety verification = reliable isolation.

**Announce at start:** "I'm using the using-git-worktrees skill to set up an isolated workspace."

## Directory Selection Process

Follow this priority order:

### 1. Check Existing Directories

```bash
ls -d .worktrees 2>/dev/null     # Preferred (hidden)
ls -d worktrees 2>/dev/null      # Alternative
```

If found: Use that directory. If both exist, `.worktrees` wins.

### 2. Check AGENTS.md

```bash
grep -i "worktree.*director" AGENTS.md 2>/dev/null
```

If preference specified: Use it without asking.

### 3. Ask User

If no directory exists and no AGENTS.md preference:

```
No worktree directory found. Where should I create worktrees?

1. .worktrees/ (project-local, hidden)
2. ~/.worktrees/<project-name>/ (global location)

Which would you prefer?
```

## Safety Verification

### For Project-Local Directories

**MUST verify directory is ignored before creating worktree:**

```bash
git check-ignore -q .worktrees 2>/dev/null || git check-ignore -q worktrees 2>/dev/null
```

**If NOT ignored:**
1. Add appropriate line to .gitignore
2. Commit the change
3. Proceed with worktree creation

### For Global Directory

No .gitignore verification needed — outside project entirely.

## Creation Steps

```bash
# Detect project name
project=$(basename "$(git rev-parse --show-toplevel)")

# Create worktree with new branch
git worktree add .worktrees/$BRANCH_NAME -b $BRANCH_NAME

# Run project setup
if [ -f go.mod ]; then go mod download; fi
if [ -f package.json ]; then npm install; fi
if [ -f Cargo.toml ]; then cargo build; fi

# Verify clean baseline
make test   # or go test ./..., npm test, etc.
```

**If baseline tests fail:** Report failures, ask whether to proceed or investigate.

**If tests pass:** Report ready.

## Quick Reference

| Situation | Action |
|-----------|--------|
| `.worktrees/` exists | Use it (verify ignored) |
| `worktrees/` exists | Use it (verify ignored) |
| Both exist | Use `.worktrees/` |
| Neither exists | Check AGENTS.md -> Ask user |
| Directory not ignored | Add to .gitignore + commit |
| Tests fail during baseline | Report failures + ask |

## Common Mistakes

- **Skipping ignore verification** — worktree contents get tracked, pollute git status
- **Assuming directory location** — follow priority: existing > AGENTS.md > ask
- **Proceeding with failing tests** — can't distinguish new bugs from pre-existing issues

## Integration

Use before executing any implementation plan. Pairs with `finishing-a-development-branch` for cleanup after work is complete.
