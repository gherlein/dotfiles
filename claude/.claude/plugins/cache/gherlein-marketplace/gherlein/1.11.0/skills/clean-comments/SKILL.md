---
name: clean-comments
description: "Remove obvious, redundant, or process-narrating comments from code, following standard WHY-not-WHAT comment conventions. Triggers on: clean up comments, remove redundant or obvious comments, strip WHAT-comments, delete commented-out code, comment cleanup before commit."
---

# Clean Comments

Remove obvious and redundant comments from code. Can be invoked as:
- `/clean-comments` -- clean comments in uncommitted changes only
- `/clean-comments all` -- clean comments across the entire codebase

## What to Remove

- Commented-out code
- Comments describing the change process (past-tense verbs: "added", "removed", "changed")
- Comments about version differences ("this code now handles...")
- Comments that restate what the code obviously does (e.g., `// increment counter` above `counter++`)
- Obvious comments near self-explanatory method/function names

## What to Keep

- TODO comments
- Linter/formatter suppression comments (e.g., `// prettier-ignore`, `//nolint:...`)
- Comments that would leave a scope empty if removed (empty catch, empty else)
- Comments explaining WHY something is done a certain way
- License headers

## Process

1. If `$ARGUMENTS` is "all", scan all source files; otherwise scan only uncommitted changes (`git diff --name-only`)
2. For each file, identify comments matching the removal criteria
3. Move any end-of-line comments above the code they describe
4. Remove qualifying comments
5. Verify the file still compiles/parses correctly
