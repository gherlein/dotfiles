---
description: "Stage changes and write a commit message following project conventions."
---

1. Run `git diff --staged` to see staged changes. If nothing is staged, run `git diff HEAD` to review all changes, then stage relevant files explicitly by name (not `git add -A`).
2. Analyze the changes and write a commit message:
   - Present-tense verb, 60–120 chars, single line, end with period
   - No praise adjectives, no Claude attribution
   - If fixing a compiler or linter error, prefix with `fixup!`
3. Echo the full `git commit -m "..."` command and wait for user confirmation before running it.
