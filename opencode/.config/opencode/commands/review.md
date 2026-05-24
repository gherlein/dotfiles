---
description: "Run a fresh code review on uncommitted changes or a specified range of commits."
agent: reviewer
---

1. Get the diff to review:
   - If no arguments: `git diff HEAD` (uncommitted changes)
   - If a SHA is provided: `git diff $ARGUMENTS HEAD`
   - If "staged": `git diff --cached`

2. Load the `requesting-code-review` skill for the review checklist.

3. Apply the four-category framework:
   - Architecture & Design
   - Code Quality
   - Maintainability
   - Correctness & Safety (domain-specific)

4. Report findings organized by severity: Critical, Important, Minor.

5. Do NOT make edits — report findings only.
