---
name: requesting-code-review
description: Use when completing tasks, implementing major features, or before merging to verify work meets requirements
---

# Requesting Code Review

Dispatch the @reviewer agent (or a fresh session) to catch issues before they cascade. The reviewer gets precisely crafted context — not the implementation session's history — to keep focus on the work product.

**Core principle:** Review early, review often.

## When to Request Review

**Mandatory:**
- After completing a major feature
- Before merge to main

**Optional but valuable:**
- When stuck (fresh perspective)
- Before refactoring (baseline check)
- After fixing a complex bug

## How to Request

**1. Get git SHAs:**
```bash
BASE_SHA=$(git rev-parse origin/main)
HEAD_SHA=$(git rev-parse HEAD)
```

**2. Invoke the reviewer:**

In OpenCode, use `@reviewer` agent with this context:

```markdown
Please review the changes from $BASE_SHA to $HEAD_SHA.

## What was implemented
[1-3 sentence description of the feature/fix]

## Plan or requirements
[Reference to REQUIREMENTS.md, plan doc, or paste the relevant section]

## Diff
[paste: git diff $BASE_SHA $HEAD_SHA]

## Focus areas
[Any specific concerns or areas to pay attention to]
```

See `code-reviewer.md` in this directory for the full review checklist to give the reviewer.

**3. Act on feedback:**
- Fix Critical issues immediately
- Fix Important issues before proceeding
- Note Minor issues for later
- Push back with technical reasoning if reviewer is wrong

## Integration with Workflows

**Implementation tasks:**
- Review after completing each major task
- Catch issues before they compound

**Before merge:**
- Review the entire diff against requirements

## Red Flags

**Never:**
- Skip review because "it's simple"
- Ignore Critical issues
- Proceed with unfixed Important issues
