---
name: writing-plans
description: Use when you have a spec or requirements for a multi-step task, before touching code
---

# Writing Plans

## Overview

Write comprehensive implementation plans assuming the engineer has zero context for the codebase and questionable taste. Document everything they need to know: which files to touch for each task, code, testing, docs they might need to check, how to test it. Give them the whole plan as bite-sized tasks. DRY. YAGNI. TDD. Frequent commits.

**Announce at start:** "I'm using the writing-plans skill to create the implementation plan."

**Save plans to:** `docs/plans/YYYY-MM-DD-<feature-name>.md`

## Scope Check

If the spec covers multiple independent subsystems, suggest breaking this into separate plans — one per subsystem. Each plan should produce working, testable software on its own.

## File Structure

Before defining tasks, map out which files will be created or modified and what each one is responsible for.

- Design units with clear boundaries and well-defined interfaces
- Each file should have one clear responsibility
- Files that change together should live together — split by responsibility, not by technical layer
- In existing codebases, follow established patterns

## Bite-Sized Task Granularity

**Each step is one action (2-5 minutes):**
- "Write the failing test" — step
- "Run it to make sure it fails" — step
- "Implement the minimal code to make the test pass" — step
- "Run the tests and make sure they pass" — step
- "Commit" — step

## Plan Document Header

**Every plan MUST start with this header:**

```markdown
# [Feature Name] Implementation Plan

**Goal:** [One sentence describing what this builds]

**Architecture:** [2-3 sentences about approach]

**Tech Stack:** [Key technologies/libraries]

---
```

## Task Structure

````markdown
### Task N: [Component Name]

**Files:**
- Create: `exact/path/to/file.go`
- Modify: `exact/path/to/existing.go`
- Test: `exact/path/to/file_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestSpecificBehavior(t *testing.T) {
    result := Function(input)
    assert.Equal(t, expected, result)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./path/... -run TestSpecificBehavior -v`
Expected: FAIL with "function not defined"

- [ ] **Step 3: Write minimal implementation**

```go
func Function(input Type) Type {
    return expected
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./path/... -run TestSpecificBehavior -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add path/to/file.go path/to/file_test.go
git commit -m "feat: add specific feature."
```
````

## Remember
- Exact file paths always
- Complete code in plan (not "add validation")
- Exact commands with expected output
- DRY, YAGNI, TDD, frequent commits

## Plan Self-Review Checklist

After writing the complete plan:

1. Does each task produce independently testable, working software?
2. Are all file paths exact and specific (not vague)?
3. Does every task have a failing-test step before implementation?
4. Are commit messages specific and present-tense?
5. Is the scope minimal — nothing beyond the spec?
6. Does the plan reference the correct build command (`make test`, `go test`, etc.)?

If issues found: fix and re-apply until approved. If loop exceeds 3 iterations, ask the user for direction.

## Execution Handoff

After saving the plan:

**"Plan complete and saved to `docs/plans/<filename>.md`. Ready to execute?"**

Wait for the user's approval before proceeding to implementation.
