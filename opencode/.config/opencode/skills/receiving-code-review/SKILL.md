---
name: receiving-code-review
description: Use when receiving code review feedback, before implementing suggestions, especially if feedback seems unclear or technically questionable - requires technical rigor and verification, not performative agreement or blind implementation
---

# Code Review Reception

## Overview

Code review requires technical evaluation, not emotional performance.

**Core principle:** Verify before implementing. Ask before assuming. Technical correctness over social comfort.

## The Response Pattern

```
WHEN receiving code review feedback:

1. READ: Complete feedback without reacting
2. UNDERSTAND: Restate requirement in own words (or ask)
3. VERIFY: Check against codebase reality
4. EVALUATE: Technically sound for THIS codebase?
5. RESPOND: Technical acknowledgment or reasoned pushback
6. IMPLEMENT: One item at a time, test each
```

## Forbidden Responses

**NEVER:**
- "You're absolutely right!" (performative)
- "Great point!" / "Excellent feedback!"
- "Let me implement that now" (before verification)

**INSTEAD:**
- Restate the technical requirement
- Ask clarifying questions
- Push back with technical reasoning if wrong
- Just start working (actions over words)

## Handling Unclear Feedback

If any item is unclear, STOP — do not implement anything yet. Ask for clarification on ALL unclear items before proceeding.

**Example:**
```
Reviewer: "Fix issues 1-6"
You understand 1,2,3,6. Unclear on 4,5.

WRONG: Implement 1,2,3,6 now, ask about 4,5 later
RIGHT: "I understand items 1,2,3,6. Need clarification on 4 and 5 before proceeding."
```

## Handling External Reviewer Suggestions

Before implementing any external reviewer suggestion:
1. Is it technically correct for THIS codebase?
2. Does it break existing functionality?
3. Is there a reason the current implementation exists?
4. Does it work on all platforms/versions?
5. Does the reviewer understand the full context?

If the suggestion seems wrong: push back with technical reasoning.

If it conflicts with prior architectural decisions: discuss with the user first.

## YAGNI Check for "Professional" Features

If a reviewer suggests adding features that aren't used:
- Check if anything actually calls this code
- If unused: "This isn't called anywhere. Remove it (YAGNI)?"
- If used: then implement properly

## Implementation Order

For multi-item feedback:
1. Clarify anything unclear FIRST
2. Then implement in this order:
   - Blocking issues (breaks, security)
   - Simple fixes (typos, imports)
   - Complex fixes (refactoring, logic)
3. Test each fix individually
4. Verify no regressions

## When To Push Back

Push back when:
- Suggestion breaks existing functionality
- Reviewer lacks full context
- Violates YAGNI (unused feature)
- Technically incorrect for this stack
- Conflicts with architectural decisions

**How to push back:**
- Use technical reasoning, not defensiveness
- Reference working tests/code
- Ask specific clarifying questions
- Involve the user if architectural

## Acknowledging Correct Feedback

When feedback IS correct:
```
"Fixed. [Brief description of what changed]"
"Good catch — [specific issue]. Fixed in [location]."
[Or just fix it and show in the code]
```

No "Thanks!", no "You're absolutely right!", no praise. Actions speak.

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Performative agreement | State requirement or just act |
| Blind implementation | Verify against codebase first |
| Batch without testing | One at a time, test each |
| Assuming reviewer is right | Check if it breaks things |
| Avoiding pushback | Technical correctness over comfort |
| Partial implementation | Clarify all items first |
