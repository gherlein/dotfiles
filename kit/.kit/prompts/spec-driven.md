---
description: Specification-first development driven by requirements documents
---
Implement from specification: $@

## Process

1. **Read the spec**: Find and read REQUIREMENTS.md and docs/DESIGN.md. If neither exists, stop and ask.
2. **Inventory**: List every requirement. Number them for tracking.
3. **Plan**: Map each requirement to files/packages that need changes.
4. **Implement**: Address requirements in dependency order. After each requirement:
   - Write or update tests
   - Run tests
   - Check off the requirement
5. **Verify**: Cross-reference every requirement against the implementation. Flag gaps.

## Rules

- The spec is the source of truth. When code and spec disagree, fix the code.
- Never simplify or skip requirements to save effort.
- If a requirement is ambiguous, ask: do not interpret creatively.
- Update the spec if you discover a genuine issue (with user approval).
- Every requirement must have at least one test covering it.
