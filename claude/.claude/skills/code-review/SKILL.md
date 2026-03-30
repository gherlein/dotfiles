---
name: code-review
description: Four-category code review framework covering architecture, quality, maintainability, and correctness with domain-specific safety checks
---

# Code Review

Run reviews in a FRESH context (not the same session where code was written).

## Four-Category Framework

### 1. Architecture & Design
- Does the change conform to project architecture?
- Are service/package boundaries respected?
- Does the change align with its stated intent?
- Are distributed system concerns handled (idempotency, retries, timeouts)?

### 2. Code Quality
- Self-explanatory and readable?
- Style matches surrounding code (gofmt, eslint)?
- Changes are minimal -- nothing unneeded?
- Follows KISS principle?

### 3. Maintainability
- Intent is clear and unambiguous?
- Comments and docs in sync with code?
- Future developers (human or AI) can understand the change?
- Logging and observability adequate?

### 4. Correctness & Safety
- **Go:** Error handling complete, no ignored errors, goroutine lifecycle managed, race-free
- **Web:** XSS prevention, CSRF protection, input sanitization
- **Distributed:** Idempotent operations, graceful degradation, timeout propagation
- **Embedded:** Resource bounds, interrupt safety, power state awareness

## Review Workflow

1. Review critically in fresh context
2. Fix issues found
3. Run tests (`go test -race ./...`, `npm test`)
4. Run linters (`golangci-lint run`, `eslint`)
5. Re-review in another fresh context
6. Stop when: tests pass AND remaining feedback is trivial

## PR Description Template

```markdown
## Summary
[1-3 bullet points of what changed and why]

## Changes
[List of specific changes with file:line references]

## Testing
[How this was tested, what commands were run]

## Deployment Notes
[Any k8s config changes, migrations, feature flags, rollback plan]
```
