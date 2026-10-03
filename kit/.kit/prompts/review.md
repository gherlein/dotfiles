---
description: Four-category code review for architecture, quality, maintainability, correctness
---
Review the following for bugs, security issues, and code quality: $@

## Architecture
- [ ] Follows existing patterns in the codebase
- [ ] Interfaces are small and composable
- [ ] Functions do one thing well
- [ ] No unnecessary abstractions

## Quality
- [ ] Error handling: all errors checked and wrapped with context
- [ ] No magic numbers (named constants used)
- [ ] Names meaningful and unabbreviated
- [ ] Comments explain WHY, not WHAT
- [ ] No commented-out code

## Security
- [ ] Input validation at boundaries
- [ ] No SQL injection (parameterized queries only)
- [ ] No hardcoded secrets or credentials
- [ ] HTTPS for all external calls
- [ ] No silenced warnings without documented rationale

## Correctness
- [ ] Tests cover the happy path and at least one error path
- [ ] Edge cases handled
- [ ] No dead code or unused imports
- [ ] No race conditions (Go: run with -race)

Report findings as: CRITICAL / HIGH / WARNING / SUGGESTION
