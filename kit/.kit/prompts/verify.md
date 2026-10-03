---
description: Verify work is complete before claiming success
---
Verify the implementation of: $@

## Verification Steps

1. **Build**: Run `make build`. Must succeed with zero errors.
2. **Test**: Run `make test` or `go test -race ./...`. All tests must pass.
3. **Lint**: Run `go vet ./...` and any configured linters.
4. **Diff**: Run `git diff` and review every changed line.
5. **Requirements check**: Compare implementation against REQUIREMENTS.md (if it exists).
6. **Security scan**: Check for hardcoded secrets, SQL injection, input validation gaps.
7. **Edge cases**: Verify at least one error path is tested per public function.

## Rules

- Do NOT claim work is complete until ALL verification steps pass.
- If any step fails, fix the issue and re-run ALL steps.
- Evidence before assertions: show the passing output, do not just say "tests pass".
