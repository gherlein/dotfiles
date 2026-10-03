---
description: Enforce test-first development with red-green-refactor
---
Implement using TDD: $@

## Order (strict)

1. Write the test FIRST: it must fail (RED)
2. Write the minimum code to pass the test (GREEN)
3. Refactor if needed: tests must still pass (REFACTOR)
4. Repeat for the next behavior

## Rules

- Do not write implementation code before its test exists.
- Run `make test` or `go test -race ./...` after each red-green-refactor cycle.
- Every public function needs a test.
- Tests must cover the happy path AND at least one error path.
- No mocks or stubs unless the user explicitly approves.
- Test names describe the behavior being tested, not the function name.
