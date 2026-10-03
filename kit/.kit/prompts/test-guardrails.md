---
description: Three-context testing workflow preventing specification gaming
---
Write tests as guardrails for: $@

## Three Contexts

1. **Specification tests**: Test what the code SHOULD do per requirements.
2. **Boundary tests**: Test at the edges of valid input (empty, max, zero, nil).
3. **Adversarial tests**: Test what a malicious or careless caller might do.

## Process

1. Read the requirements/spec for the code under test.
2. Write specification tests FIRST (happy path from the spec).
3. Write boundary tests (edge cases from the edge-cases checklist).
4. Write adversarial tests (injection, overflow, race conditions).
5. Run all tests. They should all pass if the implementation is correct.

## Rules

- Tests must be independent and order-agnostic.
- Test names describe the scenario and expected outcome.
- No mocks unless the user explicitly approves.
- No skipped or stubbed tests.
- Each test asserts ONE behavior.
- If a test reveals a bug, that is a finding: do not silently fix the code.
