---
description: Safe incremental refactoring with continuous test verification
---
Refactor: $@

## Process

1. **Baseline**: Run `make test` to confirm all tests pass before touching anything.
2. **Identify**: List the specific code smells or structural issues to address.
3. **Plan**: Break the refactor into small, independently-testable steps.
4. **Execute**: For each step:
   - Make ONE structural change
   - Run tests immediately
   - If tests fail, revert and try a smaller step
5. **Verify**: Run the full test suite after all steps complete.

## Rules

- Never change behavior during a refactor. Tests must pass at every step.
- Follow existing patterns unless this IS the refactor to change them.
- No new features, no bug fixes: pure structural improvement only.
- Extract duplicated code into shared packages (DRY).
- Names must be meaningful and unabbreviated after refactoring.
- If tests are missing for the code being refactored, write them FIRST.
