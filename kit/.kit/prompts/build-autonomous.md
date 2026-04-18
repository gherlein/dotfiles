---
description: Full autonomous design-build-test-review cycle
---
Complete autonomous build: $@

## Phases

1. **Understand**: Read relevant source files. Summarize the codebase structure. Check for PROJECT.md, REQUIREMENTS.md, and docs/DESIGN.md.
2. **Design**: Present the approach. Do NOT implement until the design is sound.
3. **Implement**: Write code test-first. Run tests after each file. Implement ONE phase at a time.
4. **Verify**: Run `make test` or `go test -race ./...` and `go vet ./...`
5. **Review**: Self-review checklist:
   - Error handling complete?
   - Edge cases covered?
   - No magic numbers?
   - Names meaningful and unabbreviated?
   - No secrets or credentials in code?
   - Comments explain WHY, not WHAT?
   - .gitignore present and correct?
6. **Commit**: Present-tense verb, 60-120 chars, single line, period at end. One logical change.

## Rules

- There is no time pressure. Take unlimited steps.
- Never simplify to save effort: follow the spec.
- Never defer complexity: if unsure, stop and ask.
- Tests are never skipped or stubbed.
- After all phases complete, run the entire test suite end-to-end.
- Run the build (`make build`).
- If anything fails, iterate: fix, re-run, repeat until everything passes.
