# Review Safety Checks by Domain

Supplementary reference for `engineering-principles`. The code-review *process* now
lives in Claude's `/code-review` and `/security-review` commands and
`superpowers:requesting-code-review` (dispatch a fresh-context reviewer subagent
against the work product, not the session history). This file preserves the
per-target correctness-and-safety checklist that was unique to the retired
`code-review` skill.

## Correctness & Safety by Domain

| Domain | Check |
|--------|-------|
| **Go** | Error handling complete, no ignored errors, goroutine lifecycle managed, race-free (`go test -race ./...`) |
| **Web** | XSS prevention, CSRF protection, input sanitization |
| **Distributed** | Idempotent operations, graceful degradation, timeout propagation |
| **Embedded** | Resource bounds, interrupt safety, power state awareness |

## Cross-cutting dimensions

Beyond the domain safety checks above, a review should still confirm:

- **Architecture** -- change conforms to project architecture; service/package
  boundaries respected; distributed concerns handled (idempotency, retries, timeouts).
- **Quality** -- self-explanatory; style matches surrounding code; minimal (nothing
  unneeded); KISS.
- **Maintainability** -- intent clear; comments/docs in sync; observability adequate.

## PR description template

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
