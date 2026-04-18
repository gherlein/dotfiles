---
description: Systematic evidence-first debugging with 5 Whys root cause analysis
---
Debug this issue: $@

## Iron Law

1. **Reproduce**: Create a minimal reproduction FIRST. No guessing.
2. **Hypothesize**: Form exactly ONE hypothesis about the root cause.
3. **Test**: Gather evidence that confirms OR refutes the hypothesis.
4. **Analyze**: If refuted, form the next hypothesis. If confirmed, apply 5 Whys to find the root cause.
5. **Fix**: Only after root cause is confirmed with evidence.
6. **Verify**: Write a test that would have caught the failure.

## Rules

- Never guess at fixes. No fix is accepted without a reproduction.
- Record each hypothesis and its outcome.
- Check error messages, logs, stack traces before forming hypotheses.
- For Go: use `go test -race`, `go vet`, and `dlv` as appropriate.
- For frontend: check browser console, network tab, component state.
- After fixing, run the full test suite to confirm no regressions.
