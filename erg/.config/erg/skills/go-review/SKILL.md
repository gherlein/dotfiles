---
name: go-review
description: Go-specific code-review checklist
---
When reviewing Go code, check specifically:

- Every returned error is handled; none are silently ignored (a bare `_ =` on an error is suspect).
- No goroutine leaks: every spawned goroutine has a clear exit path and is bounded by a context or
  joined before the state it touches is torn down.
- Slices and maps shared across goroutines are protected; look for data races.
- Deferred cleanup (Close, Unlock, cancel) is present on every path, including early returns.
- Errors are wrapped with context (`fmt.Errorf("...: %w", err)`), not swallowed or double-logged.
- Interfaces are small and defined at the consumer, not the producer.
- Inputs at boundaries are validated; preconditions fail loudly rather than being papered over.
