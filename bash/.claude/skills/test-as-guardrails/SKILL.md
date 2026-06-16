---
name: test-as-guardrails
description: Three-context testing workflow preventing specification gaming, with edge case categories for Go, web, embedded, and distributed systems
---

# Tests as Guardrails

Tests are living documentation that agents read to understand intent.

## Three-Context Workflow (prevents specification gaming)

**Context A:** Write implementation code
- Research existing patterns, plan, execute

**Context B (FRESH):** Write tests
- Agent has no memory of writing the implementation
- Tests derive independently from requirements
- Discovers edge cases the implementation may have missed

**Context C (FRESH):** Triage failures
- Objective analysis without defending code or tests
- Determine: bug in code or wrong test?

## Go Testing Patterns

- Use table-driven tests with `t.Run()` subtests
- Test at package boundaries with real implementations
- Mock ONLY external systems (databases, HTTP APIs, hardware)
- Use `testify/assert` or stdlib for assertions
- `t.Helper()` for test utility functions
- `t.Parallel()` for independent tests
- `_test.go` files in the same package for white-box, `_test` package for black-box
- Test error paths explicitly: network failures, timeouts, malformed input

## Web Frontend Testing

- Unit tests for utility functions and hooks
- Component tests for UI behavior
- Integration tests for user flows
- Mock API responses, not internal components

## Embedded Testing

- Test business logic on host (separate from hardware access)
- Hardware abstraction layers enable host-side testing
- Integration tests on real hardware via serial/UART validation

## Distributed System Testing

- Test each service independently with mocked dependencies
- Integration tests with docker-compose for multi-service flows
- Chaos/fault injection for resilience (network partitions, pod eviction)
- Contract tests between services (producer/consumer)

## Smoke Test Suite

Build a sub-30-second smoke suite covering:
- Core API endpoints return expected status codes
- Database connectivity
- Inter-service communication
- Critical business logic paths

Run after every task: `go test ./... -short`

## Edge Case Categories

| Category | Check |
|----------|-------|
| Boundary | min, max, min-1, max+1 for numeric inputs |
| Nil/empty | nil pointers, empty strings, empty slices |
| Error propagation | When dependency fails, what does caller see? |
| Concurrency | Race conditions under `-race` flag |
| Network | Timeout, DNS failure, connection refused, partial response |
| Resource | Memory pressure, disk full, connection pool exhaustion |

## Testing Discipline

- Test names should not include the word "test"
- Test assertions should be strict -- prefer `deep.equal` over `include` or loose matching
- Mocking policy: use mocking as a last resort
  - Prefer in-memory fakes over database mocks
  - Mock smaller APIs rather than larger ones they delegate to
  - Prefer record/replay network traffic frameworks over hand-written mocks
  - Do not mock your own code
- Use "fake" or "example" when not actually replacing behavior via a mocking framework
- Build tests at every level possible (unit and functional)
- NEVER skip tests; a failing test is a failure that must be fixed
- When implementing in phases, never move to the next phase until all current tests pass
