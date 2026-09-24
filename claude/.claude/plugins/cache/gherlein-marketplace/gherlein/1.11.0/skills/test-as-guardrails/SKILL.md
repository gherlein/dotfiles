---
name: test-as-guardrails
description: "Three-context testing workflow that prevents specification gaming, with edge-case categories for Go, web, embedded, distributed. Triggers on: writing tests, are my tests meaningful, tests pass but behavior is wrong, prevent gaming the tests, test coverage for edge cases."
---

# Tests as Guardrails

Tests are living documentation that agents read to understand intent.

**Composes with `superpowers:test-driven-development`.** That skill owns the core
write-test-first loop (failing test -> implement -> Red-Green-Refactor). This skill
adds what TDD does not cover: the three-fresh-contexts workflow that defeats
specification gaming, the per-domain testing patterns, and the test-quality bar.
Use TDD for the loop; use this for whether the resulting tests are meaningful.
(The Superpowers plugin provides `test-driven-development`; `build-autonomous`
preflights that it is installed.)

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

To enumerate the cases your tests must cover, use the `edge-case-discovery`
skill -- it is the canonical source for edge-case categories (universal plus
per-domain checklists for Go, web, embedded RP2040, and distributed/K8s). Feed
its output into the tests written in Context B above.

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
