---
name: refactoring
description: Safe incremental refactoring with continuous test verification, code smell detection, and Go/frontend/distributed-specific checks
---

# Refactoring (Gardener Pattern)

Safe, incremental code improvement while maintaining behavior.

## Core Principle

Hippocratic oath: Never change external behavior.
Cycle: run tests -> make one atomic change -> run tests -> repeat.

## Process

1. **Analyze** the target code -- never start without full understanding
2. **Present plan** and wait for approval before any changes
3. **Execute** incrementally with test verification at each step
4. **Never mix** refactoring and feature additions in a single commit

## Code Smells to Hunt

- DRY violations (duplicated code in 2+ places)
- Functions doing too many things
- God packages/services with too many responsibilities
- Excessive comments explaining "what" instead of "why"
- Magic numbers and hardcoded strings
- Dead code (unused functions, unreachable branches)
- Stale TODO/FIXME comments

## Actions

- **3+ hardcoded values** -> extract ALL to constants/config
- **Duplicated code in 2+ places** -> extract common package/function
- **Stale TODOs** -> delete or fix trivial ones, create issues for complex ones
- **Dead code** -> verify with static analysis (`deadcode`, `unused`), then remove
- **Dependencies** -> update one at a time, read changelog, run full tests

## Go-Specific

- Run `golangci-lint run` after each change
- Run `go test -race ./...` to catch data races
- Check that interfaces remain minimal (don't add methods you don't need)
- Verify exported API surface hasn't changed unintentionally
- Use `go vet` for correctness checks

## Frontend-Specific

- Run `npm test` and `npm run lint` after each change
- Check bundle size impact
- Verify no regressions in accessibility

## Distributed Systems

- Verify API contracts haven't changed (breaking change detection)
- Run contract tests between affected services
- Check k8s manifests are still consistent
- Verify health checks and readiness probes still work
