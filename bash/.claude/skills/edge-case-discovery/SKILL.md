---
name: edge-case-discovery
description: Two-step systematic discovery of missing edge cases with checklists for Go, web, embedded RP2040, and K8s
---

# Edge Case Discovery

Two-step pattern to systematically find gaps in code coverage.

## Step 1: Discover Existing Edge Cases

```
How does [function/endpoint] work? What edge cases exist in the current
implementation? What special handling exists for [relevant concern]?
Search for related tests and analyze what they cover.
```

This loads concrete constraints into context.

## Step 2: Identify Gaps

```
Based on the implementation you found, what edge cases are NOT covered?
What happens with:
- Nil or invalid inputs
- [domain-specific edge case 1]
- [domain-specific edge case 2]
- Concurrent access
- Resource exhaustion
```

## Universal Edge Categories

| Category | Check |
|----------|-------|
| Boundary values | min, max, min-1, max+1 for numeric inputs |
| Nil/empty | nil pointers, empty strings, empty slices, zero values |
| Error propagation | When dependency fails, what does caller see? |
| Concurrency | Race conditions under simultaneous access |
| Temporal | Timing or ordering variations, clock skew |

## Go-Specific

| Category | Check |
|----------|-------|
| Goroutine | Leak? Panic in goroutine? Context cancellation? |
| Channel | Deadlock? Closed channel send? Unbuffered blocking? |
| Interface | Nil interface vs nil concrete type? |
| Slice | Nil vs empty slice? Shared backing array? |

## Web Frontend

| Category | Check |
|----------|-------|
| Input | XSS payload, Unicode, RTL text, extremely long strings |
| Network | Offline, slow connection, partial response, CORS error |
| State | Stale cache, race between user actions, browser back button |

## Embedded (RP2040)

| Category | Check |
|----------|-------|
| Memory | Stack overflow, heap exhaustion, alignment |
| Hardware | Device not present, timeout, noise on bus, power brownout |
| Interrupt | Nested interrupt, interrupt during critical section |
| Timing | Clock drift, watchdog timeout, debounce |

## Distributed/K8s

| Category | Check |
|----------|-------|
| Network | Partition, DNS failure, TLS expiry, connection pool exhaustion |
| Ordering | Out-of-order messages, duplicate delivery, split brain |
| Scaling | Cold start, thundering herd, resource limits hit |
| State | Stale cache, inconsistent replicas, failed migration |
