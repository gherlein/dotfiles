---
description: Systematic discovery of missing edge cases
---
Find missing edge cases for: $@

## Checklist by Domain

### General
- [ ] Empty/nil/zero inputs
- [ ] Maximum size inputs
- [ ] Unicode and special characters
- [ ] Concurrent access / race conditions
- [ ] Timeout and cancellation
- [ ] Resource exhaustion (memory, file descriptors, connections)

### Go-specific
- [ ] Nil pointer dereference
- [ ] Slice out-of-bounds
- [ ] Map concurrent read/write
- [ ] Context cancellation propagation
- [ ] Goroutine leaks
- [ ] Channel deadlocks

### Web-specific
- [ ] XSS via user input
- [ ] CSRF protection
- [ ] Authentication bypass
- [ ] Rate limiting
- [ ] Large payload handling
- [ ] Malformed JSON/form data

### Embedded (RP2040)
- [ ] Buffer overflow
- [ ] Integer overflow
- [ ] Watchdog timeout
- [ ] Power loss during write
- [ ] Hardware register race conditions

### Kubernetes
- [ ] Pod restart mid-operation
- [ ] Network partition
- [ ] Resource limit exceeded
- [ ] Graceful shutdown signal handling
- [ ] Config map / secret rotation

## Output

For each discovered edge case: describe the scenario, expected behavior, and a test to cover it.
