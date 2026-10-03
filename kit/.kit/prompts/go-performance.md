---
description: Go garbage collection optimization, allocation reduction, and profiling
---
Optimize Go performance for: $@

## Analysis Process

1. **Profile first**: Use `go test -bench=. -benchmem` and `go tool pprof` before changing anything.
2. **Identify hotspots**: Focus on the top allocators and CPU consumers.
3. **Optimize allocations**:
   - Pre-allocate slices with known capacity
   - Use sync.Pool for frequently allocated objects
   - Avoid string concatenation in loops (use strings.Builder)
   - Prefer stack allocation (small structs, avoid pointers when unnecessary)
4. **Reduce GC pressure**:
   - Minimize heap allocations
   - Use value receivers for small structs
   - Avoid interface{} where concrete types work
5. **Benchmark after**: Compare before/after with `benchstat`.

## Rules

- Never optimize without profiling data.
- Readability trumps micro-optimization unless profiling proves it matters.
- Document WHY a non-obvious optimization exists.
- Run `go test -race ./...` after every change.
