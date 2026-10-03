---
name: go-performance
description: Go garbage collection optimization, allocation reduction, profiling with pprof, and memory management techniques
---

# Go Performance and GC Optimization

## Reduce Allocation Pressure

- Use `sync.Pool` for frequently allocated/freed objects
- Pre-allocate slices with `make([]T, 0, capacity)` and maps with `make(map[K]V, size)`
- Use arrays when size is known at compile time
- Avoid unnecessary string conversions (`[]byte` <-> `string`)
- Use `strings.Builder` for string concatenation

## Reduce Pointer-Heavy Structures

- Prefer value types over pointers where practical (fewer GC roots to scan)
- Use indices into slices instead of pointer-based linked structures
- Arena-style allocation: pre-allocate a large slice and sub-slice from it

## Control GC Directly

- `debug.SetGCPercent(percent)` -- higher values reduce GC frequency (default 100)
- `debug.SetMemoryLimit(bytes)` -- soft memory limit (Go 1.19+), use with `SetGCPercent(-1)` for memory-bounded workloads

## Off-Heap / Manual Memory Management

For extreme cases only:
- mmap for memory-mapped files
- cgo for C-managed memory
- Experimental arena package (Go 1.20+)

## Profiling and Diagnostics

- `runtime.ReadMemStats(&m)` for quick memory snapshot
- `go tool pprof` for heap and CPU profiles
- `GODEBUG=gctrace=1` for GC trace logging
- Escape analysis: `go build -gcflags='-m'` to see what escapes to heap
- Benchmark with `testing.B` and compare allocations with `-benchmem`
