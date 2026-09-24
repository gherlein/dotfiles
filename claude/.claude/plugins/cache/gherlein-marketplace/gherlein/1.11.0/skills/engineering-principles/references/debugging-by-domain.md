# Debugging by Domain

Supplementary reference for `engineering-principles`. The debugging *process* now
lives in `superpowers:systematic-debugging` (build a reproduction, instrument,
investigate, verify with evidence). This file preserves the multi-target tooling
and root-cause discipline that were unique to the retired `evidence-based-debugging`
skill.

## Never accept a fix without proof

Reproduce the failure with concrete evidence, apply the fix, then re-run the
reproduction and confirm resolution. A fix that was never observed to fail first,
or never re-run after, is not verified.

## Root Cause Analysis (5 Whys)

Chase the causal chain past the first plausible answer:

- Why did the request fail? -> Context deadline exceeded
- Why did the deadline expire? -> Downstream service took 30s
- Why did downstream take 30s? -> Database connection pool exhausted
- Why was the pool exhausted? -> Goroutine leak holding connections
- Why the goroutine leak? -> **Root cause: missing context cancellation in retry loop**

Report findings with evidence: file paths and line numbers (`pkg/service/handler.go:245`),
actual values from the code, specific function names, exact error messages.

## Debugging Tools by Domain

| Domain | Where to look |
|--------|---------------|
| **Go** | Goroutine dumps (`runtime/pprof`), channel states, context propagation |
| **Web frontend** | Browser devtools network/console, React/Vue devtools, lighthouse |
| **Embedded (RP2040)** | Serial/UART logs, logic analyzer traces, register dumps |
| **K8s / distributed** | `kubectl logs`, distributed traces (Jaeger/Zipkin), pod events, network policies |
| **Cross-tier** | Trace one request ID from frontend -> API -> service -> embedded device and back |
