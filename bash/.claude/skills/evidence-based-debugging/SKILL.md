---
name: evidence-based-debugging
description: Closed-loop debugging workflow with 5 Whys root cause analysis, domain-specific tools for Go, web, embedded, and K8s
---

# Evidence-Based Debugging

Never accept fixes without reproducible proof they work.

## Closed-Loop Debugging Workflow

1. **BUILD** - Create reproducible environment (scripts, docker-compose, test harness)
2. **REPRODUCE** - Verify bug manifests consistently with concrete evidence
3. **PLACE** - Instrument code with diagnostic logging or tracing
4. **INVESTIGATE** - Correlate runtime behavior + codebase + known issues
5. **VERIFY** - Apply fix, re-run reproduction, confirm resolution

## Prompt Template

```
[paste error/log output here]

Analyze the error above.

INVESTIGATE:
1. Read relevant source files and trace the code path
2. Examine error messages, stack traces, and logs
3. Identify the specific failure location
4. Understand surrounding architecture and data flow

ANALYZE:
5. Compare expected vs actual behavior
6. Identify root cause
7. Check for related issues elsewhere

EXPLAIN with evidence:
- File paths and line numbers (pkg/service/handler.go:245)
- Actual values from code
- Specific function names
- Exact error messages

Then propose a fix.
```

## Root Cause Analysis (5 Whys)

- Why did the request fail? -> Context deadline exceeded
- Why did the deadline expire? -> Downstream service took 30s
- Why did downstream take 30s? -> Database connection pool exhausted
- Why was the pool exhausted? -> Goroutine leak holding connections
- Why the goroutine leak? -> **Root cause: missing context cancellation in retry loop**

## Domain-Specific Debugging

**Go:** Check goroutine dumps (`runtime/pprof`), channel states, context propagation
**Web frontend:** Browser devtools network/console, React/Vue devtools, lighthouse
**Embedded:** Serial/UART logs, logic analyzer traces, register dumps
**K8s/distributed:** `kubectl logs`, distributed traces (Jaeger/Zipkin), pod events, network policies
**Cross-tier:** Trace request ID from frontend -> API -> service -> embedded device and back
