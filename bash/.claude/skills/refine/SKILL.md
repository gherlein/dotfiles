---
name: refine
description: Progressive solution improvement through 3 rounds of critical analysis for algorithms, performance, and system design
disable-model-invocation: true
---

# Iterative Refinement Method

Progressively refine solutions through multiple rounds of critical analysis.

## When to Use

- Complex algorithms or distributed system designs
- Performance-critical paths (hot loops, high-throughput APIs)
- When the first solution is unlikely to be optimal

## Process

### 1. Initial Solution
Provide a concise working solution focusing on core requirements.

### 2. Analysis Rounds (3 iterations)
For each round:

**Critical Analysis:**
- Strengths: 2-3 key points that work well
- Weaknesses: Edge cases and limitations (2-3 points)
- Optimizations: 1-2 specific improvements

**Solution Refinement:**
- Implement changes addressing the most critical weaknesses
- Focus only on substantial improvements
- Note what changed and why

### 3. Final Solution
- Brief summary of major improvements (2-3 sentences)
- Remaining considerations

Label each section: "INITIAL SOLUTION", "ROUND 1", "ROUND 2", "ROUND 3", "FINAL SOLUTION".

## Focus Areas by Domain

**Go services:** Goroutine leaks, channel deadlocks, context cancellation, error wrapping
**Web frontends:** Bundle size, render performance, accessibility, state management
**Embedded (RP2040):** Memory footprint, power consumption, interrupt safety, timing
**Distributed/K8s:** Network partitions, retry storms, backpressure, graceful degradation
