---
name: three-experts
description: Multi-perspective analysis with three domain experts for complex architecture and design decisions
disable-model-invocation: true
---

# Three Experts Method

Use for complex design decisions, architecture choices, or multi-perspective analysis.

## When to Use

- Architectural decisions (microservice boundaries, data flow between edge and cloud)
- Design trade-offs with no obvious answer (embedded vs cloud processing split)
- Evaluating approaches to distributed system problems
- Security review of API surfaces or inter-service communication

## Prompt Template

```
I need three senior engineers with different expertise to analyze this problem:

<problem>
[Describe the problem, requirements, constraints, and what you're trying to achieve]
</problem>

<current_approach>
[Optional: your current approach or implementation]
</current_approach>

Expert 1: **Practical Implementer** - working solutions, maintainability, proven patterns
Expert 2: **Systems Architect** - scalability, performance, long-term evolution
Expert 3: **Critical Reviewer** - potential issues, edge cases, alternative approaches

Each expert should:
1. Analyze from their unique perspective
2. Provide specific recommendations with reasoning
3. Address concerns or trade-offs

Then collaborate on a unified recommendation with:
- Clear recommended solution
- Key implementation considerations
- Trade-offs and compromises
- Next steps
```

## Adaptation for Multi-Tier Systems

Replace experts with domain-specific roles when needed:
- **Embedded Systems Expert** - resource constraints, power, hardware I/O, real-time behavior
- **Distributed Systems Expert** - consistency, partition tolerance, eventual consistency, k8s patterns
- **Platform/DevOps Expert** - deployment, observability, scaling, CI/CD pipelines
