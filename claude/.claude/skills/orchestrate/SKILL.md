---
name: orchestrate
description: Maestro pattern for decomposing complex multi-step projects into atomic tasks with sub-agent delegation
disable-model-invocation: true
---

# Task Orchestration (Maestro Pattern)

Use for complex multi-step projects spanning multiple services or tiers.

## When to Use

- "Add a new sensor pipeline from RP2040 through to the dashboard"
- "Refactor the authentication system across all services"
- "Implement a new API with frontend, backend, and k8s deployment"

## Process

### 1. Decompose
Break the request into atomic, verifiable steps. First step is always analysis/research.

### 2. Proportionality Check
If the task can be done in one step, just do it. Don't create a 10-step plan for a simple task.

### 3. Delegate by Expertise Type
- Need structure/long-term vision -> Architecture analysis
- Need working code from a plan -> Implementation
- Need to break things / write tests -> Testing
- Need to simplify / remove -> Refactoring review
- Need deployment/infra -> K8s/DevOps focus

### 4. Synthesize
After each step, synthesize results into a unified whole before the next step.

### 5. Dynamic Adaptation
After EVERY step, re-evaluate: "Given what I just learned, is the remaining plan still optimal?"

## Sub-Agent Patterns

### Research Sub-Agent (read-only)
```
Objective: [what to investigate]
Problem Context: [background]
Files for review: [paths]
Key questions: [specific questions]

STRICT: Do NOT edit files. Analysis and report only.
```

### Implementation Sub-Agent (one file/module each)
```
Objective: [what to implement]
File(s) for modification: [exact paths]
Implementation steps: [step by step]

Provide: full diff + notes on changes
```

Rules:
- One agent per file. Never two agents on the same file.
- Prefer one agent creating a complete file over two agents (stubs + fill-in).

## Context Compression

When conversation gets long, compress before continuing:

1. **Current Work** - detailed description of active task
2. **Pending Tasks** - all outstanding work
3. **Key Technical Concepts** - technologies, conventions, decisions
4. **Relevant Files** - every file path, function name examined/modified
5. **Problem Solving** - problems solved and ongoing
6. **Previous Conversation** - high-level flow

Priority: Current Work > Pending Tasks > Recent Problems > Earlier Context
