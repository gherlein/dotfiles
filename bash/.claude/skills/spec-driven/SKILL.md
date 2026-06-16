---
name: spec-driven
description: Treat specs as authoritative source of truth; code implements specs and is regenerated when they diverge
disable-model-invocation: true
---

# Spec-Driven Development

Requirements, specifications, and designs are the most valuable project artifacts. Code is ephemeral -- it can be regenerated from specs. Specs are the authoritative source of truth. Never delete specs.

## Core Principle

Specs capture intent, constraints, and design rationale that cannot be recovered from code alone. Code is a disposable implementation of the spec. If the code and spec disagree, fix the code.

## Core Workflow

1. Start with: Architecture + Interfaces + State
2. Generate first implementation pass
3. Ask: "Is the architecture sound?"
   - YES -> fix the code (mechanical error)
   - NO -> fix the spec, then regenerate code from the updated spec
4. Each loop reveals what the spec missed -- update the spec
5. Converge when loop produces no new gaps
6. Keep the spec as the living, authoritative document; update it as the system evolves

## Spec Sections

**ARCHITECTURE:**
- Modules/services (single responsibility each)
- Boundaries (service boundaries, package boundaries, API contracts)
- Contracts (preconditions/postconditions, request/response schemas)
- Third-party assumptions (what external services guarantee)

**INTERFACES:**
- API endpoints (REST/gRPC), message queues, hardware protocols
- Input validation rules, rate limits
- Output formats, SLAs, error responses

**STATE:**
- Entities (persistent vs ephemeral vs cached)
- State model per entity (CRUD / event-sourced / state machine)
- Consistency requirements (strong vs eventual)
- Initialization order across distributed services
- Failure recovery and data reconciliation

**CONSTRAINTS:** (numbered for traceability)
- C-001: NEVER [action] - Verified By [test] - Stress [scenario]

**INVARIANTS:**
- I-001: [condition always true] - Manifested By [test approach]

**BEHAVIOR:**
- Given/When/Then at service boundaries
- Edge categories: boundary values, nil/empty, error propagation, concurrency, network partition

## Multi-Tier System Specs

- **Embedded -> Cloud:** Data flow direction, protocol (MQTT/HTTP/gRPC), offline buffering, reconnection
- **Service -> Service:** API contracts, retry policies, circuit breaker thresholds, timeout budgets
- **Frontend -> API:** Request schemas, auth flow, optimistic updates, error display
- **K8s deployment:** Resource limits, scaling policies, health checks, readiness gates

## Knowledge Hierarchy

- **Specs are primary** -> the authoritative record of requirements, architecture, constraints, and design decisions
- **Code implements specs** -> code is a derivative artifact that can be regenerated; specs cannot
- **WHY knowledge** -> lives in the spec as decision records (why we chose X over Y)
- **HOW knowledge** -> lives in code, but is always traceable back to spec requirements
- Constraint IDs appear in both spec and code comments: `// C-001: NEVER process duplicate event`
- When updating behavior, update the spec FIRST, then update the code to match
