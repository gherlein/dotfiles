---
name: reverse-engineer
description: 10-phase framework for systematic source code analysis, component inventory, coupling analysis, and architectural documentation
disable-model-invocation: true
---

# Source Code Reverse Engineering (10-Phase Framework)

## Phase 1: Reconnaissance

- Survey directory structure and identify system boundaries
- Create a system manifest: name, purpose, languages, frameworks, entry points

## Phase 2: Entry Point Analysis

- Trace from `main` (or equivalent entry point)
- Identify the initialization sequence
- Map the "spine" -- the critical path from input to output

## Phase 3: Component Inventory

For each module, create a Component Card:
- **Location**: file path(s)
- **Responsibility**: single-sentence purpose
- **Public Interface**: exported functions/types
- **Dependencies**: what it imports
- **Dependents**: what imports it
- **State**: what mutable state it holds
- **Side Effects**: I/O, network, disk, hardware

Build a dependency graph from the cards.

## Phase 4: Coupling Analysis

Identify 8 coupling types between components:
1. Direct import
2. Interface/contract
3. Data (shared structs/types)
4. Message (queues, channels, events)
5. Database (shared tables)
6. API (HTTP/gRPC calls)
7. File (shared filesystem paths)
8. Temporal (ordering dependencies)

## Phase 5: Design Pattern Recognition

Search for creational (factory, builder, singleton), structural (adapter, proxy, decorator), behavioral (observer, strategy, state machine), and architectural patterns (MVC, hexagonal, event-driven, CQRS).

## Phase 6: Behavioral Analysis

Extract sequence diagrams, state diagrams, and block diagrams using Mermaid.

## Phase 7: Dense Summary Production

Write agent-optimized summaries per component:
- **IDENTITY**: name, location, one-line purpose
- **INTERFACE**: public API surface
- **BEHAVIOR**: what it does under key scenarios
- **DEPENDENCIES**: what it needs
- **INVARIANTS**: conditions that must always hold
- **GOTCHAS**: non-obvious behavior, foot-guns

## Phase 8: Critique and Improvement

Flag anti-patterns: god classes, circular dependencies, leaky abstractions, distributed monolith, missing error handling, hardcoded config, dead code, SQL injection, missing health checks, missing observability.

## Phase 9: Context Window Management

- Never load the entire codebase at once
- Chunk by component/module
- Maintain a working memory structure of discoveries
- Delegate to sub-agents for large codebases; synthesize results

## Phase 10: Output Deliverables

Standard deliverable set:
1. Architecture document
2. Component catalog
3. Coupling matrix
4. Pattern inventory
5. Sequence diagrams
6. Data flow diagram
7. Critique report
8. Glossary
