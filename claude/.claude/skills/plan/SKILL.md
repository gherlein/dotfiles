---
name: plan
description: Four-phase planning for non-trivial features spanning multiple packages, services, or tiers
disable-model-invocation: true
---

# Implementation Planning

Use for non-trivial features requiring multiple packages, services, or tiers.

## Four-Phase Approach

### Phase 1: Requirement Clarification
Ask targeted questions covering:
- Core functionality and features
- Which tiers are involved (embedded, SBC, cloud, frontend)
- Data models and relationships
- API contracts between services
- Performance and scaling constraints
- Edge cases and error handling
- Security considerations

### Phase 2: Specification
Create a specification as a persistent, authoritative document (specs outlive any given implementation):
1. **Summary**: Purpose and goals (1 paragraph)
2. **Functional Requirements**: Features, workflows, constraints
3. **Technical Specifications**: Architecture, data models, APIs, protocols
4. **Implementation Considerations**: Error handling, edge cases, security
5. **Testing Strategy**: Unit, integration, e2e, contract tests

Commit the spec alongside the code. Update the spec when requirements change -- always update the spec before changing the code.

### Phase 3: Task Decomposition
Break specification into incremental tasks:
- Each task: single responsibility, testable, builds on previous
- Include test requirements per task
- Note integration points between tasks and services

### Phase 4: Execution
For each task:
1. Implement the code
2. Write tests
3. Verify (build, test, lint)
4. Commit with conventional commit message

## Common Project Patterns

### New Go Microservice
1. Create service directory with standard layout (`cmd/`, `pkg/`, `internal/`)
2. Define API contracts (protobuf/OpenAPI)
3. Implement handlers and business logic
4. Add tests and Dockerfile
5. Create k8s manifests (deployment, service, configmap)
6. Add to CI/CD pipeline

### New Web Frontend Feature
1. Define component hierarchy and data flow
2. Create API types/interfaces matching backend contracts
3. Implement components with tests
4. Wire to API layer
5. Add e2e test for user flow

### New Embedded Feature (RP2040)
1. Define hardware interface and protocol
2. Implement driver/abstraction layer
3. Add business logic (testable on host)
4. Integration test on hardware
5. Define data contract with upstream service (SBC or cloud)

### Cross-Tier Feature (Embedded -> Cloud)
1. Define data model and protocol at each boundary
2. Implement bottom-up: device -> SBC gateway -> cloud service -> frontend
3. Test each tier independently, then integration test the full path
4. Add observability at each hop (trace IDs, structured logging)
