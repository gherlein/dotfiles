---
name: build-autonomous
description: Complete autonomous design-build-test cycle from requirements through final documentation
disable-model-invocation: true
---

# Autonomous Full-Cycle Implementation

Use when the user wants a complete hands-off implementation from design through delivery.

## When to Use

- User says "design and build this autonomously"
- User says "build-autonomous" or invokes this skill
- User provides requirements and wants minimal interaction until completion
- Complex features requiring full design-plan-implement-test-document cycle

## Complete Workflow

### Phase 0: Context Loading

Before assembling any agents:

1. Read `~/.claude/INDEX.md`
2. Identify the project's languages, frameworks, and domains from the requirements and any existing code
3. Read every relevant security rule file listed in INDEX.md for those languages and domains -- at minimum always read `~/.claude/security-rules/_core/owasp-2025.md`
4. Note which skills from INDEX.md apply to this project (e.g., `postgresql`, `rest-api-design`, `web-frontend`) -- invoke them as needed during design and implementation phases

### Phase 1: Sub-Agent Team Assembly

Create specialized sub-agents for parallel work:

1. **Design Agent** - Architecture and system design
2. **Test Planning Agent** - Test strategy and test plan creation
3. **Implementation Agent(s)** - Code implementation per module/service
4. **Review Agents** - Spec compliance, design, security reviews (post-implementation)

### Phase 2: Design and Planning

Run design and test planning agents in parallel:

**Design Agent Tasks:**
- Analyze requirements and constraints
- Create architecture (modules, boundaries, contracts, state model)
- Define interfaces (APIs, protocols, schemas)
- Document constraints and invariants
- Write to `docs/DESIGN.md`
- Update `PROJECT.md` if it exists with project-specific details

**Test Planning Agent Tasks:**
- Design test strategy (unit, integration, e2e)
- Define test phases aligned with implementation phases
- Specify test coverage targets
- Document edge cases and failure scenarios
- Write to `docs/TEST-PLAN.md`

**Update Configuration:**
- If domain-specific settings provided (e.g., "service health every 5 minutes", "7-day forecast"), update `CLAUDE.md` project instructions with these as requirements
- Document any service-level parameters, refresh intervals, or constraints

### Phase 3: Project Infrastructure Setup

Before implementation begins, ensure proper version control and file management:

**Git Repository Initialization:**
1. Check if `.git` directory exists
2. If NOT exists: run `git init`
3. Verify git is properly initialized

**Gitignore Configuration:**
1. Check if `.gitignore` exists
2. If exists: verify it contains mandatory entries (see below)
3. If NOT exists OR missing entries: create/update `.gitignore` with:
   - **Mandatory entries** (always include):
     - `.env`
     - `.envrc`
     - `*~` (emacs backups)
     - `bin/`
   - **Language-specific entries** (add based on project type):
     - **Go**: `vendor/`
     - **Node/TypeScript**: `node_modules/`, `dist/`
     - **Python**: `__pycache__/`, `*.pyc`, `.venv/`
     - **C/C++**: `*.o`, `*.a`, `*.so`, `build/`
     - **Rust**: `target/`
4. Do NOT overwrite existing entries, only append missing ones

### Phase 4: Phased Implementation

Follow the Autonomous Implementation Protocol from CLAUDE.md:

1. Break design into discrete phases with clear boundaries
2. Implement ONE phase at a time
3. After each phase:
   - Run ALL tests for that phase (`make test` or equivalent)
   - If any test fails: fix code, re-run tests, repeat until ALL pass
   - Do NOT proceed to next phase with failing tests
4. Repeat until all phases complete

### Phase 5: Full Integration Validation

After all phases implemented:

1. Run entire test suite end-to-end
2. Run build (`make build`)
3. Run linters if configured
4. Iterate on any failures until everything passes

### Phase 6: Parallel Review Gate

Launch THREE review sub-agents in parallel:

1. **Spec Compliance Review**
   - Compare implementation vs `PROJECT.md` and `docs/DESIGN.md`
   - Flag deviations, missing requirements, undocumented behavior
   - Write to `.llm/reviews/spec-review.md`

2. **Design/Architecture Review**
   - Verify interfaces, data flow, error handling patterns
   - Check deployment target compatibility
   - Verify adherence to code quality rules in CLAUDE.md
   - Write to `.llm/reviews/design-review.md`

3. **Security Review**
   - Read the security rule files loaded in Phase 0 as the authoritative checklist
   - Full audit against those rules (OWASP top 10, language-specific, framework-specific)
   - Input validation boundaries
   - Credential handling
   - Injection vectors
   - Dependency risks
   - Write to `.llm/reviews/security-review.md`

### Phase 7: Review Remediation

1. Read all three review files
2. Triage findings: critical > high > medium > low
3. Fix all critical and high findings (iterate with tests after each fix)
4. Document deferred medium/low findings with rationale in `.llm/reviews/deferred.md`
5. Re-run full test suite to confirm no regressions

### Phase 8: Documentation

Write `README.md` with:
- Project summary and purpose
- Architecture overview (reference `docs/DESIGN.md`)
- Build instructions
- Test instructions
- Deployment instructions (if applicable)
- Configuration (environment variables, config files)
- Usage examples
- Development workflow

## Key Constraints

- **Never skip phases** - each phase must complete and pass tests before next
- **Never skip reviews** - all three reviews must complete before declaring done
- **Never leave failing tests** - iterate until all tests pass
- **Minimal user interaction** - design for autonomous execution from start to finish
- **Document as you go** - design docs, test plans, and README are deliverables, not afterthoughts

## Invocation Pattern

User says:
> "Build this autonomously: [requirements]"

Or:
> "build-autonomous: [requirements]"

Or:
> "/build-autonomous [requirements]"

Then follow all phases sequentially with no human interaction until final delivery.

## Success Criteria

- All design documents written and committed
- All test plans documented
- All code implemented and passing tests
- All builds successful
- All three reviews completed
- All critical/high findings remediated
- README.md complete and accurate
- Project ready for deployment or handoff
