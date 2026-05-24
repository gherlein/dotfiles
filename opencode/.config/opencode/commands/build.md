---
description: "Complete autonomous design-build-test-review cycle from requirements through delivery. Use when the user wants hands-off implementation from a spec or requirements statement."
agent: orchestrator
---

Run a full autonomous build cycle for: $ARGUMENTS

No human interaction after this invocation. Follow all phases sequentially. Never skip a phase. Never proceed with failing tests.

---

## Phase 1: Context Loading

1. Read `AGENTS.md` — it is already loaded, but review the Autonomous Implementation Protocol and Security Context Files sections explicitly.
2. Identify the project's languages, frameworks, and deployment targets from any existing code and the requirements.
3. Load the relevant security rules from `knowledge/security-rules/`:
   - `_core/owasp-2025.md` — always load this
   - Load language/framework-specific files matching the project (e.g., `languages/go/RULES.md`, `frontend/react/RULES.md`, `containers/kubernetes/RULES.md`)
4. Note which skills apply — you will invoke them by name during later phases.

---

## Phase 2: Understand Existing Context

Dispatch `@analyst`:

```
Objective: Map the existing codebase before design begins.
Read: PROJECT.md, REQUIREMENTS.md (if they exist), any existing source files.
Identify: languages, frameworks, existing patterns, public interfaces, test conventions.
Report: a structured summary covering structure, patterns, constraints, and gaps.
STRICT: read-only. No edits.
```

If no existing code, skip `@analyst` and proceed with requirements only.

---

## Phase 3: Design

Load the `writing-plans` skill. Then write:

**`docs/DESIGN.md`** — full architecture document covering:
- Modules, boundaries, and contracts
- Interfaces (APIs, protocols, schemas)
- Data flow
- State model
- Constraints and invariants
- Deployment target compatibility (embedded / SBC / cloud as applicable)

**`docs/TEST-PLAN.md`** — test strategy covering:
- Unit, integration, and e2e test phases
- Test phases aligned with implementation phases
- Coverage targets
- Edge cases and failure scenarios

If `PROJECT.md` exists, update it with any project-specific parameters discovered.

---

## Phase 4: Infrastructure Setup

1. Check for `.git` — if missing, run `git init`.
2. Check `.gitignore` — create or update per the Gitignore Policy in `AGENTS.md`:
   - Mandatory: `.env`, `.envrc`, `*~`, `bin/`, `.llm/`
   - Language-specific entries for every language in this project
   - Never overwrite existing entries — only append missing ones
3. Create `.llm/` directory if missing. Create `.llm/todo.md` listing all implementation phases as tasks.

---

## Phase 5: Phased Implementation

Load the `test-driven-development` skill before dispatching any builder tasks.

Break `docs/DESIGN.md` into discrete implementation phases. For each phase:

Dispatch `@builder`:

```
Objective: [specific phase description]
File(s): [exact paths to create or modify]
Context: [relevant section from docs/DESIGN.md, interfaces, constraints]
Tests required: [what the tests must cover per docs/TEST-PLAN.md]
TDD rule: write failing test FIRST. No production code before a failing test exists.

Report: DONE / DONE_WITH_CONCERNS / NEEDS_CONTEXT / BLOCKED
```

After each `@builder` completes:
- If DONE: mark that phase done in `.llm/todo.md`, proceed to next phase.
- If any tests fail: dispatch `@debugger` (see below) before retrying. Never guess at fixes.
- If BLOCKED or NEEDS_CONTEXT: resolve the blocker, then re-dispatch.
- Do NOT proceed to the next phase with failing tests.

**Debugging rule:** When tests fail, dispatch `@debugger`:

```
Objective: Diagnose why [specific test] is failing.
Do NOT fix anything. Find and report the root cause only.
Files: [relevant paths]
Error output: [exact failure message]
```

Apply the diagnosed fix via `@builder`, then re-run tests.

---

## Phase 6: Full Integration Validation

After all phases complete:

1. Run `make test` (or equivalent). All tests must pass.
2. Run `make build`. Build must succeed.
3. Run linters if configured (`go vet ./...`, `golangci-lint`, `npm run lint`, etc.).
4. If anything fails: diagnose with `@debugger`, fix with `@builder`, repeat until clean.

---

## Phase 7: Three-Reviewer Gate

Dispatch `@reviewer` three times with separate focused briefs. Write each output to `.llm/reviews/` before starting the next.

**Review 1 — Spec Compliance** → `.llm/reviews/spec-review.md`
```
Compare the implementation against REQUIREMENTS.md and PROJECT.md.
Flag every deviation, missing requirement, and undocumented behavior.
Reference specific files and line numbers.
Do NOT edit — report only.
```

**Review 2 — Design/Architecture** → `.llm/reviews/design-review.md`
```
Compare the implementation against docs/DESIGN.md.
Verify: interfaces match the design, data flow is correct, error handling follows AGENTS.md patterns,
deployment target constraints are respected, code quality rules from AGENTS.md are followed.
Reference specific files and line numbers.
Do NOT edit — report only.
```

**Review 3 — Security** → `.llm/reviews/security-review.md`
```
Audit against the security rules loaded in Phase 1 (OWASP top 10 + language/framework rules).
Check: input validation at all system boundaries, credential handling, injection vectors,
parameterized queries, HTTPS enforcement, silenced warnings, dependency risks.
Reference specific files and line numbers.
Do NOT edit — report only.
```

---

## Phase 8: Review Remediation

1. Read all three review files.
2. Triage findings: critical > high > medium > low.
3. Fix all critical and high findings. For each fix: dispatch `@builder`, then re-run `make test`.
4. Write `.llm/reviews/deferred.md` — document every medium/low finding with rationale for deferral.
5. Run `make test` one final time to confirm no regressions.

---

## Phase 9: Verification Gate

Load the `verification-before-completion` skill and follow it exactly before proceeding. Do not skip this step.

---

## Phase 10: Documentation

Write `README.md` with:
- Project summary and purpose
- Architecture overview (reference `docs/DESIGN.md`)
- Build instructions (`make build`)
- Test instructions (`make test`)
- Deployment instructions (if applicable)
- Configuration (environment variables, config files)
- Usage examples
- Development workflow

---

## Phase 11: Finish

Run `/finish` to complete the branch: verify tests, present options (merge / push+PR / keep / discard), execute the chosen option.

---

## Constraints

- Never skip a phase.
- Never proceed with failing tests.
- Never guess at a fix — always diagnose first with `@debugger`.
- Test-first always — `@builder` must write a failing test before any production code.
- All three reviews must complete and findings must be triaged before declaring done.
