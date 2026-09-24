---
name: build-autonomous
description: "Conducts a complete design-build-test cycle by running the superpowers pipeline (brainstorming -> writing-plans -> subagent-driven-development -> finishing-a-development-branch) and layering gherlein rigor on top -- security-rules, the test-as-guardrails edge matrix, api-canary, and a 3-way final review. Triggers on: build this autonomously, build-autonomous, design and build this hands-off, full design-plan-implement-test-document cycle."
disable-model-invocation: true
---

# Autonomous Full-Cycle Implementation

Use when the user wants a complete hands-off implementation from design through delivery.

This skill is a **conductor**, not a separate build engine. The superpowers pipeline
does the thinking, planning, and building; `build-autonomous` runs it end-to-end
without stopping and **injects gherlein's extra rigor** at the seams. It does not
duplicate superpowers' execution machinery.

## When to Use

- User says "design and build this autonomously"
- User says "build-autonomous" or invokes this skill
- User provides requirements and wants minimal interaction until completion
- Complex features requiring a full design-plan-implement-test-document cycle

## How this composes with superpowers

**Default: superpowers owns the build loop.** The native pipeline runs as-is --
`superpowers:brainstorming` -> `superpowers:writing-plans` -> `superpowers:subagent-driven-development` (or
`superpowers:executing-plans`) -> `superpowers:finishing-a-development-branch` -- at its native paths
(`docs/superpowers/specs/`, `docs/superpowers/plans/`) and with its native gates
(design approval, spec review, plan review). `build-autonomous` adds security-rules
loading, the `test-as-guardrails` edge matrix, `api-canary`, and a 3-way final
review; it does not replace superpowers' per-task TDD and review loops.

**Override: the gherlein engine.** Only when the user explicitly asks for it
("use the gherlein build engine", "use your own build phases", "not superpowers'
executor") do you run the self-contained gherlein engine in the Appendix instead
of superpowers' executor. Everything else (Phase A setup, Phase B planning, Phase
D final gates, Phase E finish) is unchanged.

**Human interaction:** gated only at the superpowers front-end (design, spec, plan
reviews). Once the plan is approved, execution runs continuously -- break only when
a downstream skill (`superpowers:systematic-debugging`, a review gate) genuinely needs a
decision.

**Version-control rhythm:** all work happens on the dedicated branch created in
Phase A, never on `main`. Superpowers' TDD loop commits frequently; the branch is
the unit of work integrated in Phase E.

## Phase 0: Preflight -- verify plugin dependencies

Check both dependencies **before doing anything else** by reading the authoritative
install record. A skill cannot self-install (only the user can run `/plugin`), so on
a miss, print the steps and either stop or warn per the rules below.

```bash
grep -q '"superpowers@'      ~/.claude/plugins/installed_plugins.json 2>/dev/null \
  && echo "superpowers: installed"      || echo "superpowers: MISSING (required)"
grep -q '"claude-security@'  ~/.claude/plugins/installed_plugins.json 2>/dev/null \
  && echo "claude-security: installed"  || echo "claude-security: MISSING (recommended)"
```

**superpowers -- REQUIRED (hard gate).** This skill is a conductor over the
Superpowers pipeline; it cannot run without it. If missing, print these steps, tell
the user to run them, and **stop** -- do not proceed degraded:

```
/plugin marketplace add anthropics/claude-plugins-official
/plugin install superpowers@claude-plugins-official
/reload-plugins
```

Then have the user re-invoke `build-autonomous`. Only continue once superpowers
reports `installed`.

**claude-security -- RECOMMENDED (warn, do not stop).** The Phase D security review
is stronger when the `claude-security` plugin is present: its `claude-security:scan`
pipeline runs the adversarial multi-agent scan instead of a manual security-rules
pass. If missing, **warn** the user and continue -- Phase D falls back to the manual
`security-rules` review:

```
WARNING: claude-security is not installed. Phase D security review will fall back
to a manual security-rules pass. For the full adversarial scan, install it:
  /plugin install claude-security@claude-plugins-official
  /reload-plugins
```

## Phase A: Setup (gherlein, before superpowers)

1. **Confirm version control.** Check `git rev-parse --git-dir`. If the folder is
   not a git repo, ask the user whether to `git init` before continuing:
   - **Yes:** run `git init` so the superpowers spec/plan and TDD commits can land.
   - **No:** note that later commit, tag, and release steps will be impossible, and
     proceed without version control.
2. **Create the working branch.** Unless the user declined version control, create
   and switch to `build/<topic>` (a short kebab-case slug). All later commits land
   here; it is what gets merged or turned into a PR in Phase E.
3. **Load execution context.** Read `~/.claude/INDEX.md`; identify the project's
   languages, frameworks, and domains; read every relevant `~/.claude/security-rules/`
   file for that stack -- at minimum `~/.claude/security-rules/_core/owasp-2025.md`.
   These stay in context so planning and review can apply them.

## Phase B: Think and Plan (superpowers-native, interactive)

Run the superpowers front-end natively -- no output redirection, native paths,
native gates:

1. **Invoke `superpowers:brainstorming`.** Let it run its full flow: dialogue, 2-3 approaches,
   design sections, spec self-review, and the user spec-review gate. It writes the
   design spec to `docs/superpowers/specs/`.
2. **Let it hand off to `superpowers:writing-plans`.** It produces the bite-sized, TDD-structured
   plan at `docs/superpowers/plans/`, with its own plan self-review.
3. **Inject gherlein plan requirements** before execution begins -- the plan must
   bake in:
   - the `test-as-guardrails` edge-case matrix (boundary, nil/empty, error
     propagation, concurrency, network, resource) and the mocking-as-last-resort
     policy, as test tasks;
   - **if the project exposes a network API** (HTTP/REST, gRPC, GraphQL, WebSocket),
     `api-canary` tasks -- a standalone black-box canary (`canary/`, no service
     imports) is a deliverable, not an afterthought;
   - `makefile-builds` and `gitignore-policy` conformance.
   If `superpowers:writing-plans` did not already cover these, extend the plan before handing it
   to the executor.

## Phase C: Build (superpowers executor -- DEFAULT)

Let `superpowers:writing-plans` hand off to its executor and **do not intercept**:

- **`superpowers:subagent-driven-development`** (recommended) -- fresh implementer per task,
  per-task spec+quality review loops, durable progress ledger, continuous execution.
- **`superpowers:executing-plans`** -- for a separate/parallel session with batched checkpoints.

Its per-task `superpowers:test-driven-development` loop does the building. **Inject gherlein
review dimensions:** when constructing task-reviewer and final-reviewer prompts,
add the loaded `security-rules` and the `test-as-guardrails` quality bar (strict
assertions, edge matrix, no self-mocking) as explicit review criteria.

**Override -- gherlein engine:** only if the user explicitly asked for it, run the
Appendix engine instead of this phase.

## Phase D: Final Gates (gherlein additions)

These run **in addition to** superpowers' final whole-branch review, not instead:

1. **3-way parallel review.** With subagents, launch three reviewers simultaneously;
   otherwise run them sequentially, writing each file before the next:
   - **Spec compliance** vs the design spec -> `.llm/reviews/spec-review.md`
   - **Design/architecture** (interfaces, data flow, error handling, deployment
     targets, CLAUDE.md code-quality rules) -> `.llm/reviews/design-review.md`
   - **Security** -> `.llm/reviews/security-review.md`. If the Phase 0 check found
     `claude-security` installed, run its `claude-security:scan` pipeline for this
     dimension (adversarial multi-agent scan) and fold its verified findings in.
     Otherwise fall back to a manual review against the Phase A security-rules
     (OWASP, language, framework; input boundaries, credentials, injection,
     dependencies).
2. **Remediate.** Triage critical > high > medium > low; fix all critical/high
   (re-run tests after each); record deferred medium/low with rationale in
   `.llm/reviews/deferred.md`; re-run the full suite to confirm no regressions.
3. **API drift.** For API projects, run the `api-canary` smoke + contract tiers
   against a running instance from outside the process, and `make drift` to confirm
   no exposed endpoint is undocumented or missing.
4. **Verification.** Invoke `superpowers:verification-before-completion` before declaring done
   -- evidence before any success claim. Do not skip it.

## Phase E: Finish (superpowers)

Invoke `superpowers:finishing-a-development-branch`: it verifies tests, determines the base
branch, and carries out the user's chosen integration (merge or PR) with real
`git`/`gh` actions, including branch cleanup. Remind the user which branch they are
on first.

## Key Constraints

- **Superpowers is the default engine** -- do not intercept its executor unless the
  user explicitly asks for the gherlein engine.
- **Never skip the final gates** -- the 3-way review, remediation, drift check (for
  API projects), and verification-before-completion are additive and mandatory.
- **Never leave failing tests** -- `superpowers:systematic-debugging` diagnoses before any fix.
- **Tests must be meaningful** -- `test-as-guardrails` governs test quality in the
  plan and as a review dimension; strict assertions, edge matrix, mocking last.
- **External API validation** -- for network-API projects, `api-canary` is mandatory.
- **Interactive only at the superpowers front-end** -- design, spec, and plan
  reviews are the human gates; execution is continuous afterward.
- **Document as you go** -- the design spec, plan, and README are deliverables.

## Invocation Pattern

User says:
> "Build this autonomously: [requirements]"
> "build-autonomous: [requirements]"
> "/build-autonomous [requirements]"

Regardless of detail provided, the workflow opens with the Phase 0 Superpowers
preflight (stop if the plugin is missing), then Phase A setup and the interactive
superpowers front-end (Phase B). After the plan-review gate clears,
run Phases C-E continuously with no human interaction unless a downstream skill
requires it. To use the gherlein engine instead of superpowers' executor, the user
must say so explicitly.

## Success Criteria

- Design spec brainstormed and committed; user cleared the spec-review gate
- Implementation plan written and committed; user cleared the plan-review gate
- All code implemented test-first via the executor's TDD loop
- For API projects: external `api-canary` module built (black-box) and its
  smoke/contract/drift checks passing against a running instance
- Superpowers' whole-branch review plus the gherlein 3-way review completed
- All critical/high findings remediated
- verification-before-completion gate passed
- README.md complete and accurate
- Development branch finished and clean

## Appendix: gherlein build engine (override only)

Use these phases **only** when the user explicitly asks for the gherlein engine
instead of superpowers' executor. They replace Phase C; Phases A, B, D, and E still
apply. This is the self-contained build loop; prefer superpowers by default.

### G1: Sub-Agent Team Assembly

Create specialized sub-agents: Design, Test Planning, Implementation (per
module/service), and Review agents.

### G2: Design and Planning

- **Design pass** -- analyze the spec and constraints; create architecture (modules,
  boundaries, contracts, state model); define interfaces; write `docs/DESIGN.md`.
- **Test-planning pass** -- invoke `test-as-guardrails`; design the test strategy,
  the edge-case matrix, the sub-30-second smoke suite, and (for API projects) the
  `api-canary` plan; write `docs/TEST-PLAN.md`.

### G3: Phased Implementation

Each Implementation Agent invokes `superpowers:test-driven-development` (failing test first,
Red-Green-Refactor) and `test-as-guardrails` (test quality). Where subagents exist,
use the three-context workflow (implement, test, and triage in separate fresh
contexts) to defeat specification gaming. Build the `api-canary` module alongside
the code for API projects.

Implement one phase at a time. After each phase: run all phase tests, the smoke
suite, and race checks where supported; on any failure invoke `superpowers:systematic-debugging`
before fixing; do not advance with failing tests; commit the phase as a rollback
point.

### G4: Full Integration Validation

Run the entire suite end-to-end, the smoke suite and race checks, the build, and
linters. For API projects, run the `api-canary` smoke + contract tiers against a
running instance and `make drift`. On any failure, `superpowers:systematic-debugging` then
iterate until green. Then rejoin Phase D.
