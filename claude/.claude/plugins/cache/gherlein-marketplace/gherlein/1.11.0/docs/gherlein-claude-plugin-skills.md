# gherlein-claude-plugin — Skills Summary

**Plugin:** `gherlein` (v1.9.0) — Greg Herlein
**Description:** Engineering discipline skills: planning, code quality, Go, TypeScript, PostgreSQL, git workflow, debugging.
**Repo:** https://github.com/gherlein/gherlein-claude-plugin (MIT)
**Invocation:** Skills are namespaced under `gherlein:` — e.g. `/gherlein:refactoring`.

Skills marked **[manual]** have `disable-model-invocation: true` — they run only when explicitly invoked, not auto-triggered by the model. All others auto-trigger on the keywords in their descriptions.

This plugin no longer ships any Superpowers-derived skills; instead it references
`superpowers:*` skills as a declared dependency. `build-autonomous` opens with a
preflight that verifies the [Superpowers](https://github.com/obra/superpowers)
plugin (`superpowers@claude-plugins-official`) is installed and stops with install
instructions if not. A pristine upstream snapshot is kept at `vendor/superpowers/`
for attribution only.

Total: **22 skills**.

---

## Planning & Orchestration

| Skill | Trigger / Mode | Purpose |
|-------|----------------|---------|
| `build-autonomous` | [manual] | Conductor over the Superpowers pipeline (brainstorming → writing-plans → subagent-driven-development → finishing-a-development-branch), layering gherlein rigor: security-rules, the test-as-guardrails edge matrix, api-canary, and a 3-way final review. |
| `spec-driven` | repo has spec/requirements docs | Treat `PROJECT.md` / `REQUIREMENTS.md` / `docs/DESIGN.md` as authoritative; code implements them. Includes cross-tier implementation templates (Go microservice, web feature, RP2040, embedded→cloud). |
| `engineering-principles` | before non-trivial implementation | Full discipline behind CLAUDE.md: think-before-coding, simplicity-first, surgical changes, goal-driven execution. References for debugging and review safety per target. |

## Code Quality

| Skill | Trigger / Mode | Purpose |
|-------|----------------|---------|
| `edge-case-discovery` | what edge cases am I missing | Two-step discovery of missing edge cases, with checklists for Go, web, embedded RP2040, and K8s. |
| `test-as-guardrails` | writing tests / are my tests meaningful | Three-context anti-gaming testing workflow, per-domain testing patterns, and the test-quality bar. Composes with a test-first (TDD) workflow. |
| `refactoring` | refactor this / clean up this code | Safe incremental refactoring with continuous test verification and code-smell detection. |
| `clean-comments` | clean up comments | Remove obvious, redundant, or process-narrating comments (WHY-not-WHAT). |

## Standards & Conventions

| Skill | Trigger / Mode | Purpose |
|-------|----------------|---------|
| `makefile-builds` | build this / set up a build | Build via a Makefile rather than ad hoc commands. |
| `gitignore-policy` | scaffolding a repo / before first commit | Ensure a correct `.gitignore` when writing files into a dev project. |
| `llm-context` | repo has a `.llm/` folder | Conventions for the `.llm/` directory (extra context and the task list). |

## Git & Workflow

| Skill | Trigger / Mode | Purpose |
|-------|----------------|---------|
| `git-ops` | write a commit message / cherry-pick / rebase | Commit-message conventions, cherry-pick via inspect-and-recreate, rebase conflict resolution. |

## Language / Domain Specific

| Skill | Trigger / Mode | Purpose |
|-------|----------------|---------|
| `go-performance` | Go is slow / reduce allocations / pprof | Go GC optimization, allocation reduction, pprof profiling, memory management. |
| `go-usb` | USB / HID / serial in Go | Go USB device development (gousb, karalabe/usb, serial, HID, udev rules). |
| `postgresql` | design a Postgres schema / slow query | Data types, indexing, queries, migrations, ORM policy, monitoring, backups. |
| `rest-api-design` | design a REST API / add an endpoint | Status codes, pagination, error format, auth, caching, OpenAPI. |
| `web-frontend` | React component / TypeScript frontend | React / TypeScript / Tailwind / shadcn conventions and testing. |
| `api-canary` | find all exposed APIs / black-box tests | Discover exposed endpoints, then generate a standalone black-box canary test framework. |
| `unifi-fixed-hosts` | fixed IP / DHCP reservation on UniFi | Read/add/delete fixed IP assignments on a UniFi/UDM controller; look up device MACs and network info (gofips, gofimac, gofinet). |
| `goprojdex` | where does project X live / what's stale | Query and curate the personal project index: `find`/`list`/`--json`, reading `~/.goprojdex/projects/*.md` directly, and `here`/`touch`/`set`. |

## Documentation

| Skill | Trigger / Mode | Purpose |
|-------|----------------|---------|
| `documentation` | write a README / add a diagram / API docs | README structure, writing style, Mermaid diagrams, API and design docs. |

## Understanding & Onboarding

| Skill | Trigger / Mode | Purpose |
|-------|----------------|---------|
| `onboard` | [manual] | Layer hierarchical / multi-service context files onto a codebase; base `CLAUDE.md` generation defers to Claude's `/init`. |
| `reverse-engineer` | [manual] | 10-phase framework for systematic source analysis, component inventory, coupling analysis, and architecture docs. |
| `learn` | [manual] | Document tricky problems and their solutions in `CLAUDE.local.md` for future reference. |

## Notes

- **Two invocation modes.** The `[manual]` skills (`build-autonomous`, `onboard`,
  `reverse-engineer`, `learn`) set `disable-model-invocation: true` and run only
  when invoked deliberately. The rest auto-trigger on keyword matches.
- **Superpowers dependency (declared).** The generic planning/execution flows
  (`superpowers:writing-plans`, `superpowers:subagent-driven-development`,
  `superpowers:executing-plans`, `superpowers:dispatching-parallel-agents`), process
  discipline (`superpowers:systematic-debugging`, `superpowers:test-driven-development`,
  `superpowers:requesting-code-review`, etc.), and multi-perspective analysis are
  provided by the Superpowers plugin, not duplicated here. Skills reference them
  explicitly; `build-autonomous` preflights the install and stops if it is missing.
- **Claude Security dependency (recommended).** When `claude-security` is installed,
  `build-autonomous`'s Phase D security review runs `claude-security:scan`; when
  absent the preflight warns and it falls back to a manual security-rules pass.
- `scripts/check-self-contained.sh` permits `gherlein:`, `superpowers:`, and
  `claude-security:` and rejects any other plugin namespace.
- **Salvaged references.** The retired `evidence-based-debugging`, `code-review`, and
  `plan` skills left their unique per-target content behind: debugging and
  review-safety cheat-sheets under `engineering-principles/references/`, and
  cross-tier implementation templates inside `spec-driven`.
