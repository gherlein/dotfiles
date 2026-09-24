# gherlein-claude-plugin

A Claude Code plugin of engineering-discipline skills: planning, code quality,
Go, TypeScript, PostgreSQL, git workflow, debugging, and full design-build-test
workflows. It ships 22 skills that either auto-trigger when your request matches
their subject or run deliberately by name.

Disclaimer: This works for me — that's the entire guarantee. Built with AI
in the loop, so check your own biases before you love it or hate it on
principle. Use at your own risk, fork freely, and don't @ me when it
explodes. (But do drop me a note if it helps — pay it forward.)

## Install

This repo is its own marketplace — the `gherlein-marketplace` catalog lives in
`.claude-plugin/marketplace.json` right here. Add the repo as a marketplace
once, then install:

```
/plugin marketplace add gherlein/gherlein-claude-plugin
/plugin install gherlein@gherlein-marketplace
/reload-plugins
```

### Prerequisites: dependency plugins

This plugin builds on other plugins rather than duplicating them.
`build-autonomous` opens with a **preflight** that reads
`~/.claude/plugins/installed_plugins.json` and checks both:

**Superpowers — required.** The plugin builds on the
[Superpowers](https://github.com/obra/superpowers) pipeline; several skills
reference `superpowers:*` explicitly (planning, execution, TDD, systematic
debugging, code review), and `build-autonomous` **stops** with install
instructions if it is absent.

```
/plugin marketplace add anthropics/claude-plugins-official
/plugin install superpowers@claude-plugins-official
/reload-plugins
```

**Claude Security — recommended.** When the `claude-security` plugin is present,
`build-autonomous`'s Phase D security review runs its `claude-security:scan`
adversarial multi-agent pipeline instead of a manual security-rules pass. If it is
absent, the preflight **warns** and the review falls back to the manual pass — the
build still runs.

```
/plugin install claude-security@claude-plugins-official
/reload-plugins
```

The lighter skills (`engineering-principles`, `test-as-guardrails`, `spec-driven`)
work on their own; they only *hand off* to these plugins when present, so they
degrade gracefully without them.

## Updating

The marketplace listing tracks this repo directly, so refreshing it pulls the
latest published skills. To update an already-installed copy:

```
/plugin marketplace update gherlein-marketplace
/plugin update gherlein@gherlein-marketplace
/reload-plugins
```

`marketplace update` re-fetches the catalog and skills; `plugin update`
re-resolves `gherlein` to the refreshed content; `reload-plugins` reloads the
skills into your current session without a restart.

## Using the skills

Skills are namespaced under `gherlein:` — invoke any of them explicitly with
`/gherlein:<name>` (e.g. `/gherlein:refactoring`).

- **Auto-triggering skills** fire on their own when your request matches their
  subject — asking to refactor invokes `refactoring`, asking about a slow Go
  hot path invokes `go-performance`, and so on. You don't have to name them.
- **Manual-only skills** (marked *manual* below) are heavier workflows that run
  only when you invoke them by name. These are the multi-phase orchestration and
  planning flows you want to start deliberately, not have fire mid-conversation.

### Planning & orchestration

| Skill | Mode | Purpose |
|-------|------|---------|
| `build-autonomous` | manual | Two interactive gates (vision → requirements), then an autonomous design-build-test-review-document cycle |
| `spec-driven` | auto | Treat spec docs (`REQUIREMENTS.md`, `docs/DESIGN.md`) as the authoritative source; code implements them. Includes cross-tier implementation templates. |
| `engineering-principles` | auto | Think-before-coding, simplicity-first, surgical changes, goal-driven execution. References for debugging and review safety per target. |

> The generic planning and execution flows (`plan`, `writing-plans`,
> `subagent-driven-development`, `executing-plans`, `dispatching-parallel-agents`)
> and multi-perspective analysis (`three-experts`) are not shipped here — install
> the [Superpowers](https://github.com/obra/superpowers) plugin for those.
> `build-autonomous` orchestrates the Superpowers pipeline and expects it present.

#### The `build-autonomous` loop

`build-autonomous` is the flagship end-to-end workflow. It always opens with two
**interactive, human-gated** phases and then runs the rest **autonomously** — it
does not start building until you have signed off on what to build.

1. **Vision (brainstorming)** — reads or creates `VISION.md` in the repo root and
   uses a one-question-at-a-time dialogue to capture purpose, users, goals,
   non-goals, constraints, and success criteria. This phase loops until **you
   explicitly say you're done brainstorming**.
2. **Requirements analysis** — from the vision, writes or edits `REQUIREMENTS.md`
   (root, authoritative) via `spec-driven`: functional requirements, numbered
   constraints, invariants, non-functional requirements, and explicit
   out-of-scope items. Loops until **you explicitly say requirements are done**,
   then commits `VISION.md` and `REQUIREMENTS.md`.
3. **Autonomous build** — from here it proceeds without prompting: design
   (`docs/DESIGN.md`) → test plan → project/git setup → phased, test-first
   implementation → full integration validation → the three-way review gate
   (spec, design, security) → remediation → verification gate → `README.md` →
   finishing the development branch. It breaks for you only when a downstream
   step genuinely needs a decision.

The two gates are the contract: you own the vision and the requirements; the
plugin owns everything downstream of them.

### Code quality

| Skill | Mode | Purpose |
|-------|------|---------|
| `edge-case-discovery` | auto | Two-step discovery of missing edge cases, with Go / web / RP2040 / K8s checklists |
| `test-as-guardrails` | auto | Three-context testing workflow that prevents specification gaming |
| `refactoring` | auto | Safe incremental refactoring with continuous test verification |
| `clean-comments` | auto | Remove obvious, redundant, or process-narrating comments (WHY-not-WHAT) |

> Code review itself is not a shipped skill — use Claude's `/code-review` and
> `/security-review` commands (or Superpowers' `requesting-code-review`). The
> per-target correctness/safety checklist lives in `engineering-principles`.

### Standards & conventions

| Skill | Mode | Purpose |
|-------|------|---------|
| `makefile-builds` | auto | Build via a Makefile rather than ad hoc commands |
| `gitignore-policy` | auto | Ensure a correct `.gitignore` when scaffolding or adding files |
| `llm-context` | auto | Conventions for the `.llm/` directory (extra context and the task list) |

### Git workflow

| Skill | Mode | Purpose |
|-------|------|---------|
| `git-ops` | auto | Commit-message conventions, cherry-pick, rebase conflict resolution |

### Language & domain

| Skill | Mode | Purpose |
|-------|------|---------|
| `go-performance` | auto | Go GC optimization, allocation reduction, pprof profiling |
| `go-usb` | auto | USB / HID / serial device development in Go (gousb, udev rules) |
| `postgresql` | auto | Schema, indexing, queries, migrations, ORM policy |
| `rest-api-design` | auto | Status codes, pagination, error format, auth, caching, OpenAPI |
| `web-frontend` | auto | React / TypeScript / Tailwind / shadcn conventions and testing |
| `api-canary` | auto | Discover exposed endpoints, then generate a black-box canary test framework |
| `unifi-fixed-hosts` | auto | Read/add/delete fixed IP (DHCP reservation) assignments on a UniFi/UDM controller |
| `goprojdex` | auto | Look up where a project lives, its remote, state, and staleness in the personal project index |

### Docs

| Skill | Mode | Purpose |
|-------|------|---------|
| `documentation` | auto | README structure, writing style, Mermaid diagrams, API and design docs |

### Understanding & onboarding

| Skill | Mode | Purpose |
|-------|------|---------|
| `onboard` | manual | Layer hierarchical / multi-service context files onto a codebase (use `/init` for the base `CLAUDE.md`) |
| `reverse-engineer` | manual | 10-phase framework for systematic source analysis and architecture docs |
| `learn` | manual | Document tricky problems and their solutions for future reference |

## For maintainers

These steps publish updates to the plugin; they are not needed to install it.

This repo is self-hosting: its `.claude-plugin/marketplace.json` lists the plugin
with a local `"source": "./"`, so there is no separate marketplace repo to keep
in sync. Tagging and pushing this repo **is** the release. The `make release`
target automates it.

### Releasing

Authoring a release is two hand edits; publishing it is one command.

```bash
# 1. Add or edit skills under skills/<name>/SKILL.md

# 2. Bump "version" in .claude-plugin/plugin.json and add a matching
#    "## vX.Y.Z" entry to the top of CHANGELOG.md

# 3. Commit on main (make release requires a clean working tree)
make check                          # validate skill dependency references
git commit -am "Release vX.Y.Z: <summary>"

# 4. Publish in one step: tag vX.Y.Z and push main + tag
make release
```

`make release` reads the version straight from `plugin.json` (the single source
of truth) and preflights before touching anything: on `main`, clean tree, valid
semver, a matching `## vX.Y.Z` CHANGELOG entry, and the tag not already taken. It
then tags the release and pushes `main` and the tag.

`make release` finishes by printing the client-side steps it cannot run —
refresh an installed copy with:

```
/plugin marketplace update gherlein-marketplace
/plugin update gherlein@gherlein-marketplace
```

then restart the session (or `/reload-plugins`). Note `/plugin update`, not
`install` — a plain install will not upgrade an already-installed plugin.

Other Makefile targets: `make` (or `make help`) lists everything; `make check`
(also `make build` / `make test` / `make run-tests`) runs the self-containment
validation; `make clean` removes build scratch.

Each shipped skill may reference only **declared** plugin namespaces — its own
`gherlein:` and the `superpowers:` dependency. A reference to any other plugin
namespace is an undeclared dependency and fails validation.
`scripts/check-self-contained.sh` enforces this — `make release` runs it as a
preflight, and a GitHub Actions workflow fails the build on any violation. To add
a new dependency, append its namespace to the script's allow-list *and* document
it here plus preflight it in the skill that needs it (as `build-autonomous` does
for Superpowers).

## Credits

This plugin no longer ships any skills derived from the **Superpowers** project by
Jesse Vincent (https://github.com/obra/superpowers); the previously-vendored
derivatives were removed in favor of installing Superpowers directly.
`build-autonomous` orchestrates the Superpowers pipeline and expects that plugin to
be installed. A pristine upstream snapshot remains vendored at `vendor/superpowers/`
(pinned in `vendor/superpowers/PINNED_AT.txt`) as the attribution baseline and diff
target, used under the MIT License and Copyright (c) 2025 Jesse Vincent. See
[`NOTICE.md`](NOTICE.md) for the full attribution.

All skills in this plugin are original works Copyright (c) 2026 Greg Herlein. This
project is MIT-licensed; see [`LICENSE`](LICENSE).
