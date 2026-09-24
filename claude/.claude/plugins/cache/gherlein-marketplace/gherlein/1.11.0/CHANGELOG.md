# Changelog

## v1.11.0

- `documentation`: add an Ownership Disclaimer section. The "works for me"
  README disclaimer is now inserted only when the repo's git remote belongs to
  the `gherlein` personal GitHub account or the `emergingrobotics` org
  (`github.com[:/]gherlein/` or `github.com[:/]emergingrobotics/`, SSH or
  HTTPS). Any other owner -- forks, work repos, or no matching remote -- gets no
  disclaimer, and an existing disclaimer is never removed or altered.

## v1.10.0

- Declare `claude-security` as a second, recommended runtime dependency.
  `build-autonomous`'s Phase 0 preflight now checks for it and warns (rather than
  stopping) when it is absent, and Phase D runs the `claude-security:scan`
  adversarial multi-agent pipeline for the security dimension when it is present,
  falling back to the manual security-rules pass when it is not.
  `scripts/check-self-contained.sh` allows the `claude-security:` namespace, and
  the README documents both prerequisites.

- Add `goprojdex`: query and curate the personal project index
  (github.com/gherlein/goprojdex) -- where a project lives, its remote, its
  state, and what has gone stale. Covers the CLI (`find`, `list --json`,
  `here`, `touch`, `set`) and reading `~/.goprojdex/projects/*.md` directly.
  Written against baseline subagent runs; documents the traps those runs hit:
  no `--help`, `--store` must precede the subcommand, `find` does not search
  slugs, whole-store enumeration floods context, empty fields are omitted from
  both JSON and frontmatter, and a scan-built store's `status` and `updated`
  fields are defaults rather than curated signals.

## v1.9.0

- Remove 9 skills that duplicated better-maintained equivalents, taking the plugin
  from 31 to 22 skills:
  - The four vendored Superpowers derivatives (`dispatching-parallel-agents`,
    `executing-plans`, `requesting-code-review`, `subagent-driven-development`) --
    install the Superpowers plugin for these. `build-autonomous` orchestrates the
    Superpowers pipeline via explicit `superpowers:*` references.
  - `evidence-based-debugging` and `code-review` -- superseded by Superpowers'
    `systematic-debugging` and by Claude's `/code-review` + `/security-review`
    (and Superpowers' `requesting-code-review`). Their unique per-target content
    was salvaged into `engineering-principles/references/debugging-by-domain.md`
    and `review-safety-by-domain.md`.
  - `plan` -- superseded by Superpowers' `writing-plans`; its cross-tier
    implementation templates were folded into `spec-driven`.
  - `three-experts` and `refine` -- generic prompt-frameworks now covered by
    Superpowers' `brainstorming` and the Workflow judge-panel pattern.
- `test-as-guardrails`: reframed to compose with (not duplicate) a test-first
  workflow; it now owns the anti-gaming three-context workflow and test-quality bar.
- `onboard`: narrowed to hierarchical / multi-service context layering; the base
  `CLAUDE.md` generation now defers to Claude's `/init`.
- Declare Superpowers as a runtime dependency instead of vendoring it. Skills now
  reference `superpowers:*` explicitly; `scripts/check-self-contained.sh` was
  relaxed from a self-containment rule to a declared-dependency rule (permits
  `gherlein:` and `superpowers:`, rejects any other plugin namespace).
- `build-autonomous`: add a Phase 0 preflight that verifies plugin dependencies by
  reading `~/.claude/plugins/installed_plugins.json`. Superpowers is a hard gate
  (stops with `/plugin` install instructions if absent). `claude-security` is a
  recommended dependency (warns, does not stop): when present, Phase D's security
  review runs the `claude-security:scan` adversarial pipeline; when absent it falls
  back to a manual security-rules pass. `check-self-contained.sh` now also permits
  the `claude-security:` namespace. Both documented as prerequisites in the README.
- Add the missing `unifi-fixed-hosts` row to the README skill tables.

## v1.8.0

- Add a `make release` target that publishes the version in `plugin.json`: it
  tags `vX.Y.Z`, pushes `main` + tag, rewrites the marketplace repo's
  `marketplace.json` `ref`/`commit`, and pushes it -- then prints the
  client-side `/plugin` steps make cannot run. Also adds
  `build`/`test`/`run-tests`/`check`/`clean` targets; the default target prints
  help.
- Fix `scripts/check-self-contained.sh`: example MAC addresses (e.g.
  `aa:bb:cc:dd:ee:ff`) tokenize into `aa:bb` pairs that the namespace scanner
  wrongly flagged as foreign plugin references, failing validation since
  `unifi-fixed-hosts` landed in v1.6.0. Two-hex:two-hex fragments are now
  filtered out.

## v1.7.0

- `unifi-fixed-hosts`: add the `gofinet` tool for network inspection -- list
  networks with subnet, VLAN, DHCP dynamic-address pool, lease, gateway, and
  DNS (text columns + JSON field schema). Wire it into the workflow as the
  companion to `gofips`: check the dynamic pool first so fixed reservations are
  chosen outside it. Verified against the installed binary's `--help` and live
  `gofinet --json` output.

## v1.6.0

- Add `unifi-fixed-hosts`: read, add, and delete fixed IP assignments (DHCP
  reservations) on a UniFi/UDM controller and look up detected device MAC
  addresses, wrapping the `gofips` and `gofimac` CLIs from
  github.com/emergingrobotics/gofi. Reference verified against the installed
  binaries' `--help` and live `gofimac --json` output.

## v1.5.0

- `build-autonomous`: reframe from a self-contained 11-phase engine into a
  conductor over the superpowers pipeline. By default it runs superpowers natively
  (`brainstorming` -> `writing-plans` -> `subagent-driven-development` /
  `executing-plans` -> `finishing-a-development-branch`) at superpowers' native
  paths and gates, and layers gherlein rigor on top: Phase A loads security-rules
  and creates the working branch; Phase B injects the `test-as-guardrails` edge
  matrix, `api-canary`, and `makefile-builds`/`gitignore-policy` into the plan;
  Phase D adds a 3-way (spec/design/security) final review, API drift check, and
  `verification-before-completion`. The legacy self-contained engine is preserved
  as an override Appendix, used only when the user explicitly asks for it.

## v1.4.0

- Remove 9 skills that duplicated the superpowers plugin: `using-superpowers`,
  `verification-before-completion`, `using-git-worktrees`, `systematic-debugging`,
  `test-driven-development`, `receiving-code-review`, `finishing-a-development-branch`,
  `writing-plans`, and `writing-skills`. These were stale forks that double-fired
  alongside their superpowers twins; the workflow now defers to superpowers for them.
- Remove `orchestrate`; salvage its unique content into kept skills -- the
  proportionality check into `plan`, the context-compression checklist into
  `subagent-driven-development`.
- `requesting-code-review`: set `disable-model-invocation` so it no longer
  auto-fires alongside the superpowers version; it remains available by explicit
  invocation and for the build-autonomous chain's no-subagent fallback.
- `dispatching-parallel-agents`: replace the stale `Task()` example with the
  `Agent` subagent tool, stated platform-neutrally.
- `plan`: Phase 2 and Phase 3 now write `REQUIREMENTS.md` and `PLAN.md` at the
  repo root, matching the project-document convention.
- `test-as-guardrails`: replace the duplicated edge-case table with a pointer to
  `edge-case-discovery` as the canonical source.
- Repoint internal references to removed skills to bare names so they resolve to
  the superpowers plugin.

## v1.3.1

- `build-autonomous` Phase 0.1: check whether the working folder is a git repo
  and, if not, ask the user whether to create one (`git init`) before starting;
  proceed without version control if declined.
- `build-autonomous` Phase 0.1: require `VISION.md` to be fleshed out as the
  dialogue proceeds -- each answer and its rationale folded into structured,
  readable sections (purpose, motivation, users, goals, non-goals, constraints,
  chosen approach, success criteria, open questions) so it stands on its own, and
  ask the user to read it before the requirements gate.
- `build-autonomous`: create a dedicated working branch (`build/<topic>`) in
  Phase 0.1 and commit at the end of every phase as rollback points, never
  working directly on `main`.
- `build-autonomous` Phase 11: remind the user which branch they are on and ask
  whether to open a PR to `main` or merge; on merge, ask whether to delete the
  branch, then execute the choices with real `git`/`gh` actions via
  `finishing-a-development-branch`.

## v1.3.0

- `build-autonomous`: define the previously-referenced-but-missing Phase 0 as two
  interactive, human-gated steps that open the loop. Phase 0.1 (Vision) reads or
  creates `VISION.md` and uses the `brainstorming` dialogue to flesh it out,
  looping until the user signals done brainstorming. Phase 0.2 (Requirements)
  invokes `spec-driven` to write or edit `REQUIREMENTS.md` from the vision,
  looping until the user signals requirements are done. Everything from Phase 1
  onward stays autonomous, breaking only when a downstream skill needs input.
- `build-autonomous`: fix the dangling "approved spec from Phase 0" references to
  point at `VISION.md`/`REQUIREMENTS.md`; update the description, Key Constraints,
  Invocation Pattern, and Success Criteria to reflect the two gates.
- Docs: add a "The `build-autonomous` loop" section to the README explaining the
  two interactive gates and the autonomous handoff.

## v1.2.0

- Add the `api-canary` skill: discover every externally exposed API endpoint
  (HTTP/REST, gRPC, GraphQL, WebSocket) from contracts or route registrations,
  then generate a standalone black-box canary test framework that probes the
  live service from outside the deployment boundary — additive to in-repo tests,
  with smoke/contract/auth/negative/latency tiers, a continuous synthetic-monitor
  runtime, and endpoint drift detection. Plugin now ships 41 skills.
- `build-autonomous`: wire `test-as-guardrails` explicitly into the flow —
  mandatory for test planning (Phase 3) and implementation (Phase 5), with the
  three-context anti-gaming workflow, the edge-case matrix, and a sub-30s smoke
  suite run at each phase gate.
- `build-autonomous`: wire `api-canary` into the flow for projects that expose a
  network API — plan the canary in Phase 3, generate the module alongside code in
  Phase 5, and run its smoke/contract tiers plus a drift check in the Phase 6
  integration gate.
- Docs: add the `api-canary` row and correct the skills-summary count to 41.

## v1.1.2

- Remove the `codebase-memory` skill and its `codebase-memory-mcp` dependency.
  The skill was inert without the external MCP server (and its `cbm-*` discovery
  hooks), which is not bundled with the plugin. Plugin now ships 40 skills.
- Docs: drop stale pre-launch planning notes (`docs/DESIGN.md`, `docs/PLAN.md`,
  `docs/recommendation.md`) that referenced the old repo name, the removed skill,
  and superseded install commands. Correct the skills-summary count.
- Fix the marketplace listing to reference `gherlein/gherlein-claude-plugin`.

## v1.1.1

- Make the `clean-comments` skill description self-contained (remove the foreign
  plugin-namespace reference) so it passes `scripts/check-self-contained.sh`.

## v1.1.0

- Attribution: add `LICENSE` (MIT) and `NOTICE.md` crediting the upstream
  Superpowers project (Jesse Vincent / obra, MIT) for the twelve derived skills.
- Vendor a pristine, pinned snapshot of `obra/superpowers` at
  `f268f7c953744036f0fa7e9d4b73535c04e57cb8` under `vendor/superpowers/` as the
  attribution baseline and controlled-refresh diff target.
- Add `source:`/`license:` provenance frontmatter to each derived skill.
- Self-containment: rewrite `superpowers:` references to `gherlein:`; repoint the
  code-reviewer dispatch to a `general-purpose` subagent with the bundled
  `code-reviewer.md` template; de-namespace the optional `elements-of-style`
  reference.
- Add `scripts/check-self-contained.sh` and a GitHub Actions workflow that fails
  the build on any foreign plugin-namespace reference in shipped skills.
- Fix stale repo names in `README.md` and `plugin.json` (was `claude-skills`;
  now `gherlein-claude-plugin`) and correct the install command to
  `gherlein@gherlein-marketplace`.
- Bundle the enforcement layer so the plugin is self-enforcing for anyone who
  installs it: add `using-superpowers` (proactive skill discovery) and
  `writing-skills` (skill authoring), both attributed to obra/superpowers, with
  `writing-skills/anthropic-best-practices.md` credited to Anthropic. Plugin now
  ships 41 skills.

## v1.0.0

- Initial gherlein skills plugin (39 skills).
