# OpenCode Agent Configuration Guide

A comprehensive reference for structuring `.opencode/` directories, writing agents, commands, skills, and rules — with best practices.

---

## Table of Contents

- [Directory Structure](#directory-structure)
- [Config Loading Order](#config-loading-order)
- [opencode.json / opencode.jsonc](#opencodejson--opencodejsonc)
- [AGENTS.md — Rules & Instructions](#agentsmd--rules--instructions)
- [Agents](#agents)
- [Commands](#commands)
- [Skills](#skills)
- [Plugins](#plugins)
- [Multi-Agent Swarms](#multi-agent-swarms)
- [Best Practices](#best-practices)

---

## Directory Structure

OpenCode merges configuration from two root locations:

### Global (`~/.config/opencode/`)

User-level config applied across all projects.

```
~/.config/opencode/
├── opencode.jsonc          # Global config: default model, MCP servers, permissions, theme
├── AGENTS.md               # Global rules: personal workflow preferences, tool guidance
├── agents/                 # Global agent definitions (markdown files)
│   ├── planner.md
│   └── reviewer.md
├── commands/               # Global slash commands
│   ├── commit.md
│   └── debug.md
├── skills/                 # Global skills (injectable knowledge packages)
│   └── go-release/
│       └── SKILL.md
├── tools/                  # Custom MCP tool definitions
├── plugins/                # Orchestration plugins (TypeScript)
│   └── swarm.ts
└── knowledge/              # Freeform context files loaded on demand
    ├── tdd.md
    └── kubernetes.md
```

### Project (`.opencode/`)

Committed to the repository. Shared with the team. Overrides global config.

```
.opencode/
├── opencode.json           # Project config: model override, MCP, instructions, formatter
├── agents/                 # Project-specific agents
│   ├── reviewer.md
│   └── subagents/
│       ├── analyst.md
│       ├── builder.md
│       └── tester.md
├── commands/               # Project-specific slash commands
│   ├── commit.md
│   ├── plan.md
│   └── deploy.md
└── skills/
    └── release/
        └── SKILL.md
```

> **Note:** Both plural (`agents/`) and singular (`agent/`) subdirectory names are supported. Prefer plural — it's the canonical form.

---

## Config Loading Order

Later sources override earlier ones. Last write wins.

```
1. Remote config    (.well-known/opencode)      — org-enforced defaults
2. Global config    (~/.config/opencode/)        — user preferences
3. Custom config    ($OPENCODE_CONFIG env var)   — ad-hoc overrides
4. Project config   (.opencode/)                 — project/team settings
```

**Implication:** Put defaults in global, put project-specific overrides in `.opencode/`. Never duplicate settings that belong at global scope in every project.

You can also set `OPENCODE_CONFIG_DIR` to point to a separate config tree (same structure as `.opencode/`) for shared team configs outside of a single repo.

---

## opencode.json / opencode.jsonc

The primary config file. Supports JSONC (comments). Always include the schema ref for editor autocomplete.

### Minimal project config

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "model": "anthropic/claude-sonnet-4-5"
}
```

### Full example

```jsonc
{
  "$schema": "https://opencode.ai/config.json",

  // Default model for this project
  "model": "anthropic/claude-sonnet-4-5",

  // Instruction files merged with AGENTS.md
  "instructions": [
    "docs/development-standards.md",
    "test/testing-guidelines.md",
    "packages/*/AGENTS.md"           // glob patterns supported
  ],

  // MCP servers
  "mcp": {
    "github": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"]
    }
  },

  // Code formatter (runs automatically after edits)
  "formatter": {
    "command": ["gofmt", "-w", "$FILE"]
  },

  // LSP servers
  "lsp": {
    "go": {
      "command": "gopls"
    }
  },

  // Global permission defaults
  "permissions": {
    "bash": "ask",
    "edit": "allow",
    "read": "allow"
  },

  // Context compaction strategy
  "compaction": {
    "strategy": "auto"
  },

  // Autoupdate behavior
  "autoupdate": true
}
```

### Global user config example (`~/.config/opencode/opencode.json`)

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "theme": "opencode",
  "autoupdate": true,
  "model": "anthropic/claude-sonnet-4-5",

  // Personal MCP servers (not project-specific)
  "mcp": {
    "filesystem": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

---

## AGENTS.md — Rules & Instructions

Plain markdown files that inject context into every session. Equivalent to CLAUDE.md if migrating from Claude Code.

### Locations

| File | Scope | Committed? |
|---|---|---|
| `~/.config/opencode/AGENTS.md` | All sessions for this user | No |
| `./AGENTS.md` | This project, all team members | Yes |
| `packages/*/AGENTS.md` | Per-package rules (via `instructions` glob) | Yes |

The first matching file wins per location. If both `AGENTS.md` and `CLAUDE.md` exist, `AGENTS.md` takes precedence.

### Example project AGENTS.md

```markdown
# My Project

This is a Go monorepo with services under `cmd/` and shared packages under `pkg/`.

## Project Structure

- `cmd/` — service entrypoints (one dir per binary)
- `pkg/` — shared libraries
- `internal/` — private packages not exported outside this module
- `deploy/` — Kubernetes manifests

## Code Standards

- Idiomatic Go; follow stdlib conventions
- Error wrapping: `fmt.Errorf("context: %w", err)`
- No `init()` functions
- Tests alongside source files (`_test.go`)
- Table-driven tests with `t.Run`

## Workflow

- Run `make test` before declaring a task done
- Commit messages: `type(scope): short description` (Conventional Commits)
- Never commit directly to `main`
```

### Example global AGENTS.md (`~/.config/opencode/AGENTS.md`)

```markdown
# Global Preferences

## Style

- Be concise. Skip preambles and "Sure!" affirmations.
- Prefer working code over explanation prose.
- Never give time estimates unless asked.

## Tools

- Container runtime: podman (not docker)
- Shell navigation: zoxide (`z`), not `cd`
- Pass directories as arguments, don't `cd` into them

## Languages

- Primary: Go (idiomatic, stdlib conventions)
- Frontend: TypeScript with modern frameworks
- Avoid Python unless the ecosystem demands it
```

### Loading external files from AGENTS.md

OpenCode doesn't auto-parse `@file` references, but you can instruct the model to read them:

```markdown
## External Standards

CRITICAL: When you start a session, read the following file immediately:
`docs/architecture-decisions.md`

When working on infrastructure tasks, also read:
`deploy/README.md`
```

The recommended approach for multi-file projects is the `instructions` field in `opencode.json` instead.

---

## Agents

Agents are markdown files with YAML frontmatter. The filename (without extension) becomes the agent name.

### Locations

```
~/.config/opencode/agents/   # global agents
.opencode/agents/            # project agents
.opencode/agents/subagents/  # subagents (invoked by primary agents or @mention)
```

### Frontmatter fields

```yaml
---
description: "Brief description. This is shown in the agent picker and used by primary agents to decide when to invoke this subagent. Required."
model: anthropic/claude-opus-4-5   # optional: override model for this agent
temperature: 0                     # optional: 0 = deterministic, higher = creative
max_turns: 20                      # optional: cap agentic iterations (cost control)
permissions:
  read: allow
  edit: ask
  bash: deny
  glob: allow
  grep: allow
---
```

### Permission values

Each permission key accepts: `"allow"`, `"ask"`, or `"deny"`.
Fine-grained control with glob patterns:

```yaml
permissions:
  edit:
    "**/*.go": allow
    "**/*.md": ask
    "**": deny         # deny everything else
  bash: ask
  read: allow
```

MCP tool permissions follow the same pattern:

```yaml
permissions:
  "github_*": allow    # allow all github MCP tools
  "slack_*": deny      # deny all slack MCP tools
```

### Primary agent example (`.opencode/agents/reviewer.md`)

```markdown
---
description: "Code review specialist. Use for PR reviews, quality checks, and identifying logic errors. Does NOT make edits."
model: anthropic/claude-opus-4-5
temperature: 0
permissions:
  read: allow
  glob: allow
  grep: allow
  edit: deny
  bash: deny
---

You are a code reviewer. Your job is to identify:

1. Logic errors and edge cases
2. Missing or inadequate error handling
3. Non-idiomatic patterns for the language in use
4. Missing tests for meaningful code paths
5. Security concerns

Provide structured feedback. Reference specific file paths and line numbers.
Do NOT make edits — report findings only.
```

### Subagent example (`.opencode/agents/subagents/tester.md`)

```markdown
---
description: "Testing specialist. Invoked when new functions need tests or when test coverage needs to be assessed."
model: anthropic/claude-sonnet-4-5
temperature: 0
max_turns: 15
permissions:
  read: allow
  edit:
    "**/*_test.go": allow
    "**": deny
  bash:
    "go test ./...": allow
    "*": deny
---

Write table-driven tests using `t.Run`. Cover:
- Happy path
- Error cases
- Edge cases (nil, empty, boundary values)

Use `testify/assert` only if already present in `go.mod`. Otherwise use stdlib `testing`.
Never modify non-test files.
```

### Using agents

- **Primary agents:** Cycle with `Tab` during a session.
- **Subagents:** `@mention` in your message (e.g., `@tester add tests for the new handler`), or primary agents invoke them automatically based on `description`.
- **Set default agent** in `opencode.json`:
  ```json
  { "agent": "build" }
  ```

---

## Commands

Slash commands for repetitive workflows. The filename becomes the command name.

### Locations

```
~/.config/opencode/commands/   # global commands
.opencode/commands/            # project commands
```

### Define in opencode.json

```jsonc
{
  "command": {
    "test": {
      "description": "Run tests with coverage",
      "template": "Run the full test suite with `go test -race -coverprofile=coverage.out ./...`. Show failures and suggest fixes.",
      "agent": "build",
      "model": "anthropic/claude-haiku-4-5"   // use a fast model for quick tasks
    },
    "component": {
      "description": "Scaffold a new Go service",
      "template": "Create a new service named $ARGUMENTS under cmd/. Include main.go, a Dockerfile, and a basic health check HTTP handler."
    }
  }
}
```

`$ARGUMENTS` receives whatever the user types after the slash command.

### Define as markdown files

```
.opencode/commands/commit.md
.opencode/commands/plan.md
.opencode/commands/deploy.md
```

Example `.opencode/commands/commit.md`:

```markdown
---
description: "Stage all changes, write a Conventional Commit message, and commit."
agent: build
---

1. Run `git diff --staged` to see what's staged. If nothing is staged, run `git add -A` first.
2. Analyze the changes and write a commit message following Conventional Commits:
   `type(scope): short description`
   Types: feat, fix, chore, docs, refactor, test, ci
3. Run `git commit -m "<message>"`.
4. Show the resulting commit hash.
```

Example `.opencode/commands/plan.md`:

```markdown
---
description: "Decompose a feature request into a step-by-step implementation plan before writing any code."
agent: plan
temperature: 0.3
---

Analyze the request and produce a numbered implementation plan:

1. Identify all files that need to change
2. List new types/interfaces required
3. Describe each change in one sentence
4. Flag any unknowns or design decisions needed

Do NOT write code yet. Wait for approval before proceeding.
```

---

## Skills

Skills are injectable, structured knowledge packages that the agent loads on demand via the `skill` tool.

### Structure

```
.opencode/skills/
└── <skill-name>/
    └── SKILL.md
```

### SKILL.md frontmatter

```yaml
---
name: go-release
description: "Step-by-step process for tagging and publishing a new Go module release. Use when preparing a versioned release."
---
```

Only `name` and `description` are recognized. The `description` is what the agent sees in the skill tool listing — write it to describe *when* to use the skill, not just what it is.

### Example skill: `.opencode/skills/go-release/SKILL.md`

```markdown
---
name: go-release
description: "Use when preparing a tagged release of a Go module or service. Covers versioning, changelog, tagging, and pushing."
---

# Go Release Process

## Prerequisites

- All tests passing: `go test -race ./...`
- No uncommitted changes: `git status`
- `CHANGELOG.md` is up to date

## Steps

1. Determine the new version (semver): `git tag | sort -V | tail -1`
2. Update `CHANGELOG.md` — add a section for the new version
3. Commit the changelog: `git commit -m "chore: release v<VERSION>"`
4. Tag: `git tag -a v<VERSION> -m "Release v<VERSION>"`
5. Push: `git push origin main --tags`

## Version Bumping Rules

- `patch` — bug fixes only
- `minor` — new backward-compatible features
- `major` — breaking API changes

## Verification

After push, confirm the tag appears: `git ls-remote --tags origin`
```

---

## Plugins

Plugins extend OpenCode with custom tools and orchestration. Written in TypeScript.

### Location

```
~/.config/opencode/plugins/
.opencode/plugins/
```

### Loading

Via config:

```jsonc
{
  "plugin": ["./plugins/my-plugin.ts"]
}
```

Or place files directly in `plugins/` — they're auto-loaded.

Plugins can also be loaded from npm:

```jsonc
{
  "plugin": ["@myorg/opencode-plugin-deploy"]
}
```

---

## Multi-Agent Swarms

Swarms decompose work into parallel specialized subagents coordinated by a primary agent.

### Recommended layout

```
.opencode/
├── agents/
│   ├── orchestrator.md        # primary: decomposes tasks, spawns workers
│   └── subagents/
│       ├── analyst.md         # reads code, identifies patterns
│       ├── builder.md         # writes and edits code
│       ├── tester.md          # writes tests only
│       ├── reviewer.md        # reads only, reports issues
│       └── documentation.md   # writes docs and comments
├── commands/
│   ├── swarm.md               # kick off a swarm workflow
│   └── swarm-abort.md         # abort and clean up
└── plugins/
    └── swarm.ts               # orchestration logic
```

### Orchestrator agent example

```markdown
---
description: "Primary orchestrator. Decomposes complex tasks into parallel workstreams and delegates to specialist subagents."
model: anthropic/claude-opus-4-5
temperature: 0
---

You coordinate complex tasks by:

1. Analyzing the request and breaking it into independent subtasks
2. Assigning each subtask to the appropriate specialist:
   - `@analyst` for understanding existing code
   - `@builder` for implementing changes
   - `@tester` for writing tests
   - `@reviewer` for quality checks
3. Synthesizing results and reporting back

Always produce a plan before delegating. Never do implementation work yourself.
```

### Navigation

- From a parent session: `<Leader>+Down` to enter the first child session
- From a child session: navigate back to the parent

---

## Best Practices

### Structure

- **Commit `.opencode/` to the repo.** Project agents, commands, and skills benefit the whole team.
- **Keep global config lean.** Only personal preferences and credentials belong in `~/.config/opencode/`.
- **Use `subagents/` subdirectory** for agents that should only be invoked by other agents or `@mention`, not selectable as primary agents via `Tab`.
- **One responsibility per agent.** An agent that reviews and also edits will do both poorly.

### Agents

- **Write `description` as an invocation trigger**, not a capability summary. The orchestrator uses the description to decide when to call this agent. "Use when..." works better than "An agent that...".
- **Set `temperature: 0`** for agents doing deterministic tasks (code review, test writing, builds). Reserve higher temperatures for planning and brainstorming agents.
- **Use `max_turns`** on subagents doing bounded tasks. Prevents runaway cost on loops.
- **Restrict permissions tightly** for specialized agents. A test writer doesn't need bash access to production deploy scripts.
- **Never give a reviewer `edit` permission.** If it can edit, it will edit instead of reporting.

### Commands

- **Use a fast model** (`claude-haiku`) for commands that are repetitive and mechanical (commit messages, formatting, simple scaffolding). Reserve Sonnet/Opus for complex reasoning tasks.
- **Use `$ARGUMENTS`** to make commands reusable (e.g., scaffold a component by name).
- **End commands with an explicit success criterion** so the agent knows when to stop.

### AGENTS.md / Instructions

- **Global AGENTS.md = personal conventions.** Don't commit personal preferences into project AGENTS.md.
- **Project AGENTS.md = shared team context.** Keep it factual: structure, conventions, tooling, workflow.
- **Use `instructions` globs in opencode.json** for monorepos with per-package standards rather than a single giant AGENTS.md.
- **Keep AGENTS.md scannable.** The model reads it every session. Dense walls of text reduce signal.
- **Avoid contradiction.** A global AGENTS.md saying "never use Docker" and a project AGENTS.md saying "use Docker Compose for dev" will cause confusion.

### Skills

- **One skill = one well-defined procedure.** Not a general reference dump.
- **Write `description` to answer "when do I need this?"** Skills are listed in the tool — the description is what the agent uses to decide whether to load the skill.
- **Keep skills actionable.** Step-by-step numbered instructions work better than prose.
- **Skills are not AGENTS.md.** AGENTS.md is always loaded. Skills are loaded on demand. Put always-relevant context in AGENTS.md; put specialized procedures in skills.

### Models

- Use expensive models (Opus) for orchestrators and complex reasoning agents.
- Use fast models (Haiku) for mechanical subagents and slash commands.
- Set the model per-agent, not globally, when agents have different complexity requirements.

### Permissions

- Default to `"ask"` for `bash` at the global level.
- Use glob-based permissions to allow `bash` for specific safe commands in build agents:
  ```yaml
  bash:
    "go test ./...": allow
    "go build ./...": allow
    "*": ask
  ```
- Deny `edit` for reviewer and analyst agents unconditionally.
- Deny `.env` reads unless explicitly required — OpenCode denies them by default.

### Monorepo layout

```
repo-root/
├── AGENTS.md                      # top-level project context
├── opencode.json                  # or .opencode/opencode.json
├── packages/
│   ├── api/
│   │   └── AGENTS.md              # api-specific standards
│   └── web/
│       └── AGENTS.md              # frontend-specific standards
└── .opencode/
    ├── agents/
    └── commands/
```

```jsonc
// opencode.json
{
  "instructions": [
    "AGENTS.md",
    "packages/*/AGENTS.md"
  ]
}
```

---

## Quick Reference

| What | Where | Committed? |
|---|---|---|
| User model/theme/MCP defaults | `~/.config/opencode/opencode.jsonc` | No |
| Personal workflow rules | `~/.config/opencode/AGENTS.md` | No |
| Project model/instructions/MCP | `.opencode/opencode.json` | Yes |
| Shared team rules | `./AGENTS.md` | Yes |
| Primary agents (Tab-selectable) | `.opencode/agents/*.md` | Yes |
| Subagents (@mention or auto) | `.opencode/agents/subagents/*.md` | Yes |
| Slash commands | `.opencode/commands/*.md` | Yes |
| On-demand procedures | `.opencode/skills/<name>/SKILL.md` | Yes |
| Orchestration plugins | `.opencode/plugins/*.ts` | Yes |
