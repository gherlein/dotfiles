# dot-agents Design

This document describes the architecture of the `dot-agents` repository: what it contains, how it is installed, how different AI coding agents read and use it, and the design decisions behind its structure.

---

## Purpose

`dot-agents` is a personal AI coding agent configuration repository. It provides:

- **Coding standards and preferences** that apply to every session with every agent
- **Workflow skills** — structured protocols for specific types of work (debugging, planning, code review, autonomous builds, etc.)
- **Security rules** — policy files organized by language and domain that agents read before writing code

The goal is a single source of truth for how AI coding agents should behave, installable in one command, maintainable as a normal git repository, and compatible with more than one agent.

---

## Repository Structure

```
dot-agents/
├── CLAUDE.md                    Agent instructions (primary config file)
├── INDEX.md                     Maps task types to skills and security rule files
├── README.md                    Human-readable project overview
├── docs/
│   └── DESIGN.md                This file
├── safe-install                 Installer script
├── secure-coding.md             Integration notes for the security rules library (informational)
├── skills/                      38 skill directories
│   ├── brainstorming/
│   │   ├── SKILL.md
│   │   ├── spec-document-reviewer-prompt.md
│   │   ├── visual-companion.md
│   │   └── scripts/
│   ├── subagent-driven-development/
│   │   ├── SKILL.md
│   │   ├── implementer-prompt.md
│   │   ├── spec-reviewer-prompt.md
│   │   └── code-quality-reviewer-prompt.md
│   └── ... (38 total)
└── security-rules/
    ├── _core/                   OWASP Top 10, agent security, AI/ML, MCP, RAG overview
    ├── languages/               Go, TypeScript, JavaScript, Python, C/C++, Rust, and more
    ├── frontend/                React, Next.js, Angular, Vue, Svelte
    ├── backend/                 FastAPI, Django, Flask, Express, LangChain, and more
    ├── containers/              Docker, Kubernetes
    ├── iac/                     Terraform, Pulumi
    ├── cicd/                    GitHub Actions, GitLab CI
    └── rag/                     Document processing, embeddings, vector stores, graph databases
```

---

## Installed Structure

`safe-install` deploys the repository contents to `~/.claude/`. After installation:

```
~/.claude/
├── CLAUDE.md                    Installed from repo CLAUDE.md
├── INDEX.md                     Installed from repo INDEX.md
├── skills/                      Installed from repo skills/
│   └── <skill-name>/
│       ├── SKILL.md
│       └── [supporting files]
└── security-rules/              Installed from repo security-rules/
    └── ...
```

Claude Code reads `~/.claude/CLAUDE.md` automatically at startup. All other files are read on demand — agents read `INDEX.md` to discover which skills and security rules apply to a given task, then load only those files.

**What `safe-install` does not touch:** `.credentials.json`, `history.jsonl`, `settings.json`, `stats-cache.json`, `cache/`, `projects/`, `tasks/`, `todos/`, and other operational data that Claude Code manages.

---

## Config File: CLAUDE.md

`CLAUDE.md` is the primary instruction file read by agents. It contains:

- **Repository purpose notice** — tells AI agents this is a source template, not the active config; changes should go to `~/.claude/`, not this repo
- **Developer profile** — tech stack, deployment targets, primary languages
- **Global preferences** — conciseness, no guessing, read before proposing, etc.
- **Code quality rules** — naming, error handling, DRY, KISS, interface design
- **Comment rules** — why not what, no commented-out code, no change-description comments
- **Security rules** — no secrets in commits, parameterized queries, input validation, HTTPS
- **Architecture awareness** — embedded (RP2040), SBC, cloud/K8s tiers and their constraints
- **Documentation hierarchy** — specs are primary artifacts; code is ephemeral
- **Project file conventions** — `PROJECT.md`, `docs/DESIGN.md`
- **Gitignore policy** — mandatory entries and language-specific patterns
- **Build conventions** — Makefile always, never run long-lived processes
- **Git commit rules** — stage individually, commit message format, no `--no-verify`
- **LLM context** — `.llm/` directory conventions
- **Workflow** — research → plan → execute → validate
- **Autonomous implementation protocol** — phased execution, review gate, remediation cycle
- **Skills & context files** — directs agents to read `~/.claude/INDEX.md` before starting tasks

---

## INDEX.md

`INDEX.md` is the routing table for the configuration. Before starting any task, agents read it to identify:

1. Which skills apply (by task type)
2. Which security rule files to read (by language, framework, and domain)

The index is organized into sections:

- **Planning & Orchestration** — plan, orchestrate, spec-driven, three-experts, etc.
- **Process & Workflow (Superpowers)** — the full workflow pipeline skills
- **Code Quality** — code-review, refactoring, testing, debugging
- **Language & Domain** — go-performance, postgresql, rest-api-design, web-frontend, etc.
- **Onboarding & Learning** — onboard, reverse-engineer, learn
- **Security Rule Files** — core rules, then organized by language, framework, container, CI/CD, and RAG

Agents load only what applies. The index is designed to be read quickly; it is not a document to be studied but a dispatch table to be consulted.

---

## The Skill System

### Skill File Format

Each skill is a directory under `skills/`. Every skill directory contains a `SKILL.md` file with YAML frontmatter:

```markdown
---
name: skill-name
description: "One-line description used by agents to decide whether the skill applies"
disable-model-invocation: true   # optional — hides skill from auto-invocation
---

# Skill Title

[Skill content: workflow steps, decision trees, checklists, prompt templates, examples]
```

Supporting files live alongside `SKILL.md` in the same directory:

```
subagent-driven-development/
├── SKILL.md                          Workflow and orchestration protocol
├── implementer-prompt.md             Template for dispatching an implementer
├── spec-reviewer-prompt.md           Template for dispatching a spec reviewer
└── code-quality-reviewer-prompt.md   Template for dispatching a quality reviewer
```

### What Skills Contain

Skills are not abstract principles. Each contains executable content:

- **Decision trees** (rendered as Graphviz dot diagrams) for when to use the skill and what path to follow
- **Step-by-step workflows** with clear preconditions and outputs
- **Prompt templates** for dispatching subagents or performing self-reviews
- **Checklists** used as review criteria
- **Examples** showing what good outputs look like
- **Red flags** listing what must never happen

### Capability-Detection Pattern

Several skills orchestrate work differently depending on whether the agent can dispatch subagents. These skills contain an **Execution Mode** section near the top that branches explicitly:

```markdown
## Execution Mode

**With subagents (Claude Code, Codex):**
- [subagent dispatch path]

**Without subagents (Pi, single-session agent):**
- [sequential self-review path using the same checklists, writing outputs to files]
```

Skills with this pattern include: `subagent-driven-development`, `dispatching-parallel-agents`, `requesting-code-review`, `brainstorming`, `writing-plans`, `orchestrate`, and `build-autonomous`. The subagent path is unchanged from its original design; the sequential path adds file-based output so findings are explicit and recoverable.

### The Workflow Pipeline

Skills compose into a development pipeline:

```
brainstorming
  → writing-plans
    → subagent-driven-development (with subagents)
    → executing-plans (without subagents)
      → finishing-a-development-branch
```

Discipline skills apply throughout regardless of which execution path is taken:

- `test-driven-development` — test-first mandatory in all implementation
- `systematic-debugging` — root cause required before any fix
- `verification-before-completion` — explicit gate before declaring work done

The `build-autonomous` skill is a top-level orchestrator that invokes this full pipeline from brainstorming through delivery, including the parallel review gate.

---

## How Claude Code Reads the Configuration

Claude Code is the primary agent target.

### Startup

At session start, Claude Code reads `~/.claude/CLAUDE.md` (global config) and any `CLAUDE.md` files in the project directory hierarchy. These are injected into the system prompt automatically.

### Skill Discovery and Invocation

Skills are loaded on demand, not pre-injected. Claude Code lists available skill names and descriptions from `~/.claude/skills/` in its context. When a task matches a skill's description, the agent invokes the skill using the built-in Skill tool, which injects the `SKILL.md` content into the conversation.

Users can invoke skills explicitly with `/skill-name`. Skills with `disable-model-invocation: true` in their frontmatter are only accessible via explicit invocation — they are not listed for autonomous selection.

### Security Rules

Security rules are plain markdown files. Agents read the applicable files via the `read` tool when directed by `INDEX.md`. They are not pre-injected; the agent fetches them when it identifies a coding task that warrants them.

### Layered Config Hierarchy

Claude Code supports a layered config model:

1. **Global** (`~/.claude/CLAUDE.md`) — applies to all projects; provided by this repo
2. **Project root** (`<project>/CLAUDE.md`) — project-specific build commands, architecture, conventions
3. **Subdirectory** (`<project>/<subdir>/CLAUDE.md`) — overrides for specific modules or subsystems

This repo provides layer 1. Each project then adds layers 2 and 3 with project-specific content, without duplicating the shared standards.

---

## How Pi Reads the Configuration

[Pi coding agent](https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent) is a second supported agent. It is model-agnostic, single-session by default, and has a minimal 4-tool set (`read`, `write`, `edit`, `bash`).

### Instruction File Discovery

Pi walks the directory tree from the current working directory up to the filesystem root, plus checks `~/.pi/agent/`. In each directory it looks for:

1. `AGENTS.md` — checked first
2. `CLAUDE.md` — fallback if `AGENTS.md` is absent

Since this repo ships only `CLAUDE.md`, Pi reads it as the fallback. If an `AGENTS.md` is added in the future to separate universal rules from Claude Code-specific rules, Pi will automatically prefer it.

### Skill Discovery

Pi lists available skills in its system prompt (name + description from each `SKILL.md`). It searches:

- `~/.pi/agent/skills/`
- `~/.agents/skills/` (agent-agnostic shared location)
- `.pi/skills/` (project-level)
- `.agents/skills/` (project-level)

Skills are loaded lazily: Pi decides a skill applies based on its description, then calls the `read` tool to load the `SKILL.md` file into context. No pre-injection.

Users can invoke a skill explicitly with `/skill:name`.

### Single-Session Execution

Pi has no native subagent dispatch. Skills with capability-detection branches automatically route Pi to the sequential self-review path:

- Instead of dispatching a reviewer subagent, Pi reads the reviewer prompt file and applies it as a checklist to its own work
- Findings are written to `.llm/reviews/<name>.md` so they are explicit and traceable
- The task structure, quality gates, and output files are identical to the subagent path — only the execution mechanism differs

### Tool Set Differences

| Capability | Claude Code | Pi |
|---|---|---|
| Subagent dispatch | Yes (Agent tool) | No |
| Plan mode | Built-in | Use PLAN.md files |
| Task tracking | Built-in todo tools | Use TODO.md files |
| Web fetch/search | Built-in | Via `bash` + CLI tools |
| MCP servers | Full support | Not supported (use CLI tools instead) |
| Provider support | Primarily Anthropic | 18+ providers |

---

## Multi-Agent Compatibility Summary

| Concern | Status |
|---|---|
| Instruction file (`CLAUDE.md`) | Works in both — Pi reads `CLAUDE.md` as `AGENTS.md` fallback |
| Skill file format | Identical — same YAML frontmatter, same `SKILL.md` convention |
| Skill invocation | Different mechanism, same result — Skill tool (Claude Code) vs. `read` tool + `/skill:name` (Pi) |
| Subagent skills | Capability-detected — both paths produce the same file outputs |
| Security rules | Plain markdown — readable by any agent via file read |
| `safe-install` | Currently targets `~/.claude/` only — Pi install requires manual copy to `~/.pi/agent/` or `~/.agents/` |

---

## safe-install

The installer is a bash script with no dependencies beyond standard POSIX tools.

**Global install** (`./safe-install`):
- Installs `CLAUDE.md` → `~/.claude/CLAUDE.md`
- Installs `skills/` → `~/.claude/skills/` (preserves user-created skills not in this repo)
- Installs `INDEX.md` → `~/.claude/INDEX.md`
- Installs `security-rules/` → `~/.claude/security-rules/`
- Creates a timestamped backup of any existing config before overwriting

**Project install** (`./safe-install /path/to/project`):
- Installs `CLAUDE.md` → `<project>/CLAUDE.md`
- Installs `skills/` → `<project>/.claude/skills/`
- `INDEX.md` and `security-rules/` are always installed globally, even during project install

**What it does not touch:** `.credentials.json`, `history.jsonl`, `settings.json`, `stats-cache.json`, `cache/`, `projects/`, `session-env/`, `tasks/`, `todos/`, and all other Claude Code operational data.

---

## Design Decisions

### Why a separate repo rather than dotfiles?

AI agent config files share no tooling with shell dotfiles. They have different installation targets, different formats, and need to be versioned and distributed independently. A dedicated repo makes the structure explicit and the install safe.

### Why not `AGENTS.md` as the primary file?

`CLAUDE.md` is what Claude Code reads natively. Pi reads `AGENTS.md` first but falls back to `CLAUDE.md`, so the current single-file setup works for both without duplication. If the content is ever split into universal (`AGENTS.md`) and Claude-specific (`CLAUDE.md`) parts, `safe-install` can distribute both.

### Why so many skills?

Skills are loaded on demand — a session that involves only Go debugging loads only `systematic-debugging` and `evidence-based-debugging`. The full set of 38 skills has no cost at session start. The benefit is having a complete, consistent workflow protocol for every class of task without relying on the agent to reconstruct it from first principles each time.

### Why file-based outputs for sequential reviews?

When the same agent that writes code also reviews it, writing findings to files (`*.llm/reviews/*.md`) serves two purposes: it forces systematic coverage of the checklist (the agent cannot skip sections), and it produces a traceable artifact that a human can inspect. This partially compensates for the lack of fresh-context isolation that subagent reviewers provide.

### Why keep both Claude Code and Pi paths rather than standardizing on sequential?

Subagent review provides genuinely different guarantees — a fresh context window with no history of the implementation. For security reviews and spec compliance checks, that adversarial independence has real value. Discarding it when running in Claude Code would be a quality regression. The capability-detection pattern preserves the quality ceiling while extending compatibility downward.
