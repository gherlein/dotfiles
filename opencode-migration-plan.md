# OpenCode Migration Plan: dot-agents → opencode config

Source: `/external/dot-agents` (canonical Claude Code config)
Target: `/dotfiles/opencode/.config/opencode/` (stow-managed global opencode config)

---

## What "Superpowers" Are (and Why They're Still There)

The `using-superpowers` skill is a **meta-routing skill** — it enforces that the agent invokes relevant skills before responding to anything. Its job:

1. At session start, read `INDEX.md` to discover available skills
2. Before any response (even clarifying questions), check if a skill applies
3. If yes, invoke the `Skill` tool to load and follow that skill's instructions
4. It's the "discipline enforcement" layer that prevents the agent from free-styling instead of following the established workflows

**Why it's still in dot-agents**: dot-agents is the canonical upstream source repo — you haven't modified it, you've been installing FROM it. The `safe-install` script copies everything including `using-superpowers` to `~/.claude/skills/`. It's still there because it was never excluded.

**Why we don't need it in OpenCode**: OpenCode's `skill` tool natively exposes skill descriptions to the model at session start. The model selects the appropriate skill based on the description field — this is built into OpenCode's architecture. The `using-superpowers` enforcement loop is replaced by OpenCode's native discovery mechanism. The equivalent discipline is encoded in `AGENTS.md` as a reminder that skills exist.

---

## Capability Mapping

### What maps 1:1

| dot-agents | OpenCode | Notes |
|---|---|---|
| `CLAUDE.md` | `AGENTS.md` | Same role, minor format differences |
| `skills/<name>/SKILL.md` | `skills/<name>/SKILL.md` | Nearly identical format |
| Skill supporting files (`*.md`, scripts) | Same path under skill dir | Portable as-is |
| `security-rules/**` | `knowledge/security-rules/**` | Different location, same format |

### What maps with adaptation

| dot-agents | OpenCode | Notes |
|---|---|---|
| `Agent` tool (subagents) | `agents/subagents/` + `@mention` | Different invocation, same concept |
| Workflow skills (plan, debug, review) | `commands/` slash commands | Skills become commands |
| `orchestrate` skill | `agents/orchestrator.md` | Becomes a primary agent |
| `dispatching-parallel-agents` | `agents/orchestrator.md` | Subagent @mention model |
| `subagent-driven-development` | orchestrator agent workflow | Adapted to OpenCode subagent model |
| `build-autonomous` | orchestrator agent + commands | Partial — no full equivalence |

### What does not map over

| dot-agents | Reason |
|---|---|
| `using-superpowers` | Not needed — OpenCode skill discovery is native |
| `INDEX.md` routing table | Not needed — skill descriptions handle routing |
| Plan mode (`EnterPlanMode`) | OpenCode has no equivalent; use planner agent |
| `TaskCreate/TaskUpdate` (TodoWrite) | OpenCode has no built-in task tools |
| `writing-skills` skill | Claude Code-specific skill authoring guidance |
| `emoji` skill | Trivial; not worth porting |
| Brainstorming scripts (`server.js`, etc.) | Claude Code web browser integration, not applicable |

---

## Migration Phases

---

### Phase 1: Enrich AGENTS.md (from CLAUDE.md)

**Status**: Partially done — current AGENTS.md covers style, tools, languages, code rules, comments, security, workflow.

**Missing from current AGENTS.md** (needs to be added from dot-agents CLAUDE.md):
- Autonomous implementation protocol (phased execution with test gates)
- Three parallel review gates (spec compliance, design/architecture, security)
- Documentation hierarchy (specs over code; never delete specs)
- Project file conventions (PROJECT.md, REQUIREMENTS.md, docs/DESIGN.md)
- Gitignore policy (mandatory entries, language-specific patterns)
- Build commands (Makefile required, never run long-lived processes)
- LLM context conventions (`.llm/` directory, `todo.md`, read-only context)
- Architecture awareness section (embedded/SBC/cloud deployment targets)

**Action**: Edit `opencode/.config/opencode/AGENTS.md` to add these sections.

---

### Phase 2: Skills Migration (38 → ~30 skills)

OpenCode skill format uses only `name` and `description` in frontmatter (no other fields). Content and supporting files are identical.

**Frontmatter conversion**:
```yaml
# dot-agents (Claude Code)          # OpenCode
---                                   ---
name: foo                             name: foo
description: "..."                    description: "..."
disable-model-invocation: true        # drop this field
---                                   ---
```

#### Skills to copy verbatim (no changes needed)

These have no Claude Code-specific tool references:

| Skill | Notes |
|---|---|
| `go-performance` | Pure knowledge, portable |
| `go-usb` | Pure knowledge, portable |
| `postgresql` | Pure knowledge, portable |
| `rest-api-design` | Pure knowledge, portable |
| `web-frontend` | Pure knowledge, portable |
| `documentation` | Pure knowledge, portable |
| `learn` | Pure knowledge, portable |
| `onboard` | Pure knowledge, portable |
| `reverse-engineer` | Pure knowledge, portable |
| `spec-driven` | Pure knowledge, portable |
| `clean-comments` | Pure knowledge, portable |
| `code-review` | Pure knowledge, portable |
| `refactoring` | Pure knowledge, portable |
| `refine` | Pure knowledge, portable |
| `edge-case-discovery` | Pure knowledge, portable |
| `test-as-guardrails` | Pure knowledge, portable |
| `test-driven-development` | References `TodoWrite` — replace with "track tasks" |
| `verification-before-completion` | Pure knowledge, portable |
| `git-ops` | Pure knowledge, portable |
| `three-experts` | Pure knowledge, portable |
| `go-release` | Already created; review against source |

**Action**: Copy these skill directories from `/external/dot-agents/skills/` to `opencode/.config/opencode/skills/`, stripping non-standard frontmatter fields.

#### Skills needing adaptation

| Skill | What to change |
|---|---|
| `brainstorming` | Remove script references; keep the workflow/gate logic; drop visual-companion browser server |
| `writing-plans` | Keep as skill; references to `TodoWrite` → "update your task list" |
| `finishing-a-development-branch` | Replace `Skill tool` invocation language with OpenCode equivalents |
| `systematic-debugging` | Portable; references to `TodoWrite` → "track tasks"; keep supporting files |
| `evidence-based-debugging` | Same as above |
| `requesting-code-review` | Keep; references to Agent tool → `@mention` pattern |
| `receiving-code-review` | Pure knowledge, portable |
| `plan` / `plan-todo` | Convert to `commands/` slash commands (see Phase 4) |

#### Skills to convert to agents (Phase 3)

| Skill | Becomes |
|---|---|
| `orchestrate` | `agents/orchestrator.md` |
| `subagent-driven-development` | Workflow used by orchestrator agent |
| `dispatching-parallel-agents` | `agents/orchestrator.md` (merged) |
| `build-autonomous` | `agents/orchestrator.md` + `commands/build.md` |

#### Skills to drop

| Skill | Reason |
|---|---|
| `using-superpowers` | Not needed in OpenCode |
| `writing-skills` | Claude Code skill-authoring meta-skill, not applicable |
| `emoji` | Trivial; skip |
| `executing-plans` | Claude Code-specific (separate session + context handoff model); adapted into commands |

**Action**: Copy and adapt the above skills. The skill directory structure is:
```
opencode/.config/opencode/skills/
└── <skill-name>/
    ├── SKILL.md
    └── <supporting-files>.md
```

---

### Phase 3: Agents

Convert the multi-agent orchestration skills into OpenCode agents with proper permissions.

#### Primary agents (Tab-selectable)

**`agents/orchestrator.md`** — merges `orchestrate`, `dispatching-parallel-agents`, `build-autonomous`
```yaml
---
description: "Primary orchestrator. Decomposes complex multi-step projects, dispatches specialized subagents (@analyst, @builder, @tester, @reviewer), and synthesizes results."
model: anthropic/claude-opus-4-7
temperature: 0
---
```
Content: Merged from `orchestrate/SKILL.md` + parallel dispatch patterns, adapted for `@mention` invocation.

**`agents/planner.md`** — already created; review against `plan/SKILL.md` and `writing-plans/SKILL.md`

**`agents/reviewer.md`** — already created; review against `code-review/SKILL.md`

#### Subagents (invoked by orchestrator or @mention)

**`agents/subagents/analyst.md`** — from `onboard`/`reverse-engineer` skills
```yaml
---
description: "Code analyst. Use for understanding existing code, identifying patterns, and mapping architecture. Read-only — reports findings, does NOT edit."
model: anthropic/claude-sonnet-4-6
temperature: 0
permissions:
  read: allow
  glob: allow
  grep: allow
  edit: deny
  bash: deny
---
```

**`agents/subagents/builder.md`** — from `subagent-driven-development` implementer pattern
```yaml
---
description: "Implementation specialist. Use for writing and editing code per a specific task from a plan. Follows TDD. Works one task at a time."
model: anthropic/claude-sonnet-4-6
temperature: 0
permissions:
  read: allow
  edit: allow
  bash:
    "go test ./...": allow
    "go build ./...": allow
    "make test": allow
    "make build": allow
    "*": ask
---
```

**`agents/subagents/tester.md`** — from `test-driven-development` skill
```yaml
---
description: "Testing specialist. Use when new functions need tests or test coverage needs assessment. Writes tests only — does NOT modify production code."
model: anthropic/claude-sonnet-4-6
temperature: 0
permissions:
  read: allow
  edit:
    "**/*_test.go": allow
    "**/*.test.ts": allow
    "**/*.spec.ts": allow
    "**": deny
  bash:
    "go test ./...": allow
    "npm test": allow
    "*": deny
---
```

**`agents/subagents/debugger.md`** — from `systematic-debugging` and `evidence-based-debugging`
```yaml
---
description: "Debugging specialist. Use when there is a bug, test failure, or unexpected behavior. Investigates root cause before proposing any fix."
model: anthropic/claude-sonnet-4-6
temperature: 0
permissions:
  read: allow
  glob: allow
  grep: allow
  bash: ask
  edit: ask
---
```

---

### Phase 4: Commands

Convert workflow skills into slash commands.

#### Commands to create

| Command file | Source skill | Purpose |
|---|---|---|
| `commands/commit.md` | (already done) | Stage and commit |
| `commands/plan.md` | (already done) | Decompose task into implementation plan |
| `commands/review.md` | `code-review/SKILL.md` | Pre-merge code review |
| `commands/debug.md` | `systematic-debugging/SKILL.md` | Invoke debugger agent |
| `commands/test.md` | `test-driven-development/SKILL.md` | TDD workflow |
| `commands/finish.md` | `finishing-a-development-branch/SKILL.md` | Branch completion |
| `commands/brainstorm.md` | `brainstorming/SKILL.md` | Design gate before implementation |
| `commands/onboard.md` | `onboard/SKILL.md` | Ramp up on unfamiliar codebase |

---

### Phase 5: Security Rules → knowledge/

The 85+ security rule files are plain markdown and transfer without modification. They serve as on-demand context the model can be directed to load when working in a relevant domain.

**Target structure**:
```
opencode/.config/opencode/knowledge/security-rules/
├── _core/
│   ├── owasp-2025.md
│   ├── agent-security.md
│   ├── ai-security.md
│   ├── mcp-security.md
│   ├── rag-security.md
│   └── graph-database-security.md
├── languages/
│   └── go/, typescript/, python/, ...
├── frontend/
│   └── react/, nextjs/, ...
├── backend/
│   └── fastapi/, django/, langchain/, ...
├── containers/
│   └── docker/, kubernetes/, ...
├── cicd/
│   └── github-actions/, gitlab-ci/
├── iac/
│   └── terraform/, pulumi/
└── rag/
    └── (full rag subtree)
```

**AGENTS.md addition**: Add a section directing the model to load the relevant security-rules file when working in each domain:

```markdown
## Security Context Files

When working in these domains, load the relevant file from knowledge/security-rules/:
- Go code: languages/go/CLAUDE.md
- TypeScript/React: languages/typescript/CLAUDE.md + frontend/react/CLAUDE.md
- Kubernetes: containers/kubernetes/CLAUDE.md
- GitHub Actions: cicd/github-actions/CLAUDE.md
- General: _core/owasp-2025.md always applies
```

**Action**: Copy `/external/dot-agents/security-rules/` → `opencode/.config/opencode/knowledge/security-rules/`
The files named `CLAUDE.md` in dot-agents should be renamed to `RULES.md` for clarity (since CLAUDE.md has special meaning in Claude Code but not OpenCode).

---

### Phase 6: opencode.json Update

Expand the existing `opencode.json` with full config:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",

  // Default: ollama local model
  "model": "ollama/qwen3.5:35b-a3b-q4_k_m",

  "provider": {
    "ollama": {
      "npm": "@ai-sdk/openai-compatible",
      "options": { "baseURL": "http://localhost:11434/v1" },
      "models": {
        "qwen3.5:35b-a3b-q4_k_m": { "name": "Qwen3.5 35B MoE (default)", "tools": true },
        "qwen2.5-coder:32b":       { "name": "Qwen2.5 Coder 32B (coding)", "tools": true },
        "qwen2.5-coder:7b":        { "name": "Qwen2.5 Coder 7B (fast)",    "tools": true }
      }
    }
  },

  // Formatters
  "formatter": {
    "command": ["gofmt", "-w", "$FILE"]
  },

  // LSP
  "lsp": {
    "go": { "command": "gopls" }
  },

  // Permissions
  "permissions": {
    "bash": "ask",
    "edit": "allow",
    "read": "allow"
  },

  // Compaction
  "compaction": { "strategy": "auto" },

  "autoupdate": true
}
```

---

## Execution Checklist

When executing this plan (in a future session), work through these in order:

- [ ] **Phase 1**: Enrich `AGENTS.md` with missing sections from dot-agents CLAUDE.md
- [ ] **Phase 2a**: Copy verbatim skills (20 skills) from dot-agents to opencode skills/
- [ ] **Phase 2b**: Adapt skills with tool references (8 skills)
- [ ] **Phase 2c**: Drop excluded skills (using-superpowers, writing-skills, emoji)
- [ ] **Phase 3**: Create agents/ and subagents/ files (orchestrator, analyst, builder, tester, debugger)
- [ ] **Phase 4**: Create remaining commands/ files (review, debug, test, finish, brainstorm, onboard)
- [ ] **Phase 5**: Copy security-rules tree → knowledge/security-rules/, rename CLAUDE.md → RULES.md
- [ ] **Phase 6**: Update opencode.json with full config
- [ ] **Verify**: Run `stow opencode` and confirm symlinks are correct

---

## File References

- Source: `/external/dot-agents/`
- Target: `/dotfiles/opencode/.config/opencode/`
- Stow package: `opencode` (maps `.config/opencode/` → `~/.config/opencode/`)
- Install: `cd /dotfiles && stow opencode`
