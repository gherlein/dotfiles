# Local Inference Best Practices

Reference for configuring opencode agents, commands, skills, and AGENTS.md when running local models via ollama. These practices differ significantly from cloud model (Claude, GPT-4) workflows.

---

## The Core Problem

Local models have three fundamental constraints that require different patterns than cloud models:

1. **Context fills up and degrades reasoning** — performance drops sharply after ~60% context saturation. The model becomes agreeable, forgets instructions, skips verification, and accepts previously rejected ideas. This happens silently.
2. **Models are less capable** — local models hallucinate more, struggle with multi-step reasoning, and need more explicit, structured prompts to stay on track.
3. **No persistent memory between sessions** — every new session starts cold. Information not written to disk is lost.

---

## Context Window Management

### The 60% Rule

Never let context fill past ~60% of the model's window. Signs you've crossed the threshold:
- Model stops asking clarifying questions
- Model accepts ideas it rejected earlier in the session
- Model forgets constraints mentioned multiple times
- Model rushes to "complete" the task, skipping verification
- Outputs become shorter and less thorough

When you see these signs: **stop, summarize, start a new session**.

### Context is a Scarce Resource

Treat every token as expensive:
- Load files lazily — read on demand, don't pre-load everything
- Don't quote large files into prompts — reference paths, let the tool read them
- Keep AGENTS.md concise — it loads every session
- Use `knowledge/` files for domain content that is only sometimes relevant
- Use skills for procedural content — load only when needed

### Compaction Strategy

Use **dynamic summarization** for long sessions:
- Keep the last few turns verbatim
- Summarize everything older into a living summary
- Update the summary incrementally rather than discarding old messages
- For technical/coding work: prefer verbatim retention of exact values (file paths, error strings, config values) over compression

The `"compaction": { "strategy": "auto" }` setting in `opencode.json` handles this, but it triggers late. Don't rely on it — proactively start new sessions.

### `OLLAMA_KEEP_ALIVE`

Set this in your environment to prevent the model from unloading between agent turns:

```bash
export OLLAMA_KEEP_ALIVE=-1
```

Without it, ollama unloads the model after inactivity, causing reload latency on every turn.

---

## Task Decomposition

### One Task Per Session

Each agent session should do exactly ONE thing with ONE clearly defined output. No "and also" tasks. If a task has multiple parts, decompose it first (in a short planning session), write the plan to a file, then execute each step in its own session.

**Bad**: "Refactor the auth package and add tests and update the docs"
**Good**: Step 1: write plan to `.llm/plan.md`. Step 2: refactor auth (one session). Step 3: add tests (one session). Step 4: update docs (one session).

### Write the Plan First

Before any implementation session, write a numbered plan to a file (`.llm/plan.md` or `.opencode/plan.md`). This serves two purposes:
1. If context runs out mid-task, the next session can resume from the file
2. It forces decomposition into atomic steps before touching code

Each plan step should be completable in a single session without exceeding 40% context.

### Atomic Steps

A step is atomic if it:
- Changes at most 2-3 files
- Has a single, binary success criterion (`make test` passes, or it doesn't)
- Can be fully described in 2-3 sentences

If a step can't be described in 2-3 sentences, split it further.

---

## Handoff Documents

When a task spans multiple sessions (almost always), write a handoff document before ending the session. Store in `.llm/handoff.md`.

### Handoff Document Format

```markdown
# Handoff: <task name>

## Status
<one sentence: what state the codebase is in right now>

## What Was Done
- <specific change 1, with file path>
- <specific change 2, with file path>

## What Is Next
1. <next step — specific, atomic>
2. <step after that>

## Open Questions
- <anything unresolved that the next session needs to decide>

## Key Files
- `path/to/file.go` — <why it matters>

## Git State
<output of `git log --oneline -5`>
```

### What Makes a Good Handoff

- Include exact file paths, not vague descriptions
- Include the git hash — so the next agent knows the starting state
- List open questions explicitly — don't assume the next agent will figure them out
- Keep next steps atomic — if step 1 of "what's next" takes more than one session, decompose it
- Reference original evidence (test output, error messages) rather than compressed summaries

---

## Agent Configuration for Local Models

### `max_turns`

Set `max_turns` conservatively. Local models loop and accumulate context fast:

| Agent type | Recommended `max_turns` |
|---|---|
| Analyst / read-only | 15 |
| Builder (focused task) | 10 |
| Tester | 10 |
| Debugger | 12 |
| Orchestrator | 8 |

After `max_turns`, the agent stops and returns. The user decides what to do next. This is better than letting context bloat until the model degrades.

### `temperature`

Local models produce more reliable outputs at lower temperatures:
- All coding, testing, debugging agents: `temperature: 0`
- Planning and brainstorming: `temperature: 0.3` (not higher)
- No agent needs a temperature above 0.5

### Agent Scope

Each agent must have a single, narrow responsibility. A local model asked to "review and also fix and also write tests" will do all three poorly. One agent, one job.

Restrict permissions tightly per agent:
- Analysts: `edit: deny`, `bash: deny` — read-only, report only
- Builders: allow only `go test`, `go build`, `make test`, `make build`
- Testers: edit only `*_test.go` files, run only `go test ./...`
- Reviewers: `edit: deny` always — if a reviewer can edit, it will edit instead of reporting

---

## Prompt Engineering for Local Models

Local models are less capable than Claude/GPT-4 at following abstract guidance. They need:

### Be Explicit, Not Abstract

**Cloud model instruction**: "Write idiomatic Go"
**Local model instruction**: "Write Go following these rules: (1) use named returns only when they add clarity, (2) handle every error explicitly with `fmt.Errorf`, (3) prefer table-driven tests with `t.Run`, (4) no `init()` functions"

### Numbered Steps, Not Prose

Local models follow numbered lists better than paragraphs. Every skill and command should use numbered steps for procedures, not prose descriptions.

### State Success Criteria Explicitly

Every task description should end with an explicit success criterion:
- "Task is complete when `make test` exits 0 and `git diff --name-only` shows only the expected files."
- "Task is complete when the function exists, has a test, and the test passes."

Without an explicit success criterion, local models often declare victory prematurely.

### Repeat Critical Constraints

Local models forget constraints as context grows. Put the most important constraints at the top AND the bottom of the instruction:

```
CONSTRAINT: Do not modify files outside pkg/auth/
[... instructions ...]
REMINDER: Only modify files inside pkg/auth/
```

### Avoid Open-Ended Questions in Commands

Instead of "review the code", say "review the code and list issues in three categories: (1) correctness, (2) missing error handling, (3) missing tests. Output as a numbered list. Do not suggest refactors or style changes."

---

## Model Selection

### Task Routing

Route tasks by complexity, not by default:

| Task type | Model size | Rationale |
|---|---|---|
| Commit messages, formatting | 7B | Mechanical, structured output |
| Simple file edits, single-function changes | 7B–14B | Narrow scope, clear spec |
| Multi-file refactors, debugging | 32B | Needs reasoning across context |
| Architecture planning, complex debugging | 32B–70B | High reasoning requirement |
| Code review (full PR) | 32B | Needs comprehensive understanding |

Running multiple 7B instances on the same compute budget can match a single 70B for distributed, parallel tasks.

### For This Setup (Qwen Models)

- `qwen2.5-coder:7b` — commit messages, simple edits, test scaffolding
- `qwen2.5-coder:32b` — multi-file work, debugging, reviews
- `qwen3.5:35b-a3b-q4_k_m` — planning, architecture, complex reasoning

Set `model` per-agent in frontmatter, not globally. The default in `opencode.json` should be the medium model.

---

## Verification

Local models skip verification steps under context pressure. Build verification in structurally.

### Required Verification Pattern

Every builder/tester agent instruction must include:
1. Run the relevant tests (`make test` or `go test ./...`)
2. Show the output
3. If any test fails: fix it before reporting done
4. Do not report success without showing passing test output

### Self-Verification in Prompts

Add explicit self-check steps to every task:
```
After making changes:
1. Read back each file you modified
2. Verify the change you intended is actually there
3. Run the tests
4. Only then report done
```

Local models frequently write a change they intend but don't actually execute the edit. Forcing a read-back catches this.

### Diff Verification

Add to every build agent: "Run `git diff --stat` and list every changed file. Verify no unexpected files were modified."

---

## File-Based State Management

### The `.llm/` Convention

Use `.llm/` at repo root for all LLM session artifacts. Excluded from git via `.gitignore`:

```
.llm/
├── todo.md          # active task list (mark items done as you go)
├── plan.md          # current implementation plan
├── handoff.md       # state for the next session
└── reviews/         # review agent outputs
    ├── spec-review.md
    ├── design-review.md
    └── security-review.md
```

### Always Write Before Ending a Session

Before ending any session that made progress:
1. Update `.llm/todo.md` — mark completed items, add new ones discovered
2. Write `.llm/handoff.md` — state, what was done, what's next
3. Commit if appropriate

The next session's first action: read `.llm/handoff.md` and `.llm/todo.md`.

### Session Start Protocol

Every session that continues a task should begin:
1. Read `.llm/handoff.md`
2. Read `.llm/todo.md`
3. Run `git log --oneline -5` to confirm git state matches handoff
4. Then proceed

---

## Multi-Agent Patterns

### Narrow Subagent Scope

Each subagent should do one thing:
- **Analyst**: read code, report structure — never edits
- **Builder**: implement ONE task from the plan — one file or one function
- **Tester**: write tests for ONE function or file
- **Debugger**: investigate ONE bug — does not fix, only reports findings

Never give a subagent a multi-step task. Give it one step, get the output, give the next step.

### Orchestrator Discipline

The orchestrator should:
- Break work into atomic steps
- Dispatch one step at a time to a subagent
- Verify the output before dispatching the next step
- Write progress to `.llm/todo.md` after each step
- Stop and surface to the user if a step fails twice

The orchestrator should NOT implement anything itself. Orchestrators that implement get drawn into context bloat.

### Parallel Dispatch (Use Sparingly)

Local models parallelize poorly because they share a single GPU. Running multiple agents in parallel may be slower than sequential due to GPU contention. Test before relying on parallel dispatch.

---

## Summary: What to Change in Config

| Area | Current state | Recommended change |
|---|---|---|
| `max_turns` | Not set on most agents | Add to all agents; 8–15 depending on type |
| `temperature` | Mixed | Set `0` on all non-planning agents |
| Model per-agent | Not set (uses default) | Assign by task complexity |
| Handoff protocol | Not in AGENTS.md | Add session start/end protocol |
| Success criteria | Implicit | Make explicit in every command |
| Verification | Present in skills | Add self-check/read-back to builder agent |
| OLLAMA_KEEP_ALIVE | Not set | Set in shell environment |
| Context threshold | Not mentioned | Add 60% rule to AGENTS.md |
