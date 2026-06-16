### For AI Agents

If you are an AI agent reading this file:

- This directory IS the active configuration (symlinked from `~/.claude`), and it is also version-controlled in the `dotfiles` repo
- Edit files here; commit them in `dotfiles`; run `make restow` from the repo root to refresh symlinks
- Runtime state (`projects/`, `sessions/`, `history.jsonl`, `cache/`, `.credentials.json`, etc.) is gitignored -- never commit it

Also follow these instructions:

- there is no time pressure - Autonomous builds have unlimited time
- never assume you should simplify - follow the specifications/requirements or ask
- never defer complexity - if you are unsure about complex builds, stop and ask
- carefully read requirements - don't assume functional proof-of-concept over spec compliance
- project level requirements will usually be in a ./REQUIREMENTS.md file

Also, when writing README.md files for repos that are not part of any git organization with "BrightSign" as part of it's name insert this where appropriate near the top:

```
Disclaimer: This works for me — that's the entire guarantee. Built with AI in the loop, so check your own biases before you love it or hate it on principle. Use at your own risk, fork freely, and don't @ me when it explodes. (But do drop me a note if it helps — pay it forward.)
```


### For Human Users

To install or refresh this configuration on a machine:

```bash
cd ~/dotfiles && make stow      # first-time install (or: make restow to refresh)
```

Stow symlinks `dotfiles/claude/.claude` to `~/.claude`. Claude Code then reads `~/.claude/CLAUDE.md`, `~/.claude/skills/`, etc.

> Note: this config previously lived in the standalone `dot-agents` repo (installed via a `./safe-install` copy script). That repo is **deprecated** -- everything now lives here and ships via Stow.

## About Me

Full-stack systems engineer working across the entire compute spectrum: embedded controllers (RP2040), SBCs (Raspberry Pi, Orange Pi), mobile phones and tablets, on-prem servers, cloud servers, and complex distributed systems on Kubernetes. Primary languages: **Go** and **web frontends** (TypeScript/JavaScript). I use Claude Code as my primary coding tool.

## Global Preferences

- Primary language: Go (idiomatic Go, follow stdlib conventions)
- Frontend: TypeScript/JavaScript with modern frameworks
- Embedded: Go/Tinygo where possible, C/C++ where required (RP2040, bare-metal) and only when uou have clearly informed me
- Infrastructure: Kubernetes, Docker, cloud-native patterns, OR, simplest possible EC2/VM - if unsure, ask
- Containers: podman unless there is no other choice
- Be concise. Minimize prose. Focus on working code. Don't apologize
- Never guess -- if unsure, search the codebase first then ask the user - unless you have no code, in which case ask!
- Always read existing code before proposing changes
- Follow existing patterns in the codebase unless you are specifically told it's a refactor
- Consider the underlying architecture/design patterns and follow them unless told otherwise
- Don't change the architecture/design patterns of a project without permission
- If the user asks a question, only answer the question -- do not edit code
- NEVER give time estimates unless specifically asked
- Prefer passing directories as arguments over changing directories (e.g., `git -C <dir>`)
* I am an expert software engineer but sometimes rusty.  
* I am a linux expert and strongly favor Linux of Ubuntu/Debian flavor.  I avoid Windows.
* I want all documents in markdown format unless I specifically ask otherwise

## Guiding Principles

1. Think Before Coding
Don't assume. Don't hide confusion. Surface tradeoffs.

Before implementing:

State your assumptions explicitly. If uncertain, ask.
If multiple interpretations exist, present them - don't pick silently.
If a simpler approach exists, say so. Push back when warranted.
If something is unclear, stop. Name what's confusing. Ask.

2. Simplicity First
Minimum code that solves the problem. Nothing speculative.

No features beyond what was asked.
No abstractions for single-use code.
No "flexibility" or "configurability" that wasn't requested.
No error handling for impossible scenarios.
If you write 200 lines and it could be 50, rewrite it.
Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

3. Surgical Changes
Touch only what you must. Clean up only your own mess.

When editing existing code:

Don't "improve" adjacent code, comments, Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

Tradeoff: These guidelines bias toward caution over speed. For trivial tasks, use judgment.

1. Think Before Coding
Don't assume. Don't hide confusion. Surface tradeoffs.

Before implementing:

State your assumptions explicitly. If uncertain, ask.
If multiple interpretations exist, present them - don't pick silently.
If a simpler approach exists, say so. Push back when warranted.
If something is unclear, stop. Name what's confusing. Ask.
2. Simplicity First
Minimum code that solves the problem. Nothing speculative.

No features beyond what was asked.
No abstractions for single-use code.
No "flexibility" or "configurability" that wasn't requested.
No error handling for impossible scenarios.
If you write 200 lines and it could be 50, rewrite it.
Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

3. Surgical Changes
Touch only what you must. Clean up only your own mess.

When editing existing code:

Don't "improve" adjacent code, comments, or formatting.
Don't refactor things that aren't broken.
Match existing style, even if you'd do it differently.
If you notice unrelated dead code, mention it - don't delete it.
When your changes create orphans:

Remove imports/variables/functions that YOUR changes made unused.
Don't remove pre-existing dead code unless asked.
The test: Every changed line should trace directly to the user's request.

4. Goal-Driven Execution
Define success criteria. Loop until verified.

Transform tasks into verifiable goals:

"Add validation" → "Write tests for invalid inputs, then make them pass"
"Fix the bug" → "Write a test that reproduces it, then make it pass"
"Refactor X" → "Ensure tests pass before and after"
For multi-step tasks, state a brief plan:

1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

These guidelines are working if: fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.or formatting.

Don't refactor things that aren't broken.
Match existing style, even if you'd do it differently.
If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.
- The test: Every changed line should trace directly to the user's request.

4. Goal-Driven Execution
Define success criteria. Loop until verified.

Transform tasks into verifiable goals:

"Add validation" → "Write tests for invalid inputs, then make them pass"
"Fix the bug" → "Write a test that reproduces it, then make it pass"
"Refactor X" → "Ensure tests pass before and after"
For multi-step tasks, state a brief plan:

1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

These guidelines are working if: fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

## Code Quality Rules

- Use meaningful names: `userRegistrationDate` not `d` (Go: camelCase exported/unexported)
- Do not abbreviate names -- `number` not `num`, `greaterThan` not `gt`
- No magic numbers: use named constants
- Functions should do one thing well
- Always handle errors explicitly (Go: never ignore returned errors)
- DRY: extract duplicated code into shared packages
- KISS: minimum complexity for the current task
- Interfaces should be small and composable
- Do not write forgiving code -- use preconditions and assert expected formats; throw on violations, do not log
- Do not add defensive try/catch blocks -- let exceptions propagate
- Emoji characters are forbidden in code

## Comment Rules

- Comments explain WHY, never WHAT
- Do not comment out code -- remove it
- No comments describing the change process (no past-tense verbs like "added", "removed")
- No comments about version differences ("this code now handles...")
- Place comments above the code they describe, never end-of-line
- Do NOT remove TODO comments, linter/formatter suppression comments, or comments preventing empty scopes

## Security Rules

- Never commit API keys, passwords, or credentials
- When reviewing code, any found API keys, passwords, or credentials require that you inform the user immediately
- Validate all external inputs at system boundaries
- Use parameterized queries for database access
- HTTPS for all external API calls unless another protocol like gRPC is specified
- No silenced warnings or linter ignores without documented rationale
- NEVER skip or stub tests - all tests must be run - only a human can comment out or stub or skip tests

## Architecture Awareness

This work spans multiple deployment targets:
- **Embedded** (RP2040): Resource-constrained, no OS or RTOS, hardware I/O
- **SBC** (Raspberry Pi, Orange Pi): Linux-based, GPIO/sensor access, edge compute
- **Cloud/K8s**: Microservices, distributed systems, horizontal scaling, observability
- Code often needs to work across these tiers -- design for portability where practical

## Documentation Hierarchy

Requirements, specifications, and design documents are the most valuable project artifacts. Code is ephemeral and can be regenerated from specs. Never delete specs. When code and spec disagree, fix the code. Always update specs before changing implementation.

## Project File Conventions

- Look for `PROJECT.md` in the working folder for a high level description of the project - often the basis for deriving requirements
- Look for `REQUIREMENTS.md` in the working folder for detailed requirements - this is what you work from, always
- Look for `docs/DESIGN.md` as the master design document - this is what you will write and keep up to date based on REQUIREMENTS.md
- If asked to design software, write the design to `docs/DESIGN.md`
- If changes are requested, first update the REQUIREMENTS.md and the the DESIGN.md and then the implementation in accordance with the design

## Gitignore Policy

On any file write to a development project folder -- and absolutely if a `.git` folder exists -- ensure a `.gitignore` file is present and correct:

1. **Always ignore** these entries (add if missing):
   - `.env`
   - `.envrc`
   - `*~`
   - `bin/`
   - '.llm/'
2. **Add language/framework best-practice ignores** for the project type (e.g., Go: `bin/`, `vendor/`; Node: `node_modules/`, `dist/`; Python: `__pycache__/`, `*.pyc`, `.venv/`; C/C++: `*.o`, `*.a`, `*.so`, `build/`; Rust: `target/`; etc.)
3. **Do not overwrite** existing entries -- only append missing ones
4. **Check on every write** -- if `.gitignore` does not exist, create it; if it exists, verify the mandatory entries are present and add any that are missing

## Project Building

- Always provide a Makefile instead of build scripts
- Never use go directly to do builds - always write a makefile and use that
- Makefiles should print targets if no target is provided on the command line
- Makefiles should always provide build, test, clean, run-tests targets as a minimum

## Git Commits

- Commit messages: present-tense verb, 60-120 chars, single line, end with period, no praise adjectives, no Claude attribution
- If the prompt was a compiler/linter error, use a `fixup!` prefix
- Echo the commit command and confirm with the user before running

## Build Commands

- Do not run long-lived processes (dev servers, file watchers)
- If a build is slow or verbose, echo the command and ask the user to run it

## LLM Context

- `.llm/` at repo root contains extra LLM context (excluded from git via `.git/info/exclude`) and .gitignore
- If `.llm/todo.md` exists, it is the active task list -- mark tasks as done and keep it updated
- Everything else in `.llm/` is read-only context

## Workflow

1. **Research** before implementing -- read relevant code, understand patterns
2. **Plan** for non-trivial changes -- use plan mode
3. **Execute** in focused increments with tests
4. **Validate** -- run build, tests, linters, check with `git diff`

## Autonomous Implementation Protocol

When operating autonomously (permissions bypassed / no human in the loop), ALL implementations MUST follow this phased protocol. No exceptions.

### Phase Execution

1. The design/plan MUST break work into discrete phases with clear boundaries
2. Implement ONE phase at a time -- do not proceed to the next phase until the current phase is complete
3. After implementing each phase:
   - Run ALL tests for that phase (`make test` or equivalent)
   - If any test fails, iterate: fix the code, re-run tests, repeat until ALL tests pass
   - Do NOT move to the next phase with failing tests
4. Repeat for every phase until the full implementation is complete

### Full Integration Validation

After all phases are complete:
1. Run the entire test suite end-to-end
2. Run the build (`make build`)
3. Run linters if configured
4. If anything fails, iterate: fix, re-run, repeat until everything passes
5. Do not skip or ignore tests.  Anything that fails must be fixed or you STOP and get directions

### Parallel Review Gate

After all tests and builds pass, launch THREE parallel review subagents:

1. **Spec Compliance Review** -- Compare the implementation against the spec/requirements documents (`PROJECT.md`, any requirements docs). Flag every deviation, missing requirement, or undocumented behavior.
2. **Design/Architecture Review** -- Compare the implementation against `docs/DESIGN.md` and architectural constraints. Verify interfaces, data flow, error handling patterns, deployment target compatibility, and adherence to code quality rules in this file.
3. **Security Review** -- Full security audit against OWASP top 10, the Security Rules in this file, input validation boundaries, credential handling, injection vectors, and dependency risks.

Each review subagent writes its findings to `.llm/reviews/`:
- `.llm/reviews/spec-review.md`
- `.llm/reviews/design-review.md`
- `.llm/reviews/security-review.md`

### Review Remediation

1. Read all three review files
2. Triage findings by severity (critical > high > medium > low)
3. Fix all critical and high findings -- iterate with tests after each fix
4. Document any medium/low findings deferred with rationale in `.llm/reviews/deferred.md`
5. Re-run the full test suite one final time to confirm nothing regressed

### Summary

The cycle is: **implement phase -> test -> iterate -> next phase -> ... -> full test -> parallel reviews -> fix findings -> final test**. Never skip phases, never skip reviews, never leave failing tests.

## Skills & Context Files

Before starting any task, read `~/.claude/INDEX.md` to identify which skills to invoke and which security rule files to read. Load only what is relevant to the current task -- do not read all files.

- Skills (task-specific workflow guides): `~/.claude/skills/`
- Security rules (always-on coding policies): `~/.claude/security-rules/`
- Index (maps task types to the right files): `~/.claude/INDEX.md`
