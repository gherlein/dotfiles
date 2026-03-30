# CLAUDE.md - Greg Herlein's Development Environment

## IMPORTANT: Repository Purpose

**THIS REPOSITORY IS A SOURCE TEMPLATE** -- it contains the configuration structure meant to be installed to `~/.claude` using the `./safe-install` script.

### For AI Agents

If you are an AI agent reading this file:

- **DO NOT make changes to files in this repository** (the `/personal-dot-claude` working directory)
- This is a source template, not the active configuration
- The active configuration lives in `~/.claude/` after installation
- If asked to modify CLAUDE.md, skills, or other configuration files, make changes in `~/.claude/`, NOT in this repository
- This repository should only be modified by the human user to update the template itself

### For Human Users

To install this configuration:

```bash
./safe-install
```

This will safely copy the contents to your `~/.claude` directory, backing up any existing configuration.

After installation, Claude Code will read the configuration from `~/.claude/CLAUDE.md` and `~/.claude/skills/`.

## About Me

Full-stack systems engineer working across the entire compute spectrum: embedded controllers (RP2040), SBCs (Raspberry Pi, Orange Pi), mobile phones and tablets, on-prem servers, cloud servers, and complex distributed systems on Kubernetes. Primary languages: **Go** and **web frontends** (TypeScript/JavaScript). I use Claude Code as my primary coding tool.

## Global Preferences

- Primary language: Go (idiomatic Go, follow stdlib conventions)
- Frontend: TypeScript/JavaScript with modern frameworks
- Embedded: Go where possible, C/C++ where required (RP2040, bare-metal)
- Infrastructure: Kubernetes, Docker, cloud-native patterns
- Containers: podman unless there is no other choice
- Be concise. Minimize prose. Focus on working code. Don't apologize.
- Never guess -- if unsure, search the codebase first then ask the user
- Always read existing code before proposing changes
- Follow existing patterns in the codebase unless you are specifically told it's a refactor
- If the user asks a question, only answer the question -- do not edit code
- NEVER give time estimates unless specifically asked
- `cd` is replaced by `zoxide` -- use `command cd` to change directories (no `command` prefix for other commands)
- Prefer passing directories as arguments over changing directories (e.g., `git -C <dir>`)

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

- Look for `PROJECT.md` in the working folder for project details
- Look for `docs/DESIGN.md` as the master design document
- If asked to design software, write the design to `docs/DESIGN.md`

## Gitignore Policy

On any file write to a development project folder -- and absolutely if a `.git` folder exists -- ensure a `.gitignore` file is present and correct:

1. **Always ignore** these entries (add if missing):
   - `.env`
   - `.envrc`
   - `*~`
   - `bin/`
2. **Add language/framework best-practice ignores** for the project type (e.g., Go: `bin/`, `vendor/`; Node: `node_modules/`, `dist/`; Python: `__pycache__/`, `*.pyc`, `.venv/`; C/C++: `*.o`, `*.a`, `*.so`, `build/`; Rust: `target/`; etc.)
3. **Do not overwrite** existing entries -- only append missing ones
4. **Check on every write** -- if `.gitignore` does not exist, create it; if it exists, verify the mandatory entries are present and add any that are missing

## Project Building

- Always provide a Makefile instead of build scripts
- Makefiles should print targets if no target is provided on the command line
- Makefiles should always provide build, test, clean, run-tests targets as a minimum

## Git Commits

- Stage files individually (`git add <file1> <file2>`) -- never `git add .` or `git add -A`
- Run `just precommit` if a justfile with that recipe exists
- Commit messages: present-tense verb, 60-120 chars, single line, end with period, no praise adjectives, no Claude attribution
- If the prompt was a compiler/linter error, use a `fixup!` prefix
- Echo the commit command and confirm with the user before running
- If pre-commit hooks fail, stage resulting changes and retry -- never `--no-verify`

## Build Commands

- Do not run long-lived processes (dev servers, file watchers)
- If a build is slow or verbose, echo the command and ask the user to run it

## LLM Context

- `.llm/` at repo root contains extra LLM context (excluded from git via `.git/info/exclude`)
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
