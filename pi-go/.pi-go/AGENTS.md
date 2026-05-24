# Agent Instructions - Greg Herlein's Development Environment

## About Me

Full-stack systems engineer working across the entire compute spectrum: embedded controllers (RP2040), SBCs (Raspberry Pi, Orange Pi), mobile phones and tablets, on-prem servers, cloud servers, and complex distributed systems on Kubernetes. Primary languages: **Go** and **web frontends** (TypeScript/JavaScript).

## Global Preferences

- Primary language: Go (idiomatic Go, follow stdlib conventions)
- Frontend: TypeScript/JavaScript with modern frameworks
- Embedded: Go/Tinygo where possible, C/C++ where required (RP2040, bare-metal) and only when you have clearly informed me
- Infrastructure: Kubernetes, Docker, cloud-native patterns, OR simplest possible EC2/VM -- if unsure, ask
- Containers: podman unless there is no other choice
- Be concise. Minimize prose. Focus on working code. Don't apologize
- Never guess -- if unsure, search the codebase first then ask the user
- Always read existing code before proposing changes
- Follow existing patterns in the codebase unless specifically told it's a refactor
- Consider the underlying architecture/design patterns and follow them unless told otherwise
- Don't change the architecture/design patterns of a project without permission
- If the user asks a question, only answer the question -- do not edit code
- NEVER give time estimates unless specifically asked
- Prefer passing directories as arguments over changing directories (e.g., `git -C <dir>`)
- Expert software engineer, sometimes rusty
- Linux expert, strongly favor Ubuntu/Debian. Avoid Windows
- All documents in markdown format unless specifically requested otherwise

## Guiding Principles

These guidelines bias toward caution over speed. For trivial tasks, use judgment.

### 1. Think Before Coding

Don't assume. Don't hide confusion. Surface tradeoffs.

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them -- don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First

Minimum code that solves the problem. Nothing speculative.

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.
- Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical Changes

Touch only what you must. Clean up only your own mess.

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it -- don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.
- The test: every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

Define success criteria. Loop until verified.

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]

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
- NEVER skip or stub tests -- all tests must be run -- only a human can comment out or stub or skip tests

## Architecture Awareness

This work spans multiple deployment targets:
- **Embedded** (RP2040): Resource-constrained, no OS or RTOS, hardware I/O
- **SBC** (Raspberry Pi, Orange Pi): Linux-based, GPIO/sensor access, edge compute
- **Cloud/K8s**: Microservices, distributed systems, horizontal scaling, observability
- Code often needs to work across these tiers -- design for portability where practical

## Documentation Hierarchy

Requirements, specifications, and design documents are the most valuable project artifacts. Code is ephemeral and can be regenerated from specs. Never delete specs. When code and spec disagree, fix the code. Always update specs before changing implementation.

## Project File Conventions

- Look for `PROJECT.md` in the working folder for a high-level description of the project
- Look for `REQUIREMENTS.md` in the working folder for detailed requirements -- this is what you work from, always
- Look for `docs/DESIGN.md` as the master design document
- If asked to design software, write the design to `docs/DESIGN.md`
- If changes are requested, first update `REQUIREMENTS.md`, then `docs/DESIGN.md`, then the implementation

## Gitignore Policy

On any file write to a development project folder -- and absolutely if a `.git` folder exists -- ensure a `.gitignore` file is present and correct:

1. **Always ignore** these entries (add if missing):
   - `.env`
   - `.envrc`
   - `*~`
   - `bin/`
2. **Add language/framework best-practice ignores** for the project type (e.g., Go: `bin/`, `vendor/`; Node: `node_modules/`, `dist/`; Python: `__pycache__/`, `*.pyc`, `.venv/`; C/C++: `*.o`, `*.a`, `*.so`, `build/`; Rust: `target/`)
3. **Do not overwrite** existing entries -- only append missing ones
4. **Check on every write** -- if `.gitignore` does not exist, create it; if it exists, verify the mandatory entries are present and add any that are missing
5. **Never ignore** `.pi-go/` -- it contains project config, skills, and agent instructions

## Project Building

- Always provide a Makefile instead of build scripts
- Never invoke `go` directly for builds -- always write a Makefile and use that
- Makefiles should print available targets when invoked with no target
- Makefiles must provide at minimum: `build`, `test`, `clean`, `run-tests`

## Git Commits

- Commit messages: present-tense verb, 60-120 chars, single line, ends with period, no praise adjectives
- If the prompt was a compiler/linter error, use a `fixup!` prefix
- Use `/commit` to generate and review a commit message before applying

## Build Commands

- Do not run long-lived processes (dev servers, file watchers)
- If a build is slow or verbose, show the command and ask the user to run it

## Workflow

1. **Research** before implementing -- read relevant code, understand patterns
2. **Plan** for non-trivial changes -- use `/plan` to start a planning session
3. **Execute** in focused increments with tests
4. **Validate** -- run build, tests, linters, check with `git diff`

## Autonomous Implementation Protocol

When operating autonomously (no human in the loop), ALL implementations MUST follow this phased protocol. No exceptions.

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
5. Do not skip or ignore tests -- anything that fails must be fixed or you STOP and get directions

### Parallel Review Gate

After all tests and builds pass, spawn THREE parallel `reviewer` subagents:

1. **Spec Compliance Review** -- Compare the implementation against `PROJECT.md` and `REQUIREMENTS.md`. Flag every deviation, missing requirement, or undocumented behavior.
2. **Design/Architecture Review** -- Compare the implementation against `docs/DESIGN.md` and architectural constraints. Verify interfaces, data flow, error handling patterns, deployment target compatibility, and adherence to the code quality rules above.
3. **Security Review** -- Full security audit against OWASP top 10, the Security Rules above, input validation boundaries, credential handling, injection vectors, and dependency risks.

Each reviewer writes its findings to `.pi-go/reviews/`:
- `.pi-go/reviews/spec-review.md`
- `.pi-go/reviews/design-review.md`
- `.pi-go/reviews/security-review.md`

### Review Remediation

1. Read all three review files
2. Triage findings by severity (critical > high > medium > low)
3. Fix all critical and high findings -- iterate with tests after each fix
4. Document any medium/low findings deferred with rationale in `.pi-go/reviews/deferred.md`
5. Re-run the full test suite one final time to confirm nothing regressed

### Summary

The cycle is: **implement phase -> test -> iterate -> next phase -> ... -> full test -> parallel reviews -> fix findings -> final test**. Never skip phases, never skip reviews, never leave failing tests.
