# Development Preferences

Full-stack systems engineer working across the entire compute spectrum: embedded controllers (RP2040), SBCs (Raspberry Pi, Orange Pi), mobile phones and tablets, on-prem servers, cloud servers, and complex distributed systems on Kubernetes. Primary languages: Go and web frontends (TypeScript/JavaScript).

## Code Quality

- Idiomatic Go, follow stdlib conventions
- Meaningful names: `userRegistrationDate` not `d`
- No abbreviations: `number` not `num`, `greaterThan` not `gt`
- No magic numbers: use named constants
- Functions do one thing well
- Always handle errors explicitly (Go: never ignore returned errors)
- DRY: extract duplicated code into shared packages
- KISS: minimum complexity for the current task
- Interfaces should be small and composable
- Do not write forgiving code: use preconditions and assert expected formats; throw on violations, do not log
- Do not add defensive try/catch blocks: let exceptions propagate
- Emoji characters are forbidden in code

## Comment Rules

- Comments explain WHY, never WHAT
- Do not comment out code: remove it
- No comments describing the change process (no past-tense verbs like "added", "removed")
- No comments about version differences ("this code now handles...")
- Place comments above the code they describe, never end-of-line
- Do NOT remove TODO comments, linter/formatter suppression comments, or comments preventing empty scopes

## Workflow

- Be concise. Minimize prose. Focus on working code. Do not apologize.
- Never guess: search the codebase first, then ask.
- Always read existing code before proposing changes.
- Follow existing patterns unless told to refactor.
- If asked a question, answer it: do not edit code.
- `cd` is replaced by `zoxide`: use `command cd` to change directories.
- Prefer passing directories as arguments over changing directories.
- Containers: podman unless there is no other choice.

## Security

- Never commit API keys, passwords, or credentials
- When reviewing code, any found API keys, passwords, or credentials require that you inform the user immediately
- Validate all external inputs at system boundaries
- Parameterized queries for database access, never string concatenation
- HTTPS for all external API calls unless another protocol like gRPC is specified
- No silenced warnings or linter ignores without documented rationale

## Architecture Awareness

This work spans multiple deployment targets:
- Embedded (RP2040): Resource-constrained, no OS or RTOS, hardware I/O
- SBC (Raspberry Pi, Orange Pi): Linux-based, GPIO/sensor access, edge compute
- Cloud/K8s: Microservices, distributed systems, horizontal scaling, observability
- Code often needs to work across these tiers: design for portability where practical

## Git

- Commit messages: present-tense verb, 60-120 chars, single line, end with period, no praise adjectives
- One logical change per commit
- Never commit secrets, credentials, or API keys

## Build

- Always provide a Makefile instead of build scripts
- Never use go directly to do builds: always write a makefile and use that
- Makefiles should print targets if no target is provided on the command line
- Makefiles should always provide build, test, clean, run-tests targets as a minimum

## Project File Conventions

- Look for `PROJECT.md` in the working folder for project details
- Look for `REQUIREMENTS.md` in the working folder for detailed requirements
- Look for `docs/DESIGN.md` as the master design document
- If asked to design software, write the design to `docs/DESIGN.md`

## Documentation Hierarchy

Requirements, specifications, and design documents are the most valuable project artifacts. Code is ephemeral and can be regenerated from specs. Never delete specs. When code and spec disagree, fix the code. Always update specs before changing implementation.

## Gitignore Policy

On any file write to a development project folder ensure a `.gitignore` file is present and correct:
1. Always ignore: `.env`, `.envrc`, `*~`, `bin/`
2. Add language/framework best-practice ignores for the project type
3. Do not overwrite existing entries: only append missing ones
4. If `.gitignore` does not exist, create it; if it exists, verify mandatory entries
