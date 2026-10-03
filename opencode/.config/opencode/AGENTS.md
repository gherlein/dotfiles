# Global Agent Instructions — Greg Herlein

## Style

- Be concise. Skip preambles, affirmations, and trailing summaries.
- Prefer working code over explanation prose.
- Never give time estimates unless asked.
- Output markdown unless another format is specifically requested.

## Tools & Environment

- Container runtime: podman (never docker unless there is no other choice)
- OS: Linux (Ubuntu/Debian). Avoid Windows solutions.
- Shell navigation: pass directories as arguments, don't `cd` into them
- Build system: always use Makefiles, never raw build scripts

## Languages

- Primary: Go (idiomatic, stdlib conventions, camelCase exported/unexported)
- Frontend: TypeScript/JavaScript with modern frameworks
- Embedded: Go/Tinygo where possible; C/C++ only for RP2040 bare-metal when required
- Avoid Python unless the ecosystem demands it

## Architecture Awareness

This work spans multiple deployment targets:
- **Embedded** (RP2040): Resource-constrained, no OS or RTOS, hardware I/O
- **SBC** (Raspberry Pi, Orange Pi): Linux-based, GPIO/sensor access, edge compute
- **Cloud/K8s**: Microservices, distributed systems, horizontal scaling, observability
- Code often needs to work across these tiers — design for portability where practical

## Guiding Principles

1. **Think Before Coding** — State assumptions explicitly. If multiple interpretations exist, present them. If something is unclear, stop and ask. Push back when a simpler approach exists.

2. **Simplicity First** — Minimum code that solves the problem. No features beyond what was asked. No abstractions for single-use code. No error handling for impossible scenarios.

3. **Surgical Changes** — Touch only what you must. Don't improve adjacent code, comments, or formatting. Match existing style. The test: every changed line traces directly to the user's request.

4. **Goal-Driven Execution** — Transform tasks into verifiable goals. Define success criteria before starting. Loop until verified.

## Code Rules

- Meaningful names: `userRegistrationDate` not `d`, `number` not `num`
- No abbreviations: `number` not `num`, `greaterThan` not `gt`
- No magic numbers — use named constants
- Functions should do one thing well
- Always handle errors explicitly; never ignore returned errors
- DRY: extract duplicated code into shared packages
- Interfaces should be small and composable
- Do not add defensive try/catch or fallback handlers for impossible scenarios
- Validate only at system boundaries (user input, external APIs)
- Do not write forgiving code — assert expected formats, throw on violations
- No emoji characters in code

## Comments

- Comments explain WHY, never WHAT
- No commented-out code — remove it
- No comments describing the change ("added", "removed", "now handles")
- No comments about version differences
- Place comments above the code they describe, never end-of-line
- Do NOT remove TODO comments, linter/formatter suppression comments, or comments preventing empty scopes

## Security

- Never commit API keys, passwords, or credentials
- Report any found credentials to the user immediately
- Validate all external inputs at system boundaries
- Parameterized queries for database access
- HTTPS for all external API calls unless another protocol is specified
- No silenced warnings or linter ignores without documented rationale
- NEVER skip or stub tests — only a human can comment out or skip tests

## Documentation Hierarchy

Requirements, specifications, and design documents are the most valuable project artifacts. Code is ephemeral and can be regenerated from specs. Never delete specs. When code and spec disagree, fix the code. Always update specs before changing implementation.

## Project File Conventions

- `PROJECT.md` — high-level project description
- `REQUIREMENTS.md` — detailed requirements; this is what you work from, always
- `docs/DESIGN.md` — master design document; write designs here, keep it current
- If changes are requested, update REQUIREMENTS.md and DESIGN.md first, then implementation

## Gitignore Policy

On any file write to a development project — absolutely if a `.git` folder exists:

1. Always ignore: `.env`, `.envrc`, `*~`, `bin/`, `.llm/`
2. Add language/framework best-practice ignores (Go: `vendor/`; Node: `node_modules/`, `dist/`; Python: `__pycache__/`, `*.pyc`, `.venv/`; C/C++: `*.o`, `*.a`, `*.so`, `build/`; Rust: `target/`)
3. Do not overwrite existing entries — only append missing ones
4. If `.gitignore` doesn't exist, create it

## Project Building

- Always provide a Makefile instead of build scripts
- Makefiles should print available targets when invoked with no arguments
- Makefiles must provide at minimum: `build`, `test`, `clean`, `run-tests` targets
- Do not run long-lived processes (dev servers, file watchers)
- If a build is slow or verbose, echo the command and ask the user to run it

## Git Commits

- Commit messages: present-tense verb, 60–120 chars, single line, end with period
- No praise adjectives, no AI attribution
- If fixing a compiler or linter error, prefix with `fixup!`
- Echo the commit command and confirm with the user before running

## LLM Context

- `.llm/` at repo root contains extra context (excluded from git)
- If `.llm/todo.md` exists, it is the active task list — mark tasks done and keep it updated
- Everything else in `.llm/` is read-only context

## Workflow

1. **Research** before implementing — read relevant code, understand patterns
2. **Plan** for non-trivial changes — use the planner agent or /plan command
3. **Execute** in focused increments with tests
4. **Validate** — run build, tests, linters, check with `git diff`

## Autonomous Implementation Protocol

When operating autonomously (no human in the loop), ALL implementations MUST follow this phased protocol.

### Phase Execution

1. Break work into discrete phases with clear boundaries
2. Implement ONE phase at a time — do not proceed until the current phase is complete
3. After each phase: run ALL tests (`make test` or equivalent); iterate until they pass
4. Do NOT move to the next phase with failing tests

### Full Integration Validation

After all phases complete:
1. Run the entire test suite end-to-end
2. Run the build (`make build`)
3. Run linters if configured
4. Anything that fails must be fixed — or STOP and get directions

### Parallel Review Gate

After all tests and builds pass, launch three parallel review agents:

1. **Spec Compliance** — compare implementation against REQUIREMENTS.md and PROJECT.md; flag every deviation
2. **Design/Architecture** — compare against docs/DESIGN.md; verify interfaces, data flow, error handling
3. **Security** — audit against OWASP top 10, security rules, input validation, credential handling

Each review writes findings to `.llm/reviews/` (spec-review.md, design-review.md, security-review.md).

Fix all critical and high findings. Document deferred medium/low in `.llm/reviews/deferred.md`. Re-run full test suite after fixes.

## Skills

Skills are on-demand knowledge packages available via the skill tool. When a skill is relevant, load and follow it exactly.

Key skills available:
- **brainstorming** — design gate before any implementation (hard gate: no code until design approved)
- **writing-plans** — rigorous implementation plan with TDD steps
- **systematic-debugging** — root cause investigation before any fix (Iron Law)
- **evidence-based-debugging** — closed-loop debugging with domain-specific tools
- **test-driven-development** — red-green-refactor; failing test before any production code
- **verification-before-completion** — final gate before declaring work done
- **code-review** — four-category review framework
- **finishing-a-development-branch** — branch completion workflow
- **edge-case-discovery**, **refactoring**, **test-as-guardrails** — quality tools
- **go-performance**, **web-frontend**, **postgresql**, **rest-api-design** — domain knowledge
- **onboard**, **reverse-engineer**, **documentation** — codebase understanding

## Security Context Files

When working in these domains, load the relevant file from `knowledge/security-rules/`:
- Go code: `languages/go/RULES.md`
- TypeScript: `languages/typescript/RULES.md`
- React/Next.js: `frontend/react/RULES.md`, `frontend/nextjs/RULES.md`
- Kubernetes: `containers/kubernetes/RULES.md`
- Docker: `containers/docker/RULES.md`
- GitHub Actions: `cicd/github-actions/RULES.md`
- Terraform/Pulumi: `iac/terraform/RULES.md`, `iac/pulumi/RULES.md`
- General: `_core/owasp-2025.md` always applies

<!-- codebase-memory-mcp:start -->
# Codebase Knowledge Graph (codebase-memory-mcp)

This project uses codebase-memory-mcp to maintain a knowledge graph of the codebase.
ALWAYS prefer MCP graph tools over grep/glob/file-search for code discovery.

## Priority Order
1. `search_graph` — find functions, classes, routes, variables by pattern
2. `trace_path` — trace who calls a function or what it calls
3. `get_code_snippet` — read specific function/class source code
4. `query_graph` — run Cypher queries for complex patterns
5. `get_architecture` — high-level project summary

## When to fall back to grep/glob
- Searching for string literals, error messages, config values
- Searching non-code files (Dockerfiles, shell scripts, configs)
- When MCP tools return insufficient results

## Examples
- Find a handler: `search_graph(name_pattern=".*OrderHandler.*")`
- Who calls it: `trace_path(function_name="OrderHandler", direction="inbound")`
- Read source: `get_code_snippet(qualified_name="pkg/orders.OrderHandler")`
<!-- codebase-memory-mcp:end -->
