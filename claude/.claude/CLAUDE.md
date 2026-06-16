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

Work spans multiple deployment targets, and code often needs to work across them -- design for portability where practical:
- **Embedded** (RP2040): resource-constrained, no OS or RTOS, hardware I/O
- **SBC** (Raspberry Pi, Orange Pi): Linux-based, GPIO/sensor access, edge compute
- **Cloud/K8s**: microservices, distributed systems, horizontal scaling, observability

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

## Engineering Principles

The discipline in one line each. Full detail in the `engineering-principles` skill -- invoke it before non-trivial implementation work.

1. **Think before coding** -- state assumptions, surface tradeoffs, ask when unclear; don't pick silently.
2. **Simplicity first** -- minimum code that solves the problem; nothing speculative.
3. **Surgical changes** -- touch only what the request requires; match existing style; don't refactor what isn't broken.
4. **Goal-driven execution** -- turn the task into verifiable success criteria, then loop until they pass.

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

## Skills & Context Files

Before starting any task, read `~/.claude/INDEX.md` to identify which skills to invoke and which security rule files to read. Load only what is relevant to the current task -- do not read all files.

- Skills (task-specific workflow guides): `~/.claude/skills/`
- Security rules (always-on coding policies): `~/.claude/security-rules/`
- Index (maps task types to the right files): `~/.claude/INDEX.md`

Procedures and conventions that used to live in this file are now lazy-loaded skills (see INDEX.md): `engineering-principles` (full principles + workflow), `build-autonomous` (autonomous phase/test/review protocol), `spec-driven` (spec authority + PROJECT/REQUIREMENTS/DESIGN conventions), `gitignore-policy`, `makefile-builds`, `git-ops` (commit message rules), `llm-context` (`.llm/` handling).
