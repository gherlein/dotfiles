---
name: onboard
description: Layer hierarchical and multi-service context files onto a codebase after the base CLAUDE.md exists (use /init for that base). Covers subdirectory overrides, per-service CLAUDE.md, and monorepo layout.
disable-model-invocation: true
---

# Project Onboarding

Bootstrap effective AI-assisted development on a new or unfamiliar codebase.

## Steps

### 1. Research the Codebase
Before making any changes:
- Discover architecture, tech stack, build system
- Identify service/package boundaries and coding conventions
- Find existing patterns for the type of change needed
- Read existing tests to understand testing approach

### 2. Generate the base CLAUDE.md
If a project doesn't have one, use Claude Code's built-in `/init` command -- it
scans the codebase and writes a root `CLAUDE.md`. This skill does not duplicate
that. Keep the result concise (<=200 lines), focused on what an AI agent needs
(tech stack, build/test/lint/deploy commands, architecture, key directories,
conventions, critical constraints, common pitfalls), and do not duplicate README
content. The value this skill adds is everything below: the hierarchical and
multi-service structure `/init` does not produce.

### 3. Use Hierarchical Context Files
- `~/.claude/CLAUDE.md` - Global preferences (concise, verify assumptions, Go idioms)
- Project root `CLAUDE.md` - Build commands, architecture, conventions
- Subdirectory `CLAUDE.md` - Module-specific overrides (e.g., `frontend/CLAUDE.md`)

### 4. Validate
Run a typical task with context files active. If the agent doesn't follow documented conventions, iterate on the CLAUDE.md.

## For Multi-Repo / Multi-Service Projects

Each service gets its own CLAUDE.md with:
- Service-specific build/test/deploy commands
- API contracts it exposes and consumes
- Database schemas it owns
- K8s namespace and deployment details
- Environment variables and configuration

## Security Notes

Context files are injected into system prompts. Keep them:
- Minimal (only what's needed)
- Version-controlled
- Code-reviewed (no secrets, no prompt injection)

## Monorepo Project Layout

When setting up a new monorepo:
- Organize with frontend and backend in the same repository
- Treat projects as distributed systems from the start (independently deployable services)
- Separate concerns at top level: frontend apps, backend services, shared code, infrastructure, docs, tools
- Use clear descriptive names (e.g., "web-app" not "frontend"; avoid generic "src" or "lib" at root)
- Group by function/service, not by technical type
- Each service should be self-contained with its own build process, Docker image, and deployment config
- Shared packages for cross-service code (types, validation, utilities) -- keep shared code minimal
- Infrastructure as code in the repo (Docker, k8s, Terraform, CI/CD)
- Template `.env` files with documented variables; never commit secrets
- Use multi-stage Docker builds; optimize for build caching
- Testing by scope: unit tests alongside code, integration tests per service, E2E tests separate
