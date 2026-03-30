---
name: onboard
description: Bootstrap CLAUDE.md and hierarchical context files for a new or unfamiliar codebase
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

### 2. Generate CLAUDE.md
If a project doesn't have one:

```
Generate CLAUDE.md for this project. Search for architecture, tech stack,
build system, test conventions, coding style, and deployment.

Create a concise file (<=200 lines) with sections:
- Tech Stack
- Build Commands (build, test, lint, deploy)
- Architecture Overview
- Key Directories
- Coding Conventions
- Critical Constraints
- Common Pitfalls

Do NOT duplicate README content. Focus on what an AI agent needs to know.
```

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
