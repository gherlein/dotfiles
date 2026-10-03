---
description: Understand a codebase's architecture and entry points
---
Onboard to this codebase: $@

## Process

1. **Survey**: List top-level directories and their purposes.
2. **Entry points**: Find main(), cmd/, or equivalent entry points.
3. **Dependencies**: Read go.mod/package.json/requirements.txt for key dependencies.
4. **Architecture**: Identify the layering (handler -> service -> repository, etc.).
5. **Data flow**: Trace a request from entry to response.
6. **Testing**: Identify test patterns and coverage approach.
7. **Build**: Find the Makefile or build system and list available targets.
8. **Config**: Identify configuration sources (env, files, flags).

## Output

Produce a concise summary covering each point above. Note any patterns that deviate from standard conventions. Flag anything that looks like technical debt or a potential issue.

Do NOT modify any code. This is read-only exploration.
