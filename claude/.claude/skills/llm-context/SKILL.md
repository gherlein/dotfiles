---
name: llm-context
description: Conventions for the .llm/ directory at a repo root (extra LLM context and the active task list). Invoke when a repo has a .llm/ folder or when asked to track tasks in .llm/todo.md.
disable-model-invocation: true
---

# LLM Context (`.llm/`)

- `.llm/` at a repo root contains extra LLM context (excluded from git via `.git/info/exclude` and `.gitignore`).
- If `.llm/todo.md` exists, it is the active task list -- mark tasks as done and keep it updated.
- Everything else in `.llm/` is read-only context.
