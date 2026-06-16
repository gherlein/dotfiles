---
name: llm-context
description: "Conventions for the .llm/ directory at a repo root (extra LLM context and the active task list). Triggers on: repo has a .llm/ folder, .llm/todo.md task list, track tasks, where to put extra agent context."
---

# LLM Context (`.llm/`)

- `.llm/` at a repo root contains extra LLM context (excluded from git via `.git/info/exclude` and `.gitignore`).
- If `.llm/todo.md` exists, it is the active task list -- mark tasks as done and keep it updated.
- Everything else in `.llm/` is read-only context.
