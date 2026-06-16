---
name: gitignore-policy
description: "Ensure a correct .gitignore when writing files into a dev project, especially any folder with a .git directory. Triggers on: scaffolding a new repo, git init, adding files to a project, before first commit, repo hygiene, what should I gitignore."
---

# Gitignore Policy

When writing files into a development project folder -- and absolutely if a `.git` folder exists -- ensure a `.gitignore` is present and correct.

> Note: the mandatory + language-best-practice entries are now auto-enforced before any git stage/commit/push that Claude runs, via the `gitignore-gate` PreToolUse hook (`~/.claude/hooks/gitignore-gate`). This covers Claude's own git operations only -- not git run in your own shell. Use this skill as on-demand guidance for structural decisions the hook does not make.

1. **Always ignore** these entries (add if missing):
   - `.env`
   - `.envrc`
   - `*~`
   - `bin/`
   - `.llm/`
2. **Add language/framework best-practice ignores** for the project type:
   - Go: `bin/`, `vendor/`
   - Node: `node_modules/`, `dist/`
   - Python: `__pycache__/`, `*.pyc`, `.venv/`
   - C/C++: `*.o`, `*.a`, `*.so`, `build/`
   - Rust: `target/`
3. **Do not overwrite** existing entries -- only append missing ones.
4. **Check on every relevant write** -- if `.gitignore` does not exist, create it; if it exists, verify the mandatory entries are present and add any that are missing.
