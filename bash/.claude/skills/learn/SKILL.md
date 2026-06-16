---
name: learn
description: Document tricky problems and their solutions in CLAUDE.local.md for future reference
disable-model-invocation: true
---

# Learn

Document tricky problems and their solutions in `CLAUDE.local.md` so they are remembered in future sessions.

## What to Record

- CLI commands that failed multiple times before finding the right incantation
- Ordering requirements that aren't obvious (e.g., "must run X before Y")
- Prerequisites that had to be discovered or set up
- Environment-specific gotchas (OS differences, path issues, version mismatches)
- Non-obvious configuration that took debugging to figure out

## Format

Append to `CLAUDE.local.md` in the project root (create if it doesn't exist):

```markdown
## [Topic]
- Problem: [what went wrong]
- Solution: [what fixed it]
- Context: [when this applies]
```

Keep entries concise. This file is for the LLM, not for humans.
