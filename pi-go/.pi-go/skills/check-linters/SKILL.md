---
name: check-linters-before-commit
description: Check that linters pass before committing
tools: bash
---

# Check Linters

Run linters to ensure code quality before committing.

## Steps

1. Run `golangci-lint run ./...`
2. If any errors, show the output and fix them
3. On success, commit is allowed
4. If linter fails, report the error — do not proceed with commit
