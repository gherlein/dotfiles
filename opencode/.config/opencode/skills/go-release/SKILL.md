---
name: go-release
description: "Use when preparing a tagged release of a Go module or service. Covers versioning, changelog, tagging, and pushing."
---

# Go Release Process

## Prerequisites

- All tests passing: `go test -race ./...`
- No uncommitted changes: `git status`
- `CHANGELOG.md` is up to date

## Steps

1. Determine the new version (semver): `git tag | sort -V | tail -1`
2. Update `CHANGELOG.md` — add a section for the new version
3. Commit: `git commit -m "chore: release v<VERSION>."`
4. Tag: `git tag -a v<VERSION> -m "Release v<VERSION>"`
5. Push: `git push origin main --tags`

## Version Bumping Rules

- `patch` — bug fixes only
- `minor` — new backward-compatible features
- `major` — breaking API changes

## Verification

After push: `git ls-remote --tags origin`
