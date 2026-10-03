---
name: rebuild
description: Rebuild and reinstall the pi-go binary after code changes
tools: bash
---

# Pi-Go Rebuild

Rebuild and reinstall the pi-go binary from source, then restart.

## Steps

1. Run linters: `golangci-lint run ./...`
2. If linters pass: `go build ./cmd/pi && go install ./cmd/pi/`
3. If build succeeds, call the `restart` tool.
4. On any failure, show full error output — do not restart.
