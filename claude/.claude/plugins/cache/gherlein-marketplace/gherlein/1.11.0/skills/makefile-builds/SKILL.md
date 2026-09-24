---
name: makefile-builds
description: "Build projects via a Makefile rather than ad hoc commands, and run builds safely. Triggers on: set up a build, build this project, add a build target, write a Makefile, run make build or test, how should I build or test this, avoid running go build directly."
---

# Makefile Builds

## Build Tooling

- Always provide a Makefile instead of build scripts.
- Never use `go` directly to do builds -- always write a Makefile and use that.
- Makefiles should print targets if no target is provided on the command line.
- Makefiles should always provide `build`, `test`, `clean`, and `run-tests` targets as a minimum.

## Running Builds

- Do not run long-lived processes (dev servers, file watchers).
- If a build is slow or verbose, echo the command and ask the user to run it.
