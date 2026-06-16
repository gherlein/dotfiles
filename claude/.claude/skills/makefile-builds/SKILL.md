---
name: makefile-builds
description: Build projects via a Makefile rather than ad hoc commands, and run builds safely. Invoke when setting up a build, adding build tooling, or running build/test commands for a project.
disable-model-invocation: true
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
