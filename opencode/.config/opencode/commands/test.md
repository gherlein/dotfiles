---
description: "Write tests for the specified function, file, or feature using TDD patterns."
agent: tester
---

Load the `test-driven-development` skill and follow it exactly.

Target: $ARGUMENTS

If no arguments provided, ask the user what needs tests.

Rules:
- Write failing test FIRST — watch it fail before writing any implementation
- Table-driven tests in Go (`t.Run`), testing-library in React/TypeScript
- Cover happy path, error cases, and edge cases
- Never modify production code — tests only
