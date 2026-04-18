---
description: Understand existing code by tracing execution paths and documenting behavior
---
Reverse engineer: $@

## Process

1. **Entry point**: Find the main entry point or the function/handler in question.
2. **Trace forward**: Follow the execution path, noting each function call and data transformation.
3. **Map dependencies**: Identify external services, databases, files, and APIs touched.
4. **Document state**: What state is read? What state is mutated? Where?
5. **Identify contracts**: What are the implicit assumptions (input formats, expected config, required env vars)?
6. **Find tests**: What test coverage exists? What behaviors are tested?
7. **Summarize**: Produce a concise description of what the code does, why, and how.

## Rules

- Do NOT modify any code. This is read-only analysis.
- If the code is unclear, say so: do not invent explanations.
- Note any code smells, security issues, or potential bugs found during analysis.
- Output should be structured enough to serve as onboarding documentation.
