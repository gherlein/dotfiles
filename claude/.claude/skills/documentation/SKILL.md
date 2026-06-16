---
name: documentation
description: Documentation standards including README structure, writing style, Mermaid diagrams, and API docs
---

# Documentation Standards

## File Conventions

- Projects always need a `README.md` in the project root
- Docs other than README.md go in `./docs` unless the user specifies otherwise
- Design documents are always named `DESIGN.md` (detailed variants: `DESIGN-ZZZ.md`)
- When updating implementation or design, always update README.md

## README Structure

1. Project name and one-line description
2. Prerequisites
3. Quick start
4. Configuration
5. Common tasks
6. Project structure
7. API documentation (if applicable)

READMEs are for humans, not for LLMs. First describe the problem being solved, then how to use the program, then how to build it.

## Writing Style

- Avoid corporate buzzwords, unnecessary superlatives, throat-clearing phrases
- Be direct: "Use X for Y" not "You might want to consider using X for Y"
- One idea per sentence, short paragraphs (2-4 sentences), active voice
- Structure content as: what, then why, then how -- front-load important information
- Include working code examples with real variable names
- Show correct and incorrect patterns where helpful

## Diagrams

- Always use Mermaid for diagrams unless specifically instructed otherwise
- Provide block, sequence, and entity-relationship diagrams where appropriate

## API Documentation

- Document every endpoint with method, path, description, request/response types, examples, errors
- Keep API docs in sync with implementation

## Maintenance

- Update docs when code changes
- Delete outdated docs
- Date-stamp architectural decisions
