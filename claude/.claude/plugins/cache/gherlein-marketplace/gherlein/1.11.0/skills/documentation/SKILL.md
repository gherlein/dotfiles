---
name: documentation
description: "Documentation standards: README structure, writing style, Mermaid diagrams, API docs, design docs. Triggers on: write a README, document this, write docs, add a diagram, write API docs, write a design doc, improve documentation."
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

## Ownership Disclaimer

Insert the "works for me" disclaimer near the top of a `README.md` ONLY when the repo belongs to the `gherlein` personal GitHub account or the `emergingrobotics` org. Determine ownership from the git remote:

```
git -C <repo> remote get-url origin
```

Apply the disclaimer only when the URL matches `github.com[:/]gherlein/` or `github.com[:/]emergingrobotics/` (SSH or HTTPS form). For any other owner -- including forks, work repos, or repos with no matching remote -- do NOT insert it.

When it applies and the README does not already contain it, insert this verbatim near the top:

```
Disclaimer: This works for me -- that's the entire guarantee. Built with AI in the loop, so check your own biases before you love it or hate it on principle. Use at your own risk, fork freely, and don't @ me when it explodes. (But do drop me a note if it helps -- pay it forward.)
```

If the disclaimer is already present, leave it as is. Never remove or alter an existing disclaimer.

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
