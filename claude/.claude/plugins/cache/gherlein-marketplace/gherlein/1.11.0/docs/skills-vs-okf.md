# Claude Skills vs OKF

## tl;dr

Skills are **procedural knowledge** (how to do things). OKF is **declarative knowledge** (what things are). They are complementary layers, not competitors — and the community is already building skills specifically for working with OKF.

---

## The Core Distinction

| Aspect | Claude Skills | OKF Bundles |
|--------|---------------|-------------|
| **Purpose** | How to DO things — workflows, processes, best practices | What IS — knowledge, metadata, context about systems |
| **Content** | Step-by-step procedures, triggers, guardrails | Concepts, relationships, citations, schemas, examples |
| **Invocation** | Triggered via `/skill-name` or natural-language match | Loaded into agent context before a task |
| **Author** | Engineers configuring their agent's behavior | Humans, enrichment agents, pipelines from catalogs |
| **Versioned in** | Dotfiles / agent config repos | Domain repos (alongside the thing they describe) |
| **Example** | `build-autonomous`: "run tests, open PR, iterate" | `BigQuery Table: Customer Orders` — schema, joins, examples |

---

## Skills = Procedural Knowledge (HOW)

Skills tell the agent *how to approach work*:

- Engineering principles and discipline
- Spec-driven development workflow
- Plan/implement/review phases
- Build, test, deploy procedures
- Debugging workflows
- Code review frameworks

## OKF = Declarative Knowledge (WHAT)

OKF tells the agent *what things are*:

- Data models and table schemas
- API contracts and service descriptions
- Metrics definitions and business logic
- Playbooks and runbooks
- Cross-references between concepts

---

## How They Work Together

Google's canonical description (from the [OKF blog post](https://cloud.google.com/blog/products/data-analytics/how-the-open-knowledge-format-can-improve-data-sharing)):

> "Instead of using models to search the same documents for the same facts over and over, you can give your agents a shared markdown library that grows more useful over time."

The recommended pattern:

```
CLAUDE.md  →  points at OKF content
              e.g. "read /okf/sales/metrics/weekly_active_users.md before analytics tasks"

OKF bundle →  provides the structured knowledge CLAUDE.md references
              e.g. metric definition, schema, joins, citations

Skills     →  procedural layer the agent invokes on top of that knowledge
              e.g. spec-driven tells you to update REQUIREMENTS.md first
```

OKF does **not** replace `CLAUDE.md`. `CLAUDE.md` is behavioral config (skills + instructions); OKF is the knowledge store it points at.

---

## Skills That Use OKF (as of June 2026)

OKF shipped from Google Cloud on June 12, 2026, and the community has already produced Claude Code skills/plugins specifically for authoring, validating, and consuming OKF bundles:

### [`scaccogatto/okf-skills`](https://github.com/scaccogatto/okf-skills)

Dual-mode: Claude Code marketplace plugin **and** [skills.sh](https://skills.sh) compatible (works with Cursor, Codex, and 20+ other agents).

| Command | What it does |
|---------|-------------|
| `/okf:okf` | Produce, maintain, and consume OKF bundles; auto-triggers when a repo contains a bundle |
| `/okf:validate` | Deterministic conformance check against OKF v0.1 spec (not superficial review) |
| `/okf:visualize` | Render bundle as a self-contained interactive HTML graph |

Install: `/plugin install okf@scaccogatto`

Also ships a `CLAUDE-okf.md` template — paste into your project's `CLAUDE.md` to enable automatic knowledge consultation and write-back during dev tasks.

---

### [`catancs/okf-skill`](https://github.com/catancs/okf-skill)

Claude Code marketplace plugin focused on the full CRUD lifecycle for OKF bundles.

Capabilities: validate, query, lint, and create OKF bundles from within a coding session. Explicitly frames OKF as the solution to the **lost-context-between-sessions** problem: knowledge compounds across agent sessions instead of being rebuilt each time.

Install: `/plugin marketplace add catancs/okf-skill`

---

### [`supachai-j/open-knowledge-format-starter`](https://github.com/supachai-j/open-knowledge-format-starter)

Starter-kit template with a Claude Code skill in `.claude/skills/okf/`. Four operations via natural language:

1. **Ingest sources** — extract claims into concepts; human approval required before write (supervised, not autonomous)
2. **Query the wiki** — answers with citations to specific OKF concepts
3. **Add/edit concepts** — manual authoring with OKF conformance
4. **Validate conformance** — Python-backed checker

Notable design choice: ingestion is *supervised on purpose* — humans approve 5–15 extracted claims before any writes, treating approval as a quality gate.

---

## What This Repo Is

This `knowledge-catalog` repo is itself a live example of the OKF pattern in practice. The `okf/` directory contains:

- The **OKF v0.1 spec** (`okf/SPEC.md`)
- A **reference agent** (`okf/src/reference_agent/`) that produces OKF bundles from BigQuery + web crawling
- Three **sample bundles** (`okf/bundles/ga4/`, `okf/bundles/stackoverflow/`, `okf/bundles/crypto_bitcoin/`) with interactive visualizers

The format is the contribution; the agent and visualizer demonstrate production and consumption ends.

---

## The Bigger Picture

OKF sits at the intersection of three established patterns:

- **LLM "wiki" repos** — markdown + frontmatter knowledge bases agents load into context
- **Metadata-as-code** — catalog metadata stored alongside source in git, not in a proprietary registry
- **Personal knowledge tools** (Obsidian, Notion) — hierarchical markdown with cross-links

It differs from all of them primarily by being *specified* — pinning the small set of rules needed for interoperability without dictating tooling or infrastructure.

Google Cloud's Knowledge Catalog now ingests OKF natively and serves it to agents, making OKF bundles a first-class input to Google's agent stack.
