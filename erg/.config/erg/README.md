# erg config examples

Ready-to-copy configs, each describing one or more **shapes**. A shape is a named bundle that tells
the one erg engine what job to be (loop mode, provider, model, system prompt, tools, skills). See
[../DESIGN.md](../DESIGN.md#7-configuration-and-shapes) for the full setting reference.

## Quick reference

```sh
erg --shape claude              # sonnet via LiteLLM, same config.json
erg --shape oss-cloud           # gpt-oss-120b-cloud
ERG_CONFIG=~/.config/erg/coding-agent.json erg --shape coder   # a different config file entirely
erg --model <name>              # one-off model override
erg -l                          # list every config file + its shapes
```

## Running an example

Point `ERG_CONFIG` at one of these files. Paths inside the configs (the `FILE:` prompts and the
`skills` directories) are relative to your **working directory**, so run from the repo root:

```sh
ERG_CONFIG=examples/coding-agent.json ./bin/erg
```

To keep a config permanently, copy it (and the prompt files it references) to
`~/.config/erg/config.json` and make the paths absolute.

Every example points its `dgx` provider at a LiteLLM proxy (`http://dgx:4000/v1`) fronting a local
model — change the `base_url` and `model` to match your setup.

## The `FILE:` prompt convention

A shape's `system` prompt can be inline text, or it can load from a file with the `FILE:` prefix:

```json
"system": "FILE: examples/prompts/coder.md"
```

The referenced file is **required** — if it is missing, erg reports an error rather than starting
with an empty prompt.

## The examples

| File | Shapes | What it shows |
| --- | --- | --- |
| [`coding-agent.json`](./coding-agent.json) | `coder` | **The basic one.** An interactive coding agent whose system prompt comes from a file, with the full tool set, on the local model. |
| [`design-partner.json`](./design-partner.json) | `design-partner`, `coder` | Use an expensive cloud model only for the thinking-heavy role: `design-partner` asks LiteLLM for the `claude` model (`effort: high`, read-only) while `coder` stays on the free local model. Both go through the one LiteLLM endpoint — no API key in erg. |
| [`telemetry-watcher.json`](./telemetry-watcher.json) | `watcher` | An `observe` shape that watches stdin and reacts only to lines matching `error/fail/critical/panic`. |
| [`reviewer-with-skill.json`](./reviewer-with-skill.json) | `reviewer` | A one-shot reviewer that loads the [`go-review`](./skills/go-review/SKILL.md) skill (`SKILL.md`) into its system prompt. |
| [`orchestrator.json`](./orchestrator.json) | `lead` | A lead that spawns and coordinates erg workers in separate herdr panes, via the [`herdr-orchestration`](./skills/herdr-orchestration/SKILL.md) skill (needs a running herdr). |
| [`lazy-skills.json`](./lazy-skills.json) | `lead` | Eager plus **lazy** skills: `herdr-orchestration` is always in force, while `lazy_skills` catalogs `skills/*` for the model to load on demand with the `skill` tool. See [docs/skills-progressive-disclosure.md](../docs/skills-progressive-disclosure.md). |

> **Paid models go through LiteLLM too.** `design-partner.json` asks for a model named `claude`,
> which is a **LiteLLM alias** you wire in your LiteLLM `model_list` (its `api_key` held there). erg
> never holds a provider API key — that's the point of the single control point. Change `claude` to
> whatever you named the model in LiteLLM. (If you don't use LiteLLM, you can instead add a native
> `anthropic` provider with `api_key_env`, but that puts the key in erg's environment.)

Supporting files:

- `prompts/` — the `FILE:`-loaded system prompts (`coder.md`, `design-partner.md`, `watcher.md`,
  `reviewer.md`).
- `skills/go-review/SKILL.md` — a sample skill: a Go code-review checklist.

## Trying them

```sh
# Basic coding agent (interactive REPL).
ERG_CONFIG=examples/coding-agent.json ./bin/erg

# Design partner on a paid model; coding stays local.
ERG_CONFIG=examples/design-partner.json ./bin/erg --shape design-partner

# Watch a stream and react to problems only.
ERG_CONFIG=examples/telemetry-watcher.json tail -F /var/log/app.log | ./bin/erg

# One-shot review with a Go-specific skill.
ERG_CONFIG=examples/reviewer-with-skill.json ./bin/erg -p "review the changes in internal/agent"
```
