# omp (oh-my-pi) Configuration Design

Date: 2026-08-03

## Goal

Configure `omp` for local-first inference against the dgx box, with automatic
fallback to Ollama Cloud on rate limits or outages. Minimal footprint: two
tracked config files, no duplicated agent instructions, no secrets in the repo.

## Background

`omp` is `can1357/oh-my-pi`, installed here as npm package
`@oh-my-pi/pi-coding-agent` v17.2.6 via `bun install -g`. It is a **separate
project** from `dimetron/pi-go` (the existing `pi` binary and its
`~/.pi-go/config.json`); omp is not a successor and shares no config schema.
The existing `pi-go` stow package is left untouched.

Two blocked bun postinstalls (`onnxruntime-node`, `protobufjs`) are left
blocked. They are only needed for opt-in *local* tiny models; the relevant
settings (`providers.tinyModel`, `providers.memoryModel`) default to `online`.

## Hardware and topology

| host | role | hardware |
|---|---|---|
| this workstation (`helios`) | runs `omp` | AMD display controller, no NVIDIA GPU, 125 GB RAM. Ollama here is CPU-only. |
| `dgx.herlein.me` (`gx10-e685`, 192.168.2.29) | Ollama inference server | NVIDIA GB10, 121 GB unified memory |

dgx runs `ollama serve` only. It has no omp installation and no omp config —
verified by a filesystem-wide search returning zero `models.yml` files. All omp
config lives on the workstation and reaches dgx over HTTP.

### dgx Ollama tuning (applied)

`/etc/systemd/system/ollama.service.d/override.conf`:

```ini
[Service]
Environment="OLLAMA_KEEP_ALIVE=-1"
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="OLLAMA_KV_CACHE_TYPE=q8_0"
Environment="OLLAMA_NUM_PARALLEL=1"
Environment="OLLAMA_MAX_LOADED_MODELS=2"
Environment="OLLAMA_CONTEXT_LENGTH=131072"
Environment="OLLAMA_HOST=0.0.0.0:11434"
```

Two values were changed from the previous configuration:

- `OLLAMA_NUM_PARALLEL`: 4 -> 1. Ollama divides `OLLAMA_CONTEXT_LENGTH` across
  parallel slots, so 131072 with 4 slots served only **32768 tokens per
  request**. A single interactive agent benefits more from one large window than
  four small ones.
- `OLLAMA_MAX_LOADED_MODELS`: 1 -> 2, so a thinking-capable model can co-reside
  with the primary coding model instead of evicting it on every role switch.

Measured after restart, with both models loaded:

| model | context | VRAM |
|---|---|---|
| `qwen3-coder-next:latest` | 131072 | 54.4 GB |
| `qwen3.6:35b-a3b` | 131072 | 25.3 GB |
| | | **79.6 GB of 121 GB** |

KV cache is inexpensive on these models (`qwen3next` uses hybrid
linear+full attention): coder-next grew only 52.3 GB -> 54.4 GB going from 32K
to 131K context. Cold load is ~25 s per model.

## Models available

### dgx (provider `dgx`)

All six are served at 131072 (the server-wide `OLLAMA_CONTEXT_LENGTH`), but the
first five *advertise* 262144 in `/api/show` metadata. `gpt-oss:120b` advertises
131072 natively.

| model | params | advertised | capabilities |
|---|---|---|---|
| `qwen3-coder-next:latest` | 79.7B, 10/512 experts | 262144 | tools |
| `qwen3.6:35b-a3b` | 36.0B, 8/256 experts | 262144 | tools, vision, thinking |
| `qwen3-coder:30b` | 30.5B | 262144 | tools |
| `qwen3:30b` | 30.5B | 262144 | tools, thinking |
| `qwen3.5:35b-a3b` | 36.0B | 262144 | tools, vision, thinking |
| `gpt-oss:120b` | 116.8B MXFP4 | 131072 | tools, thinking |

`gpt-oss:120b` (65.4 GB) is deliberately excluded from all roles: with
coder-next resident at 54.4 GB it cannot co-reside inside 121 GB. It remains
manually selectable via `/model` at the cost of an eviction.

`qwen3-coder-next` has no `thinking` capability, which is why the planning and
reasoning roles go to `qwen3.6:35b-a3b` rather than to the larger model.

### Ollama Cloud (provider `ollama`)

Verified present via `ollama show`, then registered locally:

| tag | context (per omp) | capabilities |
|---|---|---|
| `kimi-k2.7-code:cloud` | 262144 | tools, thinking, vision |
| `deepseek-v4-pro:cloud` | 524288 | tools, thinking |
| `gpt-oss:120b-cloud` | 131072 | tools, thinking |
| `gpt-oss:20b-cloud` | 131072 | tools, thinking |
| `glm-5.1:cloud` | 202752 | tools, thinking |

Tags from prior notes that do **not** exist and are excluded:

- `nemotron-3-nano:cloud` — model not found
- `qwen3-coder:480b-cloud` — retired 2026-07-15
- `minimax-m2.7:cloud` — exists and is capable (196608, tools, thinking), but is
  licensed non-commercial. Commercial use requires prior written authorization
  from MiniMax. Excluded on licensing grounds, not technical ones.

`glm-5.1:cloud` is registered and fully viable (202752, thinking) but is not
currently referenced by any chain, purely to keep the initial configuration
minimal. `deepseek-v4-pro:cloud` already covers the planning roles with a larger
context window. Adding glm as a second planning-tier entry is a one-line change.

An earlier reading of `glm-5.1:cloud` showed 128K and no thinking capability;
that was stale bundled-catalog metadata observed before `omp models refresh`
completed discovery. Post-refresh values match `ollama show`. Treat pre-refresh
model metadata as unreliable.

## Provider architecture

Two providers, both keyless.

| provider | covers | auth |
|---|---|---|
| `dgx` | custom ID, all dgx models via `discovery.type: ollama` | `auth: none` |
| `ollama` | built-in, localhost CPU **and** all cloud models | keyless |

### Why a custom `dgx` ID rather than repointing `ollama`

An explicit `ollama` entry in `models.yml` *replaces* omp's built-in discovery
for that ID. Defining `dgx` as a separate provider keeps both hosts selectable
simultaneously: dgx as primary, localhost as alternate. Verified that
`discovery.type: ollama` works on a non-`ollama` provider ID and discovers all
six dgx models with correct capability flags.

### Why cloud rides the `ollama` provider, not `ollama-cloud`

omp ships an `ollama-cloud` provider, but its credential store is independent of
the `ollama` CLI — `omp models ollama-cloud` returns nothing even after
`ollama signin` succeeds. It would require a second login (`/login` OAuth) or an
`OLLAMA_CLOUD_API_KEY` secret.

Instead, cloud models are registered into the local Ollama daemon with
`ollama pull <tag>:cloud`, which writes only a ~300-byte manifest (no weights).
They then appear in `/api/tags` and omp discovers them under the existing
keyless `ollama` provider. Verified end-to-end: both plain inference and
**tool calling** work against `gpt-oss:120b-cloud` through this path.

This yields one provider covering localhost and cloud, no second credential, and
nothing secret to keep out of the tracked repo. Total disk cost for all five
cloud tags: 1,539 bytes.

Note: this contradicts a prior note claiming `gpt-oss:120b-cloud` lacks
tool-calling support. Through this route it advertises `tools` and uses them
correctly.

## Role assignments

| role | primary | rationale |
|---|---|---|
| `default` | `dgx/qwen3-coder-next:latest` | coder-tuned, tools, resident |
| `smol` | `dgx/qwen3-coder-next:latest` | already loaded, so free; avoids a third model competing for dgx memory |
| `commit` | `dgx/qwen3-coder-next:latest` | same |
| `plan` | `dgx/qwen3.6:35b-a3b` | thinking-capable; coder-next is not |
| `slow` | `dgx/qwen3.6:35b-a3b` | thinking-capable |
| `vision` | `dgx/qwen3.6:35b-a3b` | only vision-capable dgx model |

`tiny` is left unset — it falls back to `@smol` by design. `task`, `advisor`,
and `designer` are left unset for a minimal starting configuration.

`smol` intentionally does **not** use the workstation's localhost Ollama: with
no NVIDIA GPU, 27B CPU inference is too slow for subagent fan-out. Localhost
remains an alternate for manual selection only.

## Fallback chains

`retry.fallbackChains` maps roles (or model selectors) to ordered fallback
selectors. It triggers on 429s, quota walls, and provider outages;
`retry.fallbackRevertPolicy` defaults to `cooldown-expiry`, returning to the
primary once its suppression window ends.

| role | fallback order |
|---|---|
| `default` | `ollama/kimi-k2.7-code:cloud`, `ollama/gpt-oss:120b-cloud` |
| `smol`, `commit` | `ollama/gpt-oss:20b-cloud` |
| `plan`, `slow` | `ollama/deepseek-v4-pro:cloud` |
| `vision` | `ollama/kimi-k2.7-code:cloud` |

`deepseek-v4-pro:cloud` on the planning roles is deliberate: its 524K context
exceeds the 131K local ceiling, so it is genuinely better for large refactors
rather than merely a substitute.

This is distinct from `contextPromotionTarget`, which handles context-overflow
promotion only and is not used here.

Chains here list **fallbacks only**, excluding the primary. The upstream
documentation's example reads as a full ordered list including the primary, so
this is ambiguous. To verify during implementation: confirm omp reports no
startup config warnings and that a fallback actually engages. If the primary
must be listed first, each chain gains its role's model as entry one.

## Context window pinning

dgx advertises `context_length: 262144` in `/api/show` metadata while actually
serving 131072. omp reads that metadata and would over-pack requests by 2x.
The two models used by roles therefore get an explicit `contextWindow: 131072`
override in `models.yml`.

The other four dgx models are left unpinned and will still report 262144 to omp.
They are not assigned to any role, so this only matters if one is selected
manually via `/model`, in which case omp may over-pack it. Pinning them is a
four-line addition to `modelOverrides` if they start getting used.

## Agent instructions: inherited, not duplicated

omp's `claude` discovery provider reads `~/.claude/CLAUDE.md` (priority 80) and
also contributes Claude-discovered MCP servers, skills, and hooks.

Only **one user-scope context file survives** across all providers, and the
`native` provider (`~/.omp/agent/AGENTS.md`, priority 100) shadows every other
one. Creating an `AGENTS.md` would therefore silently suppress `CLAUDE.md` and
force maintaining two copies.

Decision: **do not create `~/.omp/agent/AGENTS.md`.** Existing rules and
preferences are inherited automatically. Any omp-specific additions go in
`~/.omp/agent/RULES.md`, which loads as an always-apply rule rather than a
context file and so stacks on top instead of shadowing.

## Files

New `omp` stow package:

```
dotfiles/omp/.omp/agent/config.yml   -> ~/.omp/agent/config.yml
dotfiles/omp/.omp/agent/models.yml   -> ~/.omp/agent/models.yml
```

`~/.omp/agent/` already exists and holds runtime state (`models.db`,
`agent.db`, `logs/`), so stow descends into it and links only these two files
rather than folding the directory. This matches the existing `~/.pi-go`
arrangement, where tracked config files are symlinks alongside untracked
runtime files.

Note that the user-level global config is `~/.omp/agent/config.yml`. A bare
`~/.omp/config.yml` is not a global path — that filename is the *per-repository*
config form (`<repo>/.omp/config.yml`). `memory.backend` therefore lives in the
global `agent/config.yml`.

### `models.yml`

```yaml
providers:
  dgx:
    baseUrl: http://dgx.herlein.me:11434
    api: openai-responses
    auth: none
    discovery:
      type: ollama
    modelOverrides:
      "qwen3-coder-next:latest":
        contextWindow: 131072
      "qwen3.6:35b-a3b":
        contextWindow: 131072
```

Model IDs containing `:` must be quoted as YAML keys.

### `config.yml`

```yaml
modelRoles:
  default: "dgx/qwen3-coder-next:latest"
  smol: "dgx/qwen3-coder-next:latest"
  commit: "dgx/qwen3-coder-next:latest"
  plan: "dgx/qwen3.6:35b-a3b"
  slow: "dgx/qwen3.6:35b-a3b"
  vision: "dgx/qwen3.6:35b-a3b"

retry:
  modelFallback: true
  fallbackChains:
    default:
      - "ollama/kimi-k2.7-code:cloud"
      - "ollama/gpt-oss:120b-cloud"
    smol:
      - "ollama/gpt-oss:20b-cloud"
    commit:
      - "ollama/gpt-oss:20b-cloud"
    plan:
      - "ollama/deepseek-v4-pro:cloud"
    slow:
      - "ollama/deepseek-v4-pro:cloud"
    vision:
      - "ollama/kimi-k2.7-code:cloud"

memory:
  backend: local
```

Thinking-level suffixes (e.g. `:high`) are omitted from role values. Because
`qwen3.6:35b-a3b` already contains a colon, appending a suffix produces an
ambiguous selector; thinking level is set per-session via `/model` instead.

## Success criteria

1. `omp models dgx` lists all six dgx models, with `qwen3-coder-next:latest` and
   `qwen3.6:35b-a3b` reporting 131K context rather than 262K.
2. `omp models ollama` lists localhost `qwen3.6:27b` plus the four cloud tags.
3. `omp config list` shows the six configured `modelRoles` resolving to concrete
   models with no startup config warnings. Malformed chains or unknown models
   are reported as warnings at startup, so a clean start is the check.
4. A one-shot run against the `default` role completes a tool call on dgx.
5. `~/.claude/CLAUDE.md` appears as the inherited user context file, with no
   competing `AGENTS.md`.
6. `make stow` produces symlinks at `~/.omp/agent/{config,models}.yml` and does
   not fold or capture runtime state into the repo.

## Out of scope

- Configuring the `ollama-cloud` provider or any API-key credential.
- Porting pi-go's `gofmt` write hook or its `codebase-memory` MCP server.
  MCP servers are already inherited from `~/.claude`; hooks can be added later
  if wanted.
- Running omp on dgx itself. That would need an ARM64 install and a second
  config to keep in sync; dgx stays a pure inference server.
- Per-repository `.omp/config.yml` overrides and path-scoped `enabledModels`.
- `glm-5.1:cloud` as a third fallback tier (one-line addition if wanted).
