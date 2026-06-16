---
name: external-go-llms
description: go-llms is the external Go LLM library adopted by goraic in v0.3 in place of the in-house gorai-llm-service
metadata: 
  node_type: memory
  type: reference
  originSessionId: 28f6a4e0-9a2e-440b-aad4-e3d86493db5f
---

`github.com/lexlapax/go-llms` (MIT license, local checkout at
`/external/go-llms`) is the LLM provider library goraic adopted in v0.3,
replacing the never-built `gorai-llm-service` sibling.

**Surface goraic actually uses:**
- `pkg/llm/domain.Provider` — unified interface: `Generate`,
  `GenerateMessage`, `GenerateWithSchema`, `Stream`, `StreamMessage`.
  `Response` is `{Content string}` — tool calls are flattened to text at
  this boundary.
- `pkg/llm/provider.New<Protocol>Provider(apiKey, model, opts...)` —
  per-protocol constructors. `NewOllamaProvider(model, opts...)` has no
  apiKey. Six providers: openai, anthropic, gemini, vertexai, ollama,
  openrouter (goraic uses only the first four + a mock for tests).
- `pkg/llm/domain` functional Options: `WithTemperature`, `WithMaxTokens`,
  `WithModel`, etc.
- `pkg/schema/domain.Schema` for `GenerateWithSchema`.

**Surface goraic does NOT use (REQ-LLM-AGENT):**
- `pkg/agent/*` (LLMAgent, tool registry, handoffs, hooks) — goraic's
  command service is its own NATS-aware ReAct agent.
- `pkg/agent/tools`, `pkg/agent/workflow`, `pkg/agent/builtins` — out of
  scope.
- `pkg/llm/provider/multi.go` + `consensus.go` — deferred to v0.3+.

**Maintenance status:** upstream is in maintenance mode — the author has
moved to a Rust successor (`rs-llmspell`) and only opportunistic fixes
will land. Mitigation: pin a tagged release (target `v0.3.6`), keep the
integration surface narrow in `goraic/internal/llmsvc`, and reserve the
right to fork into `github.com/emergingrobotics/go-llms`.

**Dependencies:** raw `net/http` + manual JSON; no provider SDKs pulled.
After adopting go-llms, `goraic`'s `go.mod` removes `anthropic-sdk-go`,
`go-openai`, etc.

**How to apply:** all go-llms construction and calls live in
`goraic/internal/llmsvc`. Any other goraic package importing go-llms is a
bug (lint test enforces this — REQ-LLM-DEP-5).

Related: [[project-goraic]].
