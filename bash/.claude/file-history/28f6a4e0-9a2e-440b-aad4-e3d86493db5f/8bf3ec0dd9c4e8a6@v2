---
name: project-goraic
description: goraic is an open-source coding agent built as a mesh of NATS services with command/LLM/capability service types
metadata: 
  node_type: memory
  type: project
  originSessionId: 28f6a4e0-9a2e-440b-aad4-e3d86493db5f
---

`goraic` (at `/gorai-all/goraic`) is an open-source coding agent — the first
practical example of the broader gorai mesh architecture (VISION.md).

**Why:** prove the gorai mesh works on a useful, observable domain (coding)
before extending it to robots/fleets/sensors. Single binary, embedded NATS,
everything-is-a-NATS-service internally.

**How to apply:** treat the **REQUIREMENTS.md** as the contract; DESIGN.md
and PLAN.md must satisfy it. When the user says "stale requirements," the
LLM-library section is the most likely culprit — the project recently
pivoted from an in-house `gorai-llm-service` sibling lib to the external
`go-llms` lib (see [[external-go-llms]]).

**Key concepts (RDL `type:` enum):**
- `llm` — a configured LLM endpoint (protocol/endpoint/model). Named.
- `command` — a slash-command role (`/plan`, `/code`, ...). The user-visible
  unit of work. References an `llm` service by name in `attributes.llm`.
  The command service IS the ReAct agent (REQ-CMD-7).
- `capability` — tool host (files, search, shell, repo, memory).
  Auto-registers; closed set.
- `coordinator` — multi-step orchestrator over command services.
- `prompt-log` — captures all task traffic to JSONL.

**Standards:** AGENTS.md (https://agents.md/) for project instructions,
Agent Skills (https://agentskills.io/) for skills. Both mandatory.

**Sibling repos in this workspace:** `/gorai-all/gorai` (the robot mesh),
`/gorai-all/gorai-llm-service` (deprecated — being replaced by go-llms),
`/gorai-all/gorai-docs`, `/gorai-all/pi-go`, `/gorai-all/ttt`.

**External libraries:** `/external/go-llms` (LLM provider library — see
[[external-go-llms]]).
