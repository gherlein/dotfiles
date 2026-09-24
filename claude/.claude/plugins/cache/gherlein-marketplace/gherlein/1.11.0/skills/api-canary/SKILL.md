---
name: api-canary
description: "Discover every externally exposed API endpoint, then generate a standalone black-box canary test framework that probes the live service from outside the deployment boundary. Triggers on: find all exposed APIs, build an external test framework, canary tests, synthetic monitoring, black-box API contract tests, smoke test the deployed API, test the API from outside, detect API drift."
---

# External API Canary Framework

Build a test suite that lives **outside** the service and treats it as a black box:
it reaches the API only over the network, exactly as a real client would.

## Why This Exists

In-repo unit/integration tests (see `gherlein:test-as-guardrails`) are white-box: they
import the code, share its assumptions, and pass even when the *deployed* surface is broken
(wrong ingress, missing auth, contract drift, expired cert, cold start over SLO). A canary
closes that gap. It is **additive**, never a replacement:

| Property | In-repo tests | Canary framework |
|----------|---------------|------------------|
| Vantage point | inside the process | outside the boundary, over the wire |
| Couples to code | yes (imports) | **no** — network only |
| Catches | logic bugs | deploy/config/contract/SLO regressions |
| Runs | CI on build | CI **and** continuously against live envs |

**Iron rule: the canary MUST NOT import the service's own packages.** If it can `import`
the handler, it is not a canary. It gets its own module, its own dependencies, its own build.

## Phase 1 — Discover the Exposed Surface

Prefer authoritative contracts when they exist; fall back to scanning route registrations.

**Authoritative sources (use first if present):**
- OpenAPI / Swagger (`openapi.yaml`, `swagger.json`) → enumerate paths + schemas directly
- gRPC `.proto` service definitions → services, methods, message types
- GraphQL SDL (`*.graphql`, schema files) → queries, mutations, types
- AsyncAPI for event/queue interfaces

**Route-registration scan (when no contract exists) — grep patterns:**
- Go: `http.HandleFunc`, `mux.Handle(`, chi `r\.(Get|Post|Put|Patch|Delete)`, gin `\.(GET|POST|PUT|PATCH|DELETE)\(`, echo `e\.(GET|POST)`, gRPC `Register\w+Server`
- Node/TS: express `app\.(get|post|put|patch|delete)`, fastify `\.route\(`, NestJS `@(Get|Post|Put|Patch|Delete)\(` and `@Controller`
- Python: FastAPI `@app\.(get|post)`, Flask `@app\.route`, decorators with methods

**Filter to what is actually EXPOSED.** "Exposed" means reachable from outside the trust
boundary — not every registered handler qualifies. Cross-reference deployment:
- Kubernetes `Ingress` rules, `Service` type `LoadBalancer`/`NodePort`, Gateway/HTTPRoute
- API gateway / reverse-proxy config (nginx, Envoy, Traefik, cloud ALB rules)
- Anything behind `internal`-only Services, cluster-IP, or mesh-only mTLS is **internal** —
  tag it, but the canary's default target set is the public surface.

**Output:** a generated inventory manifest at `canary/api-inventory.yaml`. One entry per
endpoint capturing the contract the canary will enforce:

```yaml
- id: get-user
  method: GET
  path: /api/v1/users/{id}
  exposure: public          # public | internal
  auth: bearer              # none | bearer | apikey | mtls
  expect_status: 200
  error_status: [401, 404]
  response_schema: schemas/user.json   # or $ref into the OpenAPI doc
  latency_slo_ms: { p95: 300 }
  idempotent: true
  side_effects: none        # none | creates | mutates | deletes
```

## Phase 2 — Capture the Contract

For every entry, pin down what "correct" means so the canary can assert it (align with
`gherlein:rest-api-design` conventions):
- expected status for the happy path **and** documented error paths
- response body schema (JSON Schema / proto message / SDL type) for strict validation
- required/echoed headers (`X-Request-ID`, content-type, cache headers)
- auth behavior: no credential → 401, valid credential wrong scope → 403
- latency SLO (p50/p95) per environment
- idempotency and side-effect class — decides whether the canary may call it against prod

## Phase 3 — Generate the Framework

Scaffold a **standalone module** beside (or in a sibling repo to) the service:

```
canary/
  go.mod / package.json        # own deps; ZERO imports of the service
  api-inventory.yaml           # generated in Phase 1, the source of truth
  config/targets.yaml          # base URLs + auth per environment
  internal/client/             # thin HTTP/gRPC client, retries, timeouts, X-Canary header
  internal/validate/           # schema + status + latency assertions
  tests/                       # tiered suites (below)
  cmd/canary/                  # continuous runner (synthetic monitor)
  Makefile                     # make smoke | contract | auth | canary
  README.md
```

**Config-driven targeting — never hardcode URLs or secrets.** Select environment by flag
or env var; read credentials from the environment only:

```yaml
# config/targets.yaml
local:   { base_url: "http://localhost:8080" }
staging: { base_url: "https://staging.example.com" }
prod:    { base_url: "https://api.example.com", read_only: true }
```
`CANARY_TARGET=staging CANARY_TOKEN=$TOKEN make contract`

**Test tiers** (each reads `api-inventory.yaml` — table-driven, so new endpoints extend
coverage without new code):

1. **Smoke / liveness** — health + readiness endpoints, sub-30s. The gate after every deploy.
2. **Contract** — each endpoint returns its declared status and a schema-valid body.
3. **Auth boundary** — no credential → 401/403; wrong scope → 403; expired token rejected.
4. **Negative / edge** — malformed input → 400/422 (drive from the `gherlein:test-as-guardrails`
   edge-case matrix: boundary, nil/empty, oversized, wrong content-type).
5. **Latency / SLO** — measured p50/p95 within the manifest budget.
6. **Idempotency** — safe methods (`GET`/`HEAD`) cause no mutation on repeat.

**Go skeleton (table-driven from the manifest):**

```go
// canary/tests/contract_test.go — separate module, black-box only.
func TestContract(t *testing.T) {
    inv := canary.LoadInventory("../api-inventory.yaml")
    target := canary.Target(os.Getenv("CANARY_TARGET"))
    for _, ep := range inv.Public() {
        ep := ep
        t.Run(ep.ID, func(t *testing.T) {
            t.Parallel()
            resp, elapsed := target.Call(t, ep) // real HTTP over the wire
            canary.AssertStatus(t, resp, ep.ExpectStatus)
            canary.AssertSchema(t, resp.Body, ep.ResponseSchema)
            canary.AssertLatency(t, elapsed, ep.LatencySLO)
        })
    }
}
```
TS equivalent: a vitest/node runner iterating the same manifest with `fetch` + a JSON-schema
validator (ajv). gRPC: a generated client from the `.proto`, no server imports.

## Phase 4 — Canary Runtime (Synthetic Monitoring)

`cmd/canary` runs the smoke + contract tiers on an interval against a live environment and
emits pass/fail + latency metrics (log/stdout, Prometheus, or a webhook alert). Requirements:
- **Non-destructive against prod.** Use a dedicated canary account/tenant; only exercise
  read-only or self-cleaning flows; skip any endpoint whose `side_effects` isn't `none`
  unless a teardown exists.
- **Tag every request** with an `X-Canary: true` header so production can filter canary
  traffic out of analytics and rate limits.
- **Fail loud.** Non-zero exit / alert on any failure — a green canary that never goes red
  is worthless.

## Phase 5 — Drift Detection

The manifest is the contract; the live service is reality. A `make drift` step re-runs Phase 1
discovery against the current codebase (and, where possible, the live OpenAPI/reflection
endpoint) and diffs it against `api-inventory.yaml`. Fail when:
- a new **exposed** endpoint appears that isn't in the manifest (untested surface), or
- a manifested endpoint disappears (broken contract / silent removal).

This is the payoff of an external framework: it catches the real interface diverging from
the documented one — something in-repo tests structurally cannot see.

## Integration

- Invoke `gherlein:rest-api-design` when capturing contracts so expected statuses, error
  envelopes, and pagination assertions match house conventions.
- The smoke tier IS the sub-30s smoke suite from `gherlein:test-as-guardrails`, run from
  outside instead of `-short`.
- Apply `gherlein:gitignore-policy` and `gherlein:makefile-builds` to the generated module.
- Before claiming the canary works, run it against a live target and read the output per
  `verification-before-completion` — a canary asserted-but-never-run is not evidence.
- In a `gherlein:build-autonomous` cycle, generate the canary in Phase 5 alongside in-repo
  tests and run its smoke tier in the Phase 6 integration gate.

## Red Flags — Stop

- Canary module `import`s the service's packages → it's not black-box; rebuild it isolated.
- URLs or secrets hardcoded in tests → move to `config/targets.yaml` + env.
- Destructive calls against prod with no teardown → restrict to read-only or a canary tenant.
- New public endpoint shipped with no manifest entry → drift check must fail the build.
- "Canary passes" claimed without a fresh run against a real target.

## Success Criteria

- `canary/` module builds and runs with zero imports of the service.
- `api-inventory.yaml` enumerates every **exposed** endpoint with its contract.
- Smoke, contract, auth, negative, and latency tiers all derive from the manifest.
- `cmd/canary` runs continuously, non-destructively, and fails loud.
- `make drift` fails on undocumented or removed endpoints.
- The canary has been run against a live target and its output read.
