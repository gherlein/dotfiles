# Skills & Security Rules Index

Before starting any task, identify the task domain and type, then:

1. Invoke the relevant skills listed below.
2. Read the relevant security rule files listed below.

Load only what applies to the current task -- do not read all files.

---

## Skill Selection

### Planning & Orchestration

| When | Skill |
|------|-------|
| Non-trivial feature spanning multiple packages, services, or tiers | `plan` |
| Multi-step task needing a checklist with user confirmation at each step | `plan-todo` |
| Full autonomous design-build-test-review cycle | `build-autonomous` |
| Complex project requiring sub-agent delegation | `orchestrate` |
| Spec or requirements docs exist and must be authoritative | `spec-driven` |
| Complex architecture or design decision needing multiple perspectives | `three-experts` |

### Code Quality

| When | Skill |
|------|-------|
| Reviewing code before merging | `code-review` |
| Restructuring existing code | `refactoring` |
| Removing bad or redundant comments | `clean-comments` |
| Finding missing edge cases after implementation | `edge-case-discovery` |
| Writing or reviewing tests | `test-as-guardrails` |
| Iterative improvement of algorithms or system design | `refine` |

### Language & Domain

| When | Skill |
|------|-------|
| Go optimization, profiling, or GC tuning | `go-performance` |
| USB, HID, or serial device development in Go | `go-usb` |
| React / TypeScript / Tailwind frontend work | `web-frontend` |
| PostgreSQL schema, queries, or migrations | `postgresql` |
| Designing or reviewing a REST API | `rest-api-design` |
| Debugging any issue (start here) | `evidence-based-debugging` |
| Writing READMEs, API docs, or design documents | `documentation` |
| Cherry-pick, rebase, or complex git operations | `git-ops` |

### Onboarding & Learning

| When | Skill |
|------|-------|
| Unfamiliar or new codebase | `onboard` |
| Understanding an existing system's architecture | `reverse-engineer` |
| Documenting a tricky solution for future reference | `learn` |

---

## Security Rule Files

Security rules live in `~/.claude/security-rules/`. Read the relevant files **before writing code** for any task that produces or modifies source files.

### Core (read applicable rules for every coding task)

| File | Covers |
|------|--------|
| `~/.claude/security-rules/_core/owasp-2025.md` | OWASP Top 10 2025 -- injection, XSS, SSRF, broken auth, misconfiguration |
| `~/.claude/security-rules/_core/agent-security.md` | AI agent tool sandboxing, autonomy boundaries, multi-agent trust |
| `~/.claude/security-rules/_core/ai-security.md` | Model loading, prompt injection, training data security |
| `~/.claude/security-rules/_core/mcp-security.md` | MCP server/client security, tool call validation |
| `~/.claude/security-rules/_core/rag-security.md` | RAG pipeline security overview |
| `~/.claude/security-rules/_core/graph-database-security.md` | Graph database query injection, access control |

### Languages

| Language | File |
|----------|------|
| Go | `~/.claude/security-rules/languages/go/CLAUDE.md` |
| TypeScript | `~/.claude/security-rules/languages/typescript/CLAUDE.md` |
| JavaScript | `~/.claude/security-rules/languages/javascript/CLAUDE.md` |
| Python | `~/.claude/security-rules/languages/python/CLAUDE.md` |
| C / C++ | `~/.claude/security-rules/languages/cpp/CLAUDE.md` |
| Rust | `~/.claude/security-rules/languages/rust/CLAUDE.md` |
| Java | `~/.claude/security-rules/languages/java/CLAUDE.md` |
| C# | `~/.claude/security-rules/languages/csharp/CLAUDE.md` |
| SQL | `~/.claude/security-rules/languages/sql/CLAUDE.md` |
| Ruby | `~/.claude/security-rules/languages/ruby/CLAUDE.md` |
| Julia | `~/.claude/security-rules/languages/julia/CLAUDE.md` |
| R | `~/.claude/security-rules/languages/r/CLAUDE.md` |

### Frontend Frameworks

| Framework | File |
|-----------|------|
| React | `~/.claude/security-rules/frontend/react/CLAUDE.md` |
| Next.js | `~/.claude/security-rules/frontend/nextjs/CLAUDE.md` |
| Angular | `~/.claude/security-rules/frontend/angular/CLAUDE.md` |
| Vue | `~/.claude/security-rules/frontend/vue/CLAUDE.md` |
| Svelte | `~/.claude/security-rules/frontend/svelte/CLAUDE.md` |

### Backend Frameworks

| Framework | File |
|-----------|------|
| FastAPI | `~/.claude/security-rules/backend/fastapi/CLAUDE.md` |
| Django | `~/.claude/security-rules/backend/django/CLAUDE.md` |
| Flask | `~/.claude/security-rules/backend/flask/CLAUDE.md` |
| Express | `~/.claude/security-rules/backend/express/CLAUDE.md` |
| NestJS | `~/.claude/security-rules/backend/nestjs/CLAUDE.md` |
| LangChain | `~/.claude/security-rules/backend/langchain/CLAUDE.md` |
| AutoGen | `~/.claude/security-rules/backend/autogen/CLAUDE.md` |
| CrewAI | `~/.claude/security-rules/backend/crewai/CLAUDE.md` |
| vLLM | `~/.claude/security-rules/backend/vllm/CLAUDE.md` |
| Ray Serve | `~/.claude/security-rules/backend/ray-serve/CLAUDE.md` |
| BentoML | `~/.claude/security-rules/backend/bentoml/CLAUDE.md` |
| MLflow | `~/.claude/security-rules/backend/mlflow/CLAUDE.md` |
| Modal | `~/.claude/security-rules/backend/modal/CLAUDE.md` |
| Triton | `~/.claude/security-rules/backend/triton/CLAUDE.md` |
| TorchServe | `~/.claude/security-rules/backend/torchserve/CLAUDE.md` |
| HuggingFace Transformers | `~/.claude/security-rules/backend/transformers/CLAUDE.md` |

### Containers & Infrastructure

| Domain | File |
|--------|------|
| Container security (general) | `~/.claude/security-rules/containers/_core/container-security.md` |
| Kubernetes | `~/.claude/security-rules/containers/kubernetes/CLAUDE.md` |
| Docker | `~/.claude/security-rules/containers/docker/CLAUDE.md` |
| Terraform | `~/.claude/security-rules/iac/terraform/CLAUDE.md` |
| Pulumi | `~/.claude/security-rules/iac/pulumi/CLAUDE.md` |
| IaC security (general) | `~/.claude/security-rules/iac/_core/iac-security.md` |

### CI/CD

| Domain | File |
|--------|------|
| CI/CD security (general) | `~/.claude/security-rules/cicd/_core/cicd-security.md` |
| GitHub Actions | `~/.claude/security-rules/cicd/github-actions/CLAUDE.md` |
| GitLab CI | `~/.claude/security-rules/cicd/gitlab-ci/CLAUDE.md` |

### RAG / AI Pipelines

Read the RAG core rules plus the specific tool rules for whatever the pipeline uses.

#### RAG Core

| File | Covers |
|------|--------|
| `~/.claude/security-rules/rag/_core/document-processing-security.md` | Document ingestion, file parsing |
| `~/.claude/security-rules/rag/_core/embedding-security.md` | Embedding model security |
| `~/.claude/security-rules/rag/_core/retrieval-security.md` | Query-time retrieval security |
| `~/.claude/security-rules/rag/_core/vector-store-security.md` | Vector store access control |

#### Document Processing

| Tool | File |
|------|------|
| Docling | `~/.claude/security-rules/rag/document-processing/docling/CLAUDE.md` |
| LlamaParse | `~/.claude/security-rules/rag/document-processing/llamaparse/CLAUDE.md` |
| Parsers / OCR | `~/.claude/security-rules/rag/document-processing/parsers-ocr/CLAUDE.md` |
| Unstructured | `~/.claude/security-rules/rag/document-processing/unstructured/CLAUDE.md` |
| Chunking | `~/.claude/security-rules/rag/chunking/CLAUDE.md` |

#### Embeddings

| Tool | File |
|------|------|
| API-based embeddings | `~/.claude/security-rules/rag/embeddings/api-embeddings/CLAUDE.md` |
| Local embeddings | `~/.claude/security-rules/rag/embeddings/local-embeddings/CLAUDE.md` |

#### Vector Stores (managed)

| Store | File |
|-------|------|
| Pinecone | `~/.claude/security-rules/rag/vector-managed/pinecone/CLAUDE.md` |
| Weaviate Cloud | `~/.claude/security-rules/rag/vector-managed/weaviate-cloud/CLAUDE.md` |
| Azure AI Search | `~/.claude/security-rules/rag/vector-managed/azure-ai-search/CLAUDE.md` |
| MongoDB Atlas | `~/.claude/security-rules/rag/vector-managed/mongodb-atlas/CLAUDE.md` |
| Zilliz | `~/.claude/security-rules/rag/vector-managed/zilliz/CLAUDE.md` |

#### Vector Stores (self-hosted)

| Store | File |
|-------|------|
| Chroma | `~/.claude/security-rules/rag/vector-selfhosted/chroma/CLAUDE.md` |
| Qdrant | `~/.claude/security-rules/rag/vector-selfhosted/qdrant/CLAUDE.md` |
| Milvus | `~/.claude/security-rules/rag/vector-selfhosted/milvus/CLAUDE.md` |
| pgvector | `~/.claude/security-rules/rag/vector-selfhosted/pgvector/CLAUDE.md` |
| Weaviate (self-hosted) | `~/.claude/security-rules/rag/vector-selfhosted/weaviate/CLAUDE.md` |

#### Graph Databases

| Database | File |
|----------|------|
| Neo4j | `~/.claude/security-rules/rag/graph/neo4j/CLAUDE.md` |
| ArangoDB | `~/.claude/security-rules/rag/graph/arangodb/CLAUDE.md` |
| Neptune | `~/.claude/security-rules/rag/graph/neptune/CLAUDE.md` |
| Memgraph | `~/.claude/security-rules/rag/graph/memgraph/CLAUDE.md` |
| TigerGraph | `~/.claude/security-rules/rag/graph/tigergraph/CLAUDE.md` |

#### Orchestration

| Tool | File |
|------|------|
| LlamaIndex | `~/.claude/security-rules/rag/orchestration/llamaindex/CLAUDE.md` |
| LangChain loaders | `~/.claude/security-rules/rag/orchestration/langchain-loaders/CLAUDE.md` |
| Haystack | `~/.claude/security-rules/rag/orchestration/haystack/CLAUDE.md` |
| DSPy / txtai / RAGAS | `~/.claude/security-rules/rag/orchestration/dspy-txtai-ragas/CLAUDE.md` |

#### Search & Reranking

| Tool | File |
|------|------|
| Lexical search | `~/.claude/security-rules/rag/search-rerank/lexical/CLAUDE.md` |
| Neural rerankers | `~/.claude/security-rules/rag/search-rerank/neural-rerankers/CLAUDE.md` |

#### Observability

| Tool | File |
|------|------|
| Arize Phoenix | `~/.claude/security-rules/rag/observability/arize-phoenix/CLAUDE.md` |
| LangSmith | `~/.claude/security-rules/rag/observability/langsmith/CLAUDE.md` |
| Monitoring (general) | `~/.claude/security-rules/rag/observability/monitoring/CLAUDE.md` |
