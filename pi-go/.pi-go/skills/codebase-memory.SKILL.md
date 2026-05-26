# Codebase Memory

When `codebase-memory` MCP tools are available, prefer them over grep/find/cat for
structural code questions. Graph queries cost ~500 tokens. File-by-file exploration
costs 50,000–400,000 tokens.

## Use the graph for

- "Who calls X?" → `trace_call_path(function_name="X", direction="inbound")`
- "What does X call?" → `trace_call_path(function_name="X", direction="outbound", depth=3)`
- "Find functions matching a pattern" → `search_graph(label="Function", name_pattern=".*Handler.*")`
- "Understand the structure" → `get_graph_schema` first, then targeted queries
- "Read a function body" → `get_code_snippet(qualified_name="pkg.FunctionName")`
- "Dead code?" → `search_graph(label="Function", relationship="CALLS", direction="inbound", max_degree=0, exclude_entry_points=true)`
- "Complex traversal" → `query_graph` with Cypher syntax
- "REST routes" → `search_graph(label="Route")`

## Do NOT use the graph for

- Text/string/comment search — use grep or the `search_code` tool
- Single-file reads where you already know the path — use `read_file` directly
- Config values, error message strings — not indexed

## Workflow before making changes

1. `list_projects` — confirm the graph is indexed and recent
2. `get_graph_schema` — understand node/edge counts and types
3. `trace_call_path` or `search_graph` — find blast radius before editing
4. `get_code_snippet` — read the relevant function bodies
5. Make edits; run `index_repository` again if significant structure changed

