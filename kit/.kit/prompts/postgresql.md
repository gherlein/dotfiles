---
description: PostgreSQL best practices for data types, indexing, queries, and migrations
---
PostgreSQL work: $@

## Standards

### Data Types
- Use `text` not `varchar` (unless length constraint is a business rule)
- Use `timestamptz` not `timestamp`
- Use `uuid` for primary keys in distributed systems
- Use `jsonb` not `json`
- Use `bigint` for IDs that may exceed 2^31

### Indexing
- Every foreign key gets an index
- Use partial indexes for filtered queries
- Use GIN indexes for jsonb and array columns
- Use covering indexes (INCLUDE) to avoid table lookups
- Analyze query plans with `EXPLAIN (ANALYZE, BUFFERS)`

### Queries
- Parameterized queries ONLY: never string concatenation
- Use CTEs for readability but be aware they are optimization fences in older PG
- Prefer EXISTS over IN for subqueries
- Use RETURNING to avoid extra round trips

### Migrations
- Always reversible (include up AND down)
- Never drop columns in the same release as code changes
- Add columns as nullable first, backfill, then add constraints
- Use advisory locks to prevent concurrent migrations

### ORM Policy
- ORMs are acceptable for CRUD; use raw SQL for complex queries
- Always review generated SQL via query logging
