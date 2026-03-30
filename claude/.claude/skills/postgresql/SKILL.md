---
name: postgresql
description: PostgreSQL best practices for data types, indexing, queries, migrations, ORM policy, monitoring, and backups
---

# PostgreSQL Database Practices

Strongly prefer PostgreSQL for all database needs.

## Data Types

- `UUID` or `BIGSERIAL` for primary keys
- `TIMESTAMPTZ` for timestamps (never `TIMESTAMP`)
- `JSONB` (never `JSON`)
- `TEXT` instead of `VARCHAR`
- `NUMERIC` for currency (never floating point)

## Indexing Strategy

- Index all foreign keys
- Use `CREATE INDEX CONCURRENTLY` in production
- Composite indexes for multi-column queries
- Partial indexes for filtered queries
- GIN indexes for JSONB columns
- BRIN indexes for ordered data (timestamps)

## Constraints

- Use PRIMARY KEY, FOREIGN KEY, UNIQUE, NOT NULL, CHECK, EXCLUDE constraints
- Let the database enforce data integrity

## Query Optimization

- Select only needed columns
- Avoid N+1 queries
- Use `EXPLAIN ANALYZE` to verify query plans
- Leverage CTEs, window functions, `LATERAL` joins, full-text search, `RETURNING` clause
- Use materialized views for complex frequent queries

## ORM Policy

- Do not use any ORM without specific approval first
- When approved: Prisma (preferred), Drizzle ORM, Knex.js, node-postgres
- Always use parameterized queries (`$1`, `$2` notation)

## Migrations

- Always use migrations; never modify production schema manually
- Keep migrations small and reversible
- Test on staging before production
- Use transactional DDL; `CREATE INDEX CONCURRENTLY` must be outside a transaction

## Connection Management

- Connection pooling with PgBouncer
- Read replicas where appropriate
- Use transactions for atomic operations

## Security

- Application should not use superuser database credentials
- Encrypt sensitive data at rest and in transit
- Implement audit logging

## Monitoring

- Enable `pg_stat_statements`, configure `log_min_duration_statement`
- Monitor cache hit ratios, index usage, table bloat, replication lag, lock contention
- Configure autovacuum; use table partitioning for large tables

## Backups

- Implement automated backups (pg_dump, pg_basebackup, WAL archiving, point-in-time recovery)
- Test backup restoration regularly
- Document recovery procedures and RTO/RPO targets

## Development

- Docker for local PostgreSQL
- Useful extensions: pg_stat_statements, uuid-ossp, pg_trgm, citext
