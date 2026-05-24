# ADR 020 — SQL Blocking: Keyword Rules and Forbidden Databases

**Date:** 2026-05-16  
**Status:** Accepted

## Context

`rsh` already blocked destructive Kubernetes and Helm operations. SQL clients (psql, mysql, sqlite3, etc.) can execute equally destructive operations — DELETE, TRUNCATE, DROP — from any Bash command in a Claude Code session. Unlike kubectl, SQL clients have no stable subcommand structure; the dangerous payload is inside a string argument. In addition, users sometimes want to protect specific database hosts entirely (e.g. a production DB), regardless of which SQL statement is issued.

## Decision

Two independent additions were made to `rsh`:

**1. SQL keyword rules** (`src/blacklist.rs`): Five `bin = None` rules that scan the full Bash command string for SQL keywords, without requiring a specific binary prefix.

| ID | Category | Pattern |
|---|---|---|
| `sql-delete` | SQL — Destructive DML | `(?i)\bDELETE\s+FROM\b` |
| `sql-truncate` | SQL — Destructive DML | `(?i)\bTRUNCATE\b` |
| `sql-drop` | SQL — Destructive DDL | `(?i)\bDROP\s+(?:TABLE\|DATABASE\|SCHEMA\|INDEX\|VIEW\|TRIGGER\|FUNCTION\|PROCEDURE)\b` |
| `sql-alter-table` | SQL — Destructive DDL | `(?i)\bALTER\s+TABLE\b` |
| `sql-create-ddl` | SQL — Destructive DDL | `(?i)\bCREATE\s+(?:TABLE\|DATABASE\|SCHEMA)\b` |

**2. Forbidden databases** (`src/forbid.rs`): A `databases` field added to `ForbidConfig` (stored in `forbidden.json`). When a canonical SQL client binary is present in the command, `rsh` extracts the target host from arguments after that client token: a connection URL (`postgresql://host/...`) or a `-h`/`--host` flag, including attached short form (`-hhost`). Wrapper flags before the SQL client are ignored.

CLI surface: `rsh forbid database <hostname>`, `rsh forbid remove database <hostname>`, `rsh forbid list`.

## Alternatives Considered

- **Binary-bound rules** (e.g. only block when `psql` or `mysql` is present): Rejected — SQL keywords can appear in heredocs, `echo ... | psql`, or other indirect invocations where the binary check would miss them.
- **Allowing `sql-create-ddl`**: CREATE TABLE/DATABASE/SCHEMA can permanently alter the schema; including it keeps parity with DROP.

## Consequences

- `grep "DROP TABLE"` is blocked — accepted trade-off for an AI-agent hook. The blast radius of false positives is low (the model retries without the keyword).
- `psql mydbname` without a `-h` flag is not checked against the forbidden list (no hostname to extract) — fail-open is intentional.
- SQL database forbid checks recognize canonical client names (`psql`, `mysql`, etc.). Registered aliases do not currently extend database host extraction.
- `bin = None` rules add to the global scan cost; measured impact is negligible given the small rule count.
