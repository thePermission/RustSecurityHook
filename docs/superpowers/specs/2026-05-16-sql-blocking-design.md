# SQL Blocking — Design Spec

**Date:** 2026-05-16  
**Status:** Approved

## Overview

Two independent additions to `rsh`:

1. **SQL keyword rules** — five new entries in `RAW_RULES` (`src/blacklist.rs`) that block dangerous SQL statements in any Bash command, regardless of which tool executes them.
2. **Forbidden databases** — a new sub-feature in `src/forbid.rs` that lets the user declare hostnames of databases that must never be targeted by a SQL client, mirroring the existing cluster/namespace forbid mechanism.

---

## Part 1: SQL Keyword Rules

### Approach

`bin = None` rules (keyword-scan without binary binding). The pattern is applied directly to the full Bash command string. This catches every execution path — inline flags (`psql -c "…"`), piped SQL (`echo "…" | mysql`), heredocs, and file writes (`echo "…" > script.sql`) — because the SQL keyword appears in the command string in all cases.

Accepted trade-off: `grep "DROP TABLE"` would also be blocked. For an AI-agent security hook this is acceptable.

### New Categories and Rules

**Category: SQL — Destructive DML**

| ID | Pattern | Example blocked |
|---|---|---|
| `sql-delete` | `(?i)\bDELETE\s+FROM\b` | `psql -c "DELETE FROM users"` |
| `sql-truncate` | `(?i)\bTRUNCATE\b` | `echo "TRUNCATE TABLE orders" \| mysql` |

**Category: SQL — Destructive DDL**

| ID | Pattern | Example blocked |
|---|---|---|
| `sql-drop` | `(?i)\bDROP\s+(?:TABLE\|DATABASE\|SCHEMA\|INDEX\|VIEW\|TRIGGER\|FUNCTION\|PROCEDURE)\b` | `psql -c "DROP TABLE IF EXISTS legacy"` |
| `sql-alter-table` | `(?i)\bALTER\s+TABLE\b` | `mysql -e "ALTER TABLE users ADD COLUMN email TEXT"` |
| `sql-create-schema` | `(?i)\bCREATE\s+(?:TABLE\|DATABASE\|SCHEMA)\b` | `psql -c "CREATE DATABASE test_db"` |

All five rules use `bin = None`, so the pattern is used as-is without a binary-name prefix.

### Tests

Each rule gets at least one positive and one negative test in `src/blacklist.rs`.

**Positive (blocked):**
- `psql -c "DELETE FROM users"`
- `mysql mydb -e "delete from orders where id=1"` (case-insensitive)
- `echo "TRUNCATE TABLE sessions" | psql`
- `sqlite3 app.db "truncate orders"`
- `psql -c "DROP TABLE IF EXISTS legacy"`
- `mysql -e "drop database staging"`
- `psql -c "ALTER TABLE users ADD COLUMN email TEXT"`
- `mysql -e "CREATE TABLE tmp (id INT)"`
- `psql -c "CREATE DATABASE test_db"`

**Negative (allowed):**
- `psql -c "SELECT * FROM users"`
- `mysql -e "INSERT INTO logs VALUES (1, 'ok')"`
- `sqlite3 app.db "UPDATE users SET name='x' WHERE id=1"`
- `psql -c "CREATE INDEX idx_email ON users(email)"` — INDEX is not in `sql-create-schema`

`rule_ids_are_distinct_and_match_expected_set` is extended with the five new IDs.

---

## Part 2: Forbidden Databases

### Overview

Mirrors `rsh forbid cluster` / `rsh forbid namespace`. Users declare hostnames; `forbid::check` blocks any SQL client command that targets a forbidden host.

### Storage

`~/.config/rsh/forbidden.json` gains a `databases` key:

```json
{
  "clusters": [],
  "namespaces": [],
  "databases": ["prod-db.example.com"]
}
```

Deserialization is backwards-compatible: missing `databases` key defaults to an empty `Vec`.

### CLI Surface

```
rsh forbid database <hostname>           # add to list
rsh forbid remove database <hostname>    # remove from list
rsh forbid list                          # shows clusters, namespaces, and databases
```

### Hostname Extraction

Two sources, tried in order:

1. **Connection URL** — regex `(?:postgresql|postgres|mysql|mariadb|sqlserver|mssql)://([^/:@\s]+)` captures the host segment.
2. **`-h` / `--host` flag** — regex `-h\s+(\S+)` and `--host[=\s]+(\S+)`.

If neither source yields a hostname, the check is skipped (pass-through). This avoids blocking `psql mydbname` where the implicit host is `localhost`.

### Client Guard

The forbidden-database check is only entered when the command contains a known SQL client binary: `mysql`, `mariadb`, `psql`, `sqlite3`, `sqlcmd`, or `mssql-cli`. Commands that happen to contain a hostname string but are not SQL client invocations are not checked.

### Match Semantics

**Exact match** — the extracted hostname is compared case-insensitively against each entry in `forbidden.databases`.

### Check Flow in `forbid::check`

```
blacklist::check(cmd) → hit? → block (existing)
forbid::check(cmd):
  1. kubectl/helm forbidden cluster/namespace check (existing)
  2. SQL client present in cmd?
     no  → return None
     yes → extract hostname
           no hostname found → return None
           hostname in forbidden.databases → return Hit { id: "sql-forbidden-database", reason: "…" }
           not found → return None
```

### Error Handling

Consistent with the existing forbid module: if `forbidden.json` cannot be read or parsed, the check is skipped (fail-open). A hook crash must not lock up the session.

### Tests

Unit tests via the `DbEnv` trait (analogous to `KubeEnv`) so the check is testable without a real database:

- Blocked: command with URL containing forbidden host
- Blocked: command with `-h forbidden-host` flag
- Allowed: same commands with a non-forbidden host
- Allowed: SQL client command without any host flag
- Allowed: non-SQL-client command containing forbidden hostname string
