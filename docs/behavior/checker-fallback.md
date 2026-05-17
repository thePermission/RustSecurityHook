---
title: FallbackChecker
tags:
  - rsh/checker
  - rsh/sql
  - rsh/subprocess
aliases:
  - fallback checker
  - FallbackChecker
---

# FallbackChecker behavior

`FallbackChecker` runs on **every** segment regardless of which tools appear in it. Its `bins()` method returns an empty list — `detect_checkers` always includes it.

Two categories of check:

1. `bin = None` blacklist rules — SQL keywords and subprocess list bypass
2. Database forbid check — blocks SQL client commands targeting a forbidden host

## SQL keyword rules

Five rules scan the entire content for SQL keywords. No binary prefix required — they fire for every execution path: inline flags, pipes, heredocs.

### Destructive DML

| ID | Blocked when | Example |
|---|---|---|
| `sql-delete` | Content contains `DELETE FROM` (case-insensitive) | `psql -c "DELETE FROM users"` |
| `sql-truncate` | Content contains `TRUNCATE` (case-insensitive) | `echo "TRUNCATE TABLE orders" \| mysql` |

### Destructive DDL

| ID | Blocked when | Example |
|---|---|---|
| `sql-drop` | Content contains `DROP TABLE/DATABASE/SCHEMA/INDEX/VIEW/TRIGGER/FUNCTION/PROCEDURE` | `psql -c "DROP TABLE IF EXISTS legacy"` |
| `sql-alter-table` | Content contains `ALTER TABLE` | `mysql -e "ALTER TABLE users ADD COLUMN email TEXT"` |
| `sql-create-ddl` | Content contains `CREATE TABLE/DATABASE/SCHEMA` | `psql -c "CREATE DATABASE test_db"` |

Known false positive: `grep "DROP TABLE"` is blocked because the keyword appears in the content. Accepted trade-off — the model can rephrase.

## Subprocess list bypass rules

Two `bin = None` rules close a bypass where kubectl/helm appear as Python/Ruby/Node subprocess argument **lists** rather than shell strings. Binary-bound rules in `[[checker-kubectl]]` and `[[checker-helm]]` do not fire in this case.

| ID | Blocked pattern | Example |
|---|---|---|
| `k8s-subprocess-list` | `['kubectl', ..., 'delete']` in any subprocess call | `subprocess.run(['kubectl', 'delete', 'ns', 'prod'])` |
| `helm-subprocess-list` | `['helm', ..., 'uninstall'\|'delete']` in any subprocess call | `subprocess.run(['helm', 'uninstall', 'app'])` |

Both single-quoted and double-quoted list forms match. Non-destructive calls (`['kubectl', 'get', 'pods']`) are not blocked.

## Database forbid check

After the keyword rules, `FallbackChecker` calls `forbid::check_db` line by line on the content (skipping blank lines and `#` comments). Blocks SQL client commands targeting a forbidden database host.

Supported clients: `mysql`, `mariadb`, `psql`, `sqlite3`, `sqlcmd`, `mssql-cli`.

### Host extraction

Extracts the target host from:

1. Connection URL — regex matches `mysql://`, `postgresql://`, etc.; captures the hostname
2. `-h` or `--host` flag — extracts the argument following either flag
3. No extraction fallback — returns None if neither is present

### Configuration

Stored in `~/.config/rsh/forbidden.json` (or platform-equivalent via `aliases::home_dir()`):

```json
{
  "clusters": [],
  "namespaces": [],
  "databases": ["prod.example.com", "legacy-db.internal"]
}
```

### CLI

| Command | Effect |
|---|---|
| `rsh forbid database <host>` | Adds a forbidden database host |
| `rsh forbid remove database <host>` | Removes a host from the forbid list |
| `rsh forbid list` | Shows all forbidden clusters, namespaces, and databases |

### Examples

Blocked:

- `mysql -h prod.example.com mydb` — explicit `-h` flag targets forbidden host
- `psql postgresql://user@legacy-db.internal/mydb` — URL contains forbidden host
- `mariadb -h db.prod.local -u root` — flag extraction succeeds

Allowed:

- `mysql localhost mydb` — no `-h` flag, no URL (implicitly localhost)
- `sqlite3 /tmp/test.db` — sqlite3 not in the extraction logic
- `psql mydb` — no host flag or URL
