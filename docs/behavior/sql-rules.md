# SQL Blocking Rules

`rsh` blocks dangerous SQL statements regardless of which binary executes them, and can additionally block any SQL client command that targets a forbidden database host.

## Keyword rules

Five `bin = None` rules scan the entire Bash command string for SQL keywords. Because no binary prefix is required, the rules fire for every execution path: inline flags (`psql -c "…"`), piped SQL (`echo "…" | mysql`), and heredocs alike.

### SQL — Destructive DML

| ID | Blocked when | Example |
|---|---|---|
| `sql-delete` | Command contains `DELETE FROM` (case-insensitive) | `psql -c "DELETE FROM users"` |
| `sql-truncate` | Command contains `TRUNCATE` (case-insensitive) | `echo "TRUNCATE TABLE orders" \| mysql` |

### SQL — Destructive DDL

| ID | Blocked when | Example |
|---|---|---|
| `sql-drop` | Command contains `DROP TABLE/DATABASE/SCHEMA/INDEX/VIEW/TRIGGER/FUNCTION/PROCEDURE` | `psql -c "DROP TABLE IF EXISTS legacy"` |
| `sql-alter-table` | Command contains `ALTER TABLE` | `mysql -e "ALTER TABLE users ADD COLUMN email TEXT"` |
| `sql-create-ddl` | Command contains `CREATE TABLE/DATABASE/SCHEMA` | `psql -c "CREATE DATABASE test_db"` |

**Known false positive:** `grep "DROP TABLE"` is blocked because the keyword appears in the command string. This is an accepted trade-off for a security hook — the model can rephrase the command.

## Forbidden databases

Beyond the keyword rules, `rsh` can block any SQL client command that targets a specific host. This catches operations that are not individually destructive but should never run against a protected environment (e.g. a production database).

```sh
rsh forbid database prod-db.example.com   # add to forbidden list
rsh forbid remove database prod-db.example.com
rsh forbid list                           # show clusters, namespaces, and databases
```

### How host extraction works

When a command contains a known SQL client binary (`mysql`, `mariadb`, `psql`, `sqlite3`, `sqlcmd`, `mssql-cli`), `rsh` tries two extraction methods in order:

1. **Connection URL** — regex `(?:postgresql|postgres|mysql|mariadb|sqlserver|mssql)://([^/:@\s]+)` captures the host segment.
2. **`-h` / `--host` flag** — `-h <host>` or `--host=<host>` / `--host <host>`.

If neither yields a hostname, the check is skipped (no host to compare). This means `psql mydbname` (implicit localhost) is not blocked against the forbidden list.

Comparison is case-insensitive exact match.

### Storage

`~/.config/rsh/forbidden.json` (or `%APPDATA%\rsh\forbidden.json` on Windows):

```json
{
  "clusters": [],
  "namespaces": [],
  "databases": ["prod-db.example.com"]
}
```

The `databases` field defaults to `[]` if absent (backwards-compatible with older config files).
