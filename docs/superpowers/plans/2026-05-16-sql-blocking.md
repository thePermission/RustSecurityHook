# SQL Blocking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Block dangerous SQL DML/DDL statements in any Bash command, and let users declare forbidden database hostnames that SQL clients may never target.

**Architecture:** Two independent additions — five `bin = None` regex rules in `src/blacklist.rs` (keyword-scan without binary guard), and a `databases` field plus `check_db` function in `src/forbid.rs` mirroring the existing cluster/namespace mechanism. Both are wired into the `run_check` / `check_content_blocked` paths in `src/main.rs`.

**Tech Stack:** Rust, `regex` crate (already a dependency), `serde`/`serde_json` for config persistence, `std::sync::LazyLock` for compiled regex caching.

---

## File Map

| File | Changes |
|---|---|
| `src/blacklist.rs` | Add 5 `RAW_RULES` entries; add tests; extend `rule_ids_are_distinct_and_match_expected_set` |
| `src/forbid.rs` | Add `databases` to `ForbidConfig`; add `HitKind::Database`; add `add_database`/`remove_database`; add `extract_db_host` and `check_db`; update `forbid::check` |
| `src/main.rs` | Update `run_check` and `check_content_blocked` for `HitKind::Database`; update `run_forbid` for `database` sub-commands; update `print_help`; update `list_rules` |

---

## Task 1: SQL blacklist rules

**Files:**
- Modify: `src/blacklist.rs`

- [ ] **Step 1: Add the five failing tests**

In the `tests` module of `src/blacklist.rs`, add after the `// ---- Helm ----` block:

```rust
// ---- SQL — Destructive DML ----

#[test]
fn blocks_sql_delete() {
    assert!(blocks(r#"psql -c "DELETE FROM users""#));
    assert!(blocks(r#"mysql mydb -e "delete from orders where id=1""#));
    assert!(blocks(r#"echo "DELETE FROM sessions" | psql"#));
    assert!(!blocks(r#"psql -c "SELECT * FROM users""#));
}

#[test]
fn blocks_sql_truncate() {
    assert!(blocks(r#"echo "TRUNCATE TABLE orders" | mysql"#));
    assert!(blocks(r#"sqlite3 app.db "truncate orders""#));
    assert!(!blocks(r#"mysql -e "INSERT INTO logs VALUES (1, 'ok')""#));
}

// ---- SQL — Destructive DDL ----

#[test]
fn blocks_sql_drop() {
    assert!(blocks(r#"psql -c "DROP TABLE IF EXISTS legacy""#));
    assert!(blocks(r#"mysql -e "drop database staging""#));
    assert!(blocks(r#"psql -c "DROP SCHEMA public""#));
    assert!(!blocks(r#"psql -c "CREATE INDEX idx ON users(email)""#));
}

#[test]
fn blocks_sql_alter_table() {
    assert!(blocks(r#"psql -c "ALTER TABLE users ADD COLUMN email TEXT""#));
    assert!(blocks(r#"mysql -e "alter table orders drop column foo""#));
    assert!(!blocks(r#"sqlite3 app.db "UPDATE users SET name='x' WHERE id=1""#));
}

#[test]
fn blocks_sql_create_schema() {
    assert!(blocks(r#"mysql -e "CREATE TABLE tmp (id INT)""#));
    assert!(blocks(r#"psql -c "CREATE DATABASE test_db""#));
    assert!(blocks(r#"psql -c "create schema analytics""#));
    assert!(!blocks(r#"psql -c "CREATE INDEX idx_email ON users(email)""#));
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test blocks_sql_ 2>&1 | head -40
```

Expected: 5 test failures — rules don't exist yet.

- [ ] **Step 3: Add the five rules to `RAW_RULES`**

In `src/blacklist.rs`, add after the `// ---- Helm ----` block and before the closing `];`:

```rust
// ---- SQL — Destructive DML ------------------------------------
(
    "sql-delete",
    "SQL — Destructive DML",
    None,
    r"(?i)\bDELETE\s+FROM\b",
    "Deletes rows from a database table — irreversible without a backup",
),
(
    "sql-truncate",
    "SQL — Destructive DML",
    None,
    r"(?i)\bTRUNCATE\b",
    "Removes all rows from a table instantly — no WHERE clause, no rollback without a transaction",
),
// ---- SQL — Destructive DDL ------------------------------------
(
    "sql-drop",
    "SQL — Destructive DDL",
    None,
    r"(?i)\bDROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|TRIGGER|FUNCTION|PROCEDURE)\b",
    "Permanently removes a database object and all its data",
),
(
    "sql-alter-table",
    "SQL — Destructive DDL",
    None,
    r"(?i)\bALTER\s+TABLE\b",
    "Modifies the schema of a table — column drops are irreversible",
),
(
    "sql-create-schema",
    "SQL — Destructive DDL",
    None,
    r"(?i)\bCREATE\s+(?:TABLE|DATABASE|SCHEMA)\b",
    "Creates a new database object — can permanently alter the schema",
),
```

- [ ] **Step 4: Update `rule_ids_are_distinct_and_match_expected_set`**

Replace the `expected` vector in that test with:

```rust
let expected = vec![
    "helm-uninstall",
    "k8s-apply-remote",
    "k8s-attach",
    "k8s-cluster-admin-binding",
    "k8s-cp-inbound",
    "k8s-debug-node",
    "k8s-delete-all",
    "k8s-delete-clusterrole",
    "k8s-delete-crd",
    "k8s-delete-namespace",
    "k8s-delete-node",
    "k8s-delete-pv-pvc",
    "k8s-delete-workload",
    "k8s-drain",
    "k8s-exec-shell",
    "k8s-force-delete",
    "k8s-proxy",
    "k8s-run-privileged",
    "sql-alter-table",
    "sql-create-schema",
    "sql-delete",
    "sql-drop",
    "sql-truncate",
];
```

- [ ] **Step 5: Run all blacklist tests**

```bash
cargo test --lib blacklist 2>&1
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/blacklist.rs
git commit -m "feat(blacklist): add SQL DML/DDL blocking rules"
```

---

## Task 2: `ForbidConfig.databases` field and persistence functions

**Files:**
- Modify: `src/forbid.rs`

- [ ] **Step 1: Add failing tests**

In the `tests` module of `src/forbid.rs`, add:

```rust
#[test]
fn add_and_remove_database_modifies_config() {
    let mut cfg = ForbidConfig::default();
    cfg.databases.push("prod-db.example.com".to_string());
    assert_eq!(cfg.databases.len(), 1);
    cfg.databases.retain(|d| d != "prod-db.example.com");
    assert!(cfg.databases.is_empty());
}

#[test]
fn forbid_config_is_empty_includes_databases() {
    assert!(ForbidConfig::default().is_empty());
    let cfg = ForbidConfig {
        clusters: vec![],
        namespaces: vec![],
        databases: vec!["prod-db.example.com".to_string()],
    };
    assert!(!cfg.is_empty());
}

#[test]
fn forbid_config_deserializes_without_databases_field() {
    let json = r#"{"clusters": ["prod-eu"], "namespaces": []}"#;
    let cfg: ForbidConfig = serde_json::from_str(json).unwrap();
    assert!(cfg.databases.is_empty());
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test --lib forbid::tests::add_and_remove 2>&1
cargo test --lib forbid::tests::forbid_config_is_empty 2>&1
```

Expected: compilation failure — `databases` field doesn't exist yet.

- [ ] **Step 3: Add `databases` to `ForbidConfig` and update `is_empty`**

In `src/forbid.rs`, replace the `ForbidConfig` struct and its `impl`:

```rust
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ForbidConfig {
    #[serde(default)]
    pub clusters: Vec<String>,
    #[serde(default)]
    pub namespaces: Vec<String>,
    #[serde(default)]
    pub databases: Vec<String>,
}

impl ForbidConfig {
    pub fn is_empty(&self) -> bool {
        self.clusters.is_empty() && self.namespaces.is_empty() && self.databases.is_empty()
    }
}
```

- [ ] **Step 4: Add `add_database` and `remove_database`**

After `remove_namespace` in `src/forbid.rs`, add:

```rust
pub fn add_database(host: &str) -> Result<bool> {
    let mut cfg = load();
    if cfg.databases.iter().any(|d| d == host) {
        return Ok(false);
    }
    cfg.databases.push(host.to_string());
    save(&cfg)?;
    Ok(true)
}

pub fn remove_database(host: &str) -> Result<bool> {
    let mut cfg = load();
    let before = cfg.databases.len();
    cfg.databases.retain(|d| d != host);
    let changed = cfg.databases.len() != before;
    if changed {
        save(&cfg)?;
    }
    Ok(changed)
}
```

- [ ] **Step 5: Run all forbid tests**

```bash
cargo test --lib forbid 2>&1
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/forbid.rs
git commit -m "feat(forbid): add databases field to ForbidConfig with add/remove functions"
```

---

## Task 3: DB hostname extraction and `check_db`

**Files:**
- Modify: `src/forbid.rs`

- [ ] **Step 1: Add failing tests**

At the top of the `tests` module in `src/forbid.rs`, add this helper (used by the new tests):

```rust
fn cfg_databases(hosts: &[&str]) -> ForbidConfig {
    ForbidConfig {
        clusters: vec![],
        namespaces: vec![],
        databases: hosts.iter().map(|s| s.to_string()).collect(),
    }
}
```

Then add the tests:

```rust
#[test]
fn check_db_blocks_connection_url() {
    let cfg = cfg_databases(&["prod-db.example.com"]);
    assert!(check_db("psql postgresql://prod-db.example.com/mydb", &cfg).is_some());
    assert!(check_db("mysql mysql://prod-db.example.com:3306/app", &cfg).is_some());
}

#[test]
fn check_db_blocks_url_with_userinfo() {
    let cfg = cfg_databases(&["prod-db.example.com"]);
    assert!(check_db(
        "psql postgresql://user:secret@prod-db.example.com/mydb",
        &cfg
    ).is_some());
}

#[test]
fn check_db_blocks_host_flag_space_form() {
    let cfg = cfg_databases(&["prod-db.example.com"]);
    assert!(check_db("psql -h prod-db.example.com -U user mydb", &cfg).is_some());
    assert!(check_db("mysql -h prod-db.example.com mydb", &cfg).is_some());
}

#[test]
fn check_db_blocks_host_flag_equals_form() {
    let cfg = cfg_databases(&["prod-db.example.com"]);
    assert!(check_db("psql --host=prod-db.example.com mydb", &cfg).is_some());
}

#[test]
fn check_db_allows_non_forbidden_host() {
    let cfg = cfg_databases(&["prod-db.example.com"]);
    assert!(check_db("psql -h staging-db.example.com mydb", &cfg).is_none());
    assert!(check_db("psql postgresql://staging-db.example.com/mydb", &cfg).is_none());
}

#[test]
fn check_db_allows_sql_client_without_host() {
    let cfg = cfg_databases(&["prod-db.example.com"]);
    assert!(check_db("psql mydbname", &cfg).is_none());
}

#[test]
fn check_db_skips_non_sql_client_commands() {
    let cfg = cfg_databases(&["prod-db.example.com"]);
    assert!(check_db("grep prod-db.example.com /etc/hosts", &cfg).is_none());
    assert!(check_db("curl http://prod-db.example.com/api", &cfg).is_none());
}

#[test]
fn check_db_returns_database_hit_kind() {
    let cfg = cfg_databases(&["prod-db.example.com"]);
    let hit = check_db("psql -h prod-db.example.com mydb", &cfg).unwrap();
    assert_eq!(hit.kind, HitKind::Database);
    assert_eq!(hit.value, "prod-db.example.com");
    assert!(!hit.from_current_context);
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test --lib forbid::tests::check_db 2>&1 | head -20
```

Expected: compilation failure — `check_db` and `HitKind::Database` don't exist yet.

- [ ] **Step 3: Add `HitKind::Database`**

In `src/forbid.rs`, update `HitKind`:

```rust
#[derive(Debug, PartialEq, Eq)]
pub enum HitKind {
    Cluster,
    Namespace,
    Database,
}
```

- [ ] **Step 4: Add `use std::sync::LazyLock` import**

At the top of `src/forbid.rs`, the file already has `use std::path::PathBuf;`. Add `LazyLock` to the `std` imports:

```rust
use std::sync::LazyLock;
```

- [ ] **Step 5: Add SQL client list, `extract_db_host`, and `check_db`**

After the `check_with` function in `src/forbid.rs`, add:

```rust
const SQL_CLIENTS: &[&str] = &["mysql", "mariadb", "psql", "sqlite3", "sqlcmd", "mssql-cli"];

fn extract_db_host(command: &str) -> Option<String> {
    static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?:postgresql|postgres|mysql|mariadb|sqlserver|mssql)://(?:[^@/\s]+@)?([^/:?\s]+)",
        )
        .expect("valid regex")
    });
    if let Some(caps) = URL_RE.captures(command) {
        if let Some(host) = caps.get(1).map(|m| m.as_str().to_string()) {
            if !host.is_empty() {
                return Some(host);
            }
        }
    }
    extract_flag(command, &["-h", "--host"])
}

pub fn check_db(command: &str, cfg: &ForbidConfig) -> Option<Hit> {
    if cfg.databases.is_empty() {
        return None;
    }
    let first = command.split_whitespace().next()?;
    let basename = std::path::Path::new(first)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(first);
    let basename = basename
        .strip_suffix(".exe")
        .or_else(|| basename.strip_suffix(".EXE"))
        .unwrap_or(basename);
    if !SQL_CLIENTS.contains(&basename) {
        return None;
    }
    let host = extract_db_host(command)?;
    if cfg.databases.iter().any(|d| d.eq_ignore_ascii_case(&host)) {
        Some(Hit {
            kind: HitKind::Database,
            value: host,
            from_current_context: false,
        })
    } else {
        None
    }
}
```

- [ ] **Step 6: Run all forbid tests**

```bash
cargo test --lib forbid 2>&1
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/forbid.rs
git commit -m "feat(forbid): add check_db for forbidden database hostname detection"
```

---

## Task 4: Wire `check_db` into the hook pipeline

**Files:**
- Modify: `src/forbid.rs` (update `check`)
- Modify: `src/main.rs` (update `run_check`, `check_content_blocked`)

- [ ] **Step 1: Update `forbid::check` to also run `check_db`**

In `src/forbid.rs`, replace the `check` function:

```rust
pub fn check(command: &str) -> Option<Hit> {
    let cfg = load();
    if cfg.is_empty() {
        return None;
    }
    check_with(command, &aliases::ALIASES, &cfg, &KubectlEnv)
        .or_else(|| check_db(command, &cfg))
}
```

- [ ] **Step 2: Update `run_check` in `src/main.rs` to handle `HitKind::Database`**

In `src/main.rs`, replace the forbid block in `run_check`:

```rust
if let Some(hit) = forbid::check(command) {
    match hit.kind {
        forbid::HitKind::Cluster => {
            let origin = if hit.from_current_context { " (current kubeconfig)" } else { "" };
            eprintln!("rsh blocked command: forbidden cluster '{}'{origin}", hit.value);
        }
        forbid::HitKind::Namespace => {
            let origin = if hit.from_current_context { " (current kubeconfig)" } else { "" };
            eprintln!("rsh blocked command: forbidden namespace '{}'{origin}", hit.value);
        }
        forbid::HitKind::Database => {
            eprintln!("rsh blocked command: forbidden database host '{}'", hit.value);
        }
    }
    return ExitCode::from(2);
}
```

- [ ] **Step 3: Update `check_content_blocked` in `src/main.rs` to handle `HitKind::Database`**

In `check_content_blocked`, replace the inner forbid hit block so it handles all three variants and also calls `check_db`:

```rust
if let Some(hit) = forbid::check_with(line, &aliases::ALIASES, &cfg, &forbid::KubectlEnv)
    .or_else(|| forbid::check_db(line, &cfg))
{
    let msg = match hit.kind {
        forbid::HitKind::Cluster => {
            let origin = if hit.from_current_context { " (current kubeconfig)" } else { "" };
            format!("forbidden cluster '{}'{origin}", hit.value)
        }
        forbid::HitKind::Namespace => {
            let origin = if hit.from_current_context { " (current kubeconfig)" } else { "" };
            format!("forbidden namespace '{}'{origin}", hit.value)
        }
        forbid::HitKind::Database => {
            format!("forbidden database host '{}'", hit.value)
        }
    };
    eprintln!("rsh blocked {label}: {msg}");
    return true;
}
```

- [ ] **Step 4: Run all tests**

```bash
cargo test 2>&1
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/forbid.rs src/main.rs
git commit -m "feat(forbid): wire check_db into hook check pipeline"
```

---

## Task 5: CLI sub-commands and display

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Update `usage` string in `run_forbid`**

In the `run_forbid` function, replace the `usage` binding:

```rust
let usage = "usage:\n  \
    rsh forbid cluster <name>\n  \
    rsh forbid namespace <name>\n  \
    rsh forbid database <hostname>\n  \
    rsh forbid remove cluster|namespace|database <name>\n  \
    rsh forbid list";
```

- [ ] **Step 2: Add `database` arm to `run_forbid`**

In the outer `match` of `run_forbid`, add before the `Some("remove")` arm:

```rust
Some("database") => match args.get(1) {
    Some(name) => match forbid::add_database(name) {
        Ok(true) => {
            eprintln!("forbid: added database '{name}'");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("forbid: database '{name}' was already on the list");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("forbid failed: {e:#}");
            ExitCode::FAILURE
        }
    },
    None => {
        eprintln!("usage: rsh forbid database <hostname>");
        ExitCode::FAILURE
    }
},
```

- [ ] **Step 3: Add `database` case to the `remove` arm**

In the `Some("remove")` arm, add before the catch-all `_` arm:

```rust
(Some("database"), Some(name)) => match forbid::remove_database(name) {
    Ok(true) => {
        eprintln!("forbid: removed database '{name}'");
        ExitCode::SUCCESS
    }
    Ok(false) => {
        eprintln!("forbid: database '{name}' was not on the list");
        ExitCode::SUCCESS
    }
    Err(e) => {
        eprintln!("forbid failed: {e:#}");
        ExitCode::FAILURE
    }
},
```

- [ ] **Step 4: Update `forbid list` output to include databases**

Replace the `Some("list")` arm body:

```rust
Some("list") => {
    let cfg = forbid::load();
    if cfg.is_empty() {
        println!("(no forbidden clusters, namespaces, or databases configured)");
    } else {
        println!("Clusters:");
        if cfg.clusters.is_empty() {
            println!("  (none)");
        } else {
            for c in &cfg.clusters {
                println!("  • {c}");
            }
        }
        println!("Namespaces:");
        if cfg.namespaces.is_empty() {
            println!("  (none)");
        } else {
            for n in &cfg.namespaces {
                println!("  • {n}");
            }
        }
        println!("Databases:");
        if cfg.databases.is_empty() {
            println!("  (none)");
        } else {
            for d in &cfg.databases {
                println!("  • {d}");
            }
        }
    }
    ExitCode::SUCCESS
}
```

- [ ] **Step 5: Update `print_help`**

Replace the `eprintln!` call in `print_help`:

```rust
eprintln!(
    "rsh - Rust Security Hook\n\
     \n\
     USAGE:\n\
       rsh                       Hook mode: reads Claude Code PreToolUse JSON from stdin\n\
       rsh init [-g|--global]    Register rsh as PreToolUse hook in settings.json\n\
                                 (-g writes to ~/.claude/settings.json, otherwise ./.claude/settings.json)\n\
       rsh check \"<command>\"    Run the blacklist against a literal command string\n\
       rsh list                  Show all configured blacklist rules and aliases\n\
       rsh alias <cmd> <alias>   Register that <alias> on this system points to <cmd>\n\
                                 (e.g. `rsh alias kubectl k` if `k` is a symlink/wrapper for kubectl)\n\
       rsh detect-aliases [cmd]  Auto-detect aliases by scanning $PATH for symlinks/hardlinks.\n\
                                 With no argument, scans all commands referenced by rules.\n\
       rsh forbid cluster <name>              Add a forbidden cluster (context).\n\
       rsh forbid namespace <name>            Add a forbidden namespace.\n\
       rsh forbid database <hostname>         Add a forbidden database hostname.\n\
       rsh forbid remove cluster|namespace|database <name>\n\
                                              Remove an entry from the forbid list.\n\
       rsh forbid list               Show the current forbid lists.\n\
       rsh help                  Show this message\n\
       rsh -v | --version        Show version"
);
```

- [ ] **Step 6: Update `list_rules` section header and database display**

In `list_rules`, replace the `print_section("FORBIDDEN CLUSTERS AND NAMESPACES")` block with:

```rust
print_section("FORBIDDEN CLUSTERS, NAMESPACES AND DATABASES");
let fcfg = forbid::load();
if fcfg.is_empty() {
    println!("  (none — register with `rsh forbid cluster <name>`,");
    println!("                       `rsh forbid namespace <name>`, or");
    println!("                       `rsh forbid database <hostname>`)\n");
} else {
    if fcfg.clusters.is_empty() {
        println!("  Clusters:   (none)");
    } else {
        println!("  Clusters ({}):", fcfg.clusters.len());
        for c in &fcfg.clusters {
            println!("    • {c}");
        }
    }
    if fcfg.namespaces.is_empty() {
        println!("  Namespaces: (none)");
    } else {
        println!("  Namespaces ({}):", fcfg.namespaces.len());
        for n in &fcfg.namespaces {
            println!("    • {n}");
        }
    }
    if fcfg.databases.is_empty() {
        println!("  Databases:  (none)");
    } else {
        println!("  Databases ({}):", fcfg.databases.len());
        for d in &fcfg.databases {
            println!("    • {d}");
        }
    }
    println!();
}
```

- [ ] **Step 7: Run all tests and build**

```bash
cargo test 2>&1 && cargo build --release 2>&1 | tail -5
```

Expected: all tests pass, binary builds without warnings.

- [ ] **Step 8: Manual smoke test**

```bash
./target/release/rsh forbid database prod-db.example.com
./target/release/rsh forbid list
echo '{"tool_name":"Bash","tool_input":{"command":"psql -h prod-db.example.com mydb"}}' | ./target/release/rsh
echo "Exit: $?"
./target/release/rsh forbid remove database prod-db.example.com
./target/release/rsh forbid list
```

Expected:
```
forbid: added database 'prod-db.example.com'
Databases:
  • prod-db.example.com
rsh blocked command: forbidden database host 'prod-db.example.com'
Exit: 2
forbid: removed database 'prod-db.example.com'
(no forbidden clusters, namespaces, or databases configured)
```

- [ ] **Step 9: Commit**

```bash
git add src/main.rs
git commit -m "feat(cli): add forbid database sub-commands and update help/list output"
```
