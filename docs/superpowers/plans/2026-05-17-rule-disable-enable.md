# Rule Disable/Enable Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `rsh rule disable <id>` / `rsh rule enable <id>` to toggle individual blacklist rules off and on, persisted in `~/.config/rsh/disabled-rules.json`.

**Architecture:** New `src/disabled.rs` module owns config I/O and a process-wide `LazyLock<HashSet<String>>`. `blacklist::check()` delegates to an inner `check_filtered()` that accepts an explicit disabled set (testable without global state). `main.rs` gets a new `rule` top-level subcommand.

**Tech Stack:** Rust, serde_json, std::collections::HashSet, std::sync::LazyLock

---

### Task 1: `src/disabled.rs` — storage module

**Files:**
- Create: `src/disabled.rs`
- Modify: `src/main.rs` (add `mod disabled;`)

- [ ] **Step 1: Write failing tests for `disabled.rs`**

Add a new file `src/disabled.rs` with the tests first:

```rust
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::LazyLock;

use crate::aliases;

pub static DISABLED: LazyLock<HashSet<String>> = LazyLock::new(load);

pub fn config_path() -> Result<PathBuf> {
    let base = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else if cfg!(windows) {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            PathBuf::from(appdata)
        } else {
            aliases::home_dir()
                .context("could not determine home directory")?
                .join(".config")
        }
    } else {
        aliases::home_dir()
            .context("could not determine home directory")?
            .join(".config")
    };
    Ok(base.join("rsh").join("disabled-rules.json"))
}

pub fn load() -> HashSet<String> {
    todo!()
}

pub fn save(_set: &HashSet<String>) -> Result<PathBuf> {
    todo!()
}

pub fn add(_id: &str) -> Result<bool> {
    todo!()
}

pub fn remove(_id: &str) -> Result<bool> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn load_from(path: &std::path::Path) -> HashSet<String> {
        if !path.exists() {
            return HashSet::new();
        }
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let ids: Vec<String> = serde_json::from_str(&text).unwrap_or_default();
        ids.into_iter().collect()
    }

    fn save_to(set: &HashSet<String>, path: &std::path::Path) {
        let mut sorted: Vec<&String> = set.iter().collect();
        sorted.sort();
        std::fs::write(path, serde_json::to_string_pretty(&sorted).unwrap()).unwrap();
    }

    #[test]
    fn load_returns_empty_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disabled-rules.json");
        assert!(load_from(&path).is_empty());
    }

    #[test]
    fn load_returns_empty_on_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disabled-rules.json");
        std::fs::write(&path, "not valid json").unwrap();
        assert!(load_from(&path).is_empty());
    }

    #[test]
    fn round_trip_add_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disabled-rules.json");

        let mut set = load_from(&path);
        assert!(set.insert("k8s-drain".to_string()));
        save_to(&set, &path);

        let loaded = load_from(&path);
        assert!(loaded.contains("k8s-drain"));

        let mut set2 = load_from(&path);
        assert!(set2.remove("k8s-drain"));
        save_to(&set2, &path);

        let loaded2 = load_from(&path);
        assert!(!loaded2.contains("k8s-drain"));
    }

    #[test]
    fn save_produces_sorted_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disabled-rules.json");
        let set: HashSet<String> = ["z-rule", "a-rule", "m-rule"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        save_to(&set, &path);
        let text = std::fs::read_to_string(&path).unwrap();
        let ids: Vec<String> = serde_json::from_str(&text).unwrap();
        assert_eq!(ids, vec!["a-rule", "m-rule", "z-rule"]);
    }
}
```

- [ ] **Step 2: Add `mod disabled;` to `src/main.rs`**

Add at the top of `src/main.rs` alongside the other `mod` declarations:

```rust
mod disabled;
```

- [ ] **Step 3: Add `tempfile` dev-dependency to `Cargo.toml`**

```toml
[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 4: Run tests to verify they fail**

```bash
cargo test disabled
```

Expected: compilation errors (`todo!()` panics) or test failures — confirms the tests run.

- [ ] **Step 5: Implement `load`, `save`, `add`, `remove`**

Replace the `todo!()` stubs in `src/disabled.rs`:

```rust
pub fn load() -> HashSet<String> {
    let path = match config_path() {
        Ok(p) => p,
        Err(_) => return HashSet::new(),
    };
    if !path.exists() {
        return HashSet::new();
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return HashSet::new(),
    };
    let ids: Vec<String> = serde_json::from_str(&text).unwrap_or_default();
    ids.into_iter().collect()
}

pub fn save(set: &HashSet<String>) -> Result<PathBuf> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut sorted: Vec<&String> = set.iter().collect();
    sorted.sort();
    std::fs::write(&path, serde_json::to_string_pretty(&sorted)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

pub fn add(id: &str) -> Result<bool> {
    let mut set = load();
    let inserted = set.insert(id.to_string());
    if inserted {
        save(&set)?;
    }
    Ok(inserted)
}

pub fn remove(id: &str) -> Result<bool> {
    let mut set = load();
    let removed = set.remove(id);
    if removed {
        save(&set)?;
    }
    Ok(removed)
}
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cargo test disabled
```

Expected: all 4 tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/disabled.rs src/main.rs Cargo.toml Cargo.lock
git commit -m "feat: add disabled-rules storage module"
```

---

### Task 2: Blacklist integration — `check_filtered`

**Files:**
- Modify: `src/blacklist.rs`

- [ ] **Step 1: Write failing tests for `check_filtered`**

Add the following tests to the `tests` module at the bottom of `src/blacklist.rs` (after the existing tests):

```rust
// ---- disabled-rule filtering ----

#[test]
fn check_filtered_skips_disabled_rule() {
    use std::collections::HashSet;
    let mut disabled = HashSet::new();
    disabled.insert("k8s-delete-namespace".to_string());
    // Would normally be blocked by k8s-delete-namespace
    assert!(check_filtered("kubectl delete namespace prod", &disabled).is_none());
}

#[test]
fn check_filtered_still_blocks_non_disabled_rules() {
    use std::collections::HashSet;
    let mut disabled = HashSet::new();
    disabled.insert("k8s-delete-namespace".to_string());
    // k8s-delete-all is not disabled — must still block
    assert!(check_filtered("kubectl delete pods --all", &disabled).is_some());
}

#[test]
fn check_filtered_empty_disabled_set_behaves_like_check() {
    use std::collections::HashSet;
    let disabled = HashSet::new();
    assert_eq!(
        check_filtered("kubectl delete namespace prod", &disabled).map(|h| h.id),
        check("kubectl delete namespace prod").map(|h| h.id),
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test check_filtered
```

Expected: compile error — `check_filtered` does not exist yet.

- [ ] **Step 3: Add `check_filtered` and update `check`**

In `src/blacklist.rs`, replace the existing `check` function with:

```rust
pub fn check_filtered(command: &str, disabled: &std::collections::HashSet<String>) -> Option<Hit> {
    for rule in RULES.iter() {
        if disabled.contains(rule.id) {
            continue;
        }
        if rule.regex.is_match(command) {
            return Some(Hit {
                id: rule.id,
                reason: rule.reason,
            });
        }
    }
    None
}

pub fn check(command: &str) -> Option<Hit> {
    check_filtered(command, &crate::disabled::DISABLED)
}
```

- [ ] **Step 4: Run all tests to verify nothing broke**

```bash
cargo test
```

Expected: all existing tests pass plus the 3 new `check_filtered` tests.

- [ ] **Step 5: Commit**

```bash
git add src/blacklist.rs
git commit -m "feat: add check_filtered to blacklist for per-invocation disabled set"
```

---

### Task 3: `main.rs` — `rule` subcommand

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Add `is_valid_rule_id` helper and `run_rule` function**

Add these two functions to `src/main.rs`:

```rust
fn is_valid_rule_id(id: &str) -> bool {
    blacklist::rules().iter().any(|r| r.id == id)
}

fn run_rule(args: &[String]) -> ExitCode {
    let usage = "usage:\n  \
        rsh rule disable <id>\n  \
        rsh rule enable <id>\n  \
        rsh rule list";

    match args.first().map(String::as_str) {
        Some("disable") => match args.get(1) {
            Some(id) => {
                if !is_valid_rule_id(id) {
                    eprintln!("error: unknown rule id '{id}'");
                    eprintln!("hint: run `rsh rule list` to see all valid rule IDs");
                    return ExitCode::FAILURE;
                }
                match disabled::add(id) {
                    Ok(true) => {
                        eprintln!("rule: disabled '{id}'");
                        ExitCode::SUCCESS
                    }
                    Ok(false) => {
                        eprintln!("rule: '{id}' was already disabled");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("rule failed: {e:#}");
                        ExitCode::FAILURE
                    }
                }
            }
            None => {
                eprintln!("usage: rsh rule disable <id>");
                ExitCode::FAILURE
            }
        },
        Some("enable") => match args.get(1) {
            Some(id) => {
                if !is_valid_rule_id(id) {
                    eprintln!("error: unknown rule id '{id}'");
                    eprintln!("hint: run `rsh rule list` to see all valid rule IDs");
                    return ExitCode::FAILURE;
                }
                match disabled::remove(id) {
                    Ok(true) => {
                        eprintln!("rule: enabled '{id}'");
                        ExitCode::SUCCESS
                    }
                    Ok(false) => {
                        eprintln!("rule: '{id}' was already enabled");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("rule failed: {e:#}");
                        ExitCode::FAILURE
                    }
                }
            }
            None => {
                eprintln!("usage: rsh rule enable <id>");
                ExitCode::FAILURE
            }
        },
        Some("list") => {
            list_rules();
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{usage}");
            ExitCode::FAILURE
        }
    }
}
```

- [ ] **Step 2: Wire `rule` into the `main` dispatch**

In the `match args.get(1).map(String::as_str)` block inside `fn main()`, add the new arm directly before the `Some("forbid")` arm:

```rust
Some("rule") => run_rule(&args[2..]),
```

- [ ] **Step 3: Update `print_help`**

In `print_help()`, add the new rule lines at the end of the usage string, before the `rsh help` line:

```rust
fn print_help() {
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
           rsh rule disable <id>     Disable a blacklist rule by ID.\n\
           rsh rule enable <id>      Re-enable a disabled blacklist rule.\n\
           rsh rule list             Show all rules with [DISABLED] marker where applicable.\n\
           rsh forbid cluster <name>              Add a forbidden cluster (context).\n\
           rsh forbid namespace <name>            Add a forbidden namespace.\n\
           rsh forbid database <hostname>         Add a forbidden database hostname.\n\
           rsh forbid remove cluster|namespace|database <name>\n\
                                              Remove an entry from the forbid list.\n\
           rsh forbid list               Show the current forbid lists.\n\
           rsh help                  Show this message\n\
           rsh -v | --version        Show version"
    );
}
```

- [ ] **Step 4: Build and smoke-test**

```bash
cargo build 2>&1
```

Expected: compiles without errors.

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | ./target/debug/rsh
echo $?
```

Expected: exit code 0.

```bash
./target/debug/rsh rule disable k8s-drain 2>&1
./target/debug/rsh rule list 2>&1 | grep k8s-drain
```

Expected: first command prints `rule: disabled 'k8s-drain'`; second shows `• k8s-drain` in output (marker added in Task 4).

```bash
./target/debug/rsh rule disable nonexistent 2>&1
echo $?
```

Expected: prints `error: unknown rule id 'nonexistent'` and `hint: run \`rsh rule list\`...`; exit code 1.

```bash
./target/debug/rsh rule enable k8s-drain 2>&1
```

Expected: prints `rule: enabled 'k8s-drain'`.

- [ ] **Step 5: Run all tests**

```bash
cargo test
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs
git commit -m "feat: add rsh rule disable/enable subcommand"
```

---

### Task 4: `rsh list` — `[DISABLED]` marker

**Files:**
- Modify: `src/main.rs` (function `list_rules`)

- [ ] **Step 1: Update `list_rules` to load the disabled set and show the marker**

In `list_rules()` in `src/main.rs`, add `let disabled_set = disabled::load();` after the existing `let aliases = aliases::load();` line, then update the rule-ID print line:

Find this block:
```rust
for r in items {
    println!("    • {}", r.id);
    println!("        reason  : {}", r.reason);
    if let Some(b) = r.bin {
        println!("        binary  : {b}");
    }
    println!("        pattern : {}", r.effective_pattern);
    println!();
}
```

Replace with:
```rust
for r in items {
    if disabled_set.contains(r.id) {
        println!("    • {}  [DISABLED]", r.id);
    } else {
        println!("    • {}", r.id);
    }
    println!("        reason  : {}", r.reason);
    if let Some(b) = r.bin {
        println!("        binary  : {b}");
    }
    println!("        pattern : {}", r.effective_pattern);
    println!();
}
```

- [ ] **Step 2: Verify the marker appears**

```bash
cargo build 2>&1 && ./target/debug/rsh rule disable k8s-drain 2>&1
./target/debug/rsh list 2>&1 | grep -A4 "k8s-drain"
```

Expected output contains:
```
    • k8s-drain  [DISABLED]
        reason  : Evicts all pods from a node — potential cluster-wide service disruption
```

- [ ] **Step 3: Re-enable and verify marker disappears**

```bash
./target/debug/rsh rule enable k8s-drain 2>&1
./target/debug/rsh list 2>&1 | grep "k8s-drain"
```

Expected: `• k8s-drain` with no `[DISABLED]` suffix.

- [ ] **Step 4: Verify the hook respects the disabled state**

```bash
./target/debug/rsh rule disable k8s-drain 2>&1
echo '{"tool_name":"Bash","tool_input":{"command":"kubectl drain worker-1 --ignore-daemonsets"}}' | ./target/debug/rsh
echo "exit: $?"
```

Expected: exit code 0 (rule is disabled, command passes through).

```bash
./target/debug/rsh rule enable k8s-drain 2>&1
echo '{"tool_name":"Bash","tool_input":{"command":"kubectl drain worker-1 --ignore-daemonsets"}}' | ./target/debug/rsh
echo "exit: $?"
```

Expected: exit code 2 (rule is active again, command is blocked).

- [ ] **Step 5: Run all tests**

```bash
cargo test
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs
git commit -m "feat: show [DISABLED] marker in rsh list output"
```

---

### Task 5: Documentation

**Files:**
- Create: `docs/adr/008-rule-disable-enable.md`
- Modify: `docs/behavior/kubernetes-rules.md` (add note about disabling)
- Modify: `docs/index.md` (add ADR entry)

- [ ] **Step 1: Write ADR 008**

Create `docs/adr/008-rule-disable-enable.md`:

```markdown
# ADR 008 — Rule Disable/Enable

**Date:** 2026-05-17  
**Status:** Accepted

## Context

Some users need to run commands that `rsh` blocks by default in specific, controlled contexts — e.g. temporarily running `kubectl drain` during a planned maintenance window, or disabling SQL DDL checks on a development database. Requiring a code change or a full uninstall/reinstall to remove a single rule is too coarse-grained.

## Decision

Individual blacklist rules can be toggled off and on via `rsh rule disable <id>` and `rsh rule enable <id>`. Disabled rule IDs are stored in `~/.config/rsh/disabled-rules.json` as a sorted JSON array.

At hook time, `blacklist::check_filtered(command, &DISABLED)` skips any rule whose ID is in the disabled set. `DISABLED` is a `LazyLock<HashSet<String>>` — loaded once per process, zero overhead for subsequent calls.

To keep `check_filtered` unit-testable without mutating global state, the public `check(command)` function is a thin wrapper that passes `&DISABLED`; tests call `check_filtered` directly with a constructed `HashSet`.

## Alternatives Considered

- **Per-project disable list (in `.claude/settings.json`):** Rejected — mixes rsh config into a file owned by Claude Code, and scope per-project would require a second lookup path.
- **Comment out rules in source and recompile:** Not viable for end-users who install via the binary installer.
- **`--skip <id>` flag on each hook invocation:** Not possible — Claude Code invokes the hook with no user-controlled arguments.

## Consequences

- Disabled rules persist across sessions and rsh upgrades (they are stored by ID slug, which is stable).
- A disabled rule is invisible to the running hook for the duration of that process. Re-enabling requires a new hook invocation (next tool call in Claude Code).
- The `[DISABLED]` marker in `rsh list` gives operators a quick overview of the current security posture.
```

- [ ] **Step 2: Add a "Disabling rules" note to the behavior docs**

At the end of `docs/behavior/kubernetes-rules.md`, add:

```markdown
## Disabling individual rules

Any rule can be temporarily disabled without removing it from the codebase:

```sh
rsh rule disable k8s-drain    # allow kubectl drain until re-enabled
rsh rule enable k8s-drain     # restore the rule
rsh rule list                 # show all rules with [DISABLED] marker
```

Disabled rules are stored in `~/.config/rsh/disabled-rules.json` and persist across sessions.
```

- [ ] **Step 3: Add ADR 008 to `docs/index.md`**

In the architecture decision records table in `docs/index.md`, add:

```markdown
| [adr/008-rule-disable-enable.md](adr/008-rule-disable-enable.md) | Per-rule disable/enable toggle — storage, CLI, and testability design |
```

- [ ] **Step 4: Commit docs**

```bash
git add docs/adr/008-rule-disable-enable.md docs/behavior/kubernetes-rules.md docs/index.md
git commit -m "docs: add ADR 008 and behavior notes for rule disable/enable"
```

---

### Task 6: Final verification and push

- [ ] **Step 1: Full test suite**

```bash
cargo test
```

Expected: all tests pass, zero warnings about unused imports.

- [ ] **Step 2: Install and end-to-end test**

```bash
cargo install --path . --force
rsh rule list 2>&1 | head -20
rsh rule disable helm-uninstall 2>&1
rsh check "helm uninstall postgres" 2>&1
echo "exit: $?"
rsh rule enable helm-uninstall 2>&1
rsh check "helm uninstall postgres" 2>&1
echo "exit: $?"
```

Expected:
- `rsh rule disable helm-uninstall` → `rule: disabled 'helm-uninstall'`
- First `rsh check` → no output, exit 0
- `rsh rule enable helm-uninstall` → `rule: enabled 'helm-uninstall'`
- Second `rsh check` → `rsh blocked command (rule: helm-uninstall): ...`, exit 2

- [ ] **Step 3: Delete spec and plan files**

Per project convention (CLAUDE.md): distilled content now lives in the ADR and behavior docs.

```bash
git rm docs/superpowers/specs/2026-05-17-rule-disable-enable-design.md
git rm docs/superpowers/plans/2026-05-17-rule-disable-enable.md
git commit -m "chore: remove spec and plan after implementation"
```

- [ ] **Step 4: Push**

```bash
git push origin main
```
