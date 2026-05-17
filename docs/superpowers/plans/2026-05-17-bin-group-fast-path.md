# BinGroup Fast-Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Skip regex evaluation and disk I/O for commands that don't contain a relevant binary name, reducing hook latency for unrelated tool calls.

**Architecture:** `blacklist.rs` gains a `BinGroup` struct and a `BIN_GROUPS` LazyLock that groups rule indices by binary name. `check_filtered` does a fast `str::contains` check per group before running any regex. `forbid.rs` gains a `FORBID_TOKENS` LazyLock and a pre-check in `check()` that skips `load()` (disk I/O) when no known tool token is present.

**Tech Stack:** Rust stable, `std::collections::HashMap`, existing `aliases::aliases_for`, existing `LazyLock` pattern already used throughout the codebase.

---

### Task 1: Add `BinGroup` struct and `BIN_GROUPS` LazyLock to `blacklist.rs`

**Files:**
- Modify: `src/blacklist.rs` (after the `RULES` LazyLock, around line 383)

- [ ] **Step 1: Write the structural regression test**

Add inside `mod tests` at the bottom of `src/blacklist.rs`, before the closing `}`:

```rust
#[test]
fn bin_groups_cover_all_rules() {
    let grouped: usize = super::BIN_GROUPS.iter().map(|g| g.rule_indices.len()).sum();
    assert_eq!(
        grouped,
        super::RULES.len(),
        "every rule must appear in exactly one BinGroup"
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test bin_groups_cover_all_rules 2>&1 | tail -10
```

Expected: compile error — `BIN_GROUPS` does not exist yet.

- [ ] **Step 3: Add the `BinGroup` struct and `BIN_GROUPS` static**

Insert immediately after the closing `});` of the `RULES` LazyLock (around line 383), before `pub fn rules()`:

```rust
struct BinGroup {
    tokens: Vec<String>,
    rule_indices: Vec<usize>,
}

static BIN_GROUPS: LazyLock<Vec<BinGroup>> = LazyLock::new(|| {
    let mut map: std::collections::HashMap<Option<&'static str>, Vec<usize>> =
        std::collections::HashMap::new();
    for (i, rule) in RULES.iter().enumerate() {
        map.entry(rule.bin).or_default().push(i);
    }
    map.into_iter()
        .map(|(bin, rule_indices)| BinGroup {
            tokens: match bin {
                Some(b) => aliases::aliases_for(&ALIASES, b),
                None => vec![],
            },
            rule_indices,
        })
        .collect()
});
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test bin_groups_cover_all_rules 2>&1 | tail -5
```

Expected: `test blacklist::tests::bin_groups_cover_all_rules ... ok`

- [ ] **Step 5: Commit**

```bash
git add src/blacklist.rs
git commit -m "feat: add BinGroup struct and BIN_GROUPS LazyLock to blacklist"
```

---

### Task 2: Rewrite `check_filtered` to use `BIN_GROUPS`

**Files:**
- Modify: `src/blacklist.rs` — `check_filtered` function (around line 389)

- [ ] **Step 1: Replace `check_filtered` body**

Find the current `check_filtered` function (iterates `RULES.iter()`) and replace its body:

```rust
pub fn check_filtered(command: &str, disabled: &std::collections::HashSet<String>) -> Option<Hit> {
    for group in BIN_GROUPS.iter() {
        if !group.tokens.is_empty()
            && !group.tokens.iter().any(|t| command.contains(t.as_str()))
        {
            continue;
        }
        for &idx in &group.rule_indices {
            let rule = &RULES[idx];
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
    }
    None
}
```

- [ ] **Step 2: Run the full blacklist test suite**

```bash
cargo test 2>&1 | tail -20
```

Expected: all tests pass, zero failures.

- [ ] **Step 3: Commit**

```bash
git add src/blacklist.rs
git commit -m "perf: use BinGroup fast-path in check_filtered to skip irrelevant rules"
```

---

### Task 3: Add `FORBID_TOKENS` early-exit to `forbid.rs`

**Files:**
- Modify: `src/forbid.rs` — add `FORBID_TOKENS` static and update `check()`

- [ ] **Step 1: Add the `FORBID_TOKENS` static**

Add after the existing `use` imports (after `use crate::aliases::{self, AliasMap};`, around line 23) in `src/forbid.rs`:

```rust
static FORBID_TOKENS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut tokens: Vec<String> = Vec::new();
    for tool in TOOLS {
        tokens.extend(aliases::aliases_for(&aliases::ALIASES, tool.bin_key));
    }
    for &client in SQL_CLIENTS {
        tokens.extend(aliases::aliases_for(&aliases::ALIASES, client));
    }
    tokens.sort();
    tokens.dedup();
    tokens
});
```

Note: `TOOLS` and `SQL_CLIENTS` are defined later in the file (around line 64 and 316). Rust resolves statics lazily so the forward reference is fine — `LazyLock::new` runs at first access, by which time `TOOLS` and `SQL_CLIENTS` are initialized.

- [ ] **Step 2: Add early-exit to `check()`**

Find the `pub fn check(command: &str) -> Option<Hit>` function (around line 234) and add the fast-path guard as the very first line:

```rust
pub fn check(command: &str) -> Option<Hit> {
    if !FORBID_TOKENS.iter().any(|t| command.contains(t.as_str())) {
        return None;
    }
    let cfg = load();
    if cfg.is_empty() {
        return None;
    }
    check_with(command, &aliases::ALIASES, &cfg, &KubectlEnv)
        .or_else(|| check_db(command, &cfg))
}
```

- [ ] **Step 3: Run the full test suite**

```bash
cargo test 2>&1 | tail -20
```

Expected: all tests pass, zero failures.

- [ ] **Step 4: Commit**

```bash
git add src/forbid.rs
git commit -m "perf: skip forbid load() when no known tool token is present in command"
```

---

### Task 4: Verify with benchmarks

**Files:**
- No changes — read-only verification step.

- [ ] **Step 1: Save a baseline before the optimization (if not already done)**

If you want a before/after comparison, check out the commit before Task 1 in a temp branch, save a baseline, then return:

```bash
git stash  # only if you have uncommitted changes
make bench-save NAME=before-bingroup
git stash pop
```

If the baseline was already saved in a previous session, skip this step.

- [ ] **Step 2: Run benchmarks on the current (optimized) code**

```bash
make bench 2>&1 | grep -E "time:|thrpt:|Benchmarking"
```

Expected: no panics, benchmark completes. The `irrelevant_command` benchmark (if present in `benches/hook.rs`) should show improvement.

- [ ] **Step 3: Compare if baseline exists**

```bash
make bench-compare NAME=before-bingroup 2>&1 | grep -E "change|time:|improved|regressed"
```

Expected: improvement on irrelevant-command paths, no regression on blocking paths.
