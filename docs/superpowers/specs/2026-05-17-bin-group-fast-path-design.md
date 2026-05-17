# Design: Binary-Group Fast Path for Blacklist and Forbid

## Context

`rsh` is invoked as a Claude Code PreToolUse hook on every Bash tool call. The hot path is `run_check`, which calls `blacklist::check` followed by `forbid::check`. Currently both modules iterate all rules/logic unconditionally, even when the command is clearly unrelated (e.g. `ls`, `cargo build`). With 18+ rules and more tools on the horizon, unnecessary regex evaluations and disk I/O add up.

## Goal

Skip rule evaluation and file I/O for commands that cannot possibly match — with zero change to blocking behavior.

---

## Blacklist: BinGroup

### Data structure

```rust
struct BinGroup {
    tokens: Vec<String>,      // bin name + all aliases (for fast substring check)
    rule_indices: Vec<usize>, // indices into RULES
}

static BIN_GROUPS: LazyLock<Vec<BinGroup>> = LazyLock::new(|| { ... });
```

`BIN_GROUPS` is built once alongside `RULES` in the same `LazyLock` phase. It groups rule indices by the `bin` field of each rule:

- Rules with `bin = Some(b)` → group keyed on `b`, tokens = `[b] + aliases_for(b)`
- Rules with `bin = None` → one group with `tokens = []` (always executed)

### Modified `check_filtered`

```
for each group in BIN_GROUPS:
    if tokens is non-empty AND no token is a substring of command → skip group
    for each rule_index in group:
        if rule is disabled → skip
        if regex matches → return Hit
return None
```

Substring check (`str::contains`) is chosen as the pre-filter because:
- It is strictly a pre-filter — the full regex still runs if any token matches, so no false negatives are possible.
- It is faster than regex for this use case (no backtracking, SIMD-accelerated in the standard library).

### Impact

All kubectl rules (currently 15+) share one token check. A command like `cargo build` skips all of them after a single `contains("kubectl")` → false result.

---

## Forbid: Early Exit Before `load()`

### Problem

`forbid::check` calls `load()` (disk I/O: read and parse `forbidden.json`) before any tool-identity check. For irrelevant commands, this file read is wasted.

`check_with` already calls `identify_tool` (first-word check), and `check_db` checks `SQL_CLIENTS`. Both are fast — but only run *after* `load()`.

### Fix

Add a process-wide `FORBID_TOKENS: LazyLock<Vec<String>>` collecting the canonical name and all aliases for:
- Every entry in `TOOLS` (`kubectl`, `helm`)
- Every entry in `SQL_CLIENTS` (`mysql`, `mariadb`, `psql`, `sqlite3`, `sqlcmd`, `mssql-cli`)

In `check()`, insert a substring pre-check before `load()`:

```rust
pub fn check(command: &str) -> Option<Hit> {
    if !FORBID_TOKENS.iter().any(|t| command.contains(t.as_str())) {
        return None;
    }
    let cfg = load();
    ...
}
```

Commands not containing any known tool token skip the file read entirely.

---

## Correctness invariants

- No rule is ever skipped based on the pre-filter alone — the regex always runs if a token is present.
- `bin = None` rules always run (empty token list → no pre-filter applied).
- Disabled rules still checked per-rule inside the inner loop, not per-group.
- All existing tests remain valid; no test changes needed for correctness (performance assertions are out of scope for unit tests).

---

## Testing

- All existing blacklist unit tests cover correctness unchanged.
- Existing criterion benchmarks (`benches/blacklist.rs`) can be re-run before/after to measure the speedup — `make bench-compare` handles this.
- One new unit test in `blacklist.rs`: verify that a command with a known binary present still triggers matching rules (regression guard for the grouping logic).

---

## Files affected

| File | Change |
|------|--------|
| `src/blacklist.rs` | Add `BinGroup`, `BIN_GROUPS`, rewrite `check_filtered` |
| `src/forbid.rs` | Add `FORBID_TOKENS`, add early-exit in `check()` |
