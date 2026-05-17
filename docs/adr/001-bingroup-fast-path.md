# ADR 001: BinGroup Fast-Path for Blacklist and Forbid

## Context

`rsh` is invoked as a Claude Code PreToolUse hook on every Bash tool call. The hot path is `run_check`, which calls `blacklist::check_filtered` (iterates all regex rules) and `forbid::check` (reads `forbidden.json` from disk). For tool calls unrelated to any protected binary (e.g. `ls`, `cargo build`), both operations were executed unconditionally — wasted work that grows with the rule count.

## Decision

### Blacklist: BinGroup grouping

Add a `BinGroup` struct and a `BIN_GROUPS: LazyLock<Vec<BinGroup>>` that groups `RULES` by their `bin` field. Each group holds `tokens: Vec<String>` (the binary name plus all configured aliases) and `rule_indices: Vec<usize>`.

`check_filtered` iterates groups instead of rules. For each group with non-empty tokens, it first checks whether any token appears as a substring of the command (`str::contains`). If none matches, the entire group is skipped — no regex evaluation. Groups with empty tokens (`bin = None`) are always evaluated.

### Forbid: FORBID_TOKENS pre-check

Add a `FORBID_TOKENS: LazyLock<Vec<String>>` that collects the canonical name and all configured aliases for every entry in `TOOLS` (kubectl, helm) and `SQL_CLIENTS`. In `check()`, insert a substring pre-check before `load()`. Commands that contain no known tool token skip the file read entirely.

## Alternatives considered

- **Per-rule fast token** (add `tokens` field to each `Rule`): simpler but checks every rule's tokens individually. For 15 kubectl rules, one token check per rule instead of one per group.
- **HashMap token→indices**: overkill at current rule counts, more complex, no measurable benefit over group iteration.

## Consequences

- All commands containing no known binary name skip all regex evaluation (blacklist) and disk I/O (forbid). Common cases: file ops, `cargo`, `git`, `echo`, etc.
- No false negatives possible: the pre-filter is purely additive — if a token matches, the full regex still runs. `bin = None` rules are never skipped.
- Non-deterministic cross-group hit ordering (from HashMap): if a command matches rules from two different bin-groups simultaneously, which rule's id/reason is surfaced is implementation-defined. The command is still blocked. Cross-bin matches are extremely unlikely by design.
- Rule count scales without affecting latency for unrelated commands.
