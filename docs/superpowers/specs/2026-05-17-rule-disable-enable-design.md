# Design: Rule Disable/Enable

**Date:** 2026-05-17  
**Status:** Approved

## Overview

Allow individual blacklist rules to be toggled off and on via the CLI. A disabled rule is silently skipped during every hook invocation. State persists across sessions in a dedicated config file.

## Storage

New file: `~/.config/rsh/disabled-rules.json`  
- Unix: `$XDG_CONFIG_HOME/rsh/disabled-rules.json` (default: `~/.config/rsh/disabled-rules.json`)  
- Windows: `%XDG_CONFIG_HOME%\rsh\disabled-rules.json` (default: `%APPDATA%\rsh\disabled-rules.json`)

Format: a JSON array of rule ID strings.

```json
["k8s-drain", "sql-create-ddl"]
```

A missing file or an empty array means all rules are active. Unreadable files are treated as empty (fail-open, consistent with the rest of the codebase).

## New Module: `src/disabled.rs`

Mirrors the structure of `src/aliases.rs`:

- `config_path() -> Result<PathBuf>` — XDG-aware, Windows-compatible path resolution.
- `load() -> HashSet<String>` — reads the JSON file; returns an empty set on any error.
- `save(set: &HashSet<String>) -> Result<PathBuf>` — serializes sorted (for deterministic diffs).
- `add(id: &str) -> Result<bool>` — inserts the ID, returns `true` if newly added.
- `remove(id: &str) -> Result<bool>` — removes the ID, returns `true` if it was present.
- `DISABLED: LazyLock<HashSet<String>>` — process-wide cached set, loaded once. Shared by `blacklist::check()` so the file is read at most once per hook invocation.

## Blacklist Integration

`blacklist::check()` uses `disabled::DISABLED` internally. When iterating `RULES`, any rule whose `id` is present in `DISABLED` is skipped. No change to the public function signature; callers (`main.rs`, tests) are unaffected.

The `DISABLED` set is also checked in the `check_content_blocked()` path (Write/Edit tool and script scanning), which calls `blacklist::check()` — no additional changes needed there.

## CLI Surface

New top-level subcommand `rule` in `main.rs`, dispatching three sub-subcommands:

```
rsh rule disable <id>   disable a rule by ID
rsh rule enable <id>    re-enable a disabled rule
rsh rule list           print all rules with [DISABLED] marker where applicable
```

**Validation:** Both `disable` and `enable` validate that `<id>` is a known rule ID (checked against `blacklist::rules()`). An unknown ID prints an error and exits with `ExitCode::FAILURE`:

```
error: unknown rule id 'xyz'
hint: run `rsh rule list` to see all valid rule IDs
```

`rsh rule disable <id>` on an already-disabled rule is idempotent (success, informational message).  
`rsh rule enable <id>` on an already-enabled rule is idempotent (success, informational message).

`rsh rule list` outputs the same blacklist section as `rsh list` (same formatting helper), but only the rules section — no forbid or aliases section.

## `rsh list` Changes

The existing `list_rules()` function gains awareness of the disabled set. Each rule entry gets a `[DISABLED]` suffix on its ID line when the rule is disabled:

```
  ▌ Kubernetes — Service Disruption (1)
  ────────────────────────────────────────────────────────────
    • k8s-drain  [DISABLED]
        reason  : Evicts all pods from a node — potential cluster-wide service disruption
        binary  : kubectl
        pattern : \b(?:kubectl)\b\s[^|;&\n]*?\bdrain\s+\S+
```

Active rules are displayed identically to today.

## Error Handling

- Unknown rule ID on `disable`/`enable` → print error + hint, exit 1.
- Unwritable config directory → propagate `anyhow` error, print and exit 1.
- Unreadable `disabled-rules.json` at hook time → treat as empty set (fail-open).

## Tests

Unit tests in `src/disabled.rs`:

- `add` and `remove` round-trip against a temp path (using env-var override or by calling the functions directly with a mocked path).
- `load` returns an empty set when the file is absent.
- `load` returns an empty set when the file contains invalid JSON.

Integration tests in `src/blacklist.rs`:

- A rule that is in `DISABLED` is not returned by `check()`. Since `DISABLED` is a `LazyLock`, tests will need to call `blacklist::check_with_disabled(cmd, &disabled_set)` — a new test-only helper that accepts an explicit set, avoiding global state mutation.

> **Implementation note:** To keep `check()` testable without global state, `check()` calls an inner `check_filtered(cmd, disabled)` that accepts a `&HashSet<String>`. `check()` itself passes `&disabled::DISABLED`. Tests call `check_filtered()` directly with a constructed set.
