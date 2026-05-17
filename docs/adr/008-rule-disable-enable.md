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
