---
title: Fast-Path Optimization
tags:
  - rsh/system
  - rsh/performance
aliases:
  - fast path
  - BinGroup
---

# Fast-Path Optimization

`rsh` skips rule evaluation and disk I/O for commands that cannot match any protected binary.

## How it works

### Blacklist fast-path

Rules are grouped by their associated binary (`kubectl`, `helm`, etc.). Before evaluating any regex in a group, `check_filtered` checks whether the binary name (or any of its configured aliases) appears anywhere in the command string. If not, the entire group is skipped.

Rules with no associated binary (`bin = None`) are always evaluated regardless.

### Forbid fast-path

`forbid::check` checks whether any known tool token (kubectl, helm, SQL clients, and configured aliases) appears as a substring in the command before reading `forbidden.json` from disk. Commands with no matching token return immediately without file I/O.

The token fast-path is only a pre-filter. The final forbid checks still perform structured command-token identification: kubectl and Helm use registered aliases, while database host extraction currently recognizes the canonical SQL client names.

## What it means for users

- Hook latency for unrelated commands (file ops, `cargo`, `git`) is minimized — no regex or disk access.
- Adding more rules for existing binaries does not increase latency for unrelated commands.
- Behavior is identical to the unoptimized version: the same commands are blocked, with the same reasons.

## Adding rules for new tools

When a new binary-specific rule is added to `RAW_RULES` with `bin = Some("newtool")`, it is automatically placed in a new `BinGroup` for `newtool`. Commands not containing `"newtool"` (or its aliases) skip it at no cost.

The forbid fast-path covers `TOOLS` (kubectl/helm) and `SQL_CLIENTS`. If a new tool category is added to forbid, update `TOOLS` or the equivalent constant so its binary names are included in `FORBID_TOKENS`.
