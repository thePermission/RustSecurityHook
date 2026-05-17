---
title: RshChecker
tags:
  - rsh/checker
  - rsh/security
aliases:
  - rsh checker
  - RshChecker
---

# RshChecker

`RshChecker` protects rsh's own configuration from modification during Claude Code sessions. It activates when command content contains `rsh` or any registered alias.

The checker runs only the **regex blacklist pipeline** — no forbid checks.

## Blacklist rules

| ID | Blocked command | Reason |
|---|---|---|
| `rsh-protect-disable` | `rsh rule disable <id>` | Prevents rsh from being neutered via the Bash tool |
| `rsh-protect-forbid-remove` | `rsh forbid remove <type> <name>` | Prevents removing a forbid entry via the Bash tool |
| `rsh-protect-config-access` | Any Bash command targeting `.config/rsh` | Prevents direct config file manipulation |

## Self-protection property

`rsh-protect-disable` cannot be disabled by running `rsh rule disable rsh-protect-disable` — the command matches the rule itself and is blocked before taking effect.

## Hardcoded path check (Write and Edit tools)

The Write and Edit tool interception includes a hardcoded check for `.config/rsh/` paths in the hook entry point. This check operates independently of the blacklist and cannot be bypassed by disabling any rule. It applies to both the Bash tool and the Write/Edit tools.

## What remains allowed

- `rsh rule enable <id>` — re-enabling is security-increasing
- `rsh rule list`, `rsh list` — read-only operations
- `rsh forbid cluster/namespace <name>` — adding restrictions
- Manual edits to `~/.config/rsh/` outside Claude Code sessions (hook only runs during tool calls)

## Source location

- Blacklist rules: `src/blacklist.rs` lines 334–354 (rsh Self-Protection category)
- RshChecker implementation: `src/checker.rs` lines 210–223
