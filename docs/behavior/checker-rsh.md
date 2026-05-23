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
| `rsh-protect-allow` | `rsh allow <type> <name>` | Prevents removing a forbid entry or push protection via the Bash tool |
| `rsh-protect-config-access` | Any Bash command targeting `.config/rsh` | Prevents direct config file manipulation |
| `rsh-self-disable` | `rsh off` / `rsh on` | Prevents agents from disabling or re-enabling the whole hook |
| `rsh-guard-flag-file` | Any Bash command targeting `.rsh-disabled` or `rsh/disabled` | Protects the local and global disable flag files |

## Self-protection property

`rsh-protect-disable` cannot be disabled by running `rsh rule disable rsh-protect-disable` — the command matches the rule itself and is blocked before taking effect.

## Hardcoded path check (Write and Edit tools)

The Write and Edit tool interception includes a hardcoded protected-path check in the hook entry point. It covers `.config/rsh/`, the platform-specific rsh config files, `.rsh-disabled`, the global `rsh/disabled` flag, and symlinks that resolve to those paths. This check operates independently of the blacklist and cannot be bypassed by disabling any rule.

Bash access to those paths is handled by the self-protection blacklist rules above.

## What remains allowed

- `rsh rule enable <id>` — re-enabling is security-increasing
- `rsh rule list`, `rsh list` — read-only operations
- `rsh forbid cluster/namespace <name>` — adding restrictions
- Manual edits to `~/.config/rsh/` outside Claude Code or Codex tool calls (the hook only runs during protected tool calls)
