# ADR 009 — rsh Self-Protection

**Date:** 2026-05-17
**Status:** Accepted

## Context

The `rsh rule disable` command (introduced in a prior feature) allows any caller
to deactivate individual blacklist rules for a session. Since Claude Code is the
primary hook caller, it could — intentionally or via prompt injection — disable
a rule and then execute the previously blocked command. The same risk applies to
`rsh forbid remove` (weakens the forbid list) and direct file access to
`~/.config/rsh/` (overwrites config files via Bash, Write, or Edit tools).

## Decision

Two complementary mechanisms protect the rsh config:

**1. Blacklist rules (Bash protection)**
Three rules in a new "rsh Self-Protection" category block every Bash-level
attack:
- `rsh-protect-disable`: blocks `rsh rule disable <id>`
- `rsh-protect-forbid-remove`: blocks `rsh forbid remove <type> <name>`
- `rsh-protect-config-access`: blocks any Bash command targeting `.config/rsh`

The first rule is self-referential: any attempt to run
`rsh rule disable rsh-protect-disable` itself matches the rule and is blocked.
The protection cannot be lifted through the Bash tool.

**2. Hardcoded path check (Write/Edit protection)**
`run_hook()` checks the `file_path` parameter of `Write` and `Edit` tool calls
against a hardcoded `is_protected_path()` function before scanning content.
Any path resolving to `.config/rsh` is rejected with exit code 2. This check
does not consult the disabled-rules config and is therefore immutable.

## Alternatives Considered

- **Rules only, no path check:** Write/Edit tool calls would remain unprotected
  since they are matched by content, not by path.
- **Hardcoded protection only (no rules):** Protection would be invisible in
  `rsh list` and harder to discover and reason about.
- **Block `rsh rule enable` too:** Rejected — re-enabling a rule is a
  security-increasing operation and should remain available.

## Consequences

- Claude cannot disable blacklist rules or remove forbid entries within a hook
  session.
- Direct writes to `~/.config/rsh/` via any Claude Code tool call are blocked.
- Users can still manage rsh config manually outside a Claude Code session; the
  hook only runs during tool calls.
- The new rules appear in `rsh list` under "rsh Self-Protection".
