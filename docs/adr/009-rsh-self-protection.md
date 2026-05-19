# ADR 009 — rsh Self-Protection

**Date:** 2026-05-17
**Status:** Accepted

## Context

The `rsh rule disable` command (introduced in a prior feature) allows any caller
to deactivate individual blacklist rules for a session. Since Claude Code is the
primary hook caller, it could — intentionally or via prompt injection — disable
a rule and then execute the previously blocked command. The same risk applies to
`rsh forbid remove` (weakens the forbid list), `rsh off`/`rsh on` (controls the
whole hook through flag files), and direct file access to `~/.config/rsh/` or
`.rsh-disabled` (overwrites config files or disable flags via Bash, Write, or
Edit tools).

## Decision

Two complementary mechanisms protect the rsh config:

**1. Blacklist rules (Bash protection)**
Five rules in the "rsh Self-Protection" category block Bash-level attacks:
- `rsh-protect-disable`: blocks `rsh rule disable <id>`
- `rsh-protect-forbid-remove`: blocks `rsh forbid remove <type> <name>`
- `rsh-protect-config-access`: blocks any Bash command targeting `.config/rsh`
- `rsh-self-disable`: blocks `rsh off` and `rsh on`
- `rsh-guard-flag-file`: blocks Bash access to `.rsh-disabled` and `rsh/disabled`

The first rule is self-referential: any attempt to run
`rsh rule disable rsh-protect-disable` itself matches the rule and is blocked.
The protection cannot be lifted through the Bash tool.

**2. Hardcoded path check (Write/Edit protection)**
`run_hook()` checks the `file_path` parameter of `Write` and `Edit` tool calls
against a hardcoded `is_protected_path()` function before scanning content.
Any path resolving to rsh's config directory or disable flag files is rejected
with exit code 2. This check does not consult the disabled-rules config and is
therefore immutable.

## Alternatives Considered

- **Rules only, no path check:** Write/Edit tool calls would remain unprotected
  since they are matched by content, not by path.
- **Hardcoded protection only (no rules):** Protection would be invisible in
  `rsh list` and harder to discover and reason about.
- **Block `rsh rule enable` too:** Rejected — re-enabling a rule is a
  security-increasing operation and should remain available.

## Consequences

- Claude Code and Codex tool calls cannot disable blacklist rules or remove forbid entries
  through the hook-mediated command path.
- Direct writes to `~/.config/rsh/`, `.rsh-disabled`, or the global `rsh/disabled`
  flag via Claude Code `Write`/`Edit` tool calls are blocked.
- Users can still manage rsh config manually outside Claude Code or Codex tool calls; the
  hook only runs during protected tool calls.
- The new rules appear in `rsh list` under "rsh Self-Protection".
