# rsh Self-Protection

rsh protects its own configuration from modification during Claude Code sessions.

## What is blocked

| Attack vector | Blocked by |
|---------------|-----------|
| `rsh rule disable <id>` (Bash) | rule `rsh-protect-disable` |
| `rsh forbid remove <type> <name>` (Bash) | rule `rsh-protect-forbid-remove` |
| Any Bash command targeting `.config/rsh` | rule `rsh-protect-config-access` |
| Write tool targeting a `.config/rsh` path | hardcoded path check |
| Edit tool targeting a `.config/rsh` path | hardcoded path check |

## What remains allowed

- `rsh rule enable <id>` — re-enabling a rule is security-increasing
- `rsh rule list`, `rsh list` — read-only operations
- `rsh forbid cluster/namespace/database <name>` — adding restrictions
- Manual edits to `~/.config/rsh/` outside Claude Code sessions (the hook only
  runs during tool calls)

## Self-protection property

The `rsh-protect-disable` rule cannot be disabled through the Bash tool: any
attempt to run `rsh rule disable rsh-protect-disable` matches the rule itself
and is blocked before taking effect.

The Write/Edit path check is hardcoded in `run_hook()` and does not consult the
disabled-rules config. It cannot be bypassed by disabling any rule.
