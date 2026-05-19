# ADR 013 — Secret File Protection

**Status:** Accepted  
**Date:** 2026-05-19

## Context

AI coding assistants can inadvertently read, write, or reference files that contain
credentials, private keys, or other secrets. Because `rsh` already intercepts every
`PreToolUse` event, it is well-positioned to block access at the tool boundary before
the secret ever reaches the model's context window.

The existing blacklist covers dangerous shell *operations*; this feature covers
dangerous *file paths* regardless of which command or tool is used to access them.

## Decision

Introduce a dedicated `src/secrets.rs` module containing:

- A catalogue of 20 `SecretRule` entries grouped into five categories (Environment,
  Cryptographic Keys, SSH, Cloud, System), each with an `id`, glob `patterns`, and
  `reason`.
- A custom four-form glob matcher (`**/name`, `**/*.ext`, `**/<stem>.*`, `**/<dir>/<name>`)
  that avoids adding any new crate dependency. Matching is case-insensitive (ASCII
  lowercase fold) so `.ENV` is caught alongside `.env` on case-sensitive filesystems.
- `check_path(path) -> Option<Hit>` — the single public entry point used by all callers.

Integration points:

| Hook surface      | Where blocked                            |
|-------------------|------------------------------------------|
| `Read` tool       | `run_hook_from_str`, before any content check |
| `Write` tool      | `run_hook_from_str`, after protected-path check, before content check |
| `Edit` tool       | same as Write                            |
| `Bash` tool       | `SecretFileChecker` in the parallel pipeline |

`SecretFileChecker` tokenises the command and inspects every non-flag token plus the
value side of `--flag=VALUE` tokens and the value side of `KEY=VALUE` env-assignment
prefix tokens (position 0). Known limitations are documented in a comment.

Every `secret-*` rule ID is individually toggleable via the existing
`rsh rule disable/enable` mechanism. `rsh list` renders a "SECRET FILE RULES"
section grouped by category.

## Alternatives considered

**Regex matching in the blacklist module** — rejected because glob patterns are the
idiomatic way to express path rules and would require shoehorning path semantics into
a command-content regex. Keeping secrets separate also makes the catalogue easier to
maintain and audit.

**Using the `globset` / `glob` crate** — rejected to avoid adding a dependency for a
matcher whose four required forms are straightforward to implement inline.

## Consequences

- 20 new rule IDs (`secret-dotenv` … `secret-shadow`), each individually disableable.
- `Read` tool is now actively checked; previously `rsh` only inspected tool *content*.
- Known bypass vectors documented as non-goals:
  - Shell glob expansion before `rsh` sees the command (e.g. `cat /project/.env*`)
  - Attached short flags without `=` (e.g. `curl -K/etc/ssl/server.pem`)
  - Variable indirection (`F=/project/.env; cat $F`)
- `IsolatedEnv` test helper acquires a static `Mutex` so tests are safe under default
  parallel `cargo test` execution.
