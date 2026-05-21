# ADR 017: Per-Project Push Blocker

**Status:** Accepted  
**Date:** 2026-05-21

## Context

Developers sometimes check out repositories in a read-only intent — even when they hold write access on GitHub/GitLab — to prevent accidental pushes during AI-assisted sessions. No prior `rsh` mechanism covered this: `rsh off` disables all checks, and blacklist rules are global.

## Decision

Add an opt-in, per-project push block via a `.rsh-nopush` flag file. When present, the hook blocks `git push` (all variants), `gh pr merge`, `glab mr merge`, and `glab mr create` with exit code 2. A new `rsh nopush [--off]` subcommand manages the flag and automatically adds `.rsh-nopush` to `.gitignore`.

Self-protection rules (`rsh-nopush-off`, extended `rsh-guard-flag-file`) prevent agents from removing the protection themselves.

## Alternatives Considered

- **Blacklist rules with filesystem check** — would require rules to access filesystem state, breaking the current clean separation between regex matching and environment inspection.
- **`rsh off --push-only`** — semantically confusing (`off` implies everything) and would entangle push-specific logic in the disabled module.
- **Central config by git remote URL** — more powerful but adds complexity and a dependency on `git remote` at hook time; flag file is simpler and consistent with `.rsh-disabled`.

## Consequences

- Flag file must be gitignored (handled automatically on enable).
- No upward directory walk: hook CWD is always the project root when Claude Code invokes it.
- Works for both Claude Code and Codex hooks (both use the same `rsh` hook binary).
- `rsh nopush --off` does not remove the `.gitignore` entry (harmless omission avoids noisy diffs).
