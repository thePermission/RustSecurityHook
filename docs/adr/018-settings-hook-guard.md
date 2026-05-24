# ADR 018: Settings Hook Guard

**Status:** Accepted  
**Date:** 2026-05-24

## Context

A model running under `rsh` could potentially remove the hook that guards it by editing the Claude or Codex settings file directly — using the `Write` or `Edit` tools — to delete the `PreToolUse` entry that invokes `rsh`. This would silently disable all subsequent protection without triggering any existing blacklist rule or protected-path check.

The existing `is_protected_path` mechanism covers `~/.config/rsh/` but does not cover the tool settings files themselves (`.claude/settings.json`, `.codex/hooks.json`), because those files legitimately need to be editable by both users and agents for unrelated configuration changes (themes, other hooks, etc.).

## Decision

Add a targeted guard (`settings_guard` module) that intercepts `Write` and `Edit` calls to Claude/Codex settings files and blocks only the subset of operations that would remove the rsh `PreToolUse` hook.

Guarded paths:
- `.claude/settings.json` (global and project-local)
- `.claude/settings.local.json` (global and project-local)
- `.codex/hooks.json` (global and project-local)

**For `Write`:** parse the new content as JSON, check whether any `hooks.PreToolUse[*].hooks[*].command` resolves to `rsh` (bare name or absolute path). Block if the current file had the hook but the new content does not.

**For `Edit`:** read the current file, apply the `old_string` → `new_string` replacement in memory, parse the result, and apply the same check.

The guard is strictly surgical: it only fires when the hook was present and would be absent after the operation. All other writes and edits — including adding other hooks, changing settings, or editing files that never had the hook installed — pass through unchanged.

## Consequences

- Models can still update Claude/Codex settings freely as long as the rsh `PreToolUse` entry remains intact.
- The guard is fail-open: invalid JSON, unreadable files, and unlocatable `old_string` values are never treated as block reasons, preventing spurious failures.
- `is_rsh_command` recognises both bare `rsh` and absolute paths (including Windows `.exe` suffix), covering installs via `cargo install` or manual binary paths.
- The check happens at PreToolUse time, so the settings file is never actually modified when the guard fires.
