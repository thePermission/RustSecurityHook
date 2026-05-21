# Design: Per-Project Push Blocker (`rsh nopush`)

**Date:** 2026-05-21  
**Status:** Approved

## Problem

A developer may want to check out a repository in read-only mode — even if they have write access on GitHub/GitLab — to prevent accidental pushes from within an AI-assisted session. No existing `rsh` mechanism covers this case: `rsh off` disables all checks, and the blacklist rules are global.

## Decision

Add an opt-in, per-project push block activated by a flag file (`.rsh-nopush`) in the project root. This follows the existing pattern of `.rsh-disabled` and requires no central config store.

## Architecture

### New module: `src/nopush.rs`

Mirrors `src/disabled.rs` in structure:

- `flag_path_local() -> PathBuf` — returns `.rsh-nopush` in the current working directory
- `is_nopush_active() -> bool` — returns `true` if the flag file exists
- `is_push_command(cmd: &str) -> bool` — regex-based detection of blocked commands

No upward directory walk is needed: Claude Code always operates from the project root when the hook fires.

### Blocked commands

| Command | Notes |
|---|---|
| `git push` | all variants: `--force`, `-f`, `--force-with-lease`, `--delete`, any remote/refspec |
| `gh pr merge` | all flags |
| `glab mr merge` | all flags |
| `glab mr create` | all flags (implies a push) |

Commands like `git pull`, `git fetch`, `git status`, `gh pr view`, etc. are not affected.

### Hook integration (`src/main.rs`)

In `run_hook_from_str`, after the `disabled::is_disabled()` check and before the tool-name dispatch, insert a nopush check. If the flag file is present and the command is a push command, exit with code 2 and a clear message.

This applies to all command-bearing tools (Bash, exec_command, etc.).

## CLI Surface

New subcommand added to the `Commands` enum in `main.rs`:

```
rsh nopush          # enable push block for this project
rsh nopush --off    # disable push block
```

### `rsh nopush` (enable)

1. Creates `.rsh-nopush` in CWD (empty file, like `.rsh-disabled`)
2. Appends `.rsh-nopush` to `.gitignore` if not already present; on write failure prints a warning but continues
3. Prints to stderr: `rsh: push blocked for this project — run 'rsh nopush --off' to re-enable`
4. If already active: prints `rsh: already blocked`, exits 0

### `rsh nopush --off` (disable)

1. Removes the flag file; prints `rsh: already enabled` if absent
2. Does **not** remove the `.gitignore` entry (harmless, avoids noisy diffs)
3. Exits 0

### Block message (hook stderr, exit 2)

```
rsh blocked push: this project is marked read-only (.rsh-nopush)
hint: run 'rsh nopush --off' to re-enable pushing
```

### Self-disable protection

A new blacklist rule (`rsh-nopush-off`) blocks agents from running `rsh nopush --off`,
following the same pattern as the existing `rsh-self-disable` rule that protects `rsh off`/`rsh on`.
The rule also covers the flag file name so agents cannot delete or rename it directly.

## Error Handling

| Situation | Behavior |
|---|---|
| `.gitignore` not writable | Warning on stderr; flag file still created, exit 0 |
| Flag file not deletable on `--off` | Error on stderr, exit 1 |
| Flag file already exists on enable | `rsh: already blocked`, exit 0 |
| Flag file absent on disable | `rsh: already enabled`, exit 0 |

## Tests

### Unit tests in `src/nopush.rs`

- `is_nopush_active()` returns `true` when flag file exists, `false` otherwise
- `is_push_command("git push origin main")` → `true`
- `is_push_command("git push --force")` → `true`
- `is_push_command("git push --force-with-lease")` → `true`
- `is_push_command("gh pr merge")` → `true`
- `is_push_command("glab mr merge")` → `true`
- `is_push_command("glab mr create")` → `true`
- `is_push_command("git pull")` → `false`
- `is_push_command("git status")` → `false`
- `is_push_command("gh pr view")` → `false`

### Integration tests in `main.rs`

- Hook with flag file present blocks a `git push` Bash payload (exit 2)
- Hook without flag file passes a `git push` Bash payload (exit 0)
- `rsh nopush --off` itself is blocked by the `rsh-nopush-off` blacklist rule

## Out of Scope

- Walk-up search for the flag file in parent directories (not needed; hook CWD is project root)
- Global no-push mode (use a blacklist rule directly for that)
- Automatic removal of `.gitignore` entry on `--off`
