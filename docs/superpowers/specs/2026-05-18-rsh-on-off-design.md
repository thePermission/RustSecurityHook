# Design: `rsh on` / `rsh off` — Global Enable/Disable Switch

**Date:** 2026-05-18  
**Status:** approved

## Problem

There is currently no way to temporarily disable all rsh checks without uninstalling the hook.
Individual rules can be toggled via `rsh rule disable/enable`, but no global kill-switch exists.
Additionally, there must be no way for an AI agent to disable rsh from within a Claude/Codex session.

## Goals

- Users can suspend all rsh checks with one command and resume with one command.
- AI agents cannot disable rsh — not via `rsh off`, not by touching the flag files directly.
- Project-local and global scope are both supported (global requires `-g`).

## Non-Goals

- Selective pipeline disable (e.g. blacklist off but forbid on) — out of scope.
- Persisting disabled state across reinstallation — the flag file is intentionally simple.

---

## Design

### Flag Files

Two flag files signal "disabled":

| Scope   | Path                              |
|---------|-----------------------------------|
| Global  | `~/.config/rsh/disabled`          |
| Local   | `.rsh-disabled` in CWD            |

File presence = disabled. File absence = enabled. No content is read; only existence is checked.

The hook checks both files at startup (before any JSON parsing):

```
if global_flag_exists || local_flag_exists → exit 0 immediately
```

Local flag takes precedence in the sense that either flag is sufficient to disable.

### CLI Commands

```
rsh off        # create .rsh-disabled in CWD
rsh off -g     # create ~/.config/rsh/disabled
rsh on         # remove .rsh-disabled from CWD
rsh on -g      # remove ~/.config/rsh/disabled
```

Both commands print a confirmation to stderr:

```
rsh: disabled (local) — run `rsh on` to re-enable
rsh: enabled (global)
rsh: already enabled (local)
```

`rsh list` shows a banner at the top when rsh is disabled in any scope:

```
⚠  rsh is currently DISABLED (global) — run `rsh on -g` to re-enable
```

### Agent Self-Protection

Two independent layers prevent an AI agent from disabling rsh:

#### Layer 1 — Blacklist rule `rsh-self-disable`

Blocks `rsh off` and `rsh on` when run as a Bash command through the hook.

```
id:       rsh-self-disable
bin:      rsh
pattern:  \s+(off|on)\b
reason:   agents must not disable the security hook
category: rsh-guard
```

#### Layer 2 — Flag file path protection

**Write/Edit tools:** both flag file paths added to `is_protected_path`:
- `~/.config/rsh/disabled` (matched by suffix `rsh/disabled`)
- `.rsh-disabled` (matched by filename)

**Bash commands:** a FallbackChecker rule (no `bin`) blocks any command segment
that mentions either path:

```
id:       rsh-guard-flag-file
bin:      None
pattern:  (?:rsh/disabled|\.rsh-disabled)
reason:   agents must not access or rename rsh flag files
category: rsh-guard
```

This catches `rm`, `mv`, `cp`, `touch`, `echo > ...`, `rename`, and any other
shell primitive that references the flag file by path.

---

## Data Flow

```
rsh invoked (hook mode)
  │
  ├─ global flag (~/.config/rsh/disabled) exists? → exit 0
  ├─ local flag  (.rsh-disabled)           exists? → exit 0
  │
  └─ normal check pipeline
```

```
rsh off [-g]
  │
  ├─ -g: create ~/.config/rsh/disabled (mkdir -p as needed)
  └─ (no -g): create .rsh-disabled in CWD
```

```
rsh on [-g]
  │
  ├─ -g: remove ~/.config/rsh/disabled (no error if absent)
  └─ (no -g): remove .rsh-disabled from CWD (no error if absent)
```

---

## Implementation Touchpoints

| File              | Change                                                              |
|-------------------|---------------------------------------------------------------------|
| `src/main.rs`     | Add `Off` / `On` variants to `Commands` enum (with `-g` flag)      |
| `src/main.rs`     | `run_hook()` checks flag files before any other logic               |
| `src/main.rs`     | `list_rules()` prints disabled banner when either flag is active    |
| `src/main.rs`     | Add `is_protected_path` entries for both flag file paths            |
| `src/blacklist.rs`| Add rules `rsh-self-disable` and `rsh-guard-flag-file`             |
| `src/disabled.rs` | Add `flag_path_global()` and `flag_path_local()` helpers            |
| `CLAUDE.md`       | Document `on` / `off` in the architecture table                     |

---

## Testing

- `rsh off` creates `.rsh-disabled`; subsequent hook invocation returns exit 0.
- `rsh off -g` creates `~/.config/rsh/disabled`; hook returns exit 0.
- `rsh on` removes the local flag; hook resumes blocking.
- `rsh off` then `rsh off` → idempotent (no error).
- `rsh on` when not disabled → prints "already enabled", exit 0.
- Blacklist: `rsh off` and `rsh on` are blocked when sent as Bash commands.
- FallbackChecker: commands containing `rsh/disabled` or `.rsh-disabled` are blocked.
- `is_protected_path`: Write/Edit to either flag file path is blocked.
