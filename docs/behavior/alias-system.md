---
title: Alias System
tags:
  - rsh/system
aliases:
  - aliases
  - alias system
---

# Alias System

Most blacklist rules are bound to a specific binary (e.g. `kubectl`, `docker`). If a user has a shell alias or symlink that points to the same binary under a different name (e.g. `k` → `kubectl`, `d` → `docker`), commands issued via the alias would bypass those rules. The alias system closes this gap.

## Storage

Aliases are stored in:

- **Unix:** `$XDG_CONFIG_HOME/rsh/aliases.json` (default: `~/.config/rsh/aliases.json`)
- **Windows:** `%XDG_CONFIG_HOME%\rsh\aliases.json` (default: `%APPDATA%\rsh\aliases.json`)

Format: a JSON object mapping each canonical command to a list of known aliases.

```json
{
  "kubectl": ["k", "kctl"],
  "docker": ["d"]
}
```

The file is parsed once per hook invocation and cached process-wide (`LazyLock`). Both the blacklist and the forbid modules share the same cache.

## CLI

### Manual registration

```sh
rsh alias <command> <alias>
```

Example: `rsh alias kubectl k` — registers `k` as an alias for `kubectl`. If the alias is already known, the command is a no-op (idempotent).

### Auto-detection

```sh
rsh detect-aliases [cmd]
```

Scans every directory in `$PATH` for files whose `canonicalize()` path matches the canonical binary. This catches **symlinks and hardlinks** but does **not** detect wrapper shell scripts or renamed copies.

- With no argument: scans all binaries that appear as `bin` in at least one rule (currently `kubectl`, `helm`, `docker`, `docker-compose`).
- With one or more arguments: scans only those specific commands.

`rsh init` automatically runs `detect-aliases` for all bound binaries after writing the hook entry to `settings.json`.

## How Rules Use Aliases

When a rule has `bin = Some("kubectl")`, the regex is assembled as:

```
\b(?:kubectl|k|kctl)\b<sub-pattern>
```

The first token in the alternation is always the canonical binary name; registered aliases follow. This means the regex fires regardless of which name the user typed.

Rules with `bin = None` (SQL keyword rules, subprocess-list bypass rules) are not affected by aliases — they match the full command string unconditionally.
