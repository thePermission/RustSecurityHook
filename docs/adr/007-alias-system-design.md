# ADR 007 — Alias System Design

**Date:** 2026-05-17  
**Status:** Accepted

## Context

Blacklist rules are bound to specific binary names (e.g. `kubectl`). On many systems the same binary is reachable under a different name — a symlink (`k` → `kubectl`), a hardlink, or a shell alias. If `rsh` only matched the canonical name, a model could trivially bypass every binary-bound rule by using the alias.

Three sources of "alias" information exist on a typical system:

1. **Shell aliases** (`alias k=kubectl` in `.bashrc`) — only active in interactive shells; not available in the non-interactive subprocess that Claude Code uses to run hooks.
2. **Symlinks and hardlinks in `$PATH`** — detectable by comparing `canonicalize()` paths.
3. **Wrapper scripts** — arbitrary executables that call the real binary inside; not detectable without executing them.

## Decision

`rsh` implements a **user-managed, persistent alias map** stored as JSON:

```
~/.config/rsh/aliases.json   (Unix, XDG-aware)
%APPDATA%\rsh\aliases.json   (Windows)
```

Format: `BTreeMap<String, Vec<String>>` — canonical command → list of known aliases.

Two mechanisms populate the map:

1. **Manual:** `rsh alias <command> <alias>` — idempotent, persists immediately.
2. **Auto-detection:** `rsh detect-aliases [cmd]` — scans `$PATH` for files whose `canonicalize()` path matches the target binary. Catches symlinks and hardlinks; explicitly does **not** detect wrapper scripts (see below).

`rsh init` calls `detect-aliases` automatically for all rule-bound binaries after installing the hook.

At runtime the map is loaded once per process via a `LazyLock<AliasMap>` and shared between the blacklist and forbid modules — the JSON file is parsed at most once per hook invocation regardless of how many rules or forbid checks run.

When assembling a rule regex for binary `b`, `aliases_for(map, b)` returns `[b, alias1, alias2, ...]`. The effective pattern becomes `\b(?:b|alias1|alias2)\b<sub-pattern>`.

## Alternatives Considered

- **Parse shell config files (`.bashrc`, `.zshrc`, etc.):** Rejected — shell alias syntax is complex and shell-specific; parsing it reliably without executing the shell is impractical. Shell aliases are also inactive in the hook subprocess.
- **Detect wrapper scripts:** Rejected — wrapper scripts can be arbitrary programs. Executing them to detect what they wrap would introduce its own security risks and performance overhead. The limitation (wrapper scripts bypass alias detection) is documented.
- **Store aliases in `settings.json` alongside the hook entry:** Rejected — `settings.json` is owned by Claude Code. Mixing hook infrastructure with user alias data in a file we do not fully control increases the risk of clobbering Claude Code configuration.
- **Re-read the alias file on every rule check:** Rejected — the hook runs in the hot path of every Claude Code tool call. Repeated disk I/O would add latency. The `LazyLock` pattern amortizes the cost to a single read per process lifetime.

## Consequences

- Wrapper scripts that call `kubectl` internally are not covered. Users who rely on such wrappers must either register the wrapper name manually (`rsh alias kubectl mywrapper`) or accept that wrapper-invoked commands bypass the blacklist.
- The alias map is process-wide and immutable after first access. Adding an alias while a Claude Code session is running takes effect on the next session (next hook process invocation).
- `BTreeMap` (sorted) is used instead of `HashMap` for deterministic serialization order in the JSON file, making diffs readable.
