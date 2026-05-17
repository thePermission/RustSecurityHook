# Design Spec — rsh Self-Protection

**Date:** 2026-05-17  
**Status:** Approved

## Problem

The `rsh rule disable` command introduced in a prior feature allows any caller to
deactivate individual blacklist rules. Since Claude Code itself is the primary
caller in a hook session, Claude could — intentionally or through prompt injection —
run `rsh rule disable <id>` to remove a rule, then proceed with the previously
blocked command. The same risk applies to `rsh forbid remove` (weakens the forbid
list) and any direct Bash or file-tool access to `~/.config/rsh/` (overwrites
config files directly).

## Design (Approach C — Hybrid)

### 1. Blacklist Rules — Bash Protection

New category **"rsh Self-Protection"** added to `RAW_RULES` in `src/blacklist.rs`.
All three rules use `bin = Some("rsh")` so alias expansion applies.

| ID | Sub-pattern | Reason |
|----|-------------|--------|
| `rsh-protect-disable` | `\s[^|;&\n]*?\brule\s+disable\b` | Prevents disabling blacklist rules |
| `rsh-protect-forbid-remove` | `\s[^|;&\n]*?\bforbid\s+remove\b` | Prevents removing forbid entries |
| `rsh-protect-config-access` | `(?:^|\s)[^|;&\n]*\.config[/\\]rsh\b` | Prevents any Bash access to the rsh config directory |

**Self-protection property:** Any attempt to run `rsh rule disable rsh-protect-disable`
will itself match the `rsh-protect-disable` rule and be blocked before the
disable takes effect. The protection is therefore self-referential and cannot
be lifted through the Bash tool.

### 2. Hardcoded Path Check — Write/Edit Protection

A new function `is_protected_path(path: &str) -> bool` is added (in `src/main.rs`
or extracted to `src/protected_paths.rs` if it grows). It returns `true` when
the normalised path contains `.config/rsh`:

```rust
fn is_protected_path(path: &str) -> bool {
    let p = path.replace('\\', "/");
    p.contains(".config/rsh")
}
```

`run_hook()` is extended to check `file_path` before scanning content:

```rust
"Write" => {
    let file_path = tool_input.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
    let content   = tool_input.get("content").and_then(|v| v.as_str()).unwrap_or("");
    if is_protected_path(file_path) {
        eprintln!("rsh blocked write to protected path: {file_path}");
        return ExitCode::from(2);
    }
    run_check_content(content)
}
"Edit" => {
    let file_path  = tool_input.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
    let new_string = tool_input.get("new_string").and_then(|v| v.as_str()).unwrap_or("");
    if is_protected_path(file_path) {
        eprintln!("rsh blocked edit of protected path: {file_path}");
        return ExitCode::from(2);
    }
    run_check_content(new_string)
}
```

This check is **hardcoded** — it does not consult the disabled-rules config and
cannot be bypassed by disabling a rule.

### 3. Error Messages

All block messages follow the existing pattern:
- `rsh blocked command (rule: rsh-protect-disable): <reason>`  (via normal blacklist path)
- `rsh blocked write to protected path: <path>`  (new, from path check)
- `rsh blocked edit of protected path: <path>`  (new, from path check)

## Tests

### Blacklist rule tests (in `src/blacklist.rs` `tests` module)

| Rule | Positive (must block) | Negative (must pass) |
|------|-----------------------|----------------------|
| `rsh-protect-disable` | `rsh rule disable k8s-delete-namespace` | `rsh rule list` |
| `rsh-protect-forbid-remove` | `rsh forbid remove cluster prod` | `rsh forbid list` |
| `rsh-protect-config-access` | `cat ~/.config/rsh/disabled-rules.json` | `cat ~/.config/other/file.json` |

### Path-check unit tests

- `is_protected_path(".config/rsh/disabled-rules.json")` → `true`
- `is_protected_path(".config/rsh/aliases.json")` → `true`
- `is_protected_path(".config\\rsh\\forbidden.json")` (Windows) → `true`
- `is_protected_path(".config/other/file.json")` → `false`
- `is_protected_path("")` → `false`

### Hook integration tests (stdin JSON → exit code)

- Write to `~/.config/rsh/disabled-rules.json` → exit 2
- Edit of `~/.config/rsh/aliases.json` → exit 2
- Write to `~/projects/myapp/main.rs` → exit 0 (unrelated path)

## Out of Scope

- Blocking `rsh rule enable` — re-enabling a rule is a security-increasing operation.
- Blocking `rsh forbid cluster/namespace/database` — adding entries tightens security.
- Protecting against manual edits made by the user outside a Claude Code session
  (the hook only runs during tool calls).
