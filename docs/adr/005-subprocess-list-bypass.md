# ADR 005 — Subprocess List Bypass Rules

**Date:** 2026-05-17  
**Status:** Accepted

## Context

All binary-bound blacklist rules (e.g. `k8s-delete-namespace`) match patterns of the form `\b(?:kubectl|alias1|...)\b<sub-pattern>`. This works correctly for shell command strings like `kubectl delete ns prod`.

However, when a model writes or executes Python, Ruby, or Node code that calls `kubectl` or `helm` via a subprocess **argument list**, the binary and verb appear as quoted list elements, not as a shell string:

```python
subprocess.run(['kubectl', 'delete', 'ns', 'prod'])
```

The binary-bound rule for `k8s-delete-namespace` requires `kubectl\s` (binary followed by whitespace). In the list form `'kubectl'` is followed by `'`, `,`, and `'delete'` — no whitespace between the binary token and the verb token. The rule does not fire.

This bypass is relevant for `Write`/`Edit` content scanning (a model writes a Python script with a dangerous subprocess call) and for the script-content scanner (a model executes a pre-existing Python file via `python3 script.py`).

## Decision

Two `bin = None` rules were added to `RAW_RULES`:

| ID | Pattern |
|---|---|
| `k8s-subprocess-list` | `\[['"]kubectl['"]\s*(?:,\s*['"][^'"]*['"]\s*)*,\s*['"]delete['"]` |
| `helm-subprocess-list` | `\[['"]helm['"]\s*(?:,\s*['"][^'"]*['"]\s*)*,\s*['"](?:uninstall\|delete)['"]` |

`bin = None` means the pattern is matched against the full command string (or file content) regardless of which outer program is used. Both single-quoted and double-quoted list forms are covered.

Only destructive verbs (`delete` for kubectl, `uninstall`/`delete` for helm) are matched. Non-destructive list calls (`['kubectl', 'get', 'pods']`) are not blocked.

## Alternatives Considered

- **Ignore the bypass:** Rejected — the script-content and Write/Edit scanning features were added specifically to close bypass vectors. A known list-form bypass undermines that investment.
- **Block all subprocess calls containing `kubectl`:** Rejected — too broad; `['kubectl', 'get', 'pods']` is legitimate.
- **Only block via Write/Edit, not Bash command-string:** Rejected — a pre-existing Python file executed via `python3 script.py` would bypass the Write/Edit check. The `bin = None` rules fire in all scanning contexts.

## Consequences

- The patterns match the list-literal syntax only. Dynamic list construction (`cmd = ['kubectl']; cmd.append('delete')`) is not detected — accepted limitation.
- `grep "'kubectl', 'delete'"` in a log file is blocked — accepted trade-off, consistent with the existing grep false-positive policy for SQL rules.
- Coverage is limited to Python/Ruby/Node-style bracket lists. Shell `xargs` invocations (`echo "delete ns prod" | xargs kubectl`) are not covered by these rules; they are typically caught by the command-string rules because the `kubectl` binary appears in the pipe.
