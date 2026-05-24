---
title: Write, Edit, and Apply Patch Tool Processing
tags:
  - rsh/tool-handling
  - rsh/pipeline
aliases:
  - write tool
  - edit tool
---

# Write, Edit, and Apply Patch Tool Processing

## Overview

`rsh` intercepts the Claude Code `Write` and `Edit` tools and the Codex `apply_patch` tool to prevent a model from writing or modifying content that contains forbidden commands — such as `kubectl delete` or `helm uninstall` — and then executing it from a subsequent `Bash` tool call.

Claude `Write` and `Edit` undergo a two-stage check: first, the target file path is validated to ensure it is not part of the `rsh` configuration directory; second, the file content is scanned against the full ToolChecker pipeline. Codex `apply_patch` runs the content scan stage over the patch text; it does not currently have a separate `file_path` field in the hook payload.

## Hook Input Schema

Claude Code and Codex send the hook a JSON event with `tool_name` and `tool_input` fields:

### Write

```json
{
  "tool_name": "Write",
  "tool_input": {
    "file_path": "deploy.sh",
    "content": "kubectl delete ns prod"
  }
}
```

### Edit

```json
{
  "tool_name": "Edit",
  "tool_input": {
    "file_path": "deploy.sh",
    "new_string": "kubectl delete ns prod"
  }
}
```

### Codex `apply_patch`

```json
{
  "tool_name": "apply_patch",
  "tool_input": {
    "command": "*** Begin Patch\n*** Update File: deploy.sh\n@@\n-kubectl get pods\n+kubectl delete ns prod\n*** End Patch\n"
  }
}
```

## Stage 1: Protected Path Check

Before scanning content, `rsh` verifies that the target file path is not a protected path. This check is hardcoded in `run_hook()` for Claude `Write` and `Edit` and cannot be bypassed by disabling any blacklist rule.

### Stage 1b: Settings Hook Guard

After the protected path check, `rsh` checks whether the target path is a Claude or Codex settings file:

- `.claude/settings.json` (global or project-local)
- `.claude/settings.local.json` (global or project-local)
- `.codex/hooks.json` (global or project-local)

If the path matches **and** the rsh `PreToolUse` hook is currently present in that file **and** the operation would remove it, the write or edit is blocked.

For `Write`, the new content is parsed as JSON and checked for the hook. For `Edit`, `rsh` reads the current file, applies the `old_string` → `new_string` replacement in memory, and checks the resulting JSON. Normal settings changes that preserve the hook — or edits to files that never had the hook — pass through without restriction.

The check is intentionally fail-open: unparseable JSON, missing files, or unlocatable `old_string` values are never treated as a block reason.

#### Block Message

```
rsh blocked write to /home/user/.claude/settings.json: would remove rsh PreToolUse hook
```

or

```
rsh blocked edit of /home/user/.codex/hooks.json: would remove rsh PreToolUse hook
```

### Protected Paths

A path is protected if it targets rsh's configuration directory or one of the hook disable flag files. The check handles both forward and backslashes, includes platform-specific configured paths, and canonicalizes existing paths so symlinks to protected files are also blocked.

#### Examples of protected paths

- `/home/user/.config/rsh/forbidden.json` — **blocked**
- `~/.config/rsh/aliases.json` — **blocked**
- `.config/rsh/disabled.json` — **blocked**
- `.rsh-disabled` — **blocked**
- `/home/user/.config/rsh/disabled` — **blocked**
- `/home/user/.config/other/config.json` — **allowed**

#### What is protected

The `rsh` configuration directory stores:

- `forbidden.json` — the forbid list (clusters, namespaces, databases)
- `aliases.json` — command-to-alias mappings
- `disabled.json` — per-user rule and tool enable/disable state
- `disabled` — global hook disable flag
- `.rsh-disabled` — local hook disable flag

Writing to these files would allow a model to modify the hook's own behavior — for example, to add a cluster to the allow list or disable a blocking rule. The protected path check prevents this attack surface entirely.

### Block Message

If a protected path is detected:

```
rsh blocked write to protected path: /home/user/.config/rsh/forbidden.json
```

or

```
rsh blocked edit of protected path: /home/user/.config/rsh/aliases.json
```

The entire tool call is refused (exit code 2).

## Stage 2: Content Scan

If the path check passes, the payload is scanned using the full ToolChecker pipeline. Codex `apply_patch` enters here directly and scans `tool_input.command` as content.

### What is scanned

| Tool | Field scanned | Semantics |
|---|---|---|
| `Write` | `content` | The entire file being written to disk |
| `Edit` | `new_string` | Only the replacement text, not the entire file |
| `apply_patch` | `command` | The patch text itself, scanned as content |

### Pipeline Stages

1. **Segment splitting** (`split_segments`): Divides the content on shell separators (`;`, `&&`, `||`, `|`, `\n`). Each fragment is classified as `Segment::Direct` or `Segment::Script`.
2. **Checker selection** (`detect_checkers`): Scans the content for known binary names (`kubectl`, `helm`, `docker`, `rsh`, etc.) and returns the relevant checkers. The `FallbackChecker` is always included.
3. **Sequential execution**: Checkers run one by one in the order returned by `detect_checkers`. Execution stops at the first hit.

See [[bash-tool]] for the full pipeline description, including segment types, checker selection, and sequential execution mechanics.

### Block Message

If the content scan finds a match:

```
rsh blocked file content: (rule: k8s-delete-namespace): Deletes a Kubernetes namespace and all its resources
```

The entire tool call is refused (exit code 2).

## Tools That Pass Through

All other tool names are passed through without inspection (exit code 0).

This fail-open behavior is intentional for tool calls that do not carry command text or editable
content. Command-carrying tools are scanned when `tool_input.command` or `tool_input.cmd` is
present. Claude `Write`/`Edit` and Codex `apply_patch` retain their dedicated handling described
above.

## Exit Codes

The hook respects this contract:

- **Exit 0**: The edit operation is allowed. The caller proceeds with the tool.
- **Exit 2**: The edit operation is blocked. The caller surfaces the stderr message to the model and refuses the tool call.

## See Also

- [[bash-tool]] — The ToolChecker pipeline used by Bash and content-scanned edit tools
- [[forbid-system]] — The cluster, namespace, and database forbid lists
- [[checker-rsh]] — How `rsh` prevents modification of its own configuration
