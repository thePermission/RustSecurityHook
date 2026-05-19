---
title: Bash Tool Processing
tags:
  - rsh/tool-handling
  - rsh/pipeline
aliases:
  - bash tool
  - bash processing
---

# Bash Tool Processing

## Overview

When Claude Code or Codex invokes a command-executing tool, the `rsh` hook receives a JSON event containing the command to be executed. This document describes how `rsh` processes that command through the checker pipeline and produces an allow or block decision.

## Step 0: Hook Input

Claude Code and Codex send the hook a JSON event with the following structure:

```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "kubectl delete ns prod && ./cleanup.sh"
  }
}
```

Codex command tools may also use `tool_name` values such as `exec_command` or `functions.exec_command`, and may place the shell text in either `tool_input.command` or `tool_input.cmd`.

The hook extracts the command string and passes it to the segment splitter.

## Step 1: Segment Splitting

The `split_segments` function divides the input command on shell separators and produces a vector of segments. Each segment is classified as either `Direct` (a regular command) or `Script` (a file to be executed).

After splitting, each fragment is tokenized with the `shell-words` crate. If tokenization fails because the fragment contains incomplete shell quoting, `rsh` falls back to its older lightweight tokenizer instead of treating the parse error as a block. This preserves the hook's fail-open behavior while handling normal shell quoting more accurately.

### Separators

Splitting occurs on these shell metacharacters and operators:

- `;` (command sequence)
- `&&` (logical AND)
- `||` (logical OR)
- `|` (pipe)
- `\n` (newline)

Whitespace is trimmed from each fragment. Empty segments and lines starting with `#` are discarded.

### Segment Types

#### Direct Segments

A fragment becomes `Segment::Direct { command }` if it does not match any script detection rule.

#### Script Segments

A fragment becomes `Segment::Script { path }` when one of these conditions is met:

1. **Interpreter + file argument**: The first token is a known interpreter (`bash`, `sh`, `zsh`, `ksh`, `dash`, `fish`, `python`, `python3`, `perl`, `ruby`, `node`, `nodejs`) followed by a non-flag argument. The path is the first non-flag token after the interpreter.

2. **Source or dot builtin**: The first token is `source` or `.`, and the second token is the path.

3. **Direct path execution**: The first token starts with `./` or `/`, or ends with `.sh` or `.bash`.

Quoted paths are stripped according to shell tokenization rules before extraction. For example, `bash "/tmp/deploy.sh"` yields the path `/tmp/deploy.sh`.

Before reading a script file, `rsh` expands the common home-directory forms `~`, `~/...`, `$HOME`, `$HOME/...`, `${HOME}`, and `${HOME}/...`. It does not perform general shell expansion, variable expansion for arbitrary variables, command substitution, or glob expansion.

### Fail-open Behavior

If the expanded script path cannot be read from the filesystem, `rsh` falls back to the literal path. If that also cannot be read, the segment is silently skipped.

## Step 2: Checker Selection

For each segment, the `detect_checkers` function scans the content (command text or script file contents) for known binary names and returns a vector of tool checkers to run.

| Checker | Included when |
|---------|---------------|
| [[checker-fallback|FallbackChecker]] | Always included |
| [[secret-file-protection|SecretFileChecker]] | Always included |
| [[checker-kubectl|KubectlChecker]] | `kubectl` or a configured alias appears in content |
| [[checker-helm|HelmChecker]] | `helm` or a configured alias appears in content |
| [[checker-docker|DockerChecker]] | `docker`, `docker-compose`, or a configured alias appears in content |
| [[checker-rsh|RshChecker]] | `rsh` or a configured alias appears in content |

For `Segment::Script`, the entire file contents are scanned — not just the command invocation line that triggered the script detection.

Three checkers apply additional forbid checks beyond the regex blacklist: [[checker-kubectl|KubectlChecker]] and [[checker-helm|HelmChecker]] check the target cluster and namespace, [[checker-fallback|FallbackChecker]] checks the database host. See [[forbid-system]] for details.

## Step 3: Sequential Execution

For each segment, the selected checkers are run one by one in the order returned by `detect_checkers`. Execution stops at the first hit and returns it immediately. If no checker produces a hit for any segment, `run_parallel_checks` returns `None`.

The function name `run_parallel_checks` is preserved for API stability; the implementation is sequential since ADR 015.

### Outcome

- **Exit 0 (allow)**: No checker produced a hit; the command is allowed.
- **Exit 2 (block)**: A checker produced a hit; the reason is written to stderr, and the entire Bash tool call is refused.

## Example: Chained Command with Script

Consider this command:

```sh
kubectl get pods && bash /tmp/deploy.sh; docker ps
```

The `split_segments` function produces three segments:

| Segment | Type | Content |
|---------|------|---------|
| `kubectl get pods` | Direct | Command text: `kubectl get pods` |
| `/tmp/deploy.sh` | Script | File contents (e.g., if file exists) |
| `docker ps` | Direct | Command text: `docker ps` |

If `/tmp/deploy.sh` contains the text `kubectl delete ns prod`, the following occurs:

1. Segment 1 (`kubectl get pods`): `FallbackChecker`, `SecretFileChecker`, `KubectlChecker` run in sequence — no hit.
2. Segment 2 (script contents): `KubectlChecker.check()` finds `kubectl delete ns prod` and returns a hit immediately.
3. Segment 3 is never reached.

The hook returns exit code 2 with a message on stderr — the entire Bash call is blocked, even though segment 1 and segment 3 were individually safe.

## Exit Codes

The hook respects this contract:

- **Exit 0**: Command is allowed. The caller proceeds with the tool call.
- **Exit 2**: Command is blocked. The caller surfaces the stderr message to the model and refuses the tool call.

Other exit codes are not used; they would be interpreted as errors rather than explicit blocks.
