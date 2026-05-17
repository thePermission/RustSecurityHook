# Bash Tool Processing

## Overview

When Claude Code invokes the `Bash` tool, the `rsh` hook receives a JSON event containing the command to be executed. This document describes how `rsh` processes that command through the checker pipeline and produces an allow or block decision.

## Step 0: Hook Input

Claude Code sends the hook a JSON event with the following structure:

```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "kubectl delete ns prod && ./cleanup.sh"
  }
}
```

The hook extracts the string value of `tool_input.command` and passes it to the segment splitter.

## Step 1: Segment Splitting

The `split_segments` function divides the input command on shell separators and produces a vector of segments. Each segment is classified as either `Direct` (a regular command) or `Script` (a file to be executed).

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

Quoted paths are stripped of surrounding single or double quotes before extraction. For example, `bash "/tmp/deploy.sh"` yields the path `/tmp/deploy.sh`.

### Fail-open Behavior

If a script path cannot be read from the filesystem, that segment is silently skipped (the thread exits without producing a check).

## Step 2: Checker Selection

For each segment, the `detect_checkers` function scans the content (command text or script file contents) for known binary names and returns a vector of tool checkers to run.

| Checker | Included when |
|---------|---------------|
| [[checker-fallback\|FallbackChecker]] | Always included |
| [[checker-kubectl\|KubectlChecker]] | `kubectl` or a configured alias appears in content |
| [[checker-helm\|HelmChecker]] | `helm` or a configured alias appears in content |
| [[checker-docker\|DockerChecker]] | `docker`, `docker-compose`, or a configured alias appears in content |
| [[checker-rsh\|RshChecker]] | `rsh` or a configured alias appears in content |

For `Segment::Script`, the entire file contents are scanned — not just the command invocation line that triggered the script detection.

## Step 3: Parallel Execution

All checker instances (across all segments) are spawned as independent threads. They share two synchronization primitives:

- **Stop flag**: An `AtomicBool` that signals when the first hit has been found.
- **Channel**: An `mpsc` channel for transmitting the winning hit.

Execution proceeds as follows:

1. For each segment, a thread is spawned for each selected checker.
2. Each thread checks the stop flag on entry. If it is set, the thread returns immediately.
3. If not set, the thread runs its checker against the segment content.
4. If the checker returns a hit, the thread sets the stop flag and sends the hit over the channel.
5. After all threads are spawned, the sender is dropped. The receiver waits for the first hit or returns `None` if all threads exit without finding one.

### Outcome

- **Exit 0 (allow)**: No checker produced a hit; the command is allowed.
- **Exit 2 (block)**: At least one checker produced a hit; the reason is written to stderr, and the entire Bash tool call is refused.

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

1. Three checkers are spawned for segment 1 (`KubectlChecker`, `FallbackChecker`, and `DockerChecker`).
2. Two checkers are spawned for segment 2 (at minimum `KubectlChecker` and `FallbackChecker`; if the script file also contains `docker`, then `DockerChecker` too).
3. One checker is spawned for segment 3 (`DockerChecker` and `FallbackChecker`).

When any thread scanning segment 2 runs `KubectlChecker.check()` against the script contents and finds `kubectl delete ns prod`, it sets the stop flag and sends the hit. Remaining threads observe the flag and exit without work. The hook returns exit code 2 with a message on stderr — the entire Bash call is blocked, even though segment 1 and segment 3 were individually safe.

## Exit Codes

The hook respects this contract:

- **Exit 0**: Command is allowed. Claude Code proceeds with the Bash tool.
- **Exit 2**: Command is blocked. Claude Code surfaces the stderr message to the model and refuses the tool call.

Other exit codes are not used; they would be interpreted as errors rather than explicit blocks.
