# Content Scanning — Write, Edit, and Script Files

`rsh` hooks three Claude Code tool calls, not just `Bash`. It also reads script files
referenced in shell commands and scans their content before allowing execution.

## Tool Coverage

| Claude Code tool | What is scanned |
|---|---|
| `Bash` | The `command` field — the shell command string |
| `Write` | The `content` field — the entire file being written |
| `Edit` | The `new_string` field — the replacement text |

For `Write` and `Edit`, the full check pipeline runs against the content. This prevents a
model from writing a file that contains forbidden kubectl/helm calls and then executing it.

The block message includes the context, e.g.:

```
rsh blocked file write (rule: sql-drop): Permanently removes a database object and all its data
```

All other tool names are passed through (exit 0).

## Check Pipeline

All content — whether a direct `Bash` command, a script file, or a `Write`/`Edit` payload —
goes through the same **ToolChecker pipeline**:

1. `split_segments` splits the content on shell separators (`;`, `&&`, `||`, `|`, `\n`).
   Each fragment is classified as `Segment::Direct` or `Segment::Script` (see below).
2. For each segment, `detect_checkers` scans the content for known binary names and returns
   the relevant checkers. The `FallbackChecker` is always included.
3. One thread is spawned per checker. The first thread to find a hit sets a stop flag and
   returns the hit. All other threads observe the flag and exit without work (fail-fast).

The exit-code contract is unchanged: `0` = allow, `2` = block with reason on stderr.

### Tool Checkers

| Checker | Tool(s) | Includes forbid check? |
|---|---|---|
| `KubectlChecker` | `kubectl` and aliases | Yes — cluster + namespace |
| `HelmChecker` | `helm` and aliases | Yes — cluster + namespace |
| `DockerChecker` | `docker`, `docker-compose` and aliases | No |
| `RshChecker` | `rsh` self-protection rules | No |
| `FallbackChecker` | `bin=None` rules (SQL, subprocess bypass, config protection) + `forbid::check_db` | Always runs |

Adding support for a new tool means adding one struct that implements `ToolChecker` — no
changes to `run_check` or the rest of `lib.rs`.

## Script File Scanning

When `rsh` receives a `Bash` tool call, it also inspects **script files** that the command
would execute. `split_segments` classifies each shell fragment:

### Recognized invocation patterns

| Pattern | Example |
|---|---|
| Interpreter + script path | `bash /tmp/deploy.sh`, `python3 script.py`, `perl /opt/run.pl` |
| `source` / `.` builtin | `source /etc/profile`, `. ~/.bashrc` |
| Direct execution | `./deploy.sh`, `/usr/local/bin/myscript`, `cleanup.sh`, `setup.bash` |

Recognized interpreters: `bash`, `sh`, `zsh`, `ksh`, `dash`, `fish`, `python`, `python3`,
`perl`, `ruby`, `node`, `nodejs`.

### Fail-open on unreadable files

If a referenced script cannot be read (does not exist, permission denied, binary file), `rsh`
**passes through** (fail-open). A crash or missing file in the hook must not lock up the
Claude Code session.

### What is scanned in the script

The full content of the script file is processed by the same ToolChecker pipeline as any
other content — `detect_checkers` picks the relevant checkers and they run in parallel. The
forbid check for kubectl/helm lines uses the same live kubeconfig fallback as direct commands.

The block message identifies the source:

```
rsh blocked: [k8s-delete-namespace] Deletes a Kubernetes namespace and all its resources
```

## Forbid Checks (Cluster and Namespace)

`KubectlChecker` and `HelmChecker` include the cluster and namespace forbid check in
addition to the regex blacklist. For content with no explicit `--context`/`--namespace`
flags, the checker falls back to live `kubectl config current-context` /
`kubectl config view --minify` to determine what the command would target by default.

For `Write`/`Edit` content, `FallbackChecker` runs `forbid::check_db` line by line, skipping
blank lines and `#` comments.
