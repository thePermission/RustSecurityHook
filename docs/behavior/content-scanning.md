# Content Scanning — Write, Edit, and Script Files

`rsh` hooks three Claude Code tool calls, not just `Bash`. It also reads script files referenced in shell commands and scans their content before allowing execution.

## Tool Coverage

| Claude Code tool | What is scanned |
|---|---|
| `Bash` | The `command` field — the shell command string |
| `Write` | The `content` field — the entire file being written |
| `Edit` | The `new_string` field — the replacement text |

For `Write` and `Edit`, the same blacklist and forbid pipelines run against the content. This prevents a model from writing a file that contains forbidden SQL or kubectl calls and then executing it.

The block message includes the context, e.g.:

```
rsh blocked file write (rule: sql-drop): Permanently removes a database object and all its data
```

For forbid hits on `Write`/`Edit`, the content is scanned **line by line** (blank lines and `#` comments are skipped). The forbid check uses the same live kubeconfig fallback for kubectl/helm lines that have no explicit context/namespace flag.

All other tool names are passed through (exit 0).

## Script File Scanning

When `rsh` receives a `Bash` tool call, it also inspects **script files** that the command would execute. After the blacklist and forbid checks pass on the command string itself, `rsh` splits the command on shell separators (`;`, `&&`, `||`, `|`, newline) and looks for script invocations in each segment.

### Recognized invocation patterns

| Pattern | Example |
|---|---|
| Interpreter + script path | `bash /tmp/deploy.sh`, `python3 script.py`, `perl /opt/run.pl` |
| `source` / `.` builtin | `source /etc/profile`, `. ~/.bashrc` |
| Direct execution | `./deploy.sh`, `/usr/local/bin/myscript`, `cleanup.sh`, `setup.bash` |

Recognized interpreters: `bash`, `sh`, `zsh`, `ksh`, `dash`, `fish`, `python`, `python3`, `perl`, `ruby`, `node`, `nodejs`.

Quoted paths (single or double quotes) are stripped before reading the file.

### Fail-open on unreadable files

If a referenced script cannot be read (does not exist, permission denied, binary file), `rsh` **passes through** (fail-open). A crash or missing file in the hook must not lock up the Claude Code session.

### What is scanned in the script

The full content of the script file runs through the same blacklist and forbid pipelines as a `Write`/`Edit` payload — line by line, skipping blank lines and `#` comments for the forbid check, and as a whole string for the regex blacklist.

The block message identifies the script path:

```
rsh blocked script execution (/tmp/deploy.sh) (rule: k8s-delete-namespace): Deletes a Kubernetes namespace ...
```
