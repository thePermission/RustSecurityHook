# ADR 003 — Write/Edit Tool Interception and Script Content Scanning

**Date:** 2026-05-17  
**Status:** Accepted

## Context

The original hook only intercepted `Bash` tool calls. Two bypass vectors existed:

1. **File-write bypass:** A model could write a shell script containing forbidden commands via the `Write` or `Edit` tool, then execute it with a `Bash` call. The `Bash` call itself (`bash ./deploy.sh`) contains no forbidden keywords, so the blacklist would pass it.
2. **Script-execution bypass:** Even with `Write`/`Edit` interception, a model could write the script in a prior session (before `rsh` was installed) or copy it from an external source. The `Bash` call would still appear clean.

## Decision

The hook was extended in two directions:

**1. Write/Edit interception:** `run_hook()` now handles `Write` (scanning `tool_input.content`) and `Edit` (scanning `tool_input.new_string`) in addition to `Bash`. The full blacklist and forbid pipelines run against the content. For the forbid check the content is processed line by line; blank lines and `#`-prefixed lines are skipped.

**2. Script content scanning:** After the command string itself passes the blacklist and forbid checks, `rsh` splits the command on shell separators (`;`, `&&`, `||`, `|`, newline) and inspects each segment for script invocations. Recognised forms: `bash/sh/zsh/… <path>`, `python/python3/perl/ruby/node/nodejs <path>`, `source <path>`, `. <path>`, and direct execution (`./script.sh`, `/abs/path`, `name.sh`, `name.bash`). The referenced file is read and the same blacklist + forbid pipelines run against its content.

Unreadable files (missing, permission denied) are silently skipped — fail-open, matching the general hook design.

## Alternatives Considered

- **Block all `Write` calls unconditionally:** Rejected — too broad; the vast majority of file writes are legitimate.
- **Only scan `.sh`/`.bash` files:** Rejected — Python, Ruby, and Node scripts can issue the same dangerous calls. The interpreter list in `extract_script_path` covers the common cases.
- **Require a separate `rsh scan` command:** Rejected — would require the model to cooperate. The hook runs unconditionally.

## Consequences

- `Write` and `Edit` tool calls that write SQL keywords or kubectl commands into files are blocked even if those files were never going to be executed. This is an accepted trade-off — the false-positive rate is low in practice, and the blast radius of a missed write-then-execute pattern is high.
- `bash -c 'echo hi'` — the inline string after `-c` is not a file path; `extract_script_path` returns it as the first non-flag token but `read_to_string` will fail to find it on disk → fail-open. Acceptable: inline strings are already covered by the command-string scan.
- The script scan adds one `read_to_string` call per referenced script per hook invocation. For typical single-command Bash calls the cost is negligible.
