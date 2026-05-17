# ADR 004 — Fail-Open Exit Code Contract

**Date:** 2026-05-17  
**Status:** Accepted

## Context

Claude Code's PreToolUse hook protocol interprets the exit code of the hook binary:

- **Exit 0** — tool call allowed.
- **Exit 2** — tool call explicitly blocked; stderr is surfaced to the model as the reason.
- **Exit 1** (and other non-zero, non-2 codes) — hook error; behavior depends on the Claude Code version and may surface an error to the user or silently abort.

`rsh` must handle a wide range of runtime conditions: empty stdin, malformed JSON, unreadable config files, missing `kubectl` binary (for the kubeconfig fallback), and panics. The choice of exit code for each failure mode directly affects the safety properties of the hook.

## Decision

**Explicit block → exit 2.** Any command or content that matches a blacklist rule or a forbid entry produces exit 2 with a human-readable reason on stderr.

**All other outcomes → exit 0 (fail-open).** This covers:

- Empty or unreadable stdin (`read_to_string` error)
- Malformed or non-JSON stdin
- `tool_name` not recognized as a command tool and not `Write`, `Edit`, or `apply_patch`
- Missing or unreadable config files (`aliases.json`, `forbidden.json`)
- `kubectl config current-context` / `kubectl config view` subprocess failing or not installed
- Unreadable script files referenced in a Bash command
- Any unexpected panic (Rust's default panic handler exits with code 101, but rule-compilation panics are caught at startup via `unwrap_or_else` which also produces a non-zero code — acceptable at init time, not at hook time)

Exit 1 is deliberately avoided. Claude Code treats exit 1 as a hook infrastructure error, which produces a different user experience than an explicit block and may not be consistently handled across versions.

## Alternatives Considered

- **Fail-closed on errors (exit 2 for any error):** Rejected — a misconfigured `kubectl` or a missing `forbidden.json` would lock the entire Claude Code session. The security benefit is minimal: an attacker who can corrupt `rsh`'s config can likely bypass it in other ways.
- **Exit 1 for errors, exit 2 for blocks:** Rejected — surfacing every config read error as a hook failure creates noise and makes the hook feel unreliable.
- **Separate "warn" exit code:** Not available in the current Claude Code protocol; exit 2 is the only signaling code.

## Consequences

- A corrupt or unreadable `forbidden.json` silently degrades to "no forbid checks" rather than blocking all commands. Users who rely on the forbid list for production safety should monitor the config file.
- An absent `kubectl` binary means the implicit-context fallback never fires, so commands without an explicit `--context` flag are not checked against the forbidden cluster list. This is documented in the forbid-system behavior doc.
- The fail-open contract means `rsh` is a best-effort safety layer, not a security boundary. It is designed to prevent *accidental* destructive operations in an AI-agent session, not to be an adversarial security perimeter.
