# ADR 014 — Shell Tokenization and Scoped Target Extraction

**Date:** 2026-05-19  
**Status:** Accepted

## Context

Several checks depend on understanding command tokens rather than raw substrings:

- Script detection must distinguish interpreter flags such as `bash -c` from script file paths.
- Forbid checks must extract `--context`, `--namespace`, and SQL host flags from the actual protected tool invocation.
- Wrapper commands such as `sudo`, `env`, `time`, `nice`, and `stdbuf` can have their own flags that look like protected-tool flags. For example, `sudo -n kubectl get pods` must not be interpreted as `kubectl -n kubectl`.
- Script paths commonly use home-directory syntax such as `~/deploy.sh`, but `std::fs::read_to_string("~/deploy.sh")` treats `~` literally.

The previous lightweight tokenizer handled simple quoting but was not a documented dependency boundary, and forbid flag extraction scanned the whole command string.

## Decision

Use the `shell-words` crate as the primary shell tokenizer. It implements POSIX-like quote removal and word splitting without running a shell. If `shell-words` returns a parse error, `rsh` falls back to the older lightweight tokenizer rather than blocking the tool call; this preserves the hook's fail-open behavior for malformed shell fragments.

For Kubernetes and Helm forbid checks, identify the actual tool token first, then extract explicit target flags only from arguments after that token:

- `kubectl`: `--context`, `--namespace`, `-n`
- `helm`: `--kube-context`, `--namespace`, `-n`

Wrapper commands and leading environment assignments are skipped during tool identification. Wrapper options that consume a following argument are skipped as part of wrapper handling, so their values are not mistaken for the protected command.

For database forbid checks, identify the SQL client token first and extract the host only from arguments after that token. Supported host forms are:

- connection URLs (`postgresql://host/...`, `mysql://host/...`, etc.)
- `-h host`
- `-hhost`
- `--host host`
- `--host=host`

For script file scanning, expand common home-directory forms before reading:

- `~`
- `~/...`
- `$HOME`
- `$HOME/...`
- `${HOME}`
- `${HOME}/...`

If the expanded path cannot be read, try the literal path as a fallback. If both reads fail, keep the existing fail-open behavior and skip that script segment.

## Alternatives Considered

- **Keep the handwritten tokenizer only:** Rejected because mature shell word-splitting already exists and reduces maintenance risk for quoting behavior.
- **Use a full shell parser / AST:** Rejected for now. `rsh` needs conservative tokenization and target extraction, not full command execution semantics. A full parser would add complexity and still would not perform shell expansions safely.
- **Shell out to the user's shell for expansion:** Rejected because executing shell code during a safety hook would introduce side effects and security risk.
- **Scan all flags globally:** Rejected because wrapper flags can collide with protected-tool flags and produce both false positives and false negatives.

## Consequences

- `sudo -n kubectl get pods` no longer treats `kubectl` as a namespace value.
- `sudo -h wrapper-host psql -h prod-db.example.com mydb` checks the SQL client's `-h` value, not the wrapper's `-h` value.
- `bash ~/deploy.sh` is scanned when the home-expanded script path exists.
- General shell expansion remains intentionally unsupported: arbitrary variables, command substitution, arithmetic expansion, and glob expansion are not performed.
- Database forbid checks still recognize canonical SQL client names only; registered aliases currently affect kubectl/helm forbid checks and binary-bound blacklist rules.
