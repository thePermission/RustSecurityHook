---
title: HelmChecker
tags:
  - rsh/checker
  - rsh/kubernetes
aliases:
  - helm checker
  - HelmChecker
---

# HelmChecker

`HelmChecker` handles every `helm` command and all registered aliases. It activates when a command segment contains `helm` or any known alias.

## Check Pipeline

Two types of check are applied in order:

1. **Regex blacklist** — surface-level pattern matching against 1 helm-specific rule
2. **Forbid check** — verifies the target cluster and namespace against configured forbid lists

Either check returning a hit produces a block (exit code 2).

## Regex Blacklist Rules

All helm-specific rules use `bin = Some("helm")`, so aliases are automatically expanded.

### Destructive operations

| ID | Blocked command | Reason |
|---|---|---|
| `helm-uninstall` | `helm uninstall <release>` or `helm delete <release>` | Removes a release and all its resources — possible cascading data loss |

Note: `helm install`, `helm upgrade`, `helm list`, `helm get`, `helm status`, and `helm rollback` are NOT blocked.

## Forbid Check

After the blacklist passes, `HelmChecker` extracts the target cluster and namespace from the command and checks them against the configured forbid lists. This blocks individually safe commands (e.g., `helm list`) that target a protected environment.

The forbid extractor identifies the actual helm token first, so wrapper flags before `helm` are not treated as Helm namespace or kube-context flags.

See [[forbid-system]] for target extraction, kubeconfig fallback behavior, and the CLI.

## Subprocess Bypass

`helm` called inside Python/Ruby/Node subprocess argument lists (e.g., `['helm', 'uninstall', 'postgres']`) is handled by the [[checker-fallback]] module via the `helm-subprocess-list` rule, not by this checker.

## Aliases

All registered helm aliases are expanded automatically via the alias system. See [[alias-system]].

## Disabling Rules

Individual rules or all helm rules at once can be temporarily disabled:

```sh
rsh rule disable helm-uninstall      # allow helm uninstall until re-enabled
rsh rule enable helm-uninstall       # restore the block
rsh tool disable helm                # disable all helm rules at once
rsh tool enable helm                 # restore all helm rules
rsh rule list                        # show all rules with [DISABLED] markers
```

Disabling does not affect the forbid check — only regex rules.
