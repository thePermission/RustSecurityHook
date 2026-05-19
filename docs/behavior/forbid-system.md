---
title: Forbid System
tags:
  - rsh/system
  - rsh/kubernetes
  - rsh/sql
aliases:
  - forbid
  - forbidden lists
---

# Forbid System — Clusters, Namespaces, and Databases

The forbid system lets you declare specific Kubernetes clusters, namespaces, and database
hosts that rsh should always block, regardless of the individual command's safety.

It is integrated into three checkers: [[checker-kubectl|KubectlChecker]] and
[[checker-helm|HelmChecker]] enforce cluster and namespace forbid lists;
[[checker-fallback|FallbackChecker]] enforces the database forbid list.

## Storage

All forbid entries are stored in a single JSON file:

- **Unix:** `$XDG_CONFIG_HOME/rsh/forbidden.json` (default: `~/.config/rsh/forbidden.json`)
- **Windows:** `%XDG_CONFIG_HOME%\rsh\forbidden.json` (default: `%APPDATA%\rsh\forbidden.json`)

```json
{
  "clusters": ["prod-eu"],
  "namespaces": ["kube-system"],
  "databases": ["prod-db.example.com"]
}
```

Fields that are absent in the file default to `[]` (backwards-compatible with older config files).
If the file exists but cannot be read or parsed, rsh treats the forbid configuration as invalid and blocks matching kubectl, helm, and SQL-client commands until the file is fixed. `rsh list` and `rsh forbid list` print a warning for this state.

## CLI

```sh
# Kubernetes / Helm
rsh forbid cluster <context-name>
rsh forbid namespace <namespace-name>
rsh forbid remove cluster <context-name>
rsh forbid remove namespace <namespace-name>

# SQL
rsh forbid database <hostname>
rsh forbid remove database <hostname>

# Inspect
rsh forbid list
```

All entries are also shown in `rsh list` under the "Forbidden Clusters, Namespaces and Databases" section.

## How Cluster and Namespace Checks Work

When a `kubectl` or `helm` command is intercepted:

1. **Tool identification** — `rsh` tokenizes the command, skips supported wrapper commands and leading environment assignments, and finds the actual `kubectl` or `helm` token. Supported wrappers include `sudo`, `env`, `command`, `builtin`, `nohup`, `time`, `nice`, and `stdbuf`.
2. **Explicit flag** — `rsh` extracts the target only from arguments after the identified tool token. Wrapper flags are ignored:
   - Cluster: `--context=<value>` or `--context <value>` (kubectl); `--kube-context=<value>` or `--kube-context <value>` (helm)
   - Namespace: `--namespace=<value>`, `--namespace <value>`, `-n <value>`, `-n<value>`, or `-n=<value>`
3. If the extracted value matches a forbid entry → **blocked**.
4. **Implicit fallback** — for each target not pinned by an explicit flag, `rsh` queries the live kubeconfig:
   - `kubectl config current-context` for the cluster
   - `kubectl config view --minify -o jsonpath={..namespace}` for the namespace (defaults to `"default"` when unset)
5. If the live value matches → **blocked** (block message includes "(current kubeconfig)" to explain the origin).

The fallback subprocess is only spawned when the corresponding forbid list is non-empty, so the overhead is zero when no clusters or namespaces are configured.

**Alias expansion:** The command token is matched against the canonical binary name and all registered kubectl/helm aliases (see [alias-system.md](alias-system.md)), so `k get pods` is checked the same as `kubectl get pods`. Wrapper commands and inline environment assignments can appear before the tool token.

## How Database Checks Work

When a known SQL client binary appears as the command token (`mysql`, `mariadb`, `psql`, `sqlite3`, `sqlcmd`, `mssql-cli`), `rsh` tries to extract the target hostname from arguments after that client token:

1. **Connection URL** — regex matches `postgresql://`, `postgres://`, `mysql://`, `mariadb://`, `sqlserver://`, or `mssql://` and captures the host segment (user-info stripped).
2. **`-h` / `--host` flag** — space-separated, `=`-separated, and attached short forms (`-hhost`).

If neither yields a hostname, the check is skipped (fail-open). Comparison is case-insensitive exact match.

Wrapper commands and inline environment assignments are supported, so `sudo -u postgres psql ...`, `env PGPASSWORD=x psql ...`, and `PGPASSWORD=x psql ...` are checked the same as direct SQL client invocations. Wrapper flags are ignored when extracting the database host. Registered aliases currently apply to kubectl/helm forbid checks and blacklist rules; database host extraction recognizes the canonical SQL client names listed above.
