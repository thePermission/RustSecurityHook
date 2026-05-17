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

1. **Explicit flag** — `rsh` extracts the target from the command line:
   - Cluster: `--context=<value>` or `--context <value>` (kubectl); `--kube-context=<value>` (helm)
   - Namespace: `--namespace=<value>`, `--namespace <value>`, or `-n <value>`
2. If the extracted value matches a forbid entry → **blocked**.
3. **Implicit fallback** — if the flag is absent, `rsh` queries the live kubeconfig:
   - `kubectl config current-context` for the cluster
   - `kubectl config view --minify -o jsonpath={..namespace}` for the namespace (defaults to `"default"` when unset)
4. If the live value matches → **blocked** (block message includes "(current kubeconfig)" to explain the origin).

The fallback subprocess is only spawned when the corresponding forbid list is non-empty, so the overhead is zero when no clusters or namespaces are configured.

**Alias expansion:** The first token of the command is matched against the canonical binary name and all registered aliases (see [alias-system.md](alias-system.md)), so `k get pods` is checked the same as `kubectl get pods`.

## How Database Checks Work

When a known SQL client binary is the first token of a command (`mysql`, `mariadb`, `psql`, `sqlite3`, `sqlcmd`, `mssql-cli`), `rsh` tries to extract the target hostname:

1. **Connection URL** — regex matches `postgresql://`, `postgres://`, `mysql://`, `mariadb://`, `sqlserver://`, or `mssql://` and captures the host segment (user-info stripped).
2. **`-h` / `--host` flag** — both space-separated and `=`-separated forms.

If neither yields a hostname, the check is skipped (fail-open). Comparison is case-insensitive exact match.

**Known limitation:** `env PGPASSWORD=x psql ...` and inline variable assignments (`PGPASSWORD=x psql ...`) bypass the database check because the first token is not the SQL client binary. This mirrors the same bypass in the kubectl/helm check.

