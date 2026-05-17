# ADR 006 — Kubernetes and Helm Initial Blacklist

**Date:** 2026-05-17  
**Status:** Accepted

## Context

`rsh` was built to prevent a Claude Code session from accidentally issuing destructive Kubernetes or Helm commands — the primary pain point that motivated the project. Kubernetes has a large surface area: dozens of resource kinds, multiple access patterns, and privilege-escalation paths that are not obvious from the command syntax alone.

The initial rule set had to balance coverage (catching the highest-risk operations) against false-positive rate (not blocking legitimate operations the model needs to do its job).

## Decision

Eighteen rules were defined across five categories. The categories reflect qualitatively different risk profiles:

**Kubernetes — Destructive (8 rules)**  
Operations that delete cluster resources, potentially with cascading or irreversible effects. Rule of thumb: if the resource cannot be recreated from source code without data loss, it is in this category.

- `k8s-delete-namespace` — entire namespace with all resources
- `k8s-delete-all` — all resources of a kind (`--all` flag)
- `k8s-delete-crd` — CRD plus every instance cluster-wide
- `k8s-force-delete` — `--force --grace-period=0` on any resource
- `k8s-delete-pv-pvc` — PersistentVolumes and PersistentVolumeClaims (storage data)
- `k8s-delete-clusterrole` — RBAC cluster-wide objects (lockout risk)
- `k8s-delete-node` — removes a node, evicts all workloads
- `k8s-delete-workload` — Deployment, StatefulSet, DaemonSet (stops the application)

*Not blocked:* `kubectl delete pod <name>` — a single pod is recreated by its controller; no persistent data is lost.

**Kubernetes — Pod Access (6 rules)**  
Operations that open a direct execution channel into a running container or the host node, bypassing the blacklist entirely once inside.

- `k8s-exec-shell` — `exec` with a shell binary (`sh`, `bash`, `zsh`, `ash`, `dash`)
- `k8s-run-privileged` — `run --privileged` or inline `"privileged": true`
- `k8s-debug-node` — `debug node/<name>` mounts the host filesystem
- `k8s-attach` — attaches to PID 1 of a running pod
- `k8s-proxy` — opens an unauthenticated HTTP proxy to the API server
- `k8s-cp-inbound` — copies local files into a pod (code injection)

*Not blocked:* `kubectl exec <pod> -- <non-shell-command>` (e.g. `cat`, `ls`) and `kubectl cp <pod>:<remote> <local>` (outbound copy).

**Kubernetes — Privilege Escalation (2 rules)**

- `k8s-cluster-admin-binding` — grants `cluster-admin` via ClusterRoleBinding
- `k8s-apply-remote` — applies a manifest fetched over HTTP/HTTPS (supply-chain risk)

*Not blocked:* `kubectl apply -f ./local.yaml` — local manifests are trusted.

**Kubernetes — Service Disruption (1 rule)**

- `k8s-drain` — evicts all pods from a node

*Not blocked:* `kubectl cordon` — marks a node unschedulable but does not evict existing pods; recoverable without downtime.

**Helm (1 rule)**

- `helm-uninstall` — matches both `helm uninstall` and `helm delete`

*Not blocked:* `helm install`, `helm upgrade`, `helm rollback`, `helm list`.

## Alternatives Considered

- **Block all `kubectl delete` commands:** Rejected — `kubectl delete pod <name>` is a routine operation in many debugging workflows. A blanket delete block would generate too many false positives.
- **Block `kubectl apply` unconditionally:** Rejected — applying local manifests is the normal deployment workflow; blocking it would make the hook unusable for development tasks.
- **Block `kubectl cordon`:** Rejected — cordoning is reversible (`kubectl uncordon`) and does not immediately affect running workloads.
- **Block `kubectl exec` unconditionally:** Rejected — `exec` with non-shell commands (e.g. `kubectl exec pod -- cat /etc/config`) is legitimate for debugging. Only shell binaries as the entry point are blocked.

## Consequences

- Sub-patterns follow the convention `\s[^|;&\n]*?\bVERB\b` to allow flags between the binary and the verb without crossing shell separators. This means `kubectl --context=x delete ns prod` is correctly blocked.
- The `k8s-exec-shell` rule requires the shell binary to appear after `--` (the argument separator). This prevents false positives on pod names that happen to contain `bash` or `sh`.
- The `k8s-run-privileged` rule uses a raw-string double-quote to match the JSON override form `"privileged": true`. It does not match all possible override schemas (e.g. YAML). Accepted limitation.
