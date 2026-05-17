# Kubernetes and Helm Blocking Rules

`rsh` blocks destructive, access-escalating, and service-disrupting kubectl and helm commands. Rules use `bin = Some("kubectl")` or `bin = Some("helm")`, so any registered alias (e.g. `k → kubectl`) is automatically included.

Two additional `bin = None` rules catch the same operations when the binary and verb appear as a Python/Ruby/Node **subprocess argument list** rather than a shell string.

## Kubernetes — Destructive

These rules block operations that delete cluster resources permanently or with a high blast radius.

| ID | Blocked command | Reason |
|---|---|---|
| `k8s-delete-namespace` | `kubectl delete ns/namespace/namespaces <name>` | Cascades through all resources in the namespace |
| `k8s-delete-all` | `kubectl delete <kind> --all` | Deletes every resource of that kind |
| `k8s-delete-crd` | `kubectl delete crd/customresourcedefinition <name>` | Removes the CRD and every instance cluster-wide |
| `k8s-force-delete` | `kubectl delete ... --force --grace-period=0` | Bypasses cleanup hooks; can leave orphans |
| `k8s-delete-pv-pvc` | `kubectl delete pv/pvc/persistentvolume/persistentvolumeclaim` | Irreversible storage data loss |
| `k8s-delete-clusterrole` | `kubectl delete clusterrole/clusterrolebinding` | Risks cluster lockout and broken controllers |
| `k8s-delete-node` | `kubectl delete node/nodes <name>` | Evicts all workloads; may exhaust cluster capacity |
| `k8s-delete-workload` | `kubectl delete deployment/statefulset/daemonset` (and short aliases) | Stops the application |

**Not blocked:** `kubectl delete pod <name>` — single pod deletion is recoverable (the controller reschedules it).

## Kubernetes — Pod Access

These rules block operations that grant direct process-level or filesystem access to a running container or the host.

| ID | Blocked command | Reason |
|---|---|---|
| `k8s-exec-shell` | `kubectl exec <pod> -- sh/bash/zsh/ash/dash` | Interactive shell bypasses every other blacklist rule |
| `k8s-run-privileged` | `kubectl run --privileged` or with `"privileged": true` in `--overrides` | Near-trivial path to host escape |
| `k8s-debug-node` | `kubectl debug node/<name>` | Mounts the host filesystem in a debug pod — full host access |
| `k8s-attach` | `kubectl attach <pod>` | Attaches to PID 1; same risk as exec when PID 1 is a shell |
| `k8s-proxy` | `kubectl proxy` | Opens an unauthenticated HTTP proxy to the Kubernetes API |
| `k8s-cp-inbound` | `kubectl cp <local> <pod>:<remote>` | Copies files into a pod — code injection vector |

**Not blocked:**
- `kubectl exec <pod> -- ls` or any non-shell command — exec with read-only tools is allowed.
- `kubectl cp <pod>:<remote> <local>` (pod → local direction) — reading files out is allowed.
- `kubectl debug <pod>` (pod debug without `node/`) — does not mount the host filesystem.

## Kubernetes — Privilege Escalation

| ID | Blocked command | Reason |
|---|---|---|
| `k8s-cluster-admin-binding` | `kubectl create clusterrolebinding ... --clusterrole=cluster-admin` | Grants full cluster privilege |
| `k8s-apply-remote` | `kubectl apply -f https://...` or `--filename=http://...` | Applies an untrusted remote manifest — supply-chain risk |

**Not blocked:** `kubectl apply -f ./local-file.yaml` — local manifests are allowed.

## Kubernetes — Service Disruption

| ID | Blocked command | Reason |
|---|---|---|
| `k8s-drain` | `kubectl drain <node>` | Evicts all pods from a node — potential cluster-wide disruption |

## Helm

| ID | Blocked command | Reason |
|---|---|---|
| `helm-uninstall` | `helm uninstall <release>` or `helm delete <release>` | Removes a release and all its resources — possible cascading data loss |

**Not blocked:** `helm install`, `helm upgrade`, `helm list`, `helm rollback` — non-destructive operations.

## Subprocess List Bypass

These two `bin = None` rules close a bypass where kubectl/helm calls appear as Python (or Ruby/Node) subprocess argument **lists** rather than shell strings. The binary-bound rules above do not fire in this case because the binary and verb are quoted list elements, not a shell command.

| ID | Blocked pattern | Example |
|---|---|---|
| `k8s-subprocess-list` | `['kubectl', ..., 'delete']` in any subprocess call | `subprocess.run(['kubectl', 'delete', 'ns', 'prod'])` |
| `helm-subprocess-list` | `['helm', ..., 'uninstall'/'delete']` in any subprocess call | `subprocess.run(['helm', 'uninstall', 'app'])` |

Both single-quoted and double-quoted list forms are matched. Non-destructive calls (`['kubectl', 'get', 'pods']`) are not blocked.

## Disabling individual rules

Any rule can be temporarily disabled without removing it from the codebase:

```sh
rsh rule disable k8s-drain    # allow kubectl drain until re-enabled
rsh rule enable k8s-drain     # restore the rule
rsh rule list                 # show all rules with [DISABLED] marker
```

Disabled rules are stored in `~/.config/rsh/disabled-rules.json` and persist across sessions.
