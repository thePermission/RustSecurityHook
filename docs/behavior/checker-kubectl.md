# KubectlChecker

`KubectlChecker` handles every `kubectl` command and all registered aliases. It activates when a command segment contains `kubectl` or any known alias.

## Check Pipeline

Two types of check are applied in order:

1. **Regex blacklist** — surface-level pattern matching against 15 kubectl-specific rules
2. **Forbid check** — verifies the target cluster and namespace against configured forbid lists

Either check returning a hit produces a block (exit code 2).

## Regex Blacklist Rules

All kubectl-specific rules use `bin = Some("kubectl")`, so aliases are automatically expanded.

### Destructive operations

| ID | Blocked command | Reason |
|---|---|---|
| `k8s-delete-namespace` | `kubectl delete ns/namespace/namespaces <name>` | Cascades through all resources in the namespace |
| `k8s-delete-all` | `kubectl delete <kind> --all` | Deletes every resource of that kind — high blast radius |
| `k8s-delete-crd` | `kubectl delete crd/crds/customresourcedefinition/customresourcedefinitions <name>` | Removes the CRD and every instance cluster-wide |
| `k8s-force-delete` | `kubectl delete ... --force --grace-period=0` | Bypasses cleanup hooks; can leave orphans and corrupt state |
| `k8s-delete-pv-pvc` | `kubectl delete pv/pvc/persistentvolume/persistentvolumeclaim` | Irreversible storage data loss |
| `k8s-delete-clusterrole` | `kubectl delete clusterrole/clusterrolebinding` | Risks cluster lockout and broken controllers |
| `k8s-delete-node` | `kubectl delete node/nodes <name>` | Evicts all workloads; may exhaust cluster capacity |
| `k8s-delete-workload` | `kubectl delete deployment/deploy/statefulset/sts/daemonset/ds` | Stops the application |

Note: `kubectl delete pod <name>` (single pod) is NOT blocked — single pod deletion is recoverable.

### Pod access

| ID | Blocked command | Reason |
|---|---|---|
| `k8s-exec-shell` | `kubectl exec <pod> -- sh/bash/zsh/ash/dash` | Interactive shell bypasses every other rule |
| `k8s-run-privileged` | `kubectl run --privileged` or `"privileged":true` in `--overrides` | Near-trivial path to host escape |
| `k8s-debug-node` | `kubectl debug node/<name>` | Mounts the host filesystem — full host access |
| `k8s-attach` | `kubectl attach <pod>` | Attaches to PID 1; same risk as exec with a shell |
| `k8s-proxy` | `kubectl proxy` | Opens an unauthenticated HTTP proxy to the Kubernetes API |
| `k8s-cp-inbound` | `kubectl cp <local> <pod>:<remote>` | Copies files into a pod — code injection vector |

Allowed: non-shell exec (`kubectl exec <pod> -- ls`), outbound cp (`<pod>:<remote> <local>`), `kubectl debug <pod>` without `node/`.

### Privilege escalation

| ID | Blocked command | Reason |
|---|---|---|
| `k8s-cluster-admin-binding` | `kubectl create clusterrolebinding ... --clusterrole=cluster-admin` | Grants full cluster privilege |
| `k8s-apply-remote` | `kubectl apply -f https://...` or `--filename=http://...` | Applies an untrusted remote manifest — supply-chain risk |

Allowed: `kubectl apply -f ./local-file.yaml`.

### Service disruption

| ID | Blocked command | Reason |
|---|---|---|
| `k8s-drain` | `kubectl drain <node>` | Evicts all pods from a node — potential cluster-wide service disruption |

## Forbid Check

After the blacklist passes, `KubectlChecker` extracts the target cluster and namespace from the command and checks them against the configured forbid lists. This blocks individually safe commands (e.g., `kubectl get pods`) that target a protected environment.

See [[forbid-system]] for target extraction, kubeconfig fallback behavior, and the CLI.

## Subprocess Bypass

`kubectl` called inside Python/Ruby/Node subprocess argument lists (e.g., `['kubectl', 'delete', 'ns', 'prod']`) is handled by the [[checker-fallback]] module via the `k8s-subprocess-list` rule, not by this checker.

## Aliases

All registered kubectl aliases are expanded automatically via the alias system. See [[alias-system]].

## Disabling Rules

Individual rules can be temporarily disabled:

```sh
rsh rule disable k8s-drain      # allow kubectl drain until re-enabled
rsh rule enable k8s-drain       # restore the block
rsh rule list                   # show all rules with [DISABLED] markers
```

Disabling does not affect the forbid check — only regex rules.
