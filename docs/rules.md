# Blocked commands by tool

`rsh` ships with 45 rules across twelve categories. The tables below list every rule grouped by the binary it targets. Aliases registered via `rsh alias` or detected by `rsh detect-aliases` are covered by the same rules.

## kubectl

| Rule | Blocked command pattern | Why |
|---|---|---|
| `k8s-delete-namespace` | `kubectl delete ns\|namespace` | Deletes namespace and cascades through all its resources |
| `k8s-delete-all` | `kubectl delete <kind> --all` | Deletes all resources of a kind — high blast radius |
| `k8s-delete-crd` | `kubectl delete crd\|customresourcedefinition` | Removes CRD and every instance cluster-wide |
| `k8s-force-delete` | `kubectl delete --force --grace-period=0` | Skips cleanup hooks, can leave orphaned resources |
| `k8s-delete-pv-pvc` | `kubectl delete pv\|pvc\|persistentvolume\|persistentvolumeclaim` | Irreversible storage data loss |
| `k8s-delete-clusterrole` | `kubectl delete clusterrole\|clusterrolebinding` | Risks cluster lockout and broken controllers |
| `k8s-delete-node` | `kubectl delete node` | Evicts all workloads and may exhaust capacity |
| `k8s-delete-workload` | `kubectl delete deployment\|statefulset\|daemonset` (and short forms) | Stops the application |
| `k8s-exec-shell` | `kubectl exec … -- sh\|bash\|zsh\|…` | Interactive shell bypasses every other blacklist rule |
| `k8s-run-privileged` | `kubectl run --privileged` | Near-trivial path to host escape |
| `k8s-debug-node` | `kubectl debug node/<name>` | Mounts host filesystem in a debug pod |
| `k8s-attach` | `kubectl attach <pod>` | Same risk as exec when PID 1 is a shell |
| `k8s-proxy` | `kubectl proxy` | Opens an unauthenticated HTTP proxy to the API |
| `k8s-cp-inbound` | `kubectl cp <local> <pod>:<path>` | Code injection vector (local → pod only) |
| `k8s-cluster-admin-binding` | `kubectl create clusterrolebinding --clusterrole=cluster-admin` | Full privilege escalation |
| `k8s-apply-remote` | `kubectl apply -f http(s)://…` | Supply-chain risk from remote manifests |
| `k8s-drain` | `kubectl drain <node>` | Evicts all pods — potential cluster-wide service disruption |
| `k8s-subprocess-list` | `['kubectl', …, 'delete']` in script/file content | Bypasses command-level checks via subprocess argument lists |
| Forbidden cluster | `--context=<forbidden>` or current context | Blocks any command targeting a cluster added via `rsh forbid cluster` |
| Forbidden namespace | `--namespace=<forbidden>` / `-n <forbidden>` / `-n<forbidden>` or current namespace | Blocks any command targeting a namespace added via `rsh forbid namespace` |

## helm

| Rule | Blocked command pattern | Why |
|---|---|---|
| `helm-uninstall` | `helm uninstall\|delete <release>` | Removes the release and all its resources — possible cascading data loss |
| `helm-subprocess-list` | `['helm', …, 'uninstall'\|'delete']` in script/file content | Bypasses command-level checks via subprocess argument lists |
| Forbidden cluster | `--kube-context=<forbidden>` or current context | Blocks commands targeting a forbidden cluster |
| Forbidden namespace | `--namespace=<forbidden>` / `-n <forbidden>` / `-n<forbidden>` or current namespace | Blocks commands targeting a forbidden namespace |

## docker / docker-compose

| Rule | Blocked command pattern | Why |
|---|---|---|
| `docker-volume-rm` | `docker volume rm\|remove` | Removes named volumes — irreversible data loss |
| `docker-volume-prune` | `docker volume prune` | Removes all unused volumes in bulk |
| `docker-system-prune-risky` | `docker system prune --volumes` / `-a` / `--all` | Deletes volumes and all images — high blast radius |
| `compose-down-volumes` | `docker compose down -v\|--volumes` | Removes all service containers and their volumes |
| `compose-legacy-down-volumes` | `docker-compose down -v\|--volumes` | Same as above for the legacy CLI |
| `compose-rm-volumes` | `docker compose rm -v\|--volumes` | Removes stopped containers and their anonymous volumes |
| `compose-legacy-rm-volumes` | `docker-compose rm -v\|--volumes` | Same as above for the legacy CLI |
| `docker-rm-volumes` | `docker rm -v\|--volumes` | Removes a container and its anonymous volumes |
| `docker-container-prune` | `docker container prune` | Removes all stopped containers in bulk |
| `docker-image-prune` | `docker image prune` | Removes dangling or all unused images |
| `docker-image-rm` | `docker image rm\|remove` | Removes images by name or ID |
| `docker-rmi` | `docker rmi` | Removes images via the legacy command |
| `docker-rm` | `docker rm` | Removes one or more containers |
| `compose-down` | `docker compose down` | Stops and removes all service containers |
| `compose-legacy-down` | `docker-compose down` | Same as above for the legacy CLI |

## SQL clients (any binary)

These rules match SQL keywords regardless of which client (`psql`, `mysql`, `sqlite3`, …) is used. They also fire when the keyword appears in a script file or patch that the model writes.

| Rule | Blocked pattern | Why |
|---|---|---|
| `sql-delete` | `DELETE FROM` | Deletes rows — irreversible without a backup |
| `sql-truncate` | `TRUNCATE [TABLE]` | Removes all rows instantly, no WHERE clause |
| `sql-drop` | `DROP TABLE\|DATABASE\|SCHEMA\|INDEX\|VIEW\|…` | Permanently removes a database object and its data |
| `sql-alter-table` | `ALTER TABLE` | Schema modifications — column drops are irreversible |
| `sql-create-ddl` | `CREATE TABLE\|DATABASE\|SCHEMA` | Creates persistent schema objects |
| Forbidden database | `-h <host>` / `-h<host>` / `--host=<host>` / connection URL | Blocks any SQL client command targeting a host added via `rsh forbid database` |

## rsh (self-protection)

| Rule | Blocked command pattern | Why |
|---|---|---|
| `rsh-self-disable` | `rsh off` / `rsh on` | Agents must not disable or re-enable the security hook |
| `rsh-protect-disable` | `rsh rule disable` | Deactivating rules would allow previously blocked commands through |
| `rsh-protect-forbid-remove` | `rsh forbid remove` | Removing forbid entries would re-allow forbidden clusters/namespaces |
| `rsh-protect-config-access` | Any access to `~/.config/rsh/` | Protects aliases, disabled-rules, and forbid lists from tampering |
| `rsh-guard-flag-file` | Any access to `.rsh-disabled` or `rsh/disabled` | Prevents renaming or deleting the flag files that control hook state |
