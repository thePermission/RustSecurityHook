# Blocked commands by tool

`rsh` ships with 92 blacklist rules across 28 categories plus 20 secret file rules across five categories. Run `rsh list` to see all active rules, disabled markers, and the current alias map.

Aliases registered via `rsh alias` or detected by `rsh detect-aliases` are covered by all binary-bound blacklist rules.

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
| `k8s-delete-secret` | `kubectl delete secret` | Breaks pods that mount the secret; forces immediate credential rotation |
| `k8s-delete-rolebinding` | `kubectl delete rolebinding` | Removes namespace-scoped RBAC bindings — can break service accounts |
| `k8s-delete-ingress` | `kubectl delete ingress\|ing` | Immediately removes external HTTP routing to the service |
| `k8s-exec-shell` | `kubectl exec … -- sh\|bash\|zsh\|…` | Interactive shell bypasses every other blacklist rule |
| `k8s-run-privileged` | `kubectl run --privileged` | Near-trivial path to host escape |
| `k8s-debug-node` | `kubectl debug node/<name>` | Mounts host filesystem in a debug pod |
| `k8s-attach` | `kubectl attach <pod>` | Same risk as exec when PID 1 is a shell |
| `k8s-proxy` | `kubectl proxy` | Opens an unauthenticated HTTP proxy to the API |
| `k8s-cp-inbound` | `kubectl cp <local> <pod>:<path>` | Code injection vector (local → pod only) |
| `k8s-cluster-admin-binding` | `kubectl create clusterrolebinding --clusterrole=cluster-admin` | Full privilege escalation |
| `k8s-apply-remote` | `kubectl apply -f http(s)://…` | Supply-chain risk from remote manifests |
| `k8s-drain` | `kubectl drain <node>` | Evicts all pods — potential cluster-wide service disruption |
| `k8s-scale-zero` | `kubectl scale … --replicas=0` | Shuts the application down without deleting it |
| `k8s-cordon` | `kubectl cordon <node>` | Marks node unschedulable; new pods cannot land there until uncordoned |
| `k8s-subprocess-list` | `['kubectl', …, 'delete']` in script/file content | Bypasses command-level checks via subprocess argument lists |
| Forbidden cluster | `--context=<forbidden>` or current context | Blocks any command targeting a cluster added via `rsh forbid cluster` |
| Forbidden namespace | `--namespace=<forbidden>` / `-n <forbidden>` or current namespace | Blocks any command targeting a namespace added via `rsh forbid namespace` |

## helm

| Rule | Blocked command pattern | Why |
|---|---|---|
| `helm-uninstall` | `helm uninstall\|delete <release>` | Removes the release and all its resources — possible cascading data loss |
| `helm-subprocess-list` | `['helm', …, 'uninstall'\|'delete']` in script/file content | Bypasses command-level checks via subprocess argument lists |
| Forbidden cluster | `--kube-context=<forbidden>` or current context | Blocks commands targeting a forbidden cluster |
| Forbidden namespace | `--namespace=<forbidden>` / `-n <forbidden>` or current namespace | Blocks commands targeting a forbidden namespace |

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
| `docker-subprocess-list` | `['docker', …, 'rm'\|'rmi'\|'prune'\|'down']` in script/file content | Bypasses command-level checks via subprocess argument lists |

## GitLab CLI (glab)

| Rule | Blocked command pattern | Why |
|---|---|---|
| `glab-repo-delete` | `glab repo\|project delete` | Permanently deletes the GitLab repository/project |
| `glab-release-delete` | `glab release delete` | Deletes a published GitLab release |
| `glab-variable-delete` | `glab variable delete` | Deletes a CI/CD variable — often contains undocumented secrets |
| `glab-repo-members-remove` | `glab repo members remove` | Removes a project member's access — not recoverable without re-invitation |
| `glab-issue-delete` | `glab issue delete` | Hard-deletes an issue (distinct from closing; not recoverable) |
| `glab-label-delete` | `glab label delete` | Permanently deletes a label from the project |
| `glab-subprocess-list` | `['glab', …, 'delete']` in script/file content | Bypasses command-level checks via subprocess argument lists |

## GitHub CLI (gh)

| Rule | Blocked command pattern | Why |
|---|---|---|
| `gh-repo-delete` | `gh repo delete` | Permanently deletes a GitHub repository and all its contents |
| `gh-release-delete` | `gh release delete` | Deletes a published GitHub release |
| `gh-secret-delete` | `gh secret delete` | Deletes a repository or environment secret — often undocumented credentials |
| `gh-variable-delete` | `gh variable delete` | Deletes a GitHub Actions variable |
| `gh-auth-logout` | `gh auth logout` | Logs out the CLI session — breaks the agent's GitHub access mid-task |
| `gh-subprocess-list` | `['gh', …, 'delete']` in script/file content | Bypasses command-level checks via subprocess argument lists |

## Git

| Rule | Blocked command pattern | Why |
|---|---|---|
| `git-force-push` | `git push --force` / `-f` / `--force-with-lease` | Rewrites remote branch history — can destroy other contributors' commits |
| `git-reset-hard` | `git reset --hard` | Discards all uncommitted changes and the index permanently |
| `git-clean` | `git clean -f` / `-fd` / `-fxd` | Permanently deletes untracked files from the working tree |
| `git-branch-force-delete` | `git branch -D` | Force-deletes a branch regardless of merge status — can destroy unmerged commits |
| `git-subprocess-list` | `['git', 'push', …, '--force'\|'-f']` in script/file content | Bypasses command-level checks via subprocess argument lists |

## Terraform

| Rule | Blocked command pattern | Why |
|---|---|---|
| `tf-destroy` | `terraform destroy` / `terraform apply\|plan -destroy` | Destroys all infrastructure resources managed by the current state |
| `tf-workspace-delete` | `terraform workspace delete` | Deletes a Terraform workspace and its associated state |
| `tf-force-unlock` | `terraform force-unlock` | Bypasses the state lock — can corrupt state if another operation is in progress |
| `terraform-subprocess-list` | `['terraform', …, 'destroy']` in script/file content | Bypasses command-level checks via subprocess argument lists |

## AWS CLI

| Rule | Blocked command pattern | Why |
|---|---|---|
| `aws-s3-rm-recursive` | `aws s3 rm … --recursive` | Recursively deletes all objects under an S3 prefix — mass data loss |
| `aws-s3-bucket-delete` | `aws s3 rb` | Deletes an S3 bucket (with `--force` also removes all objects first) |
| `aws-ec2-terminate` | `aws ec2 terminate-instances` | Terminates EC2 instances — cannot be undone |
| `aws-rds-delete` | `aws rds delete-db-instance` | Permanently deletes an RDS database instance |
| `aws-cf-delete-stack` | `aws cloudformation delete-stack` | Deletes a CloudFormation stack and all its managed resources |
| `aws-iam-delete` | `aws iam delete-user\|role\|policy\|group` | Deletes an IAM entity — immediately breaks services that depend on it |
| `aws-subprocess-list` | `['aws', …, 'terminate-instances'\|'delete-db-instance'\|…]` in script/file content | Bypasses command-level checks via subprocess argument lists |

## System

| Rule | Blocked command pattern | Why |
|---|---|---|
| `sys-shutdown-direct` | `shutdown` / `reboot` / `halt` / `poweroff` (at command start or after `sudo`) | Shuts down or reboots the system — terminates the agent session |
| `sys-shutdown-systemctl` | `systemctl poweroff\|reboot\|halt\|shutdown` | Same via systemctl |
| `sys-firewall-flush` | `iptables\|ip6tables -F\|--flush` | Flushes all firewall rules — immediately exposes the system to the network |
| `sys-nft-flush` | `nft flush ruleset` | Removes the entire nftables ruleset at once |

## Redis

These rules match Redis commands regardless of which client invokes them (same approach as SQL). They also fire when the keyword appears in a script file or patch.

| Rule | Blocked pattern | Why |
|---|---|---|
| `redis-flushall` | `FLUSHALL` | Deletes all keys in all Redis databases |
| `redis-flushdb` | `FLUSHDB` | Deletes all keys in the current Redis database |

## Package publishing

| Rule | Blocked command pattern | Why |
|---|---|---|
| `npm-unpublish` | `npm unpublish` | Unpublishes an npm package version — breaks downstream consumers; reversible only within 72 h |
| `cargo-yank` | `cargo yank` | Yanks a crate version from crates.io — new dependents can no longer use that version |

## SQL clients (any binary)

These rules match SQL keywords regardless of which client (`psql`, `mysql`, `sqlite3`, …) is used. They also fire when the keyword appears in a script file or patch that the model writes.

| Rule | Blocked pattern | Why |
|---|---|---|
| `sql-delete` | `DELETE FROM` | Deletes rows — irreversible without a backup |
| `sql-truncate` | `TRUNCATE [TABLE]` | Removes all rows instantly, no WHERE clause |
| `sql-drop` | `DROP TABLE\|DATABASE\|SCHEMA\|INDEX\|VIEW\|…` | Permanently removes a database object and its data |
| `sql-alter-table` | `ALTER TABLE` | Schema modifications — column drops are irreversible |
| `sql-create-ddl` | `CREATE TABLE\|DATABASE\|SCHEMA` | Creates persistent schema objects |
| `sql-drop-role` | `DROP ROLE\|USER` | Removes a database role or user — can lock out applications that rely on that account |
| `sql-grant-all` | `GRANT ALL` | Grants all privileges — privilege escalation at the database layer |
| `sql-revoke-all` | `REVOKE ALL` | Revokes all privileges — can immediately break application database access |
| Forbidden database | `-h <host>` / `--host=<host>` / connection URL | Blocks any SQL client command targeting a host added via `rsh forbid database` |

## rsh (self-protection)

| Rule | Blocked command pattern | Why |
|---|---|---|
| `rsh-self-disable` | `rsh off` / `rsh on` | Agents must not disable or re-enable the security hook |
| `rsh-protect-disable` | `rsh rule disable` | Deactivating rules would allow previously blocked commands through |
| `rsh-protect-allow` | `rsh allow push\|cluster\|namespace\|database` | Prevents lifting forbid/push restrictions — re-allowing targets would bypass user-set protections |
| `rsh-protect-config-access` | Any access to `~/.config/rsh/` | Protects aliases, disabled-rules, and forbid lists from tampering |
| `rsh-guard-flag-file` | Any access to `.rsh-disabled`, `rsh/disabled`, or `.rsh-nopush` | Prevents renaming or deleting the flag files that control hook state |
| `rsh-subprocess-list` | `['rsh', …, 'off'\|'on'\|'allow']` in script/file content | Prevents subprocess-based self-disable bypass |

## Secret file rules

These rules apply to `Read`, `Write`, and `Edit` tool calls (and `Bash` commands that reference a file path). They block access to files that commonly contain credentials or private keys regardless of the directory they live in. Symlinks are resolved before matching so a renamed symlink to `.env` is still caught.

Individual rules can be disabled with `rsh rule disable <id>` (e.g. if you intentionally manage secrets files in your project).

### Secret Files — Environment

| Rule | Matched paths | Why |
|---|---|---|
| `secret-dotenv` | `**/.env`, `**/.env.*`, `**/*.env` | Environment file may contain API keys or passwords |
| `secret-npmrc` | `**/.npmrc` | npm config may contain auth tokens for private registries |
| `secret-pip-conf` | `**/pip.conf`, `**/.pip/pip.conf` | pip config may contain index URLs with embedded credentials |
| `secret-git-credentials` | `**/.git-credentials` | Git credential helper plaintext store |
| `secret-netrc` | `**/.netrc` | FTP/HTTP credentials |
| `secret-htpasswd` | `**/.htpasswd` | Web server password hashes |
| `secret-maven-settings` | `**/settings.xml` | Maven settings may contain Nexus/Artifactory repository credentials |

### Secret Files — Cryptographic Keys

| Rule | Matched paths | Why |
|---|---|---|
| `secret-pem` | `**/*.pem` | PEM file may contain TLS certificate or private key |
| `secret-key-file` | `**/*.key` | Key file may contain a private cryptographic key |
| `secret-p12` | `**/*.p12`, `**/*.pfx` | PKCS#12 key store containing private key and certificate chain |
| `secret-pgp` | `**/*.gpg`, `**/*.asc` | PGP encrypted or signed file |
| `secret-jks` | `**/*.jks`, `**/*.keystore` | Java key store containing private keys and certificates |

### Secret Files — SSH

| Rule | Matched paths | Why |
|---|---|---|
| `secret-ssh-private-key` | `**/id_rsa`, `**/id_ed25519`, `**/id_ecdsa`, `**/id_dsa` | SSH private key |
| `secret-ssh-config` | `**/.ssh/config` | SSH config containing host and identity file paths |

### Secret Files — Cloud

| Rule | Matched paths | Why |
|---|---|---|
| `secret-aws-credentials` | `**/.aws/credentials` | AWS credentials file containing access key ID and secret |
| `secret-gcloud-key` | `**/application_default_credentials.json` | GCP service account key |
| `secret-kubeconfig` | `**/.kube/config` | Kubernetes config with cluster credentials and auth tokens |
| `secret-docker-config` | `**/.docker/config.json` | Docker config with registry auth tokens |
| `secret-vault-token` | `**/.vault-token` | HashiCorp Vault token |

### Secret Files — System

| Rule | Matched paths | Why |
|---|---|---|
| `secret-shadow` | `**/etc/shadow`, `**/etc/master.passwd` | System password hash file |
