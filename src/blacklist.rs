use crate::aliases::{self, ALIASES};
use crate::shell;
use regex::Regex;
use std::sync::LazyLock;

pub struct Rule {
    pub id: &'static str,
    pub category: &'static str,
    pub reason: &'static str,
    pub bin: Option<&'static str>,
    /// Sub-pattern as written in `RAW_RULES` (without the binary-name prefix).
    #[allow(dead_code)]
    pub sub_pattern: &'static str,
    /// Fully assembled regex including expanded alias alternation, if any.
    pub effective_pattern: String,
    regex: Regex,
}

pub struct Hit {
    pub id: &'static str,
    pub reason: &'static str,
}

/// `(id, category, bin, sub_pattern, reason)`
/// - `category` groups related rules in `rsh list` output.
/// - If `bin` is `Some(name)`, the regex is built as
///   `\b(?:name|alias1|alias2|...)\b<sub_pattern>` using aliases loaded
///   from the user's alias config.
/// - If `bin` is `None`, the sub-pattern is used as-is.
const RAW_RULES: &[(&str, &str, Option<&str>, &str, &str)] = &[
    // ---- Kubernetes — Destructive --------------------------------------
    (
        "k8s-delete-namespace",
        "Kubernetes — Destructive",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdelete\s+(ns|namespace|namespaces)\b",
        "Deletes a Kubernetes namespace and cascades through all of its resources",
    ),
    (
        "k8s-delete-all",
        "Kubernetes — Destructive",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdelete\s+\S+[^|;&\n]*?--all\b",
        "Deletes all resources of a kind — high blast radius",
    ),
    (
        "k8s-delete-crd",
        "Kubernetes — Destructive",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdelete\s+(crd|crds|customresourcedefinition|customresourcedefinitions)\b",
        "Deletes a CustomResourceDefinition and every instance of it cluster-wide",
    ),
    (
        "k8s-force-delete",
        "Kubernetes — Destructive",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdelete\b(?:[^|;&\n]*--force\b[^|;&\n]*--grace-period(?:=|\s+)0|[^|;&\n]*--grace-period(?:=|\s+)0\b[^|;&\n]*--force)",
        "Force-deletes a resource without cleanup hooks; can leave orphans and corrupt state",
    ),
    (
        "k8s-delete-pv-pvc",
        "Kubernetes — Destructive",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdelete\s+(pv|persistentvolume|persistentvolumes|pvc|persistentvolumeclaim|persistentvolumeclaims)\b",
        "Deletes PersistentVolumes or PersistentVolumeClaims — irreversible storage data loss",
    ),
    (
        "k8s-delete-clusterrole",
        "Kubernetes — Destructive",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdelete\s+(clusterrole|clusterrolebinding)s?\b",
        "Deletes cluster-wide RBAC objects — risks cluster lockout and broken controllers",
    ),
    (
        "k8s-delete-node",
        "Kubernetes — Destructive",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdelete\s+nodes?\b",
        "Removes a node from the cluster — evicts all workloads and may exhaust capacity",
    ),
    (
        "k8s-delete-workload",
        "Kubernetes — Destructive",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdelete\s+(deployment|deployments|deploy|statefulset|statefulsets|sts|daemonset|daemonsets|ds)\b",
        "Deletes a workload controller (Deployment/StatefulSet/DaemonSet) — stops the application",
    ),
    // ---- Kubernetes — Pod Access ---------------------------------------
    (
        "k8s-exec-shell",
        "Kubernetes — Pod Access",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bexec\b[^|;&\n]*?\s--\s+(?:/(?:usr/)?bin/)?(?:sh|bash|zsh|ash|dash)\b",
        "Interactive shell in a container — bypasses every other blacklist rule",
    ),
    (
        "k8s-run-privileged",
        "Kubernetes — Pod Access",
        Some("kubectl"),
        r#"\s[^|;&\n]*?\brun\b[^|;&\n]*?(?:--privileged\b|"privileged"\s*:\s*true)"#,
        "Spawns a privileged pod — near-trivial path to host escape",
    ),
    (
        "k8s-debug-node",
        "Kubernetes — Pod Access",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdebug\s+node/\S+",
        "Mounts host filesystem in a debug pod — full host access",
    ),
    (
        "k8s-attach",
        "Kubernetes — Pod Access",
        Some("kubectl"),
        r"\s[^|;&\n]*?\battach\s+\S+",
        "Attaches to PID 1 of a running pod — same risk as exec when PID 1 is a shell",
    ),
    (
        "k8s-proxy",
        "Kubernetes — Pod Access",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bproxy\b",
        "Opens an unauthenticated HTTP proxy to the Kubernetes API",
    ),
    (
        "k8s-cp-inbound",
        "Kubernetes — Pod Access",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bcp\b[^|;&\n]*?\s+[^\s:|;&\n]+\s+[^\s|;&\n]*:[^\s|;&\n]+",
        "Copies local files into a pod (local → pod) — code injection vector",
    ),
    // ---- Kubernetes — Privilege Escalation -----------------------------
    (
        "k8s-cluster-admin-binding",
        "Kubernetes — Privilege Escalation",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bcreate\s+clusterrolebinding\b[^|;&\n]*?--clusterrole(?:=|\s+)cluster-admin\b",
        "Grants cluster-admin via ClusterRoleBinding — full privilege escalation",
    ),
    (
        "k8s-apply-remote",
        "Kubernetes — Privilege Escalation",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bapply\b[^|;&\n]*?(?:-f|--filename)[=\s]+https?://",
        "Applies a manifest fetched over the network — supply-chain risk",
    ),
    // ---- Kubernetes — Service Disruption -------------------------------
    (
        "k8s-drain",
        "Kubernetes — Service Disruption",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdrain\s+\S+",
        "Evicts all pods from a node — potential cluster-wide service disruption",
    ),
    // ---- Kubernetes — Additional Destructive / Service Disruption ---------
    (
        "k8s-delete-secret",
        "Kubernetes — Destructive",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdelete\s+secrets?\b",
        "Deletes a Kubernetes Secret — breaks pods that mount it and forces immediate credential rotation",
    ),
    (
        "k8s-delete-rolebinding",
        "Kubernetes — Destructive",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdelete\s+rolebindings?\b",
        "Deletes namespace-scoped RBAC bindings — can break application service accounts immediately",
    ),
    (
        "k8s-delete-ingress",
        "Kubernetes — Service Disruption",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdelete\s+(?:ingress|ingresses|ing)\b",
        "Deletes an Ingress — immediately removes external HTTP routing to the service",
    ),
    (
        "k8s-scale-zero",
        "Kubernetes — Service Disruption",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bscale\b[^|;&\n]*?--replicas(?:=|\s+)0\b",
        "Scales a workload to zero replicas — shuts down the application without deleting it",
    ),
    (
        "k8s-cordon",
        "Kubernetes — Service Disruption",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bcordon\s+\S+",
        "Marks a node unschedulable — new pods cannot be placed there until explicitly uncordoned",
    ),
    // ---- Helm ----------------------------------------------------------
    (
        "helm-uninstall",
        "Helm",
        Some("helm"),
        r"\s[^|;&\n]*?\b(uninstall|delete)\s+\S+",
        "Removes a Helm release and all its resources — possible cascading data loss",
    ),
    // ---- Subprocess list bypass ----------------------------------------
    // These rules catch the pattern `['kubectl', 'delete', ...]` (and the
    // helm equivalent) that appears in Python/Ruby/Node subprocess calls
    // where the binary and arguments are passed as a list rather than a
    // shell string.  Because the binary and verb appear as quoted list
    // elements, the command-level regex (which requires `kubectl\s`) does
    // not fire.  `bin = None` so the pattern is matched against the full
    // command / file content regardless of which outer program is used.
    (
        "k8s-subprocess-list",
        "Kubernetes — Subprocess Bypass",
        None,
        r#"\[['"]kubectl['"]\s*(?:,\s*['"][^'"]*['"]\s*)*,\s*['"]delete['"]"#,
        "Kubectl delete in a subprocess argument list — bypasses command-level pattern checks",
    ),
    (
        "helm-subprocess-list",
        "Helm — Subprocess Bypass",
        None,
        r#"\[['"]helm['"]\s*(?:,\s*['"][^'"]*['"]\s*)*,\s*['"](?:uninstall|delete)['"]"#,
        "Helm uninstall/delete in a subprocess argument list — bypasses command-level pattern checks",
    ),
    (
        "glab-subprocess-list",
        "GitLab CLI — Subprocess Bypass",
        None,
        r#"\[['"]glab['"]\s*(?:,\s*['"][^'"]*['"]\s*)*,\s*['"]delete['"]"#,
        "glab delete in a subprocess argument list — bypasses command-level pattern checks",
    ),
    (
        "docker-subprocess-list",
        "Docker — Subprocess Bypass",
        None,
        r#"\[['"]docker['"]\s*(?:,\s*['"][^'"]*['"]\s*)*,\s*['"](?:rm|rmi|prune|down)['"]"#,
        "Docker destructive command in a subprocess argument list — bypasses command-level pattern checks",
    ),
    (
        "rsh-subprocess-list",
        "rsh Self-Protection",
        None,
        r#"\[['"]rsh['"]\s*(?:,\s*['"][^'"]*['"]\s*)*,\s*['"](?:off|on|allow)['"]"#,
        "rsh off/on/allow in a subprocess argument list — bypasses command-level self-disable protection",
    ),
    // ---- SQL — Destructive DML ------------------------------------
    // NOTE: These rules use `bin = None` so the SQL keyword check applies to any
    // Bash command regardless of the executing program. This intentionally blocks
    // `grep "DROP TABLE" logs.txt` and similar read-only uses — acceptable
    // trade-off for an AI-agent security hook where exhaustive SQL coverage matters
    // more than avoiding grep false positives.
    (
        "sql-delete",
        "SQL — Destructive DML",
        None,
        r"(?i)\bDELETE\s+FROM\b",
        "Deletes rows from a database table — irreversible without a backup",
    ),
    (
        "sql-truncate",
        "SQL — Destructive DML",
        None,
        r"(?i)\bTRUNCATE(?:\s+TABLE)?\s",
        "Removes all rows from a table instantly — no WHERE clause, no rollback without a transaction",
    ),
    // ---- SQL — Destructive DDL ------------------------------------
    (
        "sql-drop",
        "SQL — Destructive DDL",
        None,
        r"(?i)\bDROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|TRIGGER|FUNCTION|PROCEDURE)\b",
        "Permanently removes a database object and all its data",
    ),
    (
        "sql-alter-table",
        "SQL — Destructive DDL",
        None,
        r"(?i)\bALTER\s+TABLE\b",
        "Modifies the schema of a table — column drops are irreversible",
    ),
    (
        "sql-create-ddl",
        "SQL — Destructive DDL",
        None,
        r"(?i)\bCREATE\s+(?:TABLE|DATABASE|SCHEMA)\b",
        "Creates a new database object — can permanently alter the schema",
    ),
    // ---- SQL — Privilege Escalation / Role Management -----------------
    (
        "sql-drop-role",
        "SQL — Destructive DDL",
        None,
        r"(?i)\bDROP\s+(?:ROLE|USER)\b",
        "Removes a database role or user — can lock out applications that rely on that account",
    ),
    (
        "sql-grant-all",
        "SQL — Privilege Escalation",
        None,
        r"(?i)\bGRANT\s+ALL\b",
        "Grants all privileges to a role — privilege escalation at the database layer",
    ),
    (
        "sql-revoke-all",
        "SQL — Privilege Escalation",
        None,
        r"(?i)\bREVOKE\s+ALL\b",
        "Revokes all privileges from a role — can immediately break application database access",
    ),
    // ---- Docker — Volume Destruction ----------------------------------
    (
        "docker-volume-rm",
        "Docker — Volume Destruction",
        Some("docker"),
        r"\s[^|;&\n]*?\bvolume\s+(?:rm|remove)\b",
        "Removes named Docker volumes — irreversible data loss",
    ),
    (
        "docker-volume-prune",
        "Docker — Volume Destruction",
        Some("docker"),
        r"\s[^|;&\n]*?\bvolume\s+prune\b",
        "Removes all unused Docker volumes — bulk irreversible data loss",
    ),
    (
        "docker-system-prune-risky",
        "Docker — Volume Destruction",
        Some("docker"),
        r"\s[^|;&\n]*?\bsystem\s+prune\b[^|;&\n]*?(?:--volumes\b|--all\b|-[a-zA-Z]*a[a-zA-Z]*(?:\s|$))",
        "system prune with --volumes or -a/--all deletes volumes and all images — high blast radius",
    ),
    (
        "compose-down-volumes",
        "Docker — Volume Destruction",
        Some("docker"),
        r"\s[^|;&\n]*?\bcompose\b[^|;&\n]*?\sdown\b[^|;&\n]*?(?:--volumes\b|-[a-zA-Z]*v[a-zA-Z]*(?:\s|$))",
        "compose down -v removes all service containers and their volumes",
    ),
    (
        "compose-legacy-down-volumes",
        "Docker — Volume Destruction",
        Some("docker-compose"),
        r"[^|;&\n]*?\sdown\b[^|;&\n]*?(?:--volumes\b|-[a-zA-Z]*v[a-zA-Z]*(?:\s|$))",
        "docker-compose down -v removes all service containers and their volumes",
    ),
    (
        "compose-rm-volumes",
        "Docker — Volume Destruction",
        Some("docker"),
        r"\s[^|;&\n]*?\bcompose\b[^|;&\n]*?\brm\b[^|;&\n]*?(?:--volumes\b|-[a-zA-Z]*v[a-zA-Z]*(?:\s|$))",
        "compose rm -v removes stopped service containers and their anonymous volumes",
    ),
    (
        "compose-legacy-rm-volumes",
        "Docker — Volume Destruction",
        Some("docker-compose"),
        r"\s[^|;&\n]*?\brm\b[^|;&\n]*?(?:--volumes\b|-[a-zA-Z]*v[a-zA-Z]*(?:\s|$))",
        "docker-compose rm -v removes stopped service containers and their anonymous volumes",
    ),
    (
        "docker-rm-volumes",
        "Docker — Volume Destruction",
        Some("docker"),
        r"\s[^|;&\n]*?\brm\b[^|;&\n]*?(?:--volumes\b|-[a-zA-Z]*v[a-zA-Z]*(?:\s|$))",
        "Removes container and its anonymous volumes (-v) — irreversible data loss",
    ),
    // ---- Docker — Container/Image Cleanup -----------------------------
    (
        "docker-container-prune",
        "Docker — Container/Image Cleanup",
        Some("docker"),
        r"\s[^|;&\n]*?\bcontainer\s+prune\b",
        "Removes all stopped containers in bulk",
    ),
    (
        "docker-image-prune",
        "Docker — Container/Image Cleanup",
        Some("docker"),
        r"\s[^|;&\n]*?\bimage\s+prune\b",
        "Removes dangling or all unused images",
    ),
    (
        "docker-image-rm",
        "Docker — Container/Image Cleanup",
        Some("docker"),
        r"\s[^|;&\n]*?\bimage\s+(?:rm|remove)\b",
        "Removes images by name or ID",
    ),
    (
        "docker-rmi",
        "Docker — Container/Image Cleanup",
        Some("docker"),
        r"\s[^|;&\n]*?\brmi\b\s+\S",
        "Removes images (legacy rmi command)",
    ),
    (
        "docker-rm",
        "Docker — Container/Image Cleanup",
        Some("docker"),
        r"\s+rm\b\s+\S",
        "Removes one or more containers",
    ),
    (
        "compose-down",
        "Docker — Container/Image Cleanup",
        Some("docker"),
        r"\s[^|;&\n]*?\bcompose\b[^|;&\n]*?\sdown\b",
        "Stops and removes all service containers (volumes kept without -v)",
    ),
    (
        "compose-legacy-down",
        "Docker — Container/Image Cleanup",
        Some("docker-compose"),
        r"[^|;&\n]*?\sdown\b",
        "Stops and removes all service containers (volumes kept without -v)",
    ),
    // ---- GitLab CLI — Destructive -----------------------------------------
    (
        "glab-repo-delete",
        "GitLab CLI — Destructive",
        Some("glab"),
        r"\s[^|;&\n]*?\b(?:repo|project)\s+delete\b",
        "Deletes the entire GitLab repository/project — irreversible",
    ),
    (
        "glab-release-delete",
        "GitLab CLI — Destructive",
        Some("glab"),
        r"\s[^|;&\n]*?\brelease\s+delete\b",
        "Deletes a published GitLab release",
    ),
    (
        "glab-variable-delete",
        "GitLab CLI — Destructive",
        Some("glab"),
        r"\s[^|;&\n]*?\bvariable\s+delete\b",
        "Deletes a CI/CD variable — often contains undocumented secrets",
    ),
    (
        "glab-repo-members-remove",
        "GitLab CLI — Destructive",
        Some("glab"),
        r"\s[^|;&\n]*?\brepo\s+members\s+remove\b",
        "Removes a project member's access — irreversible without re-invitation",
    ),
    (
        "glab-issue-delete",
        "GitLab CLI — Destructive",
        Some("glab"),
        r"\s[^|;&\n]*?\bissue\s+delete\b",
        "Hard-deletes an issue — distinct from closing, not recoverable",
    ),
    (
        "glab-label-delete",
        "GitLab CLI — Destructive",
        Some("glab"),
        r"\s[^|;&\n]*?\blabel\s+delete\b",
        "Permanently deletes a label from the project",
    ),
    // ---- Git — Destructive ---------------------------------------------
    (
        "git-force-push",
        "Git — Destructive",
        Some("git"),
        r"\s[^|;&\n]*?\bpush\b[^|;&\n]*?(?:--force\b|--force-with-lease\b|-[a-zA-Z]*f[a-zA-Z]*(?:\s|$))",
        "Force-pushes to a remote branch — rewrites shared history and can destroy others' commits",
    ),
    (
        "git-reset-hard",
        "Git — Destructive",
        Some("git"),
        r"\s[^|;&\n]*?\breset\b[^|;&\n]*?--hard\b",
        "Resets the working tree and index to a commit — all uncommitted changes are permanently lost",
    ),
    (
        "git-clean",
        "Git — Destructive",
        Some("git"),
        r"\s[^|;&\n]*?\bclean\b[^|;&\n]*?-[a-zA-Z]*f[a-zA-Z]*",
        "Permanently deletes untracked files from the working tree",
    ),
    (
        "git-branch-force-delete",
        "Git — Destructive",
        Some("git"),
        r"\s[^|;&\n]*?\bbranch\b[^|;&\n]*?-[a-zA-Z]*D[a-zA-Z]*(?:\s|$)",
        "Force-deletes a branch regardless of merge status — can destroy unmerged commits",
    ),
    // ---- GitHub CLI — Destructive --------------------------------------
    (
        "gh-repo-delete",
        "GitHub CLI — Destructive",
        Some("gh"),
        r"\s[^|;&\n]*?\brepo\s+delete\b",
        "Permanently deletes a GitHub repository and all its contents",
    ),
    (
        "gh-release-delete",
        "GitHub CLI — Destructive",
        Some("gh"),
        r"\s[^|;&\n]*?\brelease\s+delete\b",
        "Deletes a published GitHub release",
    ),
    (
        "gh-secret-delete",
        "GitHub CLI — Destructive",
        Some("gh"),
        r"\s[^|;&\n]*?\bsecret\s+delete\b",
        "Deletes a repository or environment secret — often contains undocumented credentials",
    ),
    (
        "gh-variable-delete",
        "GitHub CLI — Destructive",
        Some("gh"),
        r"\s[^|;&\n]*?\bvariable\s+delete\b",
        "Deletes a GitHub Actions variable",
    ),
    (
        "gh-auth-logout",
        "GitHub CLI — Destructive",
        Some("gh"),
        r"\s[^|;&\n]*?\bauth\s+logout\b",
        "Logs out the GitHub CLI session — breaks the agent's GitHub access mid-task",
    ),
    // ---- Terraform — Destructive ---------------------------------------
    (
        "tf-destroy",
        "Terraform — Destructive",
        Some("terraform"),
        r"\s[^|;&\n]*?\bdestroy\b",
        "Destroys all infrastructure resources managed by the current state — irreversible without a state backup",
    ),
    (
        "tf-workspace-delete",
        "Terraform — Destructive",
        Some("terraform"),
        r"\s[^|;&\n]*?\bworkspace\s+delete\b",
        "Deletes a Terraform workspace and its associated state",
    ),
    (
        "tf-force-unlock",
        "Terraform — Destructive",
        Some("terraform"),
        r"\s[^|;&\n]*?\bforce-unlock\b",
        "Bypasses the Terraform state lock — can corrupt state if another operation is in progress",
    ),
    // ---- AWS — Destructive ---------------------------------------------
    (
        "aws-s3-rm-recursive",
        "AWS — Destructive",
        Some("aws"),
        r"\s[^|;&\n]*?\bs3\b[^|;&\n]*?\brm\b[^|;&\n]*?--recursive\b",
        "Recursively deletes all objects under an S3 prefix — irreversible mass data loss",
    ),
    (
        "aws-s3-bucket-delete",
        "AWS — Destructive",
        Some("aws"),
        r"\s[^|;&\n]*?\bs3\b[^|;&\n]*?\brb\b",
        "Deletes an S3 bucket — with --force removes all objects first",
    ),
    (
        "aws-ec2-terminate",
        "AWS — Destructive",
        Some("aws"),
        r"\s[^|;&\n]*?\bec2\b[^|;&\n]*?\bterminate-instances\b",
        "Terminates EC2 instances — cannot be undone",
    ),
    (
        "aws-rds-delete",
        "AWS — Destructive",
        Some("aws"),
        r"\s[^|;&\n]*?\brds\b[^|;&\n]*?\bdelete-db-instance\b",
        "Permanently deletes an RDS database instance",
    ),
    (
        "aws-cf-delete-stack",
        "AWS — Destructive",
        Some("aws"),
        r"\s[^|;&\n]*?\bcloudformation\b[^|;&\n]*?\bdelete-stack\b",
        "Deletes a CloudFormation stack and all its managed resources",
    ),
    (
        "aws-iam-delete",
        "AWS — Destructive",
        Some("aws"),
        r"\s[^|;&\n]*?\biam\b[^|;&\n]*?\bdelete-(?:user|role|policy|group)\b",
        "Deletes an IAM entity — immediately removes access for services that depend on it",
    ),
    // ---- System — Shutdown & Firewall ----------------------------------
    (
        "sys-shutdown-direct",
        "System — Shutdown",
        None,
        r"(?:^|\bsudo\s+)(?:shutdown|poweroff|halt|reboot)\b",
        "Shuts down or reboots the system — terminates the agent session and all running services",
    ),
    (
        "sys-shutdown-systemctl",
        "System — Shutdown",
        Some("systemctl"),
        r"\s[^|;&\n]*?\b(?:poweroff|reboot|halt|shutdown)\b",
        "Shuts down or reboots the system via systemctl — terminates the agent session",
    ),
    (
        "sys-firewall-flush",
        "System — Firewall",
        None,
        r"\b(?:iptables|ip6tables)\b[^|;&\n]*?(?:-F\b|--flush\b)",
        "Flushes all iptables firewall rules — immediately exposes the system to the network",
    ),
    (
        "sys-nft-flush",
        "System — Firewall",
        Some("nft"),
        r"\s[^|;&\n]*?\bflush\s+ruleset\b",
        "Flushes the entire nftables ruleset — removes all firewall rules immediately",
    ),
    // ---- Redis — Destructive -------------------------------------------
    (
        "redis-flushall",
        "Redis — Destructive",
        None,
        r"(?i)\bFLUSHALL\b",
        "Deletes all keys in all Redis databases",
    ),
    (
        "redis-flushdb",
        "Redis — Destructive",
        None,
        r"(?i)\bFLUSHDB\b",
        "Deletes all keys in the current Redis database",
    ),
    // ---- Package Publishing — Irreversible -----------------------------
    (
        "npm-unpublish",
        "Package Publishing — Irreversible",
        Some("npm"),
        r"\s[^|;&\n]*?\bunpublish\b",
        "Unpublishes an npm package version — breaks downstream consumers; limited to 72 h after publish",
    ),
    (
        "cargo-yank",
        "Package Publishing — Irreversible",
        Some("cargo"),
        r"\s[^|;&\n]*?\byank\b",
        "Yanks a crate version from crates.io — new dependents can no longer use that version (use cargo yank --undo manually to reverse)",
    ),
    // ---- Subprocess list bypass — new tools ----------------------------
    (
        "git-subprocess-list",
        "Git — Subprocess Bypass",
        None,
        r#"\[['"]git['"]\s*,\s*['"]push['"](?:\s*,\s*['"][^'"]*['"]\s*)*,\s*['"](?:--force|-f|--force-with-lease)['"]"#,
        "git force-push in a subprocess argument list — bypasses command-level pattern checks",
    ),
    (
        "gh-subprocess-list",
        "GitHub CLI — Subprocess Bypass",
        None,
        r#"\[['"]gh['"]\s*(?:,\s*['"][^'"]*['"]\s*)*,\s*['"]delete['"]"#,
        "gh delete in a subprocess argument list — bypasses command-level pattern checks",
    ),
    (
        "terraform-subprocess-list",
        "Terraform — Subprocess Bypass",
        None,
        r#"\[['"]terraform['"]\s*(?:,\s*['"][^'"]*['"]\s*)*,\s*['"]destroy['"]"#,
        "terraform destroy in a subprocess argument list — bypasses command-level pattern checks",
    ),
    (
        "aws-subprocess-list",
        "AWS — Subprocess Bypass",
        None,
        r#"\[['"]aws['"]\s*(?:,\s*['"][^'"]*['"]\s*)*,\s*['"](?:terminate-instances|delete-db-instance|delete-stack|delete-user|delete-role|delete-policy|rb)['"]"#,
        "AWS destructive command in a subprocess argument list — bypasses command-level pattern checks",
    ),
    // ---- rsh Self-Protection -------------------------------------------
    (
        "rsh-protect-disable",
        "rsh Self-Protection",
        Some("rsh"),
        r"\s[^|;&\n]*?\brule\s+disable\b",
        "Prevents disabling blacklist rules — would allow previously blocked commands through",
    ),
    (
        "rsh-protect-allow",
        "rsh Self-Protection",
        Some("rsh"),
        r"\s[^|;&\n]*?\ballow\s+(?:push|cluster|namespace|database)\b",
        "Prevents lifting forbid/push restrictions — re-allowing targets would bypass user-set protections",
    ),
    (
        "rsh-protect-config-access",
        "rsh Self-Protection",
        None,
        r"\.config[/\\]rsh(?:[/\\]|\s|$)",
        "Prevents any Bash access to the rsh config directory — protects disabled-rules, aliases, and forbidden lists",
    ),
    // ---- rsh self-protection ------------------------------------------
    (
        "rsh-self-disable",
        "rsh Self-Protection",
        Some("rsh"),
        r"\s+(off|on)\b",
        "agents must not disable the security hook",
    ),
    (
        "rsh-guard-flag-file",
        "rsh Self-Protection",
        None,
        r"(?:rsh/disabled|\.rsh-(?:disabled|nopush))",
        "agents must not access or rename rsh flag files",
    ),
];

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    RAW_RULES
        .iter()
        .map(|(id, category, bin, sub, reason)| {
            let effective = match bin {
                Some(b) => {
                    let alts: Vec<String> = aliases::aliases_for(&ALIASES, b)
                        .iter()
                        .map(|s| regex::escape(s))
                        .collect();
                    format!(r"\b(?:{})\b{}", alts.join("|"), sub)
                }
                None => sub.to_string(),
            };
            let regex = Regex::new(&effective)
                .unwrap_or_else(|e| panic!("invalid regex for rule {id}: {e}"));
            Rule {
                id,
                category,
                reason,
                bin: *bin,
                sub_pattern: sub,
                effective_pattern: effective,
                regex,
            }
        })
        .collect()
});

struct BinGroup {
    tokens: Vec<String>,
    rule_indices: Vec<usize>,
}

static BIN_GROUPS: LazyLock<Vec<BinGroup>> = LazyLock::new(|| {
    let mut map: std::collections::HashMap<Option<&'static str>, Vec<usize>> =
        std::collections::HashMap::new();
    for (i, rule) in RULES.iter().enumerate() {
        map.entry(rule.bin).or_default().push(i);
    }
    map.into_iter()
        .map(|(bin, rule_indices)| BinGroup {
            tokens: match bin {
                Some(b) => aliases::aliases_for(&ALIASES, b),
                None => vec![],
            },
            rule_indices,
        })
        .collect()
});

pub fn rules() -> &'static [Rule] {
    &RULES
}

pub fn check_filtered(command: &str, disabled: &std::collections::HashSet<String>) -> Option<Hit> {
    let normalized = shell::tokenize(command).join(" ");
    let normalized = if normalized == command {
        None
    } else {
        Some(normalized)
    };

    for group in BIN_GROUPS.iter() {
        let group_matches = group.tokens.is_empty()
            || group.tokens.iter().any(|t| command.contains(t.as_str()))
            || normalized
                .as_ref()
                .is_some_and(|cmd| group.tokens.iter().any(|t| cmd.contains(t.as_str())));
        if !group_matches {
            continue;
        }
        for &idx in &group.rule_indices {
            let rule = &RULES[idx];
            if disabled.contains(rule.id) {
                continue;
            }
            if rule.regex.is_match(command)
                || normalized
                    .as_ref()
                    .is_some_and(|cmd| rule.regex.is_match(cmd))
            {
                return Some(Hit {
                    id: rule.id,
                    reason: rule.reason,
                });
            }
        }
    }
    None
}

pub fn check(command: &str) -> Option<Hit> {
    check_filtered(command, &crate::disabled::DISABLED)
}

/// Checks `content` against rules whose `bin` field equals `bin`.
/// Pass `bin = Some("kubectl")` for kubectl-only rules, `bin = None` for bin=None rules.
pub fn check_for_bin(content: &str, bin: Option<&str>) -> Option<Hit> {
    let disabled = &crate::disabled::DISABLED;
    let normalized = shell::tokenize(content).join(" ");
    let normalized = if normalized == content {
        None
    } else {
        Some(normalized)
    };

    for rule in RULES.iter() {
        let matches = match (rule.bin, bin) {
            (None, None) => true,
            (Some(rb), Some(b)) => rb == b,
            _ => false,
        };
        if !matches {
            continue;
        }
        if disabled.contains(rule.id) {
            continue;
        }
        if rule.regex.is_match(content)
            || normalized
                .as_ref()
                .is_some_and(|cmd| rule.regex.is_match(cmd))
        {
            return Some(Hit {
                id: rule.id,
                reason: rule.reason,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocks(cmd: &str) -> bool {
        check(cmd).is_some()
    }

    fn hit_id(cmd: &str) -> Option<&'static str> {
        check(cmd).map(|h| h.id)
    }

    // ---- Existing destructive rules ----

    #[test]
    fn blocks_delete_namespace() {
        assert!(blocks("kubectl delete namespace prod"));
        assert!(blocks("kubectl delete ns staging"));
        assert!(blocks("kubectl --context=prod delete namespace foo"));
    }

    #[test]
    fn blocks_delete_all() {
        assert!(blocks("kubectl delete pods --all"));
        assert!(blocks("kubectl delete deployments --all -n default"));
    }

    #[test]
    fn blocks_delete_crd() {
        assert!(blocks("kubectl delete crd foos.example.com"));
        assert!(blocks("kubectl delete customresourcedefinition bar"));
    }

    #[test]
    fn blocks_force_delete() {
        assert!(blocks("kubectl delete pod stuck --force --grace-period=0"));
        assert!(blocks("kubectl delete pod stuck --grace-period=0 --force"));
        // space-separated flag variants
        assert!(blocks("kubectl delete pod stuck --force --grace-period 0"));
        assert!(blocks("kubectl delete pod stuck --grace-period 0 --force"));
    }

    // ---- New destructive rules ----

    #[test]
    fn blocks_delete_pv_pvc() {
        assert!(blocks("kubectl delete pv my-pv"));
        assert!(blocks("kubectl delete pvc my-claim"));
        assert!(blocks("kubectl delete persistentvolume foo"));
        assert!(blocks(
            "kubectl delete persistentvolumeclaim bar -n staging"
        ));
    }

    #[test]
    fn blocks_delete_clusterrole_and_binding() {
        assert!(blocks("kubectl delete clusterrole admin-helper"));
        assert!(blocks(
            "kubectl delete clusterrolebinding cluster-admin-binding"
        ));
        assert!(blocks("kubectl delete clusterroles foo"));
    }

    #[test]
    fn blocks_delete_node() {
        assert!(blocks("kubectl delete node worker-1"));
        assert!(blocks("kubectl delete nodes worker-1 worker-2"));
    }

    #[test]
    fn blocks_delete_workload() {
        assert!(blocks("kubectl delete deployment myapp"));
        assert!(blocks("kubectl delete deploy myapp"));
        assert!(blocks("kubectl delete statefulset db"));
        assert!(blocks("kubectl delete sts db"));
        assert!(blocks("kubectl delete daemonset fluentd"));
        assert!(blocks("kubectl delete ds fluentd"));
    }

    // ---- Pod access ----

    #[test]
    fn blocks_exec_shell() {
        assert!(blocks("kubectl exec mypod -- sh"));
        assert!(blocks("kubectl exec mypod -- bash"));
        assert!(blocks("kubectl exec mypod -- /bin/sh"));
        assert!(blocks("kubectl exec mypod -- /usr/bin/zsh"));
        assert!(blocks("kubectl exec -it mypod -- bash"));
        assert!(blocks("kubectl exec mypod -c sidecar -- bash"));
        // exec with non-shell command stays allowed
        assert!(!blocks("kubectl exec mypod -- ls"));
        assert!(!blocks("kubectl exec mypod -- cat /etc/hostname"));
    }

    #[test]
    fn blocks_run_privileged() {
        assert!(blocks("kubectl run dbg --image=alpine --privileged"));
        assert!(blocks(
            r#"kubectl run dbg --image=alpine --overrides='{"spec":{"containers":[{"securityContext":{"privileged":true}}]}}'"#,
        ));
        // Non-privileged run stays allowed
        assert!(!blocks("kubectl run hello --image=alpine -- echo hi"));
    }

    #[test]
    fn blocks_debug_node() {
        assert!(blocks("kubectl debug node/worker-1 --image=busybox"));
        // debug on a Pod (without node/) stays allowed
        assert!(!blocks("kubectl debug mypod --image=busybox"));
    }

    #[test]
    fn blocks_attach() {
        assert!(blocks("kubectl attach mypod"));
        assert!(blocks("kubectl attach -it mypod"));
    }

    #[test]
    fn blocks_proxy() {
        assert!(blocks("kubectl proxy"));
        assert!(blocks("kubectl proxy --port=8080"));
        assert!(blocks("kubectl proxy --address=0.0.0.0"));
    }

    #[test]
    fn blocks_cp_inbound_only() {
        // Inbound (local → pod) is blocked
        assert!(blocks("kubectl cp ./file mypod:/dst"));
        assert!(blocks("kubectl cp ./file ns/mypod:/dst"));
        assert!(blocks("kubectl cp -c container ./file mypod:/dst"));
        // Outbound (pod → local) stays allowed
        assert!(!blocks("kubectl cp mypod:/etc/foo ./out"));
        assert!(!blocks("kubectl cp ns/mypod:/var/log ./logs"));
    }

    // ---- Privilege escalation ----

    #[test]
    fn blocks_cluster_admin_binding() {
        assert!(blocks(
            "kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=default:default"
        ));
        // space-separated flag variant
        assert!(blocks(
            "kubectl create clusterrolebinding pwn --clusterrole cluster-admin --serviceaccount=default:default"
        ));
        // Non-cluster-admin binding stays allowed
        assert!(!blocks(
            "kubectl create clusterrolebinding readonly --clusterrole=view --serviceaccount=default:default"
        ));
    }

    #[test]
    fn blocks_apply_remote() {
        assert!(blocks("kubectl apply -f https://example.com/manifest.yaml"));
        assert!(blocks("kubectl apply --filename=http://example.com/m.yaml"));
        assert!(blocks(
            "kubectl apply --recursive -f https://example.com/dir/"
        ));
        // Local files stay allowed
        assert!(!blocks("kubectl apply -f ./deployment.yaml"));
        assert!(!blocks("kubectl apply -k ./overlays/prod"));
    }

    // ---- Service disruption ----

    #[test]
    fn blocks_drain() {
        assert!(blocks("kubectl drain worker-1 --ignore-daemonsets"));
        assert!(blocks(
            "kubectl drain worker-1 --delete-emptydir-data --force"
        ));
    }

    // ---- Helm ----

    #[test]
    fn blocks_helm_uninstall_delete() {
        assert!(blocks("helm uninstall postgres"));
        assert!(blocks("helm delete postgres"));
        assert!(blocks("helm uninstall postgres --namespace prod"));
        // Other helm commands stay allowed
        assert!(!blocks("helm install postgres bitnami/postgresql"));
        assert!(!blocks("helm list"));
        assert!(!blocks("helm upgrade postgres bitnami/postgresql"));
    }

    // ---- SQL — Destructive DML ----

    #[test]
    fn blocks_sql_delete() {
        assert!(blocks(r#"psql -c "DELETE FROM users""#));
        assert!(blocks(r#"mysql mydb -e "delete from orders where id=1""#));
        assert!(blocks(r#"echo "DELETE FROM sessions" | psql"#));
        assert!(!blocks(r#"psql -c "SELECT * FROM users""#));
    }

    #[test]
    fn blocks_sql_truncate() {
        assert!(blocks(r#"echo "TRUNCATE TABLE orders" | mysql"#));
        assert!(blocks(r#"psql -c "truncate orders""#));
        assert!(!blocks(r#"mysql -e "INSERT INTO logs VALUES (1, 'ok')""#));
        assert!(!blocks("TRUNCATE=1 ./deploy.sh"));
    }

    // ---- SQL — Destructive DDL ----

    #[test]
    fn blocks_sql_drop() {
        assert!(blocks(r#"psql -c "DROP TABLE IF EXISTS legacy""#));
        assert!(blocks(r#"mysql -e "drop database staging""#));
        assert!(blocks(r#"psql -c "DROP SCHEMA public""#));
        assert!(blocks(r#"psql -c "DROP INDEX idx_email""#));
        assert!(!blocks("echo drop_table_migration_001"));
    }

    #[test]
    fn blocks_sql_alter_table() {
        assert!(blocks(
            r#"psql -c "ALTER TABLE users ADD COLUMN email TEXT""#
        ));
        assert!(blocks(r#"mysql -e "alter table orders drop column foo""#));
        assert!(!blocks(
            r#"sqlite3 app.db "UPDATE users SET name='x' WHERE id=1""#
        ));
    }

    #[test]
    fn blocks_sql_create_ddl() {
        assert!(blocks(r#"mysql -e "CREATE TABLE tmp (id INT)""#));
        assert!(blocks(r#"psql -c "CREATE DATABASE test_db""#));
        assert!(blocks(r#"psql -c "create schema analytics""#));
        assert!(!blocks(
            r#"psql -c "CREATE INDEX idx_email ON users(email)""#
        ));
    }
    // ---- Docker — Volume Destruction ----

    #[test]
    fn blocks_docker_volume_rm() {
        assert!(blocks("docker volume rm mydata"));
        assert!(blocks("docker volume rm mydata otherdata"));
        assert!(blocks("docker volume rm -f mydata"));
        assert!(blocks("docker volume remove mydata"));
        assert!(!blocks("docker volume ls"));
        assert!(!blocks("docker volume inspect mydata"));
    }

    #[test]
    fn blocks_docker_volume_prune() {
        assert!(blocks("docker volume prune"));
        assert!(blocks("docker volume prune -f"));
        assert!(!blocks("docker volume ls"));
    }

    #[test]
    fn blocks_docker_system_prune_risky() {
        assert!(blocks("docker system prune --volumes"));
        assert!(blocks("docker system prune -a"));
        assert!(blocks("docker system prune --all"));
        assert!(blocks("docker system prune -af"));
        assert!(blocks("docker system prune -f --volumes"));
        assert!(!blocks("docker system prune"));
        assert!(!blocks("docker system prune -f"));
        assert!(!blocks("docker system prune --label=foo"));
        assert!(!blocks("docker system prune --filter foo"));
    }

    #[test]
    fn blocks_docker_rm_volumes() {
        assert!(blocks("docker rm -v mycontainer"));
        assert!(blocks("docker rm -fv mycontainer"));
        assert!(blocks("docker rm --volumes mycontainer"));
        assert_eq!(
            hit_id("docker rm -v mycontainer"),
            Some("docker-rm-volumes")
        );
    }

    #[test]
    fn blocks_compose_down_volumes() {
        assert!(blocks("docker compose down -v"));
        assert!(blocks("docker compose down --volumes"));
        assert!(blocks("docker compose -f compose.yml down -v"));
        assert_eq!(
            hit_id("docker compose down -v"),
            Some("compose-down-volumes")
        );
        // Service names with -down suffix must not cause false positives
        assert!(!blocks("docker compose restart markdown-down -v"));
    }

    #[test]
    fn blocks_compose_legacy_down_volumes() {
        assert!(blocks("docker-compose down -v"));
        assert!(blocks("docker-compose down --volumes"));
        assert!(blocks("docker-compose -f docker-compose.yml down -v"));
        assert_eq!(
            hit_id("docker-compose down -v"),
            Some("compose-legacy-down-volumes")
        );
        // Service names with -down suffix must not cause false positives
        assert!(!blocks("docker-compose restart markdown-down -v"));
    }

    #[test]
    fn blocks_compose_rm_volumes() {
        assert!(blocks("docker compose rm -v myservice"));
        assert!(blocks("docker compose rm --volumes"));
        assert_eq!(
            hit_id("docker compose rm -v myservice"),
            Some("compose-rm-volumes")
        );
    }

    #[test]
    fn blocks_compose_legacy_rm_volumes() {
        assert!(blocks("docker-compose rm -v myservice"));
        assert!(blocks("docker-compose rm --volumes myservice"));
        assert_eq!(
            hit_id("docker-compose rm -v"),
            Some("compose-legacy-rm-volumes")
        );
    }

    // ---- Docker — Container/Image Cleanup ----

    #[test]
    fn blocks_docker_container_prune() {
        assert!(blocks("docker container prune"));
        assert!(blocks("docker container prune -f"));
        assert!(!blocks("docker container ls"));
        assert!(!blocks("docker container inspect foo"));
    }

    #[test]
    fn blocks_docker_image_prune() {
        assert!(blocks("docker image prune"));
        assert!(blocks("docker image prune -a"));
        assert!(blocks("docker image prune -f"));
        assert!(!blocks("docker image ls"));
        assert!(!blocks("docker image inspect foo"));
    }

    #[test]
    fn blocks_docker_image_rm() {
        assert!(blocks("docker image rm myimage:latest"));
        assert!(blocks("docker image remove myimage"));
        assert!(!blocks("docker image ls"));
        assert_eq!(hit_id("docker image rm myimage"), Some("docker-image-rm"));
    }

    #[test]
    fn blocks_docker_rmi() {
        assert!(blocks("docker rmi myimage:latest"));
        assert!(blocks("docker rmi myimage1 myimage2"));
        assert!(blocks("docker rmi -f myimage"));
        assert!(!blocks("docker run myimage"));
        assert_eq!(hit_id("docker rmi myimage"), Some("docker-rmi"));
    }

    #[test]
    fn blocks_docker_rm() {
        assert!(blocks("docker rm mycontainer"));
        assert!(blocks("docker rm -f mycontainer"));
        assert_eq!(hit_id("docker rm mycontainer"), Some("docker-rm"));
        assert!(!blocks("docker run myimage"));
        assert!(!blocks("docker ps"));
        assert!(!blocks("docker start mycontainer"));
        // Management sub-commands stay allowed
        assert!(!blocks("docker network rm mynet"));
        assert!(!blocks("docker buildx rm mybuilder"));
        assert!(!blocks("docker context rm mycontext"));
    }

    #[test]
    fn blocks_compose_down() {
        assert!(blocks("docker compose down"));
        assert!(blocks("docker compose -f compose.yml down"));
        assert_eq!(hit_id("docker compose down"), Some("compose-down"));
        assert!(!blocks("docker compose up"));
        assert!(!blocks("docker compose ps"));
        // Service names with -down suffix must not be blocked
        assert!(!blocks("docker compose restart markdown-down"));
        assert!(!blocks("docker compose logs markdown-down"));
    }

    #[test]
    fn blocks_compose_legacy_down() {
        assert!(blocks("docker-compose down"));
        assert!(blocks("docker-compose -f docker-compose.yml down"));
        assert_eq!(hit_id("docker-compose down"), Some("compose-legacy-down"));
        assert!(!blocks("docker-compose up"));
        assert!(!blocks("docker-compose ps"));
        // Service names with -down suffix must not be blocked
        assert!(!blocks("docker-compose restart markdown-down"));
        assert!(!blocks("docker-compose logs markdown-down"));
    }

    // ---- GitLab CLI — Destructive ----

    #[test]
    fn blocks_glab_repo_delete() {
        assert!(blocks("glab repo delete myproject"));
        assert!(blocks("glab project delete myproject"));
        assert!(blocks("glab --repo=owner/repo repo delete myproject"));
        assert!(!blocks("glab repo list"));
        assert!(!blocks("glab repo clone myproject"));
        assert!(!blocks("glab repo create myproject"));
    }

    #[test]
    fn blocks_glab_release_delete() {
        assert!(blocks("glab release delete v1.0.0"));
        assert!(blocks("glab release delete v1.0.0 --yes"));
        assert!(!blocks("glab release list"));
        assert!(!blocks("glab release create v2.0.0"));
        assert!(!blocks("glab release view v1.0.0"));
    }

    #[test]
    fn blocks_glab_variable_delete() {
        assert!(blocks("glab variable delete MY_SECRET"));
        assert!(blocks("glab variable delete MY_SECRET --scope project"));
        assert!(!blocks("glab variable list"));
        assert!(!blocks("glab variable get MY_SECRET"));
        assert!(!blocks("glab variable set MY_VAR value"));
    }

    #[test]
    fn blocks_glab_repo_members_remove() {
        assert!(blocks("glab repo members remove --username=johndoe"));
        assert!(blocks("glab repo members remove --user-id=123"));
        assert!(!blocks("glab repo members list"));
        assert!(!blocks("glab repo list"));
        assert!(!blocks("glab repo members add --username=johndoe"));
    }

    #[test]
    fn blocks_glab_issue_delete() {
        assert!(blocks("glab issue delete 42"));
        assert!(blocks("glab issue delete 42 --yes"));
        assert!(!blocks("glab issue list"));
        assert!(!blocks("glab issue close 42"));
        assert!(!blocks("glab issue view 42"));
        assert!(!blocks("glab issue create"));
    }

    #[test]
    fn blocks_glab_label_delete() {
        assert!(blocks("glab label delete bug"));
        assert!(blocks("glab label delete \"my label\""));
        assert!(!blocks("glab label list"));
        assert!(!blocks("glab label create bug --color=#FF0000"));
    }

    // ---- Kubernetes — additional rules ----

    #[test]
    fn blocks_delete_secret() {
        assert!(blocks("kubectl delete secret myapp-secret"));
        assert!(blocks("kubectl delete secrets myapp-secret -n prod"));
        assert!(blocks("kubectl delete secret/myapp-secret"));
        assert!(!blocks("kubectl get secret myapp-secret"));
        assert!(!blocks("kubectl describe secret myapp-secret"));
    }

    #[test]
    fn blocks_delete_rolebinding() {
        assert!(blocks("kubectl delete rolebinding myapp-binding"));
        assert!(blocks("kubectl delete rolebindings myapp-binding -n prod"));
        assert!(!blocks("kubectl get rolebinding myapp-binding"));
        assert!(!blocks("kubectl create rolebinding readonly --clusterrole=view --serviceaccount=default:app"));
    }

    #[test]
    fn blocks_delete_ingress() {
        assert!(blocks("kubectl delete ingress myapp-ingress"));
        assert!(blocks("kubectl delete ingresses myapp-ingress -n prod"));
        assert!(blocks("kubectl delete ing myapp-ingress"));
        assert!(!blocks("kubectl get ingress myapp-ingress"));
        assert!(!blocks("kubectl describe ingress myapp-ingress"));
    }

    #[test]
    fn blocks_scale_zero() {
        assert!(blocks("kubectl scale deployment myapp --replicas=0"));
        assert!(blocks("kubectl scale statefulset db --replicas=0 -n prod"));
        // space-separated flag variant
        assert!(blocks("kubectl scale deployment myapp --replicas 0"));
        assert!(!blocks("kubectl scale deployment myapp --replicas=3"));
        assert!(!blocks("kubectl scale deployment myapp --replicas=1"));
        assert!(!blocks("kubectl scale deployment myapp --replicas 3"));
    }

    #[test]
    fn blocks_cordon() {
        assert!(blocks("kubectl cordon worker-1"));
        assert!(blocks("kubectl cordon node/worker-1"));
        // uncordon restores scheduling and must not be blocked
        assert!(!blocks("kubectl uncordon worker-1"));
        assert!(!blocks("kubectl get node worker-1"));
    }

    // ---- SQL — additional rules ----

    #[test]
    fn blocks_sql_drop_role() {
        assert!(blocks(r#"psql -c "DROP ROLE readonly""#));
        assert!(blocks(r#"psql -c "DROP USER app_user""#));
        assert!(blocks(r#"mysql -e "drop role analytics""#));
    }

    #[test]
    fn blocks_sql_grant_all() {
        assert!(blocks(r#"psql -c "GRANT ALL ON TABLE users TO app""#));
        assert!(blocks(r#"mysql -e "grant all privileges on *.* to 'root'@'%'""#));
        assert!(!blocks(r#"psql -c "GRANT SELECT ON TABLE users TO readonly""#));
    }

    #[test]
    fn blocks_sql_revoke_all() {
        assert!(blocks(r#"psql -c "REVOKE ALL ON TABLE users FROM app""#));
        assert!(blocks(r#"mysql -e "revoke all privileges on *.* from 'app'@'%'""#));
        assert!(!blocks(r#"psql -c "REVOKE SELECT ON TABLE users FROM readonly""#));
    }

    // ---- Git — Destructive ----

    #[test]
    fn blocks_git_force_push() {
        assert!(blocks("git push --force"));
        assert!(blocks("git push --force origin main"));
        assert!(blocks("git push origin main --force"));
        assert!(blocks("git push -f"));
        assert!(blocks("git push -f origin main"));
        assert!(blocks("git push --force-with-lease"));
        assert!(blocks("git push --force-with-lease origin main"));
        // Normal push stays allowed
        assert!(!blocks("git push origin main"));
        assert!(!blocks("git push"));
        assert!(!blocks("git push --set-upstream origin feat"));
    }

    #[test]
    fn blocks_git_reset_hard() {
        assert!(blocks("git reset --hard HEAD~1"));
        assert!(blocks("git reset --hard HEAD"));
        assert!(blocks("git reset --hard abc1234"));
        // Soft/mixed reset stays allowed
        assert!(!blocks("git reset --soft HEAD~1"));
        assert!(!blocks("git reset HEAD file.txt"));
        assert!(!blocks("git reset HEAD~1"));
    }

    #[test]
    fn blocks_git_clean() {
        assert!(blocks("git clean -f"));
        assert!(blocks("git clean -fd"));
        assert!(blocks("git clean -fxd"));
        assert!(blocks("git clean -df"));
        // Dry run stays allowed
        assert!(!blocks("git clean -n"));
        assert!(!blocks("git clean -nd"));
        assert!(!blocks("git clean -nx"));
    }

    #[test]
    fn blocks_git_branch_force_delete() {
        assert!(blocks("git branch -D mybranch"));
        assert!(blocks("git branch -Dr mybranch"));
        // Safe lowercase -d stays allowed (only deletes merged branches)
        assert!(!blocks("git branch -d mybranch"));
        assert!(!blocks("git branch --list"));
        assert!(!blocks("git branch -a"));
    }

    // ---- GitHub CLI — Destructive ----

    #[test]
    fn blocks_gh_repo_delete() {
        assert!(blocks("gh repo delete myorg/myrepo"));
        assert!(blocks("gh repo delete myrepo --yes"));
        assert!(!blocks("gh repo list"));
        assert!(!blocks("gh repo clone myrepo"));
        assert!(!blocks("gh repo create myrepo"));
    }

    #[test]
    fn blocks_gh_release_delete() {
        assert!(blocks("gh release delete v1.0.0"));
        assert!(blocks("gh release delete v1.0.0 --yes"));
        assert!(!blocks("gh release list"));
        assert!(!blocks("gh release create v2.0.0"));
        assert!(!blocks("gh release view v1.0.0"));
    }

    #[test]
    fn blocks_gh_secret_delete() {
        assert!(blocks("gh secret delete MY_SECRET"));
        assert!(blocks("gh secret delete MY_SECRET --env production"));
        assert!(!blocks("gh secret list"));
        assert!(!blocks("gh secret set MY_SECRET"));
    }

    #[test]
    fn blocks_gh_variable_delete() {
        assert!(blocks("gh variable delete MY_VAR"));
        assert!(!blocks("gh variable list"));
        assert!(!blocks("gh variable set MY_VAR value"));
    }

    #[test]
    fn blocks_gh_auth_logout() {
        assert!(blocks("gh auth logout"));
        assert!(blocks("gh auth logout --hostname github.com"));
        assert!(!blocks("gh auth login"));
        assert!(!blocks("gh auth status"));
    }

    // ---- Terraform — Destructive ----

    #[test]
    fn blocks_tf_destroy() {
        assert!(blocks("terraform destroy"));
        assert!(blocks("terraform destroy -auto-approve"));
        assert!(blocks("terraform apply -destroy"));
        assert!(blocks("terraform plan -destroy"));
        assert!(!blocks("terraform plan"));
        assert!(!blocks("terraform apply"));
        assert!(!blocks("terraform show"));
    }

    #[test]
    fn blocks_tf_workspace_delete() {
        assert!(blocks("terraform workspace delete staging"));
        assert!(blocks("terraform workspace delete staging -force"));
        assert!(!blocks("terraform workspace list"));
        assert!(!blocks("terraform workspace select staging"));
        assert!(!blocks("terraform workspace new staging"));
    }

    #[test]
    fn blocks_tf_force_unlock() {
        assert!(blocks("terraform force-unlock 12345"));
        assert!(blocks("terraform force-unlock -force 12345"));
        assert!(!blocks("terraform show"));
        assert!(!blocks("terraform init"));
    }

    // ---- AWS — Destructive ----

    #[test]
    fn blocks_aws_s3_rm_recursive() {
        assert!(blocks("aws s3 rm s3://mybucket/prefix/ --recursive"));
        assert!(blocks("aws s3 rm s3://mybucket --recursive"));
        // Without --recursive stays allowed (single object delete)
        assert!(!blocks("aws s3 rm s3://mybucket/single-file.txt"));
        assert!(!blocks("aws s3 ls s3://mybucket"));
    }

    #[test]
    fn blocks_aws_s3_bucket_delete() {
        assert!(blocks("aws s3 rb s3://mybucket"));
        assert!(blocks("aws s3 rb s3://mybucket --force"));
        assert!(!blocks("aws s3 ls s3://mybucket"));
        assert!(!blocks("aws s3 cp file.txt s3://mybucket/file.txt"));
    }

    #[test]
    fn blocks_aws_ec2_terminate() {
        assert!(blocks("aws ec2 terminate-instances --instance-ids i-1234567890abcdef0"));
        assert!(blocks("aws ec2 terminate-instances --instance-ids i-abc i-def"));
        assert!(!blocks("aws ec2 describe-instances"));
        assert!(!blocks("aws ec2 stop-instances --instance-ids i-abc"));
    }

    #[test]
    fn blocks_aws_rds_delete() {
        assert!(blocks("aws rds delete-db-instance --db-instance-identifier mydb"));
        assert!(blocks("aws rds delete-db-instance --db-instance-identifier mydb --skip-final-snapshot"));
        assert!(!blocks("aws rds describe-db-instances"));
        assert!(!blocks("aws rds stop-db-instance --db-instance-identifier mydb"));
    }

    #[test]
    fn blocks_aws_cf_delete_stack() {
        assert!(blocks("aws cloudformation delete-stack --stack-name mystack"));
        assert!(!blocks("aws cloudformation describe-stacks"));
        assert!(!blocks("aws cloudformation list-stacks"));
    }

    #[test]
    fn blocks_aws_iam_delete() {
        assert!(blocks("aws iam delete-user --user-name alice"));
        assert!(blocks("aws iam delete-role --role-name my-role"));
        assert!(blocks("aws iam delete-policy --policy-arn arn:aws:iam::123:policy/MyPolicy"));
        assert!(blocks("aws iam delete-group --group-name admins"));
        assert!(!blocks("aws iam list-users"));
        assert!(!blocks("aws iam get-user --user-name alice"));
        assert!(!blocks("aws iam create-user --user-name alice"));
    }

    // ---- System — Shutdown & Firewall ----

    #[test]
    fn blocks_sys_shutdown_direct() {
        assert!(blocks("shutdown now"));
        assert!(blocks("shutdown -h now"));
        assert!(blocks("sudo shutdown -h now"));
        assert!(blocks("reboot"));
        assert!(blocks("sudo reboot"));
        assert!(blocks("halt"));
        assert!(blocks("poweroff"));
        assert!(blocks("sudo poweroff"));
    }

    #[test]
    fn blocks_sys_shutdown_systemctl() {
        assert!(blocks("systemctl poweroff"));
        assert!(blocks("systemctl reboot"));
        assert!(blocks("systemctl halt"));
        assert!(blocks("systemctl --no-wall reboot"));
        assert!(!blocks("systemctl status nginx"));
        assert!(!blocks("systemctl restart nginx"));
        assert!(!blocks("systemctl enable nginx"));
    }

    #[test]
    fn blocks_sys_firewall_flush() {
        assert!(blocks("iptables -F"));
        assert!(blocks("iptables --flush"));
        assert!(blocks("iptables -F INPUT"));
        assert!(blocks("ip6tables -F"));
        assert!(blocks("sudo iptables -F"));
        assert!(!blocks("iptables -L"));
        assert!(!blocks("iptables -A INPUT -j ACCEPT"));
    }

    #[test]
    fn blocks_sys_nft_flush_ruleset() {
        assert!(blocks("nft flush ruleset"));
        assert!(blocks("sudo nft flush ruleset"));
        assert!(!blocks("nft list ruleset"));
        assert!(!blocks("nft add rule inet filter input accept"));
    }

    // ---- Redis — Destructive ----

    #[test]
    fn blocks_redis_flushall() {
        assert!(blocks("redis-cli FLUSHALL"));
        assert!(blocks("redis-cli -h myhost FLUSHALL"));
        assert!(!blocks("redis-cli GET mykey"));
        assert!(!blocks("redis-cli KEYS *"));
    }

    #[test]
    fn blocks_redis_flushdb() {
        assert!(blocks("redis-cli FLUSHDB"));
        assert!(blocks("redis-cli -n 3 FLUSHDB"));
        assert!(!blocks("redis-cli DBSIZE"));
        assert!(!blocks("redis-cli SELECT 3"));
    }

    // ---- Package Publishing — Irreversible ----

    #[test]
    fn blocks_npm_unpublish() {
        assert!(blocks("npm unpublish mypackage@1.0.0"));
        assert!(blocks("npm unpublish mypackage --force"));
        assert!(!blocks("npm publish"));
        assert!(!blocks("npm install mypackage"));
        assert!(!blocks("npm uninstall mypackage"));
    }

    #[test]
    fn blocks_cargo_yank() {
        assert!(blocks("cargo yank --version 1.0.0 mypackage"));
        assert!(blocks("cargo yank mypackage@1.0.0"));
        // --undo also blocked: the regex crate has no lookahead; run manually to reverse
        assert!(!blocks("cargo publish"));
        assert!(!blocks("cargo build"));
    }

    // ---- Subprocess bypass — new tools ----

    #[test]
    fn blocks_git_force_push_in_subprocess_list() {
        assert!(blocks(
            "subprocess.run(['git', 'push', '--force'])"
        ));
        assert!(blocks(
            "subprocess.run(['git', 'push', 'origin', 'main', '--force'])"
        ));
        assert!(blocks(
            r#"subprocess.run(["git", "push", "origin", "main", "--force-with-lease"])"#
        ));
        assert!(blocks(
            "subprocess.run(['git', 'push', 'origin', 'main', '-f'])"
        ));
        // Normal push must not be blocked
        assert!(!blocks("subprocess.run(['git', 'push', 'origin', 'main'])"));
        assert!(!blocks("subprocess.run(['git', 'status'])"));
    }

    #[test]
    fn blocks_gh_delete_in_subprocess_list() {
        assert!(blocks(
            "subprocess.run(['gh', 'repo', 'delete', 'myorg/myrepo'])"
        ));
        assert!(blocks(
            "subprocess.run(['gh', 'release', 'delete', 'v1.0.0'])"
        ));
        assert!(blocks(
            r#"subprocess.run(["gh", "secret", "delete", "MY_SECRET"])"#
        ));
        assert!(!blocks("subprocess.run(['gh', 'repo', 'list'])"));
        assert!(!blocks("subprocess.run(['gh', 'issue', 'create'])"));
    }

    #[test]
    fn blocks_terraform_destroy_in_subprocess_list() {
        assert!(blocks(
            "subprocess.run(['terraform', 'destroy'])"
        ));
        assert!(blocks(
            "subprocess.run(['terraform', '-chdir=infra', 'destroy'])"
        ));
        assert!(blocks(
            r#"subprocess.run(["terraform", "destroy", "-auto-approve"])"#
        ));
        assert!(!blocks("subprocess.run(['terraform', 'plan'])"));
        assert!(!blocks("subprocess.run(['terraform', 'apply'])"));
    }

    #[test]
    fn blocks_aws_destructive_in_subprocess_list() {
        assert!(blocks(
            "subprocess.run(['aws', 'ec2', 'terminate-instances', '--instance-ids', 'i-abc'])"
        ));
        assert!(blocks(
            "subprocess.run(['aws', 'rds', 'delete-db-instance', '--db-instance-identifier', 'mydb'])"
        ));
        assert!(blocks(
            "subprocess.run(['aws', 'cloudformation', 'delete-stack', '--stack-name', 'mystack'])"
        ));
        assert!(blocks(
            "subprocess.run(['aws', 'iam', 'delete-user', '--user-name', 'alice'])"
        ));
        assert!(blocks(
            "subprocess.run(['aws', 's3', 'rb', 's3://mybucket'])"
        ));
        assert!(!blocks("subprocess.run(['aws', 'ec2', 'describe-instances'])"));
        assert!(!blocks("subprocess.run(['aws', 's3', 'ls', 's3://mybucket'])"));
    }

    // ---- General negative ----

    #[test]
    fn allows_safe_kubectl() {
        assert!(!blocks("kubectl get pods"));
        assert!(!blocks("kubectl apply -f deployment.yaml"));
        assert!(!blocks("kubectl delete pod single-pod"));
        assert!(!blocks("kubectl describe namespace prod"));
        assert!(!blocks("kubectl logs mypod"));
        assert!(!blocks("kubectl scale deployment myapp --replicas=3"));
        assert!(!blocks("kubectl rollout undo deployment myapp"));
    }

    #[test]
    fn allows_unrelated_commands() {
        assert!(!blocks("ls -la"));
        assert!(!blocks("git status"));
        assert!(!blocks("cargo run"));
    }

    #[test]
    fn security_regression_blocks_shell_escaped_kubectl_binary() {
        assert!(blocks(r"kube\ctl delete ns prod"));
    }

    #[test]
    fn security_regression_blocks_shell_quoted_kubectl_verb() {
        assert!(blocks("kubectl dele''te ns prod"));
    }

    #[test]
    fn security_regression_blocks_shell_escaped_rsh_binary() {
        assert!(blocks(r"r\sh off"));
    }

    // ---- Cross-check: rule IDs are stable ----

    // ---- Subprocess list bypass ----

    #[test]
    fn blocks_kubectl_delete_in_subprocess_list() {
        // Python single-quoted list form
        assert!(blocks(
            "subprocess.run(['kubectl', 'delete', 'ns', 'prod'])"
        ));
        assert!(blocks(
            "subprocess.run(['kubectl', 'delete', 'namespace', 'prod'])"
        ));
        // Double-quoted list form
        assert!(blocks(
            r#"subprocess.run(["kubectl", "delete", "ns", "prod"])"#
        ));
        // Full python3 -c invocation
        assert!(blocks(
            r#"python3 -c "import subprocess; subprocess.run(['kubectl', 'delete', 'ns', 'prod'])""#
        ));
        // Other function names wrapping the list
        assert!(blocks(
            "execv(['kubectl', 'delete', 'deployment', 'myapp'])"
        ));
        // Non-destructive calls must not be blocked
        assert!(!blocks("subprocess.run(['kubectl', 'get', 'pods'])"));
        assert!(!blocks(
            "subprocess.run(['kubectl', 'apply', '-f', 'deploy.yaml'])"
        ));
    }

    #[test]
    fn blocks_helm_uninstall_in_subprocess_list() {
        assert!(blocks("subprocess.run(['helm', 'uninstall', 'postgres'])"));
        assert!(blocks("subprocess.run(['helm', 'delete', 'postgres'])"));
        assert!(blocks(r#"subprocess.run(["helm", "uninstall", "app"])"#));
        // Safe helm calls must not be blocked
        assert!(!blocks("subprocess.run(['helm', 'list'])"));
        assert!(!blocks(
            "subprocess.run(['helm', 'upgrade', 'app', 'chart'])"
        ));
    }

    #[test]
    fn blocks_glab_delete_in_subprocess_list() {
        assert!(blocks(
            "subprocess.run(['glab', 'repo', 'delete', 'myproject'])"
        ));
        assert!(blocks(
            "subprocess.run(['glab', 'release', 'delete', 'v1.0.0'])"
        ));
        assert!(blocks(
            r#"subprocess.run(["glab", "variable", "delete", "MY_SECRET"])"#
        ));
        assert!(!blocks("subprocess.run(['glab', 'repo', 'list'])"));
        assert!(!blocks("subprocess.run(['glab', 'issue', 'list'])"));
    }

    #[test]
    fn blocks_docker_destructive_in_subprocess_list() {
        assert!(blocks("subprocess.run(['docker', 'rm', 'mycontainer'])"));
        assert!(blocks("subprocess.run(['docker', 'rmi', 'myimage'])"));
        assert!(blocks(
            "subprocess.run(['docker', 'volume', 'rm', 'mydata'])"
        ));
        assert!(blocks(
            "subprocess.run(['docker', 'system', 'prune', '--volumes'])"
        ));
        assert!(blocks("subprocess.run(['docker', 'compose', 'down'])"));
        assert!(!blocks("subprocess.run(['docker', 'ps'])"));
        assert!(!blocks(
            "subprocess.run(['docker', 'build', '-t', 'img', '.'])"
        ));
        assert!(!blocks("subprocess.run(['docker', 'run', 'myimage'])"));
    }

    #[test]
    fn blocks_rsh_off_on_in_subprocess_list() {
        assert!(blocks("subprocess.run(['rsh', 'off'])"));
        assert!(blocks("subprocess.run(['rsh', 'on'])"));
        assert!(blocks(r#"subprocess.run(["rsh", "off"])"#));
        assert!(!blocks("subprocess.run(['rsh', 'list'])"));
        assert!(!blocks("subprocess.run(['rsh', 'check', 'something'])"));
    }

    #[test]
    fn rule_ids_are_distinct_and_match_expected_set() {
        let mut ids: Vec<&str> = rules().iter().map(|r| r.id).collect();
        ids.sort();
        let expected = vec![
            "aws-cf-delete-stack",
            "aws-ec2-terminate",
            "aws-iam-delete",
            "aws-rds-delete",
            "aws-s3-bucket-delete",
            "aws-s3-rm-recursive",
            "aws-subprocess-list",
            "cargo-yank",
            "compose-down",
            "compose-down-volumes",
            "compose-legacy-down",
            "compose-legacy-down-volumes",
            "compose-legacy-rm-volumes",
            "compose-rm-volumes",
            "docker-container-prune",
            "docker-image-prune",
            "docker-image-rm",
            "docker-rm",
            "docker-rm-volumes",
            "docker-rmi",
            "docker-subprocess-list",
            "docker-system-prune-risky",
            "docker-volume-prune",
            "docker-volume-rm",
            "gh-auth-logout",
            "gh-release-delete",
            "gh-repo-delete",
            "gh-secret-delete",
            "gh-subprocess-list",
            "gh-variable-delete",
            "git-branch-force-delete",
            "git-clean",
            "git-force-push",
            "git-reset-hard",
            "git-subprocess-list",
            "glab-issue-delete",
            "glab-label-delete",
            "glab-release-delete",
            "glab-repo-delete",
            "glab-repo-members-remove",
            "glab-subprocess-list",
            "glab-variable-delete",
            "helm-subprocess-list",
            "helm-uninstall",
            "k8s-apply-remote",
            "k8s-attach",
            "k8s-cluster-admin-binding",
            "k8s-cordon",
            "k8s-cp-inbound",
            "k8s-debug-node",
            "k8s-delete-all",
            "k8s-delete-clusterrole",
            "k8s-delete-crd",
            "k8s-delete-ingress",
            "k8s-delete-namespace",
            "k8s-delete-node",
            "k8s-delete-pv-pvc",
            "k8s-delete-rolebinding",
            "k8s-delete-secret",
            "k8s-delete-workload",
            "k8s-drain",
            "k8s-exec-shell",
            "k8s-force-delete",
            "k8s-proxy",
            "k8s-run-privileged",
            "k8s-scale-zero",
            "k8s-subprocess-list",
            "npm-unpublish",
            "redis-flushall",
            "redis-flushdb",
            "rsh-guard-flag-file",
            "rsh-protect-allow",
            "rsh-protect-config-access",
            "rsh-protect-disable",
            "rsh-self-disable",
            "rsh-subprocess-list",
            "sql-alter-table",
            "sql-create-ddl",
            "sql-delete",
            "sql-drop",
            "sql-drop-role",
            "sql-grant-all",
            "sql-revoke-all",
            "sql-truncate",
            "sys-firewall-flush",
            "sys-nft-flush",
            "sys-shutdown-direct",
            "sys-shutdown-systemctl",
            "terraform-subprocess-list",
            "tf-destroy",
            "tf-force-unlock",
            "tf-workspace-delete",
        ];
        assert_eq!(ids, expected);
    }

    #[test]
    fn correct_rule_fires_for_each_pattern() {
        assert_eq!(
            hit_id("kubectl delete ns prod"),
            Some("k8s-delete-namespace")
        );
        assert_eq!(hit_id("kubectl delete pvc db"), Some("k8s-delete-pv-pvc"));
        assert_eq!(hit_id("kubectl exec p -- bash"), Some("k8s-exec-shell"));
        assert_eq!(hit_id("helm uninstall foo"), Some("helm-uninstall"));
        assert_eq!(hit_id("kubectl proxy"), Some("k8s-proxy"));
        assert_eq!(hit_id(r#"psql -c "DELETE FROM users""#), Some("sql-delete"));
        assert_eq!(
            hit_id(r#"psql -c "TRUNCATE TABLE orders""#),
            Some("sql-truncate")
        );
        assert_eq!(hit_id(r#"psql -c "DROP TABLE foo""#), Some("sql-drop"));
        assert_eq!(
            hit_id(r#"psql -c "ALTER TABLE users ADD COLUMN x INT""#),
            Some("sql-alter-table")
        );
        assert_eq!(
            hit_id(r#"mysql -e "CREATE TABLE tmp (id INT)""#),
            Some("sql-create-ddl")
        );
    }

    // ---- disabled-rule filtering ----

    #[test]
    fn check_filtered_skips_disabled_rule() {
        use std::collections::HashSet;
        let mut disabled = HashSet::new();
        disabled.insert("k8s-delete-namespace".to_string());
        assert!(check_filtered("kubectl delete namespace prod", &disabled).is_none());
    }

    #[test]
    fn check_filtered_still_blocks_non_disabled_rules() {
        use std::collections::HashSet;
        let mut disabled = HashSet::new();
        disabled.insert("k8s-delete-namespace".to_string());
        assert!(check_filtered("kubectl delete pods --all", &disabled).is_some());
    }

    #[test]
    fn check_filtered_empty_disabled_set_behaves_like_check() {
        use std::collections::HashSet;
        let disabled = HashSet::new();
        assert_eq!(
            check_filtered("kubectl delete namespace prod", &disabled).map(|h| h.id),
            check("kubectl delete namespace prod").map(|h| h.id),
        );
    }

    // ---- rsh Self-Protection ----

    #[test]
    fn blocks_rsh_rule_disable() {
        assert!(blocks("rsh rule disable k8s-delete-namespace"));
        assert!(blocks("rsh rule disable rsh-protect-disable"));
        assert!(blocks("rsh  rule  disable helm-uninstall"));
        // list and enable must not be blocked
        assert!(!blocks("rsh rule list"));
        assert!(!blocks("rsh rule enable k8s-delete-namespace"));
    }

    #[test]
    fn blocks_rsh_allow() {
        assert!(blocks("rsh allow push"));
        assert!(blocks("rsh allow cluster prod"));
        assert!(blocks("rsh allow namespace default"));
        assert!(blocks("rsh allow database db.example.com"));
        assert_eq!(hit_id("rsh allow push"), Some("rsh-protect-allow"));
        assert_eq!(hit_id("rsh allow cluster prod"), Some("rsh-protect-allow"));
        // forbid (adding) must not be blocked
        assert!(!blocks("rsh forbid cluster prod"));
        assert!(!blocks("rsh forbid namespace staging"));
    }

    #[test]
    fn blocks_rsh_config_access() {
        assert!(blocks("cat ~/.config/rsh/disabled-rules.json"));
        assert!(blocks("echo '[]' > ~/.config/rsh/disabled-rules.json"));
        assert!(blocks("rm ~/.config/rsh/aliases.json"));
        assert!(blocks("ls ~/.config/rsh/"));
        assert!(blocks("ls ~/.config/rsh"));
        // unrelated config paths must not be blocked
        assert!(!blocks("cat ~/.config/other/file.json"));
        assert!(!blocks("ls ~/.config/"));
        assert!(!blocks("cat ~/.config/rsh-backup/file.json"));
        assert!(!blocks("ls ~/.config/rsh.old"));
    }

    #[test]
    fn bin_groups_cover_all_rules() {
        // Every rule index appears in exactly one group.
        let grouped: usize = super::BIN_GROUPS.iter().map(|g| g.rule_indices.len()).sum();
        assert_eq!(
            grouped,
            super::RULES.len(),
            "every rule must appear in exactly one BinGroup"
        );

        // The kubectl group exists and its tokens contain "kubectl".
        let kubectl_group = super::BIN_GROUPS
            .iter()
            .find(|g| g.tokens.iter().any(|t| t == "kubectl"))
            .expect("kubectl group must exist");
        assert!(
            kubectl_group.rule_indices.len() >= 10,
            "kubectl group must have at least 10 rules, got {}",
            kubectl_group.rule_indices.len()
        );

        // bin=None rules have empty tokens (never skipped).
        let binless = super::BIN_GROUPS.iter().find(|g| g.tokens.is_empty());
        assert!(
            binless.is_some(),
            "there must be a bin=None group with empty tokens"
        );
    }

    #[test]
    fn check_for_bin_kubectl_only() {
        // kubectl rule must fire
        assert!(check_for_bin("kubectl delete ns prod", Some("kubectl")).is_some());
        // helm rule must NOT fire for kubectl-only check
        assert!(check_for_bin("helm uninstall postgres", Some("kubectl")).is_none());
    }

    #[test]
    fn check_for_bin_helm_only() {
        assert!(check_for_bin("helm uninstall postgres", Some("helm")).is_some());
        assert!(check_for_bin("kubectl delete ns prod", Some("helm")).is_none());
    }

    #[test]
    fn check_for_bin_none_rules() {
        // SQL rules have bin=None
        assert!(check_for_bin(r#"psql -c "DELETE FROM users""#, None).is_some());
        // kubectl rules must NOT fire in bin=None check
        assert!(check_for_bin("kubectl delete ns prod", None).is_none());
    }

    #[test]
    fn blocks_rsh_off_and_on() {
        assert!(blocks("rsh off"));
        assert!(blocks("rsh on"));
        assert_eq!(hit_id("rsh off"), Some("rsh-self-disable"));
        assert_eq!(hit_id("rsh on"), Some("rsh-self-disable"));
    }

    #[test]
    fn allows_other_rsh_subcommands() {
        assert!(!blocks("rsh list"));
        assert!(!blocks("rsh check foo"));
        assert!(!blocks("rsh init"));
    }

    #[test]
    fn blocks_commands_referencing_flag_files() {
        // These should be blocked by rsh-guard-flag-file
        assert!(blocks("rm ~/.rsh-disabled"));
        assert!(blocks("mv .rsh-disabled /tmp/bak"));
        assert!(blocks("touch /home/user/.rsh-disabled"));
        assert_eq!(hit_id("rm ~/.rsh-disabled"), Some("rsh-guard-flag-file"));
    }

    #[test]
    fn allows_commands_not_referencing_flag_files() {
        assert!(!blocks("ls ~/"));
        assert!(!blocks("cat ~/myfile.txt"));
    }

    #[test]
    fn blocks_flag_file_nopush_manipulation() {
        assert!(blocks("rm .rsh-nopush"));
        assert!(blocks("mv .rsh-nopush /tmp/bak"));
        assert_eq!(hit_id("rm .rsh-nopush"), Some("rsh-guard-flag-file"));
    }
}
