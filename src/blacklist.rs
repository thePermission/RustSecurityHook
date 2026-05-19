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
        r"\s[^|;&\n]*?\bdelete\b(?:[^|;&\n]*--force\b[^|;&\n]*--grace-period=0|[^|;&\n]*--grace-period=0\b[^|;&\n]*--force)",
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
        r"\s[^|;&\n]*?\bcreate\s+clusterrolebinding\b[^|;&\n]*?--clusterrole=cluster-admin\b",
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
    // ---- rsh Self-Protection -------------------------------------------
    (
        "rsh-protect-disable",
        "rsh Self-Protection",
        Some("rsh"),
        r"\s[^|;&\n]*?\brule\s+disable\b",
        "Prevents disabling blacklist rules — would allow previously blocked commands through",
    ),
    (
        "rsh-protect-forbid-remove",
        "rsh Self-Protection",
        Some("rsh"),
        r"\s[^|;&\n]*?\bforbid\s+remove\b",
        "Prevents removing entries from the forbid list — would re-allow forbidden clusters/namespaces",
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
        r"(?:rsh/disabled|\.rsh-disabled)",
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
    fn rule_ids_are_distinct_and_match_expected_set() {
        let mut ids: Vec<&str> = rules().iter().map(|r| r.id).collect();
        ids.sort();
        let expected = vec![
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
            "docker-system-prune-risky",
            "docker-volume-prune",
            "docker-volume-rm",
            "glab-issue-delete",
            "glab-label-delete",
            "glab-release-delete",
            "glab-repo-delete",
            "glab-repo-members-remove",
            "glab-variable-delete",
            "helm-subprocess-list",
            "helm-uninstall",
            "k8s-apply-remote",
            "k8s-attach",
            "k8s-cluster-admin-binding",
            "k8s-cp-inbound",
            "k8s-debug-node",
            "k8s-delete-all",
            "k8s-delete-clusterrole",
            "k8s-delete-crd",
            "k8s-delete-namespace",
            "k8s-delete-node",
            "k8s-delete-pv-pvc",
            "k8s-delete-workload",
            "k8s-drain",
            "k8s-exec-shell",
            "k8s-force-delete",
            "k8s-proxy",
            "k8s-run-privileged",
            "k8s-subprocess-list",
            "rsh-guard-flag-file",
            "rsh-protect-config-access",
            "rsh-protect-disable",
            "rsh-protect-forbid-remove",
            "rsh-self-disable",
            "sql-alter-table",
            "sql-create-ddl",
            "sql-delete",
            "sql-drop",
            "sql-truncate",
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
    fn blocks_rsh_forbid_remove() {
        assert!(blocks("rsh forbid remove cluster prod"));
        assert!(blocks("rsh forbid remove namespace default"));
        assert!(blocks("rsh forbid remove database db.example.com"));
        // list and add must not be blocked
        assert!(!blocks("rsh forbid list"));
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
}
