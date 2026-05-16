use crate::aliases::{self, ALIASES};
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
    // ---- SQL — Destructive DML ------------------------------------
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
        r"(?i)\bTRUNCATE\b",
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
        "sql-create-schema",
        "SQL — Destructive DDL",
        None,
        r"(?i)\bCREATE\s+(?:TABLE|DATABASE|SCHEMA)\b",
        "Creates a new database object — can permanently alter the schema",
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

pub fn rules() -> &'static [Rule] {
    &RULES
}

pub fn check(command: &str) -> Option<Hit> {
    for rule in RULES.iter() {
        if rule.regex.is_match(command) {
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
        assert!(blocks("kubectl delete persistentvolumeclaim bar -n staging"));
    }

    #[test]
    fn blocks_delete_clusterrole_and_binding() {
        assert!(blocks("kubectl delete clusterrole admin-helper"));
        assert!(blocks("kubectl delete clusterrolebinding cluster-admin-binding"));
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
        assert!(blocks(r#"sqlite3 app.db "truncate orders""#));
        assert!(!blocks(r#"mysql -e "INSERT INTO logs VALUES (1, 'ok')""#));
    }

    // ---- SQL — Destructive DDL ----

    #[test]
    fn blocks_sql_drop() {
        assert!(blocks(r#"psql -c "DROP TABLE IF EXISTS legacy""#));
        assert!(blocks(r#"mysql -e "drop database staging""#));
        assert!(blocks(r#"psql -c "DROP SCHEMA public""#));
        assert!(!blocks(r#"psql -c "CREATE INDEX idx ON users(email)""#));
    }

    #[test]
    fn blocks_sql_alter_table() {
        assert!(blocks(r#"psql -c "ALTER TABLE users ADD COLUMN email TEXT""#));
        assert!(blocks(r#"mysql -e "alter table orders drop column foo""#));
        assert!(!blocks(r#"sqlite3 app.db "UPDATE users SET name='x' WHERE id=1""#));
    }

    #[test]
    fn blocks_sql_create_schema() {
        assert!(blocks(r#"mysql -e "CREATE TABLE tmp (id INT)""#));
        assert!(blocks(r#"psql -c "CREATE DATABASE test_db""#));
        assert!(blocks(r#"psql -c "create schema analytics""#));
        assert!(!blocks(r#"psql -c "CREATE INDEX idx_email ON users(email)""#));
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

    // ---- Cross-check: rule IDs are stable ----

    #[test]
    fn rule_ids_are_distinct_and_match_expected_set() {
        let mut ids: Vec<&str> = rules().iter().map(|r| r.id).collect();
        ids.sort();
        let expected = vec![
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
            "sql-alter-table",
            "sql-create-schema",
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
        assert_eq!(
            hit_id("kubectl exec p -- bash"),
            Some("k8s-exec-shell")
        );
        assert_eq!(hit_id("helm uninstall foo"), Some("helm-uninstall"));
        assert_eq!(hit_id("kubectl proxy"), Some("k8s-proxy"));
    }
}
