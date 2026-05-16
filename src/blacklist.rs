use crate::aliases::{self, AliasMap};
use regex::Regex;
use std::sync::LazyLock;

pub struct Rule {
    pub id: &'static str,
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

/// `(id, bin, sub_pattern, reason)`
/// - If `bin` is `Some(name)`, the regex is built as
///   `\b(?:name|alias1|alias2|...)\b<sub_pattern>` using aliases loaded
///   from the user's alias config.
/// - If `bin` is `None`, the sub-pattern is used as-is.
const RAW_RULES: &[(&str, Option<&str>, &str, &str)] = &[
    (
        "k8s-delete-namespace",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdelete\s+(ns|namespace|namespaces)\b",
        "Deletes a Kubernetes namespace and cascades through all of its resources",
    ),
    (
        "k8s-delete-all",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdelete\s+\S+[^|;&\n]*?--all\b",
        "Deletes all resources of a kind — high blast radius",
    ),
    (
        "k8s-delete-crd",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdelete\s+(crd|crds|customresourcedefinition|customresourcedefinitions)\b",
        "Deletes a CustomResourceDefinition and every instance of it cluster-wide",
    ),
    (
        "k8s-force-delete",
        Some("kubectl"),
        r"\s[^|;&\n]*?\bdelete\b(?:[^|;&\n]*--force\b[^|;&\n]*--grace-period=0|[^|;&\n]*--grace-period=0\b[^|;&\n]*--force)",
        "Force-deletes a resource without cleanup hooks; can leave orphans and corrupt state",
    ),
];

static ALIASES: LazyLock<AliasMap> = LazyLock::new(aliases::load);

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    RAW_RULES
        .iter()
        .map(|(id, bin, sub, reason)| {
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

    #[test]
    fn allows_safe_kubectl() {
        assert!(!blocks("kubectl get pods"));
        assert!(!blocks("kubectl apply -f deployment.yaml"));
        assert!(!blocks("kubectl delete pod single-pod"));
        assert!(!blocks("kubectl describe namespace prod"));
    }

    #[test]
    fn allows_unrelated_commands() {
        assert!(!blocks("ls -la"));
        assert!(!blocks("git status"));
        assert!(!blocks("cargo run"));
    }
}
