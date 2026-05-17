#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub rule_id: String,
    /// Full human-readable block message (everything after "rsh blocked: ")
    pub message: String,
}

pub trait ToolChecker: Send + Sync {
    /// Binary names (including aliases) that indicate this checker is relevant.
    /// An empty vec means "always run" (e.g. FallbackChecker).
    fn bins(&self) -> Vec<String>;
    /// Check `content` (a command string or script file contents) for violations.
    fn check(&self, content: &str) -> Option<Hit>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Segment {
    Script { path: String },
    Direct { command: String },
}

pub fn split_segments(command: &str) -> Vec<Segment> {
    command
        .split(|c| c == ';' || c == '\n')
        .flat_map(|s| s.split("&&"))
        .flat_map(|s| s.split("||"))
        .flat_map(|s| s.split('|'))
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(|fragment| {
            if let Some(path) = extract_script_path(fragment) {
                Segment::Script { path }
            } else {
                Segment::Direct { command: fragment.to_string() }
            }
        })
        .collect()
}

const INTERPRETERS: &[&str] = &[
    "bash", "sh", "zsh", "ksh", "dash", "fish",
    "python", "python3", "perl", "ruby", "node", "nodejs",
];

fn extract_script_path(cmd: &str) -> Option<String> {
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let first = *tokens.first()?;
    let basename = std::path::Path::new(first)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(first);

    if INTERPRETERS.contains(&basename) {
        return tokens
            .iter()
            .skip(1)
            .find(|t| !t.starts_with('-'))
            .map(|s| strip_quotes(s));
    }

    if first == "source" || first == "." {
        return tokens.get(1).map(|s| strip_quotes(s));
    }

    let unquoted = strip_quotes(first);
    if unquoted.starts_with("./")
        || unquoted.starts_with('/')
        || unquoted.ends_with(".sh")
        || unquoted.ends_with(".bash")
    {
        return Some(unquoted);
    }

    None
}

fn strip_quotes(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"'))
        || (s.starts_with('\'') && s.ends_with('\''))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

use crate::{aliases, blacklist, forbid};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub struct KubectlChecker;

impl ToolChecker for KubectlChecker {
    fn bins(&self) -> Vec<String> {
        aliases::aliases_for(&aliases::ALIASES, "kubectl")
    }

    fn check(&self, content: &str) -> Option<Hit> {
        if let Some(h) = blacklist::check_for_bin(content, Some("kubectl")) {
            return Some(Hit {
                rule_id: h.id.to_string(),
                message: format!("(rule: {}): {}", h.id, h.reason),
            });
        }
        let cfg = forbid::load();
        if cfg.is_empty() {
            return None;
        }
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(h) =
                forbid::check_with(line, &aliases::ALIASES, &cfg, &forbid::KubectlEnv)
            {
                let origin =
                    if h.from_current_context { " (current kubeconfig)" } else { "" };
                let (rule_id, message) = match &h.kind {
                    forbid::HitKind::Cluster => (
                        "forbid-cluster".to_string(),
                        format!("forbidden cluster '{}'{origin}", h.value),
                    ),
                    forbid::HitKind::Namespace => (
                        "forbid-namespace".to_string(),
                        format!("forbidden namespace '{}'{origin}", h.value),
                    ),
                    forbid::HitKind::Database => (
                        "forbid-database".to_string(),
                        format!("forbidden database host '{}'", h.value),
                    ),
                };
                return Some(Hit { rule_id, message });
            }
        }
        None
    }
}

pub struct HelmChecker;

impl ToolChecker for HelmChecker {
    fn bins(&self) -> Vec<String> {
        aliases::aliases_for(&aliases::ALIASES, "helm")
    }

    fn check(&self, content: &str) -> Option<Hit> {
        if let Some(h) = blacklist::check_for_bin(content, Some("helm")) {
            return Some(Hit {
                rule_id: h.id.to_string(),
                message: format!("(rule: {}): {}", h.id, h.reason),
            });
        }
        let cfg = forbid::load();
        if cfg.is_empty() {
            return None;
        }
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(h) =
                forbid::check_with(line, &aliases::ALIASES, &cfg, &forbid::KubectlEnv)
            {
                let origin =
                    if h.from_current_context { " (current kubeconfig)" } else { "" };
                let (rule_id, message) = match &h.kind {
                    forbid::HitKind::Cluster => (
                        "forbid-cluster".to_string(),
                        format!("forbidden cluster '{}'{origin}", h.value),
                    ),
                    forbid::HitKind::Namespace => (
                        "forbid-namespace".to_string(),
                        format!("forbidden namespace '{}'{origin}", h.value),
                    ),
                    forbid::HitKind::Database => (
                        "forbid-database".to_string(),
                        format!("forbidden database host '{}'", h.value),
                    ),
                };
                return Some(Hit { rule_id, message });
            }
        }
        None
    }
}

pub struct DockerChecker;

impl ToolChecker for DockerChecker {
    fn bins(&self) -> Vec<String> {
        let mut b = aliases::aliases_for(&aliases::ALIASES, "docker");
        b.extend(aliases::aliases_for(&aliases::ALIASES, "docker-compose"));
        b.sort();
        b.dedup();
        b
    }

    fn check(&self, content: &str) -> Option<Hit> {
        if let Some(h) = blacklist::check_for_bin(content, Some("docker"))
            .or_else(|| blacklist::check_for_bin(content, Some("docker-compose")))
        {
            return Some(Hit {
                rule_id: h.id.to_string(),
                message: format!("(rule: {}): {}", h.id, h.reason),
            });
        }
        None
    }
}

pub struct RshChecker;

impl ToolChecker for RshChecker {
    fn bins(&self) -> Vec<String> {
        aliases::aliases_for(&aliases::ALIASES, "rsh")
    }

    fn check(&self, content: &str) -> Option<Hit> {
        blacklist::check_for_bin(content, Some("rsh")).map(|h| Hit {
            rule_id: h.id.to_string(),
            message: format!("(rule: {}): {}", h.id, h.reason),
        })
    }
}

pub struct FallbackChecker;

impl ToolChecker for FallbackChecker {
    fn bins(&self) -> Vec<String> {
        vec![]
    }

    fn check(&self, content: &str) -> Option<Hit> {
        if let Some(h) = blacklist::check_for_bin(content, None) {
            return Some(Hit {
                rule_id: h.id.to_string(),
                message: format!("(rule: {}): {}", h.id, h.reason),
            });
        }
        let cfg = forbid::load();
        if cfg.is_empty() {
            return None;
        }
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(h) = forbid::check_db(line, &cfg) {
                return Some(Hit {
                    rule_id: "forbid-database".to_string(),
                    message: format!("forbidden database host '{}'", h.value),
                });
            }
        }
        None
    }
}

pub fn detect_checkers(content: &str) -> Vec<Box<dyn ToolChecker>> {
    let candidates: Vec<Box<dyn ToolChecker>> = vec![
        Box::new(FallbackChecker),
        Box::new(KubectlChecker),
        Box::new(HelmChecker),
        Box::new(DockerChecker),
        Box::new(RshChecker),
    ];
    candidates
        .into_iter()
        .filter(|c| {
            let bins = c.bins();
            bins.is_empty() || bins.iter().any(|b| content.contains(b.as_str()))
        })
        .collect()
}

pub fn run_parallel_checks(segments: Vec<Segment>) -> Option<Hit> {
    use std::sync::mpsc;
    use std::thread;

    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Hit>();

    for segment in segments {
        let content: String = match segment {
            Segment::Direct { command } => command,
            Segment::Script { path } => match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            },
        };
        let checkers = detect_checkers(&content);
        for checker in checkers {
            let stop = stop.clone();
            let tx = tx.clone();
            let content = content.clone();
            thread::spawn(move || {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                if let Some(hit) = checker.check(&content) {
                    stop.store(true, Ordering::Relaxed);
                    let _ = tx.send(hit);
                }
            });
        }
    }
    drop(tx);
    rx.recv().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kubectl_checker_blocks_delete_namespace() {
        let hit = KubectlChecker.check("kubectl delete ns production");
        assert!(hit.is_some());
        assert!(hit.unwrap().rule_id.contains("k8s-delete-namespace"));
    }

    #[test]
    fn kubectl_checker_allows_safe_command() {
        assert!(KubectlChecker.check("kubectl get pods").is_none());
    }

    #[test]
    fn kubectl_checker_bins_contains_kubectl() {
        assert!(KubectlChecker.bins().iter().any(|b| b == "kubectl"));
    }

    fn direct(cmd: &str) -> Segment {
        Segment::Direct { command: cmd.to_string() }
    }
    fn script(path: &str) -> Segment {
        Segment::Script { path: path.to_string() }
    }

    #[test]
    fn split_direct_only() {
        assert_eq!(split_segments("kubectl get pods"), vec![direct("kubectl get pods")]);
    }

    #[test]
    fn split_detects_bash_script() {
        assert_eq!(
            split_segments("bash /tmp/deploy.sh"),
            vec![script("/tmp/deploy.sh")]
        );
    }

    #[test]
    fn split_detects_dot_slash_script() {
        assert_eq!(split_segments("./setup.sh"), vec![script("./setup.sh")]);
    }

    #[test]
    fn split_mixed_command() {
        assert_eq!(
            split_segments("kubectl apply -f config.yaml && ./deploy.sh"),
            vec![
                direct("kubectl apply -f config.yaml"),
                script("./deploy.sh"),
            ]
        );
    }

    #[test]
    fn split_semicolon_separator() {
        assert_eq!(
            split_segments("echo start; bash setup.sh; echo done"),
            vec![
                direct("echo start"),
                script("setup.sh"),
                direct("echo done"),
            ]
        );
    }

    #[test]
    fn split_newline_separator() {
        assert_eq!(
            split_segments("git status\n./run.sh\necho bye"),
            vec![
                direct("git status"),
                script("./run.sh"),
                direct("echo bye"),
            ]
        );
    }

    #[test]
    fn split_skips_empty_and_comment_segments() {
        let segs = split_segments("# comment\n\nkubectl get pods");
        assert_eq!(segs, vec![direct("kubectl get pods")]);
    }

    #[test]
    fn split_source_dot() {
        assert_eq!(
            split_segments("source /etc/profile"),
            vec![script("/etc/profile")]
        );
        assert_eq!(
            split_segments(". ~/.bashrc"),
            vec![script("~/.bashrc")]
        );
    }

    #[test]
    fn split_quoted_script_path() {
        assert_eq!(
            split_segments("bash \"/tmp/deploy.sh\""),
            vec![script("/tmp/deploy.sh")]
        );
    }

    #[test]
    fn split_pipe_separator() {
        assert_eq!(
            split_segments("cat file.txt | bash /tmp/process.sh"),
            vec![
                direct("cat file.txt"),
                script("/tmp/process.sh"),
            ]
        );
    }

    #[test]
    fn helm_checker_blocks_uninstall() {
        let hit = HelmChecker.check("helm uninstall postgres");
        assert!(hit.is_some());
        assert!(hit.unwrap().rule_id.contains("helm-uninstall"));
    }

    #[test]
    fn helm_checker_allows_safe_command() {
        assert!(HelmChecker.check("helm list").is_none());
        assert!(HelmChecker.check("helm upgrade postgres bitnami/postgresql").is_none());
    }

    #[test]
    fn helm_checker_bins_contains_helm() {
        assert!(HelmChecker.bins().iter().any(|b| b == "helm"));
    }

    #[test]
    fn docker_checker_blocks_volume_rm() {
        let hit = DockerChecker.check("docker volume rm mydata");
        assert!(hit.is_some());
        assert!(hit.unwrap().rule_id.contains("docker-volume-rm"));
    }

    #[test]
    fn docker_checker_blocks_compose_legacy_down() {
        let hit = DockerChecker.check("docker-compose down");
        assert!(hit.is_some());
    }

    #[test]
    fn docker_checker_allows_safe_command() {
        assert!(DockerChecker.check("docker ps").is_none());
        assert!(DockerChecker.check("docker build -t myimage .").is_none());
    }

    #[test]
    fn docker_checker_bins_contains_docker() {
        assert!(DockerChecker.bins().iter().any(|b| b == "docker"));
    }

    #[test]
    fn fallback_checker_blocks_sql_delete() {
        let hit = FallbackChecker.check(r#"psql -c "DELETE FROM users""#);
        assert!(hit.is_some());
        assert!(hit.unwrap().rule_id.contains("sql-delete"));
    }

    #[test]
    fn fallback_checker_blocks_subprocess_kubectl_delete() {
        let hit = FallbackChecker.check("subprocess.run(['kubectl', 'delete', 'ns', 'prod'])");
        assert!(hit.is_some());
    }

    #[test]
    fn fallback_checker_bins_is_empty() {
        assert!(FallbackChecker.bins().is_empty());
    }

    #[test]
    fn rsh_checker_blocks_rule_disable() {
        let hit = RshChecker.check("rsh rule disable k8s-delete-namespace");
        assert!(hit.is_some());
    }

    #[test]
    fn rsh_checker_allows_rule_list() {
        assert!(RshChecker.check("rsh rule list").is_none());
    }

    #[test]
    fn rsh_checker_bins_contains_rsh() {
        assert!(RshChecker.bins().iter().any(|b| b == "rsh"));
    }

    #[test]
    fn detect_checkers_returns_fallback_always() {
        let checkers = detect_checkers("ls -la");
        assert!(checkers.iter().any(|c| c.bins().is_empty())); // FallbackChecker present
    }

    #[test]
    fn detect_checkers_returns_kubectl_when_present() {
        let checkers = detect_checkers("kubectl delete ns prod");
        assert!(checkers.iter().any(|c| c.bins().iter().any(|b| b == "kubectl")));
    }

    #[test]
    fn detect_checkers_does_not_return_kubectl_for_helm_only() {
        let checkers = detect_checkers("helm list");
        assert!(!checkers.iter().any(|c| c.bins().iter().any(|b| b == "kubectl")));
    }

    #[test]
    fn detect_checkers_returns_both_for_mixed_content() {
        let checkers = detect_checkers("kubectl get pods\nhelm list");
        assert!(checkers.iter().any(|c| c.bins().iter().any(|b| b == "kubectl")));
        assert!(checkers.iter().any(|c| c.bins().iter().any(|b| b == "helm")));
    }

    #[test]
    fn detect_checkers_returns_docker_when_present() {
        let checkers = detect_checkers("docker volume rm mydata");
        assert!(checkers.iter().any(|c| c.bins().iter().any(|b| b == "docker")));
    }

    #[test]
    fn run_parallel_checks_returns_hit_for_blocked_command() {
        let segs = vec![Segment::Direct {
            command: "kubectl delete ns prod".to_string(),
        }];
        let hit = run_parallel_checks(segs);
        assert!(hit.is_some());
        assert!(hit.unwrap().rule_id.contains("k8s-delete-namespace"));
    }

    #[test]
    fn run_parallel_checks_returns_none_for_safe_command() {
        let segs = vec![Segment::Direct {
            command: "kubectl get pods".to_string(),
        }];
        assert!(run_parallel_checks(segs).is_none());
    }

    #[test]
    fn run_parallel_checks_detects_hit_in_mixed_segments() {
        let segs = vec![
            Segment::Direct {
                command: "kubectl get pods".to_string(),
            },
            Segment::Direct {
                command: "helm uninstall postgres".to_string(),
            },
        ];
        assert!(run_parallel_checks(segs).is_some());
    }

    #[test]
    fn run_parallel_checks_skips_unreadable_script() {
        let segs = vec![Segment::Script {
            path: "/nonexistent/script.sh".to_string(),
        }];
        assert!(run_parallel_checks(segs).is_none());
    }
}
