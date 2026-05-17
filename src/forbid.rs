//! Forbidden-cluster / forbidden-namespace check.
//!
//! Separate from the regex blacklist: rather than matching on the surface
//! syntax of a command, this module inspects the *target* of a kubectl- or
//! helm-aliased command (which cluster + namespace it would hit) and blocks
//! it if either is on the user's forbid list.
//!
//! Configuration lives in `~/.config/rsh/forbidden.json` (or the platform
//! equivalent, mirroring `aliases::config_path`) as:
//!
//! ```json
//! { "clusters": ["my-prod-eu"], "namespaces": ["kube-system"], "databases": ["prod-db.example.com"] }
//! ```

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;
use std::sync::LazyLock;

use crate::aliases::{self, AliasMap};

static FORBID_TOKENS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut tokens = Vec::new();
    for tool in TOOLS {
        tokens.extend(aliases::aliases_for(&aliases::ALIASES, tool.bin_key));
    }
    for &client in SQL_CLIENTS {
        tokens.extend(aliases::aliases_for(&aliases::ALIASES, client));
    }
    tokens.sort();
    tokens.dedup();
    tokens
});

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ForbidConfig {
    #[serde(default)]
    pub clusters: Vec<String>,
    #[serde(default)]
    pub namespaces: Vec<String>,
    #[serde(default)]
    pub databases: Vec<String>,
}

impl ForbidConfig {
    pub fn is_empty(&self) -> bool {
        self.clusters.is_empty() && self.namespaces.is_empty() && self.databases.is_empty()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum HitKind {
    Cluster,
    Namespace,
    Database,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Hit {
    pub kind: HitKind,
    pub value: String,
    /// True when the value came from the live kubeconfig (no explicit flag),
    /// false when it was extracted directly from the command-line flag.
    pub from_current_context: bool,
}

/// One tool we know how to inspect.
struct ToolSpec {
    /// Key into the alias map (and the basename of the canonical binary).
    bin_key: &'static str,
    context_flags: &'static [&'static str],
    namespace_flags: &'static [&'static str],
}

const TOOLS: &[ToolSpec] = &[
    ToolSpec {
        bin_key: "kubectl",
        context_flags: &["--context"],
        namespace_flags: &["--namespace", "-n"],
    },
    ToolSpec {
        bin_key: "helm",
        context_flags: &["--kube-context"],
        namespace_flags: &["--namespace", "-n"],
    },
];

// ---- config persistence -------------------------------------------------

pub fn config_path() -> Result<PathBuf> {
    let base = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else if cfg!(windows) {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            PathBuf::from(appdata)
        } else {
            aliases::home_dir()
                .context("could not determine home directory")?
                .join(".config")
        }
    } else {
        aliases::home_dir()
            .context("could not determine home directory")?
            .join(".config")
    };
    Ok(base.join("rsh").join("forbidden.json"))
}

pub fn load() -> ForbidConfig {
    let path = match config_path() {
        Ok(p) => p,
        Err(_) => return ForbidConfig::default(),
    };
    if !path.exists() {
        return ForbidConfig::default();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn save(cfg: &ForbidConfig) -> Result<PathBuf> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(cfg)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

pub fn add_cluster(name: &str) -> Result<bool> {
    let mut cfg = load();
    if cfg.clusters.iter().any(|c| c == name) {
        return Ok(false);
    }
    cfg.clusters.push(name.to_string());
    save(&cfg)?;
    Ok(true)
}

pub fn add_namespace(name: &str) -> Result<bool> {
    let mut cfg = load();
    if cfg.namespaces.iter().any(|n| n == name) {
        return Ok(false);
    }
    cfg.namespaces.push(name.to_string());
    save(&cfg)?;
    Ok(true)
}

pub fn remove_cluster(name: &str) -> Result<bool> {
    let mut cfg = load();
    let before = cfg.clusters.len();
    cfg.clusters.retain(|c| c != name);
    let changed = cfg.clusters.len() != before;
    if changed {
        save(&cfg)?;
    }
    Ok(changed)
}

pub fn remove_namespace(name: &str) -> Result<bool> {
    let mut cfg = load();
    let before = cfg.namespaces.len();
    cfg.namespaces.retain(|n| n != name);
    let changed = cfg.namespaces.len() != before;
    if changed {
        save(&cfg)?;
    }
    Ok(changed)
}

pub fn add_database(host: &str) -> Result<bool> {
    let mut cfg = load();
    if cfg.databases.iter().any(|d| d == host) {
        return Ok(false);
    }
    cfg.databases.push(host.to_string());
    save(&cfg)?;
    Ok(true)
}

pub fn remove_database(host: &str) -> Result<bool> {
    let mut cfg = load();
    let before = cfg.databases.len();
    cfg.databases.retain(|d| d != host);
    let changed = cfg.databases.len() != before;
    if changed {
        save(&cfg)?;
    }
    Ok(changed)
}

// ---- check pipeline -----------------------------------------------------

/// Pluggable lookup for the live kubeconfig context/namespace, so tests can
/// avoid shelling out to a real `kubectl`.
pub trait KubeEnv {
    fn current_context(&self) -> Option<String>;
    fn current_namespace(&self) -> Option<String>;
}

/// Default implementation: shells out to `kubectl config ...`.
pub struct KubectlEnv;

impl KubeEnv for KubectlEnv {
    fn current_context(&self) -> Option<String> {
        let out = Command::new("kubectl")
            .args(["config", "current-context"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    }

    fn current_namespace(&self) -> Option<String> {
        let out = Command::new("kubectl")
            .args([
                "config",
                "view",
                "--minify",
                "-o",
                "jsonpath={..namespace}",
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // Empty string means the context has no namespace pinned: the
        // implicit namespace is "default".
        Some(if s.is_empty() { "default".to_string() } else { s })
    }
}

/// Default check used by the hook. Uses the process-wide alias cache, the
/// on-disk forbid config, and live `kubectl` for fallback lookups.
pub fn check(command: &str) -> Option<Hit> {
    if !FORBID_TOKENS.iter().any(|t| command.contains(t.as_str())) {
        return None;
    }
    let cfg = load();
    if cfg.is_empty() {
        return None;
    }
    check_with(command, &aliases::ALIASES, &cfg, &KubectlEnv)
        .or_else(|| check_db(command, &cfg))
}

/// Inner check that's pure (no globals, no I/O) when `env` is a mock —
/// makes the logic unit-testable.
pub fn check_with(
    command: &str,
    aliases: &AliasMap,
    cfg: &ForbidConfig,
    env: &dyn KubeEnv,
) -> Option<Hit> {
    if cfg.is_empty() {
        return None;
    }

    let tool = match identify_tool(command, aliases) {
        Some(t) => t,
        None => return None,
    };

    let explicit_context = extract_flag(command, tool.context_flags);
    let explicit_namespace = extract_flag(command, tool.namespace_flags);

    // Explicit-flag matches first.
    if let Some(ctx) = &explicit_context {
        if cfg.clusters.iter().any(|c| c == ctx) {
            return Some(Hit {
                kind: HitKind::Cluster,
                value: ctx.clone(),
                from_current_context: false,
            });
        }
    }
    if let Some(ns) = &explicit_namespace {
        if cfg.namespaces.iter().any(|n| n == ns) {
            return Some(Hit {
                kind: HitKind::Namespace,
                value: ns.clone(),
                from_current_context: false,
            });
        }
    }

    // Fall back to current kubeconfig values for whatever the user did NOT
    // pin explicitly. Skip the subprocess entirely if the corresponding
    // list is empty.
    if explicit_context.is_none() && !cfg.clusters.is_empty() {
        if let Some(current) = env.current_context() {
            if cfg.clusters.iter().any(|c| c == &current) {
                return Some(Hit {
                    kind: HitKind::Cluster,
                    value: current,
                    from_current_context: true,
                });
            }
        }
    }
    if explicit_namespace.is_none() && !cfg.namespaces.is_empty() {
        if let Some(current) = env.current_namespace() {
            if cfg.namespaces.iter().any(|n| n == &current) {
                return Some(Hit {
                    kind: HitKind::Namespace,
                    value: current,
                    from_current_context: true,
                });
            }
        }
    }

    None
}

// ---- database check -----------------------------------------------------

// sqlite3 doesn't use -h/--host or connection URLs; check_db always
// returns None for it. Listed for future-proofing.
const SQL_CLIENTS: &[&str] = &["mysql", "mariadb", "psql", "sqlite3", "sqlcmd", "mssql-cli"];

fn extract_db_host(command: &str) -> Option<String> {
    static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?:postgresql|postgres|mysql|mariadb|sqlserver|mssql)://(?:[^@/\s]+@)?([^/:?\s]+)",
        )
        .expect("valid regex")
    });
    if let Some(caps) = URL_RE.captures(command) {
        if let Some(host) = caps.get(1).map(|m| m.as_str().to_string()) {
            if !host.is_empty() {
                return Some(host);
            }
        }
    }
    extract_flag(command, &["-h", "--host"])
}

/// Checks whether a SQL client command targets a forbidden database hostname.
pub fn check_db(command: &str, cfg: &ForbidConfig) -> Option<Hit> {
    if cfg.databases.is_empty() {
        return None;
    }
    let first = command.split_whitespace().next()?;
    let basename = std::path::Path::new(first)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(first);
    let basename = basename
        .strip_suffix(".exe")
        .or_else(|| basename.strip_suffix(".EXE"))
        .unwrap_or(basename);
    // Known limitation: `env VAR=val psql ...` and inline var assignments
    // (`PGPASSWORD=x psql ...`) bypass this check because the first token is
    // not the SQL client binary. This mirrors the existing kubectl/helm bypass
    // for the same pattern and is an accepted trade-off.
    if !SQL_CLIENTS.contains(&basename) {
        return None;
    }
    let host = extract_db_host(command)?;
    if cfg.databases.iter().any(|d| d.eq_ignore_ascii_case(&host)) {
        Some(Hit {
            kind: HitKind::Database,
            value: host,
            from_current_context: false,
        })
    } else {
        None
    }
}

// ---- helpers ------------------------------------------------------------

fn identify_tool<'a>(command: &str, aliases: &AliasMap) -> Option<&'a ToolSpec> {
    let first = command.split_whitespace().next()?;
    // Allow both bare names and absolute paths like /usr/local/bin/kubectl.
    let basename = std::path::Path::new(first)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(first);
    // Strip a Windows .exe suffix so detection works across platforms.
    let basename = basename
        .strip_suffix(".exe")
        .or_else(|| basename.strip_suffix(".EXE"))
        .unwrap_or(basename);

    for tool in TOOLS {
        let names = aliases::aliases_for(aliases, tool.bin_key);
        if names.iter().any(|n| n == basename) {
            return Some(tool);
        }
    }
    None
}

/// Extracts the value of a flag from a command string. Recognises both the
/// `--flag=value` and `--flag value` (space-separated) forms. Returns the
/// first match wins.
fn extract_flag(command: &str, flags: &[&str]) -> Option<String> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i];
        for flag in flags {
            let with_eq = format!("{flag}=");
            if let Some(rest) = tok.strip_prefix(&with_eq) {
                if !rest.is_empty() {
                    return Some(rest.to_string());
                }
            }
            if tok == *flag {
                if let Some(next) = tokens.get(i + 1) {
                    return Some(next.to_string());
                }
            }
        }
        i += 1;
    }
    None
}

// ---- tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Helper: build an alias map where only the bin_key itself is known
    /// (no aliases), so identify_tool only matches the canonical name.
    fn empty_aliases() -> AliasMap {
        BTreeMap::new()
    }

    /// KubeEnv mock for tests.
    struct StaticEnv {
        ctx: Option<String>,
        ns: Option<String>,
    }
    impl KubeEnv for StaticEnv {
        fn current_context(&self) -> Option<String> {
            self.ctx.clone()
        }
        fn current_namespace(&self) -> Option<String> {
            self.ns.clone()
        }
    }

    fn no_kube() -> StaticEnv {
        StaticEnv {
            ctx: None,
            ns: None,
        }
    }

    fn cfg_clusters(names: &[&str]) -> ForbidConfig {
        ForbidConfig {
            clusters: names.iter().map(|s| s.to_string()).collect(),
            namespaces: vec![],
            databases: vec![],
        }
    }
    fn cfg_namespaces(names: &[&str]) -> ForbidConfig {
        ForbidConfig {
            clusters: vec![],
            namespaces: names.iter().map(|s| s.to_string()).collect(),
            databases: vec![],
        }
    }

    fn cfg_databases(hosts: &[&str]) -> ForbidConfig {
        ForbidConfig {
            clusters: vec![],
            namespaces: vec![],
            databases: hosts.iter().map(|s| s.to_string()).collect(),
        }
    }

    // ---- check_db ----

    #[test]
    fn check_db_blocks_connection_url() {
        let cfg = cfg_databases(&["prod-db.example.com"]);
        assert!(check_db("psql postgresql://prod-db.example.com/mydb", &cfg).is_some());
        assert!(check_db("mysql mysql://prod-db.example.com:3306/app", &cfg).is_some());
    }

    #[test]
    fn check_db_blocks_url_with_userinfo() {
        let cfg = cfg_databases(&["prod-db.example.com"]);
        assert!(check_db(
            "psql postgresql://user:secret@prod-db.example.com/mydb",
            &cfg
        )
        .is_some());
    }

    #[test]
    fn check_db_blocks_host_flag_space_form() {
        let cfg = cfg_databases(&["prod-db.example.com"]);
        assert!(check_db("psql -h prod-db.example.com -U user mydb", &cfg).is_some());
        assert!(check_db("mysql -h prod-db.example.com mydb", &cfg).is_some());
    }

    #[test]
    fn check_db_blocks_host_flag_equals_form() {
        let cfg = cfg_databases(&["prod-db.example.com"]);
        assert!(check_db("psql --host=prod-db.example.com mydb", &cfg).is_some());
    }

    #[test]
    fn check_db_allows_non_forbidden_host() {
        let cfg = cfg_databases(&["prod-db.example.com"]);
        assert!(check_db("psql -h staging-db.example.com mydb", &cfg).is_none());
        assert!(check_db("psql postgresql://staging-db.example.com/mydb", &cfg).is_none());
    }

    #[test]
    fn check_db_allows_sql_client_without_host() {
        let cfg = cfg_databases(&["prod-db.example.com"]);
        assert!(check_db("psql mydbname", &cfg).is_none());
    }

    #[test]
    fn check_db_skips_non_sql_client_commands() {
        let cfg = cfg_databases(&["prod-db.example.com"]);
        assert!(check_db("grep prod-db.example.com /etc/hosts", &cfg).is_none());
        assert!(check_db("curl http://prod-db.example.com/api", &cfg).is_none());
    }

    #[test]
    fn check_db_returns_database_hit_kind() {
        let cfg = cfg_databases(&["prod-db.example.com"]);
        let hit = check_db("psql -h prod-db.example.com mydb", &cfg).unwrap();
        assert_eq!(hit.kind, HitKind::Database);
        assert_eq!(hit.value, "prod-db.example.com");
        assert!(!hit.from_current_context);
    }

    // ---- extract_flag ----

    #[test]
    fn extract_flag_handles_equals_form() {
        let cmd = "kubectl --context=prod-eu get pods";
        assert_eq!(
            extract_flag(cmd, &["--context"]),
            Some("prod-eu".to_string())
        );
    }

    #[test]
    fn extract_flag_handles_space_form() {
        let cmd = "kubectl --context prod-eu get pods";
        assert_eq!(
            extract_flag(cmd, &["--context"]),
            Some("prod-eu".to_string())
        );
    }

    #[test]
    fn extract_flag_handles_short_namespace_form() {
        let cmd = "kubectl get pods -n kube-system";
        assert_eq!(
            extract_flag(cmd, &["--namespace", "-n"]),
            Some("kube-system".to_string())
        );
    }

    #[test]
    fn extract_flag_returns_none_when_absent() {
        let cmd = "kubectl get pods";
        assert!(extract_flag(cmd, &["--context"]).is_none());
    }

    // ---- tool identification ----

    #[test]
    fn identifies_kubectl_with_absolute_path() {
        let cmd = "/usr/local/bin/kubectl get pods";
        assert!(identify_tool(cmd, &empty_aliases()).is_some());
    }

    #[test]
    fn ignores_non_k8s_commands() {
        let cmd = "ls -la";
        assert!(identify_tool(cmd, &empty_aliases()).is_none());
    }

    #[test]
    fn identifies_aliased_kubectl() {
        let mut a = empty_aliases();
        a.insert("kubectl".into(), vec!["k".into()]);
        assert!(identify_tool("k get pods", &a).is_some());
        assert!(identify_tool("kubectl get pods", &a).is_some());
    }

    // ---- explicit-flag blocking ----

    #[test]
    fn blocks_when_context_flag_is_forbidden() {
        let cfg = cfg_clusters(&["prod-eu"]);
        let hit = check_with(
            "kubectl --context=prod-eu get pods",
            &empty_aliases(),
            &cfg,
            &no_kube(),
        )
        .expect("should block");
        assert_eq!(hit.kind, HitKind::Cluster);
        assert_eq!(hit.value, "prod-eu");
        assert!(!hit.from_current_context);
    }

    #[test]
    fn blocks_when_namespace_flag_is_forbidden() {
        let cfg = cfg_namespaces(&["kube-system"]);
        let hit = check_with(
            "kubectl -n kube-system get pods",
            &empty_aliases(),
            &cfg,
            &no_kube(),
        )
        .expect("should block");
        assert_eq!(hit.kind, HitKind::Namespace);
        assert_eq!(hit.value, "kube-system");
    }

    #[test]
    fn allows_when_explicit_context_not_forbidden() {
        let cfg = cfg_clusters(&["prod-eu"]);
        assert!(check_with(
            "kubectl --context=staging get pods",
            &empty_aliases(),
            &cfg,
            &no_kube()
        )
        .is_none());
    }

    // ---- implicit-context blocking via kube env ----

    #[test]
    fn blocks_when_current_context_is_forbidden_and_no_flag() {
        let cfg = cfg_clusters(&["prod-eu"]);
        let env = StaticEnv {
            ctx: Some("prod-eu".into()),
            ns: None,
        };
        let hit = check_with("kubectl get pods", &empty_aliases(), &cfg, &env)
            .expect("should block via current-context");
        assert_eq!(hit.kind, HitKind::Cluster);
        assert!(hit.from_current_context);
    }

    #[test]
    fn explicit_flag_overrides_implicit_current_context() {
        // Even if the kubeconfig points at prod, an explicit --context to a
        // non-forbidden cluster should NOT trigger the current-context fallback.
        let cfg = cfg_clusters(&["prod-eu"]);
        let env = StaticEnv {
            ctx: Some("prod-eu".into()),
            ns: None,
        };
        assert!(check_with(
            "kubectl --context=staging get pods",
            &empty_aliases(),
            &cfg,
            &env
        )
        .is_none());
    }

    #[test]
    fn blocks_when_current_namespace_is_forbidden() {
        let cfg = cfg_namespaces(&["kube-system"]);
        let env = StaticEnv {
            ctx: None,
            ns: Some("kube-system".into()),
        };
        let hit = check_with("kubectl get pods", &empty_aliases(), &cfg, &env)
            .expect("should block");
        assert_eq!(hit.kind, HitKind::Namespace);
        assert!(hit.from_current_context);
    }

    #[test]
    fn empty_config_is_a_no_op() {
        let cfg = ForbidConfig::default();
        let env = StaticEnv {
            ctx: Some("prod-eu".into()),
            ns: Some("kube-system".into()),
        };
        assert!(check_with(
            "kubectl --context=prod-eu -n kube-system get pods",
            &empty_aliases(),
            &cfg,
            &env
        )
        .is_none());
    }

    #[test]
    fn helm_uses_kube_context_flag() {
        let cfg = cfg_clusters(&["prod-eu"]);
        let hit = check_with(
            "helm --kube-context=prod-eu list",
            &empty_aliases(),
            &cfg,
            &no_kube(),
        )
        .expect("should block");
        assert_eq!(hit.value, "prod-eu");
    }

    #[test]
    fn forbid_config_databases_field_mutates_as_expected() {
        let mut cfg = ForbidConfig::default();
        cfg.databases.push("prod-db.example.com".to_string());
        assert_eq!(cfg.databases.len(), 1);
        cfg.databases.retain(|d| d != "prod-db.example.com");
        assert!(cfg.databases.is_empty());
    }

    #[test]
    fn forbid_config_is_empty_includes_databases() {
        assert!(ForbidConfig::default().is_empty());
        let cfg = ForbidConfig {
            clusters: vec![],
            namespaces: vec![],
            databases: vec!["prod-db.example.com".to_string()],
        };
        assert!(!cfg.is_empty());
    }

    #[test]
    fn check_returns_none_for_irrelevant_command() {
        // Early-exit: no tool token → load() is never reached.
        // Even if forbidden.json existed with entries, this must return None.
        assert!(check("ls -la /tmp").is_none());
        assert!(check("cargo build --release").is_none());
        assert!(check("echo hello world").is_none());
    }

    #[test]
    fn forbid_config_deserializes_without_databases_field() {
        let json = r#"{"clusters": ["prod-eu"], "namespaces": []}"#;
        let cfg: ForbidConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.databases.is_empty());
    }
}
