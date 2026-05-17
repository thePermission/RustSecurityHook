# Tool-Checker Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the monolithic sequential check pipeline with a `ToolChecker` trait that encapsulates per-tool logic and runs checks in parallel threads with fail-fast behaviour.

**Architecture:** Commands and script file contents are split into `Segment`s; for each segment, `detect_checkers` returns the relevant `ToolChecker` instances; all checker threads share an `AtomicBool` stop-flag so the first hit cancels the rest. `KubectlChecker` and `HelmChecker` include the `forbid` (cluster/namespace) check; `FallbackChecker` covers bin=None blacklist rules and the database forbid check; `DockerChecker` and `RshChecker` cover their respective binary rules.

**Tech Stack:** Rust stable (edition 2024); `std::thread`, `std::sync::mpsc`, `std::sync::atomic::AtomicBool`; no new dependencies.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `src/checker.rs` | Create | `Segment`, `split_segments`, `Hit`, `ToolChecker` trait, all concrete checkers, `detect_checkers`, `run_parallel_checks` |
| `src/blacklist.rs` | Modify | Add `check_for_bin(content, bin)` |
| `src/lib.rs` | Modify | Add `pub mod checker`; rewrite `run_check` / `run_check_content`; remove `check_content_blocked`, `script_paths_in`, `extract_script_path`, `strip_quotes` and their tests |

---

## Task 1: `Segment` enum and `split_segments` in `src/checker.rs`

**Files:**
- Create: `src/checker.rs`

- [ ] **Step 1: Write failing tests**

Create `src/checker.rs` with the test module only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

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
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test split_ 2>&1 | head -20
```

Expected: compile error (`Segment` not defined).

- [ ] **Step 3: Implement `Segment` and `split_segments`**

Add before the test module in `src/checker.rs`:

```rust
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test split_ 2>&1
```

Expected: all `split_*` tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/checker.rs
git commit -m "feat: add Segment enum and split_segments to checker module"
```

---

## Task 2: `Hit` struct, `ToolChecker` trait, wire up `mod checker`

**Files:**
- Modify: `src/checker.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Add `Hit` and `ToolChecker` to `src/checker.rs`**

Add these definitions before `split_segments` in `src/checker.rs`:

```rust
#[derive(Debug, Clone)]
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
```

- [ ] **Step 2: Add `pub mod checker` to `src/lib.rs`**

In `src/lib.rs`, after the existing `pub mod` declarations at the top:

```rust
pub mod checker;
```

- [ ] **Step 3: Verify it compiles**

```bash
cargo build 2>&1
```

Expected: compiles cleanly.

- [ ] **Step 4: Commit**

```bash
git add src/checker.rs src/lib.rs
git commit -m "feat: add Hit struct and ToolChecker trait"
```

---

## Task 3: `blacklist::check_for_bin`

**Files:**
- Modify: `src/blacklist.rs`

- [ ] **Step 1: Write failing test**

In `src/blacklist.rs`, inside the `#[cfg(test)] mod tests` block, add:

```rust
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
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test check_for_bin 2>&1 | head -10
```

Expected: compile error (`check_for_bin` not found).

- [ ] **Step 3: Implement `check_for_bin`**

In `src/blacklist.rs`, after the existing `pub fn check` function:

```rust
/// Checks `content` against rules whose `bin` field equals `bin`.
/// Pass `bin = Some("kubectl")` for kubectl-only rules, `bin = None` for bin=None rules.
pub fn check_for_bin(content: &str, bin: Option<&str>) -> Option<Hit> {
    let disabled = &crate::disabled::DISABLED;
    for rule in RULES.iter() {
        let matches = match (rule.bin, bin) {
            (None, None) => true,
            (Some(rb), Some(b)) => rb == b,
            _ => false,
        };
        if !matches { continue; }
        if disabled.contains(rule.id) { continue; }
        if rule.regex.is_match(content) {
            return Some(Hit { id: rule.id, reason: rule.reason });
        }
    }
    None
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test check_for_bin 2>&1
```

Expected: all three tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/blacklist.rs
git commit -m "feat: add blacklist::check_for_bin for per-tool rule filtering"
```

---

## Task 4: `KubectlChecker`

**Files:**
- Modify: `src/checker.rs`

- [ ] **Step 1: Write failing tests**

In the `tests` module of `src/checker.rs`, add:

```rust
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
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test kubectl_checker 2>&1 | head -10
```

Expected: compile error (`KubectlChecker` not found).

- [ ] **Step 3: Implement `KubectlChecker`**

Add to `src/checker.rs`, before the test module. Requires these imports at the top of the file:

```rust
use crate::{aliases, blacklist, forbid};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc::Sender};
```

Then the struct and impl:

```rust
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
```

- [ ] **Step 4: Run tests**

```bash
cargo test kubectl_checker 2>&1
```

Expected: all three pass.

- [ ] **Step 5: Commit**

```bash
git add src/checker.rs
git commit -m "feat: implement KubectlChecker with blacklist and forbid checks"
```

---

## Task 5: `HelmChecker`

**Files:**
- Modify: `src/checker.rs`

- [ ] **Step 1: Write failing tests**

In the `tests` module of `src/checker.rs`:

```rust
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
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test helm_checker 2>&1 | head -10
```

Expected: compile error.

- [ ] **Step 3: Implement `HelmChecker`**

Add to `src/checker.rs` after `KubectlChecker`:

```rust
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
```

- [ ] **Step 4: Run tests**

```bash
cargo test helm_checker 2>&1
```

Expected: all three pass.

- [ ] **Step 5: Commit**

```bash
git add src/checker.rs
git commit -m "feat: implement HelmChecker with blacklist and forbid checks"
```

---

## Task 6: `DockerChecker`

**Files:**
- Modify: `src/checker.rs`

`docker-compose` is a separate binary from `docker` in the rule set (`bin = Some("docker-compose")`). `DockerChecker` covers both.

- [ ] **Step 1: Write failing tests**

```rust
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
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test docker_checker 2>&1 | head -10
```

- [ ] **Step 3: Implement `DockerChecker`**

```rust
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
```

- [ ] **Step 4: Run tests**

```bash
cargo test docker_checker 2>&1
```

Expected: all four pass.

- [ ] **Step 5: Commit**

```bash
git add src/checker.rs
git commit -m "feat: implement DockerChecker covering docker and docker-compose rules"
```

---

## Task 7: `RshChecker` and `FallbackChecker`

**Files:**
- Modify: `src/checker.rs`

`FallbackChecker` handles rules with `bin = None` (SQL, subprocess bypass, rsh-protect-config-access) and the database forbid check. It always runs. `RshChecker` handles `bin = Some("rsh")` rules (rsh-protect-disable, rsh-protect-forbid-remove).

- [ ] **Step 1: Write failing tests**

```rust
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
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test fallback_checker 2>&1 | head -5
cargo test rsh_checker 2>&1 | head -5
```

- [ ] **Step 3: Implement `RshChecker` and `FallbackChecker`**

```rust
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
```

- [ ] **Step 4: Run tests**

```bash
cargo test fallback_checker rsh_checker 2>&1
```

Expected: all six pass.

- [ ] **Step 5: Commit**

```bash
git add src/checker.rs
git commit -m "feat: implement RshChecker and FallbackChecker"
```

---

## Task 8: `detect_checkers`

**Files:**
- Modify: `src/checker.rs`

- [ ] **Step 1: Write failing tests**

```rust
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
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test detect_checkers 2>&1 | head -10
```

- [ ] **Step 3: Implement `detect_checkers`**

```rust
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
```

- [ ] **Step 4: Run tests**

```bash
cargo test detect_checkers 2>&1
```

Expected: all five pass.

- [ ] **Step 5: Commit**

```bash
git add src/checker.rs
git commit -m "feat: implement detect_checkers for tool presence scanning"
```

---

## Task 9: `run_parallel_checks` (parallel execution driver)

**Files:**
- Modify: `src/checker.rs`

- [ ] **Step 1: Write failing tests**

```rust
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
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test run_parallel_checks 2>&1 | head -10
```

- [ ] **Step 3: Implement `run_parallel_checks`**

Add to `src/checker.rs`, before the test module. The imports added in Task 4 cover what's needed; add `std::thread` and `std::sync::mpsc`:

```rust
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
```

- [ ] **Step 4: Run tests**

```bash
cargo test run_parallel_checks 2>&1
```

Expected: all four pass.

- [ ] **Step 5: Run full test suite to confirm nothing broke**

```bash
cargo test 2>&1
```

Expected: all existing tests still pass.

- [ ] **Step 6: Commit**

```bash
git add src/checker.rs
git commit -m "feat: implement run_parallel_checks with fail-fast AtomicBool"
```

---

## Task 10: Rewrite `run_check` in `src/lib.rs`

**Files:**
- Modify: `src/lib.rs`

- [ ] **Step 1: Rewrite `run_check`**

Replace the entire body of `pub fn run_check` (currently lines 8–40 in `src/lib.rs`) with:

```rust
pub fn run_check(command: &str) -> ExitCode {
    let segments = checker::split_segments(command);
    match checker::run_parallel_checks(segments) {
        Some(hit) => {
            eprintln!("rsh blocked: {}", hit.message);
            ExitCode::from(2)
        }
        None => ExitCode::SUCCESS,
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test 2>&1
```

Expected: all tests pass.

- [ ] **Step 3: Smoke-test the hook**

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"kubectl delete ns prod"}}' | cargo run --quiet
echo "Exit: $?"
echo '{"tool_name":"Bash","tool_input":{"command":"kubectl get pods"}}' | cargo run --quiet
echo "Exit: $?"
```

Expected: first exits 2 (with a "rsh blocked" message on stderr), second exits 0.

- [ ] **Step 4: Commit**

```bash
git add src/lib.rs
git commit -m "feat: rewrite run_check to use checker::run_parallel_checks"
```

---

## Task 11: Rewrite `run_check_content` in `src/lib.rs`

**Files:**
- Modify: `src/lib.rs`

`run_check_content` is called for `Write` and `Edit` tool events. It checks the file content (not a shell command), so there is no `split_segments` step — content goes directly to `detect_checkers`.

- [ ] **Step 1: Rewrite `run_check_content`**

Replace the body of `pub fn run_check_content` (currently lines 42–48 in `src/lib.rs`) with:

```rust
pub fn run_check_content(content: &str) -> ExitCode {
    let checkers = checker::detect_checkers(content);
    let segments = vec![crate::checker::Segment::Direct {
        command: content.to_string(),
    }];
    match checker::run_parallel_checks(segments) {
        Some(hit) => {
            eprintln!("rsh blocked file content: {}", hit.message);
            ExitCode::from(2)
        }
        None => ExitCode::SUCCESS,
    }
}
```

Note: `run_parallel_checks` calls `detect_checkers` internally when processing `Segment::Direct`, so the `let checkers = ...` line above is unused — remove it:

```rust
pub fn run_check_content(content: &str) -> ExitCode {
    let segments = vec![crate::checker::Segment::Direct {
        command: content.to_string(),
    }];
    match checker::run_parallel_checks(segments) {
        Some(hit) => {
            eprintln!("rsh blocked file content: {}", hit.message);
            ExitCode::from(2)
        }
        None => ExitCode::SUCCESS,
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test 2>&1
```

Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/lib.rs
git commit -m "feat: rewrite run_check_content to use checker pipeline"
```

---

## Task 12: Remove dead code from `src/lib.rs`

**Files:**
- Modify: `src/lib.rs`

Remove the now-dead functions and their tests. The following are no longer called from `lib.rs` and their logic has moved to `checker.rs`:
- `check_content_blocked`
- `script_paths_in`
- `extract_script_path`
- `strip_quotes`

And the corresponding `#[cfg(test)]` tests:
- `extract_script_path_*` (all)
- `script_paths_in_*` (all)

The `protected_path_*` tests must be kept — `is_protected_path` is still in `lib.rs`.

- [ ] **Step 1: Delete dead functions and their tests**

Remove from `src/lib.rs`:
- The function `fn check_content_blocked(content: &str, label: &str) -> bool` and its body.
- The function `fn script_paths_in(command: &str) -> Vec<String>` and its body.
- The function `fn extract_script_path(cmd: &str) -> Option<String>` and its body.
- The function `fn strip_quotes(s: &str) -> String` and its body.
- All `#[test]` functions whose names start with `extract_script_path_` or `script_paths_in_`.

Keep:
- `pub fn run_check`
- `pub fn run_check_content`
- `pub fn is_protected_path`
- `pub mod checker`
- `pub mod aliases`, `pub mod blacklist`, `pub mod disabled`, `pub mod forbid`
- `protected_path_*` tests

- [ ] **Step 2: Verify it compiles with no warnings**

```bash
cargo build 2>&1
```

Expected: clean compile, no unused-code warnings.

- [ ] **Step 3: Run full test suite**

```bash
cargo test 2>&1
```

Expected: all tests pass, none deleted accidentally.

- [ ] **Step 4: Run the hook end-to-end for each supported tool_name**

```bash
# Bash — blocked
echo '{"tool_name":"Bash","tool_input":{"command":"kubectl delete ns prod"}}' | cargo run --quiet 2>&1
echo "Exit: $?"

# Bash — allowed
echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | cargo run --quiet 2>&1
echo "Exit: $?"

# Write — blocked (SQL content)
echo '{"tool_name":"Write","tool_input":{"file_path":"/tmp/q.sql","content":"DELETE FROM users"}}' | cargo run --quiet 2>&1
echo "Exit: $?"

# Write — blocked (protected path)
echo '{"tool_name":"Write","tool_input":{"file_path":"~/.config/rsh/aliases.json","content":"{}"}}' | cargo run --quiet 2>&1
echo "Exit: $?"

# Write — allowed
echo '{"tool_name":"Write","tool_input":{"file_path":"/tmp/foo.txt","content":"hello"}}' | cargo run --quiet 2>&1
echo "Exit: $?"
```

Expected: exits 2 for blocked cases (with message on stderr), 0 for allowed.

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs
git commit -m "refactor: remove dead code superseded by checker module"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| Split segments (script vs direct) | Task 1 |
| `ToolChecker` trait, `Hit` struct | Task 2 |
| Per-bin blacklist filtering | Task 3 |
| `KubectlChecker` with forbid check | Task 4 |
| `HelmChecker` with forbid check | Task 5 |
| `DockerChecker` (docker + docker-compose) | Task 6 |
| `FallbackChecker` (bin=None rules + db forbid) | Task 7 |
| `detect_checkers` | Task 8 |
| Parallel execution + fail-fast | Task 9 |
| `run_check` rewrite | Task 10 |
| `run_check_content` rewrite | Task 11 |
| Dead code removal | Task 12 |
| File protection (Write/Edit) unchanged | Task 10/11 (`is_protected_path` stays in `main.rs`) |

**Type consistency check:**

- `Hit` defined in Task 2, used in Tasks 4–9 — consistent.
- `split_segments` returns `Vec<Segment>` — used in `run_parallel_checks` (Task 9) and `run_check` (Task 10) — consistent.
- `detect_checkers` returns `Vec<Box<dyn ToolChecker>>` — called inside `run_parallel_checks` — consistent.
- `check_for_bin` returns `Option<blacklist::Hit>` — converted to `checker::Hit` inside each checker — consistent.

**No placeholders found.**
