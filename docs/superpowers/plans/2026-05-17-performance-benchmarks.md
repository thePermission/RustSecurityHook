# Performance Benchmarks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Criterion benchmarks that measure the full `run_check` pipeline across harmless, blocking, and edge-case inputs.

**Architecture:** Criterion benchmark files in `benches/` are compiled as separate crates and can only access items from a `[lib]` crate, not from a `[[bin]]` crate. A new `src/lib.rs` exposes `run_check` and re-exports the four modules. `src/main.rs` becomes a thin CLI wrapper that imports from the lib. `benches/hook.rs` calls `rsh::run_check` directly.

**Tech Stack:** Rust stable, Criterion 0.5 with html_reports

---

### Task 1: Introduce `src/lib.rs` — move modules and core check logic

**Files:**
- Create: `src/lib.rs`
- Modify: `src/main.rs`

The four submodules (`aliases`, `blacklist`, `disabled`, `forbid`) must be declared in
exactly one place. Moving them to `lib.rs` lets both `main.rs` and `benches/hook.rs`
reach them. The core check functions move with them.

- [ ] **Step 1: Create `src/lib.rs` with this exact content**

```rust
pub mod aliases;
pub mod blacklist;
pub mod disabled;
pub mod forbid;

use std::process::ExitCode;

pub fn run_check(command: &str) -> ExitCode {
    if let Some(hit) = blacklist::check(command) {
        eprintln!("rsh blocked command (rule: {}): {}", hit.id, hit.reason);
        return ExitCode::from(2);
    }
    if let Some(hit) = forbid::check(command) {
        match hit.kind {
            forbid::HitKind::Cluster => {
                let origin = if hit.from_current_context { " (current kubeconfig)" } else { "" };
                eprintln!("rsh blocked command: forbidden cluster '{}'{origin}", hit.value);
            }
            forbid::HitKind::Namespace => {
                let origin = if hit.from_current_context { " (current kubeconfig)" } else { "" };
                eprintln!("rsh blocked command: forbidden namespace '{}'{origin}", hit.value);
            }
            forbid::HitKind::Database => {
                eprintln!("rsh blocked command: forbidden database host '{}'", hit.value);
            }
        }
        return ExitCode::from(2);
    }
    for path in script_paths_in(command) {
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                if check_content_blocked(&content, &format!("script execution ({path})")) {
                    return ExitCode::from(2);
                }
            }
            Err(_) => {}
        }
    }
    ExitCode::SUCCESS
}

pub fn run_check_content(content: &str) -> ExitCode {
    if check_content_blocked(content, "file write") {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

pub fn is_protected_path(path: &str) -> bool {
    let p = path.replace('\\', "/");
    p.contains("/.config/rsh/")
        || p.ends_with("/.config/rsh")
        || p.starts_with(".config/rsh/")
        || p == ".config/rsh"
}

fn check_content_blocked(content: &str, label: &str) -> bool {
    if let Some(hit) = blacklist::check(content) {
        eprintln!("rsh blocked {} (rule: {}): {}", label, hit.id, hit.reason);
        return true;
    }
    let cfg = forbid::load();
    if cfg.is_empty() {
        return false;
    }
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(hit) =
            forbid::check_with(line, &aliases::ALIASES, &cfg, &forbid::KubectlEnv)
                .or_else(|| forbid::check_db(line, &cfg))
        {
            let msg = match hit.kind {
                forbid::HitKind::Cluster => {
                    let origin =
                        if hit.from_current_context { " (current kubeconfig)" } else { "" };
                    format!("forbidden cluster '{}'{origin}", hit.value)
                }
                forbid::HitKind::Namespace => {
                    let origin =
                        if hit.from_current_context { " (current kubeconfig)" } else { "" };
                    format!("forbidden namespace '{}'{origin}", hit.value)
                }
                forbid::HitKind::Database => {
                    format!("forbidden database host '{}'", hit.value)
                }
            };
            eprintln!("rsh blocked {label}: {msg}");
            return true;
        }
    }
    false
}

pub fn script_paths_in(command: &str) -> Vec<String> {
    command
        .split(|c| c == ';' || c == '\n')
        .flat_map(|s| s.split("&&"))
        .flat_map(|s| s.split("||"))
        .flat_map(|s| s.split('|'))
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .filter_map(extract_script_path)
        .collect()
}

fn extract_script_path(cmd: &str) -> Option<String> {
    const INTERPRETERS: &[&str] = &[
        "bash", "sh", "zsh", "ksh", "dash", "fish",
        "python", "python3", "perl", "ruby", "node", "nodejs",
    ];

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_script_path_interpreter_with_script() {
        assert_eq!(
            extract_script_path("bash /tmp/deploy.sh"),
            Some("/tmp/deploy.sh".to_string())
        );
        assert_eq!(
            extract_script_path("sh ./run.sh"),
            Some("./run.sh".to_string())
        );
        assert_eq!(
            extract_script_path("zsh -x /opt/setup.sh"),
            Some("/opt/setup.sh".to_string())
        );
    }

    #[test]
    fn extract_script_path_extended_interpreters() {
        assert_eq!(
            extract_script_path("python3 /tmp/evil.py"),
            Some("/tmp/evil.py".to_string())
        );
        assert_eq!(
            extract_script_path("python /tmp/evil.py"),
            Some("/tmp/evil.py".to_string())
        );
        assert_eq!(
            extract_script_path("perl /tmp/evil.pl"),
            Some("/tmp/evil.pl".to_string())
        );
        assert_eq!(
            extract_script_path("ruby /tmp/evil.rb"),
            Some("/tmp/evil.rb".to_string())
        );
        assert_eq!(
            extract_script_path("node /tmp/evil.js"),
            Some("/tmp/evil.js".to_string())
        );
        assert_eq!(
            extract_script_path("nodejs /tmp/evil.js"),
            Some("/tmp/evil.js".to_string())
        );
    }

    #[test]
    fn extract_script_path_interpreter_no_script() {
        assert_eq!(extract_script_path("bash"), None);
    }

    #[test]
    fn extract_script_path_quoted_paths() {
        assert_eq!(
            extract_script_path("bash \"/tmp/deploy.sh\""),
            Some("/tmp/deploy.sh".to_string())
        );
        assert_eq!(
            extract_script_path("sh -c '/tmp/run.sh'"),
            Some("/tmp/run.sh".to_string())
        );
        assert_eq!(
            extract_script_path("source \"/etc/profile\""),
            Some("/etc/profile".to_string())
        );
        assert_eq!(
            extract_script_path("\"/tmp/script.sh\""),
            Some("/tmp/script.sh".to_string())
        );
    }

    #[test]
    fn extract_script_path_source_dot() {
        assert_eq!(
            extract_script_path("source /etc/profile"),
            Some("/etc/profile".to_string())
        );
        assert_eq!(
            extract_script_path(". ~/.bashrc"),
            Some("~/.bashrc".to_string())
        );
    }

    #[test]
    fn extract_script_path_direct_execution() {
        assert_eq!(
            extract_script_path("./deploy.sh"),
            Some("./deploy.sh".to_string())
        );
        assert_eq!(
            extract_script_path("/usr/local/bin/myscript"),
            Some("/usr/local/bin/myscript".to_string())
        );
        assert_eq!(
            extract_script_path("cleanup.sh"),
            Some("cleanup.sh".to_string())
        );
        assert_eq!(
            extract_script_path("setup.bash"),
            Some("setup.bash".to_string())
        );
    }

    #[test]
    fn extract_script_path_non_script_commands() {
        assert_eq!(extract_script_path("ls -la"), None);
        assert_eq!(extract_script_path("git status"), None);
        assert_eq!(extract_script_path("kubectl get pods"), None);
        assert_eq!(extract_script_path("cargo build --release"), None);
    }

    #[test]
    fn script_paths_in_single_segment() {
        assert_eq!(script_paths_in("./deploy.sh"), vec!["./deploy.sh"]);
    }

    #[test]
    fn script_paths_in_semicolon_separator() {
        let paths = script_paths_in("echo start; ./deploy.sh; echo done");
        assert_eq!(paths, vec!["./deploy.sh"]);
    }

    #[test]
    fn script_paths_in_and_and_separator() {
        let paths = script_paths_in("cd /tmp && bash setup.sh");
        assert_eq!(paths, vec!["setup.sh"]);
    }

    #[test]
    fn script_paths_in_pipe_separator() {
        let paths = script_paths_in("cat file.txt | bash /tmp/process.sh");
        assert_eq!(paths, vec!["/tmp/process.sh"]);
    }

    #[test]
    fn script_paths_in_newline_separator() {
        let paths = script_paths_in("echo hi\n./run.sh\necho bye");
        assert_eq!(paths, vec!["./run.sh"]);
    }

    #[test]
    fn script_paths_in_no_scripts() {
        let paths = script_paths_in("kubectl get pods && helm list");
        assert!(paths.is_empty());
    }

    #[test]
    fn script_paths_in_multiple_scripts() {
        let paths = script_paths_in("./a.sh; bash b.sh && source c.sh");
        assert_eq!(paths, vec!["./a.sh", "b.sh", "c.sh"]);
    }

    #[test]
    fn script_paths_in_skips_comments() {
        let paths = script_paths_in("# this is a comment\n./deploy.sh");
        assert_eq!(paths, vec!["./deploy.sh"]);
    }

    #[test]
    fn protected_path_matches_rsh_config() {
        assert!(is_protected_path("/home/user/.config/rsh/disabled-rules.json"));
        assert!(is_protected_path("~/.config/rsh/aliases.json"));
        assert!(is_protected_path(".config/rsh/forbidden.json"));
    }

    #[test]
    fn protected_path_matches_windows_backslash() {
        assert!(is_protected_path(r"C:\Users\user\.config\rsh\disabled-rules.json"));
        assert!(is_protected_path(r".config\rsh\aliases.json"));
    }

    #[test]
    fn protected_path_does_not_match_unrelated() {
        assert!(!is_protected_path("/home/user/.config/other/file.json"));
        assert!(!is_protected_path("~/.config/rsh_backup/foo"));
        assert!(!is_protected_path(""));
        assert!(!is_protected_path("my.config/rsh/file.json"));
        assert!(!is_protected_path("/var/my.config/rsh/app.yaml"));
    }
}
```

- [ ] **Step 2: Replace the top of `src/main.rs`**

Remove the four `mod` declarations and the two `#[cfg(test)]` modules at the bottom. Add imports from the lib crate instead. The new top of `main.rs` should read:

```rust
use rsh::{aliases, blacklist, disabled, forbid};
use rsh::{is_protected_path, run_check, run_check_content};

use anyhow::{Context, Result};
use serde::Deserialize;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
```

Remove the following functions from `main.rs` (they now live in `lib.rs`):
- `fn run_check`
- `fn run_check_content`
- `fn check_content_blocked`
- `fn is_protected_path`
- `fn script_paths_in`
- `fn extract_script_path`
- `fn strip_quotes`
- The entire `#[cfg(test)] mod tests` block (the one with `extract_script_path_*` and `script_paths_in_*` tests)
- The entire `#[cfg(test)] mod protected_path_tests` block

- [ ] **Step 3: Verify the existing tests still pass**

```bash
cargo test
```

Expected: all tests pass. If any test in `main.rs` now fails to compile because it references a moved function, that test was missed in Step 2 — move it to `lib.rs` too.

- [ ] **Step 4: Commit**

```bash
git add src/lib.rs src/main.rs
git commit -m "refactor: extract core check logic into lib.rs for benchmark access"
```

---

### Task 2: Add Criterion to `Cargo.toml` and skeleton `benches/hook.rs`

**Files:**
- Modify: `Cargo.toml`
- Create: `benches/hook.rs`

- [ ] **Step 1: Add Criterion to `Cargo.toml`**

In the `[dev-dependencies]` section add:

```toml
criterion = { version = "0.5", features = ["html_reports"] }
```

After the existing `tempfile` line. Then add a new `[[bench]]` section anywhere after `[dev-dependencies]`:

```toml
[[bench]]
name = "hook"
harness = false
```

- [ ] **Step 2: Create `benches/hook.rs` skeleton**

```rust
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rsh::run_check;

fn bench_harmless(c: &mut Criterion) {
    let _ = c;
}

fn bench_blocked_k8s(c: &mut Criterion) {
    let _ = c;
}

fn bench_blocked_helm(c: &mut Criterion) {
    let _ = c;
}

fn bench_edge(c: &mut Criterion) {
    let _ = c;
}

criterion_group!(benches, bench_harmless, bench_blocked_k8s, bench_blocked_helm, bench_edge);
criterion_main!(benches);
```

- [ ] **Step 3: Verify the skeleton compiles**

```bash
cargo bench --no-run 2>&1 | tail -5
```

Expected: `Compiling rsh ...` followed by `Finished`. No errors. (Criterion will print warnings about unused variables — those go away in Task 3.)

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock benches/hook.rs
git commit -m "chore: add criterion dev-dependency and benchmark skeleton"
```

---

### Task 3: Implement the four benchmark groups

**Files:**
- Modify: `benches/hook.rs`

Note: blocked commands trigger `eprintln!` inside `run_check` on every iteration. This
is correct behavior and expected to appear on stderr during the benchmark run. Suppress
it with `cargo bench 2>/dev/null` if you want clean output.

- [ ] **Step 1: Replace `benches/hook.rs` with the full implementation**

```rust
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rsh::run_check;

fn bench_harmless(c: &mut Criterion) {
    let commands = [
        "ls -la",
        "git status",
        "cargo build --release",
        "echo hello",
        "cat /tmp/file",
    ];
    let mut group = c.benchmark_group("harmless");
    for cmd in commands {
        group.bench_with_input(BenchmarkId::from_parameter(cmd), cmd, |b, cmd| {
            b.iter(|| black_box(run_check(black_box(cmd))));
        });
    }
    group.finish();
}

fn bench_blocked_k8s(c: &mut Criterion) {
    let commands = [
        "kubectl delete ns production",
        "kubectl delete --all -n default",
        "kubectl delete crd mykind",
    ];
    let mut group = c.benchmark_group("blocked_k8s");
    for cmd in commands {
        group.bench_with_input(BenchmarkId::from_parameter(cmd), cmd, |b, cmd| {
            b.iter(|| black_box(run_check(black_box(cmd))));
        });
    }
    group.finish();
}

fn bench_blocked_helm(c: &mut Criterion) {
    let commands = [
        "helm uninstall my-release",
        "helm rollback my-release 0",
    ];
    let mut group = c.benchmark_group("blocked_helm");
    for cmd in commands {
        group.bench_with_input(BenchmarkId::from_parameter(cmd), cmd, |b, cmd| {
            b.iter(|| black_box(run_check(black_box(cmd))));
        });
    }
    group.finish();
}

fn bench_edge(c: &mut Criterion) {
    let long_cmd = "x".repeat(10_000);
    let mut group = c.benchmark_group("edge");
    group.bench_function("empty", |b| {
        b.iter(|| black_box(run_check(black_box(""))));
    });
    group.bench_function("10k_chars", |b| {
        b.iter(|| black_box(run_check(black_box(long_cmd.as_str()))));
    });
    group.finish();
}

criterion_group!(benches, bench_harmless, bench_blocked_k8s, bench_blocked_helm, bench_edge);
criterion_main!(benches);
```

- [ ] **Step 2: Run all benchmarks**

```bash
cargo bench 2>/dev/null
```

Expected output (timing will differ per machine — the key is that all groups complete):

```
harmless/ls -la         time:   [... ns ... ns ... ns]
harmless/git status     time:   [... ns ... ns ... ns]
...
blocked_k8s/kubectl delete ns production
                        time:   [... ns ... ns ... ns]
...
blocked_helm/helm uninstall my-release
                        time:   [... ns ... ns ... ns]
...
edge/empty              time:   [... ns ... ns ... ns]
edge/10k_chars          time:   [... ns ... ns ... ns]
```

If any benchmark group produces an error rather than timing output, stop and investigate.

- [ ] **Step 3: Commit**

```bash
git add benches/hook.rs
git commit -m "feat: add criterion benchmarks for run_check pipeline"
```
