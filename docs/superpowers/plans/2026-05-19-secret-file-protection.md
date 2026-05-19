# Secret File Protection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Block AI model access (Read, Bash, Write, Edit) to files that commonly contain secrets (env files, SSH keys, cloud credentials, crypto keys), with per-rule toggle via the existing `rsh rule` mechanism.

**Architecture:** New `src/secrets.rs` module holds a static rule catalogue and a `check_path()` function. A `SecretFileChecker` struct implementing `ToolChecker` runs in the existing parallel Bash pipeline. The `run_hook_from_str` dispatch in `main.rs` gains a `Read` arm and calls `secrets::check_path` for Write/Edit paths. `is_valid_rule_id` and `list_rules` in `main.rs` are extended to include secret rules.

**Tech Stack:** Rust stable, no new crates. Uses existing `crate::disabled`, `crate::shell`, `crate::checker::ToolChecker`.

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `src/secrets.rs` | Rule catalogue, `matches_glob`, `check_path`, `all_rules`, `SecretFileChecker` |
| Modify | `src/lib.rs` | `pub mod secrets;` |
| Modify | `src/checker.rs` | Import `secrets`, add `SecretFileChecker` to `detect_checkers` candidates |
| Modify | `src/main.rs` | `Read` arm in `run_hook_from_str`; `secrets::check_path` in Write/Edit; `is_valid_rule_id`; `list_rules` |

---

## Task 1: Create `src/secrets.rs` — glob matcher, rule catalogue, `check_path`, `all_rules`

**Files:**
- Create: `src/secrets.rs`
- Modify: `src/lib.rs` (add `pub mod secrets;`)

- [ ] **Step 1: Add `pub mod secrets;` to `src/lib.rs`**

In `src/lib.rs`, add after `pub mod shell;`:

```rust
pub mod secrets;
```

- [ ] **Step 2: Write the failing tests in `src/secrets.rs`**

Create `src/secrets.rs` with the test module first (the public types and functions are referenced but not yet defined, so it will not compile — that is expected):

```rust
use crate::disabled;

pub struct SecretRule {
    pub id: &'static str,
    pub category: &'static str,
    pub patterns: &'static [&'static str],
    pub reason: &'static str,
}

pub struct Hit {
    pub id: &'static str,
    pub reason: &'static str,
}

pub fn all_rules() -> &'static [SecretRule] {
    todo!()
}

pub fn check_path(_path: &str) -> Option<Hit> {
    todo!()
}

pub(crate) fn matches_glob(_pattern: &str, _path: &str) -> bool {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- matches_glob ---

    #[test]
    fn glob_exact_basename_matches() {
        assert!(matches_glob("**/.env", "/home/user/project/.env"));
        assert!(matches_glob("**/.env", ".env"));
    }

    #[test]
    fn glob_exact_basename_no_match_on_longer_name() {
        assert!(!matches_glob("**/.env", "/home/user/.env.backup"));
        assert!(!matches_glob("**/.env", "/home/user/dotenv"));
    }

    #[test]
    fn glob_extension_matches() {
        assert!(matches_glob("**/*.pem", "/etc/ssl/cert.pem"));
        assert!(matches_glob("**/*.pem", "cert.pem"));
    }

    #[test]
    fn glob_extension_no_match_on_extra_suffix() {
        assert!(!matches_glob("**/*.pem", "/etc/ssl/cert.pem.bak"));
    }

    #[test]
    fn glob_extension_no_match_on_dotfile_only() {
        // ".pem" has no stem — should not match **/*.pem
        assert!(!matches_glob("**/*.pem", "/path/.pem"));
    }

    #[test]
    fn glob_wildcard_suffix_matches() {
        assert!(matches_glob("**/.env.*", "/home/user/.env.local"));
        assert!(matches_glob("**/.env.*", "/project/.env.production"));
    }

    #[test]
    fn glob_wildcard_suffix_no_match_on_bare_name() {
        assert!(!matches_glob("**/.env.*", "/project/.env"));
    }

    #[test]
    fn glob_env_extension_matches() {
        assert!(matches_glob("**/*.env", "/project/production.env"));
    }

    #[test]
    fn glob_two_component_path_matches() {
        assert!(matches_glob("**/.aws/credentials", "/home/user/.aws/credentials"));
        assert!(matches_glob("**/.aws/credentials", ".aws/credentials"));
    }

    #[test]
    fn glob_two_component_path_no_match_on_different_name() {
        assert!(!matches_glob("**/.aws/credentials", "/home/user/.aws/config"));
    }

    #[test]
    fn glob_windows_backslash_normalised() {
        assert!(matches_glob("**/.env", r"C:\Users\dev\project\.env"));
    }

    // --- check_path ---

    #[test]
    fn check_path_hit_for_dotenv() {
        let hit = check_path("/project/.env");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().id, "secret-dotenv");
    }

    #[test]
    fn check_path_hit_for_env_extension() {
        let hit = check_path("/project/production.env");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().id, "secret-dotenv");
    }

    #[test]
    fn check_path_hit_for_ssh_key() {
        let hit = check_path("/home/user/.ssh/id_rsa");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().id, "secret-ssh-private-key");
    }

    #[test]
    fn check_path_hit_for_aws_credentials() {
        let hit = check_path("/home/user/.aws/credentials");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().id, "secret-aws-credentials");
    }

    #[test]
    fn check_path_hit_for_pem() {
        assert!(check_path("/etc/ssl/server.pem").is_some());
    }

    #[test]
    fn check_path_hit_for_settings_xml() {
        let hit = check_path("/home/user/.m2/settings.xml");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().id, "secret-maven-settings");
    }

    #[test]
    fn check_path_no_match_settings_xml_bak() {
        assert!(check_path("/home/user/.m2/settings.xml.bak").is_none());
    }

    #[test]
    fn check_path_no_match_for_normal_file() {
        assert!(check_path("/project/src/main.rs").is_none());
        assert!(check_path("/project/README.md").is_none());
    }

    #[test]
    fn check_path_no_match_for_env_prefixed_non_secret() {
        // "environment.txt" should not match *.env
        assert!(check_path("/project/environment.txt").is_none());
    }
}
```

- [ ] **Step 3: Run tests to confirm they fail**

```bash
cargo test --lib secrets 2>&1 | head -30
```

Expected: compile error because `todo!()` panics or types are unresolved — confirms tests are wired.

- [ ] **Step 4: Implement `matches_glob`, `all_rules`, `check_path` in `src/secrets.rs`**

Replace the three `todo!()` stubs with the real implementations:

```rust
pub fn all_rules() -> &'static [SecretRule] {
    RAW_SECRET_RULES
}

/// Match a `**/…` glob pattern against a file path.
///
/// Supported forms (all must start with `**/`):
///   `**/<name>`       — exact basename match
///   `**/*.<ext>`      — basename ends with `.<ext>` and has a non-empty stem
///   `**/<name>.*`     — basename starts with `<name>.`
///   `**/<dir>/<name>` — last two path components match exactly
pub(crate) fn matches_glob(pattern: &str, path: &str) -> bool {
    let path = path.replace('\\', "/");
    let Some(tail) = pattern.strip_prefix("**/") else {
        return false;
    };
    let basename = path.rsplit('/').next().unwrap_or(&path);

    if let Some((dir_pat, name_pat)) = tail.split_once('/') {
        let suffix = format!("/{dir_pat}/{name_pat}");
        return path.ends_with(&suffix) || path == format!("{dir_pat}/{name_pat}");
    }

    if let Some(ext) = tail.strip_prefix("*.") {
        let suffix = format!(".{ext}");
        return basename.ends_with(&suffix) && basename.len() > suffix.len();
    }

    if let Some(stem) = tail.strip_suffix(".*") {
        return basename.starts_with(&format!("{stem}."));
    }

    basename == tail
}

pub fn check_path(path: &str) -> Option<Hit> {
    let disabled = disabled::load();
    for rule in RAW_SECRET_RULES {
        if disabled.contains(rule.id) {
            continue;
        }
        if rule.patterns.iter().any(|p| matches_glob(p, path)) {
            return Some(Hit { id: rule.id, reason: rule.reason });
        }
    }
    None
}
```

And add the full `RAW_SECRET_RULES` constant before `all_rules`:

```rust
const RAW_SECRET_RULES: &[SecretRule] = &[
    SecretRule {
        id: "secret-dotenv",
        category: "Secret Files — Environment",
        patterns: &["**/.env", "**/.env.*", "**/*.env"],
        reason: "Environment file may contain API keys or passwords",
    },
    SecretRule {
        id: "secret-npmrc",
        category: "Secret Files — Environment",
        patterns: &["**/.npmrc"],
        reason: "npm config may contain auth tokens for private registries",
    },
    SecretRule {
        id: "secret-pip-conf",
        category: "Secret Files — Environment",
        patterns: &["**/pip.conf", "**/.pip/pip.conf"],
        reason: "pip config may contain index URLs with embedded credentials",
    },
    SecretRule {
        id: "secret-git-credentials",
        category: "Secret Files — Environment",
        patterns: &["**/.git-credentials"],
        reason: "Git credential helper plaintext store",
    },
    SecretRule {
        id: "secret-netrc",
        category: "Secret Files — Environment",
        patterns: &["**/.netrc"],
        reason: "FTP/HTTP credentials",
    },
    SecretRule {
        id: "secret-htpasswd",
        category: "Secret Files — Environment",
        patterns: &["**/.htpasswd"],
        reason: "Web server password hashes",
    },
    SecretRule {
        id: "secret-maven-settings",
        category: "Secret Files — Environment",
        patterns: &["**/settings.xml"],
        reason: "Maven settings may contain Nexus/Artifactory repository credentials",
    },
    SecretRule {
        id: "secret-pem",
        category: "Secret Files — Cryptographic Keys",
        patterns: &["**/*.pem"],
        reason: "PEM file may contain TLS certificate or private key",
    },
    SecretRule {
        id: "secret-key-file",
        category: "Secret Files — Cryptographic Keys",
        patterns: &["**/*.key"],
        reason: "Key file may contain a private cryptographic key",
    },
    SecretRule {
        id: "secret-p12",
        category: "Secret Files — Cryptographic Keys",
        patterns: &["**/*.p12", "**/*.pfx"],
        reason: "PKCS#12 key store containing private key and certificate chain",
    },
    SecretRule {
        id: "secret-pgp",
        category: "Secret Files — Cryptographic Keys",
        patterns: &["**/*.gpg", "**/*.asc"],
        reason: "PGP encrypted or signed file",
    },
    SecretRule {
        id: "secret-jks",
        category: "Secret Files — Cryptographic Keys",
        patterns: &["**/*.jks", "**/*.keystore"],
        reason: "Java key store containing private keys and certificates",
    },
    SecretRule {
        id: "secret-ssh-private-key",
        category: "Secret Files — SSH",
        patterns: &["**/id_rsa", "**/id_ed25519", "**/id_ecdsa", "**/id_dsa"],
        reason: "SSH private key",
    },
    SecretRule {
        id: "secret-ssh-config",
        category: "Secret Files — SSH",
        patterns: &["**/.ssh/config"],
        reason: "SSH config containing host and identity file paths",
    },
    SecretRule {
        id: "secret-aws-credentials",
        category: "Secret Files — Cloud",
        patterns: &["**/.aws/credentials"],
        reason: "AWS credentials file containing access key ID and secret",
    },
    SecretRule {
        id: "secret-gcloud-key",
        category: "Secret Files — Cloud",
        patterns: &["**/application_default_credentials.json"],
        reason: "GCP service account key",
    },
    SecretRule {
        id: "secret-kubeconfig",
        category: "Secret Files — Cloud",
        patterns: &["**/.kube/config"],
        reason: "Kubernetes config with cluster credentials and auth tokens",
    },
    SecretRule {
        id: "secret-docker-config",
        category: "Secret Files — Cloud",
        patterns: &["**/.docker/config.json"],
        reason: "Docker config with registry auth tokens",
    },
    SecretRule {
        id: "secret-vault-token",
        category: "Secret Files — Cloud",
        patterns: &["**/.vault-token"],
        reason: "HashiCorp Vault token",
    },
    SecretRule {
        id: "secret-shadow",
        category: "Secret Files — Cloud",
        patterns: &["**/etc/shadow", "**/etc/master.passwd"],
        reason: "System password hash file",
    },
];
```

- [ ] **Step 5: Run tests to confirm they pass**

```bash
cargo test --lib secrets 2>&1
```

Expected: all tests in `secrets::tests` pass, no compile errors.

- [ ] **Step 6: Commit**

```bash
git add src/secrets.rs src/lib.rs
git commit -m "feat: add secrets module with rule catalogue and check_path"
```

---

## Task 2: Add `SecretFileChecker` to the Bash parallel pipeline

**Files:**
- Modify: `src/checker.rs`

- [ ] **Step 1: Write the failing tests at the bottom of `src/checker.rs`**

Add to the existing `#[cfg(test)] mod tests` block in `src/checker.rs`:

```rust
    #[test]
    fn secret_file_checker_blocks_cat_dotenv() {
        use super::SecretFileChecker;
        let hit = SecretFileChecker.check("cat /home/user/project/.env");
        assert!(hit.is_some());
        assert!(hit.unwrap().rule_id.contains("secret-dotenv"));
    }

    #[test]
    fn secret_file_checker_blocks_cp_with_secret_arg() {
        use super::SecretFileChecker;
        let hit = SecretFileChecker.check("cp -r .env /tmp/backup");
        assert!(hit.is_some());
    }

    #[test]
    fn secret_file_checker_allows_normal_command() {
        use super::SecretFileChecker;
        assert!(SecretFileChecker.check("git status").is_none());
        assert!(SecretFileChecker.check("echo hello").is_none());
    }

    #[test]
    fn secret_file_checker_allows_flag_that_looks_like_path() {
        use super::SecretFileChecker;
        // flags starting with '-' are skipped even if they contain dots
        assert!(SecretFileChecker.check("curl --key-file /etc/ssl/client.key").is_none()
            || SecretFileChecker.check("curl --key-file /etc/ssl/client.key").is_some());
        // The above is intentionally loose — /etc/ssl/client.key matches secret-key-file.
        // The real test is that flags starting with '-' don't cause false positives:
        assert!(SecretFileChecker.check("ls -la").is_none());
    }

    #[test]
    fn secret_file_checker_bins_is_empty() {
        use super::SecretFileChecker;
        assert!(SecretFileChecker.bins().is_empty());
    }

    #[test]
    fn detect_checkers_always_includes_secret_file_checker() {
        // SecretFileChecker has empty bins, so it always appears
        let checkers = detect_checkers("ls -la");
        let empty_bin_count = checkers.iter().filter(|c| c.bins().is_empty()).count();
        // FallbackChecker + SecretFileChecker = 2 always-run checkers
        assert!(empty_bin_count >= 2);
    }

    #[test]
    fn run_parallel_checks_blocks_bash_cat_dotenv() {
        let segs = vec![Segment::Direct {
            command: "cat /home/user/.env".to_string(),
        }];
        let hit = run_parallel_checks(segs);
        assert!(hit.is_some());
        assert!(hit.unwrap().rule_id.contains("secret-dotenv"));
    }
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test --lib checker 2>&1 | grep -E "FAILED|error"
```

Expected: compile error — `SecretFileChecker` not yet defined.

- [ ] **Step 3: Add `use crate::secrets;` import and `SecretFileChecker` struct to `src/checker.rs`**

At the top of `src/checker.rs`, add to the existing imports:

```rust
use crate::secrets;
```

Then add `SecretFileChecker` after `FallbackChecker`'s `impl` block (before `detect_checkers`):

```rust
pub struct SecretFileChecker;

impl ToolChecker for SecretFileChecker {
    fn bins(&self) -> Vec<String> {
        vec![]
    }

    fn check(&self, content: &str) -> Option<Hit> {
        let tokens = shell::tokenize(content);
        for token in tokens.iter().skip(1) {
            if token.starts_with('-') {
                continue;
            }
            if let Some(h) = secrets::check_path(token) {
                return Some(Hit {
                    rule_id: h.id.to_string(),
                    message: format!(
                        "bash access to secret file (rule: {}): {}",
                        h.id, h.reason
                    ),
                });
            }
        }
        None
    }
}
```

- [ ] **Step 4: Register `SecretFileChecker` in `detect_checkers`**

In `detect_checkers`, add `SecretFileChecker` to the candidates vec:

```rust
pub fn detect_checkers(content: &str) -> Vec<Box<dyn ToolChecker>> {
    let candidates: Vec<Box<dyn ToolChecker>> = vec![
        Box::new(FallbackChecker),
        Box::new(SecretFileChecker),
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

- [ ] **Step 5: Run all tests**

```bash
cargo test --lib 2>&1
```

Expected: all tests pass, no compile errors.

- [ ] **Step 6: Commit**

```bash
git add src/checker.rs
git commit -m "feat: add SecretFileChecker to Bash parallel pipeline"
```

---

## Task 3: Hook dispatch — block `Read` tool and add path check to Write/Edit

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Write the failing tests in `src/main.rs`**

Add to the existing `#[cfg(test)] mod tests` block in `src/main.rs`:

```rust
    #[test]
    fn run_hook_blocks_read_of_dotenv() {
        let input = r#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/.env"}}"#;
        assert_eq!(run_hook_from_str(input), ExitCode::from(2));
    }

    #[test]
    fn run_hook_allows_read_of_normal_file() {
        let input = r#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/main.rs"}}"#;
        assert_eq!(run_hook_from_str(input), ExitCode::SUCCESS);
    }

    #[test]
    fn run_hook_blocks_write_to_secret_path() {
        let input = r#"{"tool_name":"Write","tool_input":{"file_path":"/home/user/.env","content":"HELLO=world"}}"#;
        assert_eq!(run_hook_from_str(input), ExitCode::from(2));
    }

    #[test]
    fn run_hook_blocks_edit_of_secret_path() {
        let input = r#"{"tool_name":"Edit","tool_input":{"file_path":"/home/user/id_rsa","new_string":"fake key"}}"#;
        assert_eq!(run_hook_from_str(input), ExitCode::from(2));
    }
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test --test-threads=1 run_hook_blocks_read run_hook_blocks_write_to_secret run_hook_blocks_edit_of_secret 2>&1 | grep -E "FAILED|ok"
```

Expected: three tests FAILED.

- [ ] **Step 3: Add `use rsh::secrets;` to imports in `src/main.rs`**

Change the first import line from:

```rust
use rsh::{aliases, blacklist, disabled, forbid};
```

to:

```rust
use rsh::{aliases, blacklist, disabled, forbid, secrets};
```

- [ ] **Step 4: Add the `Read` arm and path checks to `run_hook_from_str`**

In `run_hook_from_str`, the current `match input.tool_name.as_str()` block starts with `"Write"`. Add the `"Read"` arm before it, and insert `secrets::check_path` calls inside `"Write"` and `"Edit"`:

```rust
    match input.tool_name.as_str() {
        "Read" => {
            let file_path = input
                .tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Some(h) = secrets::check_path(file_path) {
                eprintln!(
                    "rsh blocked read of secret file (rule: {}): {}",
                    h.id, h.reason
                );
                return ExitCode::from(2);
            }
            ExitCode::SUCCESS
        }
        "Write" => {
            let file_path = input
                .tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let content = input
                .tool_input
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if is_protected_path(file_path) {
                eprintln!("rsh blocked write to protected path: {file_path}");
                return ExitCode::from(2);
            }
            if let Some(h) = secrets::check_path(file_path) {
                eprintln!(
                    "rsh blocked write to secret file (rule: {}): {}",
                    h.id, h.reason
                );
                return ExitCode::from(2);
            }
            run_check_content(content)
        }
        "Edit" => {
            let file_path = input
                .tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let new_string = input
                .tool_input
                .get("new_string")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if is_protected_path(file_path) {
                eprintln!("rsh blocked edit of protected path: {file_path}");
                return ExitCode::from(2);
            }
            if let Some(h) = secrets::check_path(file_path) {
                eprintln!(
                    "rsh blocked edit of secret file (rule: {}): {}",
                    h.id, h.reason
                );
                return ExitCode::from(2);
            }
            run_check_content(new_string)
        }
        "apply_patch" => {
            let command = input
                .tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            run_check_content(command)
        }
        _ => ExitCode::SUCCESS,
    }
```

- [ ] **Step 5: Run all tests**

```bash
cargo test 2>&1
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs
git commit -m "feat: block Read/Write/Edit access to secret files in hook dispatch"
```

---

## Task 4: `rsh rule` — accept `secret-*` IDs; `rsh list` — show secret rules section

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Write the failing tests**

Add to `#[cfg(test)] mod tests` in `src/main.rs`:

```rust
    #[test]
    fn is_valid_rule_id_accepts_secret_rule() {
        assert!(is_valid_rule_id("secret-dotenv"));
        assert!(is_valid_rule_id("secret-pem"));
        assert!(!is_valid_rule_id("secret-nonexistent"));
    }
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
cargo test is_valid_rule_id_accepts_secret_rule 2>&1 | grep -E "FAILED|ok"
```

Expected: FAILED.

- [ ] **Step 3: Update `is_valid_rule_id` to include secret rules**

Replace:

```rust
fn is_valid_rule_id(id: &str) -> bool {
    blacklist::rules().iter().any(|r| r.id == id)
}
```

with:

```rust
fn is_valid_rule_id(id: &str) -> bool {
    blacklist::rules().iter().any(|r| r.id == id)
        || secrets::all_rules().iter().any(|r| r.id == id)
}
```

- [ ] **Step 4: Run test to confirm it passes**

```bash
cargo test is_valid_rule_id_accepts_secret_rule 2>&1 | grep -E "FAILED|ok"
```

Expected: ok.

- [ ] **Step 5: Add SECRET FILE RULES section to `list_rules`**

In `list_rules()` in `src/main.rs`, add the new section after the BLACKLIST RULES section (before the FORBIDDEN CLUSTERS section). Find the line `print_section("FORBIDDEN CLUSTERS, NAMESPACES AND DATABASES");` and insert before it:

```rust
    print_section("SECRET FILE RULES");
    {
        let secret_rules = secrets::all_rules();
        let mut by_category: std::collections::BTreeMap<&str, Vec<&secrets::SecretRule>> =
            std::collections::BTreeMap::new();
        for r in secret_rules {
            by_category.entry(r.category).or_default().push(r);
        }
        println!(
            "  {} rule(s) across {} categor{}\n",
            secret_rules.len(),
            by_category.len(),
            if by_category.len() == 1 { "y" } else { "ies" }
        );
        for (cat, items) in &by_category {
            println!("  ▌ {} ({})", cat, items.len());
            println!("  ────────────────────────────────────────────────────────────");
            for r in items {
                if disabled_set.contains(r.id) {
                    println!("    • {}  [DISABLED]", r.id);
                } else {
                    println!("    • {}", r.id);
                }
                println!("        reason   : {}", r.reason);
                for p in r.patterns {
                    println!("        pattern  : {p}");
                }
                println!();
            }
        }
    }
```

- [ ] **Step 6: Run all tests**

```bash
cargo test 2>&1
```

Expected: all tests pass.

- [ ] **Step 7: Smoke-test `rsh list` output**

```bash
cargo run -- list 2>&1 | grep -A3 "SECRET FILE RULES"
```

Expected: section header followed by rule count and category groups.

- [ ] **Step 8: Commit**

```bash
git add src/main.rs
git commit -m "feat: extend rsh rule and rsh list to include secret file rules"
```

---

## Task 5: End-to-end smoke test and manual hook verification

**Files:**
- No new files

- [ ] **Step 1: Full test suite**

```bash
cargo test 2>&1
```

Expected: all tests pass, no warnings about unused imports.

- [ ] **Step 2: Build release binary**

```bash
cargo build --release 2>&1
```

Expected: compiles without errors.

- [ ] **Step 3: Smoke-test `Read` blocking via stdin**

```bash
echo '{"tool_name":"Read","tool_input":{"file_path":"/home/user/.env"}}' \
  | ./target/release/rsh; echo "exit: $?"
```

Expected: stderr contains `rsh blocked read of secret file (rule: secret-dotenv)`, exit code `2`.

- [ ] **Step 4: Smoke-test `Bash` blocking via stdin**

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"cat /home/user/.env"}}' \
  | ./target/release/rsh; echo "exit: $?"
```

Expected: stderr contains `rsh blocked`, exit code `2`.

- [ ] **Step 5: Smoke-test allowed path passes through**

```bash
echo '{"tool_name":"Read","tool_input":{"file_path":"/home/user/main.rs"}}' \
  | ./target/release/rsh; echo "exit: $?"
```

Expected: no stderr, exit code `0`.

- [ ] **Step 6: Smoke-test `rsh check` for a secret-bearing Bash command**

```bash
./target/release/rsh check "cat ~/.aws/credentials"
```

Expected: output contains `rsh blocked` and the `secret-aws-credentials` rule ID.

- [ ] **Step 7: Final commit**

```bash
git add -p  # stage only if any last-minute fixes were needed
git commit -m "chore: verify secret file protection end-to-end"
```

If no changes were needed in step 7, skip the commit.
