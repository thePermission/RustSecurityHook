# glab Rules + Subprocess-Bypass Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `glab` blacklist rules for irreversible destructive operations plus subprocess-list bypass rules for glab, docker, and rsh.

**Architecture:** New `GlabChecker` in `checker.rs` (mirrors `HelmChecker`); seven `bin = Some("glab")` rules and three `bin = None` subprocess-bypass rules in `blacklist.rs`; `detect_checkers` updated to include `GlabChecker`.

**Tech Stack:** Rust, `regex` crate, `cargo test`

---

## Files

| File | Change |
|---|---|
| `src/blacklist.rs` | Add 7 glab rules + 3 subprocess-bypass rules; update `rule_ids_are_distinct_and_match_expected_set` |
| `src/checker.rs` | Add `GlabChecker` struct + impl; add to `detect_checkers` candidates |

---

### Task 1: Create feature branch

- [ ] **Step 1: Create and switch to feature branch**

```bash
git checkout -b feat/glab-rules
```

Expected: `Switched to a new branch 'feat/glab-rules'`

---

### Task 2: Add glab blacklist rules (TDD)

**Files:**
- Modify: `src/blacklist.rs`

- [ ] **Step 1: Write failing tests**

Add the following test functions inside the `mod tests` block in `src/blacklist.rs`, after the `// ---- Docker — Container/Image Cleanup ----` section:

```rust
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
fn blocks_glab_member_delete() {
    assert!(blocks("glab member delete johndoe"));
    assert!(blocks("glab member delete johndoe --yes"));
    assert!(!blocks("glab member list"));
    assert!(!blocks("glab member add johndoe --role=developer"));
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

#[test]
fn blocks_glab_protected_branch_delete() {
    assert!(blocks("glab protected-branch delete main"));
    assert!(blocks("glab protected-branches delete main"));
    assert!(!blocks("glab protected-branch list"));
    assert!(!blocks("glab protected-branch create main"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test blocks_glab 2>&1 | tail -20
```

Expected: multiple `FAILED` lines — rules do not exist yet.

- [ ] **Step 3: Add glab rules to `RAW_RULES`**

In `src/blacklist.rs`, find the comment `// ---- rsh Self-Protection` and insert the following block **before** it:

```rust
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
    "glab-member-delete",
    "GitLab CLI — Destructive",
    Some("glab"),
    r"\s[^|;&\n]*?\bmember\s+delete\b",
    "Removes a team member's access to the project",
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
(
    "glab-protected-branch-delete",
    "GitLab CLI — Destructive",
    Some("glab"),
    r"\s[^|;&\n]*?\bprotected-branch(?:es)?\s+delete\b",
    "Removes branch protection rules — allows force-push and deletion of protected branches",
),
```

- [ ] **Step 4: Update `rule_ids_are_distinct_and_match_expected_set`**

Replace the `expected` vec with (glab IDs added, docker-subprocess-list and rsh-subprocess-list not yet included):

```rust
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
    "glab-member-delete",
    "glab-protected-branch-delete",
    "glab-release-delete",
    "glab-repo-delete",
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
```

- [ ] **Step 5: Run all tests**

```bash
cargo test 2>&1 | tail -5
```

Expected: `test result: ok. X passed; 0 failed`

- [ ] **Step 6: Commit**

```bash
git add src/blacklist.rs
git commit -m "feat: add glab destructive operation blacklist rules"
```

---

### Task 3: Add subprocess-bypass rules for docker, rsh, and glab (TDD)

**Files:**
- Modify: `src/blacklist.rs`

- [ ] **Step 1: Write failing tests**

Add inside `mod tests` in `src/blacklist.rs`, after the `blocks_helm_uninstall_in_subprocess_list` test:

```rust
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
    assert!(!blocks("subprocess.run(['docker', 'build', '-t', 'img', '.'])"));
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test blocks_glab_delete_in_subprocess_list blocks_docker_destructive_in_subprocess_list blocks_rsh_off_on_in_subprocess_list 2>&1 | tail -10
```

Expected: all three `FAILED`.

- [ ] **Step 3: Add subprocess-bypass rules to `RAW_RULES`**

In `src/blacklist.rs`, find `helm-subprocess-list` and add the three new rules immediately after it:

```rust
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
    r#"\[['"]rsh['"]\s*(?:,\s*['"][^'"]*['"]\s*)*,\s*['"](?:off|on)['"]"#,
    "rsh off/on in a subprocess argument list — bypasses command-level self-disable protection",
),
```

- [ ] **Step 4: Update `rule_ids_are_distinct_and_match_expected_set`**

Replace the `expected` vec with the complete final list:

```rust
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
    "docker-subprocess-list",
    "docker-system-prune-risky",
    "docker-volume-prune",
    "docker-volume-rm",
    "glab-issue-delete",
    "glab-label-delete",
    "glab-member-delete",
    "glab-protected-branch-delete",
    "glab-release-delete",
    "glab-repo-delete",
    "glab-subprocess-list",
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
    "rsh-subprocess-list",
    "sql-alter-table",
    "sql-create-ddl",
    "sql-delete",
    "sql-drop",
    "sql-truncate",
];
```

- [ ] **Step 5: Run all tests**

```bash
cargo test 2>&1 | tail -5
```

Expected: `test result: ok. X passed; 0 failed`

- [ ] **Step 6: Commit**

```bash
git add src/blacklist.rs
git commit -m "feat: add subprocess-list bypass rules for glab, docker, and rsh"
```

---

### Task 4: Add GlabChecker (TDD)

**Files:**
- Modify: `src/checker.rs`

- [ ] **Step 1: Write failing tests**

Add inside `mod tests` in `src/checker.rs`, after the `docker_checker_*` tests:

```rust
#[test]
fn glab_checker_blocks_repo_delete() {
    let hit = GlabChecker.check("glab repo delete myproject");
    assert!(hit.is_some());
    assert!(hit.unwrap().rule_id.contains("glab-repo-delete"));
}

#[test]
fn glab_checker_blocks_release_delete() {
    let hit = GlabChecker.check("glab release delete v1.0.0");
    assert!(hit.is_some());
    assert!(hit.unwrap().rule_id.contains("glab-release-delete"));
}

#[test]
fn glab_checker_allows_safe_command() {
    assert!(GlabChecker.check("glab repo list").is_none());
    assert!(GlabChecker.check("glab issue view 42").is_none());
    assert!(GlabChecker.check("glab mr list").is_none());
}

#[test]
fn glab_checker_bins_contains_glab() {
    assert!(GlabChecker.bins().iter().any(|b| b == "glab"));
}

#[test]
fn detect_checkers_returns_glab_when_present() {
    let checkers = detect_checkers("glab repo delete myproject");
    assert!(
        checkers
            .iter()
            .any(|c| c.bins().iter().any(|b| b == "glab"))
    );
}

#[test]
fn detect_checkers_does_not_return_glab_for_helm_only() {
    let checkers = detect_checkers("helm list");
    assert!(
        !checkers
            .iter()
            .any(|c| c.bins().iter().any(|b| b == "glab"))
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test glab_checker detect_checkers_returns_glab detect_checkers_does_not_return_glab 2>&1 | tail -10
```

Expected: compilation error — `GlabChecker` not defined yet.

- [ ] **Step 3: Implement `GlabChecker`**

In `src/checker.rs`, find `pub struct RshChecker;` and insert the following block **before** it:

```rust
pub struct GlabChecker;

impl ToolChecker for GlabChecker {
    fn bins(&self) -> Vec<String> {
        aliases::aliases_for(&aliases::ALIASES, "glab")
    }

    fn check(&self, content: &str) -> Option<Hit> {
        blacklist::check_for_bin(content, Some("glab")).map(|h| Hit {
            rule_id: h.id.to_string(),
            message: format!("(rule: {}): {}", h.id, h.reason),
        })
    }
}
```

- [ ] **Step 4: Add `GlabChecker` to `detect_checkers`**

In `src/checker.rs`, find the `candidates` vec in `detect_checkers`. After `Box::new(DockerChecker),` add `Box::new(GlabChecker),`:

```rust
let candidates: Vec<Box<dyn ToolChecker>> = vec![
    Box::new(FallbackChecker),
    Box::new(SecretFileChecker),
    Box::new(KubectlChecker),
    Box::new(HelmChecker),
    Box::new(DockerChecker),
    Box::new(GlabChecker),
    Box::new(RshChecker),
];
```

- [ ] **Step 5: Run all tests**

```bash
cargo test 2>&1 | tail -5
```

Expected: `test result: ok. X passed; 0 failed`

- [ ] **Step 6: Commit**

```bash
git add src/checker.rs
git commit -m "feat: add GlabChecker for glab destructive command detection"
```

---

### Task 5: Final verification

- [ ] **Step 1: Run full test suite**

```bash
cargo test 2>&1
```

Expected: all tests pass, zero failures.

- [ ] **Step 2: Smoke-test blocked command**

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"glab repo delete myproject"}}' | cargo run --quiet 2>&1
echo "exit: $?"
```

Expected: exit code 2, stderr contains `glab-repo-delete`.

- [ ] **Step 3: Smoke-test allowed command**

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"glab repo list"}}' | cargo run --quiet 2>&1
echo "exit: $?"
```

Expected: exit code 0, no output.

- [ ] **Step 4: Verify rule list**

```bash
cargo run --quiet -- list 2>/dev/null | grep -E "glab|docker-subprocess|rsh-subprocess"
```

Expected: all 10 new rule IDs appear in the output.
