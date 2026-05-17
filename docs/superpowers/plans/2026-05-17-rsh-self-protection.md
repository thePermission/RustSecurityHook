# rsh Self-Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent Claude from weakening rsh's own security configuration by blocking `rsh rule disable`, `rsh forbid remove`, any Bash access to `~/.config/rsh/`, and Write/Edit tool calls targeting that directory.

**Architecture:** Two mechanisms work together. Three new blacklist rules (category "rsh Self-Protection") cover all Bash-level attacks; they are self-referential and cannot be disabled through the Bash tool. A hardcoded `is_protected_path()` check in `run_hook()` covers Write/Edit tool calls by inspecting `file_path` before scanning content — this check does not consult the disabled-rules config and is therefore immutable.

**Tech Stack:** Rust, `regex` crate (already in use), existing blacklist/hook infrastructure in `src/blacklist.rs` and `src/main.rs`.

---

### Task 1: Failing tests for the three new blacklist rules

**Files:**
- Modify: `src/blacklist.rs` (tests module, at the end of the file)

- [ ] **Step 1: Add failing tests for `rsh-protect-disable`**

Append inside the `#[cfg(test)] mod tests { ... }` block in `src/blacklist.rs`:

```rust
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
    // unrelated config paths must not be blocked
    assert!(!blocks("cat ~/.config/other/file.json"));
    assert!(!blocks("ls ~/.config/"));
}
```

- [ ] **Step 2: Run the tests to confirm they fail**

```bash
cargo test blocks_rsh_rule_disable blocks_rsh_forbid_remove blocks_rsh_config_access 2>&1 | tail -20
```

Expected: three test failures (the functions referenced do not yet exist as rules).

---

### Task 2: Add the three blacklist rules

**Files:**
- Modify: `src/blacklist.rs` (RAW_RULES constant — find the end of the list just before the closing `];`)

- [ ] **Step 1: Add the new rule entries**

Locate the closing `];` of `RAW_RULES`. Directly above it, insert:

```rust
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
        Some("rsh"),
        r"(?:^|\s)[^|;&\n]*\.config[/\\]rsh\b",
        "Prevents any Bash access to the rsh config directory — protects disabled-rules, aliases, and forbidden lists",
    ),
```

- [ ] **Step 2: Run the three new tests**

```bash
cargo test blocks_rsh_rule_disable blocks_rsh_forbid_remove blocks_rsh_config_access 2>&1 | tail -20
```

Expected: all three pass.

- [ ] **Step 3: Run the full test suite**

```bash
cargo test 2>&1 | tail -20
```

Expected: all tests pass, no regressions.

- [ ] **Step 4: Smoke-check with `rsh check`**

```bash
cargo build --release 2>/dev/null
./target/release/rsh check "rsh rule disable k8s-delete-namespace"
echo "exit: $?"
./target/release/rsh check "rsh rule list"
echo "exit: $?"
```

Expected: first command prints a block message and exits 2; second exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/blacklist.rs
git commit -m "feat: add rsh self-protection blacklist rules"
```

---

### Task 3: Failing tests for `is_protected_path` and the Write/Edit path check

**Files:**
- Modify: `src/main.rs` (tests module — add a new `#[cfg(test)] mod protected_path_tests { ... }` block at the bottom of the file, or inside an existing test module if one exists)

- [ ] **Step 1: Add unit tests for `is_protected_path`**

At the bottom of `src/main.rs`, append:

```rust
#[cfg(test)]
mod protected_path_tests {
    use super::is_protected_path;

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
    }
}
```

- [ ] **Step 2: Run the new tests to confirm they fail**

```bash
cargo test protected_path_tests 2>&1 | tail -20
```

Expected: all three tests fail to compile because `is_protected_path` is not defined yet.

---

### Task 4: Implement `is_protected_path` and extend the Write/Edit handlers

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Add `is_protected_path`**

Add the function anywhere before `run_hook()`:

```rust
fn is_protected_path(path: &str) -> bool {
    let p = path.replace('\\', "/");
    p.contains(".config/rsh")
}
```

- [ ] **Step 2: Extend the Write handler in `run_hook()`**

Find this block in `run_hook()`:

```rust
        "Write" => {
            let content = input
                .tool_input
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            run_check_content(content)
        }
```

Replace it with:

```rust
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
            run_check_content(content)
        }
```

- [ ] **Step 3: Extend the Edit handler in `run_hook()`**

Find:

```rust
        "Edit" => {
            let new_string = input
                .tool_input
                .get("new_string")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            run_check_content(new_string)
        }
```

Replace with:

```rust
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
            run_check_content(new_string)
        }
```

- [ ] **Step 4: Run the full test suite**

```bash
cargo test 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 5: Smoke-check the Write/Edit path check**

```bash
cargo build --release 2>/dev/null
echo '{"tool_name":"Write","tool_input":{"file_path":"/home/user/.config/rsh/disabled-rules.json","content":"[]"}}' | ./target/release/rsh
echo "exit: $?"
echo '{"tool_name":"Edit","tool_input":{"file_path":"~/.config/rsh/aliases.json","old_string":"{}","new_string":"{}"}}' | ./target/release/rsh
echo "exit: $?"
echo '{"tool_name":"Write","tool_input":{"file_path":"/home/user/projects/main.rs","content":"fn main() {}"}}' | ./target/release/rsh
echo "exit: $?"
```

Expected: first two commands exit 2 with a "blocked write/edit to protected path" message; third exits 0.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs
git commit -m "feat: block Write/Edit tool calls targeting the rsh config directory"
```

---

### Task 5: Update CLAUDE.md and write documentation

**Files:**
- Modify: `CLAUDE.md`

The Architecture section in `CLAUDE.md` currently says:

> For other tool names, or empty/invalid stdin, `rsh` lets the call through (exit 0).

This is outdated — `Write` and `Edit` are also handled. Fix that sentence.

- [ ] **Step 1: Fix the incorrect sentence in CLAUDE.md**

Find in `CLAUDE.md`:

```
For other tool names, or empty/invalid stdin, `rsh` lets the call through (exit 0). This fail-open behavior is intentional — a crash in the hook must not lock up the whole session.
```

Replace with:

```
For tool names other than `Bash`, `Write`, and `Edit`, or for empty/invalid stdin, `rsh` lets the call through (exit 0). This fail-open behavior is intentional — a crash in the hook must not lock up the whole session.
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: correct hook tool coverage description in CLAUDE.md"
```

---

### Task 6: Write ADR and behavior doc, clean up spec/plan

**Files:**
- Create: `docs/adr/009-rsh-self-protection.md`
- Create: `docs/behavior/rsh-self-protection.md`
- Delete: `docs/superpowers/specs/2026-05-17-rsh-self-protection-design.md`
- Delete: `docs/superpowers/plans/2026-05-17-rsh-self-protection.md`

- [ ] **Step 1: Write ADR 009**

Create `docs/adr/009-rsh-self-protection.md`:

```markdown
# ADR 009 — rsh Self-Protection

**Date:** 2026-05-17
**Status:** Accepted

## Context

The `rsh rule disable` command (introduced in a prior feature) allows any caller
to deactivate individual blacklist rules for a session. Since Claude Code is the
primary hook caller, it could — intentionally or via prompt injection — disable
a rule and then execute the previously blocked command. The same risk applies to
`rsh forbid remove` (weakens the forbid list) and direct file access to
`~/.config/rsh/` (overwrites config files via Bash, Write, or Edit tools).

## Decision

Two complementary mechanisms protect the rsh config:

**1. Blacklist rules (Bash protection)**
Three rules in a new "rsh Self-Protection" category block every Bash-level
attack:
- `rsh-protect-disable`: blocks `rsh rule disable <id>`
- `rsh-protect-forbid-remove`: blocks `rsh forbid remove <type> <name>`
- `rsh-protect-config-access`: blocks any Bash command containing `.config/rsh`

The first rule is self-referential: any attempt to run
`rsh rule disable rsh-protect-disable` itself matches the rule and is blocked.
The protection cannot be lifted through the Bash tool.

**2. Hardcoded path check (Write/Edit protection)**
`run_hook()` checks the `file_path` parameter of `Write` and `Edit` tool calls
against a hardcoded `is_protected_path()` function before scanning content.
Any path containing `.config/rsh` is rejected with exit code 2. This check does
not consult the disabled-rules config and is therefore immutable.

## Alternatives Considered

- **Rules only, no path check:** Write/Edit tool calls would remain unprotected
  since they are matched by content, not by path.
- **Hardcoded protection only (no rules):** Protection would be invisible in
  `rsh list` and harder to discover and reason about.
- **Block `rsh rule enable` too:** Rejected — re-enabling a rule is a
  security-increasing operation and should remain available.

## Consequences

- Claude cannot disable blacklist rules or remove forbid entries within a hook
  session.
- Direct writes to `~/.config/rsh/` via any Claude Code tool call are blocked.
- Users can still manage rsh config manually outside a Claude Code session; the
  hook only runs during tool calls.
- The new rules appear in `rsh list` under "rsh Self-Protection".
```

- [ ] **Step 2: Write behavior doc**

Create `docs/behavior/rsh-self-protection.md`:

```markdown
# rsh Self-Protection

rsh protects its own configuration from modification during Claude Code sessions.

## What is blocked

| Attack vector | Blocked by |
|---------------|-----------|
| `rsh rule disable <id>` (Bash) | rule `rsh-protect-disable` |
| `rsh forbid remove <type> <name>` (Bash) | rule `rsh-protect-forbid-remove` |
| Any Bash command containing `.config/rsh` | rule `rsh-protect-config-access` |
| Write tool targeting a `.config/rsh` path | hardcoded path check |
| Edit tool targeting a `.config/rsh` path | hardcoded path check |

## What remains allowed

- `rsh rule enable <id>` — re-enabling a rule is security-increasing
- `rsh rule list`, `rsh list` — read-only operations
- `rsh forbid cluster/namespace/database <name>` — adding restrictions
- Manual edits to `~/.config/rsh/` outside Claude Code sessions (the hook only
  runs during tool calls)

## Self-protection property

The `rsh-protect-disable` rule cannot be disabled through the Bash tool: any
attempt to run `rsh rule disable rsh-protect-disable` matches the rule itself
and is blocked before taking effect.

The Write/Edit path check is hardcoded in `run_hook()` and does not consult the
disabled-rules config. It cannot be bypassed by disabling any rule.
```

- [ ] **Step 3: Delete spec and plan**

```bash
rm docs/superpowers/specs/2026-05-17-rsh-self-protection-design.md
rm docs/superpowers/plans/2026-05-17-rsh-self-protection.md
```

- [ ] **Step 4: Verify both files are gone**

```bash
find docs/superpowers -type f | sort
```

Expected: neither the spec nor the plan appears in the output.

- [ ] **Step 5: Commit**

```bash
git add docs/adr/009-rsh-self-protection.md docs/behavior/rsh-self-protection.md
git rm docs/superpowers/specs/2026-05-17-rsh-self-protection-design.md
git rm docs/superpowers/plans/2026-05-17-rsh-self-protection.md
git commit -m "docs: add ADR 009 and behavior doc for rsh self-protection"
```
