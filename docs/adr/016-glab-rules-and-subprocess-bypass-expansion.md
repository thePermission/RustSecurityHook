# ADR 016 — glab Blacklist Rules and Subprocess-Bypass Expansion

**Date:** 2026-05-20  
**Status:** Accepted

## Context

`rsh` had no coverage for the GitLab CLI (`glab`). An AI agent with `glab` access can
permanently delete repositories, releases, CI/CD variables, team member access, issues,
and labels — all irreversible without an external backup.

Additionally, the subprocess-list bypass protection introduced in ADR 005 covered only
`kubectl` and `helm`. `docker` and `rsh` itself were missing, leaving a gap where code
like `subprocess.run(['docker', 'volume', 'rm', 'mydata'])` bypassed command-level rules.

## Decision

### glab rules

A new `GlabChecker` was added to `src/checker.rs`, following the same pattern as
`HelmChecker` (no forbid integration). Six `bin = Some("glab")` rules were added to
`RAW_RULES` in `src/blacklist.rs`:

| ID | Blocked command | Reason |
|---|---|---|
| `glab-repo-delete` | `glab repo delete` / `glab project delete` | Deletes the entire repository/project — irreversible |
| `glab-release-delete` | `glab release delete` | Deletes a published release |
| `glab-variable-delete` | `glab variable delete` | Deletes a CI/CD variable — often undocumented secrets |
| `glab-repo-members-remove` | `glab repo members remove` | Removes a project member's access |
| `glab-issue-delete` | `glab issue delete` | Hard-deletes an issue (not just closes it) |
| `glab-label-delete` | `glab label delete` | Permanently deletes a project label |

The scope is intentionally limited to irreversible destructive operations. Non-destructive
writes (MR creation, issue creation, label assignment) are not blocked.

**Ruled out during design:** A `glab-protected-branch-delete` rule was initially planned
but dropped after research confirmed the command does not exist in the glab CLI — branch
protection management requires `glab api` or the GitLab web UI.

The initial `glab-member-delete` rule was corrected to `glab-repo-members-remove` after
verifying the real CLI surface: the actual command is `glab repo members remove`, not
`glab member delete`.

### Subprocess-bypass expansion

Three new `bin = None` rules extend the bypass coverage from ADR 005:

| ID | Pattern covers |
|---|---|
| `glab-subprocess-list` | `['glab', ..., 'delete']` in any subprocess argument list |
| `docker-subprocess-list` | `['docker', ..., 'rm'/'rmi'/'prune'/'down']` in subprocess lists |
| `rsh-subprocess-list` | `['rsh', 'off'/'on']` in subprocess lists |

## Alternatives Considered

- **Block all `glab` write operations:** Rejected — too broad; `glab issue create`,
  `glab mr create`, and similar are legitimate agent actions.
- **Add `glab` to the forbid system:** Rejected — `glab` has no cluster/namespace
  concept analogous to kubectl. Forbid integration would require a different abstraction.
- **Skip subprocess bypass for docker/rsh:** Rejected — consistency and completeness
  matter; the gap was real and the fix is cheap.

## Performance

Benchmarked against the baseline from ADR 015 (sequential checker, rsh v0.8.1).
All changes are within ±3.2% — within normal measurement noise.

| Benchmark | Baseline | After | Δ |
|---|---|---|---|
| edge/empty | 47.567 ns | 47.733 ns | +0.3% |
| harmless/ls -la | 3.749 µs | 3.693 µs | −1.5% |
| harmless/git status | 10.027 µs | 10.150 µs | +1.2% |
| blocked_k8s/delete ns | 25.294 µs | 24.799 µs | −2.0% |
| blocked_helm/uninstall | 18.276 µs | 18.543 µs | +1.5% |
| edge/10k_chars | 86.979 µs | 89.726 µs | +3.2% |

No measurable overhead. The BIN_GROUPS fast-path skips all glab rules when `glab`
does not appear in the command, so existing kubectl/helm/docker benchmarks are unaffected.
The three new `bin = None` subprocess-bypass rules run on every command but are simple
regex operations with negligible cost.

## Consequences

- 6 glab rules + 3 subprocess-bypass rules = 9 new rules, bringing the total to 53.
- The `glab-subprocess-list` rule catches all glab destructive verbs with a single
  `delete` match (all 5 destructive glab operations use the `delete` verb, except
  `glab repo members remove` which is not typically called via subprocess lists).
- Dynamic list construction (`cmd = ['glab']; cmd.append('delete')`) is not detected —
  accepted limitation, consistent with the existing subprocess-bypass rules.
- Commands that do not exist in the real glab CLI (e.g., `glab protected-branch delete`)
  are not blocked — avoiding rules for non-existent commands reduces maintenance burden.
