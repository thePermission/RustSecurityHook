# Design: glab Blacklist Rules + Universal Subprocess-Bypass Protection

**Date:** 2026-05-20  
**Status:** Approved

## Context

`rsh` currently protects kubectl, helm, docker, and SQL operations. `glab` (the GitLab
CLI) is missing coverage. An AI agent with `glab` access can permanently delete
repositories, releases, CI/CD variables, and team member access — all irreversible
without a backup.

Additionally, subprocess-list bypass rules (analogous to `k8s-subprocess-list` and
`helm-subprocess-list`) are missing for docker and rsh, leaving gaps where Python/Ruby
code that calls these tools via `subprocess(['docker', 'volume', 'rm', ...])` is not
caught.

## Scope

- New `GlabChecker` in `checker.rs`
- New glab blacklist rules in `blacklist.rs`
- New subprocess-list bypass rules for glab, docker, and rsh

Out of scope: git destructive commands (force push, reset --hard, etc.) — separate feature.

## Architecture

### GlabChecker (`src/checker.rs`)

Analogous to `HelmChecker`. Calls `blacklist::check_for_bin(content, Some("glab"))`.
No forbid-list integration needed (glab has no cluster/namespace concept).

Added to `detect_checkers` candidate list alongside the existing checkers.

### Blacklist Rules (`src/blacklist.rs`)

Category: **"GitLab CLI — Destructive"**, `bin = Some("glab")`.

All sub-patterns follow the established convention:
`\s[^|;&\n]*?\b<verb>\b` — flags are allowed between the binary and the verb, matches
do not cross shell separators.

| ID | Sub-pattern | Reason |
|---|---|---|
| `glab-repo-delete` | `\s[^|;&\n]*?\b(?:repo\|project)\s+delete\b` | Deletes the entire repository/project — irreversible |
| `glab-release-delete` | `\s[^|;&\n]*?\brelease\s+delete\b` | Deletes a published release |
| `glab-variable-delete` | `\s[^|;&\n]*?\bvariable\s+delete\b` | Deletes CI/CD variables — often undocumented secrets |
| `glab-member-delete` | `\s[^|;&\n]*?\bmember\s+delete\b` | Removes a team member's access |
| `glab-issue-delete` | `\s[^|;&\n]*?\bissue\s+delete\b` | Hard-deletes an issue (distinct from closing) |
| `glab-label-delete` | `\s[^|;&\n]*?\blabel\s+delete\b` | Permanently deletes a label |
| `glab-protected-branch-delete` | `\s[^|;&\n]*?\bprotected-branch(?:es)?\s+delete\b` | Removes branch protection rules |

### Subprocess-Bypass Rules (`bin = None`)

Three new `bin = None` rules added to the existing subprocess-bypass section:

| ID | Pattern covers |
|---|---|
| `glab-subprocess-list` | `['glab', ..., 'delete']` in any subprocess call |
| `docker-subprocess-list` | `['docker', ..., 'rm'/'rmi'/'prune'/'volume'/'down']` |
| `rsh-subprocess-list` | `['rsh', 'off'/'on']` |

The glab pattern must match all destructive verbs: `delete` is the common one across all
sub-commands, so a single pattern covering `'delete'` suffices.

The docker pattern covers the most dangerous operations already in the binary-level rules
(`rm`, `rmi`, `volume rm`, `prune`, `compose down`).

## Error Handling

No changes needed. The existing exit-code contract (0 = allow, 2 = block) and
fail-open behavior are unchanged.

## Testing

Each new rule gets at least one positive (blocked) and one negative (allowed) test in
`blacklist.rs`. The `GlabChecker` gets a unit test in `checker.rs`.

The `rule_ids_are_distinct_and_match_expected_set` test must be updated to include all
new rule IDs.

## Non-goals

- No `glab forbid` integration (no cluster/namespace concept in GitLab CLI)
- No rewriting of glab commands
- No coverage of non-destructive glab operations (read, list, create)
