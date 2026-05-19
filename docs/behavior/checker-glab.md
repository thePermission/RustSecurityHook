---
title: GlabChecker
tags:
  - rsh/checker
  - rsh/gitlab
aliases:
  - glab checker
  - GlabChecker
---

# GlabChecker

`GlabChecker` handles every `glab` command and all registered aliases. It activates when
a command segment contains `glab` or any known alias.

## Check Pipeline

One type of check is applied:

1. **Regex blacklist** — surface-level pattern matching against glab-specific rules

No forbid-list integration exists — `glab` has no cluster/namespace concept.

## Regex Blacklist Rules

All glab-specific rules use `bin = Some("glab")`, so aliases are automatically expanded.

### Destructive operations

| ID | Blocked command | Reason |
|---|---|---|
| `glab-repo-delete` | `glab repo delete <name>` or `glab project delete <name>` | Deletes the entire repository/project — irreversible |
| `glab-release-delete` | `glab release delete <tag>` | Deletes a published release |
| `glab-variable-delete` | `glab variable delete <name>` | Deletes a CI/CD variable — often contains undocumented secrets |
| `glab-repo-members-remove` | `glab repo members remove --username=<user>` | Removes a project member's access |
| `glab-issue-delete` | `glab issue delete <id>` | Hard-deletes an issue — distinct from closing, not recoverable |
| `glab-label-delete` | `glab label delete <name>` | Permanently deletes a project label |

**Not blocked:** `glab issue close`, `glab mr create`, `glab issue create`, `glab repo list`,
`glab release create`, `glab variable set`, `glab variable list`, and all other
non-destructive operations.

**No rule for `glab protected-branch delete`:** This command does not exist in the glab
CLI. Protected branch management requires `glab api` or the GitLab web UI.

## Subprocess Bypass

`glab` called inside Python/Ruby/Node subprocess argument lists
(e.g., `['glab', 'repo', 'delete', 'myproject']`) is handled by the [[checker-fallback]]
module via the `glab-subprocess-list` rule, not by this checker. The rule matches on the
`delete` verb, which covers all currently blocked destructive glab operations except
`glab repo members remove` (uses `remove`, not `delete`).

## Aliases

All registered glab aliases are expanded automatically via the alias system. See
[[alias-system]].

## Disabling Rules

Individual rules can be temporarily disabled:

```sh
rsh rule disable glab-repo-delete       # allow glab repo delete until re-enabled
rsh rule enable glab-repo-delete        # restore the block
rsh rule list                            # show all rules with [DISABLED] markers
```
