---
title: "ADR 012: Per-Checker Documentation Structure"
tags:
  - rsh/adr
  - rsh/docs
---

# ADR 012: Per-Checker Documentation Structure

## Context

The original behavior documentation was organised thematically:

| File | Topic |
|---|---|
| `kubernetes-rules.md` | All kubectl and helm rules |
| `docker-rules.md` | Docker and Compose rules |
| `sql-rules.md` | SQL keyword rules |
| `content-scanning.md` | Write/Edit interception and script scanning |
| `rsh-self-protection.md` | rsh self-protection rules |
| `forbid-system.md` | Cluster, namespace, and database forbid |

This grouping predated the `ToolChecker` architecture (ADR 011). After that refactor, each
checker owns its rules and its forbid checks. The thematic split cut across checker
boundaries: kubectl's forbid check was in `forbid-system.md`, its subprocess bypass rule
was in `kubernetes-rules.md`, and its primary rules were also in `kubernetes-rules.md` —
three files for one checker.

`CLAUDE.md` still described the old sequential `blacklist::check` → `forbid::check`
pipeline, which had been superseded.

## Decision

Reorganise the behavior documentation to mirror the `ToolChecker` code structure:

**Per Claude Code tool (how input is processed):**
- `bash-tool.md` — segment splitting, script detection, chained commands, parallel pipeline
- `write-edit-tool.md` — protected path check, content scan for Write and Edit

**Per checker (what is checked and blocked):**
- `checker-kubectl.md` — all kubectl rules + cluster/namespace forbid
- `checker-helm.md` — helm rules + cluster/namespace forbid
- `checker-docker.md` — docker/compose rules
- `checker-fallback.md` — SQL rules + subprocess bypass + database forbid
- `checker-rsh.md` — self-protection rules

**Supporting mechanism docs (kept, updated):**
- `forbid-system.md` — storage, CLI, target extraction (referenced by kubectl/helm/fallback)
- `alias-system.md` — alias registration and expansion (unchanged)
- `fast-path-optimization.md` — BinGroup fast-path (unchanged)

All internal cross-references use Obsidian wiki-link syntax (`[[filename]]`).
All files carry YAML frontmatter with `title`, `tags`, and `aliases`.
No single file exceeds 260 lines.

`CLAUDE.md` was updated to describe the ToolChecker parallel pipeline instead of the
old sequential pipeline.

## Alternatives considered

**Keep thematic grouping** — simpler for users who think in terms of "kubernetes rules"
rather than checker internals. Rejected because it forces three-file lookups for a single
checker and diverges from the code structure contributors work with.

**One mega-doc** — put all rules in a single reference table. Simpler to grep, but loses
the per-checker context (which checks run together, what forbid logic applies) and grows
unwieldy as rules are added.

## Consequences

- Adding a new tool means adding one `checker-<tool>.md` file — the same unit as adding
  one `ToolChecker` struct in code.
- Each checker doc is self-contained: rules, forbid checks, aliases, and disable CLI in
  one place.
- `forbid-system.md` is now a mechanism reference only; checker docs explain which
  checkers call it and why.
- `docs/index.md` groups the doc table by Claude Code tool handling and tool categories,
  making the model visible at the top level.
