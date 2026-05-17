# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Language policy:** all project artifacts (code, comments, docs, commit messages, CLI output, scripts) are written in English. The conversation language with the developer may differ, but anything that ends up in the repo is English-only.

## Project

`rsh` (Rust Security Hook) is a single-binary CLI that registers itself as a Claude Code **PreToolUse hook** and screens every planned `Bash` tool call against a regex blacklist. On a match it exits with code `2` and a stderr reason — Claude Code interprets that as "tool call refused" and surfaces the message to the model.

Inspired by the hook/init mechanics of [rtk-ai/rtk](https://github.com/rtk-ai/rtk), but deliberately minimal: blocking only — no rewriting, no proxying.

**Blacklist status:** 18 rules across five categories — Kubernetes Destructive, Pod Access, Privilege Escalation, Service Disruption, and Helm. Additional rules are added by the maintainer in `RAW_RULES` (`src/blacklist.rs`).

## Workflow

```bash
cargo install --path .   # install rsh into ~/.cargo/bin (must be on PATH)
rsh init -g              # register the hook in ~/.claude/settings.json (global)
rsh init                 # alternatively: ./.claude/settings.json in the current project
```

End-user installation goes through the cargo-dist-generated installer scripts hosted on the release page (one-liner in `README.md`). That path is binary-only and does not require a Rust toolchain — see the release pipeline section below.

## Release pipeline (for end-user install)

The release pipeline is managed by [`cargo-dist`](https://opensource.axo.dev/cargo-dist/). It owns three things that **must not be hand-edited**:

- `.github/workflows/release.yml` — regenerated every time the dist config or version changes.
- `rsh-installer.sh` / `rsh-installer.ps1` — generated at release time and uploaded as release assets (not committed to the repo).
- The artifact layout (filenames, tarball/zip choice, checksums).

The pipeline lives in `dist-workspace.toml`. Targets, installers, and install path are configured there. After any change, run `dist generate` to refresh `release.yml`.

**Releasing a new version:**

```sh
# 1. bump the version
vim Cargo.toml          # update [package].version
cargo build             # refresh Cargo.lock
git add Cargo.toml Cargo.lock
git commit -m "chore: release v0.X.Y"
git push origin main

# 2. tag and push (cargo-dist accepts tag formats like v0.X.Y,
#    0.X.Y, rsh/0.X.Y, etc. — see release.yml header)
git tag v0.X.Y
git push origin v0.X.Y
```

The workflow runs `dist plan` → `dist build` → uploads artifacts → creates the GitHub Release with a generated body. PRs touching `release.yml` also trigger a dry-run build for verification.

When upgrading the dist version (`cargo install cargo-dist --locked`), update `cargo-dist-version` in `dist-workspace.toml` to match, then `dist generate` again.

## Build / Test

```bash
cargo build --release           # release binary at target/release/rsh
cargo test                      # unit tests live in src/blacklist.rs
cargo test <name>               # single test, e.g. cargo test blocks_delete_namespace
rsh check "kubectl delete ns x" # run the blacklist against a literal command
```

Manual hook simulation (this is exactly how Claude Code invokes the binary):

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | rsh
# exit 0 → allowed
```

## Architecture

The binary dispatches on `argv[1]`:

| Mode             | Trigger                          | Behavior                                                                                                  |
|------------------|----------------------------------|-----------------------------------------------------------------------------------------------------------|
| Hook (default)   | no/unknown `argv[1]`             | Reads PreToolUse JSON from stdin. `Bash`: splits the command into segments (`split_segments`), runs each through the ToolChecker parallel pipeline (`run_parallel_checks`). `Write`/`Edit`: checks `file_path` against protected paths, then runs the content through the same pipeline. Other tool names pass through (exit 0). |
| `check`          | `rsh check "<cmd>"`              | Checks the argument directly against both pipelines — useful for testing a rule locally.                  |
| `init`           | `rsh init [-g\|--global]`        | Patches `settings.json` (with `-g` in `~/.claude/`, otherwise project-local `./.claude/`) and runs `detect-aliases`. |
| `list` / `rules` | `rsh list`                       | Prints all rules grouped by `category` (with `bin`, full expanded regex), the forbid lists, and the alias map. |
| `alias`          | `rsh alias <cmd> <alias>`        | Adds an alias to `~/.config/rsh/aliases.json` (e.g. `rsh alias kubectl k`).                               |
| `detect-aliases` | `rsh detect-aliases [cmd]`       | Scans `$PATH` for symlinks/hardlinks whose `realpath` matches `cmd` (or every bound rule binary).         |
| `forbid`         | `rsh forbid ...`                 | Manages forbidden clusters and namespaces. Sub-commands: `cluster <name>`, `namespace <name>`, `remove cluster\|namespace <name>`, `list`. |
| `help`           | `rsh help` / `-h` / `--help`     | Usage summary.                                                                                            |
| `version`        | `rsh version` / `-v` / `--version` | Prints the Cargo package version.                                                                       |

Hook input schema (PreToolUse event from Claude Code): JSON with at least `tool_name` (string) and `tool_input` (object). For the `Bash` tool the command lives in `tool_input.command`. For tool names other than `Bash`, `Write`, and `Edit`, or for empty/invalid stdin, `rsh` lets the call through (exit 0). This fail-open behavior is intentional — a crash in the hook must not lock up the whole session.

**Blacklist module** (`src/blacklist.rs`): the place to add rules. Rules are `(id, category, Option<bin>, sub_pattern, reason)` tuples in `RAW_RULES`. When `bin = Some(b)`, the LazyLock init assembles the full regex as `\b(?:b|alias1|alias2|...)\b<sub_pattern>` using aliases loaded from `~/.config/rsh/aliases.json` (module `src/aliases.rs`). When `bin = None`, `sub_pattern` is used as-is — these rules run in `FallbackChecker` on every segment. Convention for kubectl-style sub-patterns: start with `\s[^|;&\n]*?\bVERB\b` so flags are allowed between the binary and the verb, and matches don't cross shell separators. When adding a rule: an entry in `RAW_RULES`, at least one positive and one negative test in the `tests` module. `id` slugs are stable — they appear in the block message shown to the model.

**Forbid module** (`src/forbid.rs`): a second blocking pipeline orthogonal to the regex blacklist. Targets are the *cluster* and *namespace* a kubectl/helm command would hit, rather than the surface syntax of the command itself. Forbid checks are integrated into individual `ToolChecker` implementations: `KubectlChecker` and `HelmChecker` call `forbid::check_with` for cluster/namespace, and `FallbackChecker` calls `forbid::check_db` for databases. Either returning a hit produces exit code 2.

The check extracts `--context=`/`--kube-context=` and `--namespace=`/`-n` from the command-line. If a flag is present, the extracted value is checked against the on-disk forbid lists. If a flag is absent, `forbid::check` falls back to live `kubectl config current-context` / `kubectl config view --minify -o jsonpath={..namespace}` to determine what the command would target by default. The `KubeEnv` trait makes those lookups injectable so the check is unit-testable without `kubectl` installed.

Storage: `~/.config/rsh/forbidden.json` (or `%APPDATA%\rsh\forbidden.json` on Windows), holding `{ "clusters": [...], "namespaces": [...] }`. CLI surface: `rsh forbid cluster|namespace <name>`, `rsh forbid remove cluster|namespace <name>`, `rsh forbid list`. The forbid section is also rendered in `rsh list`.

**Alias module** (`src/aliases.rs`): persists a `BTreeMap<command, Vec<alias>>` as JSON. The process-wide `aliases::ALIASES` `LazyLock` is shared between `blacklist` and `forbid` so we parse the JSON once per hook invocation. Storage location is platform-aware:

- Unix: `$XDG_CONFIG_HOME/rsh/aliases.json` or `~/.config/rsh/aliases.json`.
- Windows: `%XDG_CONFIG_HOME%/rsh/aliases.json` or `%APPDATA%\rsh\aliases.json`.

`home_dir()` looks up `HOME` (Unix) and falls back to `USERPROFILE` (Windows). `detect_in_path()` finds aliases by comparing `std::fs::canonicalize()` of every executable in `$PATH` against the target binary — catches symlinks and hardlinks, **not** wrapper scripts or renamed copies. The executability check is `cfg`-gated: Unix uses the permission-bit, Windows matches the file extension against `PATHEXT`.

**Exit-code contract:** only `0` (allow) and `2` (block, message on stderr). Avoid other exit codes — Claude Code interprets `1` as "hook error", and behavior varies by version, which is not the same as "explicit block".

## Benchmark workflow

The project uses **Criterion** (`benches/hook.rs`). Before starting any performance-relevant feature, capture a baseline:

```bash
cargo bench 2>&1 | tee docs/benchmarks/<feature-slug>-before.txt
```

After the feature is complete, run the same command and save the result:

```bash
cargo bench 2>&1 | tee docs/benchmarks/<feature-slug>-after.txt
```

Criterion prints change percentages automatically when the same benchmark IDs exist in both runs — include the relevant lines in the commit message or ADR. Benchmark files in `docs/benchmarks/` are ephemeral — delete them after the comparison is recorded in the ADR.

## Documentation workflow

After a feature is fully implemented:

1. Distill the content of `docs/superpowers/specs/<feature>.md` and `docs/superpowers/plans/<feature>.md` into permanent documentation:
   - **ADR** (`docs/adr/NNN-<slug>.md`) — record the architectural decision: context, decision, alternatives considered, consequences.
   - **Behavior doc** (`docs/behavior/<topic>.md`) — describe the resulting behavior for users and contributors (living document, updated as rules evolve).
2. Delete the spec and plan files — their content now lives in the ADR and behavior docs.
   Run `find docs/superpowers -type f | sort` to confirm both are gone before closing the branch. Do not rely on subagent self-reports; verify directly.

If no spec/plan exists for a feature, write the ADR and behavior doc from scratch before closing the branch.

3. Update `README.md` to reflect the current state of the code — verify that all described commands, flags, and behaviors match the actual implementation.

## Edition

`Cargo.toml` uses `edition = "2024"` (set by `cargo init`). Requires a current stable Rust toolchain — installed via `rustup` (see `~/.cargo/env`).
