# CLAUDE.md

This file provides guidance when working with code in this repository.

> **Language policy:** all project artifacts (code, comments, docs, commit messages, CLI output, scripts) are written in English. The conversation language with the developer may differ, but anything that ends up in the repo is English-only.

## Project

`rsh` (Rust Security Hook) is a single-binary CLI that registers itself as a Claude Code or Codex **PreToolUse hook** and screens protected tool calls against a regex blacklist. On a match it exits with code `2` and a stderr reason — both tools interpret that as "tool call refused" and surface the message to the model.

Inspired by the hook/init mechanics of [rtk-ai/rtk](https://github.com/rtk-ai/rtk), but deliberately minimal: blocking only — no rewriting, no proxying.

**Blacklist status:** see `README.md` or `rsh list` for the current rule count and categories. Keep documentation in sync with the code instead of hardcoding counts here.

## Workflow

```bash
cargo install --path .   # install rsh into ~/.cargo/bin (must be on PATH)
rsh init -g              # auto-detect and register hooks globally
rsh init                 # auto-detect and register hooks in the current project
rsh init --tool codex    # force Codex-only installation
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

Manual hook simulation:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | rsh
# exit 0 → allowed
```

## Architecture

The binary dispatches on `argv[1]`:

| Mode             | Trigger                          | Behavior                                                                                                  |
|------------------|----------------------------------|-----------------------------------------------------------------------------------------------------------|
| Hook (default)   | no `argv[1]` (no subcommand)     | Reads PreToolUse JSON from stdin. `Bash`: splits the command into segments (`split_segments`), runs each through the ToolChecker parallel pipeline (`run_parallel_checks`). `Write`/`Edit`: checks `file_path` against protected paths, then runs the content through the same pipeline. `apply_patch`: scans `tool_input.command` through the same content pipeline. Other tool names pass through (exit 0). |
| `check`          | `rsh check "<cmd>"`              | Checks the argument directly against both pipelines — useful for testing a rule locally.                  |
| `init`           | `rsh init [-g\|--global] [--tool claude\|codex\|all]` | Auto-detects supported tools or installs explicitly into Claude `settings.json` and/or Codex `hooks.json`, then runs `detect-aliases`. |
| `list` / `rules` | `rsh list`                       | Prints all rules grouped by `category` (with `bin`, full expanded regex), the forbid lists, and the alias map. |
| `alias`          | `rsh alias <cmd> <alias>`        | Adds an alias to `~/.config/rsh/aliases.json` (e.g. `rsh alias kubectl k`).                               |
| `detect-aliases` | `rsh detect-aliases [cmd]`       | Scans `$PATH` for symlinks whose `canonicalize()` path matches `cmd` (or every bound rule binary). Hardlinks are not reliably auto-detected. |
| `forbid`         | `rsh forbid ...`                 | Manages forbidden clusters, namespaces, and database hosts. Sub-commands: `cluster <name>`, `namespace <name>`, `database <host>`, `remove cluster\|namespace\|database <name>`, `list`. |
| `help`           | `rsh help` / `-h` / `--help`     | Usage summary.                                                                                            |
| `version`        | `--version` / `-V`               | Prints the Cargo package version.                                                                       |
| `off`            | `rsh off [-g\|--global]`           | Creates a flag file (`.rsh-disabled` locally, `~/.config/rsh/disabled` globally) that causes the hook to exit 0 immediately, passing all tool calls through unchecked. |
| `on`             | `rsh on [-g\|--global]`            | Removes the flag file created by `rsh off`. Prints "already enabled" if the flag is absent. Agents are blocked from running `rsh off`/`on` by the `rsh-self-disable` blacklist rule. |

Hook input schema (PreToolUse event from Claude Code or Codex): JSON with at least `tool_name` (string) and `tool_input` (object). For `Bash` and Codex `apply_patch`, the command usually lives in `tool_input.command`; Codex command tools may also use `tool_input.cmd`. Claude `Write` uses `tool_input.content`; Claude `Edit` uses `tool_input.new_string`. For unrecognized tool names, or for empty/invalid stdin, `rsh` lets the call through (exit 0). This fail-open behavior is intentional — a crash in the hook must not lock up the whole session.

**Blacklist module** (`src/blacklist.rs`): the place to add rules. Rules are `(id, category, Option<bin>, sub_pattern, reason)` tuples in `RAW_RULES`. When `bin = Some(b)`, the LazyLock init assembles the full regex as `\b(?:b|alias1|alias2|...)\b<sub_pattern>` using aliases loaded from `~/.config/rsh/aliases.json` (module `src/aliases.rs`). When `bin = None`, `sub_pattern` is used as-is — these rules run in `FallbackChecker` on every segment. Convention for kubectl-style sub-patterns: start with `\s[^|;&\n]*?\bVERB\b` so flags are allowed between the binary and the verb, and matches don't cross shell separators. When adding a rule: an entry in `RAW_RULES`, at least one positive and one negative test in the `tests` module. `id` slugs are stable — they appear in the block message shown to the model.

**Forbid module** (`src/forbid.rs`): a second blocking pipeline orthogonal to the regex blacklist. Targets are the *cluster* and *namespace* a kubectl/helm command would hit, rather than the surface syntax of the command itself. Forbid checks are integrated into individual `ToolChecker` implementations: `KubectlChecker` and `HelmChecker` call `forbid::check_with` for cluster/namespace, and `FallbackChecker` calls `forbid::check_db` for databases. Either returning a hit produces exit code 2.

The check tokenizes the command, skips supported wrappers and leading environment assignments, identifies the actual kubectl/helm token, and extracts `--context=`/`--kube-context=` and `--namespace=`/`-n` only from arguments after that token. If a target flag is present, the extracted value is checked against the on-disk forbid lists. For any target not pinned by an explicit flag, `forbid::check` falls back to live `kubectl config current-context` / `kubectl config view --minify -o jsonpath={..namespace}` to determine what the command would target by default. The `KubeEnv` trait makes those lookups injectable so the check is unit-testable without `kubectl` installed.

Storage: `~/.config/rsh/forbidden.json` (or `%APPDATA%\rsh\forbidden.json` on Windows), holding `{ "clusters": [...], "namespaces": [...], "databases": [...] }`. CLI surface: `rsh forbid cluster|namespace|database <name>`, `rsh forbid remove cluster|namespace|database <name>`, `rsh forbid list`. The forbid section is also rendered in `rsh list`.

**Shell module** (`src/shell.rs`): shared tokenization for checker and forbid logic. It uses `shell-words` for POSIX-like quote removal and word splitting, with the older lightweight parser as a fallback for malformed shell fragments. Script scanning expands common home-directory path forms (`~`, `~/...`, `$HOME/...`, `${HOME}/...`) before reading a referenced script; it does not perform general shell expansion, command substitution, or glob expansion.

**Alias module** (`src/aliases.rs`): persists a `BTreeMap<command, Vec<alias>>` as JSON. The process-wide `aliases::ALIASES` `LazyLock` is shared between `blacklist` and `forbid` so we parse the JSON once per hook invocation. Storage location is platform-aware:

- Unix: `$XDG_CONFIG_HOME/rsh/aliases.json` or `~/.config/rsh/aliases.json`.
- Windows: `%XDG_CONFIG_HOME%/rsh/aliases.json` or `%APPDATA%\rsh\aliases.json`.

`home_dir()` looks up `HOME` (Unix) and falls back to `USERPROFILE` (Windows). `detect_in_path()` finds aliases by comparing `std::fs::canonicalize()` of every executable in `$PATH` against the target binary — catches symlinks, **not** hardlinks, wrapper scripts, shell aliases, or renamed copies. The executability check is `cfg`-gated: Unix uses the permission-bit, Windows matches the file extension against `PATHEXT`.

**Exit-code contract:** only `0` (allow) and `2` (block, message on stderr). Avoid other exit codes — Claude Code and Codex interpret non-`2` failures as hook infrastructure errors rather than explicit blocks.

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
