# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Language policy:** all project artifacts (code, comments, docs, commit messages, CLI output, scripts) are written in English. The conversation language with the developer may differ, but anything that ends up in the repo is English-only.

## Project

`rsh` (Rust Security Hook) is a single-binary CLI that registers itself as a Claude Code **PreToolUse hook** and screens every planned `Bash` tool call against a regex blacklist. On a match it exits with code `2` and a stderr reason — Claude Code interprets that as "tool call refused" and surfaces the message to the model.

Inspired by the hook/init mechanics of [rtk-ai/rtk](https://github.com/rtk-ai/rtk), but deliberately minimal: blocking only — no rewriting, no proxying.

**Blacklist status:** a curated mini-set of destructive `kubectl` operations (delete namespace, delete --all, delete crd, force-delete). Additional rules are added by the maintainer in `RAW_RULES` (`src/blacklist.rs`).

## Workflow

```bash
cargo install --path .   # install rsh into ~/.cargo/bin (must be on PATH)
rsh init -g              # register the hook in ~/.claude/settings.json (global)
rsh init                 # alternatively: ./.claude/settings.json in the current project
```

End-user installation goes through `README.md` and `install.sh` (one-liner: `curl -fsSL https://raw.githubusercontent.com/thePermission/RustSecurityHook/main/install.sh | sh`). That path is binary-only and does not require a Rust toolchain — see the release pipeline section below.

## Release pipeline (for end-user install)

End users install `rsh` via the one-liner above. That script does **not** require a Rust toolchain — it downloads a prebuilt binary from the GitHub release. For that to work, the release workflow must have run before publishing:

- `.github/workflows/release.yml` triggers on tag push `v*.*.*` (or `workflow_dispatch` with a tag parameter).
- Matrix build for five targets: `x86_64-unknown-linux-musl` (statically linked), `aarch64-unknown-linux-gnu` (via `cross`), `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`.
- Unix targets are packaged as `rsh-<tag>-<triple>.tar.gz`, the Windows target as `rsh-<tag>-x86_64-pc-windows-msvc.zip`. Both formats contain the binary at the archive root (`rsh` or `rsh.exe`). Assets are attached via `softprops/action-gh-release`.
- `install.sh` (Unix) and `install.ps1` (Windows) both resolve "latest" through the redirect from `/releases/latest` (avoiding the GitHub API rate limit) and download the matching asset. `install.ps1` additionally appends the install dir to the user `PATH` automatically.

**Releasing a new version:**

```sh
# bump version in Cargo.toml, then:
git tag v0.X.Y
git push --tags
# Actions builds and publishes; install.sh picks up the new asset automatically.
```

When changing the asset name, supported targets, or install path, keep `install.sh`, `release.yml`, and the README platform table in sync.

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
| Hook (default)   | no/unknown `argv[1]`             | Reads PreToolUse JSON from stdin, extracts `tool_input.command`, runs it through the blacklist.           |
| `check`          | `rsh check "<cmd>"`              | Checks the argument directly — useful for testing a rule locally.                                         |
| `init`           | `rsh init [-g\|--global]`        | Patches `settings.json` (with `-g` in `~/.claude/`, otherwise project-local `./.claude/`) and runs `detect-aliases`. |
| `list` / `rules` | `rsh list`                       | Prints all rules grouped by `category` (with `bin`, full expanded regex) and the alias map.               |
| `alias`          | `rsh alias <cmd> <alias>`        | Adds an alias to `~/.config/rsh/aliases.json` (e.g. `rsh alias kubectl k`).                               |
| `detect-aliases` | `rsh detect-aliases [cmd]`       | Scans `$PATH` for symlinks/hardlinks whose `realpath` matches `cmd` (or every bound rule binary).         |
| `help`           | `rsh help` / `-h` / `--help`     | Usage summary.                                                                                            |
| `version`        | `rsh version` / `-v` / `--version` | Prints the Cargo package version.                                                                       |

Hook input schema (PreToolUse event from Claude Code): JSON with at least `tool_name` (string) and `tool_input` (object). For the `Bash` tool the command lives in `tool_input.command`. For other tool names, or empty/invalid stdin, `rsh` lets the call through (exit 0). This fail-open behavior is intentional — a crash in the hook must not lock up the whole session.

**Blacklist module** (`src/blacklist.rs`): the place to add rules. Rules are `(id, category, Option<bin>, sub_pattern, reason)` tuples in `RAW_RULES`. When `bin = Some(b)`, the LazyLock init assembles the full regex as `\b(?:b|alias1|alias2|...)\b<sub_pattern>` using aliases loaded from `~/.config/rsh/aliases.json` (module `src/aliases.rs`). When `bin = None`, `sub_pattern` is used as-is. Convention for kubectl-style sub-patterns: start with `\s[^|;&\n]*?\bVERB\b` so flags are allowed between the binary and the verb, and matches don't cross shell separators. When adding a rule: an entry in `RAW_RULES`, at least one positive and one negative test in the `tests` module. `id` slugs are stable — they appear in the block message shown to the model.

**Alias module** (`src/aliases.rs`): persists a `BTreeMap<command, Vec<alias>>` as JSON. Storage location is platform-aware:

- Unix: `$XDG_CONFIG_HOME/rsh/aliases.json` or `~/.config/rsh/aliases.json`.
- Windows: `%XDG_CONFIG_HOME%/rsh/aliases.json` or `%APPDATA%\rsh\aliases.json`.

`home_dir()` looks up `HOME` (Unix) and falls back to `USERPROFILE` (Windows). `detect_in_path()` finds aliases by comparing `std::fs::canonicalize()` of every executable in `$PATH` against the target binary — catches symlinks and hardlinks, **not** wrapper scripts or renamed copies. The executability check is `cfg`-gated: Unix uses the permission-bit, Windows matches the file extension against `PATHEXT`.

**Exit-code contract:** only `0` (allow) and `2` (block, message on stderr). Avoid other exit codes — Claude Code interprets `1` as "hook error", and behavior varies by version, which is not the same as "explicit block".

## Edition

`Cargo.toml` uses `edition = "2024"` (set by `cargo init`). Requires a current stable Rust toolchain — installed via `rustup` (see `~/.cargo/env`).
