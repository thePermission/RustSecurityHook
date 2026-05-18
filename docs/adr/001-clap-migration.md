# ADR 001: Adopt clap 4 for CLI argument parsing

**Date:** 2026-05-18  
**Status:** Accepted

## Context

`rsh` previously parsed CLI arguments by calling `std::env::args()` and dispatching on `argv[1]` with a large `match` chain in `main.rs`. This required:

- A hand-maintained `print_help()` function
- Manual parsers (`parse_init_options`, `parse_requested_targets`) that could drift from the actual command tree
- `run_rule` and `run_forbid` doing their own sub-argument parsing from `&[String]` slices
- No built-in completions support

## Decision

Adopt [clap 4](https://docs.rs/clap/latest/clap/) with the derive API (`#[derive(Parser, Subcommand, ValueEnum)]`) as the sole argument-parsing layer. Use `clap_complete` for shell completion generation.

Key choices:
- `Cli { command: Option<Commands> }` — `None` maps to hook mode (reads PreToolUse JSON from stdin). No arguments triggers hook mode, exactly as before.
- `run_rule` and `run_forbid` receive typed enum arguments instead of `&[String]` slices.
- `rsh completions <shell>` added as a new subcommand.

## Breaking Changes

- `rsh -v` (lowercase) removed. Use `rsh --version` or `rsh -V`.
- `rsh version` (bare subcommand) removed. Use `rsh --version`.
- Unknown subcommands now produce a clap parse error (exit 2) rather than falling through to hook mode. Hook mode requires no arguments.
- clap parse errors exit with code 2 (same as the block signal). This only affects interactive misuse; the hook runner always invokes `rsh` with no arguments.

## Alternatives Considered

- **Builder API**: More boilerplate, no type safety gain, no advantage over the existing manual code.
- **Partial adoption** (replace only `parse_init_options`): Inconsistent result, no completions support.

## Consequences

- Help text is generated and stays in sync automatically.
- Compiler catches missing subcommand branches at build time.
- `cli_debug_assert()` test catches malformed clap schemas at test time.
- Binary size increases by the clap + clap_complete dependency graph (~300 KB stripped on Linux/amd64 — acceptable for a dev-tool binary).
