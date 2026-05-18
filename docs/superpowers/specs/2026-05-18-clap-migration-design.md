# Design: clap Migration for rsh CLI

**Date:** 2026-05-18  
**Status:** Approved

## Context

`rsh` currently parses CLI arguments manually via `std::env::args()` and a large `match` chain in `main.rs`. This requires hand-written error messages, a custom `parse_init_options` function, and a hand-maintained `print_help` string. The goal is to replace this with [clap](https://docs.rs/clap/latest/clap/) using the derive API.

## Decision

Use **clap 4 derive macros** (`#[derive(Parser)]`) for the full CLI surface, plus `clap_complete` for shell completion generation.

## CLI Structure

```rust
#[derive(Parser)]
#[command(name = "rsh", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}
```

`command: Option<Commands>` — when `None`, the binary runs in **hook mode** (reads PreToolUse JSON from stdin). This preserves the existing rückwärtskompatible invocation by Claude Code and Codex.

### Subcommands

```rust
#[derive(Subcommand)]
enum Commands {
    /// Register rsh hooks for detected tools
    Init {
        #[arg(short = 'g', long)]
        global: bool,
        #[arg(long, value_name = "TOOL")]
        tool: Option<ToolArg>,
    },
    /// Run the blacklist against a literal command string
    Check {
        command: String,
    },
    /// Show all configured rules, forbid lists, and aliases
    #[command(alias = "rules")]
    List,
    /// Register a command alias
    Alias {
        command: String,
        alias: String,
    },
    /// Auto-detect aliases by scanning $PATH for symlinks/hardlinks
    DetectAliases {
        /// Commands to scan (defaults to all rule binaries)
        commands: Vec<String>,
    },
    /// Manage blacklist rules
    Rule {
        #[command(subcommand)]
        action: RuleAction,
    },
    /// Manage forbidden clusters, namespaces, and databases
    Forbid {
        #[command(subcommand)]
        action: ForbidAction,
    },
    /// Generate shell completions
    Completions {
        shell: clap_complete::Shell,
    },
}
```

**Naming:** clap automatically converts `detect_aliases` → `detect-aliases` (kebab-case) for the CLI surface.

### Nested Subcommands

```rust
#[derive(Subcommand)]
enum RuleAction {
    Disable { id: String },
    Enable { id: String },
    List,
}

#[derive(Subcommand)]
enum ForbidAction {
    Cluster { name: String },
    Namespace { name: String },
    Database { hostname: String },
    Remove {
        #[command(subcommand)]
        target: ForbidRemoveTarget,
    },
    List,
}

#[derive(Subcommand)]
enum ForbidRemoveTarget {
    Cluster { name: String },
    Namespace { name: String },
    Database { hostname: String },
}

#[derive(ValueEnum, Clone)]
enum ToolArg {
    Claude,
    Codex,
    All,
}
```

## Dependencies

```toml
clap = { version = "4", features = ["derive"] }
clap_complete = "4"
```

## Shell Completions

New subcommand `rsh completions <shell>` where `<shell>` is one of `bash`, `zsh`, `fish`, `powershell`, `elvish`:

```rust
Commands::Completions { shell } => {
    clap_complete::generate(shell, &mut Cli::command(), "rsh", &mut io::stdout());
    ExitCode::SUCCESS
}
```

## Version Flag

clap's default short form for `--version` is `-V` (uppercase).

**Breaking changes (intentional):**
- `rsh version` (bare subcommand) is removed — use `rsh --version` or `rsh -V`.
- `-v` short form is dropped in favour of clap's standard `-V`.

These are minor CLI surface changes; the hook invocation (no args) is unaffected.

## What Changes

| Before | After |
|--------|-------|
| `parse_init_options(&args[2..])` | clap parses `Init { global, tool }` |
| `print_help()` (manual string) | clap auto-generates `--help` / `-h` |
| `-v` / `--version` / `version` sub | `--version` / `-V` (clap built-in) |
| `parse_init_options` unit tests | removed (clap is self-tested) |
| `run_rule(&args[2..])` | `run_rule(action: RuleAction)` |
| `run_forbid(&args[2..])` | `run_forbid(action: ForbidAction)` |

## What Stays Unchanged

- Exit-code contract: `0` (allow), `2` (block). No other exit codes.
- `run_hook_from_str` — business logic untouched.
- `run_detect`, `list_rules`, `run_check`, `run_hook` — logic unchanged, only call-site signatures adapt.
- All blacklist, forbid, alias, and disabled module internals.
- Integration tests in `src/blacklist.rs` and `src/forbid.rs`.

## Error Handling

clap exits with code `2` for argument errors and prints a user-friendly message to stderr. This aligns with rsh's existing exit-code contract for blocks — both use `2`. In hook mode (no subcommand), argument errors cannot occur, so there is no conflict.

## Testing

- Existing `run_hook_from_str` tests in `main.rs` remain.
- `detect_targets` and `install_*_hook` tests remain.
- The `parse_init_options_*` tests are removed (replaced by clap's own validation).
- Manual smoke test: `rsh --help`, `rsh init --help`, `rsh completions bash`.
