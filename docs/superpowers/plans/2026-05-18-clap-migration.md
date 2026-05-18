# clap Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace manual `std::env::args()` parsing in `src/main.rs` with clap 4 derive macros and add a `completions` subcommand via `clap_complete`.

**Architecture:** `Cli::parse()` at the top of `main()` yields `Option<Commands>`; `None` maps to hook mode (reads PreToolUse JSON from stdin, unchanged). All subcommands become enum variants with typed fields; `run_rule` and `run_forbid` receive typed enums instead of `&[String]` slices.

**Tech Stack:** Rust, clap 4 (derive feature), clap_complete 4

---

## File Map

| File | Change |
|------|--------|
| `Cargo.toml` | Add `clap` and `clap_complete` dependencies |
| `src/main.rs` | Add clap type definitions; replace `main()`, `run_rule`, `run_forbid`; remove `parse_init_options`, `parse_requested_targets`, `print_help` |

---

### Task 1: Add clap dependencies

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add dependencies**

  In `Cargo.toml`, replace the `[dependencies]` block with:

  ```toml
  [dependencies]
  serde = { version = "1", features = ["derive"] }
  serde_json = "1"
  regex = "1"
  anyhow = "1"
  clap = { version = "4", features = ["derive"] }
  clap_complete = "4"
  ```

- [ ] **Step 2: Verify compilation**

  Run: `cargo check`

  Expected: no errors (no code changes yet, so this just downloads and compiles the new crates).

- [ ] **Step 3: Commit**

  ```bash
  git add Cargo.toml Cargo.lock
  git commit -m "chore: add clap and clap_complete dependencies"
  ```

---

### Task 2: Define clap types + validation test

**Files:**
- Modify: `src/main.rs`

This task only *adds* type definitions. No existing code is removed or changed yet, so the binary keeps compiling and all existing tests keep passing.

- [ ] **Step 1: Add clap imports**

  At the top of `src/main.rs`, add to the existing `use` block:

  ```rust
  use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
  ```

- [ ] **Step 2: Add type definitions**

  Insert the following block directly after the existing `use` statements and before the `HookInput` struct (i.e., before line 11 in the current file):

  ```rust
  #[derive(Parser)]
  #[command(name = "rsh", version, about = "Rust Security Hook — Claude/Codex PreToolUse hook")]
  struct Cli {
      #[command(subcommand)]
      command: Option<Commands>,
  }

  #[derive(Subcommand)]
  enum Commands {
      /// Register rsh hooks for detected tools
      Init {
          /// Install globally (~/.claude/settings.json) instead of project-local
          #[arg(short = 'g', long)]
          global: bool,
          /// Force a specific tool; auto-detects when omitted
          #[arg(long, value_name = "TOOL")]
          tool: Option<ToolArg>,
      },
      /// Run the blacklist against a literal command string
      Check {
          /// Command string to evaluate
          command: String,
      },
      /// Show all configured rules, forbid lists, and aliases
      #[command(alias = "rules")]
      List,
      /// Register a command alias
      Alias {
          /// Canonical command name (e.g. kubectl)
          command: String,
          /// Alias to register (e.g. k)
          alias: String,
      },
      /// Auto-detect aliases by scanning $PATH for symlinks/hardlinks
      DetectAliases {
          /// Commands to scan; defaults to all rule binaries when empty
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
      /// Print shell completion script to stdout
      Completions {
          /// Target shell
          shell: clap_complete::Shell,
      },
  }

  #[derive(Subcommand)]
  enum RuleAction {
      /// Disable a blacklist rule by ID
      Disable {
          /// Rule ID (see `rsh rule list`)
          id: String,
      },
      /// Re-enable a disabled blacklist rule
      Enable {
          /// Rule ID (see `rsh rule list`)
          id: String,
      },
      /// Show all rules with [DISABLED] marker where applicable
      List,
  }

  #[derive(Subcommand)]
  enum ForbidAction {
      /// Add a forbidden kubectl context (cluster)
      Cluster { name: String },
      /// Add a forbidden Kubernetes namespace
      Namespace { name: String },
      /// Add a forbidden database hostname
      Database { hostname: String },
      /// Remove an entry from the forbid list
      Remove {
          #[command(subcommand)]
          target: ForbidRemoveTarget,
      },
      /// Show all forbidden entries
      List,
  }

  #[derive(Subcommand)]
  enum ForbidRemoveTarget {
      /// Remove a forbidden cluster
      Cluster { name: String },
      /// Remove a forbidden namespace
      Namespace { name: String },
      /// Remove a forbidden database
      Database { hostname: String },
  }

  #[derive(ValueEnum, Clone)]
  enum ToolArg {
      Claude,
      Codex,
      All,
  }
  ```

- [ ] **Step 3: Add cli_debug_assert test**

  In the `#[cfg(test)]` block at the bottom of `src/main.rs`, add:

  ```rust
  #[test]
  fn cli_debug_assert() {
      Cli::command().debug_assert();
  }
  ```

- [ ] **Step 4: Run the new test**

  Run: `cargo test cli_debug_assert -- --nocapture`

  Expected: `test cli_debug_assert ... ok`

- [ ] **Step 5: Run all tests to confirm nothing broke**

  Run: `cargo test`

  Expected: all existing tests still pass.

- [ ] **Step 6: Commit**

  ```bash
  git add src/main.rs
  git commit -m "feat: add clap type definitions and cli_debug_assert test"
  ```

---

### Task 3: Replace `main()` and adapt `run_rule` / `run_forbid`

**Files:**
- Modify: `src/main.rs`

This is the core refactor. All three functions (`main`, `run_rule`, `run_forbid`) must change together in one edit because their signatures are coupled. After this task, `parse_init_options`, `parse_requested_targets`, and `print_help` are fully removed.

- [ ] **Step 1: Replace `main()`**

  Delete the entire `fn main() -> ExitCode { ... }` block (lines 60–130 in the original file) and replace it with:

  ```rust
  fn main() -> ExitCode {
      let cli = Cli::parse();
      match cli.command {
          None => run_hook(),
          Some(Commands::Init { global, tool }) => {
              let requested_targets = tool.map(|t| match t {
                  ToolArg::Claude => vec![HookTarget::Claude],
                  ToolArg::Codex => vec![HookTarget::Codex],
                  ToolArg::All => vec![HookTarget::Claude, HookTarget::Codex],
              });
              match init_hooks(InitOptions { global, requested_targets }) {
                  Ok(results) => {
                      for r in &results {
                          eprintln!(
                              "rsh hook installed for {} in {}",
                              r.target.label(),
                              r.path.display()
                          );
                      }
                      let _ = run_detect(&rule_bins());
                      ExitCode::SUCCESS
                  }
                  Err(e) => {
                      eprintln!("init failed: {e:#}");
                      ExitCode::FAILURE
                  }
              }
          }
          Some(Commands::Check { command }) => run_check(&command),
          Some(Commands::List) => {
              list_rules();
              ExitCode::SUCCESS
          }
          Some(Commands::Alias { command, alias }) => {
              match aliases::add(&command, &alias) {
                  Ok((path, true)) => {
                      eprintln!("added alias {alias} → {command} in {}", path.display());
                      ExitCode::SUCCESS
                  }
                  Ok((path, false)) => {
                      eprintln!(
                          "alias {alias} → {command} already present ({})",
                          path.display()
                      );
                      ExitCode::SUCCESS
                  }
                  Err(e) => {
                      eprintln!("alias failed: {e:#}");
                      ExitCode::FAILURE
                  }
              }
          }
          Some(Commands::DetectAliases { commands }) => {
              let targets = if commands.is_empty() { rule_bins() } else { commands };
              run_detect(&targets)
          }
          Some(Commands::Rule { action }) => run_rule(action),
          Some(Commands::Forbid { action }) => run_forbid(action),
          Some(Commands::Completions { shell }) => {
              clap_complete::generate(
                  shell,
                  &mut Cli::command(),
                  "rsh",
                  &mut std::io::stdout(),
              );
              ExitCode::SUCCESS
          }
      }
  }
  ```

- [ ] **Step 2: Replace `run_rule`**

  Delete the entire old `fn run_rule(args: &[String]) -> ExitCode { ... }` block and replace with:

  ```rust
  fn run_rule(action: RuleAction) -> ExitCode {
      match action {
          RuleAction::Disable { id } => {
              if !is_valid_rule_id(&id) {
                  eprintln!("error: unknown rule id '{id}'");
                  eprintln!("hint: run `rsh rule list` to see all valid rule IDs");
                  return ExitCode::FAILURE;
              }
              match disabled::add(&id) {
                  Ok(true) => {
                      eprintln!("rule: disabled '{id}'");
                      ExitCode::SUCCESS
                  }
                  Ok(false) => {
                      eprintln!("rule: '{id}' was already disabled");
                      ExitCode::SUCCESS
                  }
                  Err(e) => {
                      eprintln!("rule failed: {e:#}");
                      ExitCode::FAILURE
                  }
              }
          }
          RuleAction::Enable { id } => {
              if !is_valid_rule_id(&id) {
                  eprintln!("error: unknown rule id '{id}'");
                  eprintln!("hint: run `rsh rule list` to see all valid rule IDs");
                  return ExitCode::FAILURE;
              }
              match disabled::remove(&id) {
                  Ok(true) => {
                      eprintln!("rule: enabled '{id}'");
                      ExitCode::SUCCESS
                  }
                  Ok(false) => {
                      eprintln!("rule: '{id}' was already enabled");
                      ExitCode::SUCCESS
                  }
                  Err(e) => {
                      eprintln!("rule failed: {e:#}");
                      ExitCode::FAILURE
                  }
              }
          }
          RuleAction::List => {
              list_rules();
              ExitCode::SUCCESS
          }
      }
  }
  ```

- [ ] **Step 3: Replace `run_forbid`**

  Delete the entire old `fn run_forbid(args: &[String]) -> ExitCode { ... }` block and replace with:

  ```rust
  fn run_forbid(action: ForbidAction) -> ExitCode {
      match action {
          ForbidAction::Cluster { name } => match forbid::add_cluster(&name) {
              Ok(true) => {
                  eprintln!("forbid: added cluster '{name}'");
                  ExitCode::SUCCESS
              }
              Ok(false) => {
                  eprintln!("forbid: cluster '{name}' was already on the list");
                  ExitCode::SUCCESS
              }
              Err(e) => {
                  eprintln!("forbid failed: {e:#}");
                  ExitCode::FAILURE
              }
          },
          ForbidAction::Namespace { name } => match forbid::add_namespace(&name) {
              Ok(true) => {
                  eprintln!("forbid: added namespace '{name}'");
                  ExitCode::SUCCESS
              }
              Ok(false) => {
                  eprintln!("forbid: namespace '{name}' was already on the list");
                  ExitCode::SUCCESS
              }
              Err(e) => {
                  eprintln!("forbid failed: {e:#}");
                  ExitCode::FAILURE
              }
          },
          ForbidAction::Database { hostname } => match forbid::add_database(&hostname) {
              Ok(true) => {
                  eprintln!("forbid: added database '{hostname}'");
                  ExitCode::SUCCESS
              }
              Ok(false) => {
                  eprintln!("forbid: database '{hostname}' was already on the list");
                  ExitCode::SUCCESS
              }
              Err(e) => {
                  eprintln!("forbid failed: {e:#}");
                  ExitCode::FAILURE
              }
          },
          ForbidAction::Remove { target } => match target {
              ForbidRemoveTarget::Cluster { name } => match forbid::remove_cluster(&name) {
                  Ok(true) => {
                      eprintln!("forbid: removed cluster '{name}'");
                      ExitCode::SUCCESS
                  }
                  Ok(false) => {
                      eprintln!("forbid: cluster '{name}' was not on the list");
                      ExitCode::SUCCESS
                  }
                  Err(e) => {
                      eprintln!("forbid failed: {e:#}");
                      ExitCode::FAILURE
                  }
              },
              ForbidRemoveTarget::Namespace { name } => match forbid::remove_namespace(&name) {
                  Ok(true) => {
                      eprintln!("forbid: removed namespace '{name}'");
                      ExitCode::SUCCESS
                  }
                  Ok(false) => {
                      eprintln!("forbid: namespace '{name}' was not on the list");
                      ExitCode::SUCCESS
                  }
                  Err(e) => {
                      eprintln!("forbid failed: {e:#}");
                      ExitCode::FAILURE
                  }
              },
              ForbidRemoveTarget::Database { hostname } => {
                  match forbid::remove_database(&hostname) {
                      Ok(true) => {
                          eprintln!("forbid: removed database '{hostname}'");
                          ExitCode::SUCCESS
                      }
                      Ok(false) => {
                          eprintln!("forbid: database '{hostname}' was not on the list");
                          ExitCode::SUCCESS
                      }
                      Err(e) => {
                          eprintln!("forbid failed: {e:#}");
                          ExitCode::FAILURE
                      }
                  }
              }
          },
          ForbidAction::List => {
              let cfg = forbid::load();
              if cfg.is_empty() {
                  println!("(no forbidden clusters, namespaces, or databases configured)");
              } else {
                  println!("Clusters:");
                  if cfg.clusters.is_empty() {
                      println!("  (none)");
                  } else {
                      for c in &cfg.clusters {
                          println!("  • {c}");
                      }
                  }
                  println!("Namespaces:");
                  if cfg.namespaces.is_empty() {
                      println!("  (none)");
                  } else {
                      for n in &cfg.namespaces {
                          println!("  • {n}");
                      }
                  }
                  println!("Databases:");
                  if cfg.databases.is_empty() {
                      println!("  (none)");
                  } else {
                      for d in &cfg.databases {
                          println!("  • {d}");
                      }
                  }
              }
              ExitCode::SUCCESS
          }
      }
  }
  ```

- [ ] **Step 4: Delete obsolete functions**

  Remove the following functions entirely from `src/main.rs`:
  - `fn print_help()` (lines 132–160 in the original)
  - `fn parse_init_options(args: &[String]) -> Result<InitOptions>` (lines 660–680)
  - `fn parse_requested_targets(value: &str) -> Result<Vec<HookTarget>>` (lines 682–689)

- [ ] **Step 5: Build**

  Run: `cargo build`

  Expected: compiles cleanly. Any `unused import` warning for `Context` from `anyhow` is fine to fix by removing it from the `use` line if it appears.

- [ ] **Step 6: Run all tests**

  Run: `cargo test`

  Expected: all tests pass.

- [ ] **Step 7: Commit**

  ```bash
  git add src/main.rs
  git commit -m "feat: replace manual arg parsing with clap derive"
  ```

---

### Task 4: Remove obsolete tests + smoke test

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Remove parse_init_options tests**

  In the `#[cfg(test)]` block at the bottom of `src/main.rs`, delete these two test functions:
  - `fn parse_init_options_defaults_to_auto()`
  - `fn parse_init_options_accepts_global_and_tool()`

  The remaining tests (`detect_targets_uses_existing_config_dirs`, `install_claude_hook_is_idempotent`, `install_codex_hook_is_idempotent`, `run_hook_*`) are unchanged.

- [ ] **Step 2: Run all tests**

  Run: `cargo test`

  Expected: all remaining tests pass.

- [ ] **Step 3: Build release binary**

  Run: `cargo build --release`

  Expected: `target/release/rsh` produced without errors.

- [ ] **Step 4: Smoke test — help**

  Run: `./target/release/rsh --help`

  Expected output contains all subcommands:
  ```
  Commands:
    init
    check
    list
    alias
    detect-aliases
    rule
    forbid
    completions
    help
  ```

- [ ] **Step 5: Smoke test — subcommand help**

  Run: `./target/release/rsh init --help`

  Expected: output mentions `--global` and `--tool`.

- [ ] **Step 6: Smoke test — version**

  Run: `./target/release/rsh --version`

  Expected: `rsh 0.7.3` (matches `version` in `Cargo.toml`).

- [ ] **Step 7: Smoke test — completions**

  Run: `./target/release/rsh completions bash | head -5`

  Expected: non-empty bash completion script output, exit code 0.

- [ ] **Step 8: Smoke test — hook allow (stdin)**

  Run: `echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | ./target/release/rsh`

  Expected: exit code `0`.

- [ ] **Step 9: Smoke test — hook block (stdin)**

  Run the existing unit test that covers blocking behavior:

  `cargo test run_hook_blocks -- --nocapture`

  Expected: all `run_hook_blocks_*` tests pass, confirming the hook path is intact.

- [ ] **Step 10: Commit**

  ```bash
  git add src/main.rs
  git commit -m "chore: remove obsolete parse_init_options tests"
  ```
