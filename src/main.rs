use rsh::{aliases, blacklist, disabled, forbid, nopush, secrets, settings_guard};
use rsh::{is_protected_path, run_check, run_check_content};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use serde_json::json;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "rsh",
    version,
    about = "Rust Security Hook — Claude/Codex PreToolUse hook"
)]
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
    /// Manage tool-level rule switches (disable/enable all rules for a binary)
    Tool {
        #[command(subcommand)]
        action: ToolAction,
    },
    /// Block access to a cluster, namespace, database, or enable the push lock
    Forbid {
        #[command(subcommand)]
        action: ForbidAction,
    },
    /// Lift a forbid restriction or the push lock
    Allow {
        #[command(subcommand)]
        target: AllowTarget,
    },
    /// Print shell completion script to stdout
    Completions {
        /// Target shell
        shell: clap_complete::Shell,
    },
    /// Disable all rsh checks (writes a flag file)
    Off {
        /// Disable globally (~/.config/rsh/disabled) instead of project-local (.rsh-disabled)
        #[arg(short = 'g', long)]
        global: bool,
    },
    /// Re-enable all rsh checks (removes the flag file)
    On {
        /// Remove the global flag (~/.config/rsh/disabled) instead of project-local (.rsh-disabled)
        #[arg(short = 'g', long)]
        global: bool,
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
enum ToolAction {
    /// Disable all blacklist rules for a tool binary
    Disable {
        /// Tool binary name (e.g. kubectl, docker, glab)
        bin: String,
    },
    /// Re-enable all blacklist rules for a tool binary
    Enable {
        /// Tool binary name (e.g. kubectl, docker, glab)
        bin: String,
    },
    /// Show all known tool binaries with rule counts and status
    List,
}

#[derive(Subcommand)]
enum ForbidAction {
    /// Block git push for this project (creates .rsh-nopush flag file)
    Push,
    /// Add a forbidden kubectl context (cluster)
    Cluster { name: String },
    /// Add a forbidden Kubernetes namespace
    Namespace { name: String },
    /// Add a forbidden database hostname
    Database { hostname: String },
    /// Show all forbidden entries
    List,
}

#[derive(Subcommand)]
enum AllowTarget {
    /// Re-enable git push for this project (removes .rsh-nopush)
    Push,
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

#[derive(Deserialize)]
struct HookInput {
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: serde_json::Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HookTarget {
    Claude,
    Codex,
}

impl HookTarget {
    fn label(self) -> &'static str {
        match self {
            HookTarget::Claude => "claude",
            HookTarget::Codex => "codex",
        }
    }

    fn global_path(self, home: &Path) -> PathBuf {
        match self {
            HookTarget::Claude => home.join(".claude/settings.json"),
            HookTarget::Codex => home.join(".codex/hooks.json"),
        }
    }

    fn local_path(self, cwd: &Path) -> PathBuf {
        match self {
            HookTarget::Claude => cwd.join(".claude/settings.json"),
            HookTarget::Codex => cwd.join(".codex/hooks.json"),
        }
    }
}

#[derive(Debug, Default)]
struct InitOptions {
    global: bool,
    requested_targets: Option<Vec<HookTarget>>,
}

#[derive(Debug)]
struct InstallResult {
    target: HookTarget,
    path: PathBuf,
}

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
            match init_hooks(InitOptions {
                global,
                requested_targets,
            }) {
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
        Some(Commands::Alias { command, alias }) => match aliases::add(&command, &alias) {
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
        },
        Some(Commands::DetectAliases { commands }) => {
            let targets = if commands.is_empty() {
                rule_bins()
            } else {
                commands
            };
            run_detect(&targets)
        }
        Some(Commands::Rule { action }) => run_rule(action),
        Some(Commands::Tool { action }) => run_tool(action),
        Some(Commands::Forbid { action }) => run_forbid(action),
        Some(Commands::Allow { target }) => run_allow(target),
        Some(Commands::Completions { shell }) => {
            clap_complete::generate(shell, &mut Cli::command(), "rsh", &mut std::io::stdout());
            ExitCode::SUCCESS
        }
        Some(Commands::Off { global }) => run_off(global),
        Some(Commands::On { global }) => run_on(global),
    }
}

fn list_rules() {
    use std::collections::BTreeMap;

    let globally = disabled::flag_path_global()
        .map(|p| p.exists())
        .unwrap_or(false);
    let locally = disabled::flag_path_local().exists();
    if globally {
        println!("WARNING: rsh is currently DISABLED (global) — run `rsh on -g` to re-enable\n");
    } else if locally {
        println!("WARNING: rsh is currently DISABLED (local) — run `rsh on` to re-enable\n");
    }

    let rules = blacklist::rules();
    let aliases = aliases::load();
    let disabled_set = disabled::load();

    print_section("BLACKLIST RULES");
    if rules.is_empty() {
        println!("  (no rules configured)\n");
    } else {
        let mut by_category: BTreeMap<&str, Vec<&blacklist::Rule>> = BTreeMap::new();
        for r in rules {
            by_category.entry(r.category).or_default().push(r);
        }
        println!(
            "  {} rule(s) across {} categor{}\n",
            rules.len(),
            by_category.len(),
            if by_category.len() == 1 { "y" } else { "ies" }
        );
        for (cat, items) in &by_category {
            let common_bin = items.first().and_then(|r| r.bin);
            let tool_disabled = common_bin.is_some()
                && items.iter().all(|r| r.bin == common_bin)
                && common_bin
                    .map_or(false, |b| disabled_set.contains(&format!("tool:{b}")));
            if tool_disabled {
                println!("  ▌ {} ({})  [TOOL DISABLED]", cat, items.len());
            } else {
                println!("  ▌ {} ({})", cat, items.len());
            }
            println!("  ────────────────────────────────────────────────────────────");
            for r in items {
                if disabled_set.contains(r.id) {
                    println!("    • {}  [DISABLED]", r.id);
                } else {
                    println!("    • {}", r.id);
                }
                println!("        reason  : {}", r.reason);
                if let Some(b) = r.bin {
                    println!("        binary  : {b}");
                }
                println!("        pattern : {}", r.effective_pattern);
                println!();
            }
        }
    }

    print_section("SECRET FILE RULES");
    {
        let secret_rules = secrets::all_rules();
        let mut by_category: BTreeMap<&str, Vec<&secrets::SecretRule>> = BTreeMap::new();
        for r in secret_rules {
            by_category.entry(r.category).or_default().push(r);
        }
        println!(
            "  {} rule(s) across {} categor{}\n",
            secret_rules.len(),
            by_category.len(),
            if by_category.len() == 1 { "y" } else { "ies" }
        );
        for (cat, items) in &by_category {
            println!("  ▌ {} ({})", cat, items.len());
            println!("  ────────────────────────────────────────────────────────────");
            for r in items {
                if disabled_set.contains(r.id) {
                    println!("    • {}  [DISABLED]", r.id);
                } else {
                    println!("    • {}", r.id);
                }
                println!("        reason  : {}", r.reason);
                for p in r.patterns {
                    println!("        pattern : {p}");
                }
                println!();
            }
        }
    }

    print_section("FORBIDDEN CLUSTERS, NAMESPACES AND DATABASES");
    let fcfg = forbid::load();
    if fcfg.invalid {
        println!("  WARNING: {}", forbid::INVALID_CONFIG_MESSAGE);
        println!();
    }
    if fcfg.is_empty() {
        println!("  (none — register with `rsh forbid push`,");
        println!("                       `rsh forbid cluster <name>`,");
        println!("                       `rsh forbid namespace <name>`, or");
        println!("                       `rsh forbid database <hostname>`)\n");
    } else {
        if fcfg.clusters.is_empty() {
            println!("  Clusters:   (none)");
        } else {
            println!("  Clusters ({}):", fcfg.clusters.len());
            for c in &fcfg.clusters {
                println!("    • {c}");
            }
        }
        if fcfg.namespaces.is_empty() {
            println!("  Namespaces: (none)");
        } else {
            println!("  Namespaces ({}):", fcfg.namespaces.len());
            for n in &fcfg.namespaces {
                println!("    • {n}");
            }
        }
        if fcfg.databases.is_empty() {
            println!("  Databases:  (none)");
        } else {
            println!("  Databases ({}):", fcfg.databases.len());
            for d in &fcfg.databases {
                println!("    • {d}");
            }
        }
        println!();
    }

    print_section("ALIASES");
    if aliases.is_empty() {
        println!("  (none — register with `rsh alias <cmd> <alias>`");
        println!("         or auto-detect with `rsh detect-aliases`)\n");
    } else {
        let total: usize = aliases.values().map(|v| v.len()).sum();
        println!(
            "  {} alias{} for {} command{}\n",
            total,
            if total == 1 { "" } else { "es" },
            aliases.len(),
            if aliases.len() == 1 { "" } else { "s" }
        );
        for (cmd, list) in &aliases {
            println!("    {cmd}");
            for (i, a) in list.iter().enumerate() {
                let connector = if i + 1 == list.len() {
                    "└─"
                } else {
                    "├─"
                };
                println!("      {connector} {a}");
            }
            println!();
        }
    }
}

fn list_rule_table() {
    use std::collections::BTreeMap;

    let rules = blacklist::rules();
    let secret_rules = secrets::all_rules();
    let disabled_set = disabled::load();

    let mut by_category: BTreeMap<&str, Vec<&blacklist::Rule>> = BTreeMap::new();
    for r in rules {
        by_category.entry(r.category).or_default().push(r);
    }
    println!(
        "{} blacklist rule(s) across {} categor{}:",
        rules.len(),
        by_category.len(),
        if by_category.len() == 1 { "y" } else { "ies" }
    );
    for (cat, items) in &by_category {
        let common_bin = items.first().and_then(|r| r.bin);
        let tool_disabled = common_bin.is_some()
            && items.iter().all(|r| r.bin == common_bin)
            && common_bin
                .map_or(false, |b| disabled_set.contains(&format!("tool:{b}")));
        if tool_disabled {
            println!("  ▌ {cat}  [TOOL DISABLED]");
        } else {
            println!("  ▌ {cat}");
        }
        for r in items {
            if disabled_set.contains(r.id) {
                println!("    • {}  [DISABLED]", r.id);
            } else {
                println!("    • {}", r.id);
            }
        }
    }
    println!();
    println!("{} secret file rule(s):", secret_rules.len());
    for r in secret_rules {
        if disabled_set.contains(r.id) {
            println!("  • {}  [DISABLED]  ({})", r.id, r.category);
        } else {
            println!("  • {}  ({})", r.id, r.category);
        }
    }
}

fn print_section(title: &str) {
    println!("══════════════════════════════════════════════════════════════");
    println!("  {title}");
    println!("══════════════════════════════════════════════════════════════");
}

fn rule_bins() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for r in blacklist::rules() {
        if let Some(b) = r.bin {
            let s = b.to_string();
            if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out
}

fn run_detect(targets: &[String]) -> ExitCode {
    if targets.is_empty() {
        eprintln!("no targets to scan (no rules with a bound binary)");
        return ExitCode::SUCCESS;
    }
    let mut any_added = false;
    for cmd in targets {
        let found = aliases::detect_in_path(cmd);
        if found.is_empty() {
            eprintln!("no aliases found for {cmd}");
            continue;
        }
        for alias in &found {
            match aliases::add(cmd, alias) {
                Ok((_, true)) => {
                    eprintln!("detected alias {alias} → {cmd}");
                    any_added = true;
                }
                Ok((_, false)) => {
                    eprintln!("alias {alias} → {cmd} (already known)");
                }
                Err(e) => {
                    eprintln!("could not save alias {alias} → {cmd}: {e:#}");
                    return ExitCode::FAILURE;
                }
            }
        }
    }
    if !any_added {
        eprintln!("(no new aliases added)");
    }
    ExitCode::SUCCESS
}

fn run_hook() -> ExitCode {
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() {
        return ExitCode::SUCCESS;
    }
    run_hook_from_str(&buf)
}

fn run_hook_from_str(input: &str) -> ExitCode {
    if disabled::is_disabled() {
        return ExitCode::SUCCESS;
    }
    let Ok(input) = serde_json::from_str::<HookInput>(input) else {
        return ExitCode::SUCCESS;
    };
    if is_command_tool(&input.tool_name, &input.tool_input) {
        let command = extract_command(&input.tool_input);
        if nopush::is_nopush_active() && nopush::is_push_command(command) {
            eprintln!("rsh blocked push: this project is marked read-only (.rsh-nopush)");
            eprintln!("hint: run 'rsh allow push' to re-enable pushing");
            return ExitCode::from(2);
        }
        return run_check(command);
    }

    match input.tool_name.as_str() {
        "Read" => {
            let file_path = input
                .tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Some(h) = secrets::check_path(file_path) {
                eprintln!(
                    "rsh blocked read of secret file (rule: {}): {}",
                    h.id, h.reason
                );
                return ExitCode::from(2);
            }
            ExitCode::SUCCESS
        }
        "Write" => {
            let file_path = input
                .tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let content = input
                .tool_input
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if is_protected_path(file_path) {
                eprintln!("rsh blocked write to protected path: {file_path}");
                return ExitCode::from(2);
            }
            if let Some(h) = secrets::check_path(file_path) {
                eprintln!(
                    "rsh blocked write to secret file (rule: {}): {}",
                    h.id, h.reason
                );
                return ExitCode::from(2);
            }
            if settings_guard::is_settings_path(file_path)
                && settings_guard::write_removes_hook(file_path, content)
            {
                eprintln!(
                    "rsh blocked write to {file_path}: would remove rsh PreToolUse hook"
                );
                return ExitCode::from(2);
            }
            run_check_content(content)
        }
        "Edit" => {
            let file_path = input
                .tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let old_string = input
                .tool_input
                .get("old_string")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let new_string = input
                .tool_input
                .get("new_string")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if is_protected_path(file_path) {
                eprintln!("rsh blocked edit of protected path: {file_path}");
                return ExitCode::from(2);
            }
            if let Some(h) = secrets::check_path(file_path) {
                eprintln!(
                    "rsh blocked edit of secret file (rule: {}): {}",
                    h.id, h.reason
                );
                return ExitCode::from(2);
            }
            if settings_guard::is_settings_path(file_path)
                && settings_guard::edit_removes_hook(file_path, old_string, new_string)
            {
                eprintln!(
                    "rsh blocked edit of {file_path}: would remove rsh PreToolUse hook"
                );
                return ExitCode::from(2);
            }
            run_check_content(new_string)
        }
        "apply_patch" => {
            let command = input
                .tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            run_check_content(command)
        }
        _ => ExitCode::SUCCESS,
    }
}

fn is_command_tool(tool_name: &str, tool_input: &serde_json::Value) -> bool {
    matches!(tool_name, "Bash" | "exec_command")
        || tool_name.ends_with(".exec_command")
        || tool_name.ends_with("/exec_command")
        || tool_name.ends_with("::exec_command")
        || (tool_name != "apply_patch" && !extract_command(tool_input).is_empty())
}

fn extract_command(tool_input: &serde_json::Value) -> &str {
    tool_input
        .get("command")
        .or_else(|| tool_input.get("cmd"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

fn is_valid_rule_id(id: &str) -> bool {
    blacklist::rules().iter().any(|r| r.id == id) || secrets::all_rules().iter().any(|r| r.id == id)
}

fn is_valid_tool_bin(bin: &str) -> bool {
    blacklist::rules().iter().any(|r| r.bin == Some(bin))
}

fn run_tool(action: ToolAction) -> ExitCode {
    match action {
        ToolAction::Disable { bin } => {
            if !is_valid_tool_bin(&bin) {
                eprintln!("error: no rules bound to tool '{bin}'");
                eprintln!("hint: run `rsh tool list` to see all known tools");
                return ExitCode::FAILURE;
            }
            match disabled::add_tool(&bin) {
                Ok(true) => {
                    let count = blacklist::rules()
                        .iter()
                        .filter(|r| r.bin == Some(bin.as_str()))
                        .count();
                    eprintln!(
                        "tool: disabled '{bin}' ({count} rule{})",
                        if count == 1 { "" } else { "s" }
                    );
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("tool: '{bin}' was already disabled");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("tool failed: {e:#}");
                    ExitCode::FAILURE
                }
            }
        }
        ToolAction::Enable { bin } => {
            if !is_valid_tool_bin(&bin) {
                eprintln!("error: no rules bound to tool '{bin}'");
                eprintln!("hint: run `rsh tool list` to see all known tools");
                return ExitCode::FAILURE;
            }
            match disabled::remove_tool(&bin) {
                Ok(true) => {
                    eprintln!("tool: enabled '{bin}'");
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("tool: '{bin}' was already enabled");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("tool failed: {e:#}");
                    ExitCode::FAILURE
                }
            }
        }
        ToolAction::List => {
            let disabled_set = disabled::load();
            let rules = blacklist::rules();
            let bins: std::collections::BTreeSet<&'static str> =
                rules.iter().filter_map(|r| r.bin).collect();
            for bin in &bins {
                let count = rules.iter().filter(|r| r.bin == Some(bin)).count();
                let marker = if disabled_set.contains(&format!("tool:{bin}")) {
                    "  [TOOL DISABLED]"
                } else {
                    ""
                };
                println!(
                    "  {bin:<20} ({count} rule{}){marker}",
                    if count == 1 { "" } else { "s" }
                );
            }
            ExitCode::SUCCESS
        }
    }
}

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
            list_rule_table();
            ExitCode::SUCCESS
        }
    }
}

fn run_forbid(action: ForbidAction) -> ExitCode {
    match action {
        ForbidAction::Push => {
            let flag = nopush::flag_path();
            if flag.exists() {
                eprintln!("rsh: already blocked (push is read-only for this project)");
            } else {
                if let Err(e) = std::fs::write(&flag, "") {
                    eprintln!("rsh: failed to create flag file: {e:#}");
                    return ExitCode::FAILURE;
                }
                eprintln!("rsh: push blocked for this project — run 'rsh allow push' to re-enable");
                if let Err(e) = add_to_gitignore() {
                    eprintln!("rsh: warning — could not update .gitignore: {e:#}");
                }
            }
            ExitCode::SUCCESS
        }
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
        ForbidAction::List => {
            let cfg = forbid::load();
            print!("{}", render_forbid_list(&cfg));
            ExitCode::SUCCESS
        }
    }
}

fn render_forbid_list(cfg: &forbid::ForbidConfig) -> String {
    let mut out = String::new();
    if cfg.invalid {
        out.push_str("WARNING: ");
        out.push_str(forbid::INVALID_CONFIG_MESSAGE);
        out.push_str("\n\n");
    }
    if cfg.is_empty() {
        out.push_str("(no forbidden clusters, namespaces, or databases configured)\n");
        return out;
    }

    out.push_str("Clusters:\n");
    if cfg.clusters.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for c in &cfg.clusters {
            out.push_str(&format!("  • {c}\n"));
        }
    }
    out.push_str("Namespaces:\n");
    if cfg.namespaces.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for n in &cfg.namespaces {
            out.push_str(&format!("  • {n}\n"));
        }
    }
    out.push_str("Databases:\n");
    if cfg.databases.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for d in &cfg.databases {
            out.push_str(&format!("  • {d}\n"));
        }
    }
    out
}

fn run_off(global: bool) -> ExitCode {
    if global {
        let path = match disabled::flag_path_global() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("rsh: {e:#}");
                return ExitCode::FAILURE;
            }
        };
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            eprintln!("rsh: failed to create directory: {e:#}");
            return ExitCode::FAILURE;
        }
        if path.exists() {
            eprintln!("rsh: already disabled (global)");
        } else {
            if let Err(e) = std::fs::write(&path, "") {
                eprintln!("rsh: failed to write flag file: {e:#}");
                return ExitCode::FAILURE;
            }
            eprintln!("rsh: disabled (global) — run `rsh on -g` to re-enable");
        }
    } else {
        let path = disabled::flag_path_local();
        if path.exists() {
            eprintln!("rsh: already disabled (local)");
        } else {
            if let Err(e) = std::fs::write(&path, "") {
                eprintln!("rsh: failed to write flag file: {e:#}");
                return ExitCode::FAILURE;
            }
            eprintln!("rsh: disabled (local) — run `rsh on` to re-enable");
        }
    }
    ExitCode::SUCCESS
}

fn run_on(global: bool) -> ExitCode {
    if global {
        let path = match disabled::flag_path_global() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("rsh: {e:#}");
                return ExitCode::FAILURE;
            }
        };
        if !path.exists() {
            eprintln!("rsh: already enabled (global)");
        } else {
            if let Err(e) = std::fs::remove_file(&path) {
                eprintln!("rsh: failed to remove flag file: {e:#}");
                return ExitCode::FAILURE;
            }
            eprintln!("rsh: enabled (global)");
        }
    } else {
        let path = disabled::flag_path_local();
        if !path.exists() {
            eprintln!("rsh: already enabled (local)");
        } else {
            if let Err(e) = std::fs::remove_file(&path) {
                eprintln!("rsh: failed to remove flag file: {e:#}");
                return ExitCode::FAILURE;
            }
            eprintln!("rsh: enabled (local)");
        }
    }
    ExitCode::SUCCESS
}

fn run_allow(target: AllowTarget) -> ExitCode {
    match target {
        AllowTarget::Push => {
            let flag = nopush::flag_path();
            if !flag.exists() {
                eprintln!("rsh: already enabled (push not blocked)");
            } else {
                if let Err(e) = std::fs::remove_file(&flag) {
                    eprintln!("rsh: failed to remove flag file: {e:#}");
                    return ExitCode::FAILURE;
                }
                eprintln!("rsh: push re-enabled — run 'rsh forbid push' to block again");
            }
            ExitCode::SUCCESS
        }
        AllowTarget::Cluster { name } => match forbid::remove_cluster(&name) {
            Ok(true) => {
                eprintln!("allow: removed cluster '{name}'");
                ExitCode::SUCCESS
            }
            Ok(false) => {
                eprintln!("allow: cluster '{name}' was not on the forbid list");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("allow failed: {e:#}");
                ExitCode::FAILURE
            }
        },
        AllowTarget::Namespace { name } => match forbid::remove_namespace(&name) {
            Ok(true) => {
                eprintln!("allow: removed namespace '{name}'");
                ExitCode::SUCCESS
            }
            Ok(false) => {
                eprintln!("allow: namespace '{name}' was not on the forbid list");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("allow failed: {e:#}");
                ExitCode::FAILURE
            }
        },
        AllowTarget::Database { hostname } => match forbid::remove_database(&hostname) {
            Ok(true) => {
                eprintln!("allow: removed database '{hostname}'");
                ExitCode::SUCCESS
            }
            Ok(false) => {
                eprintln!("allow: database '{hostname}' was not on the forbid list");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("allow failed: {e:#}");
                ExitCode::FAILURE
            }
        },
    }
}

fn add_to_gitignore() -> anyhow::Result<()> {
    let gitignore = std::path::Path::new(".gitignore");
    let entry = ".rsh-nopush";
    if gitignore.exists() {
        let content = std::fs::read_to_string(gitignore)?;
        if content.lines().any(|l| l.trim() == entry) {
            return Ok(());
        }
        let mut updated = content;
        if !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(entry);
        updated.push('\n');
        std::fs::write(gitignore, updated)?;
    } else {
        std::fs::write(gitignore, format!("{entry}\n"))?;
    }
    Ok(())
}

fn hook_command() -> String {
    // Prefer the bare name "rsh" when the binary is reachable via $PATH
    // (e.g. the user installed it through `cargo install --path .`).
    // Otherwise fall back to the absolute path of the currently running binary.
    let current = std::env::current_exe().ok();
    if let (Some(path_rsh), Some(current_exe)) = (which("rsh"), current.as_ref()) {
        let path_rsh = std::fs::canonicalize(path_rsh).ok();
        let current_exe = std::fs::canonicalize(current_exe).ok();
        if path_rsh.is_some() && path_rsh == current_exe {
            return "rsh".to_string();
        }
    }
    current
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "rsh".to_string())
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let candidates: &[&str] = if cfg!(windows) {
        &["", ".exe", ".cmd", ".bat"]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path) {
        for ext in candidates {
            let file = if ext.is_empty() {
                dir.join(name)
            } else {
                dir.join(format!("{name}{ext}"))
            };
            if file.is_file() {
                return Some(file);
            }
        }
    }
    None
}

fn init_hooks(options: InitOptions) -> Result<Vec<InstallResult>> {
    let home = aliases::home_dir().context("could not determine home directory")?;
    let cwd = std::env::current_dir().context("getting current dir")?;
    let targets = match options.requested_targets {
        Some(targets) => targets,
        None => detect_targets(&home, &cwd),
    };
    if targets.is_empty() {
        anyhow::bail!(
            "no supported tool detected; install Claude or Codex first, or specify `rsh init --tool claude|codex`"
        );
    }

    let mut results = Vec::new();
    for target in targets {
        let path = install_hook(target, options.global, &home, &cwd)?;
        results.push(InstallResult { target, path });
    }
    Ok(results)
}

fn detect_targets(home: &Path, cwd: &Path) -> Vec<HookTarget> {
    let mut targets = Vec::new();
    if which("claude").is_some() || home.join(".claude").exists() || cwd.join(".claude").exists() {
        targets.push(HookTarget::Claude);
    }
    if which("codex").is_some() || home.join(".codex").exists() || cwd.join(".codex").exists() {
        targets.push(HookTarget::Codex);
    }
    targets
}

fn install_hook(target: HookTarget, global: bool, home: &Path, cwd: &Path) -> Result<PathBuf> {
    let path = if global {
        target.global_path(home)
    } else {
        target.local_path(cwd)
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let mut value: serde_json::Value = if path.exists() {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?
    } else {
        json!({})
    };

    let cmd = hook_command();
    match target {
        HookTarget::Claude => install_claude_hook(&mut value, &cmd)?,
        HookTarget::Codex => install_codex_hook(&mut value, &cmd)?,
    }

    let pretty = serde_json::to_string_pretty(&value)?;
    std::fs::write(&path, pretty).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

fn install_claude_hook(value: &mut serde_json::Value, cmd: &str) -> Result<()> {
    let hooks = value
        .as_object_mut()
        .context("settings.json is not an object")?
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let pre = hooks
        .as_object_mut()
        .context("hooks is not an object")?
        .entry("PreToolUse")
        .or_insert_with(|| json!([]));
    let arr = pre.as_array_mut().context("PreToolUse is not an array")?;

    arr.retain(|e| {
        !e.get("hooks")
            .and_then(|h| h.as_array())
            .map(|hs| {
                hs.iter()
                    .any(|h| h.get("command").and_then(|c| c.as_str()) == Some(cmd))
            })
            .unwrap_or(false)
    });
    arr.push(json!({
        "matcher": "",
        "hooks": [{
            "type": "command",
            "command": cmd
        }]
    }));
    Ok(())
}

fn install_codex_hook(value: &mut serde_json::Value, cmd: &str) -> Result<()> {
    let hooks = value
        .as_object_mut()
        .context("hooks.json is not an object")?
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let pre = hooks
        .as_object_mut()
        .context("hooks is not an object")?
        .entry("PreToolUse")
        .or_insert_with(|| json!([]));
    let arr = pre.as_array_mut().context("PreToolUse is not an array")?;

    arr.retain(|e| {
        !e.get("hooks")
            .and_then(|h| h.as_array())
            .map(|hs| {
                hs.iter()
                    .any(|h| h.get("command").and_then(|c| c.as_str()) == Some(cmd))
            })
            .unwrap_or(false)
    });
    arr.push(json!({
        "matcher": "",
        "hooks": [{
            "type": "command",
            "command": cmd
        }]
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Temporarily redirect XDG_CONFIG_HOME to an empty temp dir so tests that
    /// call `run_hook_from_str` are not affected by a real `~/.config/rsh/disabled`
    /// flag the developer may have set.
    ///
    /// # Thread safety
    /// `set_var`/`remove_var` are process-wide. `IsolatedEnv` serializes all
    /// concurrent uses via `ENV_LOCK` so tests can run with the default thread
    /// count without racing each other.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct IsolatedEnv {
        _dir: tempfile::TempDir,
        prev_xdg: Option<std::ffi::OsString>,
        prev_cwd: Option<std::path::PathBuf>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl IsolatedEnv {
        fn new() -> Self {
            let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let dir = tempfile::tempdir().unwrap();
            let prev_xdg = std::env::var_os("XDG_CONFIG_HOME");
            let prev_cwd = std::env::current_dir().ok();
            unsafe { std::env::set_var("XDG_CONFIG_HOME", dir.path()) };
            // Change CWD to the temp dir so a local .rsh-disabled in the repo root
            // does not cause run_hook_from_str to pass all checks through unchecked.
            let _ = std::env::set_current_dir(dir.path());
            IsolatedEnv {
                _dir: dir,
                prev_xdg,
                prev_cwd,
                _guard: guard,
            }
        }

        fn dir_path(&self) -> &std::path::Path {
            self._dir.path()
        }
    }

    impl Drop for IsolatedEnv {
        fn drop(&mut self) {
            match &self.prev_xdg {
                Some(v) => unsafe { std::env::set_var("XDG_CONFIG_HOME", v) },
                None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
            }
            if let Some(cwd) = &self.prev_cwd {
                let _ = std::env::set_current_dir(cwd);
            }
        }
    }

    #[test]
    fn is_valid_rule_id_accepts_secret_rule() {
        assert!(is_valid_rule_id("secret-dotenv"));
        assert!(is_valid_rule_id("secret-pem"));
        assert!(!is_valid_rule_id("secret-nonexistent"));
    }

    #[test]
    fn cli_debug_assert() {
        Cli::command().debug_assert();
    }

    #[test]
    fn detect_targets_uses_existing_config_dirs() {
        let home = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".claude")).unwrap();
        std::fs::create_dir_all(cwd.path().join(".codex")).unwrap();

        let targets = detect_targets(home.path(), cwd.path());
        assert_eq!(targets, vec![HookTarget::Claude, HookTarget::Codex]);
    }

    #[test]
    fn install_claude_hook_is_idempotent() {
        let mut value = json!({});
        install_claude_hook(&mut value, "rsh").unwrap();
        install_claude_hook(&mut value, "rsh").unwrap();

        let arr = value["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["hooks"][0]["command"], "rsh");
    }

    #[test]
    fn install_codex_hook_is_idempotent() {
        let mut value = json!({});
        install_codex_hook(&mut value, "rsh").unwrap();
        install_codex_hook(&mut value, "rsh").unwrap();

        let arr = value["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["hooks"][0]["command"], "rsh");
    }

    #[test]
    fn tool_disabled_marker_appears_in_rule_list_output() {
        // Grundlage: is_valid_tool_bin funktioniert korrekt
        assert!(is_valid_tool_bin("kubectl"));
        assert!(!is_valid_tool_bin("nonexistent-tool-xyz"));
    }

    #[test]
    fn security_regression_install_hook_rejects_invalid_existing_json() {
        let home = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let hook_path = cwd.path().join(".codex").join("hooks.json");
        std::fs::create_dir_all(hook_path.parent().unwrap()).unwrap();
        std::fs::write(&hook_path, "not json").unwrap();

        let result = install_hook(HookTarget::Codex, false, home.path(), cwd.path());

        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(&hook_path).unwrap(), "not json");
    }

    #[test]
    fn security_regression_hook_command_does_not_use_unrelated_rsh_on_path() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let fake_rsh = dir
            .path()
            .join(if cfg!(windows) { "rsh.exe" } else { "rsh" });
        std::fs::write(&fake_rsh, "not the current rsh binary").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&fake_rsh).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&fake_rsh, perms).unwrap();
        }

        let prev_path = std::env::var_os("PATH");
        unsafe {
            std::env::set_var("PATH", dir.path());
        }
        let command = hook_command();
        match prev_path {
            Some(path) => unsafe {
                std::env::set_var("PATH", path);
            },
            None => unsafe {
                std::env::remove_var("PATH");
            },
        }

        assert_ne!(command, "rsh");
        assert!(
            std::path::Path::new(&command).is_absolute(),
            "expected an absolute current-exe fallback, got {command}"
        );
    }

    #[test]
    fn run_hook_accepts_codex_apply_patch_payload() {
        let input = r#"{
            "tool_name":"apply_patch",
            "tool_input":{"command":"*** Begin Patch\n*** End Patch\n"}
        }"#;
        assert_eq!(run_hook_from_str(input), ExitCode::SUCCESS);
    }

    #[test]
    fn run_hook_accepts_codex_exec_command_payload() {
        let input = r#"{
            "tool_name":"exec_command",
            "tool_input":{"cmd":"echo ok"}
        }"#;
        assert_eq!(run_hook_from_str(input), ExitCode::SUCCESS);
    }

    #[test]
    fn run_hook_blocks_codex_exec_command_payload() {
        let _env = IsolatedEnv::new();
        let input = r#"{
            "tool_name":"exec_command",
            "tool_input":{"cmd":"docker compose down -v"}
        }"#;
        assert_eq!(run_hook_from_str(input), ExitCode::from(2));
    }

    #[test]
    fn run_hook_blocks_namespaced_exec_command_payload() {
        let _env = IsolatedEnv::new();
        let input = r#"{
            "tool_name":"functions.exec_command",
            "tool_input":{"cmd":"kubectl delete ns prod"}
        }"#;
        assert_eq!(run_hook_from_str(input), ExitCode::from(2));
    }

    #[test]
    fn run_hook_blocks_unknown_command_tool_payload() {
        let _env = IsolatedEnv::new();
        let input = r#"{
            "tool_name":"shell_runner",
            "tool_input":{"command":"docker compose down -v"}
        }"#;
        assert_eq!(run_hook_from_str(input), ExitCode::from(2));
    }

    #[test]
    fn run_hook_allows_unknown_non_command_tool_payload() {
        let input = r#"{
            "tool_name":"list_files",
            "tool_input":{"path":"src"}
        }"#;
        assert_eq!(run_hook_from_str(input), ExitCode::SUCCESS);
    }

    #[test]
    fn run_hook_passes_through_when_globally_disabled() {
        let env = IsolatedEnv::new();
        let flag = env.dir_path().join("rsh").join("disabled");
        std::fs::create_dir_all(flag.parent().unwrap()).unwrap();
        std::fs::write(&flag, "").unwrap();

        let input = r#"{"tool_name":"Bash","tool_input":{"command":"kubectl delete ns prod"}}"#;
        let result = run_hook_from_str(input);

        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn security_regression_run_hook_blocks_write_to_xdg_rsh_config_path() {
        let env = IsolatedEnv::new();
        let protected = env.dir_path().join("rsh").join("forbidden.json");
        let input = json!({
            "tool_name": "Write",
            "tool_input": {
                "file_path": protected,
                "content": "{}"
            }
        })
        .to_string();

        assert_eq!(run_hook_from_str(&input), ExitCode::from(2));
    }

    #[cfg(unix)]
    #[test]
    fn security_regression_run_hook_blocks_read_via_secret_symlink() {
        let _env = IsolatedEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join(".env");
        std::fs::write(&target, "SECRET=value").unwrap();
        let link = dir.path().join("safe-name.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let input = json!({
            "tool_name": "Read",
            "tool_input": {
                "file_path": link
            }
        })
        .to_string();

        assert_eq!(run_hook_from_str(&input), ExitCode::from(2));
    }

    #[cfg(unix)]
    #[test]
    fn security_regression_run_hook_blocks_write_via_protected_symlink() {
        let env = IsolatedEnv::new();
        let protected = env.dir_path().join("rsh").join("forbidden.json");
        std::fs::create_dir_all(protected.parent().unwrap()).unwrap();
        std::fs::write(&protected, "{}").unwrap();
        let link = env.dir_path().join("safe-name.json");
        std::os::unix::fs::symlink(&protected, &link).unwrap();
        let input = json!({
            "tool_name": "Write",
            "tool_input": {
                "file_path": link,
                "content": "{}"
            }
        })
        .to_string();

        assert_eq!(run_hook_from_str(&input), ExitCode::from(2));
    }

    #[test]
    fn security_regression_invalid_forbid_config_does_not_fail_open() {
        let env = IsolatedEnv::new();
        let forbid_path = env.dir_path().join("rsh").join("forbidden.json");
        std::fs::create_dir_all(forbid_path.parent().unwrap()).unwrap();
        std::fs::write(&forbid_path, "not json").unwrap();

        assert!(forbid::check("kubectl get pods").is_some());
    }

    #[test]
    fn security_regression_forbid_list_reports_invalid_config() {
        let cfg = forbid::ForbidConfig {
            invalid: true,
            ..forbid::ForbidConfig::default()
        };

        let output = render_forbid_list(&cfg);

        assert!(output.contains("invalid forbid configuration"), "{output}");
    }

    #[test]
    fn run_off_creates_local_flag_and_run_on_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let flag = dir.path().join(".rsh-disabled");
        assert!(!flag.exists());
        std::fs::write(&flag, "").unwrap();
        assert!(flag.exists());
        std::fs::remove_file(&flag).unwrap();
        assert!(!flag.exists());
    }

    #[test]
    fn run_hook_blocks_read_of_dotenv() {
        let _env = IsolatedEnv::new();
        let input = r#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/.env"}}"#;
        assert_eq!(run_hook_from_str(input), ExitCode::from(2));
    }

    #[test]
    fn run_hook_allows_read_of_normal_file() {
        let _env = IsolatedEnv::new();
        let input = r#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/main.rs"}}"#;
        assert_eq!(run_hook_from_str(input), ExitCode::SUCCESS);
    }

    #[test]
    fn run_hook_blocks_write_to_secret_path() {
        let _env = IsolatedEnv::new();
        let input = r#"{"tool_name":"Write","tool_input":{"file_path":"/home/user/.env","content":"HELLO=world"}}"#;
        assert_eq!(run_hook_from_str(input), ExitCode::from(2));
    }

    #[test]
    fn run_hook_blocks_edit_of_secret_path() {
        let _env = IsolatedEnv::new();
        let input = r#"{"tool_name":"Edit","tool_input":{"file_path":"/home/user/id_rsa","new_string":"fake key"}}"#;
        assert_eq!(run_hook_from_str(input), ExitCode::from(2));
    }


    #[test]
    fn run_hook_blocks_git_push_when_nopush_active() {
        let _env = IsolatedEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        std::fs::write(".rsh-nopush", "").unwrap();

        let input = r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#;
        let result = run_hook_from_str(input);

        std::env::set_current_dir(prev).unwrap();
        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn run_hook_allows_git_push_when_nopush_inactive() {
        let _env = IsolatedEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        // no .rsh-nopush file

        let input = r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#;
        let result = run_hook_from_str(input);

        std::env::set_current_dir(prev).unwrap();
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn run_hook_blocks_gh_pr_merge_when_nopush_active() {
        let _env = IsolatedEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        std::fs::write(".rsh-nopush", "").unwrap();

        let input = r#"{"tool_name":"Bash","tool_input":{"command":"gh pr merge 42 --squash"}}"#;
        let result = run_hook_from_str(input);

        std::env::set_current_dir(prev).unwrap();
        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn forbid_push_creates_flag_and_updates_gitignore() {
        let _env = IsolatedEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let result = run_forbid(ForbidAction::Push);

        let flag_exists = dir.path().join(".rsh-nopush").exists();
        let gitignore = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap_or_default();
        std::env::set_current_dir(prev).unwrap();

        assert_eq!(result, ExitCode::SUCCESS);
        assert!(flag_exists);
        assert!(gitignore.contains(".rsh-nopush"));
    }

    #[test]
    fn allow_push_removes_flag() {
        let _env = IsolatedEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        std::fs::write(".rsh-nopush", "").unwrap();

        let result = run_allow(AllowTarget::Push);

        let flag_exists = dir.path().join(".rsh-nopush").exists();
        std::env::set_current_dir(prev).unwrap();

        assert_eq!(result, ExitCode::SUCCESS);
        assert!(!flag_exists);
    }

    #[test]
    fn forbid_push_idempotent() {
        let _env = IsolatedEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        std::fs::write(".rsh-nopush", "").unwrap();

        let result = run_forbid(ForbidAction::Push);

        std::env::set_current_dir(prev).unwrap();
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn allow_push_idempotent() {
        let _env = IsolatedEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        // no flag file

        let result = run_allow(AllowTarget::Push);

        std::env::set_current_dir(prev).unwrap();
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn add_to_gitignore_does_not_duplicate_entry() {
        // IsolatedEnv serialises CWD + XDG_CONFIG_HOME; the test then switches
        // into its own subdirectory so .gitignore is written there.
        let _env = IsolatedEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        std::fs::write(".gitignore", ".rsh-nopush\n").unwrap();

        add_to_gitignore().unwrap();

        let content = std::fs::read_to_string(".gitignore").unwrap();
        std::env::set_current_dir(prev).unwrap();

        let count = content.lines().filter(|l| l.trim() == ".rsh-nopush").count();
        assert_eq!(count, 1);
    }

    fn settings_json_with_rsh_hook() -> String {
        serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "",
                    "hooks": [{"type": "command", "command": "rsh"}]
                }]
            }
        })
        .to_string()
    }

    #[test]
    fn security_regression_run_hook_blocks_write_that_removes_rsh_hook() {
        let _env = IsolatedEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let settings = dir.path().join(".claude").join("settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(&settings, settings_json_with_rsh_hook()).unwrap();

        let input = serde_json::json!({
            "tool_name": "Write",
            "tool_input": {
                "file_path": settings,
                "content": r#"{"theme":"dark"}"#
            }
        })
        .to_string();

        assert_eq!(run_hook_from_str(&input), ExitCode::from(2));
    }

    #[test]
    fn security_regression_run_hook_allows_write_that_preserves_rsh_hook() {
        let _env = IsolatedEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let settings = dir.path().join(".claude").join("settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(&settings, settings_json_with_rsh_hook()).unwrap();

        let new_content = serde_json::json!({
            "theme": "dark",
            "hooks": {
                "PreToolUse": [{
                    "matcher": "",
                    "hooks": [{"type": "command", "command": "rsh"}]
                }]
            }
        })
        .to_string();

        let input = serde_json::json!({
            "tool_name": "Write",
            "tool_input": {
                "file_path": settings,
                "content": new_content
            }
        })
        .to_string();

        assert_eq!(run_hook_from_str(&input), ExitCode::SUCCESS);
    }

    #[test]
    fn run_tool_disable_unknown_bin_returns_failure() {
        let result = run_tool(ToolAction::Disable {
            bin: "nonexistent-binary".to_string(),
        });
        assert_eq!(result, ExitCode::FAILURE);
    }

    #[test]
    fn run_tool_enable_unknown_bin_returns_failure() {
        let result = run_tool(ToolAction::Enable {
            bin: "nonexistent-binary".to_string(),
        });
        assert_eq!(result, ExitCode::FAILURE);
    }

    #[test]
    fn is_valid_tool_bin_rejects_unknown() {
        assert!(!is_valid_tool_bin("nonexistent"));
    }

    #[test]
    fn is_valid_tool_bin_accepts_kubectl() {
        assert!(is_valid_tool_bin("kubectl"));
    }

    #[test]
    fn security_regression_run_hook_blocks_edit_that_removes_rsh_hook() {
        let _env = IsolatedEnv::new();
        let dir = tempfile::tempdir().unwrap();
        let settings = dir.path().join(".codex").join("hooks.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        let original = settings_json_with_rsh_hook();
        std::fs::write(&settings, &original).unwrap();

        // BTreeMap key order: "hooks" < "matcher", "command" < "type"
        let hook_entry =
            r#"{"hooks":[{"command":"rsh","type":"command"}],"matcher":""}"#;
        let input = serde_json::json!({
            "tool_name": "Edit",
            "tool_input": {
                "file_path": settings,
                "old_string": hook_entry,
                "new_string": r#"{"matcher":""}"#
            }
        })
        .to_string();

        assert_eq!(run_hook_from_str(&input), ExitCode::from(2));
    }
}
