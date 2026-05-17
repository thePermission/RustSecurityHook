use rsh::{aliases, blacklist, disabled, forbid};
use rsh::{is_protected_path, run_check, run_check_content};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::json;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("init") => {
            match parse_init_options(&args[2..]).and_then(init_hooks) {
                Ok(results) => {
                    for result in &results {
                        eprintln!(
                            "rsh hook installed for {} in {}",
                            result.target.label(),
                            result.path.display()
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
        Some("check") => {
            let cmd = args.get(2).map(String::as_str).unwrap_or("");
            run_check(cmd)
        }
        Some("list") | Some("rules") => {
            list_rules();
            ExitCode::SUCCESS
        }
        Some("alias") => match (args.get(2), args.get(3)) {
            (Some(command), Some(alias)) => match aliases::add(command, alias) {
                Ok((path, true)) => {
                    eprintln!("added alias {alias} → {command} in {}", path.display());
                    ExitCode::SUCCESS
                }
                Ok((path, false)) => {
                    eprintln!("alias {alias} → {command} already present ({})", path.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("alias failed: {e:#}");
                    ExitCode::FAILURE
                }
            },
            _ => {
                eprintln!("usage: rsh alias <command> <alias>");
                ExitCode::FAILURE
            }
        },
        Some("detect-aliases") => {
            let targets: Vec<String> = if args.len() > 2 {
                args[2..].to_vec()
            } else {
                rule_bins()
            };
            run_detect(&targets)
        }
        Some("rule") => run_rule(&args[2..]),
        Some("forbid") => run_forbid(&args[2..]),
        Some("--help") | Some("-h") | Some("help") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--version") | Some("-v") | Some("version") => {
            println!("rsh {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => run_hook(),
    }
}

fn print_help() {
    eprintln!(
        "rsh - Rust Security Hook\n\
         \n\
         USAGE:\n\
           rsh                       Hook mode: reads Claude/Codex PreToolUse JSON from stdin\n\
           rsh init [-g|--global] [--tool claude|codex|all]\n\
                                     Register rsh hooks for detected tools.\n\
                                     Claude: ~/.claude/settings.json or ./.claude/settings.json\n\
                                     Codex:  ~/.codex/hooks.json or ./.codex/hooks.json\n\
           rsh check \"<command>\"    Run the blacklist against a literal command string\n\
           rsh list                  Show all configured blacklist rules and aliases\n\
           rsh alias <cmd> <alias>   Register that <alias> on this system points to <cmd>\n\
                                     (e.g. `rsh alias kubectl k` if `k` is a symlink/wrapper for kubectl)\n\
           rsh detect-aliases [cmd]  Auto-detect aliases by scanning $PATH for symlinks/hardlinks.\n\
                                     With no argument, scans all commands referenced by rules.\n\
           rsh rule disable <id>     Disable a blacklist rule by ID.\n\
           rsh rule enable <id>      Re-enable a disabled blacklist rule.\n\
           rsh rule list             Show all rules with [DISABLED] marker where applicable.\n\
           rsh forbid cluster <name>              Add a forbidden cluster (context).\n\
           rsh forbid namespace <name>            Add a forbidden namespace.\n\
           rsh forbid database <hostname>         Add a forbidden database hostname.\n\
           rsh forbid remove cluster|namespace|database <name>\n\
                                              Remove an entry from the forbid list.\n\
           rsh forbid list               Show the current forbid lists.\n\
           rsh help                  Show this message\n\
           rsh -v | --version        Show version"
    );
}

fn list_rules() {
    use std::collections::BTreeMap;

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
            println!("  ▌ {} ({})", cat, items.len());
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

    print_section("FORBIDDEN CLUSTERS, NAMESPACES AND DATABASES");
    let fcfg = forbid::load();
    if fcfg.is_empty() {
        println!("  (none — register with `rsh forbid cluster <name>`,");
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
                let connector = if i + 1 == list.len() { "└─" } else { "├─" };
                println!("      {connector} {a}");
            }
            println!();
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
    let Ok(input) = serde_json::from_str::<HookInput>(input) else {
        return ExitCode::SUCCESS;
    };
    if is_command_tool(&input.tool_name, &input.tool_input) {
        let command = extract_command(&input.tool_input);
        return run_check(command);
    }

    match input.tool_name.as_str() {
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
            run_check_content(content)
        }
        "Edit" => {
            let file_path = input
                .tool_input
                .get("file_path")
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
        || (tool_name != "apply_patch" && extract_command(tool_input) != "")
}

fn extract_command(tool_input: &serde_json::Value) -> &str {
    tool_input
        .get("command")
        .or_else(|| tool_input.get("cmd"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

fn is_valid_rule_id(id: &str) -> bool {
    blacklist::rules().iter().any(|r| r.id == id)
}

fn run_rule(args: &[String]) -> ExitCode {
    let usage = "usage:\n  \
        rsh rule disable <id>\n  \
        rsh rule enable <id>\n  \
        rsh rule list";

    match args.first().map(String::as_str) {
        Some("disable") => match args.get(1) {
            Some(id) => {
                if !is_valid_rule_id(id) {
                    eprintln!("error: unknown rule id '{id}'");
                    eprintln!("hint: run `rsh rule list` to see all valid rule IDs");
                    return ExitCode::FAILURE;
                }
                match disabled::add(id) {
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
            None => {
                eprintln!("usage: rsh rule disable <id>");
                ExitCode::FAILURE
            }
        },
        Some("enable") => match args.get(1) {
            Some(id) => {
                if !is_valid_rule_id(id) {
                    eprintln!("error: unknown rule id '{id}'");
                    eprintln!("hint: run `rsh rule list` to see all valid rule IDs");
                    return ExitCode::FAILURE;
                }
                match disabled::remove(id) {
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
            None => {
                eprintln!("usage: rsh rule enable <id>");
                ExitCode::FAILURE
            }
        },
        Some("list") => {
            list_rules();
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{usage}");
            ExitCode::FAILURE
        }
    }
}

fn run_forbid(args: &[String]) -> ExitCode {
    let usage = "usage:\n  \
        rsh forbid cluster <name>\n  \
        rsh forbid namespace <name>\n  \
        rsh forbid database <hostname>\n  \
        rsh forbid remove cluster|namespace|database <name>\n  \
        rsh forbid list";

    match args.first().map(String::as_str) {
        Some("cluster") => match args.get(1) {
            Some(name) => match forbid::add_cluster(name) {
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
            None => {
                eprintln!("usage: rsh forbid cluster <name>");
                ExitCode::FAILURE
            }
        },
        Some("namespace") => match args.get(1) {
            Some(name) => match forbid::add_namespace(name) {
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
            None => {
                eprintln!("usage: rsh forbid namespace <name>");
                ExitCode::FAILURE
            }
        },
        Some("database") => match args.get(1) {
            Some(name) => match forbid::add_database(name) {
                Ok(true) => {
                    eprintln!("forbid: added database '{name}'");
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("forbid: database '{name}' was already on the list");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("forbid failed: {e:#}");
                    ExitCode::FAILURE
                }
            },
            None => {
                eprintln!("usage: rsh forbid database <hostname>");
                ExitCode::FAILURE
            }
        },
        Some("remove") => match (args.get(1).map(String::as_str), args.get(2)) {
            (Some("cluster"), Some(name)) => match forbid::remove_cluster(name) {
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
            (Some("namespace"), Some(name)) => match forbid::remove_namespace(name) {
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
            (Some("database"), Some(name)) => match forbid::remove_database(name) {
                Ok(true) => {
                    eprintln!("forbid: removed database '{name}'");
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    eprintln!("forbid: database '{name}' was not on the list");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("forbid failed: {e:#}");
                    ExitCode::FAILURE
                }
            },
            _ => {
                eprintln!("usage: rsh forbid remove cluster|namespace|database <name>");
                ExitCode::FAILURE
            }
        },
        Some("list") => {
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
        _ => {
            eprintln!("{usage}");
            ExitCode::FAILURE
        }
    }
}

fn hook_command() -> String {
    // Prefer the bare name "rsh" when the binary is reachable via $PATH
    // (e.g. the user installed it through `cargo install --path .`).
    // Otherwise fall back to the absolute path of the currently running binary.
    if which("rsh").is_some() {
        "rsh".to_string()
    } else {
        std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "rsh".to_string())
    }
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

fn parse_init_options(args: &[String]) -> Result<InitOptions> {
    let mut options = InitOptions::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-g" | "--global" => {
                options.global = true;
                i += 1;
            }
            "--tool" => {
                let Some(value) = args.get(i + 1) else {
                    anyhow::bail!("missing value for --tool (expected claude, codex, or all)");
                };
                options.requested_targets = Some(parse_requested_targets(value)?);
                i += 2;
            }
            other => anyhow::bail!("unknown init argument: {other}"),
        }
    }
    Ok(options)
}

fn parse_requested_targets(value: &str) -> Result<Vec<HookTarget>> {
    match value {
        "claude" => Ok(vec![HookTarget::Claude]),
        "codex" => Ok(vec![HookTarget::Codex]),
        "all" => Ok(vec![HookTarget::Claude, HookTarget::Codex]),
        _ => anyhow::bail!("invalid --tool value '{value}' (expected claude, codex, or all)"),
    }
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
    if which("claude").is_some()
        || home.join(".claude").exists()
        || cwd.join(".claude").exists()
    {
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
        std::fs::create_dir_all(parent).ok();
    }

    let mut value: serde_json::Value = if path.exists() {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    let cmd = hook_command();
    match target {
        HookTarget::Claude => install_claude_hook(&mut value, &cmd)?,
        HookTarget::Codex => install_codex_hook(&mut value, &cmd)?,
    }

    let pretty = serde_json::to_string_pretty(&value)?;
    std::fs::write(&path, pretty)
        .with_context(|| format!("writing {}", path.display()))?;
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

    arr.retain(|e| e.get("command").and_then(|c| c.as_str()) != Some(cmd));
    arr.push(json!({
        "matcher": "",
        "command": cmd
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_init_options_defaults_to_auto() {
        let opts = parse_init_options(&[]).unwrap();
        assert!(!opts.global);
        assert!(opts.requested_targets.is_none());
    }

    #[test]
    fn parse_init_options_accepts_global_and_tool() {
        let opts = parse_init_options(&["--global".into(), "--tool".into(), "codex".into()]).unwrap();
        assert!(opts.global);
        assert_eq!(opts.requested_targets, Some(vec![HookTarget::Codex]));
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
        assert_eq!(arr[0]["command"], "rsh");
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
        let input = r#"{
            "tool_name":"exec_command",
            "tool_input":{"cmd":"docker compose down -v"}
        }"#;
        assert_eq!(run_hook_from_str(input), ExitCode::from(2));
    }

    #[test]
    fn run_hook_blocks_namespaced_exec_command_payload() {
        let input = r#"{
            "tool_name":"functions.exec_command",
            "tool_input":{"cmd":"kubectl delete ns prod"}
        }"#;
        assert_eq!(run_hook_from_str(input), ExitCode::from(2));
    }

    #[test]
    fn run_hook_blocks_unknown_command_tool_payload() {
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
}
