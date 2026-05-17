mod aliases;
mod blacklist;
mod disabled;
mod forbid;

use anyhow::{Context, Result};
use serde::Deserialize;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Deserialize)]
struct HookInput {
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: serde_json::Value,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("init") => {
            let global = args.iter().skip(2).any(|a| a == "-g" || a == "--global");
            match init_hook(global) {
                Ok(path) => {
                    eprintln!("rsh hook installed in {}", path.display());
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
           rsh                       Hook mode: reads Claude Code PreToolUse JSON from stdin\n\
           rsh init [-g|--global]    Register rsh as PreToolUse hook in settings.json\n\
                                     (-g writes to ~/.claude/settings.json, otherwise ./.claude/settings.json)\n\
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
                println!("    • {}", r.id);
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
    let Ok(input) = serde_json::from_str::<HookInput>(&buf) else {
        return ExitCode::SUCCESS;
    };
    match input.tool_name.as_str() {
        "Bash" => {
            let command = input
                .tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            run_check(command)
        }
        "Write" => {
            let content = input
                .tool_input
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            run_check_content(content)
        }
        "Edit" => {
            let new_string = input
                .tool_input
                .get("new_string")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            run_check_content(new_string)
        }
        _ => ExitCode::SUCCESS,
    }
}

/// Shared inner check: prints to stderr and returns true if blocked.
/// `label` appears in the message, e.g. "file write" or "script execution (/tmp/run.sh)".
fn check_content_blocked(content: &str, label: &str) -> bool {
    if let Some(hit) = blacklist::check(content) {
        eprintln!("rsh blocked {} (rule: {}): {}", label, hit.id, hit.reason);
        return true;
    }
    // Load forbid config once for all lines instead of re-reading disk per line.
    let cfg = forbid::load();
    if cfg.is_empty() {
        return false;
    }
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(hit) = forbid::check_with(line, &aliases::ALIASES, &cfg, &forbid::KubectlEnv)
            .or_else(|| forbid::check_db(line, &cfg))
        {
            let msg = match hit.kind {
                forbid::HitKind::Cluster => {
                    let origin = if hit.from_current_context { " (current kubeconfig)" } else { "" };
                    format!("forbidden cluster '{}'{origin}", hit.value)
                }
                forbid::HitKind::Namespace => {
                    let origin = if hit.from_current_context { " (current kubeconfig)" } else { "" };
                    format!("forbidden namespace '{}'{origin}", hit.value)
                }
                forbid::HitKind::Database => {
                    format!("forbidden database host '{}'", hit.value)
                }
            };
            eprintln!("rsh blocked {label}: {msg}");
            return true;
        }
    }
    false
}

fn run_check_content(content: &str) -> ExitCode {
    if check_content_blocked(content, "file write") {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

fn run_check(command: &str) -> ExitCode {
    if let Some(hit) = blacklist::check(command) {
        eprintln!("rsh blocked command (rule: {}): {}", hit.id, hit.reason);
        return ExitCode::from(2);
    }
    if let Some(hit) = forbid::check(command) {
        match hit.kind {
            forbid::HitKind::Cluster => {
                let origin = if hit.from_current_context { " (current kubeconfig)" } else { "" };
                eprintln!("rsh blocked command: forbidden cluster '{}'{origin}", hit.value);
            }
            forbid::HitKind::Namespace => {
                let origin = if hit.from_current_context { " (current kubeconfig)" } else { "" };
                eprintln!("rsh blocked command: forbidden namespace '{}'{origin}", hit.value);
            }
            forbid::HitKind::Database => {
                eprintln!("rsh blocked command: forbidden database host '{}'", hit.value);
            }
        }
        return ExitCode::from(2);
    }
    for path in script_paths_in(command) {
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                if check_content_blocked(&content, &format!("script execution ({path})")) {
                    return ExitCode::from(2);
                }
            }
            Err(_) => {} // unreadable or non-existent → fail-open
        }
    }
    ExitCode::SUCCESS
}

/// Splits a possibly multi-command string on shell separators and returns the
/// path of any script file each segment would execute.
fn script_paths_in(command: &str) -> Vec<String> {
    command
        .split(|c| c == ';' || c == '\n')
        .flat_map(|s| s.split("&&"))
        .flat_map(|s| s.split("||"))
        .flat_map(|s| s.split('|'))
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .filter_map(extract_script_path)
        .collect()
}

/// If `cmd` is an invocation of a script file, returns the file path; otherwise None.
fn extract_script_path(cmd: &str) -> Option<String> {
    const INTERPRETERS: &[&str] = &[
        "bash", "sh", "zsh", "ksh", "dash", "fish",
        "python", "python3", "perl", "ruby", "node", "nodejs",
    ];

    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    let first = *tokens.first()?;
    let basename = std::path::Path::new(first)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(first);

    if INTERPRETERS.contains(&basename) {
        // First non-flag token after the interpreter name is the script path.
        // Strip surrounding quotes that the shell would normally remove.
        return tokens
            .iter()
            .skip(1)
            .find(|t| !t.starts_with('-'))
            .map(|s| strip_quotes(s));
    }

    if first == "source" || first == "." {
        return tokens.get(1).map(|s| strip_quotes(s));
    }

    // Direct script execution: ./script.sh, /abs/path/script, or bare *.sh / *.bash
    let unquoted = strip_quotes(first);
    if unquoted.starts_with("./")
        || unquoted.starts_with('/')
        || unquoted.ends_with(".sh")
        || unquoted.ends_with(".bash")
    {
        return Some(unquoted);
    }

    None
}

fn strip_quotes(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"'))
        || (s.starts_with('\'') && s.ends_with('\''))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
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

fn settings_path(global: bool) -> Result<PathBuf> {
    if global {
        let home = aliases::home_dir().context("could not determine home directory")?;
        Ok(home.join(".claude/settings.json"))
    } else {
        let cwd = std::env::current_dir().context("getting current dir")?;
        Ok(cwd.join(".claude/settings.json"))
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

fn init_hook(global: bool) -> Result<PathBuf> {
    let path = settings_path(global)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let mut value: serde_json::Value = if path.exists() {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let cmd = hook_command();

    let hooks = value
        .as_object_mut()
        .context("settings.json is not an object")?
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let pre = hooks
        .as_object_mut()
        .context("hooks is not an object")?
        .entry("PreToolUse")
        .or_insert_with(|| serde_json::json!([]));
    let arr = pre.as_array_mut().context("PreToolUse is not an array")?;

    // Remove stale entries (old "Bash"-only installs or any entry referencing our command).
    arr.retain(|e| {
        !e.get("hooks")
            .and_then(|h| h.as_array())
            .map(|hs| {
                hs.iter().any(|h| {
                    h.get("command").and_then(|c| c.as_str()) == Some(cmd.as_str())
                })
            })
            .unwrap_or(false)
    });
    arr.push(serde_json::json!({
        "matcher": "",
        "hooks": [{
            "type": "command",
            "command": cmd
        }]
    }));

    let pretty = serde_json::to_string_pretty(&value)?;
    std::fs::write(&path, pretty)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- extract_script_path ----

    #[test]
    fn extract_script_path_interpreter_with_script() {
        assert_eq!(
            extract_script_path("bash /tmp/deploy.sh"),
            Some("/tmp/deploy.sh".to_string())
        );
        assert_eq!(
            extract_script_path("sh ./run.sh"),
            Some("./run.sh".to_string())
        );
        assert_eq!(
            extract_script_path("zsh -x /opt/setup.sh"),
            Some("/opt/setup.sh".to_string())
        );
    }

    #[test]
    fn extract_script_path_extended_interpreters() {
        assert_eq!(
            extract_script_path("python3 /tmp/evil.py"),
            Some("/tmp/evil.py".to_string())
        );
        assert_eq!(
            extract_script_path("python /tmp/evil.py"),
            Some("/tmp/evil.py".to_string())
        );
        assert_eq!(
            extract_script_path("perl /tmp/evil.pl"),
            Some("/tmp/evil.pl".to_string())
        );
        assert_eq!(
            extract_script_path("ruby /tmp/evil.rb"),
            Some("/tmp/evil.rb".to_string())
        );
        assert_eq!(
            extract_script_path("node /tmp/evil.js"),
            Some("/tmp/evil.js".to_string())
        );
        assert_eq!(
            extract_script_path("nodejs /tmp/evil.js"),
            Some("/tmp/evil.js".to_string())
        );
    }

    #[test]
    fn extract_script_path_interpreter_no_script() {
        // "bash -c 'echo hi'" — inline string is not a file path; strip_quotes yields "echo hi" which isn't a .sh path
        // but the token-based approach returns it (not a path, will fail read → fail-open, acceptable)
        // bare interpreter with no arguments
        assert_eq!(extract_script_path("bash"), None);
    }

    #[test]
    fn extract_script_path_quoted_paths() {
        assert_eq!(
            extract_script_path("bash \"/tmp/deploy.sh\""),
            Some("/tmp/deploy.sh".to_string())
        );
        assert_eq!(
            extract_script_path("sh -c '/tmp/run.sh'"),
            Some("/tmp/run.sh".to_string())
        );
        assert_eq!(
            extract_script_path("source \"/etc/profile\""),
            Some("/etc/profile".to_string())
        );
        assert_eq!(
            extract_script_path("\"/tmp/script.sh\""),
            Some("/tmp/script.sh".to_string())
        );
    }

    #[test]
    fn extract_script_path_source_dot() {
        assert_eq!(
            extract_script_path("source /etc/profile"),
            Some("/etc/profile".to_string())
        );
        assert_eq!(
            extract_script_path(". ~/.bashrc"),
            Some("~/.bashrc".to_string())
        );
    }

    #[test]
    fn extract_script_path_direct_execution() {
        assert_eq!(
            extract_script_path("./deploy.sh"),
            Some("./deploy.sh".to_string())
        );
        assert_eq!(
            extract_script_path("/usr/local/bin/myscript"),
            Some("/usr/local/bin/myscript".to_string())
        );
        assert_eq!(
            extract_script_path("cleanup.sh"),
            Some("cleanup.sh".to_string())
        );
        assert_eq!(
            extract_script_path("setup.bash"),
            Some("setup.bash".to_string())
        );
    }

    #[test]
    fn extract_script_path_non_script_commands() {
        assert_eq!(extract_script_path("ls -la"), None);
        assert_eq!(extract_script_path("git status"), None);
        assert_eq!(extract_script_path("kubectl get pods"), None);
        assert_eq!(extract_script_path("cargo build --release"), None);
    }

    // ---- script_paths_in ----

    #[test]
    fn script_paths_in_single_segment() {
        assert_eq!(script_paths_in("./deploy.sh"), vec!["./deploy.sh"]);
    }

    #[test]
    fn script_paths_in_semicolon_separator() {
        let paths = script_paths_in("echo start; ./deploy.sh; echo done");
        assert_eq!(paths, vec!["./deploy.sh"]);
    }

    #[test]
    fn script_paths_in_and_and_separator() {
        let paths = script_paths_in("cd /tmp && bash setup.sh");
        assert_eq!(paths, vec!["setup.sh"]);
    }

    #[test]
    fn script_paths_in_pipe_separator() {
        let paths = script_paths_in("cat file.txt | bash /tmp/process.sh");
        assert_eq!(paths, vec!["/tmp/process.sh"]);
    }

    #[test]
    fn script_paths_in_newline_separator() {
        let paths = script_paths_in("echo hi\n./run.sh\necho bye");
        assert_eq!(paths, vec!["./run.sh"]);
    }

    #[test]
    fn script_paths_in_no_scripts() {
        let paths = script_paths_in("kubectl get pods && helm list");
        assert!(paths.is_empty());
    }

    #[test]
    fn script_paths_in_multiple_scripts() {
        let paths = script_paths_in("./a.sh; bash b.sh && source c.sh");
        assert_eq!(paths, vec!["./a.sh", "b.sh", "c.sh"]);
    }

    #[test]
    fn script_paths_in_skips_comments() {
        let paths = script_paths_in("# this is a comment\n./deploy.sh");
        assert_eq!(paths, vec!["./deploy.sh"]);
    }
}
