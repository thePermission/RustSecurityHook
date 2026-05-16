mod aliases;
mod blacklist;
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
           rsh forbid cluster <name>     Add a forbidden cluster (context).\n\
           rsh forbid namespace <name>   Add a forbidden namespace.\n\
           rsh forbid remove cluster|namespace <name>\n\
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

    print_section("FORBIDDEN CLUSTERS AND NAMESPACES");
    let fcfg = forbid::load();
    if fcfg.is_empty() {
        println!("  (none — register with `rsh forbid cluster <name>` or");
        println!("                       `rsh forbid namespace <name>`)\n");
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
    if input.tool_name != "Bash" {
        return ExitCode::SUCCESS;
    }
    let command = input
        .tool_input
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    run_check(command)
}

fn run_check(command: &str) -> ExitCode {
    if let Some(hit) = blacklist::check(command) {
        eprintln!("rsh blocked command (rule: {}): {}", hit.id, hit.reason);
        return ExitCode::from(2);
    }
    if let Some(hit) = forbid::check(command) {
        let kind = match hit.kind {
            forbid::HitKind::Cluster => "cluster",
            forbid::HitKind::Namespace => "namespace",
        };
        let origin = if hit.from_current_context {
            " (current kubeconfig)"
        } else {
            ""
        };
        eprintln!(
            "rsh blocked command: forbidden {kind} '{}'{origin}",
            hit.value
        );
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

fn run_forbid(args: &[String]) -> ExitCode {
    let usage = "usage:\n  \
        rsh forbid cluster <name>\n  \
        rsh forbid namespace <name>\n  \
        rsh forbid remove cluster|namespace <name>\n  \
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
            _ => {
                eprintln!("usage: rsh forbid remove cluster|namespace <name>");
                ExitCode::FAILURE
            }
        },
        Some("list") => {
            let cfg = forbid::load();
            if cfg.is_empty() {
                println!("(no forbidden clusters or namespaces configured)");
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

    let already = arr.iter().any(|e| {
        e.get("hooks")
            .and_then(|h| h.as_array())
            .map(|hs| {
                hs.iter().any(|h| {
                    h.get("command").and_then(|c| c.as_str()) == Some(cmd.as_str())
                })
            })
            .unwrap_or(false)
    });
    if !already {
        arr.push(serde_json::json!({
            "matcher": "Bash",
            "hooks": [{
                "type": "command",
                "command": cmd
            }]
        }));
    }

    let pretty = serde_json::to_string_pretty(&value)?;
    std::fs::write(&path, pretty)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}
