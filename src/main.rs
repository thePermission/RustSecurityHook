mod blacklist;

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
        Some("--help") | Some("-h") | Some("help") => {
            print_help();
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
           rsh list                  Show all configured blacklist rules\n\
           rsh help                  Show this message"
    );
}

fn list_rules() {
    let rules = blacklist::rules();
    if rules.is_empty() {
        println!("(no blacklist rules configured)");
        return;
    }
    println!("{} rule(s) configured:\n", rules.len());
    for r in rules {
        println!("  [{}]", r.id);
        println!("    reason:  {}", r.reason);
        println!("    pattern: {}", r.pattern);
        println!();
    }
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
    match blacklist::check(command) {
        Some(hit) => {
            eprintln!("rsh blocked command (rule: {}): {}", hit.id, hit.reason);
            ExitCode::from(2)
        }
        None => ExitCode::SUCCESS,
    }
}

fn settings_path(global: bool) -> Result<PathBuf> {
    if global {
        let home = std::env::var("HOME").context("HOME not set")?;
        Ok(PathBuf::from(home).join(".claude/settings.json"))
    } else {
        let cwd = std::env::current_dir().context("getting current dir")?;
        Ok(cwd.join(".claude/settings.json"))
    }
}

fn hook_command() -> String {
    // Bevorzugt den Namen "rsh", wenn das Binary im PATH erreichbar ist
    // (Nutzer hat es z.B. via `cargo install --path .` installiert),
    // sonst Fallback auf den absoluten Pfad des aktuell laufenden Binaries.
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
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
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
