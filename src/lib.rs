pub mod aliases;
pub mod blacklist;
pub mod checker;
pub mod disabled;
pub mod forbid;

use std::process::ExitCode;

pub fn run_check(command: &str) -> ExitCode {
    let segments = checker::split_segments(command);
    match checker::run_parallel_checks(segments) {
        Some(hit) => {
            eprintln!("rsh blocked: {}", hit.message);
            ExitCode::from(2)
        }
        None => ExitCode::SUCCESS,
    }
}

pub fn run_check_content(content: &str) -> ExitCode {
    let segments = vec![crate::checker::Segment::Direct {
        command: content.to_string(),
    }];
    match checker::run_parallel_checks(segments) {
        Some(hit) => {
            eprintln!("rsh blocked file content: {}", hit.message);
            ExitCode::from(2)
        }
        None => ExitCode::SUCCESS,
    }
}

pub fn is_protected_path(path: &str) -> bool {
    let p = path.replace('\\', "/");
    p.contains("/.config/rsh/")
        || p.ends_with("/.config/rsh")
        || p.starts_with(".config/rsh/")
        || p == ".config/rsh"
}

fn check_content_blocked(content: &str, label: &str) -> bool {
    if let Some(hit) = blacklist::check(content) {
        eprintln!("rsh blocked {} (rule: {}): {}", label, hit.id, hit.reason);
        return true;
    }
    let cfg = forbid::load();
    if cfg.is_empty() {
        return false;
    }
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(hit) =
            forbid::check_with(line, &aliases::ALIASES, &cfg, &forbid::KubectlEnv)
                .or_else(|| forbid::check_db(line, &cfg))
        {
            let msg = match hit.kind {
                forbid::HitKind::Cluster => {
                    let origin =
                        if hit.from_current_context { " (current kubeconfig)" } else { "" };
                    format!("forbidden cluster '{}'{origin}", hit.value)
                }
                forbid::HitKind::Namespace => {
                    let origin =
                        if hit.from_current_context { " (current kubeconfig)" } else { "" };
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
        return tokens
            .iter()
            .skip(1)
            .find(|t| !t.starts_with('-'))
            .map(|s| strip_quotes(s));
    }

    if first == "source" || first == "." {
        return tokens.get(1).map(|s| strip_quotes(s));
    }

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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn protected_path_matches_rsh_config() {
        assert!(is_protected_path("/home/user/.config/rsh/disabled-rules.json"));
        assert!(is_protected_path("~/.config/rsh/aliases.json"));
        assert!(is_protected_path(".config/rsh/forbidden.json"));
    }

    #[test]
    fn protected_path_matches_windows_backslash() {
        assert!(is_protected_path(r"C:\Users\user\.config\rsh\disabled-rules.json"));
        assert!(is_protected_path(r".config\rsh\aliases.json"));
    }

    #[test]
    fn protected_path_does_not_match_unrelated() {
        assert!(!is_protected_path("/home/user/.config/other/file.json"));
        assert!(!is_protected_path("~/.config/rsh_backup/foo"));
        assert!(!is_protected_path(""));
        assert!(!is_protected_path("my.config/rsh/file.json"));
        assert!(!is_protected_path("/var/my.config/rsh/app.yaml"));
    }
}
