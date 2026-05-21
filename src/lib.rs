pub mod aliases;
pub mod blacklist;
pub mod checker;
pub mod disabled;
pub mod forbid;
pub mod nopush;
pub mod secrets;
pub mod shell;

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
    let configured = configured_rsh_paths();
    path_matches_protected_patterns(path, &configured)
        || std::fs::canonicalize(path).ok().is_some_and(|canonical| {
            path_matches_protected_patterns(&path_to_match_string(&canonical), &configured)
        })
}

fn path_matches_protected_patterns(path: &str, configured: &[String]) -> bool {
    let p = path.replace('\\', "/");
    p.contains("/.config/rsh/")
        || p.ends_with("/.config/rsh")
        || p.starts_with(".config/rsh/")
        || p == ".config/rsh"
        || p.ends_with("/.rsh-disabled")
        || p == ".rsh-disabled"
        || p.ends_with("/.rsh-nopush")
        || p == ".rsh-nopush"
        || configured
            .iter()
            .any(|protected| is_same_or_child(&p, protected))
}

fn configured_rsh_paths() -> Vec<String> {
    let mut paths = Vec::new();
    for path in [
        aliases::config_path().ok(),
        disabled::config_path().ok(),
        disabled::flag_path_global().ok(),
        forbid::config_path().ok(),
    ]
    .into_iter()
    .flatten()
    {
        paths.push(path_to_match_string(&path));
        if let Some(parent) = path.parent() {
            paths.push(path_to_match_string(parent));
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn path_to_match_string(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn is_same_or_child(path: &str, protected: &str) -> bool {
    path == protected
        || path
            .strip_prefix(protected)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_path_matches_rsh_config() {
        assert!(is_protected_path(
            "/home/user/.config/rsh/disabled-rules.json"
        ));
        assert!(is_protected_path("~/.config/rsh/aliases.json"));
        assert!(is_protected_path(".config/rsh/forbidden.json"));
    }

    #[test]
    fn protected_path_matches_windows_backslash() {
        assert!(is_protected_path(
            r"C:\Users\user\.config\rsh\disabled-rules.json"
        ));
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

    #[test]
    fn protected_path_matches_local_rsh_disabled() {
        assert!(is_protected_path(".rsh-disabled"));
        assert!(is_protected_path("/project/.rsh-disabled"));
        assert!(!is_protected_path(".rsh-disabled-backup"));
        assert!(!is_protected_path("rsh-disabled"));
    }

    #[test]
    fn protected_path_matches_local_rsh_nopush() {
        assert!(is_protected_path(".rsh-nopush"));
        assert!(is_protected_path("/project/.rsh-nopush"));
        assert!(!is_protected_path(".rsh-nopush-backup"));
        assert!(!is_protected_path("rsh-nopush"));
    }

    #[cfg(unix)]
    #[test]
    fn security_regression_protected_path_matches_symlink_to_local_disable_flag() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join(".rsh-disabled");
        std::fs::write(&target, "").unwrap();
        let link = dir.path().join("safe-name.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(is_protected_path(link.to_str().unwrap()));
    }
}
