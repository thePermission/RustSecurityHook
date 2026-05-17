pub mod aliases;
pub mod blacklist;
pub mod checker;
pub mod disabled;
pub mod forbid;
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
    let p = path.replace('\\', "/");
    p.contains("/.config/rsh/")
        || p.ends_with("/.config/rsh")
        || p.starts_with(".config/rsh/")
        || p == ".config/rsh"
}

#[cfg(test)]
mod tests {
    use super::*;

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
