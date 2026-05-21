use regex::Regex;
use std::path::PathBuf;
use std::sync::LazyLock;

static PUSH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:\bgit\b[^|;&\n]*\bpush\b|\bgh\b[^|;&\n]*\bpr\b[^|;&\n]*\bmerge\b|\bglab\b[^|;&\n]*\bmr\b[^|;&\n]*\b(?:merge|create)\b)",
    )
    .unwrap()
});

pub fn flag_path() -> PathBuf {
    PathBuf::from(".rsh-nopush")
}

pub fn is_nopush_active() -> bool {
    flag_path().exists()
}

pub fn is_push_command(cmd: &str) -> bool {
    PUSH_RE.is_match(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_path_is_dot_rsh_nopush() {
        assert_eq!(flag_path(), PathBuf::from(".rsh-nopush"));
    }

    #[test]
    fn is_nopush_active_false_when_no_flag() {
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let result = is_nopush_active();
        std::env::set_current_dir(prev).unwrap();
        assert!(!result);
    }

    #[test]
    fn is_nopush_active_true_when_flag_exists() {
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        std::fs::write(".rsh-nopush", "").unwrap();
        let result = is_nopush_active();
        std::env::set_current_dir(prev).unwrap();
        assert!(result);
    }

    #[test]
    fn blocks_git_push_plain() {
        assert!(is_push_command("git push"));
    }

    #[test]
    fn blocks_git_push_with_remote_and_branch() {
        assert!(is_push_command("git push origin main"));
    }

    #[test]
    fn blocks_git_push_force() {
        assert!(is_push_command("git push --force"));
        assert!(is_push_command("git push -f"));
        assert!(is_push_command("git push --force-with-lease"));
    }

    #[test]
    fn blocks_git_push_delete() {
        assert!(is_push_command("git push origin --delete my-branch"));
    }

    #[test]
    fn blocks_gh_pr_merge() {
        assert!(is_push_command("gh pr merge 42"));
        assert!(is_push_command("gh pr merge --squash"));
    }

    #[test]
    fn blocks_glab_mr_merge() {
        assert!(is_push_command("glab mr merge 42"));
    }

    #[test]
    fn blocks_glab_mr_create() {
        assert!(is_push_command("glab mr create --title foo"));
    }

    #[test]
    fn allows_git_pull() {
        assert!(!is_push_command("git pull"));
    }

    #[test]
    fn allows_git_fetch() {
        assert!(!is_push_command("git fetch origin"));
    }

    #[test]
    fn allows_git_status() {
        assert!(!is_push_command("git status"));
    }

    #[test]
    fn allows_gh_pr_view() {
        assert!(!is_push_command("gh pr view 42"));
    }

    #[test]
    fn allows_glab_mr_list() {
        assert!(!is_push_command("glab mr list"));
    }

    #[test]
    fn does_not_cross_shell_separator() {
        assert!(is_push_command("git status; git push origin main"));
        assert!(!is_push_command("git status; git pull"));
    }
}
