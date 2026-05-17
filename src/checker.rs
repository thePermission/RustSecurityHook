#[derive(Debug, Clone)]
pub struct Hit {
    pub rule_id: String,
    /// Full human-readable block message (everything after "rsh blocked: ")
    pub message: String,
}

pub trait ToolChecker: Send + Sync {
    /// Binary names (including aliases) that indicate this checker is relevant.
    /// An empty vec means "always run" (e.g. FallbackChecker).
    fn bins(&self) -> Vec<String>;
    /// Check `content` (a command string or script file contents) for violations.
    fn check(&self, content: &str) -> Option<Hit>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Segment {
    Script { path: String },
    Direct { command: String },
}

pub fn split_segments(command: &str) -> Vec<Segment> {
    command
        .split(|c| c == ';' || c == '\n')
        .flat_map(|s| s.split("&&"))
        .flat_map(|s| s.split("||"))
        .flat_map(|s| s.split('|'))
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(|fragment| {
            if let Some(path) = extract_script_path(fragment) {
                Segment::Script { path }
            } else {
                Segment::Direct { command: fragment.to_string() }
            }
        })
        .collect()
}

const INTERPRETERS: &[&str] = &[
    "bash", "sh", "zsh", "ksh", "dash", "fish",
    "python", "python3", "perl", "ruby", "node", "nodejs",
];

fn extract_script_path(cmd: &str) -> Option<String> {
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

    fn direct(cmd: &str) -> Segment {
        Segment::Direct { command: cmd.to_string() }
    }
    fn script(path: &str) -> Segment {
        Segment::Script { path: path.to_string() }
    }

    #[test]
    fn split_direct_only() {
        assert_eq!(split_segments("kubectl get pods"), vec![direct("kubectl get pods")]);
    }

    #[test]
    fn split_detects_bash_script() {
        assert_eq!(
            split_segments("bash /tmp/deploy.sh"),
            vec![script("/tmp/deploy.sh")]
        );
    }

    #[test]
    fn split_detects_dot_slash_script() {
        assert_eq!(split_segments("./setup.sh"), vec![script("./setup.sh")]);
    }

    #[test]
    fn split_mixed_command() {
        assert_eq!(
            split_segments("kubectl apply -f config.yaml && ./deploy.sh"),
            vec![
                direct("kubectl apply -f config.yaml"),
                script("./deploy.sh"),
            ]
        );
    }

    #[test]
    fn split_semicolon_separator() {
        assert_eq!(
            split_segments("echo start; bash setup.sh; echo done"),
            vec![
                direct("echo start"),
                script("setup.sh"),
                direct("echo done"),
            ]
        );
    }

    #[test]
    fn split_newline_separator() {
        assert_eq!(
            split_segments("git status\n./run.sh\necho bye"),
            vec![
                direct("git status"),
                script("./run.sh"),
                direct("echo bye"),
            ]
        );
    }

    #[test]
    fn split_skips_empty_and_comment_segments() {
        let segs = split_segments("# comment\n\nkubectl get pods");
        assert_eq!(segs, vec![direct("kubectl get pods")]);
    }

    #[test]
    fn split_source_dot() {
        assert_eq!(
            split_segments("source /etc/profile"),
            vec![script("/etc/profile")]
        );
        assert_eq!(
            split_segments(". ~/.bashrc"),
            vec![script("~/.bashrc")]
        );
    }

    #[test]
    fn split_quoted_script_path() {
        assert_eq!(
            split_segments("bash \"/tmp/deploy.sh\""),
            vec![script("/tmp/deploy.sh")]
        );
    }

    #[test]
    fn split_pipe_separator() {
        assert_eq!(
            split_segments("cat file.txt | bash /tmp/process.sh"),
            vec![
                direct("cat file.txt"),
                script("/tmp/process.sh"),
            ]
        );
    }
}
