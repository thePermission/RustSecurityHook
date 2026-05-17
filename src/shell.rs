use std::path::Path;

pub fn tokenize(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            '\\' if !in_single => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

pub fn normalize_command_name(token: &str) -> &str {
    let basename = Path::new(token)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(token);
    basename
        .strip_suffix(".exe")
        .or_else(|| basename.strip_suffix(".EXE"))
        .unwrap_or(basename)
}

pub fn is_env_assignment(token: &str) -> bool {
    let Some((name, _)) = token.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name
            .chars()
            .all(|c| c == '_' || c.is_ascii_alphanumeric())
        && name
            .chars()
            .next()
            .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_preserves_quoted_spaces() {
        assert_eq!(
            tokenize(r#"bash "/tmp/prod deploy.sh" --flag"#),
            vec!["bash", "/tmp/prod deploy.sh", "--flag"]
        );
    }

    #[test]
    fn tokenize_handles_single_quotes() {
        assert_eq!(
            tokenize("kubectl --context='prod eu' get pods"),
            vec!["kubectl", "--context=prod eu", "get", "pods"]
        );
    }

    #[test]
    fn detects_env_assignments() {
        assert!(is_env_assignment("PGPASSWORD=secret"));
        assert!(is_env_assignment("_X=1"));
        assert!(!is_env_assignment("=value"));
        assert!(!is_env_assignment("prod-db.example.com"));
    }
}
