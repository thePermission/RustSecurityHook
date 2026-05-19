use crate::disabled;

pub struct SecretRule {
    pub id: &'static str,
    pub category: &'static str,
    pub patterns: &'static [&'static str],
    pub reason: &'static str,
}

pub struct Hit {
    pub id: &'static str,
    pub reason: &'static str,
}

const RAW_SECRET_RULES: &[SecretRule] = &[
    SecretRule {
        id: "secret-dotenv",
        category: "Secret Files — Environment",
        patterns: &["**/.env", "**/.env.*", "**/*.env"],
        reason: "Environment file may contain API keys or passwords",
    },
    SecretRule {
        id: "secret-npmrc",
        category: "Secret Files — Environment",
        patterns: &["**/.npmrc"],
        reason: "npm config may contain auth tokens for private registries",
    },
    SecretRule {
        id: "secret-pip-conf",
        category: "Secret Files — Environment",
        patterns: &["**/pip.conf", "**/.pip/pip.conf"],
        reason: "pip config may contain index URLs with embedded credentials",
    },
    SecretRule {
        id: "secret-git-credentials",
        category: "Secret Files — Environment",
        patterns: &["**/.git-credentials"],
        reason: "Git credential helper plaintext store",
    },
    SecretRule {
        id: "secret-netrc",
        category: "Secret Files — Environment",
        patterns: &["**/.netrc"],
        reason: "FTP/HTTP credentials",
    },
    SecretRule {
        id: "secret-htpasswd",
        category: "Secret Files — Environment",
        patterns: &["**/.htpasswd"],
        reason: "Web server password hashes",
    },
    SecretRule {
        id: "secret-maven-settings",
        category: "Secret Files — Environment",
        patterns: &["**/settings.xml"],
        reason: "Maven settings may contain Nexus/Artifactory repository credentials",
    },
    SecretRule {
        id: "secret-pem",
        category: "Secret Files — Cryptographic Keys",
        patterns: &["**/*.pem"],
        reason: "PEM file may contain TLS certificate or private key",
    },
    SecretRule {
        id: "secret-key-file",
        category: "Secret Files — Cryptographic Keys",
        patterns: &["**/*.key"],
        reason: "Key file may contain a private cryptographic key",
    },
    SecretRule {
        id: "secret-p12",
        category: "Secret Files — Cryptographic Keys",
        patterns: &["**/*.p12", "**/*.pfx"],
        reason: "PKCS#12 key store containing private key and certificate chain",
    },
    SecretRule {
        id: "secret-pgp",
        category: "Secret Files — Cryptographic Keys",
        patterns: &["**/*.gpg", "**/*.asc"],
        reason: "PGP encrypted or signed file",
    },
    SecretRule {
        id: "secret-jks",
        category: "Secret Files — Cryptographic Keys",
        patterns: &["**/*.jks", "**/*.keystore"],
        reason: "Java key store containing private keys and certificates",
    },
    SecretRule {
        id: "secret-ssh-private-key",
        category: "Secret Files — SSH",
        patterns: &["**/id_rsa", "**/id_ed25519", "**/id_ecdsa", "**/id_dsa"],
        reason: "SSH private key",
    },
    SecretRule {
        id: "secret-ssh-config",
        category: "Secret Files — SSH",
        patterns: &["**/.ssh/config"],
        reason: "SSH config containing host and identity file paths",
    },
    SecretRule {
        id: "secret-aws-credentials",
        category: "Secret Files — Cloud",
        patterns: &["**/.aws/credentials"],
        reason: "AWS credentials file containing access key ID and secret",
    },
    SecretRule {
        id: "secret-gcloud-key",
        category: "Secret Files — Cloud",
        patterns: &["**/application_default_credentials.json"],
        reason: "GCP service account key",
    },
    SecretRule {
        id: "secret-kubeconfig",
        category: "Secret Files — Cloud",
        patterns: &["**/.kube/config"],
        reason: "Kubernetes config with cluster credentials and auth tokens",
    },
    SecretRule {
        id: "secret-docker-config",
        category: "Secret Files — Cloud",
        patterns: &["**/.docker/config.json"],
        reason: "Docker config with registry auth tokens",
    },
    SecretRule {
        id: "secret-vault-token",
        category: "Secret Files — Cloud",
        patterns: &["**/.vault-token"],
        reason: "HashiCorp Vault token",
    },
    SecretRule {
        id: "secret-shadow",
        category: "Secret Files — System",
        patterns: &["**/etc/shadow", "**/etc/master.passwd"],
        reason: "System password hash file",
    },
];

pub fn all_rules() -> &'static [SecretRule] {
    RAW_SECRET_RULES
}

/// Match a `**/…` glob pattern against a file path.
///
/// Supported forms (all must start with `**/`):
///   `**/<name>`       — exact basename match
///   `**/*.<ext>`      — basename ends with `.<ext>` and has a non-empty stem
///   `**/<name>.*`     — basename starts with `<name>.`
///   `**/<dir>/<name>` — last two path components match exactly
pub(crate) fn matches_glob(pattern: &str, path: &str) -> bool {
    // Normalize separators and fold to lowercase so `.ENV` matches `**/.env`
    // on case-insensitive filesystems (macOS default, Windows).
    // All static patterns are already ASCII lowercase.
    let path = path.replace('\\', "/").to_ascii_lowercase();
    let Some(tail) = pattern.strip_prefix("**/") else {
        return false;
    };
    let basename = path.rsplit('/').next().unwrap_or(&path);

    if let Some((dir_pat, name_pat)) = tail.split_once('/') {
        let suffix = format!("/{dir_pat}/{name_pat}");
        return path.ends_with(&suffix) || path == format!("{dir_pat}/{name_pat}");
    }

    if let Some(ext) = tail.strip_prefix("*.") {
        let suffix = format!(".{ext}");
        return basename.ends_with(&suffix) && basename.len() > suffix.len();
    }

    if let Some(stem) = tail.strip_suffix(".*") {
        let prefix = format!("{stem}.");
        return basename.starts_with(&prefix) && basename.len() > prefix.len();
    }

    basename == tail
}

pub fn check_path(path: &str) -> Option<Hit> {
    let disabled = disabled::load();
    if let Some(hit) = check_path_candidate(path, &disabled) {
        return Some(hit);
    }
    std::fs::canonicalize(path)
        .ok()
        .and_then(|canonical| check_path_candidate(&canonical.to_string_lossy(), &disabled))
}

fn check_path_candidate(path: &str, disabled: &std::collections::HashSet<String>) -> Option<Hit> {
    for rule in RAW_SECRET_RULES {
        if disabled.contains(rule.id) {
            continue;
        }
        if rule.patterns.iter().any(|p| matches_glob(p, path)) {
            return Some(Hit {
                id: rule.id,
                reason: rule.reason,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- matches_glob ---

    #[test]
    fn glob_exact_basename_matches() {
        assert!(matches_glob("**/.env", "/home/user/project/.env"));
        assert!(matches_glob("**/.env", ".env"));
    }

    #[test]
    fn glob_exact_basename_no_match_on_longer_name() {
        assert!(!matches_glob("**/.env", "/home/user/.env.backup"));
        assert!(!matches_glob("**/.env", "/home/user/dotenv"));
    }

    #[test]
    fn glob_extension_matches() {
        assert!(matches_glob("**/*.pem", "/etc/ssl/cert.pem"));
        assert!(matches_glob("**/*.pem", "cert.pem"));
    }

    #[test]
    fn glob_extension_no_match_on_extra_suffix() {
        assert!(!matches_glob("**/*.pem", "/etc/ssl/cert.pem.bak"));
    }

    #[test]
    fn glob_extension_no_match_on_dotfile_only() {
        // ".pem" has no stem — should not match **/*.pem
        assert!(!matches_glob("**/*.pem", "/path/.pem"));
    }

    #[test]
    fn glob_wildcard_suffix_matches() {
        assert!(matches_glob("**/.env.*", "/home/user/.env.local"));
        assert!(matches_glob("**/.env.*", "/project/.env.production"));
    }

    #[test]
    fn glob_wildcard_suffix_no_match_on_bare_name() {
        assert!(!matches_glob("**/.env.*", "/project/.env"));
    }

    #[test]
    fn glob_env_extension_matches() {
        assert!(matches_glob("**/*.env", "/project/production.env"));
    }

    #[test]
    fn glob_two_component_path_matches() {
        assert!(matches_glob(
            "**/.aws/credentials",
            "/home/user/.aws/credentials"
        ));
        assert!(matches_glob("**/.aws/credentials", ".aws/credentials"));
    }

    #[test]
    fn glob_two_component_path_no_match_on_different_name() {
        assert!(!matches_glob(
            "**/.aws/credentials",
            "/home/user/.aws/config"
        ));
    }

    #[test]
    fn glob_windows_backslash_normalised() {
        assert!(matches_glob("**/.env", r"C:\Users\dev\project\.env"));
    }

    #[test]
    fn glob_case_insensitive_basename() {
        assert!(matches_glob("**/.env", "/project/.ENV"));
        assert!(matches_glob("**/.env", "/project/.Env"));
        assert!(matches_glob("**/*.pem", "/etc/ssl/CERT.PEM"));
    }

    #[test]
    fn glob_case_insensitive_two_component() {
        assert!(matches_glob(
            "**/.aws/credentials",
            "/home/user/.AWS/Credentials"
        ));
    }

    // --- check_path ---

    #[test]
    fn check_path_hit_for_dotenv() {
        let hit = check_path("/project/.env");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().id, "secret-dotenv");
    }

    #[test]
    fn check_path_hit_for_env_extension() {
        let hit = check_path("/project/production.env");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().id, "secret-dotenv");
    }

    #[test]
    fn check_path_hit_for_ssh_key() {
        let hit = check_path("/home/user/.ssh/id_rsa");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().id, "secret-ssh-private-key");
    }

    #[test]
    fn check_path_hit_for_aws_credentials() {
        let hit = check_path("/home/user/.aws/credentials");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().id, "secret-aws-credentials");
    }

    #[test]
    fn check_path_hit_for_pem() {
        let hit = check_path("/etc/ssl/server.pem");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().id, "secret-pem");
    }

    #[test]
    fn all_rules_count() {
        assert_eq!(all_rules().len(), 20);
    }

    #[test]
    fn glob_wildcard_suffix_no_match_on_trailing_dot_only() {
        // ".env." has nothing after the dot — should not match **/.env.*
        assert!(!matches_glob("**/.env.*", "/project/.env."));
    }

    #[test]
    fn check_path_hit_for_settings_xml() {
        let hit = check_path("/home/user/.m2/settings.xml");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().id, "secret-maven-settings");
    }

    #[test]
    fn check_path_no_match_settings_xml_bak() {
        assert!(check_path("/home/user/.m2/settings.xml.bak").is_none());
    }

    #[test]
    fn check_path_no_match_for_normal_file() {
        assert!(check_path("/project/src/main.rs").is_none());
        assert!(check_path("/project/README.md").is_none());
    }

    #[test]
    fn check_path_no_match_for_env_prefixed_non_secret() {
        // "environment.txt" should not match *.env
        assert!(check_path("/project/environment.txt").is_none());
    }
}
