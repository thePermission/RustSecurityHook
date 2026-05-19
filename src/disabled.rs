use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::LazyLock;

use crate::aliases;

pub static DISABLED: LazyLock<HashSet<String>> = LazyLock::new(load);

fn rsh_config_base() -> Result<PathBuf> {
    let base = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else if cfg!(windows) {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            PathBuf::from(appdata)
        } else {
            aliases::home_dir()
                .context("could not determine home directory")?
                .join(".config")
        }
    } else {
        aliases::home_dir()
            .context("could not determine home directory")?
            .join(".config")
    };
    Ok(base.join("rsh"))
}

pub fn config_path() -> Result<PathBuf> {
    Ok(rsh_config_base()?.join("disabled-rules.json"))
}

pub fn flag_path_global() -> Result<PathBuf> {
    Ok(rsh_config_base()?.join("disabled"))
}

pub fn flag_path_local() -> PathBuf {
    PathBuf::from(".rsh-disabled")
}

pub fn is_disabled() -> bool {
    flag_path_global().map(|p| p.exists()).unwrap_or(false) || flag_path_local().exists()
}

pub fn load() -> HashSet<String> {
    let path = match config_path() {
        Ok(p) => p,
        Err(_) => return HashSet::new(),
    };
    if !path.exists() {
        return HashSet::new();
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return HashSet::new(),
    };
    let ids: Vec<String> = serde_json::from_str(&text).unwrap_or_default();
    ids.into_iter().collect()
}

pub fn save(set: &HashSet<String>) -> Result<PathBuf> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut sorted: Vec<&String> = set.iter().collect();
    sorted.sort();
    std::fs::write(&path, serde_json::to_string_pretty(&sorted)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

pub fn add(id: &str) -> Result<bool> {
    let mut set = load();
    let inserted = set.insert(id.to_string());
    if inserted {
        save(&set)?;
    }
    Ok(inserted)
}

pub fn remove(id: &str) -> Result<bool> {
    let mut set = load();
    let removed = set.remove(id);
    if removed {
        save(&set)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_from(path: &std::path::Path) -> HashSet<String> {
        if !path.exists() {
            return HashSet::new();
        }
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let ids: Vec<String> = serde_json::from_str(&text).unwrap_or_default();
        ids.into_iter().collect()
    }

    fn save_to(set: &HashSet<String>, path: &std::path::Path) {
        let mut sorted: Vec<&String> = set.iter().collect();
        sorted.sort();
        std::fs::write(path, serde_json::to_string_pretty(&sorted).unwrap()).unwrap();
    }

    #[test]
    fn load_returns_empty_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disabled-rules.json");
        assert!(load_from(&path).is_empty());
    }

    #[test]
    fn load_returns_empty_on_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disabled-rules.json");
        std::fs::write(&path, "not valid json").unwrap();
        assert!(load_from(&path).is_empty());
    }

    #[test]
    fn round_trip_add_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disabled-rules.json");
        let mut set = load_from(&path);
        assert!(set.insert("k8s-drain".to_string()));
        save_to(&set, &path);
        let loaded = load_from(&path);
        assert!(loaded.contains("k8s-drain"));
        let mut set2 = load_from(&path);
        assert!(set2.remove("k8s-drain"));
        save_to(&set2, &path);
        let loaded2 = load_from(&path);
        assert!(!loaded2.contains("k8s-drain"));
    }

    #[test]
    fn save_produces_sorted_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disabled-rules.json");
        let set: HashSet<String> = ["z-rule", "a-rule", "m-rule"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        save_to(&set, &path);
        let text = std::fs::read_to_string(&path).unwrap();
        let ids: Vec<String> = serde_json::from_str(&text).unwrap();
        assert_eq!(ids, vec!["a-rule", "m-rule", "z-rule"]);
    }

    #[test]
    fn flag_path_global_ends_with_rsh_disabled() {
        let path = flag_path_global().unwrap();
        assert!(path.ends_with("rsh/disabled") || path.ends_with(r"rsh\disabled"));
    }

    #[test]
    fn flag_path_local_is_dot_rsh_disabled() {
        assert_eq!(flag_path_local(), PathBuf::from(".rsh-disabled"));
    }

    #[test]
    fn is_disabled_returns_true_when_global_flag_exists() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", dir.path());
        }
        let flag = dir.path().join("rsh").join("disabled");
        std::fs::create_dir_all(flag.parent().unwrap()).unwrap();
        std::fs::write(&flag, "").unwrap();
        assert!(is_disabled());
        std::fs::remove_file(&flag).unwrap();
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }
}
