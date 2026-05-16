use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub type AliasMap = BTreeMap<String, Vec<String>>;

pub fn config_path() -> Result<PathBuf> {
    let base = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else {
        let home = std::env::var_os("HOME").context("HOME not set")?;
        PathBuf::from(home).join(".config")
    };
    Ok(base.join("rsh").join("aliases.json"))
}

pub fn load() -> AliasMap {
    let path = match config_path() {
        Ok(p) => p,
        Err(_) => return AliasMap::new(),
    };
    if !path.exists() {
        return AliasMap::new();
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return AliasMap::new(),
    };
    serde_json::from_str(&text).unwrap_or_default()
}

pub fn save(map: &AliasMap) -> Result<PathBuf> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let pretty = serde_json::to_string_pretty(map)?;
    std::fs::write(&path, pretty)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

pub fn add(command: &str, alias: &str) -> Result<(PathBuf, bool)> {
    let mut map = load();
    let entry = map.entry(command.to_string()).or_default();
    let inserted = if entry.iter().any(|a| a == alias) {
        false
    } else {
        entry.push(alias.to_string());
        true
    };
    let path = save(&map)?;
    Ok((path, inserted))
}

pub fn aliases_for(map: &AliasMap, command: &str) -> Vec<String> {
    let mut out = vec![command.to_string()];
    if let Some(extras) = map.get(command) {
        for a in extras {
            if !out.contains(a) {
                out.push(a.clone());
            }
        }
    }
    out
}

/// Scans $PATH for files whose canonical path matches `command`'s canonical
/// path. Catches symlinks and hardlinks; does NOT detect wrapper shell scripts.
pub fn detect_in_path(command: &str) -> Vec<String> {
    let Some(path_var) = std::env::var_os("PATH") else {
        return Vec::new();
    };
    let Some(target_path) = find_in_path(command, &path_var) else {
        return Vec::new();
    };
    let Ok(target_canon) = std::fs::canonicalize(&target_path) else {
        return Vec::new();
    };

    let mut out: Vec<String> = Vec::new();
    for dir in std::env::split_paths(&path_var) {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let p = entry.path();
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else { continue };
            if name == command {
                continue;
            }
            if !is_executable(&p) {
                continue;
            }
            if let Ok(canon) = std::fs::canonicalize(&p) {
                if canon == target_canon && !out.iter().any(|x| x == name) {
                    out.push(name.to_string());
                }
            }
        }
    }
    out
}

fn find_in_path(name: &str, path_var: &std::ffi::OsStr) -> Option<PathBuf> {
    for dir in std::env::split_paths(path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata()
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
        .unwrap_or(false)
}
