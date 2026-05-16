use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub type AliasMap = BTreeMap<String, Vec<String>>;

/// Best-effort cross-platform home-directory lookup: HOME on Unix,
/// USERPROFILE on Windows. Returns `None` if neither is set.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

pub fn config_path() -> Result<PathBuf> {
    let base = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else if cfg!(windows) {
        // Convention on Windows: %APPDATA%\rsh\aliases.json
        if let Some(appdata) = std::env::var_os("APPDATA") {
            PathBuf::from(appdata)
        } else {
            home_dir()
                .context("could not determine home directory")?
                .join(".config")
        }
    } else {
        home_dir()
            .context("could not determine home directory")?
            .join(".config")
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
        for ext in executable_extensions() {
            let candidate = if ext.is_empty() {
                dir.join(name)
            } else {
                dir.join(format!("{name}{ext}"))
            };
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(unix)]
fn executable_extensions() -> Vec<String> {
    vec![String::new()]
}

#[cfg(windows)]
fn executable_extensions() -> Vec<String> {
    // PATHEXT defines which extensions Windows considers executable.
    // Include the empty string so plain `kubectl` (e.g. a hardlink without
    // extension) is still found.
    let raw = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    let mut out = vec![String::new()];
    for ext in raw.split(';') {
        let trimmed = ext.trim();
        if !trimmed.is_empty() {
            out.push(trimmed.to_string());
        }
    }
    out
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata()
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
        .unwrap_or(false)
}

#[cfg(windows)]
fn is_executable(p: &Path) -> bool {
    if !p.is_file() {
        return false;
    }
    let Some(ext) = p.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let needle = format!(".{}", ext.to_ascii_uppercase());
    executable_extensions()
        .iter()
        .any(|e| !e.is_empty() && e.to_ascii_uppercase() == needle)
}
