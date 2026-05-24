use serde_json::Value;

/// Returns true if the path is a Claude or Codex settings/hooks file.
pub fn is_settings_path(path: &str) -> bool {
    let p = path.replace('\\', "/");
    p.ends_with("/.claude/settings.json")
        || p == ".claude/settings.json"
        || p.ends_with("/.claude/settings.local.json")
        || p == ".claude/settings.local.json"
        || p.ends_with("/.codex/hooks.json")
        || p == ".codex/hooks.json"
}

/// Returns true when writing `new_content` to `file_path` would remove an
/// rsh PreToolUse hook that is currently present in the file.
pub fn write_removes_hook(file_path: &str, new_content: &str) -> bool {
    if !current_file_has_hook(file_path) {
        return false;
    }
    let Ok(json) = serde_json::from_str::<Value>(new_content) else {
        return false;
    };
    !has_rsh_hook(&json)
}

/// Returns true when applying `old_string` → `new_string` to `file_path`
/// would remove an rsh PreToolUse hook that is currently present in the file.
pub fn edit_removes_hook(file_path: &str, old_string: &str, new_string: &str) -> bool {
    let Ok(current) = std::fs::read_to_string(file_path) else {
        return false;
    };
    if !parse_has_rsh_hook(&current) {
        return false;
    }
    let Some(pos) = current.find(old_string) else {
        return false;
    };
    let mut result = current[..pos].to_string();
    result.push_str(new_string);
    result.push_str(&current[pos + old_string.len()..]);
    let Ok(json) = serde_json::from_str::<Value>(&result) else {
        return false;
    };
    !has_rsh_hook(&json)
}

fn current_file_has_hook(file_path: &str) -> bool {
    std::fs::read_to_string(file_path)
        .ok()
        .map(|s| parse_has_rsh_hook(&s))
        .unwrap_or(false)
}

fn parse_has_rsh_hook(content: &str) -> bool {
    serde_json::from_str::<Value>(content)
        .ok()
        .map(|v| has_rsh_hook(&v))
        .unwrap_or(false)
}

fn has_rsh_hook(value: &Value) -> bool {
    let Some(entries) = value
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|p| p.as_array())
    else {
        return false;
    };
    entries.iter().any(|entry| {
        entry
            .get("hooks")
            .and_then(|h| h.as_array())
            .map(|hooks| {
                hooks.iter().any(|hook| {
                    hook.get("command")
                        .and_then(|c| c.as_str())
                        .map(is_rsh_command)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    })
}

fn is_rsh_command(cmd: &str) -> bool {
    let normalized = cmd.replace('\\', "/");
    let basename = normalized.rsplit('/').next().unwrap_or(&normalized);
    let basename = basename.strip_suffix(".exe").unwrap_or(basename);
    basename == "rsh"
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn settings_with_hook(cmd: &str) -> String {
        json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "",
                    "hooks": [{"type": "command", "command": cmd}]
                }]
            }
        })
        .to_string()
    }

    fn settings_without_hook() -> String {
        json!({"theme": "dark"}).to_string()
    }

    // --- is_settings_path ---

    #[test]
    fn detects_global_claude_settings() {
        assert!(is_settings_path("/home/user/.claude/settings.json"));
        assert!(is_settings_path("/home/user/.claude/settings.local.json"));
    }

    #[test]
    fn detects_local_claude_settings() {
        assert!(is_settings_path(".claude/settings.json"));
        assert!(is_settings_path(".claude/settings.local.json"));
    }

    #[test]
    fn detects_codex_hooks() {
        assert!(is_settings_path("/home/user/.codex/hooks.json"));
        assert!(is_settings_path(".codex/hooks.json"));
    }

    #[test]
    fn detects_windows_backslash_paths() {
        assert!(is_settings_path(r"C:\Users\user\.claude\settings.json"));
        assert!(is_settings_path(r".codex\hooks.json"));
    }

    #[test]
    fn does_not_flag_unrelated_files() {
        assert!(!is_settings_path("/home/user/.claude/other.json"));
        assert!(!is_settings_path("/etc/config.json"));
        assert!(!is_settings_path("settings.json"));
    }

    // --- is_rsh_command ---

    #[test]
    fn bare_rsh_is_recognized() {
        assert!(is_rsh_command("rsh"));
    }

    #[test]
    fn absolute_path_rsh_is_recognized() {
        assert!(is_rsh_command("/home/user/.cargo/bin/rsh"));
        assert!(is_rsh_command(r"C:\Users\user\.cargo\bin\rsh.exe"));
    }

    #[test]
    fn unrelated_command_is_not_rsh() {
        assert!(!is_rsh_command("bash"));
        assert!(!is_rsh_command("/usr/bin/echo"));
        assert!(!is_rsh_command("rsh-backup"));
    }

    // --- write_removes_hook ---

    #[test]
    fn write_blocks_when_hook_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, settings_with_hook("rsh")).unwrap();

        assert!(write_removes_hook(
            path.to_str().unwrap(),
            &settings_without_hook()
        ));
    }

    #[test]
    fn write_allows_when_hook_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, settings_with_hook("rsh")).unwrap();

        assert!(!write_removes_hook(
            path.to_str().unwrap(),
            &settings_with_hook("rsh")
        ));
    }

    #[test]
    fn write_allows_when_file_had_no_hook() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, settings_without_hook()).unwrap();

        assert!(!write_removes_hook(
            path.to_str().unwrap(),
            &settings_without_hook()
        ));
    }

    #[test]
    fn write_allows_when_file_does_not_exist() {
        assert!(!write_removes_hook(
            "/tmp/nonexistent_rsh_settings.json",
            &settings_without_hook()
        ));
    }

    #[test]
    fn write_allows_when_new_content_is_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, settings_with_hook("rsh")).unwrap();

        assert!(!write_removes_hook(path.to_str().unwrap(), "not json"));
    }

    #[test]
    fn write_blocks_absolute_path_rsh_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, settings_with_hook("/usr/local/bin/rsh")).unwrap();

        assert!(write_removes_hook(
            path.to_str().unwrap(),
            &settings_without_hook()
        ));
    }

    // --- edit_removes_hook ---

    fn hook_entry_json(cmd: &str) -> String {
        // serde_json uses BTreeMap (alphabetical key order) by default:
        // "hooks" < "matcher", "command" < "type"
        format!(
            r#"{{"hooks":[{{"command":"{cmd}","type":"command"}}],"matcher":""}}"#
        )
    }

    #[test]
    fn edit_blocks_when_hook_entry_replaced_without_hook() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = settings_with_hook("rsh");
        std::fs::write(&path, &original).unwrap();

        // Replace entire hook entry with an object that has no hooks key
        let old = hook_entry_json("rsh");
        assert!(edit_removes_hook(
            path.to_str().unwrap(),
            &old,
            r#"{"matcher":""}"#
        ));
    }

    #[test]
    fn edit_allows_when_hook_preserved_after_edit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = settings_with_hook("rsh");
        std::fs::write(&path, &original).unwrap();

        // Edit replaces the entire hook entry with itself — hook stays
        let entry = hook_entry_json("rsh");
        assert!(!edit_removes_hook(
            path.to_str().unwrap(),
            &entry,
            &entry
        ));
    }

    #[test]
    fn edit_allows_when_old_string_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, settings_with_hook("rsh")).unwrap();

        assert!(!edit_removes_hook(
            path.to_str().unwrap(),
            "this string does not exist",
            ""
        ));
    }

    #[test]
    fn edit_allows_when_file_had_no_hook() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, settings_without_hook()).unwrap();

        assert!(!edit_removes_hook(path.to_str().unwrap(), "dark", "light"));
    }

    #[test]
    fn edit_allows_when_file_does_not_exist() {
        assert!(!edit_removes_hook(
            "/tmp/nonexistent_rsh_settings.json",
            "old",
            "new"
        ));
    }
}
