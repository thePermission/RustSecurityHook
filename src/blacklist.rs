use regex::Regex;
use std::sync::LazyLock;

pub struct Rule {
    pub id: &'static str,
    pub reason: &'static str,
    pub pattern: &'static str,
    regex: Regex,
}

pub struct Hit {
    pub id: &'static str,
    pub reason: &'static str,
}

const RAW_RULES: &[(&str, &str, &str)] = &[
    // Regeln werden vom Nutzer ergaenzt. Format: (id, regex, reason).
];

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    RAW_RULES
        .iter()
        .map(|(id, pat, reason)| Rule {
            id,
            reason,
            pattern: pat,
            regex: Regex::new(pat).expect("invalid blacklist regex"),
        })
        .collect()
});

pub fn rules() -> &'static [Rule] {
    &RULES
}

pub fn check(command: &str) -> Option<Hit> {
    for rule in RULES.iter() {
        if rule.regex.is_match(command) {
            return Some(Hit { id: rule.id, reason: rule.reason });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_blacklist_allows_everything() {
        assert!(check("rm -rf /").is_none());
        assert!(check("ls").is_none());
    }
}
