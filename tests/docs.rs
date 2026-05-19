#[test]
fn security_regression_fail_open_adr_mentions_invalid_forbid_config_fail_closed() {
    let adr = include_str!("../docs/adr/004-fail-open-exit-code-contract.md");

    assert!(adr.contains("invalid forbid"));
    assert!(!adr.contains("corrupt or unreadable `forbidden.json` silently degrades"));
}
