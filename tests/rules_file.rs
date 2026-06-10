//! End-to-end checks: the shipped rule set must compile, and auditing the
//! bundled example config must produce section-aware findings.

use netsec_audit::engine;
use netsec_audit::rules::load_rules;
use std::path::{Path, PathBuf};

fn manifest_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

#[test]
fn shipped_rules_compile() {
    let rules = load_rules(&manifest_path("rules/cisco-ios.toml")).expect("rules file must load");
    assert!(!rules.is_empty());
}

#[test]
fn example_config_findings_are_section_aware() {
    let rules = load_rules(&manifest_path("rules/cisco-ios.toml")).unwrap();
    let config =
        std::fs::read_to_string(manifest_path("examples/vulnerable-router.cfg")).unwrap();
    let report = engine::audit("vulnerable-router.cfg", &config, &rules);

    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();

    // The vty block (header on line 17) has no access-class; the finding
    // points at that block's header, not at the whole file.
    let vty_acl = report
        .findings
        .iter()
        .find(|f| f.rule_id == "cisco-ios-no-vty-acl")
        .expect("vty acl finding");
    assert_eq!(vty_acl.line, Some(17));
    assert_eq!(vty_acl.evidence.as_deref(), Some("line vty 0 4"));

    // 'line con 0' has an exec-timeout, 'line vty 0 4' does not: exactly one
    // finding, on the vty header.
    let timeouts: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == "cisco-ios-no-exec-timeout")
        .collect();
    assert_eq!(timeouts.len(), 1);
    assert_eq!(timeouts[0].line, Some(17));

    // No 'line aux' block in the config, so the aux rule stays silent.
    assert!(!ids.contains(&"cisco-ios-aux-port"));

    // The specific SNMP rules fire and suppress the generic v1/v2c rule on
    // the same lines (the example has no other community strings).
    assert!(ids.contains(&"cisco-ios-snmp-public"));
    assert!(ids.contains(&"cisco-ios-snmp-private"));
    assert!(!ids.contains(&"cisco-ios-snmp-v1v2"));

    // Telnet on the vty line is still caught.
    let telnet = report
        .findings
        .iter()
        .find(|f| f.rule_id == "cisco-ios-telnet-enabled")
        .expect("telnet finding");
    assert_eq!(telnet.line, Some(19));

    // Credential and service-hardening rules fire on the example.
    for expected in [
        "cisco-ios-username-plaintext-password",
        "cisco-ios-username-type7-password",
        "cisco-ios-ftp-plaintext-credentials",
        "cisco-ios-no-aaa-new-model",
        "cisco-ios-snmp-host-not-v3",
        "cisco-ios-ntp-unauthenticated",
        "cisco-ios-no-ssh-version-2",
        "cisco-ios-no-login-banner",
        "cisco-ios-source-routing",
        "cisco-ios-no-login-block",
    ] {
        assert!(ids.contains(&expected), "expected finding for {expected}");
    }

    // 'line con 0' has 'exec-timeout 0 0': flagged as disabled, not missing.
    let disabled: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == "cisco-ios-exec-timeout-disabled")
        .collect();
    assert_eq!(disabled.len(), 1);
    assert_eq!(disabled[0].line, Some(16));

    // The shared vty password is flagged inside the line block.
    let line_pw = report
        .findings
        .iter()
        .find(|f| f.rule_id == "cisco-ios-line-password")
        .expect("line password finding");
    assert_eq!(line_pw.line, Some(18));

    // 'private RW' is covered by the more specific default-community rule.
    assert!(!ids.contains(&"cisco-ios-snmp-rw-community"));
}

#[test]
fn custom_rw_community_fires_and_suppresses_generic_rule() {
    let rules = load_rules(&manifest_path("rules/cisco-ios.toml")).unwrap();
    let config = "snmp-server community s3cr3t RW\n";
    let report = engine::audit("test.cfg", config, &rules);
    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"cisco-ios-snmp-rw-community"));
    assert!(!ids.contains(&"cisco-ios-snmp-v1v2"));
}

#[test]
fn finite_exec_timeout_is_not_flagged_as_disabled() {
    let rules = load_rules(&manifest_path("rules/cisco-ios.toml")).unwrap();
    let config = "line vty 0 4\n exec-timeout 10 0\n transport input ssh\n";
    let report = engine::audit("test.cfg", config, &rules);
    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"cisco-ios-exec-timeout-disabled"));
    assert!(!ids.contains(&"cisco-ios-no-exec-timeout"));
    assert!(!ids.contains(&"cisco-ios-vty-transport-all"));
}

#[test]
fn transport_all_is_flagged_on_vty() {
    let rules = load_rules(&manifest_path("rules/cisco-ios.toml")).unwrap();
    let config = "line vty 0 4\n transport input all\n";
    let report = engine::audit("test.cfg", config, &rules);
    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(ids.contains(&"cisco-ios-vty-transport-all"));
}

#[test]
fn snmp_host_rule_skips_v3_and_keyed_ntp_is_ignored() {
    let rules = load_rules(&manifest_path("rules/cisco-ios.toml")).unwrap();
    let config = "snmp-server host 192.0.2.1 version 3 priv opsuser\n\
                  ntp server 192.0.2.2 key 1\n";
    let report = engine::audit("test.cfg", config, &rules);
    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(!ids.contains(&"cisco-ios-snmp-host-not-v3"));
    assert!(!ids.contains(&"cisco-ios-ntp-unauthenticated"));
}
