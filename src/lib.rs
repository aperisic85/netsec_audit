//! `netsec-audit` — offline, rule-driven security auditor for network device
//! configurations (Cisco IOS first).
//!
//! The library is organised around a small pipeline:
//! 1. [`rules::load_rules`] reads and compiles rules from TOML.
//! 2. [`engine::audit`] evaluates those rules against a configuration string.
//! 3. [`report::render`] formats the resulting [`model::Report`].

#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod engine;
pub mod error;
pub mod model;
pub mod report;
pub mod rules;

pub use error::{AuditError, Result};
pub use model::{Finding, Report, Rule, Severity};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MatchKind, Rule};
    use crate::rules::CompiledRule;
    use regex::Regex;

    /// Build a compiled rule inline for tests.
    fn compiled(id: &str, sev: Severity, kind: MatchKind) -> CompiledRule {
        let pattern = match &kind {
            MatchKind::PresentRegex { pattern } | MatchKind::AbsentRegex { pattern } => {
                pattern.clone()
            }
        };
        CompiledRule {
            rule: Rule {
                id: id.to_string(),
                title: format!("test {id}"),
                severity: sev,
                kind,
                description: "desc".to_string(),
                remediation: "fix".to_string(),
                cis: None,
            },
            regex: Regex::new(&pattern).unwrap(), // test-only: patterns are known-valid
        }
    }

    #[test]
    fn present_regex_flags_matching_line() {
        let rules = vec![compiled(
            "telnet",
            Severity::High,
            MatchKind::PresentRegex {
                pattern: r"transport input telnet".to_string(),
            },
        )];
        let config = "line vty 0 4\n transport input telnet\n";
        let report = engine::audit("test.cfg", config, &rules);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].line, Some(2));
        assert_eq!(report.findings[0].severity, Severity::High);
    }

    #[test]
    fn absent_regex_flags_when_missing() {
        let rules = vec![compiled(
            "pw-encrypt",
            Severity::Medium,
            MatchKind::AbsentRegex {
                pattern: r"service password-encryption".to_string(),
            },
        )];
        let config = "hostname R1\n";
        let report = engine::audit("test.cfg", config, &rules);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].line, None);
    }

    #[test]
    fn absent_regex_silent_when_present() {
        let rules = vec![compiled(
            "pw-encrypt",
            Severity::Medium,
            MatchKind::AbsentRegex {
                pattern: r"service password-encryption".to_string(),
            },
        )];
        let config = "service password-encryption\nhostname R1\n";
        let report = engine::audit("test.cfg", config, &rules);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn findings_sorted_by_descending_severity() {
        let rules = vec![
            compiled(
                "low",
                Severity::Low,
                MatchKind::PresentRegex {
                    pattern: "aaa".to_string(),
                },
            ),
            compiled(
                "crit",
                Severity::Critical,
                MatchKind::PresentRegex {
                    pattern: "bbb".to_string(),
                },
            ),
        ];
        let config = "aaa\nbbb\n";
        let report = engine::audit("test.cfg", config, &rules);
        assert_eq!(report.findings[0].severity, Severity::Critical);
        assert_eq!(report.findings[1].severity, Severity::Low);
    }

    #[test]
    fn exit_code_respects_threshold() {
        let rules = vec![compiled(
            "med",
            Severity::Medium,
            MatchKind::PresentRegex {
                pattern: "ccc".to_string(),
            },
        )];
        let report = engine::audit("test.cfg", "ccc\n", &rules);
        assert_eq!(engine::exit_code(&report, Severity::High), 0);
        assert_eq!(engine::exit_code(&report, Severity::Medium), 1);
    }

    #[test]
    fn severity_ordering_is_correct() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
}
