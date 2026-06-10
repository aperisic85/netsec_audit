//! Domain model: rules, findings, and severities.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity of a finding, ordered from least to most serious.
///
/// `Ord` is derived so findings can be sorted by severity directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational; no direct security impact.
    Info,
    /// Low impact or defence-in-depth concern.
    Low,
    /// Should be remediated; moderate exposure.
    Medium,
    /// Significant exposure; remediate promptly.
    High,
    /// Critical exposure; remediate immediately.
    Critical,
}

impl Severity {
    /// A short uppercase label for terminal output.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    /// An ANSI colour code for terminal rendering.
    #[must_use]
    pub fn ansi_color(self) -> &'static str {
        match self {
            Severity::Info => "\x1b[36m",     // cyan
            Severity::Low => "\x1b[34m",      // blue
            Severity::Medium => "\x1b[33m",   // yellow
            Severity::High => "\x1b[31m",     // red
            Severity::Critical => "\x1b[1;31m", // bold red
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// How a rule decides whether a configuration is non-compliant.
///
/// Modelled as an enum so each rule has exactly one well-defined matching
/// strategy — invalid combinations are unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "match", rename_all = "snake_case")]
pub enum MatchKind {
    /// Flag when the pattern IS present in the config (e.g. `transport input telnet`).
    PresentRegex {
        /// Regex that, if found, triggers the finding.
        pattern: String,
    },
    /// Flag when the pattern is ABSENT from the config
    /// (e.g. missing `service password-encryption`).
    AbsentRegex {
        /// Regex that, if NOT found, triggers the finding.
        pattern: String,
    },
}

/// A single audit rule, deserialised from a TOML rules file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Stable, unique identifier (e.g. `cisco-ios-telnet-enabled`).
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Severity assigned to a match.
    pub severity: Severity,
    /// Matching strategy.
    #[serde(flatten)]
    pub kind: MatchKind,
    /// Explanation of why this is a problem.
    pub description: String,
    /// Actionable remediation guidance.
    pub remediation: String,
    /// Optional CIS Benchmark reference (e.g. `CIS Cisco IOS 1.1.1`).
    #[serde(default)]
    pub cis: Option<String>,
}

/// A rule violation found in a configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The id of the rule that produced this finding.
    pub rule_id: String,
    /// The rule title.
    pub title: String,
    /// Severity of the finding.
    pub severity: Severity,
    /// 1-based line number where the issue was found, if applicable.
    /// `None` for absence-based findings that apply to the whole file.
    pub line: Option<usize>,
    /// The matched line content, trimmed (for present-regex findings).
    pub evidence: Option<String>,
    /// Why this matters.
    pub description: String,
    /// How to fix it.
    pub remediation: String,
    /// Optional CIS reference.
    pub cis: Option<String>,
}

/// The full result of auditing one configuration file.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Path of the audited configuration.
    pub target: String,
    /// All findings, sorted by descending severity.
    pub findings: Vec<Finding>,
    /// Number of rules evaluated.
    pub rules_evaluated: usize,
}

impl Report {
    /// Count of findings at or above the given severity.
    #[must_use]
    pub fn count_at_least(&self, min: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity >= min).count()
    }

    /// The highest severity present, if any findings exist.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}
