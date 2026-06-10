//! The audit engine: evaluate compiled rules against a configuration.

use crate::model::{Finding, MatchKind, Report, Severity};
use crate::rules::CompiledRule;

/// Audit a configuration string against a set of compiled rules.
///
/// Findings are returned sorted by descending severity, then by rule id for
/// stable output.
#[must_use]
pub fn audit(target: &str, config: &str, rules: &[CompiledRule]) -> Report {
    let mut findings: Vec<Finding> = Vec::new();

    for compiled in rules {
        match &compiled.rule.kind {
            MatchKind::PresentRegex { .. } => {
                // Flag every line that matches the pattern.
                for (idx, line) in config.lines().enumerate() {
                    if compiled.regex.is_match(line) {
                        findings.push(finding_from(
                            compiled,
                            Some(idx + 1),
                            Some(line.trim().to_string()),
                        ));
                    }
                }
            }
            MatchKind::AbsentRegex { .. } => {
                // Flag once if the pattern is absent from the whole config.
                if !compiled.regex.is_match(config) {
                    findings.push(finding_from(compiled, None, None));
                }
            }
        }
    }

    // Sort: most severe first; ties broken by rule id then line for determinism.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.line.cmp(&b.line))
    });

    Report {
        target: target.to_string(),
        findings,
        rules_evaluated: rules.len(),
    }
}

/// Build a `Finding` from a compiled rule and optional location.
fn finding_from(
    compiled: &CompiledRule,
    line: Option<usize>,
    evidence: Option<String>,
) -> Finding {
    let r = &compiled.rule;
    Finding {
        rule_id: r.id.clone(),
        title: r.title.clone(),
        severity: r.severity,
        line,
        evidence,
        description: r.description.clone(),
        remediation: r.remediation.clone(),
        cis: r.cis.clone(),
    }
}

/// Exit code policy: non-zero if anything at or above `fail_on` is present.
#[must_use]
pub fn exit_code(report: &Report, fail_on: Severity) -> i32 {
    i32::from(report.count_at_least(fail_on) > 0)
}
