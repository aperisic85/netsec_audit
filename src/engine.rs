//! The audit engine: evaluate compiled rules against a configuration.

use crate::model::{Finding, MatchKind, Report, Severity};
use crate::rules::CompiledRule;
use std::collections::{HashMap, HashSet};

/// A top-level configuration block: an unindented header line plus the
/// indented lines that follow it (IOS-style sectioning).
struct Section<'a> {
    /// 1-based line number of the header.
    header_line: usize,
    /// The header line content.
    header: &'a str,
    /// Indented body lines as (1-based line number, content).
    body: Vec<(usize, &'a str)>,
}

impl<'a> Section<'a> {
    /// Header and body lines with their 1-based line numbers.
    fn lines(&self) -> impl Iterator<Item = (usize, &'a str)> + '_ {
        std::iter::once((self.header_line, self.header)).chain(self.body.iter().copied())
    }
}

/// True for IOS comment/separator lines (`!`, optionally indented).
fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with('!')
}

/// Split a config into top-level sections. Comment and blank lines are
/// excluded; an indented line belongs to the most recent header.
fn parse_sections(config: &str) -> Vec<Section<'_>> {
    let mut sections: Vec<Section<'_>> = Vec::new();
    for (idx, line) in config.lines().enumerate() {
        if line.trim().is_empty() || is_comment(line) {
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            // Indented lines before any header are malformed; ignore them.
            if let Some(current) = sections.last_mut() {
                current.body.push((idx + 1, line));
            }
        } else {
            sections.push(Section {
                header_line: idx + 1,
                header: line,
                body: Vec::new(),
            });
        }
    }
    sections
}

/// Audit a configuration string against a set of compiled rules.
///
/// Rules without a `within` scope are evaluated against the whole config
/// (comment lines are never matched). Rules with `within` are evaluated
/// per block whose header matches the scope: `present_regex` flags matching
/// lines inside such blocks, and `absent_regex` flags each matching block
/// that lacks the pattern, pointing at the block header.
///
/// Findings are returned sorted by descending severity, then by rule id and
/// line for stable output.
#[must_use]
pub fn audit(target: &str, config: &str, rules: &[CompiledRule]) -> Report {
    let sections = parse_sections(config);
    let mut findings: Vec<Finding> = Vec::new();

    for compiled in rules {
        match &compiled.rule.kind {
            MatchKind::PresentRegex { .. } => match &compiled.within {
                // Flag every non-comment line that matches the pattern.
                None => {
                    for (idx, line) in config.lines().enumerate() {
                        if !is_comment(line) && compiled.regex.is_match(line) {
                            findings.push(finding_from(
                                compiled,
                                Some(idx + 1),
                                Some(line.trim().to_string()),
                            ));
                        }
                    }
                }
                // Flag matching lines only inside in-scope blocks.
                Some(within) => {
                    for section in sections.iter().filter(|s| within.is_match(s.header)) {
                        for (line_no, line) in section.lines() {
                            if compiled.regex.is_match(line) {
                                findings.push(finding_from(
                                    compiled,
                                    Some(line_no),
                                    Some(line.trim().to_string()),
                                ));
                            }
                        }
                    }
                }
            },
            MatchKind::AbsentRegex { .. } => match &compiled.within {
                // Flag once if the pattern is absent from the whole config.
                None => {
                    if !compiled.regex.is_match(config) {
                        findings.push(finding_from(compiled, None, None));
                    }
                }
                // Flag each in-scope block that lacks the pattern.
                Some(within) => {
                    for section in sections.iter().filter(|s| within.is_match(s.header)) {
                        let present =
                            section.lines().any(|(_, line)| compiled.regex.is_match(line));
                        if !present {
                            findings.push(finding_from(
                                compiled,
                                Some(section.header_line),
                                Some(section.header.trim().to_string()),
                            ));
                        }
                    }
                }
            },
        }
    }

    apply_suppressions(&mut findings, rules);

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

/// Drop findings whose rule lists a `suppressed_by` rule that fired on the
/// same line, letting specific rules silence broader overlapping ones.
fn apply_suppressions(findings: &mut Vec<Finding>, rules: &[CompiledRule]) {
    let suppressed_by: HashMap<&str, &[String]> = rules
        .iter()
        .filter(|c| !c.rule.suppressed_by.is_empty())
        .map(|c| (c.rule.id.as_str(), c.rule.suppressed_by.as_slice()))
        .collect();
    if suppressed_by.is_empty() {
        return;
    }
    let fired: HashSet<(String, Option<usize>)> = findings
        .iter()
        .map(|f| (f.rule_id.clone(), f.line))
        .collect();
    findings.retain(|f| {
        let Some(ids) = suppressed_by.get(f.rule_id.as_str()) else {
            return true;
        };
        !ids.iter().any(|id| fired.contains(&(id.clone(), f.line)))
    });
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
