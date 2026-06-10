//! Loading and compiling rules from TOML.

use crate::error::{AuditError, Result};
use crate::model::{MatchKind, Rule};
use regex::Regex;
use serde::Deserialize;
use std::path::Path;

/// Top-level structure of a rules TOML file.
#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<Rule>,
}

/// A rule paired with its pre-compiled regex, ready for evaluation.
///
/// Compiling regexes once up front keeps the audit hot loop allocation-free.
#[derive(Debug)]
pub struct CompiledRule {
    /// The original rule metadata.
    pub rule: Rule,
    /// The compiled regex.
    pub regex: Regex,
    /// Compiled section-scope regex, if the rule declares `within`.
    pub within: Option<Regex>,
}

/// Load and compile all rules from a TOML file.
///
/// # Errors
/// Returns an error if the file cannot be read, is not valid TOML, or
/// contains a rule whose regex fails to compile.
pub fn load_rules(path: &Path) -> Result<Vec<CompiledRule>> {
    let path_str = path.display().to_string();
    let contents = std::fs::read_to_string(path).map_err(|source| AuditError::Io {
        path: path_str.clone(),
        source,
    })?;

    let parsed: RuleFile = toml::from_str(&contents).map_err(|source| AuditError::RuleParse {
        path: path_str,
        source,
    })?;

    parsed.rule.into_iter().map(compile_rule).collect()
}

/// Compile a single rule's pattern (and optional `within` scope) into regexes.
fn compile_rule(rule: Rule) -> Result<CompiledRule> {
    let pattern = match &rule.kind {
        MatchKind::PresentRegex { pattern } | MatchKind::AbsentRegex { pattern } => pattern,
    };
    let regex = Regex::new(pattern).map_err(|source| AuditError::BadRegex {
        rule_id: rule.id.clone(),
        source,
    })?;
    let within = rule
        .within
        .as_deref()
        .map(Regex::new)
        .transpose()
        .map_err(|source| AuditError::BadRegex {
            rule_id: rule.id.clone(),
            source,
        })?;
    Ok(CompiledRule { rule, regex, within })
}
