//! Error types for `netsec-audit`.

use thiserror::Error;

/// Errors that can arise while loading rules or auditing a configuration.
#[derive(Debug, Error)]
pub enum AuditError {
    /// An I/O error occurred while reading a config or rules file.
    #[error("failed to read {path}: {source}")]
    Io {
        /// The path that could not be read.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// A rules file could not be parsed as valid TOML.
    #[error("failed to parse rules file {path}: {source}")]
    RuleParse {
        /// The rules file path.
        path: String,
        /// The underlying TOML error.
        source: toml::de::Error,
    },

    /// A rule contained a regex pattern that failed to compile.
    #[error("rule '{rule_id}' has an invalid regex: {source}")]
    BadRegex {
        /// The id of the offending rule.
        rule_id: String,
        /// The underlying regex error.
        source: regex::Error,
    },

    /// Serialising a report to JSON failed.
    #[error("failed to serialise report to JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, AuditError>;
