//! CLI entry point for `netsec-audit`.

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use netsec_audit::engine::{self, exit_code};
use netsec_audit::report::{render, Format};
use netsec_audit::rules::load_rules;
use netsec_audit::Severity;
use std::path::PathBuf;
use std::process::ExitCode;

/// Offline security auditor for network device configurations.
#[derive(Debug, Parser)]
#[command(name = "netsec-audit", version, about)]
struct Cli {
    /// Path to the configuration file to audit.
    #[arg(short, long)]
    config: PathBuf,

    /// Path to the rules file (TOML).
    #[arg(short, long, default_value = "rules/cisco-ios.toml")]
    rules: PathBuf,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutFormat::Terminal)]
    format: OutFormat,

    /// Exit non-zero if any finding at or above this severity is present.
    #[arg(long, value_enum, default_value_t = FailLevel::High)]
    fail_on: FailLevel,

    /// Disable coloured output.
    #[arg(long)]
    no_color: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutFormat {
    Terminal,
    Json,
    Sarif,
}

impl From<OutFormat> for Format {
    fn from(f: OutFormat) -> Self {
        match f {
            OutFormat::Terminal => Format::Terminal,
            OutFormat::Json => Format::Json,
            OutFormat::Sarif => Format::Sarif,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FailLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<FailLevel> for Severity {
    fn from(f: FailLevel) -> Self {
        match f {
            FailLevel::Info => Severity::Info,
            FailLevel::Low => Severity::Low,
            FailLevel::Medium => Severity::Medium,
            FailLevel::High => Severity::High,
            FailLevel::Critical => Severity::Critical,
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    let rules = load_rules(&cli.rules)
        .with_context(|| format!("loading rules from {}", cli.rules.display()))?;

    let config = std::fs::read_to_string(&cli.config)
        .with_context(|| format!("reading config {}", cli.config.display()))?;

    let target = cli.config.display().to_string();
    let report = engine::audit(&target, &config, &rules);

    let color = !cli.no_color && matches!(cli.format, OutFormat::Terminal);
    let output = render(&report, cli.format.into(), color)?;
    println!("{output}");

    let code = exit_code(&report, cli.fail_on.into());
    Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)))
}
