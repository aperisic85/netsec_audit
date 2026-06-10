//! Output renderers: human-readable terminal, JSON, and SARIF.

use crate::error::Result;
use crate::model::{Report, Severity};
use serde_json::json;

/// Output formats supported by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Coloured, human-readable terminal output.
    Terminal,
    /// Machine-readable JSON.
    Json,
    /// SARIF 2.1.0 for ingestion by GitHub code scanning and other tools.
    Sarif,
}

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";

/// Render a report to a string in the requested format.
///
/// # Errors
/// Returns an error only if JSON/SARIF serialisation fails.
pub fn render(report: &Report, format: Format, color: bool) -> Result<String> {
    match format {
        Format::Terminal => Ok(render_terminal(report, color)),
        Format::Json => Ok(serde_json::to_string_pretty(report)?),
        Format::Sarif => render_sarif(report),
    }
}

fn render_terminal(report: &Report, color: bool) -> String {
    let mut out = String::new();
    let paint = |code: &str| if color { code } else { "" };

    out.push_str(&format!(
        "{}netsec-audit{}  target: {}\n",
        paint(BOLD),
        paint(RESET),
        report.target
    ));
    out.push_str(&format!(
        "{}{} rules evaluated, {} findings{}\n\n",
        paint(DIM),
        report.rules_evaluated,
        report.findings.len(),
        paint(RESET),
    ));

    if report.findings.is_empty() {
        out.push_str("No findings. \u{2713}\n");
        return out;
    }

    for f in &report.findings {
        let loc = match f.line {
            Some(n) => format!("line {n}"),
            None => "config-wide".to_string(),
        };
        out.push_str(&format!(
            "{}[{}]{} {} {}({}){}\n",
            paint(f.severity.ansi_color()),
            f.severity.label(),
            paint(RESET),
            f.title,
            paint(DIM),
            f.rule_id,
            paint(RESET),
        ));
        out.push_str(&format!("    {}{}{}\n", paint(DIM), loc, paint(RESET)));
        if let Some(ev) = &f.evidence {
            out.push_str(&format!("    > {ev}\n"));
        }
        out.push_str(&format!("    {}\n", f.description));
        out.push_str(&format!("    fix: {}\n", f.remediation));
        if let Some(cis) = &f.cis {
            out.push_str(&format!("    {}{}{}\n", paint(DIM), cis, paint(RESET)));
        }
        out.push('\n');
    }

    // Summary line.
    let crit = report.count_at_least(Severity::Critical);
    let high = report.count_at_least(Severity::High) - crit;
    out.push_str(&format!(
        "{}Summary:{} {} critical, {} high, {} total\n",
        paint(BOLD),
        paint(RESET),
        crit,
        high,
        report.findings.len(),
    ));
    out
}

/// Map our severity to a SARIF `level`.
fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Info | Severity::Low => "note",
        Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    }
}

fn render_sarif(report: &Report) -> Result<String> {
    let results: Vec<_> = report
        .findings
        .iter()
        .map(|f| {
            let region = f.line.map(|line| json!({ "startLine": line }));
            json!({
                "ruleId": f.rule_id,
                "level": sarif_level(f.severity),
                "message": { "text": format!("{}: {}", f.title, f.description) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": report.target },
                        "region": region,
                    }
                }],
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "netsec-audit",
                    "informationUri": "https://github.com/yourname/netsec-audit",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            },
            "results": results,
        }],
    });

    Ok(serde_json::to_string_pretty(&sarif)?)
}
