//! Terminal rendering.
//!
//! The report has a job beyond listing findings: it has to leave the reader
//! with an accurate sense of what was *not* checked. So coverage is printed
//! before the findings, not in a footnote after them, and the verdict line
//! never contracts to a single reassuring word.

use ps_model::{CoverageStatus, Report, Severity, ThreatTier};
use std::fmt::Write as _;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const GREY: &str = "\x1b[90m";

/// Whether to emit ANSI escapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Colour {
    Always,
    Never,
}

impl Colour {
    const fn pick(self, code: &'static str) -> &'static str {
        match self {
            Self::Always => code,
            Self::Never => "",
        }
    }
}

const fn severity_colour(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => RED,
        Severity::Medium => YELLOW,
        Severity::Low => BLUE,
        Severity::Info => GREY,
    }
}

const fn severity_marker(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "!!",
        Severity::High => " !",
        Severity::Medium => " ~",
        Severity::Low => " -",
        Severity::Info => " .",
    }
}

const fn coverage_marker(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Covered => "checked",
        CoverageStatus::Partial => "partial",
        CoverageStatus::NotCovered => "NOT CHECKED",
    }
}

/// Render a full report as plain text.
#[must_use]
pub(crate) fn report(report: &Report, colour: Colour) -> String {
    let bold = colour.pick(BOLD);
    let dim = colour.pick(DIM);
    let reset = colour.pick(RESET);
    let grey = colour.pick(GREY);

    let mut out = String::new();

    let _ = writeln!(
        out,
        "\n{bold}{}{reset}  {dim}{}{reset}",
        report.device.display_name(),
        report.generated_at.format("%Y-%m-%d %H:%M UTC")
    );

    if let Some(patch) = &report.device.security_patch {
        let _ = writeln!(out, "{grey}security patch level {patch}{reset}");
    }

    let _ = writeln!(out, "\n{bold}{}{reset}\n", report.verdict().headline());

    // Coverage first. A reader who stops here must still be correctly informed.
    let _ = writeln!(out, "{bold}What this scan could check{reset}");
    for entry in &report.coverage {
        let marker = coverage_marker(entry.status);
        let tint = match entry.status {
            CoverageStatus::Covered => colour.pick(BLUE),
            CoverageStatus::Partial => colour.pick(YELLOW),
            CoverageStatus::NotCovered => colour.pick(GREY),
        };
        let _ = writeln!(
            out,
            "  {tint}{marker:>11}{reset}  {}\n               {grey}{}{reset}",
            entry.tier.plain_language(),
            wrap(&entry.rationale, 62, 15)
        );
    }

    let findings = ordered_findings(report);
    if findings.is_empty() {
        let _ = writeln!(out, "\n{grey}No findings were raised.{reset}");
    } else {
        let _ = writeln!(out, "\n{bold}Findings{reset}");
        for finding in findings {
            let tint = colour.pick(severity_colour(finding.severity));
            let _ = writeln!(
                out,
                "\n  {tint}{} {}{reset}  {dim}{} / {}{reset}",
                severity_marker(finding.severity),
                finding.title,
                finding.severity,
                finding.confidence
            );
            let _ = writeln!(out, "     {}", wrap(&finding.detail, 68, 5));

            if let Some(basis) = finding.weakest_basis() {
                let _ = writeln!(out, "     {grey}{}{reset}", wrap(basis.caveat(), 68, 5));
            }
            for evidence in &finding.evidence {
                let _ = writeln!(out, "     {grey}source: {}{reset}", evidence.source);
            }
        }
    }

    if !report.feeds.is_empty() {
        let _ = writeln!(out, "\n{bold}Indicator feeds{reset}");
        for feed in &report.feeds {
            let _ = writeln!(
                out,
                "  {grey}{} ({}) {}{reset}",
                feed.name,
                feed.license,
                feed.digest.get(..12).unwrap_or(&feed.digest)
            );
        }
    }

    out
}

/// Findings worst-first, with `Info` entries demoted to the bottom so a long
/// tail of benign context never buries a critical hit.
fn ordered_findings(report: &Report) -> Vec<&ps_model::Finding> {
    report.findings_credible_against(ThreatTier::AppLevel)
}

/// Naive word wrap with a hanging indent. Adequate for report prose; no attempt
/// at grapheme awareness, because the corpus is our own English strings.
fn wrap(text: &str, width: usize, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines.join(&format!("\n{pad}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use chrono::Utc;
    use ps_model::{DeviceIdentity, TierCoverage};

    fn empty_report() -> Report {
        let mut r = Report::new(
            DeviceIdentity {
                serial: "S".into(),
                model: Some("Pixel 9".into()),
                ..DeviceIdentity::default()
            },
            Utc::now(),
        );
        r.coverage = vec![
            TierCoverage {
                tier: ThreatTier::AppLevel,
                status: CoverageStatus::Covered,
                rationale: "everything collected".to_owned(),
            },
            TierCoverage {
                tier: ThreatTier::RuntimeKernel,
                status: CoverageStatus::NotCovered,
                rationale: "all inputs came from the device itself".to_owned(),
            },
        ];
        r
    }

    #[test]
    fn a_quiet_report_still_prints_what_was_not_checked() {
        let text = report(&empty_report(), Colour::Never);

        assert!(text.contains("NOT CHECKED"));
        assert!(text.contains("not ruled out"));
        assert!(!text.to_lowercase().contains("device is clean"));
    }

    #[test]
    fn colour_never_emits_no_escape_sequences() {
        let text = report(&empty_report(), Colour::Never);
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn wrapping_breaks_on_width_and_indents_continuations() {
        let wrapped = wrap("one two three four five", 9, 2);
        assert_eq!(wrapped, "one two\n  three\n  four five");
    }

    #[test]
    fn wrapping_handles_a_word_longer_than_the_width() {
        assert_eq!(wrap("supercalifragilistic", 5, 0), "supercalifragilistic");
    }
}
