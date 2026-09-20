//! Colour and spacing decisions, in one place.
//!
//! Severity colour is the only place this interface uses hue to carry meaning,
//! so each severity also carries a text marker. Roughly one man in twelve
//! cannot separate the red from the amber, and a security report is the last
//! thing that should depend on that.

use egui::Color32;
use ps_model::{CoverageStatus, Severity};

/// Vertical rhythm, so spacing is consistent rather than sprinkled.
pub const GAP_S: f32 = 4.0;
pub const GAP_M: f32 = 10.0;
pub const GAP_L: f32 = 18.0;

/// Colour for a severity, tuned separately for dark and light backgrounds so
/// contrast holds in both.
#[must_use]
pub fn severity_colour(severity: Severity, dark: bool) -> Color32 {
    match (severity, dark) {
        (Severity::Critical, true) => Color32::from_rgb(255, 118, 117),
        (Severity::Critical, false) => Color32::from_rgb(180, 30, 30),
        (Severity::High, true) => Color32::from_rgb(255, 159, 67),
        (Severity::High, false) => Color32::from_rgb(180, 95, 10),
        (Severity::Medium, true) => Color32::from_rgb(254, 202, 87),
        (Severity::Medium, false) => Color32::from_rgb(150, 110, 10),
        (Severity::Low, true) => Color32::from_rgb(116, 185, 255),
        (Severity::Low, false) => Color32::from_rgb(30, 100, 170),
        (Severity::Info, true) => Color32::from_rgb(150, 150, 158),
        (Severity::Info, false) => Color32::from_rgb(110, 110, 118),
    }
}

/// A short text marker so severity never depends on colour alone.
#[must_use]
pub const fn severity_marker(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

/// Colour for a coverage state.
///
/// Note that `Covered` is deliberately *not* green. Green reads as "you are
/// safe", and all this states is that one tier was examined — the tiers below
/// it in the same list may say the opposite.
#[must_use]
pub fn coverage_colour(status: CoverageStatus, dark: bool) -> Color32 {
    match (status, dark) {
        (CoverageStatus::Covered, true) => Color32::from_rgb(130, 190, 255),
        (CoverageStatus::Covered, false) => Color32::from_rgb(25, 95, 165),
        (CoverageStatus::Partial, true) => Color32::from_rgb(254, 202, 87),
        (CoverageStatus::Partial, false) => Color32::from_rgb(150, 110, 10),
        (CoverageStatus::NotCovered, true) => Color32::from_rgb(160, 160, 168),
        (CoverageStatus::NotCovered, false) => Color32::from_rgb(105, 105, 112),
    }
}

/// Label for a coverage state. Spelled out, not an icon: "NOT CHECKED" is the
/// single most important thing on the screen when it applies.
#[must_use]
pub const fn coverage_label(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Covered => "CHECKED",
        CoverageStatus::Partial => "PARTIAL",
        CoverageStatus::NotCovered => "NOT CHECKED",
    }
}

/// Muted colour for secondary prose (caveats, sources).
#[must_use]
pub const fn muted(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(150, 150, 158)
    } else {
        Color32::from_rgb(110, 110, 118)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_severity_has_a_text_marker_so_colour_is_never_the_only_signal() {
        for severity in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert!(!severity_marker(severity).is_empty());
        }
    }

    #[test]
    fn covered_is_not_rendered_green() {
        // Green would read as "you are safe", which coverage never means.
        for dark in [true, false] {
            let c = coverage_colour(CoverageStatus::Covered, dark);
            assert!(
                c.g() <= c.b(),
                "coverage colour should not be green-dominant, got {c:?}"
            );
        }
    }

    #[test]
    fn not_covered_is_spelled_out_in_full() {
        assert_eq!(coverage_label(CoverageStatus::NotCovered), "NOT CHECKED");
    }
}
