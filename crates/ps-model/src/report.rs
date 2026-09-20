//! The report, and the coverage statement that keeps it honest.
//!
//! A scan that finds nothing must never render as "clean". It renders as *"no
//! indicators found, at these tiers, with these feeds, on this date"* — because
//! that is the only claim the evidence supports. [`TierCoverage`] carries that
//! statement as data so the UI cannot quietly drop it.

use crate::device::DeviceIdentity;
use crate::finding::{Finding, Severity};
use crate::trust::ThreatTier;
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// How well a given run interrogated a given adversary tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageStatus {
    /// The run collected what is needed to reason about this tier.
    Covered,
    /// Some inputs were collected, others were missing or refused.
    Partial,
    /// Nothing in this run speaks to this tier.
    NotCovered,
}

/// Per-tier coverage, with the reason spelled out for the reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierCoverage {
    pub tier: ThreatTier,
    pub status: CoverageStatus,
    /// Why — named inputs, not adjectives. "No attestation certificate was
    /// collected" beats "limited coverage".
    pub rationale: String,
}

/// Provenance of an indicator feed used in the run, recorded so a report can be
/// re-evaluated later against what was actually known at the time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedProvenance {
    pub name: String,
    pub source_url: String,
    /// SHA-256 of the feed content as loaded.
    pub digest: String,
    pub retrieved_at: DateTime<Utc>,
    /// Licence of the feed. Recorded because redistribution terms differ and
    /// some widely used indicator sets carry attribution requirements.
    pub license: String,
}

/// The bottom line. Deliberately missing a "clean" variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Verdict {
    /// At least one finding at `High` or above.
    IndicatorsFound { critical: usize, high: usize },
    /// Nothing found, and the run genuinely covered tiers up to and including
    /// `covered_through`. Says nothing about tiers above it.
    NoIndicatorsFound { covered_through: ThreatTier },
    /// The run could not establish coverage even at the lowest tier — for
    /// example acquisition failed part way.
    Inconclusive { reason: String },
}

impl Verdict {
    /// One sentence for the top of the UI. Never overclaims.
    #[must_use]
    pub fn headline(&self) -> String {
        match self {
            Self::IndicatorsFound { critical, high } if *critical > 0 => {
                format!("{critical} critical and {high} high-severity indicator(s) found.")
            }
            Self::IndicatorsFound { high, .. } => {
                format!("{high} high-severity indicator(s) found.")
            }
            Self::NoIndicatorsFound { covered_through } => format!(
                "No indicators found for threats at or below: {}. Higher tiers were not ruled out.",
                covered_through.slug()
            ),
            Self::Inconclusive { reason } => format!("Inconclusive: {reason}"),
        }
    }
}

/// A complete scan result: what we looked at, what we found, and what we could
/// not see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// Bumped whenever the serialised shape changes incompatibly.
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub device: DeviceIdentity,
    pub findings: Vec<Finding>,
    pub coverage: Vec<TierCoverage>,
    pub feeds: Vec<FeedProvenance>,
    /// Free-form run metadata (tool version, host OS, adb version). Ordered for
    /// reproducible output.
    pub metadata: IndexMap<String, String>,
}

impl Report {
    /// Current schema version.
    pub const SCHEMA_VERSION: u32 = 1;

    #[must_use]
    pub fn new(device: DeviceIdentity, generated_at: DateTime<Utc>) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            generated_at,
            device,
            findings: Vec::new(),
            coverage: Vec::new(),
            feeds: Vec::new(),
            metadata: IndexMap::new(),
        }
    }

    /// The highest tier covered without a gap, starting from the weakest
    /// adversary. A gap matters: claiming to cover kernel-level threats while
    /// skipping app-level ones would be incoherent.
    #[must_use]
    pub fn covered_through(&self) -> Option<ThreatTier> {
        let mut reached = None;
        for tier in ThreatTier::all() {
            let status = self
                .coverage
                .iter()
                .find(|c| c.tier == tier)
                .map(|c| c.status);
            match status {
                Some(CoverageStatus::Covered) => reached = Some(tier),
                _ => break,
            }
        }
        reached
    }

    /// Derive the verdict from the findings and the coverage statement.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        let critical = self.count_at_least(Severity::Critical);
        let high = self.count_at(Severity::High);

        if critical > 0 || high > 0 {
            return Verdict::IndicatorsFound { critical, high };
        }

        match self.covered_through() {
            Some(tier) => Verdict::NoIndicatorsFound {
                covered_through: tier,
            },
            None => Verdict::Inconclusive {
                reason: "no adversary tier was fully covered by this run".to_owned(),
            },
        }
    }

    fn count_at_least(&self, min: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity >= min).count()
    }

    fn count_at(&self, exact: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == exact).count()
    }

    /// Findings that survive an adversary at `tier`, worst first.
    #[must_use]
    pub fn findings_credible_against(&self, tier: ThreatTier) -> Vec<&Finding> {
        let mut out: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| f.is_credible_against(tier))
            .collect();
        out.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| b.confidence.cmp(&a.confidence))
                .then_with(|| a.id.cmp(&b.id))
        });
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::finding::{Confidence, Evidence, FindingBuilder, SourceRef};
    use crate::trust::TrustBasis;

    fn report_with(coverage: Vec<TierCoverage>, findings: Vec<Finding>) -> Report {
        let mut r = Report::new(DeviceIdentity::default(), Utc::now());
        r.coverage = coverage;
        r.findings = findings;
        r
    }

    fn covered(tier: ThreatTier) -> TierCoverage {
        TierCoverage {
            tier,
            status: CoverageStatus::Covered,
            rationale: "collected".to_owned(),
        }
    }

    fn finding(id: &str, severity: Severity, basis: TrustBasis) -> Finding {
        FindingBuilder::new(id, "t")
            .severity(severity)
            .confidence(Confidence::Strong)
            .evidence(Evidence::new(SourceRef::new("a.txt"), basis, "x"))
            .build()
            .unwrap()
    }

    #[test]
    fn a_quiet_scan_is_never_reported_as_clean() {
        let r = report_with(vec![covered(ThreatTier::AppLevel)], vec![]);
        let verdict = r.verdict();

        assert_eq!(
            verdict,
            Verdict::NoIndicatorsFound {
                covered_through: ThreatTier::AppLevel
            }
        );
        assert!(verdict.headline().contains("not ruled out"));
        assert!(!verdict.headline().to_lowercase().contains("clean"));
    }

    #[test]
    fn coverage_stops_at_the_first_gap() {
        let r = report_with(
            vec![
                covered(ThreatTier::AppLevel),
                TierCoverage {
                    tier: ThreatTier::PrivilegedPersistent,
                    status: CoverageStatus::NotCovered,
                    rationale: "no attestation certificate collected".to_owned(),
                },
                covered(ThreatTier::RuntimeKernel),
            ],
            vec![],
        );
        assert_eq!(r.covered_through(), Some(ThreatTier::AppLevel));
    }

    #[test]
    fn no_coverage_at_all_is_inconclusive_not_negative() {
        let r = report_with(vec![], vec![]);
        assert!(matches!(r.verdict(), Verdict::Inconclusive { .. }));
    }

    #[test]
    fn self_reported_findings_are_filtered_out_for_kernel_tier() {
        let r = report_with(
            vec![covered(ThreatTier::AppLevel)],
            vec![
                finding("a.self", Severity::High, TrustBasis::SelfReported),
                finding("b.wire", Severity::High, TrustBasis::OutOfBand),
            ],
        );

        let survivors = r.findings_credible_against(ThreatTier::RuntimeKernel);
        assert_eq!(survivors.len(), 1);
        assert_eq!(survivors.first().map(|f| f.id.as_str()), Some("b.wire"));
    }
}
