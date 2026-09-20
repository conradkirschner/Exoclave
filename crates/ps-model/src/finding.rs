//! Findings: what the analysis engine emits, and the evidence behind each one.

use crate::trust::{ThreatTier, TrustBasis};
use serde::{Deserialize, Serialize};
use std::fmt;

/// How bad it is if the finding is real.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Context for the reader. Not a problem on its own.
    Info,
    /// Worth understanding, but a normal device can legitimately look like this.
    Low,
    /// Unusual. Needs an explanation the user can give.
    Medium,
    /// A mechanism that malicious software depends on is active.
    High,
    /// Matches a known malicious indicator, or two sources contradict.
    Critical,
}

impl Severity {
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// How sure we are that the finding is what it looks like.
///
/// Deliberately separate from [`Severity`]: "this device has an active
/// accessibility service" is certain but might be benign; "this traffic pattern
/// resembles beaconing" is serious but uncertain. Collapsing the two is how
/// security tools end up crying wolf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    /// A heuristic fired. Expect false positives.
    Weak,
    /// Consistent with malicious behaviour, but benign explanations exist.
    Moderate,
    /// Hard to explain benignly, though not matched to a known family.
    Strong,
    /// Matched a published indicator, or verified cryptographically.
    Confirmed,
}

impl Confidence {
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Weak => "weak",
            Self::Moderate => "moderate",
            Self::Strong => "strong",
            Self::Confirmed => "confirmed",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// A pointer into the collected artifact bundle, so every claim is auditable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    /// Path of the artifact within the bundle, e.g. `dumpsys/package.txt`.
    pub artifact: String,
    /// Where inside it, e.g. a line number, key path or section name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

impl SourceRef {
    pub fn new(artifact: impl Into<String>) -> Self {
        Self {
            artifact: artifact.into(),
            locator: None,
        }
    }

    #[must_use]
    pub fn at(mut self, locator: impl Into<String>) -> Self {
        self.locator = Some(locator.into());
        self
    }
}

impl fmt::Display for SourceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.locator {
            Some(loc) => write!(f, "{}:{loc}", self.artifact),
            None => f.write_str(&self.artifact),
        }
    }
}

/// A verbatim excerpt supporting a finding, with its provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub source: SourceRef,
    pub basis: TrustBasis,
    /// Raw text, trimmed. Never paraphrased — the reader must be able to check.
    pub excerpt: String,
}

impl Evidence {
    pub fn new(source: SourceRef, basis: TrustBasis, excerpt: impl Into<String>) -> Self {
        Self {
            source,
            basis,
            excerpt: excerpt.into(),
        }
    }
}

/// A single conclusion from one analysis module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable dotted slug, e.g. `accessibility.unrecognised-service`. Used for
    /// suppression lists, UI routing and regression tests. Never change one
    /// without a migration.
    pub id: String,
    pub title: String,
    /// What was observed, in plain language, for a non-specialist.
    pub detail: String,
    pub severity: Severity,
    pub confidence: Confidence,
    /// The adversary tier this finding is *meaningful against*, given the trust
    /// basis of its evidence.
    pub tier: ThreatTier,
    pub evidence: Vec<Evidence>,
    /// Identifier of the remediation step that addresses it, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl Finding {
    /// The weakest trust basis among this finding's evidence — the one that
    /// determines how much the finding can actually carry.
    ///
    /// Returns `None` for a finding with no evidence, which the builder forbids.
    #[must_use]
    pub fn weakest_basis(&self) -> Option<TrustBasis> {
        self.evidence
            .iter()
            .map(|e| e.basis)
            .min_by_key(|b| b.forgeable_by().map_or(u8::MAX, |t| t as u8))
    }

    /// Whether this finding survives an adversary operating at `tier`.
    #[must_use]
    pub fn is_credible_against(&self, tier: ThreatTier) -> bool {
        self.weakest_basis()
            .is_some_and(|b| b.is_credible_against(tier))
    }
}

/// Builder that makes an evidence-free finding unrepresentable.
#[derive(Debug)]
pub struct FindingBuilder {
    id: String,
    title: String,
    detail: String,
    severity: Severity,
    confidence: Confidence,
    tier: ThreatTier,
    evidence: Vec<Evidence>,
    remediation: Option<String>,
}

impl FindingBuilder {
    pub fn new(id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            detail: String::new(),
            severity: Severity::Info,
            confidence: Confidence::Weak,
            tier: ThreatTier::AppLevel,
            evidence: Vec::new(),
            remediation: None,
        }
    }

    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    #[must_use]
    pub const fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    #[must_use]
    pub const fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    #[must_use]
    pub const fn tier(mut self, tier: ThreatTier) -> Self {
        self.tier = tier;
        self
    }

    #[must_use]
    pub fn evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    #[must_use]
    pub fn remediation(mut self, step_id: impl Into<String>) -> Self {
        self.remediation = Some(step_id.into());
        self
    }

    /// Finalise. `None` if no evidence was attached: a finding without evidence
    /// is an opinion, and this tool does not ship opinions.
    #[must_use]
    pub fn build(self) -> Option<Finding> {
        if self.evidence.is_empty() {
            return None;
        }
        Some(Finding {
            id: self.id,
            title: self.title,
            detail: self.detail,
            severity: self.severity,
            confidence: self.confidence,
            tier: self.tier,
            evidence: self.evidence,
            remediation: self.remediation,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn sample(basis: TrustBasis) -> Evidence {
        Evidence::new(
            SourceRef::new("dumpsys/package.txt").at("line 42"),
            basis,
            "x",
        )
    }

    #[test]
    fn a_finding_without_evidence_cannot_be_built() {
        assert!(
            FindingBuilder::new("test.empty", "Nothing")
                .build()
                .is_none()
        );
    }

    #[test]
    fn weakest_basis_governs_credibility() {
        let finding = FindingBuilder::new("test.mixed", "Mixed")
            .evidence(sample(TrustBasis::OutOfBand))
            .evidence(sample(TrustBasis::SelfReported))
            .build()
            .unwrap();

        assert_eq!(finding.weakest_basis(), Some(TrustBasis::SelfReported));
        assert!(finding.is_credible_against(ThreatTier::AppLevel));
        assert!(!finding.is_credible_against(ThreatTier::RuntimeKernel));
    }

    #[test]
    fn source_ref_renders_with_locator() {
        let r = SourceRef::new("settings/secure.txt").at("enabled_accessibility_services");
        assert_eq!(
            r.to_string(),
            "settings/secure.txt:enabled_accessibility_services"
        );
    }
}
