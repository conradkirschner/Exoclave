//! Indicator sets, and the provenance record that has to travel with them.
//!
//! Indicator feeds are not neutral data. They have licences (the widely used
//! stalkerware set is CC-BY and therefore needs attribution), they change
//! daily, and a report produced against yesterday's feed is a different claim
//! from one produced against today's. So loading a feed always produces a
//! [`FeedProvenance`] alongside the matcher, and the report carries it.

use chrono::Utc;
use ps_model::FeedProvenance;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// What an indicator match means about the matched thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IndicatorClass {
    /// Commercial monitoring software installed by someone with physical
    /// access. Usually sold openly.
    Stalkerware,
    /// Credential theft, typically via overlay and accessibility abuse.
    BankingTrojan,
    /// Aggressive advertising or click fraud.
    Adware,
    /// Attributed to a named surveillance vendor or campaign.
    TargetedSpyware,
    /// Legitimate monitoring software — parental control, enterprise MDM.
    /// Reported, never accused: it may be there on purpose.
    Watchware,
}

impl IndicatorClass {
    #[must_use]
    pub const fn describes(self) -> &'static str {
        match self {
            Self::Stalkerware => "commercial monitoring software",
            Self::BankingTrojan => "banking credential theft",
            Self::Adware => "aggressive advertising or click fraud",
            Self::TargetedSpyware => "surveillance vendor implant",
            Self::Watchware => "monitoring software that may be installed legitimately",
        }
    }
}

/// One indicator: an application id and what it signifies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppIndicator {
    pub app_id: String,
    pub class: IndicatorClass,
    /// Family or product name, for the report. Not required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// The on-disk feed format this tool consumes.
///
/// Public feeds each have their own shape; converting them into this one is the
/// job of a fetcher, kept outside the matcher so the matcher stays pure and the
/// conversion stays auditable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedDocument {
    pub name: String,
    pub source_url: String,
    pub license: String,
    pub indicators: Vec<AppIndicator>,
}

/// An indexed, queryable indicator set.
#[derive(Debug, Clone, Default)]
pub struct IndicatorSet {
    by_app_id: std::collections::BTreeMap<String, AppIndicator>,
    provenance: Vec<FeedProvenance>,
}

impl IndicatorSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a feed document, recording its digest and licence.
    ///
    /// # Errors
    /// Returns the underlying JSON error if `raw` is not a valid feed document.
    pub fn load_feed(&mut self, raw: &str) -> Result<(), serde_json::Error> {
        let doc: FeedDocument = serde_json::from_str(raw)?;

        let digest = hex::encode(Sha256::digest(raw.as_bytes()));
        self.provenance.push(FeedProvenance {
            name: doc.name,
            source_url: doc.source_url,
            digest,
            retrieved_at: Utc::now(),
            license: doc.license,
        });

        for indicator in doc.indicators {
            // Application ids are case-sensitive on Android, but feeds are
            // inconsistent; normalise once, here, rather than at every lookup.
            let key = indicator.app_id.trim().to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            self.by_app_id.insert(key, indicator);
        }
        Ok(())
    }

    /// Look up an application id.
    #[must_use]
    pub fn lookup(&self, app_id: &str) -> Option<&AppIndicator> {
        self.by_app_id.get(&app_id.trim().to_ascii_lowercase())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_app_id.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_app_id.is_empty()
    }

    /// Provenance of every loaded feed, for the report.
    #[must_use]
    pub fn provenance(&self) -> &[FeedProvenance] {
        &self.provenance
    }

    /// Names of loaded feeds, for the coverage statement.
    #[must_use]
    pub fn feed_names(&self) -> BTreeSet<&str> {
        self.provenance.iter().map(|p| p.name.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const FEED: &str = r#"{
        "name": "test-feed",
        "source_url": "https://example.invalid/feed.json",
        "license": "CC-BY-4.0",
        "indicators": [
            {"app_id": "com.Bad.Spy", "class": "stalkerware", "name": "BadSpy"},
            {"app_id": "  ", "class": "adware"}
        ]
    }"#;

    #[test]
    fn lookups_are_case_insensitive_and_blank_ids_are_dropped() {
        let mut set = IndicatorSet::new();
        set.load_feed(FEED).expect("valid feed");

        assert_eq!(set.len(), 1);
        let hit = set.lookup("com.bad.spy").expect("match");
        assert_eq!(hit.class, IndicatorClass::Stalkerware);
        assert_eq!(hit.name.as_deref(), Some("BadSpy"));
        assert!(set.lookup("com.unrelated").is_none());
    }

    #[test]
    fn loading_records_licence_and_digest_for_the_report() {
        let mut set = IndicatorSet::new();
        set.load_feed(FEED).expect("valid feed");

        let provenance = set.provenance().first().expect("one feed");
        assert_eq!(provenance.license, "CC-BY-4.0");
        assert_eq!(provenance.digest.len(), 64);
        assert_eq!(set.feed_names().len(), 1);
    }

    #[test]
    fn a_malformed_feed_is_an_error_not_a_silent_empty_set() {
        let mut set = IndicatorSet::new();
        assert!(set.load_feed("{ not json").is_err());
        assert!(set.is_empty());
    }
}
