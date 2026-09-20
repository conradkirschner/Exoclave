//! Fixture devices, shared by every front end.
//!
//! This runs the real pipeline — the same collectors, detectors and coverage
//! statement — with only the ADB transport replaced. It is a way to exercise
//! and demonstrate the tool without a phone attached, not a mock-up of what a
//! report might look like.
//!
//! The indicator feed below is synthetic. It exists so the fixtures have
//! something to match; it is not a real indicator set and must never be used
//! as one.

use crate::{IndicatorSet, Observations};
use chrono::{DateTime, Utc};
use ps_adb::{AdbError, Device, fake::scenarios};
use ps_model::Report;

/// Synthetic feed covering only the fixtures' `com.demo.*` packages.
const DEMO_FEED: &str = r#"{
  "name": "exoclave-demo-feed (synthetic, not real indicators)",
  "source_url": "https://github.com/conradkirschner/Exoclave#demo",
  "license": "MIT",
  "indicators": [
    {
      "app_id": "com.demo.trackerpro",
      "class": "stalkerware",
      "name": "TrackerPro (demo)"
    },
    {
      "app_id": "com.demo.pdfreader",
      "class": "adware",
      "name": "PDF Reader (demo)"
    }
  ]
}"#;

/// Which fixture device to examine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// A device with nothing wrong with it at app level.
    Healthy,
    /// A device showing the full range of app-tier problems.
    Compromised,
}

impl Scenario {
    #[must_use]
    pub const fn serial(self) -> &'static str {
        match self {
            Self::Healthy => "DEMO-HEALTHY",
            Self::Compromised => "DEMO-COMPROMISED",
        }
    }
}

/// Run the full pipeline against the chosen fixture.
///
/// # Errors
/// Only if a fixture is missing a command the collectors issue, which would be
/// a bug in the fixture rather than a runtime condition.
pub async fn run(scenario: Scenario, generated_at: DateTime<Utc>) -> Result<Report, AdbError> {
    let mut indicators = IndicatorSet::new();
    // The feed is a compile-time constant checked by the tests below, so a
    // parse failure here is unreachable in a working build.
    if indicators.load_feed(DEMO_FEED).is_err() {
        return Err(AdbError::CommandFailed {
            status: -1,
            stderr: "the built-in demo feed is malformed, which is a bug".to_owned(),
        });
    }

    let observations = match scenario {
        Scenario::Healthy => {
            let device = Device::new(scenarios::healthy());
            Observations::collect(&device, scenario.serial()).await?
        }
        Scenario::Compromised => {
            let device = Device::new(scenarios::compromised());
            Observations::collect(&device, scenario.serial()).await?
        }
    };

    Ok(crate::report(&observations, &indicators, generated_at))
}

/// Convenience for callers that do not care about the timestamp.
///
/// # Errors
/// As [`run`].
pub async fn run_now(scenario: Scenario) -> Result<Report, AdbError> {
    run(scenario, Utc::now()).await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use ps_model::{Severity, ThreatTier, Verdict};

    #[test]
    fn the_built_in_feed_parses() {
        let mut set = IndicatorSet::new();
        set.load_feed(DEMO_FEED).expect("demo feed must be valid");
        assert_eq!(set.len(), 2);
    }

    #[tokio::test]
    async fn the_healthy_fixture_produces_no_serious_findings() {
        let report = run_now(Scenario::Healthy).await.unwrap();

        assert_eq!(
            report.verdict(),
            Verdict::NoIndicatorsFound {
                covered_through: ThreatTier::AppLevel
            }
        );
        assert!(report.findings.iter().all(|f| f.severity < Severity::High));
    }

    #[tokio::test]
    async fn the_compromised_fixture_exercises_every_detector() {
        let report = run_now(Scenario::Compromised).await.unwrap();

        for expected in [
            "indicator.package-match",
            "accessibility.enabled-service",
            "device-admin.active",
            "notifications.listener",
            "provenance.no-installer",
            "provenance.non-play-installer",
            "boot.not-verified",
        ] {
            assert!(
                report.findings.iter().any(|f| f.id == expected),
                "demo should exercise `{expected}`; got {:?}",
                report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
            );
        }

        assert!(matches!(report.verdict(), Verdict::IndicatorsFound { .. }));
    }

    #[tokio::test]
    async fn the_demo_finds_a_package_hiding_in_the_work_profile() {
        let report = run_now(Scenario::Compromised).await.unwrap();

        // Several packages match indicators; pick the one planted in the work
        // profile rather than whichever happens to come first.
        let hit = report
            .findings
            .iter()
            .find(|f| f.id == "indicator.package-match" && f.detail.contains("com.demo.trackerpro"))
            .expect("the work-profile stalkerware match");

        assert_eq!(hit.severity, Severity::Critical);
        assert!(hit.detail.contains("user 10"), "got: {}", hit.detail);
    }

    #[tokio::test]
    async fn even_the_compromised_demo_never_claims_the_higher_tiers() {
        let report = run_now(Scenario::Compromised).await.unwrap();
        assert!(
            report
                .findings_credible_against(ThreatTier::RuntimeKernel)
                .is_empty()
        );
    }
}
