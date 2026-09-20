//! Demo mode: the real pipeline, against a fixture device.
//!
//! Every stage is the production one — the same collectors, the same
//! detectors, the same coverage statement. Only the transport is swapped, for
//! a [`ps_adb::fake::FakeShell`] replaying recorded-shaped output. So this is
//! a way to see and test the tool without a phone attached, not a mock-up of
//! what it might look like.
//!
//! The indicator feed below is synthetic. It exists so the demo has something
//! to match; it is not a real indicator set and must never be used as one.

use anyhow::{Context, Result};
use chrono::Utc;
use clap::ValueEnum;
use ps_adb::{Device, fake::scenarios};
use ps_analyze::{IndicatorSet, Observations};
use ps_model::Report;

/// Synthetic feed covering only the fixture's `com.demo.*` packages.
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
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum Scenario {
    /// A device with nothing wrong with it at app level.
    Healthy,
    /// A device showing the full range of app-tier problems.
    Compromised,
}

/// Run the full pipeline against the chosen fixture.
pub(crate) async fn run(scenario: Scenario) -> Result<Report> {
    let mut indicators = IndicatorSet::new();
    indicators
        .load_feed(DEMO_FEED)
        .context("the built-in demo feed is malformed, which is a bug")?;

    let report = match scenario {
        Scenario::Healthy => {
            let device = Device::new(scenarios::healthy());
            let observations = Observations::collect(&device, "DEMO-HEALTHY").await?;
            ps_analyze::report(&observations, &indicators, Utc::now())
        }
        Scenario::Compromised => {
            let device = Device::new(scenarios::compromised());
            let observations = Observations::collect(&device, "DEMO-COMPROMISED").await?;
            ps_analyze::report(&observations, &indicators, Utc::now())
        }
    };

    Ok(report)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use ps_model::{Severity, ThreatTier, Verdict};

    #[tokio::test]
    async fn the_healthy_fixture_produces_no_serious_findings() {
        let report = run(Scenario::Healthy).await.unwrap();

        assert_eq!(
            report.verdict(),
            Verdict::NoIndicatorsFound {
                covered_through: ThreatTier::AppLevel
            }
        );
        assert!(
            report.findings.iter().all(|f| f.severity < Severity::High),
            "healthy fixture should not raise anything serious"
        );
    }

    #[tokio::test]
    async fn the_compromised_fixture_exercises_every_detector() {
        let report = run(Scenario::Compromised).await.unwrap();

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
        let report = run(Scenario::Compromised).await.unwrap();

        // Several packages match indicators; pick the one planted in the work
        // profile rather than whichever happens to come first.
        let hit = report
            .findings
            .iter()
            .find(|f| f.id == "indicator.package-match" && f.detail.contains("com.demo.trackerpro"))
            .expect("the work-profile stalkerware match");

        assert_eq!(hit.severity, Severity::Critical);
        assert!(
            hit.detail.contains("user 10"),
            "the report must say which profile it was found in; got: {}",
            hit.detail
        );
    }

    #[tokio::test]
    async fn even_the_compromised_demo_never_claims_the_higher_tiers() {
        let report = run(Scenario::Compromised).await.unwrap();
        assert!(
            report
                .findings_credible_against(ThreatTier::RuntimeKernel)
                .is_empty()
        );
    }
}
