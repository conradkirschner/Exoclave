//! Detection: collected observations in, evidenced findings out.
//!
//! The pipeline is deliberately boring and synchronous once acquisition is
//! done. [`Observations`] is a plain value, so the whole detection stage runs
//! against fixtures in CI with no device, no network and no clock.
//!
//! What this crate does *not* do is as important as what it does. It emits a
//! [`ps_model::Report`] whose coverage statement says, in every run, that
//! nothing here can rule out an implant with kernel privileges — because every
//! input came from the device's own operating system. Raising that ceiling
//! requires evidence the device cannot edit: a hardware attestation
//! certificate, or traffic observed on our own access point.

pub mod demo;
pub mod detectors;
pub mod indicators;
pub mod observations;

pub use detectors::{analyse, coverage};
pub use indicators::{AppIndicator, FeedDocument, IndicatorClass, IndicatorSet};
pub use observations::{Observations, Observed};

use chrono::{DateTime, Utc};
use ps_model::Report;

/// Assemble a complete report from one acquisition.
#[must_use]
pub fn report(
    obs: &Observations,
    indicators: &IndicatorSet,
    generated_at: DateTime<Utc>,
) -> Report {
    let mut report = Report::new(obs.identity.clone(), generated_at);
    report.findings = analyse(obs, indicators);
    report.coverage = coverage(obs, indicators);
    report.feeds = indicators.provenance().to_vec();
    report.metadata.insert(
        "tool_version".to_owned(),
        env!("CARGO_PKG_VERSION").to_owned(),
    );
    report
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use ps_adb::{Device, fake::FakeShell};
    use ps_model::{ThreatTier, Verdict};

    /// A device with nothing wrong with it, at app level.
    fn clean_device_shell() -> FakeShell {
        FakeShell::new()
            .with(
                "shell getprop",
                "[ro.product.manufacturer]: [Google]\n[ro.product.model]: [Pixel 9]\n",
            )
            .with("shell pm list users", "UserInfo{0:Owner:c13} running\n")
            .with(
                "shell pm list packages -f -i -u --user 0",
                "package:/data/app/a/base.apk=com.example installer=com.android.vending\n",
            )
            .with(
                "shell settings get secure enabled_accessibility_services",
                "null\n",
            )
            .with(
                "shell settings get secure enabled_notification_listeners",
                "null\n",
            )
            .with("shell dumpsys device_policy", "")
            .with("shell getprop ro.boot.verifiedbootstate", "green\n")
    }

    fn loaded_indicators() -> IndicatorSet {
        let mut set = IndicatorSet::new();
        set.load_feed(
            r#"{"name":"test","source_url":"https://example.invalid","license":"CC-BY-4.0",
                "indicators":[{"app_id":"com.bad.spy","class":"stalkerware"}]}"#,
        )
        .expect("valid feed");
        set
    }

    #[tokio::test]
    async fn an_uneventful_scan_reports_the_tier_it_covered_and_no_more() {
        let device = Device::new(clean_device_shell());
        let obs = Observations::collect(&device, "SERIAL").await.unwrap();
        let report = report(&obs, &loaded_indicators(), Utc::now());

        assert_eq!(
            report.verdict(),
            Verdict::NoIndicatorsFound {
                covered_through: ThreatTier::AppLevel
            }
        );

        let headline = report.verdict().headline();
        assert!(headline.contains("not ruled out"), "got: {headline}");
    }

    #[tokio::test]
    async fn the_report_carries_feed_provenance_for_later_re_evaluation() {
        let device = Device::new(clean_device_shell());
        let obs = Observations::collect(&device, "SERIAL").await.unwrap();
        let report = report(&obs, &loaded_indicators(), Utc::now());

        let feed = report.feeds.first().expect("one feed");
        assert_eq!(feed.license, "CC-BY-4.0");
        assert_eq!(feed.digest.len(), 64);
    }

    #[tokio::test]
    async fn a_stalkerware_hit_drives_the_verdict() {
        let shell = clean_device_shell().with(
            "shell pm list packages -f -i -u --user 0",
            "package:/data/app/a/base.apk=com.bad.spy installer=null\n",
        );
        let device = Device::new(shell);
        let obs = Observations::collect(&device, "SERIAL").await.unwrap();
        let report = report(&obs, &loaded_indicators(), Utc::now());

        assert!(matches!(
            report.verdict(),
            Verdict::IndicatorsFound { critical: 1, .. }
        ));
    }

    #[tokio::test]
    async fn findings_from_the_device_do_not_survive_the_kernel_tier_filter() {
        let shell = clean_device_shell().with(
            "shell pm list packages -f -i -u --user 0",
            "package:/data/app/a/base.apk=com.bad.spy installer=null\n",
        );
        let device = Device::new(shell);
        let obs = Observations::collect(&device, "SERIAL").await.unwrap();
        let report = report(&obs, &loaded_indicators(), Utc::now());

        assert!(!report.findings.is_empty());
        assert!(
            report
                .findings_credible_against(ThreatTier::RuntimeKernel)
                .is_empty(),
            "self-reported findings must not be presented as kernel-tier evidence"
        );
    }
}
