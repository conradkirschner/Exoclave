//! Cleanup: what to do about what was found, and doing it safely.
//!
//! Five rules hold this crate together, each enforced by the types rather than
//! by documentation:
//!
//! 1. **Only act on something a finding named.** A [`plan::Step`] can only be
//!    built from a [`ps_model::Finding`] carrying a [`ps_model::Subject`], so
//!    there is no path from free text to a device command.
//! 2. **Refuse system software even when a finding names it.** Indicator feeds
//!    are third-party data; see [`protected`].
//! 3. **Prefer disabling to uninstalling.** Reversible if the finding is
//!    wrong, and it preserves the evidence.
//! 4. **Order is a correctness constraint**, not presentation: device
//!    administrator rights must go before any uninstall or the uninstall
//!    silently fails.
//! 5. **Verify by re-reading the device.** Android's shell tools report
//!    failure on stdout with a zero exit status, so a trusted exit code would
//!    mean telling someone their phone was cleaned when nothing happened.
//!
//! A [`plan::Plan`] is inert. Holding one changes nothing; steps run only when
//! passed to [`execute::run`], one at a time, after the user agrees to that
//! specific step.
//!
//! The plan also carries what cleanup *cannot* fix. Monitoring software exists
//! to take credentials, and access established elsewhere survives anything
//! done to the handset — so a serious finding always adds account steps, and
//! the warnings say plainly that the only reliable certainty is a factory
//! reset without restoring a backup.

pub mod execute;
pub mod plan;
pub mod protected;

pub use execute::{Outcome, run};
pub use plan::{Action, DeviceAction, Plan, Reversibility, Step, from_report};

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use ps_adb::fake::FakeShell;
    use ps_model::{
        Confidence, DeviceIdentity, Evidence, FindingBuilder, Report, Severity, SourceRef, Subject,
        ThreatTier, TrustBasis,
    };

    /// A report shaped like a real stalkerware hit: a package match, an
    /// accessibility service, and a device administrator, all one app.
    fn infested_report() -> Report {
        let mut report = Report::new(DeviceIdentity::default(), chrono::Utc::now());

        let make = |id: &str, remediation: &str, subject: Subject| {
            FindingBuilder::new(id, "t")
                .detail("d")
                .severity(Severity::Critical)
                .confidence(Confidence::Confirmed)
                .tier(ThreatTier::AppLevel)
                .evidence(Evidence::new(
                    SourceRef::new("a.txt"),
                    TrustBasis::SelfReported,
                    "x",
                ))
                .remediation(remediation)
                .subject(subject)
                .build()
                .unwrap()
        };

        report.findings = vec![
            make(
                "indicator.package-match",
                "remove-malicious-app",
                Subject::Package {
                    id: "com.bad.spy".to_owned(),
                    user_id: 0,
                },
            ),
            make(
                "device-admin.active",
                "revoke-device-admin",
                Subject::Component {
                    package: "com.bad.spy".to_owned(),
                    class: "com.bad.spy.Admin".to_owned(),
                    user_id: 0,
                },
            ),
            make(
                "accessibility.enabled-service",
                "revoke-accessibility",
                Subject::Component {
                    package: "com.bad.spy".to_owned(),
                    class: "com.bad.spy.Service".to_owned(),
                    user_id: 0,
                },
            ),
        ];
        report
    }

    #[test]
    fn a_plan_is_inert_until_a_step_is_run() {
        // Building a plan touches no device at all: there is no shell here to
        // touch one with.
        let plan = from_report(&infested_report());
        assert_eq!(plan.automatic().len(), 3);
    }

    #[tokio::test]
    async fn the_planned_order_is_the_order_that_actually_works() {
        let plan = from_report(&infested_report());

        // Accessibility, then device admin, then the app itself.
        let ids: Vec<&str> = plan.automatic().iter().map(|s| s.id.as_str()).collect();
        assert!(ids.first().unwrap().starts_with("revoke-accessibility"));
        assert!(ids.get(1).unwrap().starts_with("revoke-device-admin"));
        assert!(ids.get(2).unwrap().starts_with("remove-malicious-app"));

        // And the last of those really does succeed once the admin is gone.
        let shell = FakeShell::new()
            .with("shell pm disable-user --user 0 com.bad.spy", "")
            .with(
                "shell pm list packages -d --user 0",
                "package:com.bad.spy\n",
            );

        let step = plan.automatic().get(2).copied().unwrap().clone();
        let Action::Device(action) = step.action else {
            panic!("expected a device action");
        };
        assert_eq!(run(&shell, &action).await.unwrap(), Outcome::Done);
    }

    #[test]
    fn every_automatic_step_explains_itself_before_it_is_confirmed() {
        let plan = from_report(&infested_report());

        for step in plan.automatic() {
            assert!(!step.title.is_empty(), "{} has no title", step.id);
            assert!(!step.why.is_empty(), "{} has no rationale", step.id);
            assert!(
                step.reversibility().is_some(),
                "{} does not say whether it can be undone",
                step.id
            );
            assert!(
                !step.addresses.is_empty(),
                "{} is not traceable to a finding",
                step.id
            );
        }
    }

    #[test]
    fn the_plan_says_what_cleanup_cannot_fix() {
        let plan = from_report(&infested_report());

        assert!(
            plan.warnings.iter().any(|w| w.contains("factory reset")),
            "certainty costs a reset, and the plan has to say so"
        );
        assert!(
            plan.manual().iter().any(|s| s.id == "accounts.rotate"),
            "a phone reset does nothing about credentials already taken"
        );
    }
}
