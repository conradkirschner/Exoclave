//! Detection modules.
//!
//! Each detector turns one slice of [`Observations`] into evidenced findings.
//! They share three rules:
//!
//! * **No finding without a verbatim excerpt.** The builder enforces it.
//! * **Severity and confidence are independent.** An active accessibility
//!   service is certain and often benign; a beaconing pattern is uncertain and
//!   rarely benign. Collapsing the two is how a tool teaches its user to ignore
//!   it.
//! * **Report, do not accuse.** Legitimate monitoring software exists, and the
//!   person reading this report may have installed it themselves.

use crate::indicators::{IndicatorClass, IndicatorSet};
use crate::observations::Observations;
use ps_adb::parse::ComponentName;
use ps_model::{
    Confidence, CoverageStatus, Evidence, Finding, FindingBuilder, Severity, SourceRef, ThreatTier,
    TierCoverage, TrustBasis,
};

/// Accessibility services shipped by Android or a vendor, or belonging to
/// well-known assistive and password-management software.
///
/// Being on this list means "do not raise an alarm by default", not "trusted":
/// an attacker who compromises one of these packages inherits its privileges.
const KNOWN_ACCESSIBILITY_PACKAGES: &[&str] = &[
    // Google assistive technology
    "com.google.android.marvin.talkback",
    "com.google.android.apps.accessibility.voiceaccess",
    "com.google.android.accessibility.selecttospeak",
    "com.google.android.accessibility.switchaccess",
    "com.google.android.apps.accessibility.reveal",
    // Samsung assistive technology
    "com.samsung.android.app.talkback",
    "com.samsung.accessibility",
    // Password managers, which legitimately need autofill via accessibility
    "com.x8bit.bitwarden",
    "com.agilebits.onepassword",
    "com.lastpass.lpandroid",
    "com.keepassdroid",
];

/// Device administrator packages that are ordinarily legitimate: Google's own
/// device management, and mainstream enterprise MDM agents.
const KNOWN_DEVICE_ADMIN_PACKAGES: &[&str] = &[
    "com.google.android.gms",
    "com.google.android.apps.work.clouddpc",
    "com.microsoft.windowsintune.companyportal",
    "com.airwatch.androidagent",
    "net.soti.mobicontrol.androidwork",
];

fn is_known(package: &str, list: &[&str]) -> bool {
    list.iter().any(|known| known.eq_ignore_ascii_case(package))
}

/// Run every detector.
#[must_use]
pub fn analyse(obs: &Observations, indicators: &IndicatorSet) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(matched_indicators(obs, indicators));
    findings.extend(accessibility_services(obs, indicators));
    findings.extend(device_admins(obs, indicators));
    findings.extend(notification_listeners(obs, indicators));
    findings.extend(install_provenance(obs));
    findings.extend(claimed_boot_state(obs));
    findings
}

/// Installed packages matching a published indicator feed.
fn matched_indicators(obs: &Observations, indicators: &IndicatorSet) -> Vec<Finding> {
    let Some(packages) = obs.packages.get() else {
        return Vec::new();
    };

    packages
        .iter()
        .filter_map(|package| {
            let hit = indicators.lookup(&package.id)?;

            // Watchware may be present with the owner's knowledge — parental
            // controls, a work phone. Flag it, but do not call it an attack.
            let (severity, verb) = match hit.class {
                IndicatorClass::Watchware => {
                    (Severity::Medium, "matches known monitoring software")
                }
                _ => (Severity::Critical, "matches a known malicious indicator"),
            };

            let label = hit.name.as_deref().unwrap_or(&hit.app_id);
            let user_note = if package.is_secondary_user() {
                format!(
                    " It is installed under user {}, not the main profile.",
                    package.user_id
                )
            } else {
                String::new()
            };

            FindingBuilder::new("indicator.package-match", format!("{label} is installed"))
                .detail(format!(
                    "The package `{}` {verb} ({}).{user_note}",
                    package.id,
                    hit.class.describes()
                ))
                .severity(severity)
                .confidence(Confidence::Confirmed)
                .tier(ThreatTier::AppLevel)
                .evidence(Evidence::new(
                    SourceRef::new("adb/pm-list-packages.txt").at(&package.id),
                    TrustBasis::SelfReported,
                    package
                        .apk_path
                        .clone()
                        .unwrap_or_else(|| package.id.clone()),
                ))
                .remediation("remove-malicious-app")
                .subject(ps_model::Subject::Package {
                    id: package.id.clone(),
                    user_id: package.user_id,
                })
                .build()
        })
        .collect()
}

/// Enabled accessibility services — the mechanism stalkerware and banking
/// trojans overwhelmingly depend on.
fn accessibility_services(obs: &Observations, indicators: &IndicatorSet) -> Vec<Finding> {
    component_findings(
        obs.accessibility_services.get(),
        indicators,
        &ComponentKind {
            source: "adb/settings-secure.txt",
            locator: "enabled_accessibility_services",
            id: "accessibility.enabled-service",
            allowlist: KNOWN_ACCESSIBILITY_PACKAGES,
            unknown_severity: Severity::High,
            remediation: "revoke-accessibility",
            describe_unknown: |component| {
                format!(
                    "`{}` can read everything on screen, see what you type, and act on \
                     your behalf. This is the capability overlay attacks and keyloggers \
                     are built on. If you did not deliberately enable an accessibility \
                     tool, this should not be here.",
                    component.package
                )
            },
            describe_known: |component| {
                format!(
                    "`{}` is a recognised accessibility tool. Expected if you use it.",
                    component.package
                )
            },
        },
    )
}

/// Active device administrators — used by malware to resist uninstall.
fn device_admins(obs: &Observations, indicators: &IndicatorSet) -> Vec<Finding> {
    component_findings(
        obs.device_admins.get(),
        indicators,
        &ComponentKind {
            source: "adb/dumpsys-device_policy.txt",
            locator: "admin",
            id: "device-admin.active",
            allowlist: KNOWN_DEVICE_ADMIN_PACKAGES,
            unknown_severity: Severity::High,
            remediation: "revoke-device-admin",
            describe_unknown: |component| {
                format!(
                    "`{}` is registered as a device administrator. That lets it lock or \
                     wipe the device and makes it refuse to uninstall normally. Malware \
                     uses this to dig in; so does legitimate work-phone management.",
                    component.package
                )
            },
            describe_known: |component| {
                format!(
                    "`{}` is a recognised device management component.",
                    component.package
                )
            },
        },
    )
}

/// Notification listeners — they see one-time codes as they arrive.
fn notification_listeners(obs: &Observations, indicators: &IndicatorSet) -> Vec<Finding> {
    component_findings(
        obs.notification_listeners.get(),
        indicators,
        &ComponentKind {
            source: "adb/settings-secure.txt",
            locator: "enabled_notification_listeners",
            id: "notifications.listener",
            allowlist: &[],
            unknown_severity: Severity::Medium,
            remediation: "revoke-notification-access",
            describe_unknown: |component| {
                format!(
                    "`{}` can read every notification, including banking confirmation \
                     codes and messages, without opening any app.",
                    component.package
                )
            },
            describe_known: |component| format!("`{}` reads notifications.", component.package),
        },
    )
}

/// Shared shape for the three "a component holds a dangerous privilege" checks.
struct ComponentKind {
    source: &'static str,
    locator: &'static str,
    id: &'static str,
    allowlist: &'static [&'static str],
    unknown_severity: Severity,
    remediation: &'static str,
    describe_unknown: fn(&ComponentName) -> String,
    describe_known: fn(&ComponentName) -> String,
}

fn component_findings(
    components: Option<&Vec<ComponentName>>,
    indicators: &IndicatorSet,
    kind: &ComponentKind,
) -> Vec<Finding> {
    let Some(components) = components else {
        return Vec::new();
    };

    components
        .iter()
        .filter_map(|component| {
            let flagged = indicators.lookup(&component.package).is_some();
            let known_good = !flagged && is_known(&component.package, kind.allowlist);

            let (severity, confidence, detail) = if flagged {
                (
                    Severity::Critical,
                    Confidence::Confirmed,
                    format!(
                        "`{}` holds this privilege *and* matches a known malicious \
                         indicator.",
                        component.package
                    ),
                )
            } else if known_good {
                (
                    Severity::Info,
                    Confidence::Strong,
                    (kind.describe_known)(component),
                )
            } else {
                (
                    kind.unknown_severity,
                    Confidence::Moderate,
                    (kind.describe_unknown)(component),
                )
            };

            FindingBuilder::new(
                kind.id,
                format!("{} holds a sensitive privilege", component.package),
            )
            .detail(detail)
            .severity(severity)
            .confidence(confidence)
            .tier(ThreatTier::AppLevel)
            .evidence(Evidence::new(
                SourceRef::new(kind.source).at(kind.locator),
                TrustBasis::SelfReported,
                component.to_string(),
            ))
            .remediation(kind.remediation)
            // Secure settings are read for the primary user, so that is the
            // profile any revocation has to target.
            .subject(ps_model::Subject::Component {
                package: component.package.clone(),
                class: component.class.clone(),
                user_id: 0,
            })
            .build()
        })
        .collect()
}

/// Packages that did not come from the Play Store.
///
/// Emitted as one grouped finding: a device with thirty sideloaded packages
/// should produce one line to investigate, not thirty alarms.
fn install_provenance(obs: &Observations) -> Vec<Finding> {
    let Some(packages) = obs.packages.get() else {
        return Vec::new();
    };

    let sideloaded: Vec<&ps_model::Package> = packages
        .iter()
        .filter(|p| !p.uninstalled && !p.is_from_play() && p.installer.is_some())
        .collect();

    let unattributed: Vec<&ps_model::Package> = packages
        .iter()
        .filter(|p| !p.uninstalled && p.installer.is_none())
        .collect();

    let mut findings = Vec::new();

    if !unattributed.is_empty() {
        let names: Vec<&str> = unattributed.iter().map(|p| p.id.as_str()).collect();
        let builder = FindingBuilder::new(
            "provenance.no-installer",
            format!("{} package(s) have no recorded installer", names.len()),
        )
        .detail(
            "These packages have no installing app on record, which is what a \
             sideloaded APK looks like. Pre-installed system software also appears \
             this way, so this is a starting point for review rather than a problem \
             in itself."
                .to_owned(),
        )
        .severity(Severity::Low)
        .confidence(Confidence::Moderate)
        .tier(ThreatTier::AppLevel)
        .evidence(Evidence::new(
            SourceRef::new("adb/pm-list-packages.txt").at("installer=null"),
            TrustBasis::SelfReported,
            names.join("\n"),
        ));
        findings.extend(builder.build());
    }

    if !sideloaded.is_empty() {
        let lines: Vec<String> = sideloaded
            .iter()
            .map(|p| format!("{} <- {}", p.id, p.installer.as_deref().unwrap_or("?")))
            .collect();
        let builder = FindingBuilder::new(
            "provenance.non-play-installer",
            format!(
                "{} package(s) were installed by something other than the Play Store",
                lines.len()
            ),
        )
        .detail(
            "Another app installed these. That is normal for a vendor app store or \
             a package manager you use deliberately; it is also exactly how a dropper \
             delivers its payload. Check that you recognise the installing app."
                .to_owned(),
        )
        .severity(Severity::Medium)
        .confidence(Confidence::Moderate)
        .tier(ThreatTier::AppLevel)
        .evidence(Evidence::new(
            SourceRef::new("adb/pm-list-packages.txt").at("installer"),
            TrustBasis::SelfReported,
            lines.join("\n"),
        ));
        findings.extend(builder.build());
    }

    findings
}

/// Verified Boot state as claimed by the device.
///
/// Only the *adverse* answer is worth reporting. A compromised OS can claim
/// `green` freely, so a green claim proves nothing; but no implant benefits
/// from claiming a worse state than the truth, so a non-green claim is
/// credible. Settling a green claim requires an attestation certificate, which
/// this run does not yet collect — the coverage statement says so.
fn claimed_boot_state(obs: &Observations) -> Vec<Finding> {
    let Some(state) = obs.claimed_boot_state.get() else {
        return Vec::new();
    };
    if state.is_nominal() {
        return Vec::new();
    }

    FindingBuilder::new(
        "boot.not-verified",
        "The device reports that Verified Boot is not intact",
    )
    .detail(format!(
        "Verified Boot state is `{state:?}` rather than green. The bootloader is \
         unlocked or the system partitions are not vendor-signed, which means \
         software can persist through a factory reset. The device has no reason to \
         understate its own integrity, so this answer can be believed."
    ))
    .severity(Severity::High)
    .confidence(Confidence::Strong)
    .tier(ThreatTier::PrivilegedPersistent)
    .evidence(Evidence::new(
        SourceRef::new("adb/getprop.txt").at("ro.boot.verifiedbootstate"),
        TrustBasis::SelfReported,
        format!("{state:?}"),
    ))
    .remediation("reflash-and-relock")
    .build()
    .into_iter()
    .collect()
}

/// State what this run could and could not speak to, per adversary tier.
///
/// This is the function that stops the tool from ever implying "clean".
#[must_use]
pub fn coverage(obs: &Observations, indicators: &IndicatorSet) -> Vec<TierCoverage> {
    let gaps = obs.collection_gaps();

    let app_level = if indicators.is_empty() {
        TierCoverage {
            tier: ThreatTier::AppLevel,
            status: CoverageStatus::Partial,
            rationale: "Device state was collected, but no indicator feed was loaded, so \
                        known malicious packages could not be matched."
                .to_owned(),
        }
    } else if gaps.is_empty() {
        TierCoverage {
            tier: ThreatTier::AppLevel,
            status: CoverageStatus::Covered,
            rationale: format!(
                "Packages, accessibility services, notification listeners and device \
                 administrators were all collected and matched against {} indicator(s) \
                 from {} feed(s).",
                indicators.len(),
                indicators.feed_names().len()
            ),
        }
    } else {
        let missing: Vec<&str> = gaps.iter().map(|(name, _)| *name).collect();
        TierCoverage {
            tier: ThreatTier::AppLevel,
            status: CoverageStatus::Partial,
            rationale: format!("Could not collect: {}.", missing.join(", ")),
        }
    };

    vec![
        app_level,
        TierCoverage {
            tier: ThreatTier::PrivilegedPersistent,
            status: CoverageStatus::NotCovered,
            rationale: "No hardware attestation certificate was collected. The device's \
                        own claim about Verified Boot cannot settle this, because \
                        privileged code can rewrite that property."
                .to_owned(),
        },
        TierCoverage {
            tier: ThreatTier::RuntimeKernel,
            status: CoverageStatus::NotCovered,
            rationale: "Every input in this run came from the device's own operating \
                        system, which an implant with kernel privileges can alter. \
                        Ruling this tier in or out needs observation from outside the \
                        device."
                .to_owned(),
        },
        TierCoverage {
            tier: ThreatTier::BootChain,
            status: CoverageStatus::NotCovered,
            rationale: "Compromise beneath the operating system cannot be assessed by \
                        any host-side tool."
                .to_owned(),
        },
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::observations::Observed;
    use ps_model::{DeviceIdentity, Package};

    fn indicators_with(app_id: &str, class: &str) -> IndicatorSet {
        let feed = format!(
            r#"{{"name":"t","source_url":"u","license":"CC-BY-4.0",
                 "indicators":[{{"app_id":"{app_id}","class":"{class}","name":"Nasty"}}]}}"#
        );
        let mut set = IndicatorSet::new();
        set.load_feed(&feed).expect("valid feed");
        set
    }

    fn package(id: &str, installer: Option<&str>) -> Package {
        Package {
            id: id.to_owned(),
            apk_path: Some(format!("/data/app/{id}/base.apk")),
            installer: installer.map(ToOwned::to_owned),
            user_id: 0,
            uninstalled: false,
        }
    }

    fn observations(packages: Vec<Package>, accessibility: Vec<&str>) -> Observations {
        Observations {
            identity: DeviceIdentity::default(),
            packages: Observed::Present(packages),
            accessibility_services: Observed::Present(
                accessibility
                    .into_iter()
                    .filter_map(ComponentName::parse)
                    .collect(),
            ),
            notification_listeners: Observed::Present(Vec::new()),
            device_admins: Observed::Present(Vec::new()),
            claimed_boot_state: Observed::Present(ps_model::BootState::Green),
        }
    }

    #[test]
    fn a_known_malicious_package_is_critical_and_confirmed() {
        let obs = observations(
            vec![package("com.bad.spy", Some("com.android.vending"))],
            vec![],
        );
        let findings = analyse(&obs, &indicators_with("com.bad.spy", "stalkerware"));

        let hit = findings
            .iter()
            .find(|f| f.id == "indicator.package-match")
            .expect("match");
        assert_eq!(hit.severity, Severity::Critical);
        assert_eq!(hit.confidence, Confidence::Confirmed);
        assert!(hit.title.contains("Nasty"));
    }

    #[test]
    fn watchware_is_reported_but_not_treated_as_an_attack() {
        let obs = observations(
            vec![package("com.family.control", Some("com.android.vending"))],
            vec![],
        );
        let findings = analyse(&obs, &indicators_with("com.family.control", "watchware"));

        let hit = findings
            .iter()
            .find(|f| f.id == "indicator.package-match")
            .expect("match");
        assert_eq!(hit.severity, Severity::Medium);
    }

    #[test]
    fn talkback_does_not_raise_an_alarm_but_an_unknown_service_does() {
        let obs = observations(
            vec![],
            vec![
                "com.google.android.marvin.talkback/.TalkBackService",
                "com.unknown.app/.Svc",
            ],
        );
        let findings = analyse(&obs, &IndicatorSet::new());

        let severities: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "accessibility.enabled-service")
            .map(|f| (f.title.clone(), f.severity))
            .collect();

        assert!(
            severities
                .iter()
                .any(|(title, sev)| title.contains("talkback") && *sev == Severity::Info)
        );
        assert!(
            severities
                .iter()
                .any(|(title, sev)| title.contains("com.unknown.app") && *sev == Severity::High)
        );
    }

    #[test]
    fn an_accessibility_service_that_is_also_a_known_indicator_escalates() {
        let obs = observations(vec![], vec!["com.bad.spy/.Svc"]);
        let findings = analyse(&obs, &indicators_with("com.bad.spy", "stalkerware"));

        let hit = findings
            .iter()
            .find(|f| f.id == "accessibility.enabled-service")
            .expect("service finding");
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn sideloaded_packages_are_grouped_into_one_finding() {
        let obs = observations(
            vec![
                package("com.a", None),
                package("com.b", None),
                package("com.c", Some("com.android.vending")),
            ],
            vec![],
        );
        let findings = analyse(&obs, &IndicatorSet::new());

        let grouped: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "provenance.no-installer")
            .collect();
        assert_eq!(grouped.len(), 1);
        assert!(grouped.first().expect("one").title.starts_with("2 package"));
    }

    #[test]
    fn a_green_boot_claim_produces_no_finding_because_it_proves_nothing() {
        let obs = observations(vec![], vec![]);
        let findings = analyse(&obs, &IndicatorSet::new());
        assert!(!findings.iter().any(|f| f.id == "boot.not-verified"));
    }

    #[test]
    fn an_adverse_boot_claim_is_believed() {
        let mut obs = observations(vec![], vec![]);
        obs.claimed_boot_state = Observed::Present(ps_model::BootState::Orange);

        let findings = analyse(&obs, &IndicatorSet::new());
        let hit = findings
            .iter()
            .find(|f| f.id == "boot.not-verified")
            .expect("boot finding");
        assert_eq!(hit.tier, ThreatTier::PrivilegedPersistent);
        assert_eq!(hit.confidence, Confidence::Strong);
    }

    #[test]
    fn coverage_never_claims_the_higher_tiers() {
        let obs = observations(vec![], vec![]);
        let coverage = coverage(&obs, &indicators_with("com.bad.spy", "stalkerware"));

        let covered: Vec<_> = coverage
            .iter()
            .filter(|c| c.status == CoverageStatus::Covered)
            .map(|c| c.tier)
            .collect();
        assert_eq!(covered, vec![ThreatTier::AppLevel]);
        assert!(coverage.iter().all(|c| !c.rationale.is_empty()));
    }

    #[test]
    fn without_an_indicator_feed_even_app_level_is_only_partial() {
        let obs = observations(vec![], vec![]);
        let coverage = coverage(&obs, &IndicatorSet::new());

        let app = coverage
            .iter()
            .find(|c| c.tier == ThreatTier::AppLevel)
            .expect("app tier");
        assert_eq!(app.status, CoverageStatus::Partial);
    }
}
