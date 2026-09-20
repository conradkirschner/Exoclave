//! Turning a report into an ordered, survivable cleanup plan.

use crate::protected;
use ps_model::{Finding, Report, Severity};
use serde::{Deserialize, Serialize};

/// How hard a step is to undo. Shown before the user commits to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reversibility {
    /// Can be switched straight back on.
    Reversible,
    /// The app can be reinstalled, but its data is gone.
    LosesData,
    /// Cannot be undone at all.
    Irreversible,
}

impl Reversibility {
    #[must_use]
    pub const fn describes(self) -> &'static str {
        match self {
            Self::Reversible => "can be undone",
            Self::LosesData => "the app can be reinstalled, but its data is gone",
            Self::Irreversible => "cannot be undone",
        }
    }
}

/// Something this tool can do over ADB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DeviceAction {
    /// Take away the ability to read the screen and act on the user's behalf.
    RevokeAccessibility { component: String, user_id: u32 },
    /// Take away the ability to read every notification.
    RevokeNotificationAccess { component: String, user_id: u32 },
    /// Give up device-administrator rights, which otherwise block uninstall.
    RemoveDeviceAdmin { component: String },
    /// Stop the app running, keeping it and its data in place.
    DisablePackage { package: String, user_id: u32 },
    /// Remove the app and its data.
    UninstallPackage { package: String, user_id: u32 },
}

impl DeviceAction {
    /// The package this action affects.
    #[must_use]
    pub fn package(&self) -> &str {
        match self {
            Self::RevokeAccessibility { component, .. }
            | Self::RevokeNotificationAccess { component, .. }
            | Self::RemoveDeviceAdmin { component } => component
                .split_once('/')
                .map_or(component.as_str(), |(p, _)| p),
            Self::DisablePackage { package, .. } | Self::UninstallPackage { package, .. } => {
                package
            }
        }
    }

    #[must_use]
    pub const fn reversibility(&self) -> Reversibility {
        match self {
            Self::RevokeAccessibility { .. }
            | Self::RevokeNotificationAccess { .. }
            | Self::RemoveDeviceAdmin { .. }
            | Self::DisablePackage { .. } => Reversibility::Reversible,
            Self::UninstallPackage { .. } => Reversibility::LosesData,
        }
    }

    /// Sort key. Ordering is a correctness constraint, not presentation:
    /// capability is cut first so a watching app loses its eyes before it is
    /// disturbed, and device-admin rights must go before any uninstall,
    /// because an active admin makes `pm uninstall` fail.
    #[must_use]
    pub const fn order(&self) -> u8 {
        match self {
            Self::RevokeAccessibility { .. } => 10,
            Self::RevokeNotificationAccess { .. } => 20,
            Self::RemoveDeviceAdmin { .. } => 30,
            Self::DisablePackage { .. } => 40,
            Self::UninstallPackage { .. } => 50,
        }
    }
}

/// What a step asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Action {
    /// Exoclave can do this, once the user confirms.
    Device(DeviceAction),
    /// Only the user can do this.
    Manual { instructions: Vec<String> },
}

/// One thing to do, with the reasoning attached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub id: String,
    pub title: String,
    /// Why this is being suggested, in plain language.
    pub why: String,
    pub action: Action,
    /// Something the user should weigh before confirming.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caution: Option<String>,
    /// Finding ids this step addresses.
    pub addresses: Vec<String>,
}

impl Step {
    #[must_use]
    pub const fn is_automatic(&self) -> bool {
        matches!(self.action, Action::Device(_))
    }

    #[must_use]
    pub fn reversibility(&self) -> Option<Reversibility> {
        match &self.action {
            Action::Device(action) => Some(action.reversibility()),
            Action::Manual { .. } => None,
        }
    }

    fn order(&self) -> u8 {
        match &self.action {
            Action::Device(action) => action.order(),
            // Manual steps are advice that outlives the device work.
            Action::Manual { .. } => 90,
        }
    }
}

/// An ordered cleanup plan.
///
/// Inert by construction: holding a `Plan` changes nothing. Each step is
/// carried out only when passed to [`crate::execute`], one at a time, after
/// the user has agreed to that specific step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// Things to weigh before starting at all.
    pub warnings: Vec<String>,
    pub steps: Vec<Step>,
}

impl Plan {
    /// Steps Exoclave can carry out itself.
    #[must_use]
    pub fn automatic(&self) -> Vec<&Step> {
        self.steps.iter().filter(|s| s.is_automatic()).collect()
    }

    /// Steps only the user can do.
    #[must_use]
    pub fn manual(&self) -> Vec<&Step> {
        self.steps.iter().filter(|s| !s.is_automatic()).collect()
    }
}

/// Build a plan from a report.
#[must_use]
pub fn from_report(report: &Report) -> Plan {
    let mut steps: Vec<Step> = Vec::new();

    for finding in &report.findings {
        steps.extend(step_for(finding));
    }

    // Two findings about the same package can ask for the same action; doing
    // it twice is noise at best.
    steps.sort_by(|a, b| a.order().cmp(&b.order()).then_with(|| a.id.cmp(&b.id)));
    steps.dedup_by(|a, b| a.id == b.id);

    steps.extend(account_hygiene(report));

    Plan {
        warnings: warnings(report),
        steps,
    }
}

/// Things to consider before touching anything, phrased as decisions rather
/// than alarms.
fn warnings(report: &Report) -> Vec<String> {
    let mut out = Vec::new();

    let serious = report
        .findings
        .iter()
        .any(|f| f.severity >= Severity::High && f.subject.is_some());

    if serious {
        out.push(
            "Removing an app destroys the evidence of it. If this might end up in a police \
             report, a legal case, or a safety plan, export the report and keep it before \
             you clean anything up."
                .to_owned(),
        );
        out.push(
            "Whoever installed monitoring software may be alerted when it stops reporting. \
             If your safety depends on them not knowing, decide that before you act, not \
             after."
                .to_owned(),
        );
    }

    out.push(
        "Cleanup addresses what was found. Because detection failure is silent, the only \
         reliable way to be sure is a factory reset without restoring a backup."
            .to_owned(),
    );

    out
}

/// Steps that apply after any real finding, because a phone is not the only
/// thing that was exposed.
fn account_hygiene(report: &Report) -> Vec<Step> {
    let serious = report.findings.iter().any(|f| f.severity >= Severity::High);
    if !serious {
        return Vec::new();
    }

    vec![Step {
        id: "accounts.rotate".to_owned(),
        title: "Secure the accounts, not just the phone".to_owned(),
        why: "Monitoring software exists to take credentials. Cleaning or even resetting \
              the phone does nothing about access that has already been established \
              elsewhere, which is where the lasting damage usually is."
            .to_owned(),
        action: Action::Manual {
            instructions: vec![
                "Do all of this from a different device, not the phone being examined.".to_owned(),
                "Bank: ask them to check for registered TAN devices you do not recognise, \
                 new payees, and changed transfer limits. An attacker who registered their \
                 own TAN device keeps access after any phone reset."
                    .to_owned(),
                "Google account: change the password, sign out all devices, then check the \
                 recovery email and phone number, app passwords, and third-party access."
                    .to_owned(),
                "Email: check for forwarding rules and filters. A silent forward survives \
                 everything you do to the phone."
                    .to_owned(),
                "Phone line: dial ##002# to clear call and SMS forwarding, and ask your \
                 carrier for a port-out lock."
                    .to_owned(),
                "Treat anything typed on the phone while it was compromised as known — \
                 including any crypto wallet seed phrase."
                    .to_owned(),
            ],
        },
        caution: None,
        addresses: report
            .findings
            .iter()
            .filter(|f| f.severity >= Severity::High)
            .map(|f| f.id.clone())
            .collect(),
    }]
}

/// The step, if any, that addresses one finding.
fn step_for(finding: &Finding) -> Option<Step> {
    let subject = finding.subject.as_ref()?;
    let package = subject.package().to_owned();

    // A finding against system or vendor software becomes advice, never an
    // automatic action. See `protected`.
    if protected::is_protected(&package) {
        return Some(Step {
            id: format!("manual.protected.{package}"),
            title: format!("Review {package} by hand"),
            why: finding.detail.clone(),
            action: Action::Manual {
                instructions: vec![protected::protection_reason(&package)],
            },
            caution: None,
            addresses: vec![finding.id.clone()],
        });
    }

    let action = match finding.remediation.as_deref()? {
        "revoke-accessibility" => DeviceAction::RevokeAccessibility {
            component: subject.component_name()?,
            user_id: subject.user_id(),
        },
        "revoke-notification-access" => DeviceAction::RevokeNotificationAccess {
            component: subject.component_name()?,
            user_id: subject.user_id(),
        },
        "revoke-device-admin" => DeviceAction::RemoveDeviceAdmin {
            component: subject.component_name()?,
        },
        // Deliberately disable rather than uninstall. It stops the app dead,
        // it is reversible if the finding turns out to be wrong, and it keeps
        // the evidence in place.
        "remove-malicious-app" => DeviceAction::DisablePackage {
            package: package.clone(),
            user_id: subject.user_id(),
        },
        _ => return None,
    };

    Some(Step {
        id: format!(
            "{}.{package}",
            finding.remediation.clone().unwrap_or_default()
        ),
        title: title_for(&action, &package),
        why: finding.detail.clone(),
        caution: caution_for(&action),
        action: Action::Device(action),
        addresses: vec![finding.id.clone()],
    })
}

fn title_for(action: &DeviceAction, package: &str) -> String {
    match action {
        DeviceAction::RevokeAccessibility { .. } => {
            format!("Stop {package} reading the screen")
        }
        DeviceAction::RevokeNotificationAccess { .. } => {
            format!("Stop {package} reading notifications")
        }
        DeviceAction::RemoveDeviceAdmin { .. } => {
            format!("Remove {package}'s device administrator rights")
        }
        DeviceAction::DisablePackage { .. } => format!("Disable {package}"),
        DeviceAction::UninstallPackage { .. } => format!("Uninstall {package}"),
    }
}

fn caution_for(action: &DeviceAction) -> Option<String> {
    match action {
        DeviceAction::DisablePackage { .. } => Some(
            "Disabling stops the app without deleting it, so this can be undone and the \
             evidence is preserved. Uninstall it once you are sure."
                .to_owned(),
        ),
        DeviceAction::UninstallPackage { .. } => Some(
            "This deletes the app and its data. Export the report first if you may need \
             the evidence."
                .to_owned(),
        ),
        DeviceAction::RemoveDeviceAdmin { .. } => Some(
            "Device administrator rights are what stop an app being uninstalled normally, \
             so this has to happen before any removal."
                .to_owned(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use ps_model::{
        Confidence, DeviceIdentity, Evidence, FindingBuilder, SourceRef, Subject, ThreatTier,
        TrustBasis,
    };

    fn finding(id: &str, remediation: &str, subject: Subject, severity: Severity) -> Finding {
        FindingBuilder::new(id, "t")
            .detail("because reasons")
            .severity(severity)
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
    }

    fn report_with(findings: Vec<Finding>) -> Report {
        let mut report = Report::new(DeviceIdentity::default(), chrono::Utc::now());
        report.findings = findings;
        report
    }

    fn component(package: &str) -> Subject {
        Subject::Component {
            package: package.to_owned(),
            class: format!("{package}.Service"),
            user_id: 0,
        }
    }

    #[test]
    fn device_admin_is_always_revoked_before_the_app_is_touched() {
        let plan = from_report(&report_with(vec![
            finding(
                "indicator.package-match",
                "remove-malicious-app",
                Subject::Package {
                    id: "com.bad.spy".to_owned(),
                    user_id: 0,
                },
                Severity::Critical,
            ),
            finding(
                "device-admin.active",
                "revoke-device-admin",
                component("com.bad.spy"),
                Severity::High,
            ),
        ]));

        let order: Vec<&str> = plan.automatic().iter().map(|s| s.id.as_str()).collect();

        let admin = order
            .iter()
            .position(|id| id.starts_with("revoke-device-admin"));
        let remove = order
            .iter()
            .position(|id| id.starts_with("remove-malicious-app"));
        assert!(
            admin < remove,
            "an active device admin blocks uninstall; got {order:?}"
        );
    }

    #[test]
    fn accessibility_is_cut_first_of_all() {
        let plan = from_report(&report_with(vec![
            finding(
                "notifications.listener",
                "revoke-notification-access",
                component("com.bad.spy"),
                Severity::Medium,
            ),
            finding(
                "accessibility.enabled-service",
                "revoke-accessibility",
                component("com.bad.spy"),
                Severity::High,
            ),
        ]));

        assert!(
            plan.automatic()
                .first()
                .is_some_and(|s| s.id.starts_with("revoke-accessibility")),
            "reading the screen is the most dangerous capability, so it goes first"
        );
    }

    #[test]
    fn a_malicious_app_is_disabled_rather_than_uninstalled() {
        let plan = from_report(&report_with(vec![finding(
            "indicator.package-match",
            "remove-malicious-app",
            Subject::Package {
                id: "com.bad.spy".to_owned(),
                user_id: 0,
            },
            Severity::Critical,
        )]));

        let step = plan.automatic().first().copied().expect("a step").clone();
        assert!(matches!(
            step.action,
            Action::Device(DeviceAction::DisablePackage { .. })
        ));
        assert_eq!(step.reversibility(), Some(Reversibility::Reversible));
        assert!(step.caution.unwrap_or_default().contains("undone"));
    }

    #[test]
    fn a_system_package_becomes_advice_instead_of_an_automatic_action() {
        let plan = from_report(&report_with(vec![finding(
            "indicator.package-match",
            "remove-malicious-app",
            Subject::Package {
                id: "com.android.systemui".to_owned(),
                user_id: 0,
            },
            Severity::Critical,
        )]));

        assert!(
            plan.automatic().is_empty(),
            "a bad feed entry must never become `pm uninstall` against the platform"
        );
        assert_eq!(
            plan.manual().len(),
            2,
            "the protected step plus account hygiene"
        );
        assert!(
            plan.manual()
                .iter()
                .any(|s| s.id.contains("com.android.systemui"))
        );
    }

    #[test]
    fn the_same_action_asked_for_twice_appears_once() {
        let plan = from_report(&report_with(vec![
            finding(
                "accessibility.enabled-service",
                "revoke-accessibility",
                component("com.bad.spy"),
                Severity::High,
            ),
            finding(
                "accessibility.enabled-service",
                "revoke-accessibility",
                component("com.bad.spy"),
                Severity::High,
            ),
        ]));

        assert_eq!(plan.automatic().len(), 1);
    }

    #[test]
    fn a_serious_finding_adds_account_steps_that_a_phone_reset_would_not_fix() {
        let plan = from_report(&report_with(vec![finding(
            "indicator.package-match",
            "remove-malicious-app",
            Subject::Package {
                id: "com.bad.spy".to_owned(),
                user_id: 0,
            },
            Severity::Critical,
        )]));

        let accounts = plan
            .manual()
            .into_iter()
            .find(|s| s.id == "accounts.rotate")
            .expect("account hygiene");

        let text = match &accounts.action {
            Action::Manual { instructions } => instructions.join(" "),
            Action::Device(_) => String::new(),
        };
        assert!(text.contains("TAN"), "got: {text}");
        assert!(text.contains("different device"), "got: {text}");
    }

    #[test]
    fn a_quiet_report_produces_no_actions_but_still_says_what_certainty_costs() {
        let plan = from_report(&report_with(vec![]));

        assert!(plan.steps.is_empty());
        assert!(
            plan.warnings.iter().any(|w| w.contains("factory reset")),
            "got: {:?}",
            plan.warnings
        );
        assert!(
            !plan.warnings.iter().any(|w| w.contains("evidence")),
            "an empty report should not warn about destroying evidence"
        );
    }

    #[test]
    fn a_finding_with_no_subject_produces_no_action() {
        let orphan = FindingBuilder::new("boot.not-verified", "t")
            .detail("d")
            .severity(Severity::High)
            .evidence(Evidence::new(
                SourceRef::new("a.txt"),
                TrustBasis::SelfReported,
                "x",
            ))
            .remediation("reflash-and-relock")
            .build()
            .unwrap();

        let plan = from_report(&report_with(vec![orphan]));
        assert!(plan.automatic().is_empty());
    }
}
