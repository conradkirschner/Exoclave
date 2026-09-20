//! What a run managed to collect, and what it did not.
//!
//! Collection is allowed to partially fail — an old device may not implement a
//! command, a vendor may rename a dumpsys section — and a partial run is still
//! worth analysing. But a missing input must never look like a negative
//! result, so every field records whether it was collected, and the failures
//! are carried through into the coverage statement rather than logged and
//! forgotten.

use ps_adb::{Device, Shell, parse::ComponentName};
use ps_model::{BootState, DeviceIdentity, Package};

/// A value that may not have been collectable, with the reason.
#[derive(Debug, Clone)]
pub enum Observed<T> {
    Present(T),
    Missing { reason: String },
}

impl<T> Observed<T> {
    #[must_use]
    pub const fn get(&self) -> Option<&T> {
        match self {
            Self::Present(value) => Some(value),
            Self::Missing { .. } => None,
        }
    }

    #[must_use]
    pub const fn is_present(&self) -> bool {
        matches!(self, Self::Present(_))
    }

    #[must_use]
    pub fn missing_reason(&self) -> Option<&str> {
        match self {
            Self::Present(_) => None,
            Self::Missing { reason } => Some(reason.as_str()),
        }
    }

    fn from_result<E: std::fmt::Display>(result: Result<T, E>) -> Self {
        match result {
            Ok(value) => Self::Present(value),
            Err(error) => Self::Missing {
                reason: error.to_string(),
            },
        }
    }
}

/// Everything one acquisition run gathered from the device.
///
/// Every field here is [`ps_model::TrustBasis::SelfReported`]: it is the
/// device's account of itself. Sources that do not have that weakness —
/// attestation certificates, network capture, Google's server-side records —
/// arrive through other types, and comparing them against this is where
/// contradiction detection happens.
#[derive(Debug, Clone)]
pub struct Observations {
    pub identity: DeviceIdentity,
    pub packages: Observed<Vec<Package>>,
    pub accessibility_services: Observed<Vec<ComponentName>>,
    pub notification_listeners: Observed<Vec<ComponentName>>,
    pub device_admins: Observed<Vec<ComponentName>>,
    pub claimed_boot_state: Observed<BootState>,
}

impl Observations {
    /// Run every collector against a device, tolerating individual failures.
    ///
    /// # Errors
    /// Only identity collection is fatal: without it there is no device to
    /// report on.
    pub async fn collect<S: Shell>(
        device: &Device<S>,
        serial: &str,
    ) -> Result<Self, ps_adb::AdbError> {
        let identity = device.identity(serial).await?;

        Ok(Self {
            identity,
            packages: Observed::from_result(device.all_packages().await),
            accessibility_services: Observed::from_result(device.accessibility_services().await),
            notification_listeners: Observed::from_result(device.notification_listeners().await),
            device_admins: Observed::from_result(device.device_admins().await),
            claimed_boot_state: Observed::from_result(device.claimed_boot_state().await),
        })
    }

    /// Packages indexed for lookup by application id, across all users.
    #[must_use]
    pub fn package_ids(&self) -> Vec<&str> {
        self.packages
            .get()
            .map(|pkgs| pkgs.iter().map(|p| p.id.as_str()).collect())
            .unwrap_or_default()
    }

    /// Inputs that could not be collected, for the coverage statement.
    #[must_use]
    pub fn collection_gaps(&self) -> Vec<(&'static str, &str)> {
        [
            ("packages", self.packages.missing_reason()),
            (
                "accessibility services",
                self.accessibility_services.missing_reason(),
            ),
            (
                "notification listeners",
                self.notification_listeners.missing_reason(),
            ),
            ("device admins", self.device_admins.missing_reason()),
            ("boot state", self.claimed_boot_state.missing_reason()),
        ]
        .into_iter()
        .filter_map(|(name, reason)| reason.map(|reason| (name, reason)))
        .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use ps_adb::fake::FakeShell;

    fn shell_with_everything() -> FakeShell {
        FakeShell::new()
            .with("shell getprop", "[ro.product.model]: [Pixel 9]\n")
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

    #[tokio::test]
    async fn a_complete_run_reports_no_gaps() {
        let device = Device::new(shell_with_everything());
        let obs = Observations::collect(&device, "SERIAL").await.unwrap();

        assert!(obs.collection_gaps().is_empty());
        assert_eq!(obs.package_ids(), vec!["com.example"]);
        assert_eq!(obs.claimed_boot_state.get(), Some(&BootState::Green));
    }

    #[tokio::test]
    async fn a_failed_collector_becomes_a_named_gap_not_a_negative_result() {
        // Everything present except the device admin dump.
        let shell = FakeShell::new()
            .with("shell getprop", "[ro.product.model]: [Pixel 9]\n")
            .with("shell pm list users", "UserInfo{0:Owner:c13} running\n")
            .with("shell pm list packages -f -i -u --user 0", "")
            .with(
                "shell settings get secure enabled_accessibility_services",
                "null\n",
            )
            .with(
                "shell settings get secure enabled_notification_listeners",
                "null\n",
            )
            .with("shell getprop ro.boot.verifiedbootstate", "green\n");

        let device = Device::new(shell);
        let obs = Observations::collect(&device, "SERIAL").await.unwrap();

        let gaps = obs.collection_gaps();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps.first().map(|(name, _)| *name), Some("device admins"));
        assert!(!obs.device_admins.is_present());
    }

    #[tokio::test]
    async fn identity_failure_is_fatal() {
        let device = Device::new(FakeShell::new());
        assert!(Observations::collect(&device, "SERIAL").await.is_err());
    }
}
