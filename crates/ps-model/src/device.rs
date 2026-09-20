//! What we know about the device under examination.
//!
//! Every field here is *claimed* by the device unless it carries its own
//! provenance. The types keep that distinction visible: [`BootState`] read from
//! `getprop` and [`BootState`] read from an attestation certificate are the same
//! value with very different weight, so callers must pass the basis along.

use serde::{Deserialize, Serialize};

/// Identity of the examined device, as reported over ADB.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// ADB transport serial. Not a stable hardware identifier.
    pub serial: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    /// `ro.build.version.release`, e.g. `16`.
    pub android_release: Option<String>,
    /// `ro.build.version.sdk`, e.g. `36`.
    pub sdk: Option<u32>,
    /// `ro.build.version.security_patch`, e.g. `2026-08-01`.
    pub security_patch: Option<String>,
    pub build_fingerprint: Option<String>,
}

impl DeviceIdentity {
    /// A short label for the UI, degrading gracefully when properties are absent.
    #[must_use]
    pub fn display_name(&self) -> String {
        match (&self.manufacturer, &self.model) {
            (Some(vendor), Some(model)) => format!("{vendor} {model}"),
            (None, Some(model)) => model.clone(),
            (Some(vendor), None) => vendor.clone(),
            (None, None) => self.serial.clone(),
        }
    }
}

/// Verified Boot state.
///
/// Meaningful only together with the [`crate::trust::TrustBasis`] it was read
/// on: `getprop` can be rewritten by root, an attestation certificate cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootState {
    /// Locked bootloader, vendor-signed OS, dm-verity intact.
    Green,
    /// Locked bootloader, but a user-supplied root of trust.
    Yellow,
    /// Unlocked bootloader. Anything may have been flashed.
    Orange,
    /// Verification failed.
    Red,
    /// Property absent or unrecognised.
    Unknown,
}

impl BootState {
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "green" => Self::Green,
            "yellow" => Self::Yellow,
            "orange" => Self::Orange,
            "red" => Self::Red,
            _ => Self::Unknown,
        }
    }

    /// Whether this state is consistent with an untampered vendor OS.
    #[must_use]
    pub const fn is_nominal(self) -> bool {
        matches!(self, Self::Green)
    }
}

/// An installed package, as enumerated over ADB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    /// Application id, e.g. `com.example.app`.
    pub id: String,
    /// APK path on device, when `pm list packages -f` was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apk_path: Option<String>,
    /// Installing package, e.g. `com.android.vending` for Play. `None` means
    /// sideloaded or installed by a package that has since been removed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installer: Option<String>,
    /// Android user id the package belongs to. 0 is the primary user; a work
    /// profile or secondary user has a different id and is a common hiding place.
    pub user_id: u32,
    /// Present in the package database but not installed for this user —
    /// `pm list packages -u`. Traces of a removed app land here.
    pub uninstalled: bool,
}

impl Package {
    /// Whether the package came from the Play Store.
    #[must_use]
    pub fn is_from_play(&self) -> bool {
        self.installer.as_deref() == Some("com.android.vending")
    }

    /// Whether the package lives outside the primary user.
    #[must_use]
    pub const fn is_secondary_user(&self) -> bool {
        self.user_id != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_state_parsing_is_case_insensitive_and_total() {
        assert_eq!(BootState::parse("GREEN"), BootState::Green);
        assert_eq!(BootState::parse(" orange \n"), BootState::Orange);
        assert_eq!(BootState::parse("banana"), BootState::Unknown);
        assert!(BootState::Green.is_nominal());
        assert!(!BootState::Yellow.is_nominal());
    }

    #[test]
    fn display_name_degrades_without_properties() {
        let bare = DeviceIdentity {
            serial: "ABC123".into(),
            ..DeviceIdentity::default()
        };
        assert_eq!(bare.display_name(), "ABC123");

        let full = DeviceIdentity {
            serial: "ABC123".into(),
            manufacturer: Some("Google".into()),
            model: Some("Pixel 9".into()),
            ..DeviceIdentity::default()
        };
        assert_eq!(full.display_name(), "Google Pixel 9");
    }

    #[test]
    fn play_provenance_is_explicit() {
        let sideloaded = Package {
            id: "com.example".into(),
            apk_path: None,
            installer: None,
            user_id: 0,
            uninstalled: false,
        };
        assert!(!sideloaded.is_from_play());
        assert!(!sideloaded.is_secondary_user());
    }
}
