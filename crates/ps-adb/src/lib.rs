//! Typed access to a device over the Android Debug Bridge.
//!
//! Two design choices carry this crate:
//!
//! 1. **Everything goes through the [`Shell`] trait.** The real implementation
//!    spawns `adb`; [`fake::FakeShell`] replays canned output. Analysis modules
//!    are therefore testable against fixtures captured from real devices,
//!    without hardware in CI.
//!
//! 2. **Parsing lives in [`parse`], separate from I/O.** Android's command
//!    output is inconsistent across vendors and versions; that is where the
//!    bugs are, so that is what the tests target.
//!
//! Note on containers: a Linux container cannot claim a USB device on Windows
//! or macOS. Set `ADB_SERVER_SOCKET=tcp:host.docker.internal:5037` and this
//! crate talks to the ADB server running on the host instead, which needs no
//! USB passthrough.

pub mod devices;
pub mod fake;
pub mod parse;
pub mod proxy;

use ps_model::{BootState, DeviceIdentity, Package};
use std::future::Future;
use std::process::Stdio;
use tokio::process::Command;
use tracing::debug;

/// Failure modes when talking to a device.
#[derive(Debug, thiserror::Error)]
pub enum AdbError {
    #[error("could not run `{program}`: {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },

    #[error("adb exited with status {status}: {stderr}")]
    CommandFailed { status: i32, stderr: String },

    #[error("adb produced output that is not valid UTF-8")]
    NotUtf8,

    #[error("no device is connected, or it has not authorised this computer")]
    NoDevice,

    #[error("device is unauthorised: accept the USB debugging prompt on the phone")]
    Unauthorised,

    /// Writing a secure setting was refused.
    ///
    /// On stock Android, `adb shell` runs as `com.android.shell`, which holds
    /// `WRITE_SECURE_SETTINGS` — so this does not happen. Xiaomi layers an
    /// extra restriction on top, gated behind a Developer options toggle that
    /// wants a signed-in Mi account.
    #[error(
        "the phone refused to let this computer change a system setting. On Xiaomi, \
         enable Developer options \u{2192} \u{201c}USB debugging (Security settings)\u{201d}; \
         it needs a signed-in Mi account and a SIM in the phone"
    )]
    SecureSettingsDenied,

    #[error(
        "the proxy setting could not be cleared and is still {remaining}. The phone may \
         have no internet until it is. Run: adb shell settings put global http_proxy :0"
    )]
    ProxyNotCleared { remaining: String },
}

pub type AdbResult<T> = Result<T, AdbError>;

/// A transport that can run an `adb` invocation and return its stdout.
///
/// Implementors receive the arguments *after* the device selector, e.g.
/// `["shell", "getprop"]`.
pub trait Shell: Send + Sync {
    fn exec(&self, args: Vec<String>) -> impl Future<Output = AdbResult<String>> + Send;
}

/// Runs the real `adb` binary.
#[derive(Debug, Clone)]
pub struct ProcessShell {
    program: String,
    serial: Option<String>,
}

impl Default for ProcessShell {
    fn default() -> Self {
        Self {
            program: "adb".to_owned(),
            serial: None,
        }
    }
}

impl ProcessShell {
    /// Use a specific `adb` binary (or one found on `PATH` by default).
    #[must_use]
    pub fn with_program(mut self, program: impl Into<String>) -> Self {
        self.program = program.into();
        self
    }

    /// Target one device by serial. Required whenever more than one is attached.
    #[must_use]
    pub fn with_serial(mut self, serial: impl Into<String>) -> Self {
        self.serial = Some(serial.into());
        self
    }
}

impl Shell for ProcessShell {
    async fn exec(&self, args: Vec<String>) -> AdbResult<String> {
        let mut command = Command::new(&self.program);
        if let Some(serial) = &self.serial {
            command.arg("-s").arg(serial);
        }
        command.args(&args);
        command.stdin(Stdio::null());

        debug!(program = %self.program, ?args, "running adb");

        let output = command.output().await.map_err(|source| AdbError::Spawn {
            program: self.program.clone(),
            source,
        })?;

        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            return Err(classify_failure(
                output.status.code().unwrap_or(-1),
                &stderr,
            ));
        }

        let stdout = String::from_utf8(output.stdout).map_err(|_| AdbError::NotUtf8)?;
        Ok(normalise_newlines(&stdout))
    }
}

/// Map adb's stderr onto the two failures users actually hit, so the UI can
/// give an instruction rather than a stack trace.
fn classify_failure(status: i32, stderr: &str) -> AdbError {
    let lowered = stderr.to_ascii_lowercase();
    if lowered.contains("unauthorized") {
        AdbError::Unauthorised
    } else if lowered.contains("no devices") || lowered.contains("device not found") {
        AdbError::NoDevice
    } else {
        AdbError::CommandFailed {
            status,
            stderr: stderr.trim().to_owned(),
        }
    }
}

/// `adb shell` reports line endings as CRLF on many devices; normalise so
/// parsers only ever see `\n`.
fn normalise_newlines(raw: &str) -> String {
    raw.replace("\r\n", "\n")
}

/// High-level, typed queries against one device.
#[derive(Debug)]
pub struct Device<S: Shell> {
    shell: S,
}

impl<S: Shell> Device<S> {
    pub const fn new(shell: S) -> Self {
        Self { shell }
    }

    async fn shell_out(&self, command: &str) -> AdbResult<String> {
        self.shell
            .exec(vec!["shell".to_owned(), command.to_owned()])
            .await
    }

    /// Build properties, trimmed to the fields the report needs.
    pub async fn identity(&self, serial: impl Into<String>) -> AdbResult<DeviceIdentity> {
        let props = parse::getprop(&self.shell_out("getprop").await?);
        let get = |key: &str| {
            props
                .get(key)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };

        Ok(DeviceIdentity {
            serial: serial.into(),
            manufacturer: get("ro.product.manufacturer"),
            model: get("ro.product.model"),
            android_release: get("ro.build.version.release"),
            sdk: get("ro.build.version.sdk").and_then(|v| v.parse().ok()),
            security_patch: get("ro.build.version.security_patch"),
            build_fingerprint: get("ro.build.fingerprint"),
        })
    }

    /// Verified Boot state **as the device reports it**.
    ///
    /// Callers must record this as [`ps_model::TrustBasis::SelfReported`]: root
    /// can rewrite the property. Only an attestation certificate settles it.
    pub async fn claimed_boot_state(&self) -> AdbResult<BootState> {
        let raw = self.shell_out("getprop ro.boot.verifiedbootstate").await?;
        Ok(BootState::parse(&raw))
    }

    /// Android user ids present on the device, including work profiles.
    pub async fn user_ids(&self) -> AdbResult<Vec<u32>> {
        let out = self.shell_out("pm list users").await?;
        let ids = parse::user_ids(&out);
        Ok(if ids.is_empty() { vec![0] } else { ids })
    }

    /// Installed packages for one user, including ones only present as leftover
    /// records (`-u`), with APK path and installing package.
    pub async fn packages(&self, user_id: u32) -> AdbResult<Vec<Package>> {
        let out = self
            .shell_out(&format!("pm list packages -f -i -u --user {user_id}"))
            .await?;
        Ok(parse::packages(&out, user_id, false))
    }

    /// Packages across every user on the device. Secondary users and work
    /// profiles are a routine hiding place, so enumerating only user 0 is a
    /// common and costly mistake.
    pub async fn all_packages(&self) -> AdbResult<Vec<Package>> {
        let mut all = Vec::new();
        for user in self.user_ids().await? {
            all.extend(self.packages(user).await?);
        }
        Ok(all)
    }

    /// Accessibility services the user has enabled. The primary mechanism for
    /// overlay attacks, keylogging and remote control.
    pub async fn accessibility_services(&self) -> AdbResult<Vec<parse::ComponentName>> {
        let out = self
            .shell_out("settings get secure enabled_accessibility_services")
            .await?;
        Ok(parse::component_list(&out))
    }

    /// Apps allowed to read every notification, which includes one-time codes.
    pub async fn notification_listeners(&self) -> AdbResult<Vec<parse::ComponentName>> {
        let out = self
            .shell_out("settings get secure enabled_notification_listeners")
            .await?;
        Ok(parse::component_list(&out))
    }

    /// Active device administrators. Malware uses these to resist uninstall.
    pub async fn device_admins(&self) -> AdbResult<Vec<parse::ComponentName>> {
        let out = self.shell_out("dumpsys device_policy").await?;
        Ok(parse::device_admins(&out))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use fake::FakeShell;

    #[test]
    fn crlf_is_normalised_before_parsing() {
        assert_eq!(normalise_newlines("a\r\nb\r\n"), "a\nb\n");
    }

    #[test]
    fn stderr_is_classified_into_actionable_errors() {
        assert!(matches!(
            classify_failure(1, "error: device unauthorized."),
            AdbError::Unauthorised
        ));
        assert!(matches!(
            classify_failure(1, "error: no devices/emulators found"),
            AdbError::NoDevice
        ));
        assert!(matches!(
            classify_failure(1, "something else"),
            AdbError::CommandFailed { .. }
        ));
    }

    #[tokio::test]
    async fn identity_is_assembled_from_build_properties() {
        let shell = FakeShell::new().with(
            "shell getprop",
            "[ro.product.manufacturer]: [Google]\n\
             [ro.product.model]: [Pixel 9]\n\
             [ro.build.version.sdk]: [36]\n\
             [ro.build.version.security_patch]: [2026-08-01]\n",
        );
        let device = Device::new(shell);

        let identity = device.identity("SERIAL1").await.expect("identity");
        assert_eq!(identity.display_name(), "Google Pixel 9");
        assert_eq!(identity.sdk, Some(36));
        assert_eq!(identity.security_patch.as_deref(), Some("2026-08-01"));
        assert_eq!(identity.android_release, None);
    }

    #[tokio::test]
    async fn packages_are_collected_across_every_user() {
        let shell = FakeShell::new()
            .with(
                "shell pm list users",
                "Users:\n\tUserInfo{0:Owner:c13} running\n\tUserInfo{10:Work:30} running\n",
            )
            .with(
                "shell pm list packages -f -i -u --user 0",
                "package:/data/app/a/base.apk=com.primary\n",
            )
            .with(
                "shell pm list packages -f -i -u --user 10",
                "package:/data/app/b/base.apk=com.work\n",
            );
        let device = Device::new(shell);

        let packages = device.all_packages().await.expect("packages");
        assert_eq!(packages.len(), 2);
        assert!(
            packages
                .iter()
                .any(|p| p.id == "com.work" && p.user_id == 10)
        );
    }

    #[tokio::test]
    async fn a_device_with_no_user_list_still_yields_the_primary_user() {
        let device = Device::new(FakeShell::new().with("shell pm list users", ""));
        assert_eq!(device.user_ids().await.expect("users"), vec![0]);
    }
}
