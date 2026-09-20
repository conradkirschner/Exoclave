//! A replaying [`Shell`] for tests and fixtures.
//!
//! Analysis modules are the part of this tool most likely to be wrong, and they
//! are the part hardest to exercise against real hardware. Capturing genuine
//! command output once and replaying it here lets the whole detection pipeline
//! run in CI, on a machine with no phone attached.

use crate::{AdbError, AdbResult, Shell};
use std::collections::BTreeMap;
use std::future::Future;

/// Replays canned output keyed by the space-joined argument vector.
///
/// ```text
/// let shell = FakeShell::new()
///     .with("shell getprop", "[ro.product.model]: [Pixel 9]\n");
/// let identity = Device::new(shell).identity("SERIAL").await?;
/// assert_eq!(identity.display_name(), "Pixel 9");
/// ```
#[derive(Debug, Default, Clone)]
pub struct FakeShell {
    responses: BTreeMap<String, Vec<String>>,
    /// Per-command call counter, so a sequence can advance. Shared across
    /// clones deliberately: a clone is the same fake device, not a fresh one.
    calls: std::sync::Arc<std::sync::Mutex<BTreeMap<String, usize>>>,
}

impl FakeShell {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register output for one invocation. `args` is the space-joined argument
    /// vector, e.g. `"shell pm list users"`. The same output is returned every
    /// time the command runs.
    #[must_use]
    pub fn with(mut self, args: &str, output: &str) -> Self {
        self.responses
            .insert(args.to_owned(), vec![output.to_owned()]);
        self
    }

    /// Register a sequence of outputs for repeated calls to one command, the
    /// last repeating once exhausted.
    ///
    /// Needed for read-modify-verify flows, which are the whole shape of
    /// cleanup: read the current value, write a new one, then read again to
    /// confirm it took. A fake that answered identically both times could not
    /// tell a successful change from one that silently did nothing — which is
    /// precisely the failure this tool has to catch.
    #[must_use]
    pub fn with_sequence(mut self, args: &str, outputs: &[&str]) -> Self {
        self.responses.insert(
            args.to_owned(),
            outputs.iter().map(|s| (*s).to_owned()).collect(),
        );
        self
    }

    /// Commands registered so far, for assertions about coverage.
    #[must_use]
    pub fn registered(&self) -> Vec<&str> {
        self.responses.keys().map(String::as_str).collect()
    }
}

impl Shell for FakeShell {
    // Not `async fn`: there is nothing to await, and clippy rightly objects to
    // an async function that never yields.
    fn exec(&self, args: Vec<String>) -> impl Future<Output = AdbResult<String>> + Send {
        let key = args.join(" ");

        let result = match self.responses.get(&key) {
            Some(outputs) => {
                let mut calls = match self.calls.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let seen = calls.entry(key.clone()).or_insert(0);
                // Past the end of the sequence, the last answer repeats.
                let index = (*seen).min(outputs.len().saturating_sub(1));
                *seen += 1;
                outputs.get(index).cloned().unwrap_or_default()
            }
            None => {
                return std::future::ready(Err(AdbError::CommandFailed {
                    status: 127,
                    stderr: format!(
                        "FakeShell has no response registered for `{key}`; registered: {:?}",
                        self.registered()
                    ),
                }));
            }
        };

        std::future::ready(Ok(result))
    }
}

/// Ready-made devices, for the demo mode and for cross-crate tests.
///
/// The output below is shaped like real `adb` output — including the awkward
/// parts, such as `=` inside APK paths and a work profile holding packages the
/// main user never sees. Package names are deliberately synthetic
/// (`com.demo.*`): these are illustrations, not indicators.
pub mod scenarios {
    use super::FakeShell;

    const GETPROP: &str = "[ro.product.manufacturer]: [Google]\n\
                           [ro.product.model]: [Pixel 8]\n\
                           [ro.build.version.release]: [16]\n\
                           [ro.build.version.sdk]: [36]\n\
                           [ro.build.version.security_patch]: [2026-08-01]\n\
                           [ro.build.fingerprint]: [google/shiba/shiba:16/BP3A.250805.014/13421211:user/release-keys]\n";

    /// A device with nothing wrong with it at app level.
    #[must_use]
    pub fn healthy() -> FakeShell {
        FakeShell::new()
            .with("shell getprop", GETPROP)
            .with("shell pm list users", "Users:\n\tUserInfo{0:Owner:c13} running\n")
            .with(
                "shell pm list packages -f -i -u --user 0",
                "package:/data/app/~~7Hq2==/com.android.chrome-Kd91==/base.apk=com.android.chrome  installer=com.android.vending\n\
                 package:/data/app/~~bB4z==/com.spotify.music-Pl32==/base.apk=com.spotify.music  installer=com.android.vending\n\
                 package:/data/app/~~mN8x==/com.x8bit.bitwarden-Qw77==/base.apk=com.x8bit.bitwarden  installer=com.android.vending\n",
            )
            .with(
                "shell settings get secure enabled_accessibility_services",
                "com.google.android.marvin.talkback/.TalkBackService\n",
            )
            .with(
                "shell settings get secure enabled_notification_listeners",
                "null\n",
            )
            .with("shell dumpsys device_policy", "Current Device Policy Manager state:\n")
            .with("shell getprop ro.boot.verifiedbootstate", "green\n")
    }

    /// A device showing the full range of app-tier problems: a known indicator
    /// hiding in a work profile, an unrecognised accessibility service, a
    /// device administrator resisting uninstall, notification access, sideloaded
    /// packages, and a bootloader that is no longer locked.
    #[must_use]
    pub fn compromised() -> FakeShell {
        FakeShell::new()
            .with("shell getprop", GETPROP)
            .with(
                "shell pm list users",
                "Users:\n\tUserInfo{0:Owner:c13} running\n\tUserInfo{10:Work profile:1030} running\n",
            )
            .with(
                "shell pm list packages -f -i -u --user 0",
                "package:/data/app/~~7Hq2==/com.android.chrome-Kd91==/base.apk=com.android.chrome  installer=com.android.vending\n\
                 package:/data/app/~~zX1p==/com.demo.batterysaver-Rt44==/base.apk=com.demo.batterysaver  installer=com.demo.filemanager\n\
                 package:/data/app/~~kK9w==/com.demo.filemanager-Yu21==/base.apk=com.demo.filemanager  installer=null\n\
                 package:/data/app/~~qQ3e==/com.demo.pdfreader-Zz09==/base.apk=com.demo.pdfreader  installer=null\n",
            )
            .with(
                "shell pm list packages -f -i -u --user 10",
                "package:/data/app/~~vV5t==/com.demo.trackerpro-Ab12==/base.apk=com.demo.trackerpro  installer=null\n",
            )
            .with(
                "shell settings get secure enabled_accessibility_services",
                "com.demo.trackerpro/.MonitorService:com.demo.batterysaver/.OptimiserService\n",
            )
            .with(
                "shell settings get secure enabled_notification_listeners",
                "com.demo.batterysaver/.NotificationCollector\n",
            )
            .with(
                "shell dumpsys device_policy",
                "Current Device Policy Manager state:\n  \
                 Device Admin:\n    \
                 admin=ComponentInfo{com.demo.trackerpro/com.demo.trackerpro.AdminReceiver}\n      \
                 uid=10287\n      \
                 policies:\n        \
                 limit-password\n        \
                 wipe-data\n",
            )
            .with("shell getprop ro.boot.verifiedbootstate", "orange\n")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[tokio::test]
    async fn unregistered_commands_fail_with_a_readable_message() {
        let shell = FakeShell::new().with("shell getprop", "");
        let err = shell
            .exec(vec!["shell".to_owned(), "whoami".to_owned()])
            .await
            .expect_err("should fail");

        let message = err.to_string();
        assert!(message.contains("shell whoami"), "got: {message}");
        assert!(message.contains("shell getprop"), "got: {message}");
    }
}
