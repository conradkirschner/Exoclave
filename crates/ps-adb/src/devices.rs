//! Enumerating attached devices.
//!
//! The types live in [`ps_model`] so the interface can reason about connection
//! state without depending on an ADB implementation; the parsing lives here,
//! next to the command whose output it is coupled to.

use crate::{AdbResult, Shell};
use ps_model::{DeviceEntry, DeviceState};

fn parse_state(raw: &str) -> DeviceState {
    match raw.trim() {
        "device" => DeviceState::Ready,
        "unauthorized" => DeviceState::Unauthorized,
        // `authorizing` and `connecting` are transient; treating them as
        // offline gives the user the right instruction (replug and wait)
        // rather than a state name that means nothing to them.
        "offline" | "connecting" | "authorizing" => DeviceState::Offline,
        other => DeviceState::Unavailable(other.to_owned()),
    }
}

/// Parse `adb devices -l` output.
///
/// Lines look like:
/// ```text
/// List of devices attached
/// 1234ABCD        device product:venus model:Mi_11 device:venus transport_id:1
/// 5678EFGH        unauthorized
/// ```
#[must_use]
pub fn parse_device_list(output: &str) -> Vec<DeviceEntry> {
    output
        .lines()
        // Everything before the header is daemon chatter, and must not be
        // mistaken for a device.
        .skip_while(|line| !line.contains("List of devices"))
        .skip(1)
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let mut parts = line.split_whitespace();
            let serial = parts.next()?;
            let state = parts.next()?;

            let model = parts
                .find_map(|field| field.strip_prefix("model:"))
                .filter(|m| !m.is_empty())
                .map(ToOwned::to_owned);

            Some(DeviceEntry {
                serial: serial.to_owned(),
                state: parse_state(state),
                model,
            })
        })
        .collect()
}

/// Ask adb which devices are attached.
pub async fn list<S: Shell>(shell: &S) -> AdbResult<Vec<DeviceEntry>> {
    let output = shell
        .exec(vec!["devices".to_owned(), "-l".to_owned()])
        .await?;
    Ok(parse_device_list(&output))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::fake::FakeShell;

    #[test]
    fn a_ready_device_is_parsed_with_its_model() {
        let out = "List of devices attached\n\
                   1234ABCD       device product:venus model:Mi_11 device:venus transport_id:1\n";
        let devices = parse_device_list(out);

        let device = devices.first().expect("one device");
        assert_eq!(device.serial, "1234ABCD");
        assert_eq!(device.state, DeviceState::Ready);
        assert_eq!(device.display_name(), "Mi 11");
        assert!(device.state.is_scannable());
        assert!(device.state.next_step().is_none());
    }

    #[test]
    fn an_unauthorised_device_is_reported_with_the_action_that_fixes_it() {
        let out = "List of devices attached\n5678EFGH\tunauthorized\n";
        let devices = parse_device_list(out);

        let device = devices.first().expect("one device");
        assert_eq!(device.state, DeviceState::Unauthorized);
        assert!(!device.state.is_scannable());
        // Falls back to the serial: an unauthorised device tells us nothing.
        assert_eq!(device.display_name(), "5678EFGH");

        let step = device.state.next_step().expect("an instruction");
        assert!(step.contains("Allow USB debugging"));
    }

    #[test]
    fn unusual_modes_are_kept_verbatim_rather_than_lumped_into_offline() {
        let devices = parse_device_list("List of devices attached\nXYZ  recovery\n");

        assert_eq!(
            devices.first().map(|d| d.state.clone()),
            Some(DeviceState::Unavailable("recovery".to_owned()))
        );
        assert!(
            devices
                .first()
                .map(|d| d.state.summary())
                .unwrap_or_default()
                .contains("recovery")
        );
    }

    #[test]
    fn an_empty_list_is_not_an_error() {
        assert!(parse_device_list("List of devices attached\n\n").is_empty());
        assert!(parse_device_list("").is_empty());
    }

    #[test]
    fn daemon_chatter_before_the_header_is_ignored() {
        let out = "* daemon not running; starting now at tcp:5037\n\
                   * daemon started successfully\n\
                   List of devices attached\n\
                   1234ABCD       device model:Mi_11\n";
        let devices = parse_device_list(out);

        assert_eq!(devices.len(), 1, "daemon lines must not parse as devices");
        assert_eq!(devices.first().map(|d| d.serial.as_str()), Some("1234ABCD"));
    }

    #[tokio::test]
    async fn listing_goes_through_the_shell() {
        let shell = FakeShell::new().with(
            "devices -l",
            "List of devices attached\n1234ABCD  device model:Mi_11\n",
        );
        assert_eq!(list(&shell).await.expect("list").len(), 1);
    }
}
