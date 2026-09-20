//! Carrying out one confirmed step, and checking that it actually happened.
//!
//! Every action verifies itself afterwards by re-reading the device. Android's
//! shell tools are cheerfully unreliable about failure: `pm uninstall` reports
//! `Failure` on stdout with a zero exit status, and `settings put` does the
//! same for a permission denial. Trusting the exit code would mean telling
//! someone their phone was cleaned when nothing happened — which is worse than
//! failing loudly.

use crate::plan::DeviceAction;
use ps_adb::{AdbError, AdbResult, Shell, parse};
use tracing::debug;

/// What happened when a step ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Carried out, and confirmed by re-reading the device.
    Done,
    /// Nothing to do — it was already in the desired state.
    AlreadyDone,
    /// The device refused. The string is shown to the user as-is.
    Refused(String),
}

/// Carry out one action.
///
/// # Errors
/// If the device cannot be reached. A refusal by the device is an [`Outcome`],
/// not an error: it is an answer, and the user needs to see it.
pub async fn run<S: Shell>(shell: &S, action: &DeviceAction) -> AdbResult<Outcome> {
    debug!(?action, "carrying out cleanup step");
    match action {
        DeviceAction::RevokeAccessibility { component, .. } => {
            revoke_component(shell, "enabled_accessibility_services", component, true).await
        }
        DeviceAction::RevokeNotificationAccess { component, .. } => {
            revoke_component(shell, "enabled_notification_listeners", component, false).await
        }
        DeviceAction::RemoveDeviceAdmin { component } => remove_admin(shell, component).await,
        DeviceAction::DisablePackage { package, user_id } => {
            disable(shell, package, *user_id).await
        }
        DeviceAction::UninstallPackage { package, user_id } => {
            uninstall(shell, package, *user_id).await
        }
    }
}

async fn shell_out<S: Shell>(shell: &S, command: String) -> AdbResult<String> {
    shell.exec(vec!["shell".to_owned(), command]).await
}

/// Remove one component from a colon-separated secure setting.
///
/// `disable_master` also clears the master toggle when the list empties, which
/// accessibility needs: leaving `accessibility_enabled` at 1 with an empty
/// list is an inconsistent state that some builds repopulate from.
async fn revoke_component<S: Shell>(
    shell: &S,
    key: &str,
    component: &str,
    disable_master: bool,
) -> AdbResult<Outcome> {
    let current = shell_out(shell, format!("settings get secure {key}")).await?;
    let remaining: Vec<String> = parse::component_list(&current)
        .into_iter()
        .map(|c| c.to_string())
        .filter(|c| !c.eq_ignore_ascii_case(component))
        .collect();

    if remaining.len() == parse::component_list(&current).len() {
        return Ok(Outcome::AlreadyDone);
    }

    let value = remaining.join(":");
    let written = shell_out(shell, format!("settings put secure {key} '{value}'")).await?;

    if is_permission_denial(&written) {
        return Err(AdbError::SecureSettingsDenied);
    }

    if disable_master && remaining.is_empty() {
        let _ = shell_out(
            shell,
            "settings put secure accessibility_enabled 0".to_owned(),
        )
        .await;
    }

    // Verify by re-reading rather than trusting the write.
    let after = shell_out(shell, format!("settings get secure {key}")).await?;
    if parse::component_list(&after)
        .iter()
        .any(|c| c.to_string().eq_ignore_ascii_case(component))
    {
        return Ok(Outcome::Refused(format!(
            "{component} is still listed in {key} after the change."
        )));
    }

    Ok(Outcome::Done)
}

async fn remove_admin<S: Shell>(shell: &S, component: &str) -> AdbResult<Outcome> {
    let before = shell_out(shell, "dumpsys device_policy".to_owned()).await?;
    if !admin_present(&before, component) {
        return Ok(Outcome::AlreadyDone);
    }

    let out = shell_out(shell, format!("dpm remove-active-admin {component}")).await?;
    if is_permission_denial(&out) {
        return Err(AdbError::SecureSettingsDenied);
    }

    let after = shell_out(shell, "dumpsys device_policy".to_owned()).await?;
    if admin_present(&after, component) {
        return Ok(Outcome::Refused(format!(
            "{component} is still an active device administrator. Some apps can only be \
             removed from Settings, and a device owner cannot be removed at all without a \
             factory reset. Device output: {}",
            out.trim()
        )));
    }

    Ok(Outcome::Done)
}

fn admin_present(dump: &str, component: &str) -> bool {
    parse::device_admins(dump)
        .iter()
        .any(|c| c.to_string().eq_ignore_ascii_case(component))
}

async fn disable<S: Shell>(shell: &S, package: &str, user_id: u32) -> AdbResult<Outcome> {
    let out = shell_out(shell, format!("pm disable-user --user {user_id} {package}")).await?;

    // Verify against the disabled list rather than the command's own report.
    let disabled = shell_out(shell, format!("pm list packages -d --user {user_id}")).await?;
    if parse::packages(&disabled, user_id, false)
        .iter()
        .any(|p| p.id == package)
    {
        return Ok(Outcome::Done);
    }

    Ok(Outcome::Refused(format!(
        "{package} does not appear as disabled afterwards. Device output: {}",
        out.trim()
    )))
}

async fn uninstall<S: Shell>(shell: &S, package: &str, user_id: u32) -> AdbResult<Outcome> {
    let out = shell_out(shell, format!("pm uninstall --user {user_id} {package}")).await?;

    let installed = shell_out(shell, format!("pm list packages --user {user_id}")).await?;
    if parse::packages(&installed, user_id, false)
        .iter()
        .any(|p| p.id == package)
    {
        return Ok(Outcome::Refused(format!(
            "{package} is still installed. An active device administrator will block \
             removal, so revoke that first. Device output: {}",
            out.trim()
        )));
    }

    Ok(Outcome::Done)
}

fn is_permission_denial(output: &str) -> bool {
    output.contains("Permission denial") || output.contains("SecurityException")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use ps_adb::fake::FakeShell;

    #[tokio::test]
    async fn revoking_accessibility_writes_back_only_the_other_services() {
        let shell = FakeShell::new()
            // First read shows both services; the verification read afterwards
            // shows only the legitimate one.
            .with_sequence(
                "shell settings get secure enabled_accessibility_services",
                &[
                    "com.good/com.good.Svc:com.bad.spy/com.bad.spy.Service\n",
                    "com.good/com.good.Svc\n",
                ],
            )
            // Only the exact expected write is registered, so writing anything
            // else — including clobbering the legitimate service — fails here.
            .with(
                "shell settings put secure enabled_accessibility_services 'com.good/com.good.Svc'",
                "",
            );

        let outcome = run(
            &shell,
            &DeviceAction::RevokeAccessibility {
                component: "com.bad.spy/com.bad.spy.Service".to_owned(),
                user_id: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(outcome, Outcome::Done);
    }

    #[tokio::test]
    async fn revoking_something_not_present_is_not_an_error() {
        let shell = FakeShell::new().with(
            "shell settings get secure enabled_accessibility_services",
            "com.good/com.good.Svc\n",
        );

        let outcome = run(
            &shell,
            &DeviceAction::RevokeAccessibility {
                component: "com.absent/com.absent.Svc".to_owned(),
                user_id: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(outcome, Outcome::AlreadyDone);
    }

    #[tokio::test]
    async fn a_write_that_silently_failed_is_reported_as_refused_not_done() {
        let shell = FakeShell::new()
            .with(
                "shell settings get secure enabled_notification_listeners",
                "com.bad.spy/com.bad.spy.Listener\n",
            )
            .with(
                "shell settings put secure enabled_notification_listeners ''",
                "",
            );
        // The verification read still shows it: the write did nothing.

        let outcome = run(
            &shell,
            &DeviceAction::RevokeNotificationAccess {
                component: "com.bad.spy/com.bad.spy.Listener".to_owned(),
                user_id: 0,
            },
        )
        .await
        .unwrap();

        assert!(
            matches!(outcome, Outcome::Refused(_)),
            "a write that did not take must never report success; got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn a_permission_denial_surfaces_the_xiaomi_toggle() {
        let shell = FakeShell::new()
            .with(
                "shell settings get secure enabled_accessibility_services",
                "com.bad.spy/com.bad.spy.Service\n",
            )
            .with(
                "shell settings put secure enabled_accessibility_services ''",
                "java.lang.SecurityException: Permission denial: writing to settings\n",
            );

        let error = run(
            &shell,
            &DeviceAction::RevokeAccessibility {
                component: "com.bad.spy/com.bad.spy.Service".to_owned(),
                user_id: 0,
            },
        )
        .await
        .expect_err("should fail");

        assert!(matches!(error, AdbError::SecureSettingsDenied));
    }

    #[tokio::test]
    async fn an_uninstall_blocked_by_a_device_admin_is_reported_with_the_cause() {
        let shell = FakeShell::new()
            .with(
                "shell pm uninstall --user 0 com.bad.spy",
                "Failure [DELETE_FAILED_DEVICE_POLICY_MANAGER]\n",
            )
            .with("shell pm list packages --user 0", "package:com.bad.spy\n");

        let outcome = run(
            &shell,
            &DeviceAction::UninstallPackage {
                package: "com.bad.spy".to_owned(),
                user_id: 0,
            },
        )
        .await
        .unwrap();

        match outcome {
            Outcome::Refused(message) => {
                assert!(message.contains("device administrator"), "got: {message}");
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn disabling_is_confirmed_against_the_disabled_list() {
        let shell = FakeShell::new()
            .with("shell pm disable-user --user 0 com.bad.spy", "")
            .with(
                "shell pm list packages -d --user 0",
                "package:com.bad.spy\n",
            );

        let outcome = run(
            &shell,
            &DeviceAction::DisablePackage {
                package: "com.bad.spy".to_owned(),
                user_id: 0,
            },
        )
        .await
        .unwrap();

        assert_eq!(outcome, Outcome::Done);
    }

    #[tokio::test]
    async fn a_device_owner_that_refuses_removal_says_what_it_costs_to_fix() {
        let dump = "admin=ComponentInfo{com.bad.spy/com.bad.spy.Admin}\n";
        let shell = FakeShell::new()
            .with("shell dumpsys device_policy", dump)
            .with(
                "shell dpm remove-active-admin com.bad.spy/com.bad.spy.Admin",
                "Error: Attempt to remove non-test admin\n",
            );

        let outcome = run(
            &shell,
            &DeviceAction::RemoveDeviceAdmin {
                component: "com.bad.spy/com.bad.spy.Admin".to_owned(),
            },
        )
        .await
        .unwrap();

        match outcome {
            Outcome::Refused(message) => {
                assert!(message.contains("factory reset"), "got: {message}");
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }
}
