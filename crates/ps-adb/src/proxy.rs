//! Pointing the device's traffic at a proxy on this computer, and — more
//! importantly — putting it back.
//!
//! Two facts from the Android source shape everything here.
//!
//! **`Settings.Global.HTTP_PROXY` is watched live.** `ConnectivityService`
//! registers a `ContentObserver` on exactly that key, so a write over adb
//! applies immediately with no reboot and no Wi-Fi toggle. It is also
//! network-independent: `getProxyForNetwork()` returns the global proxy before
//! it ever looks at a network's `LinkProperties`, so it covers Wi-Fi and
//! mobile data alike.
//!
//! **Clearing it is a trap.** `settings delete global http_proxy` looks like
//! the obvious undo and is actively wrong.
//! `ProxyTracker.loadDeprecatedGlobalHttpProxy()` guards its whole body on the
//! value being non-empty, so a deleted key leaves the old proxy live in
//! memory; and `setGlobalProxy()` has already persisted the host and port into
//! `global_http_proxy_host`/`_port`, which `loadGlobalProxy()` reads at the
//! next boot — so the proxy comes back from the dead. Writing the sentinel
//! `:0` takes the else-branch that actually clears `mGlobalProxy` and wipes
//! those backing keys.
//!
//! Getting this wrong would leave someone's phone pointed at a proxy that no
//! longer exists, with no internet and no obvious cause. So clearing is done
//! with `:0`, it is verified afterwards, and the manual command is surfaced to
//! the user if it ever fails.

use crate::{AdbError, AdbResult, Shell};

/// Default port for the tunnel, on both the device's loopback and this host.
///
/// Away from 8080 and 8888, which are commonly already in use.
pub const DEFAULT_TUNNEL_PORT: u16 = 8083;

/// The sentinel that genuinely clears a global proxy. See the module docs.
const CLEAR_SENTINEL: &str = ":0";

/// The command a user can run by hand if automatic cleanup ever fails.
pub const MANUAL_CLEAR_COMMAND: &str = "adb shell settings put global http_proxy :0";

/// Read the current global proxy, if one is set.
///
/// Android returns the literal string `null` when the key is unset.
pub async fn read<S: Shell>(shell: &S) -> AdbResult<Option<String>> {
    let out = shell
        .exec(vec![
            "shell".to_owned(),
            "settings get global http_proxy".to_owned(),
        ])
        .await?;

    let value = out.trim();
    if value.is_empty() || value == "null" || value == CLEAR_SENTINEL {
        return Ok(None);
    }
    Ok(Some(value.to_owned()))
}

/// Point the device at `host:port`.
pub async fn set<S: Shell>(shell: &S, host: &str, port: u16) -> AdbResult<()> {
    let out = shell
        .exec(vec![
            "shell".to_owned(),
            format!("settings put global http_proxy {host}:{port}"),
        ])
        .await?;

    check_secure_settings(&out)
}

/// Clear the global proxy.
///
/// Uses the `:0` sentinel rather than `settings delete`, for the reasons in
/// the module documentation.
pub async fn clear<S: Shell>(shell: &S) -> AdbResult<()> {
    let out = shell
        .exec(vec![
            "shell".to_owned(),
            format!("settings put global http_proxy {CLEAR_SENTINEL}"),
        ])
        .await?;

    check_secure_settings(&out)
}

/// Clear the proxy and confirm it actually went.
///
/// Worth the extra round trip: a silent failure here is the difference between
/// a working phone and one with no internet.
pub async fn clear_and_verify<S: Shell>(shell: &S) -> AdbResult<()> {
    clear(shell).await?;
    match read(shell).await? {
        None => Ok(()),
        Some(remaining) => Err(AdbError::ProxyNotCleared { remaining }),
    }
}

/// Open a reverse tunnel so the device's loopback port reaches this host.
///
/// `adb reverse tcp:<device> tcp:<host>`: adbd listens on the device's
/// loopback and forwards over USB. Because it is loopback rather than the
/// LAN, it keeps working when the phone is on mobile data.
pub async fn open_reverse<S: Shell>(shell: &S, port: u16) -> AdbResult<()> {
    shell
        .exec(vec![
            "reverse".to_owned(),
            format!("tcp:{port}"),
            format!("tcp:{port}"),
        ])
        .await
        .map(|_| ())
}

/// Remove the reverse tunnel again.
pub async fn close_reverse<S: Shell>(shell: &S, port: u16) -> AdbResult<()> {
    shell
        .exec(vec![
            "reverse".to_owned(),
            "--remove".to_owned(),
            format!("tcp:{port}"),
        ])
        .await
        .map(|_| ())
}

/// Whether a proxy value looks like one this tool left behind after a crash.
///
/// Only loopback addresses qualify: a proxy on the device's own loopback can
/// only have been put there by something tunnelling over adb, whereas a LAN or
/// public address may well be the user's own deliberate configuration, and
/// clearing that without asking would be rude.
#[must_use]
pub fn is_abandoned_tunnel(value: &str, port: u16) -> bool {
    let Some((host, set_port)) = value.rsplit_once(':') else {
        return false;
    };
    let loopback = matches!(host.trim(), "127.0.0.1" | "localhost" | "::1" | "[::1]");
    loopback && set_port.trim().parse::<u16>() == Ok(port)
}

/// `settings put` reports a permission failure on stdout while still exiting
/// zero, so the output has to be inspected rather than the status trusted.
fn check_secure_settings(output: &str) -> AdbResult<()> {
    if output.contains("Permission denial") || output.contains("WRITE_SECURE_SETTINGS") {
        return Err(AdbError::SecureSettingsDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::fake::FakeShell;

    #[tokio::test]
    async fn an_unset_proxy_reads_as_none() {
        for value in ["null\n", "", ":0\n"] {
            let shell = FakeShell::new().with("shell settings get global http_proxy", value);
            assert_eq!(read(&shell).await.unwrap(), None, "for {value:?}");
        }
    }

    #[tokio::test]
    async fn a_set_proxy_reads_back() {
        let shell =
            FakeShell::new().with("shell settings get global http_proxy", "127.0.0.1:8083\n");
        assert_eq!(
            read(&shell).await.unwrap().as_deref(),
            Some("127.0.0.1:8083")
        );
    }

    #[tokio::test]
    async fn clearing_writes_the_sentinel_and_never_deletes_the_key() {
        // Registering only the sentinel form means any other command — in
        // particular `settings delete` — fails the test loudly.
        let shell = FakeShell::new().with("shell settings put global http_proxy :0", "");
        assert!(clear(&shell).await.is_ok());
    }

    #[tokio::test]
    async fn clearing_is_verified_and_a_surviving_proxy_is_an_error() {
        let stubborn = FakeShell::new()
            .with("shell settings put global http_proxy :0", "")
            .with("shell settings get global http_proxy", "127.0.0.1:8083\n");

        let error = clear_and_verify(&stubborn).await.expect_err("should fail");
        assert!(matches!(error, AdbError::ProxyNotCleared { .. }));

        let obedient = FakeShell::new()
            .with("shell settings put global http_proxy :0", "")
            .with("shell settings get global http_proxy", "null\n");
        assert!(clear_and_verify(&obedient).await.is_ok());
    }

    #[tokio::test]
    async fn a_xiaomi_permission_denial_is_recognised_despite_a_zero_exit_status() {
        let shell = FakeShell::new().with(
            "shell settings put global http_proxy 127.0.0.1:8083",
            "Exception occurred while executing 'put':\n\
             java.lang.SecurityException: Permission denial: writing to settings requires:\
             android.permission.WRITE_SECURE_SETTINGS\n",
        );

        let error = set(&shell, "127.0.0.1", 8083)
            .await
            .expect_err("should fail");
        assert!(matches!(error, AdbError::SecureSettingsDenied));
        assert!(
            error.to_string().contains("Security settings"),
            "the error must name the toggle that fixes it; got: {error}"
        );
    }

    #[tokio::test]
    async fn the_reverse_tunnel_maps_the_device_loopback_to_this_host() {
        let shell = FakeShell::new().with("reverse tcp:8083 tcp:8083", "8083\n");
        assert!(open_reverse(&shell, 8083).await.is_ok());

        let remove = FakeShell::new().with("reverse --remove tcp:8083", "");
        assert!(close_reverse(&remove, 8083).await.is_ok());
    }

    #[test]
    fn only_a_loopback_proxy_on_our_port_counts_as_ours_to_clean_up() {
        assert!(is_abandoned_tunnel("127.0.0.1:8083", 8083));
        assert!(is_abandoned_tunnel("localhost:8083", 8083));
        assert!(is_abandoned_tunnel("[::1]:8083", 8083));

        // Someone else's deliberate configuration must be left alone.
        assert!(!is_abandoned_tunnel("192.168.1.50:8083", 8083));
        assert!(!is_abandoned_tunnel("proxy.corp.example:8080", 8083));
        assert!(!is_abandoned_tunnel("127.0.0.1:3128", 8083));
        assert!(!is_abandoned_tunnel("garbage", 8083));
    }
}
