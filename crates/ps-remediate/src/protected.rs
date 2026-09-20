//! Packages this tool refuses to touch automatically.
//!
//! Indicator feeds are third-party data on a network path. A wrong or poisoned
//! entry naming `com.android.systemui` must not turn into `pm uninstall`
//! against someone's phone. So the denylist is checked *after* a finding has
//! already named a package — belt and braces — and a protected package is not
//! dropped from the plan but demoted to a manual step with an explanation.
//!
//! The rule is deliberately blunt. A false negative here means a user removes
//! something by hand; a false positive means a bricked phone.

/// Exact package names that are never acted on automatically.
const PROTECTED_EXACT: &[&str] = &[
    "android",
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.google.android.packageinstaller",
    "com.google.android.permissioncontroller",
    "com.google.android.webview",
];

/// Package prefixes that are never acted on automatically: the platform, and
/// the system surfaces of the vendors this tool is most likely to meet.
const PROTECTED_PREFIXES: &[&str] = &[
    "com.android.",
    "com.google.android.apps.nexuslauncher",
    // Xiaomi
    "com.miui.",
    "com.xiaomi.",
    // Samsung
    "com.samsung.android.",
    "com.sec.android.",
    // Oppo / Realme / OnePlus share a platform layer
    "com.oppo.",
    "com.oplus.",
    "com.coloros.",
    "com.realme.",
    // Huawei
    "com.huawei.",
];

/// Whether a package is off-limits to automatic action.
#[must_use]
pub fn is_protected(package: &str) -> bool {
    let package = package.trim();
    PROTECTED_EXACT.contains(&package) || PROTECTED_PREFIXES.iter().any(|p| package.starts_with(p))
}

/// Why a protected package is handled by hand, phrased for the user.
#[must_use]
pub fn protection_reason(package: &str) -> String {
    format!(
        "`{package}` looks like part of the operating system or the manufacturer's own \
         software. Removing it automatically could stop the phone working, so Exoclave \
         will not do it. If you are confident this is malicious, remove it yourself and \
         be ready to reflash the phone."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_and_vendor_packages_are_protected() {
        for package in [
            "android",
            "com.android.systemui",
            "com.android.settings",
            "com.google.android.gms",
            "com.miui.securitycenter",
            "com.samsung.android.dialer",
            "com.coloros.safecenter",
            "com.huawei.systemmanager",
        ] {
            assert!(is_protected(package), "{package} should be protected");
        }
    }

    #[test]
    fn ordinary_applications_are_not_protected() {
        for package in [
            "com.demo.trackerpro",
            "com.topspy",
            "com.whatsapp",
            "org.thoughtcrime.securesms",
        ] {
            assert!(!is_protected(package), "{package} should not be protected");
        }
    }

    #[test]
    fn a_lookalike_does_not_slip_past_the_prefix_rule() {
        // Not the platform: no trailing dot, so it is a different namespace.
        assert!(!is_protected("com.androidmalware.spy"));
        // But the real platform prefix still matches.
        assert!(is_protected("com.android.malicious.injected"));
    }

    #[test]
    fn the_reason_names_the_package_and_the_risk() {
        let reason = protection_reason("com.android.systemui");
        assert!(reason.contains("com.android.systemui"));
        assert!(reason.contains("reflash"));
    }
}
