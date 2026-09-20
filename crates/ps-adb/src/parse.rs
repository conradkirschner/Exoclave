//! Pure parsers for ADB command output.
//!
//! Deliberately free of I/O so the tricky part — Android's inconsistent output
//! formats — is unit-testable without a device attached. Every parser here is
//! total: malformed input yields fewer results, never a panic.

use ps_model::Package;
use std::collections::BTreeMap;

/// An Android component reference, `package/class`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComponentName {
    pub package: String,
    pub class: String,
}

impl ComponentName {
    /// Parse `com.example.app/.SomeService` or `com.example.app/com.example.app.SomeService`.
    ///
    /// Returns `None` when there is no `/` separator or either side is empty.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let (package, class) = raw.trim().split_once('/')?;
        if package.is_empty() || class.is_empty() {
            return None;
        }
        // A leading dot is shorthand for "relative to the package".
        let class = if let Some(suffix) = class.strip_prefix('.') {
            format!("{package}.{suffix}")
        } else {
            class.to_owned()
        };
        Some(Self {
            package: package.to_owned(),
            class,
        })
    }
}

impl std::fmt::Display for ComponentName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.package, self.class)
    }
}

/// Parse `getprop` output, whose lines look like `[ro.build.version.sdk]: [36]`.
#[must_use]
pub fn getprop(output: &str) -> BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix('[')?;
            let (key, rest) = rest.split_once("]: [")?;
            let value = rest.strip_suffix(']')?;
            if key.is_empty() {
                return None;
            }
            Some((key.to_owned(), value.to_owned()))
        })
        .collect()
}

/// Parse `pm list packages` output, with or without `-f` (path) and `-i`
/// (installer).
///
/// Lines take the shape:
/// ```text
/// package:/data/app/~~aB==/com.example-Xy==/base.apk=com.example  installer=com.android.vending
/// package:com.example
/// ```
///
/// The APK path itself contains `=` characters, so the package name is taken
/// from the *last* `=` before the optional installer suffix.
#[must_use]
pub fn packages(output: &str, user_id: u32, uninstalled: bool) -> Vec<Package> {
    output
        .lines()
        .filter_map(|line| {
            let body = line.trim().strip_prefix("package:")?;
            if body.is_empty() {
                return None;
            }

            let (body, installer) = match body.split_once("installer=") {
                Some((head, tail)) => {
                    let installer = tail.split_whitespace().next().unwrap_or_default();
                    // `null` is how pm spells "no recorded installer".
                    let installer = match installer {
                        "" | "null" => None,
                        other => Some(other.to_owned()),
                    };
                    (head.trim_end(), installer)
                }
                None => (body, None),
            };

            // With -f the body is `<path>=<id>`; without it, just `<id>`.
            let (apk_path, id) = match body.rsplit_once('=') {
                Some((path, id)) if !path.is_empty() && !id.is_empty() => {
                    (Some(path.to_owned()), id)
                }
                _ => (None, body),
            };

            if id.is_empty() || id.contains(char::is_whitespace) {
                return None;
            }

            Some(Package {
                id: id.to_owned(),
                apk_path,
                installer,
                user_id,
                uninstalled,
            })
        })
        .collect()
}

/// Parse a colon-separated component list, the format used by several `settings
/// get secure` keys (`enabled_accessibility_services`,
/// `enabled_notification_listeners`).
///
/// Android returns the literal string `null` when the key is unset.
#[must_use]
pub fn component_list(output: &str) -> Vec<ComponentName> {
    let trimmed = output.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Vec::new();
    }
    trimmed
        .split(':')
        .filter_map(ComponentName::parse)
        .collect()
}

/// Extract active device-administrator components from `dumpsys device_policy`.
///
/// The dump is large and its shape varies by vendor and Android version; the
/// stable part is the `admin=ComponentInfo{pkg/cls}` line, which we anchor on
/// rather than trying to model the whole document.
#[must_use]
pub fn device_admins(output: &str) -> Vec<ComponentName> {
    let mut found: Vec<ComponentName> = output
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("admin=ComponentInfo{")?;
            let inner = rest.split_once('}').map_or(rest, |(head, _)| head);
            ComponentName::parse(inner)
        })
        .collect();
    found.sort();
    found.dedup();
    found
}

/// Parse `pm list users` output: `UserInfo{0:Owner:c13} running`.
#[must_use]
pub fn user_ids(output: &str) -> Vec<u32> {
    let mut ids: Vec<u32> = output
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("UserInfo{")?;
            let id = rest.split(':').next()?;
            id.parse::<u32>().ok()
        })
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn getprop_reads_bracketed_pairs_and_ignores_noise() {
        let out = "[ro.build.version.sdk]: [36]\n\
                   [ro.product.model]: [Pixel 9]\n\
                   [ro.empty]: []\n\
                   garbage line\n";
        let props = getprop(out);

        assert_eq!(
            props.get("ro.build.version.sdk").map(String::as_str),
            Some("36")
        );
        assert_eq!(
            props.get("ro.product.model").map(String::as_str),
            Some("Pixel 9")
        );
        assert_eq!(props.get("ro.empty").map(String::as_str), Some(""));
        assert_eq!(props.len(), 3);
    }

    #[test]
    fn package_name_survives_equals_signs_in_the_apk_path() {
        let out = "package:/data/app/~~kLm9==/com.example.app-Xy7Q==/base.apk=com.example.app";
        let parsed = packages(out, 0, false);

        let pkg = parsed.first().expect("one package");
        assert_eq!(pkg.id, "com.example.app");
        assert_eq!(
            pkg.apk_path.as_deref(),
            Some("/data/app/~~kLm9==/com.example.app-Xy7Q==/base.apk")
        );
    }

    #[test]
    fn installer_is_captured_and_null_becomes_none() {
        let out = "package:/data/app/a/base.apk=com.play.app  installer=com.android.vending\n\
                   package:/data/app/b/base.apk=com.side.app  installer=null\n";
        let parsed = packages(out, 0, false);

        let play = parsed.first().expect("play package");
        assert!(play.is_from_play());

        let side = parsed.get(1).expect("sideloaded package");
        assert_eq!(side.installer, None);
        assert!(!side.is_from_play());
    }

    #[test]
    fn bare_package_lines_parse_without_a_path() {
        let parsed = packages("package:com.example.app\n", 10, true);
        let pkg = parsed.first().expect("one package");

        assert_eq!(pkg.id, "com.example.app");
        assert_eq!(pkg.apk_path, None);
        assert_eq!(pkg.user_id, 10);
        assert!(pkg.uninstalled);
        assert!(pkg.is_secondary_user());
    }

    #[test]
    fn component_list_handles_null_and_relative_class_names() {
        assert!(component_list("null").is_empty());
        assert!(component_list("   ").is_empty());

        let parsed = component_list("com.example/.MyService:com.other/com.other.Svc");
        assert_eq!(
            parsed.first().map(ToString::to_string),
            Some("com.example/com.example.MyService".to_owned())
        );
        assert_eq!(
            parsed.get(1).map(ToString::to_string),
            Some("com.other/com.other.Svc".to_owned())
        );
    }

    #[test]
    fn device_admins_are_extracted_deduplicated_from_a_noisy_dump() {
        let dump = "Current Device Policy Manager state:\n  \
                    Device Admin: \n    \
                    admin=ComponentInfo{com.bad.app/com.bad.app.AdminReceiver}\n    \
                    uid=10234\n  \
                    admin=ComponentInfo{com.bad.app/com.bad.app.AdminReceiver}\n";
        let admins = device_admins(dump);

        assert_eq!(admins.len(), 1);
        assert_eq!(
            admins.first().map(ToString::to_string),
            Some("com.bad.app/com.bad.app.AdminReceiver".to_owned())
        );
    }

    #[test]
    fn user_ids_include_secondary_profiles() {
        let out =
            "Users:\n\tUserInfo{0:Owner:c13} running\n\tUserInfo{10:Work profile:1030} running\n";
        assert_eq!(user_ids(out), vec![0, 10]);
    }

    #[test]
    fn parsers_are_total_on_garbage() {
        assert!(packages("\u{0}\nnot a package\n", 0, false).is_empty());
        assert!(device_admins("admin=ComponentInfo{}").is_empty());
        assert!(component_list("/").is_empty());
        assert!(user_ids("UserInfo{notanumber:x}").is_empty());
    }
}
