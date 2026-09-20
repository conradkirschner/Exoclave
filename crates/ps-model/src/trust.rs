//! Threat tiers and the trust provenance of the data a finding rests on.
//!
//! This module encodes the central idea of the tool. Almost every mobile
//! forensics tool asks *"what does the device report?"*. That question is only
//! meaningful if you also know *"who could have forged that answer?"*.
//!
//! A banking trojan cannot edit `dumpsys` output. A kernel implant can. So the
//! same string, read from the same file, is strong evidence against one
//! adversary and worthless against another. We make that explicit in the type
//! system rather than in a footnote of the report.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The privilege level of the adversary a signal is being evaluated against.
///
/// Ordered by capability: a higher tier can do everything a lower tier can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatTier {
    /// An ordinary installed application. No root. Abuses Accessibility
    /// Services, overlays, notification listeners, device admin. This is where
    /// essentially all commercial stalkerware and every banking trojan lives.
    AppLevel,

    /// Privileged code with persistence on a writable partition — a system app,
    /// a Magisk-style module, an unlocked bootloader. Defeats the OS's own
    /// reporting but leaves the boot chain measurably different.
    PrivilegedPersistent,

    /// Root obtained at runtime through a kernel or driver exploit. Nothing on
    /// disk changes, so Verified Boot still reports green and hardware
    /// attestation still passes: those attest the *boot chain*, not the
    /// *running kernel*. Dies on reboot. Everything the OS says about itself is
    /// forgeable at this tier.
    RuntimeKernel,

    /// Compromise below the OS: bootloader, TEE, or signed firmware. Defeats
    /// hardware attestation itself. Out of reach of any host-side tool.
    BootChain,
}

impl ThreatTier {
    /// All tiers, weakest adversary first.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::AppLevel,
            Self::PrivilegedPersistent,
            Self::RuntimeKernel,
            Self::BootChain,
        ]
    }

    /// Short stable slug for report keys and UI routing.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::AppLevel => "app-level",
            Self::PrivilegedPersistent => "privileged-persistent",
            Self::RuntimeKernel => "runtime-kernel",
            Self::BootChain => "boot-chain",
        }
    }

    /// One line a non-specialist can act on.
    #[must_use]
    pub const fn plain_language(self) -> &'static str {
        match self {
            Self::AppLevel => {
                "A malicious app. Removed completely by a factory reset, and visible \
                 to normal inspection."
            }
            Self::PrivilegedPersistent => {
                "Malicious code embedded in the system, surviving a reset. Detectable \
                 through hardware attestation; removed by reflashing signed firmware."
            }
            Self::RuntimeKernel => {
                "Root obtained through an exploit after boot. The phone cannot be \
                 trusted to report on itself, but the implant does not survive a \
                 reboot."
            }
            Self::BootChain => {
                "Compromise beneath the operating system. No host-side tool can rule \
                 this in or out; it requires laboratory analysis."
            }
        }
    }
}

impl fmt::Display for ThreatTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// Where a piece of evidence came from, expressed as *who could have faked it*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustBasis {
    /// The device's own operating system told us. `pm list packages`,
    /// `dumpsys`, `getprop`, logcat, a bugreport. Authoritative against an app,
    /// meaningless against a kernel implant.
    SelfReported,

    /// A third party's records, read from that third party rather than from the
    /// phone: Google Play's server-side install history, a Takeout export, the
    /// account's device list. The phone cannot rewrite these after the fact.
    ServerSide,

    /// A certificate chain signed inside the TEE or `StrongBox` and verified
    /// against the vendor root on the host. Unforgeable by a compromised
    /// kernel — but it attests the boot chain only, so it answers a narrow
    /// question very well and most questions not at all.
    HardwareAttested,

    /// Observed by equipment the phone does not control — our own access point,
    /// resolver and capture. An implant can change its behaviour, but it cannot
    /// edit our record of what crossed the wire.
    OutOfBand,

    /// Two independent sources were compared and *disagreed*. This is the only
    /// basis that can implicate an adversary above the tier that produced the
    /// data, because the contradiction itself is the artifact.
    Contradiction,
}

impl TrustBasis {
    /// The lowest adversary tier capable of forging evidence on this basis.
    ///
    /// `None` means no tier in our model can forge it.
    #[must_use]
    pub const fn forgeable_by(self) -> Option<ThreatTier> {
        match self {
            // An app cannot rewrite dumpsys; privileged persistent code and
            // anything above it can.
            Self::SelfReported => Some(ThreatTier::PrivilegedPersistent),
            // Rewriting a third party's server-side records requires
            // compromising that third party, which is outside this model.
            Self::ServerSide | Self::OutOfBand | Self::Contradiction => None,
            // Attestation is rooted in hardware the kernel cannot reach.
            Self::HardwareAttested => Some(ThreatTier::BootChain),
        }
    }

    /// Whether evidence on this basis still means something against `tier`.
    #[must_use]
    pub fn is_credible_against(self, tier: ThreatTier) -> bool {
        match self.forgeable_by() {
            Some(forger) => tier < forger,
            None => true,
        }
    }

    /// Human-readable caveat to print next to any finding using this basis.
    #[must_use]
    pub const fn caveat(self) -> &'static str {
        match self {
            Self::SelfReported => {
                "Reported by the device itself. Code with system privileges could \
                 have altered this answer."
            }
            Self::ServerSide => "Read from a third party's records rather than from the device.",
            Self::HardwareAttested => {
                "Signed inside the device's secure element. Covers the boot chain \
                 only — it cannot detect an exploit that gained root after boot."
            }
            Self::OutOfBand => {
                "Observed independently of the device. The device cannot alter this \
                 record."
            }
            Self::Contradiction => {
                "Two independent sources disagree. The disagreement is itself the \
                 evidence."
            }
        }
    }
}

impl fmt::Display for TrustBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SelfReported => "self-reported",
            Self::ServerSide => "server-side",
            Self::HardwareAttested => "hardware-attested",
            Self::OutOfBand => "out-of-band",
            Self::Contradiction => "contradiction",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_are_ordered_by_capability() {
        assert!(ThreatTier::AppLevel < ThreatTier::PrivilegedPersistent);
        assert!(ThreatTier::PrivilegedPersistent < ThreatTier::RuntimeKernel);
        assert!(ThreatTier::RuntimeKernel < ThreatTier::BootChain);
    }

    #[test]
    fn self_reported_data_is_credible_only_against_apps() {
        let basis = TrustBasis::SelfReported;
        assert!(basis.is_credible_against(ThreatTier::AppLevel));
        assert!(!basis.is_credible_against(ThreatTier::PrivilegedPersistent));
        assert!(!basis.is_credible_against(ThreatTier::RuntimeKernel));
    }

    #[test]
    fn attestation_survives_a_kernel_implant_but_not_the_boot_chain() {
        let basis = TrustBasis::HardwareAttested;
        assert!(basis.is_credible_against(ThreatTier::RuntimeKernel));
        assert!(!basis.is_credible_against(ThreatTier::BootChain));
    }

    #[test]
    fn out_of_band_observation_cannot_be_forged_by_the_device() {
        for tier in ThreatTier::all() {
            assert!(TrustBasis::OutOfBand.is_credible_against(tier));
            assert!(TrustBasis::Contradiction.is_credible_against(tier));
        }
    }
}
