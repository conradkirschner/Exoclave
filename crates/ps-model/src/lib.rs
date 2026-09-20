//! Core domain model for exoclave.
//!
//! The model is built around one rule: **a claim is only as strong as the
//! adversary that could not have forged it.**
//!
//! Mobile forensic tools generally collect what the device says about itself
//! and match it against indicators. That is exactly right for an ordinary
//! malicious app, which cannot rewrite `dumpsys` output — and worth nothing
//! against an implant with kernel privileges, which can rewrite all of it.
//! Tools that do not distinguish the two produce reports that read identically
//! in both cases.
//!
//! So every [`Evidence`] carries a [`TrustBasis`], every [`Finding`] inherits
//! the weakest basis among its evidence, and every [`Report`] carries an
//! explicit per-tier [`TierCoverage`] statement. The consequence is that this
//! crate has no way to express "the device is clean". The strongest negative
//! result it can represent is [`Verdict::NoIndicatorsFound`], which names the
//! tier it actually covered.
//!
//! ```
//! use ps_model::{ThreatTier, TrustBasis};
//!
//! // Anything the phone says about itself is forgeable by privileged code.
//! assert!(TrustBasis::SelfReported.is_credible_against(ThreatTier::AppLevel));
//! assert!(!TrustBasis::SelfReported.is_credible_against(ThreatTier::RuntimeKernel));
//!
//! // What our own access point saw is not.
//! assert!(TrustBasis::OutOfBand.is_credible_against(ThreatTier::RuntimeKernel));
//! ```

pub mod device;
pub mod finding;
pub mod report;
pub mod trust;

pub use device::{BootState, DeviceEntry, DeviceIdentity, DeviceState, Package};
pub use finding::{Confidence, Evidence, Finding, FindingBuilder, Severity, SourceRef};
pub use report::{CoverageStatus, FeedProvenance, Report, TierCoverage, Verdict};
pub use trust::{ThreatTier, TrustBasis};
