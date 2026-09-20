//! What was observed crossing the wire.
//!
//! This is the only evidence in the whole tool that a compromised operating
//! system cannot edit. Everything collected over ADB is the device's own
//! account of itself; a packet that left the phone and arrived at equipment we
//! control is a fact about the world.
//!
//! That asymmetry cuts one way only, and the types here are shaped to keep it
//! honest. **Traffic we saw is evidence. Traffic we did not see proves
//! nothing** — the observation path may simply have been bypassed. So an
//! [`ObservationSet`] records how complete it believes itself to be, and a
//! silent capture is never reported as a quiet device.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How a destination was learned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservedVia {
    /// An HTTP `CONNECT` tunnel. The hostname is in cleartext even though the
    /// payload is not, which is what makes a proxy useful without any attempt
    /// at interception.
    TlsTunnel,
    /// A plaintext HTTP request, so the full URL was visible.
    PlainHttp,
    /// A DNS query answered by a resolver we control.
    DnsQuery,
    /// A TLS `ClientHello` read from captured packets.
    TlsClientHello,
}

impl ObservedVia {
    #[must_use]
    pub const fn describes(self) -> &'static str {
        match self {
            Self::TlsTunnel => "encrypted connection, hostname visible",
            Self::PlainHttp => "unencrypted HTTP request",
            Self::DnsQuery => "DNS lookup",
            Self::TlsClientHello => "TLS handshake",
        }
    }
}

/// One destination the device talked to, aggregated over a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkObservation {
    /// Hostname as the device asked for it. Not resolved or normalised, since
    /// the exact string is the evidence.
    pub host: String,
    pub port: u16,
    pub via: ObservedVia,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Number of separate connections or queries.
    pub count: u32,
    /// Bytes the device sent. Note this is ciphertext for tunnelled traffic;
    /// it bounds what could have been exfiltrated, not what was.
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl NetworkObservation {
    /// Seconds between first and last sighting. Zero for a single connection.
    #[must_use]
    pub fn span_seconds(&self) -> i64 {
        (self.last_seen - self.first_seen).num_seconds().max(0)
    }

    /// Mean interval between connections, when there are enough to mean
    /// anything. Regular intervals are the signature of a beacon.
    #[must_use]
    pub fn mean_interval_seconds(&self) -> Option<f64> {
        if self.count < 3 {
            return None;
        }
        // A capture session is minutes or hours, so narrowing to i32 loses
        // nothing real and keeps the conversion to f64 exact.
        let span = i32::try_from(self.span_seconds()).unwrap_or(i32::MAX);
        if span <= 0 {
            return None;
        }
        Some(f64::from(span) / f64::from(self.count - 1))
    }

    /// Whether the device sent substantially more than it received, which is
    /// the shape of exfiltration rather than of normal fetching.
    #[must_use]
    pub const fn is_upload_heavy(&self) -> bool {
        // A small absolute floor keeps chatter and handshakes out of it.
        self.bytes_sent > 256 * 1024 && self.bytes_sent > self.bytes_received * 4
    }
}

/// How much of the device's traffic a session could actually see.
///
/// Named rather than boolean, because the honest answer is rarely "all of it".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureCompleteness {
    /// Every route off the device passed through us — an isolated access point
    /// with no other path out.
    Exhaustive,
    /// Only traffic that chose to use the path we offered. An application that
    /// ignores the system proxy, or uses QUIC or a raw socket, is invisible.
    ProxiedOnly,
    /// Capture ran but something was known to be leaking around it, such as an
    /// active mobile data connection. Carries the specific reason, since a
    /// generic warning teaches the reader nothing.
    Leaking(String),
}

impl CaptureCompleteness {
    /// What absence of traffic is worth under this completeness.
    #[must_use]
    pub fn absence_means(&self) -> &str {
        match self {
            Self::Exhaustive => {
                "Nothing left the device by any route during the session, so silence here \
                 is meaningful — though an implant may simply have stayed dormant."
            }
            Self::ProxiedOnly => {
                "Only traffic that honoured the system proxy was visible. Anything using a \
                 raw socket, QUIC, or its own proxy settings would not appear, so silence \
                 proves nothing at all."
            }
            Self::Leaking(reason) => reason,
        }
    }

    /// Whether silence from this capture can support any negative conclusion.
    #[must_use]
    pub const fn silence_is_evidence(&self) -> bool {
        matches!(self, Self::Exhaustive)
    }
}

/// Everything one capture session saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationSet {
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub completeness: CaptureCompleteness,
    pub observations: Vec<NetworkObservation>,
}

impl ObservationSet {
    #[must_use]
    pub fn new(
        started_at: DateTime<Utc>,
        ended_at: DateTime<Utc>,
        completeness: CaptureCompleteness,
    ) -> Self {
        Self {
            started_at,
            ended_at,
            completeness,
            observations: Vec::new(),
        }
    }

    /// Duration of the session in seconds.
    #[must_use]
    pub fn duration_seconds(&self) -> i64 {
        (self.ended_at - self.started_at).num_seconds().max(0)
    }

    /// Distinct hosts, in the order most-contacted first.
    #[must_use]
    pub fn hosts_by_activity(&self) -> Vec<&NetworkObservation> {
        let mut out: Vec<&NetworkObservation> = self.observations.iter().collect();
        out.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| b.bytes_sent.cmp(&a.bytes_sent))
                .then_with(|| a.host.cmp(&b.host))
        });
        out
    }

    /// Merge repeated sightings of the same host and port into one entry.
    ///
    /// Capture produces one record per connection; a report wants one per
    /// destination.
    #[must_use]
    pub fn aggregated(&self) -> Self {
        let mut merged: BTreeMap<(String, u16, ObservedVia), NetworkObservation> = BTreeMap::new();

        for obs in &self.observations {
            let key = (obs.host.clone(), obs.port, obs.via);
            merged
                .entry(key)
                .and_modify(|existing| {
                    existing.count += obs.count;
                    existing.bytes_sent += obs.bytes_sent;
                    existing.bytes_received += obs.bytes_received;
                    existing.first_seen = existing.first_seen.min(obs.first_seen);
                    existing.last_seen = existing.last_seen.max(obs.last_seen);
                })
                .or_insert_with(|| obs.clone());
        }

        Self {
            started_at: self.started_at,
            ended_at: self.ended_at,
            completeness: self.completeness.clone(),
            observations: merged.into_values().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use chrono::TimeZone as _;

    fn at(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + seconds, 0).unwrap()
    }

    fn observation(host: &str, count: u32, first: i64, last: i64) -> NetworkObservation {
        NetworkObservation {
            host: host.to_owned(),
            port: 443,
            via: ObservedVia::TlsTunnel,
            first_seen: at(first),
            last_seen: at(last),
            count,
            bytes_sent: 1024,
            bytes_received: 4096,
        }
    }

    #[test]
    fn silence_is_only_evidence_when_every_route_was_covered() {
        assert!(CaptureCompleteness::Exhaustive.silence_is_evidence());
        assert!(!CaptureCompleteness::ProxiedOnly.silence_is_evidence());
        assert!(
            !CaptureCompleteness::Leaking("mobile data was on".to_owned()).silence_is_evidence()
        );

        assert!(
            CaptureCompleteness::ProxiedOnly
                .absence_means()
                .contains("proves nothing")
        );
    }

    #[test]
    fn beacon_intervals_need_enough_connections_to_mean_anything() {
        // Two connections describe no rhythm.
        assert!(
            observation("a.example", 2, 0, 600)
                .mean_interval_seconds()
                .is_none()
        );

        // Five connections over an hour: one every fifteen minutes.
        let regular = observation("a.example", 5, 0, 3600);
        let interval = regular.mean_interval_seconds().expect("an interval");
        assert!((interval - 900.0).abs() < 1.0, "got {interval}");
    }

    #[test]
    fn an_instantaneous_burst_reports_no_interval_rather_than_dividing_by_zero() {
        assert!(
            observation("a.example", 9, 50, 50)
                .mean_interval_seconds()
                .is_none()
        );
    }

    #[test]
    fn upload_heavy_needs_both_a_ratio_and_a_floor() {
        let mut chatty = observation("a.example", 1, 0, 0);
        chatty.bytes_sent = 8 * 1024;
        chatty.bytes_received = 8;
        assert!(
            !chatty.is_upload_heavy(),
            "a tiny lopsided exchange is just a handshake"
        );

        let mut exfil = observation("a.example", 1, 0, 0);
        exfil.bytes_sent = 40 * 1024 * 1024;
        exfil.bytes_received = 2048;
        assert!(exfil.is_upload_heavy());
    }

    #[test]
    fn aggregation_merges_by_host_port_and_method() {
        let mut set = ObservationSet::new(at(0), at(100), CaptureCompleteness::ProxiedOnly);
        set.observations = vec![
            observation("a.example", 1, 10, 10),
            observation("a.example", 1, 40, 40),
            observation("b.example", 1, 20, 20),
        ];

        let merged = set.aggregated();
        assert_eq!(merged.observations.len(), 2);

        let a = merged
            .observations
            .iter()
            .find(|o| o.host == "a.example")
            .expect("merged entry");
        assert_eq!(a.count, 2);
        assert_eq!(a.bytes_sent, 2048);
        assert_eq!(a.first_seen, at(10));
        assert_eq!(a.last_seen, at(40));
    }

    #[test]
    fn the_same_host_over_different_methods_stays_separate() {
        let mut set = ObservationSet::new(at(0), at(100), CaptureCompleteness::ProxiedOnly);
        let mut plain = observation("a.example", 1, 10, 10);
        plain.via = ObservedVia::PlainHttp;
        plain.port = 80;
        set.observations = vec![observation("a.example", 1, 10, 10), plain];

        assert_eq!(
            set.aggregated().observations.len(),
            2,
            "a host reached both in cleartext and over TLS is two different facts"
        );
    }

    #[test]
    fn hosts_are_ranked_by_activity() {
        let mut set = ObservationSet::new(at(0), at(100), CaptureCompleteness::ProxiedOnly);
        set.observations = vec![
            observation("quiet.example", 1, 0, 0),
            observation("busy.example", 9, 0, 0),
        ];

        assert_eq!(
            set.hosts_by_activity().first().map(|o| o.host.as_str()),
            Some("busy.example")
        );
    }
}
