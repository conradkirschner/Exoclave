//! Pure parsing of the first bytes a client sends to a proxy.
//!
//! Kept free of I/O because this is where the bugs live: a proxy sees
//! absolute-form URIs, `CONNECT` authority-form, IPv6 literals in brackets,
//! and clients that omit the port. Getting the hostname wrong means the
//! report names the wrong destination, which is worse than naming none.

use ps_model::ObservedVia;

/// Largest request head we will buffer before giving up.
///
/// A proxy request head is small. Anything larger is either broken or hostile,
/// and we will not hold it in memory to find out which.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// The parts of a request head this tool cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead<'a> {
    pub method: &'a str,
    /// Request target, exactly as sent.
    pub target: &'a str,
    pub host_header: Option<&'a str>,
}

/// Where the client wants to go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub host: String,
    pub port: u16,
    pub via: ObservedVia,
}

/// Index just past the blank line ending the head, if it has arrived.
#[must_use]
pub fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|start| start + 4)
}

/// Parse the request line and the `Host` header.
#[must_use]
pub fn parse_head(head: &str) -> Option<RequestHead<'_>> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;

    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    if method.is_empty() || target.is_empty() {
        return None;
    }

    let host_header = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("host").then_some(value)
        })
        .map(str::trim)
        .filter(|v| !v.is_empty());

    Some(RequestHead {
        method,
        target,
        host_header,
    })
}

/// Split `host:port`, honouring bracketed IPv6 literals.
///
/// Returns the host without brackets, and the port if one was given.
fn split_authority(authority: &str) -> Option<(String, Option<u16>)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }

    // Strip any userinfo; it is not part of the destination.
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, rest)| rest);

    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: [::1] or [::1]:8443
        let (host, tail) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = match tail.strip_prefix(':') {
            Some(p) => Some(p.parse().ok()?),
            None => None,
        };
        return Some((host.to_owned(), port));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Some((host.to_owned(), Some(port.parse().ok()?))),
        // A bare colon, or no colon at all.
        Some(_) => None,
        None => Some((authority.to_owned(), None)),
    }
}

/// Work out the destination from a parsed head.
///
/// `None` when the request names no reachable host, which is the only case the
/// proxy rejects outright.
#[must_use]
pub fn destination(head: &RequestHead<'_>) -> Option<Destination> {
    // CONNECT uses authority-form: `CONNECT example.com:443 HTTP/1.1`.
    if head.method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_authority(head.target)?;
        return Some(Destination {
            host,
            port: port.unwrap_or(443),
            via: ObservedVia::TlsTunnel,
        });
    }

    // Everything else through a proxy uses absolute-form:
    // `GET http://example.com/path HTTP/1.1`.
    let authority = if let Some(rest) = strip_scheme(head.target) {
        // Authority runs until the first '/', '?' or '#'.
        rest.split(['/', '?', '#']).next().unwrap_or(rest)
    } else {
        // Origin-form reached a proxy, which is irregular but survivable when
        // the client sent a Host header.
        head.host_header?
    };

    let (host, port) = split_authority(authority)?;
    let default_port = if head.target.starts_with("https://") {
        443
    } else {
        80
    };

    Some(Destination {
        host,
        port: port.unwrap_or(default_port),
        via: if default_port == 443 {
            ObservedVia::TlsTunnel
        } else {
            ObservedVia::PlainHttp
        },
    })
}

/// Strip `http://` or `https://`, case-insensitively.
fn strip_scheme(target: &str) -> Option<&str> {
    let lowered = target.to_ascii_lowercase();
    for scheme in ["http://", "https://"] {
        if lowered.starts_with(scheme) {
            return target.get(scheme.len()..);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn dest(raw: &str) -> Option<Destination> {
        let head = parse_head(raw)?;
        destination(&head)
    }

    #[test]
    fn the_head_is_only_complete_after_a_blank_line() {
        assert!(find_head_end(b"GET / HTTP/1.1\r\nHost: a\r\n").is_none());
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(18));
    }

    #[test]
    fn connect_gives_a_hostname_even_though_the_payload_is_encrypted() {
        let d = dest("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert_eq!(d.host, "example.com");
        assert_eq!(d.port, 443);
        assert_eq!(d.via, ObservedVia::TlsTunnel);
    }

    #[test]
    fn connect_without_a_port_defaults_to_https() {
        let d = dest("CONNECT example.com HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(d.port, 443);
    }

    #[test]
    fn connect_to_a_non_standard_port_is_preserved() {
        let d = dest("CONNECT c2.example:8443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!((d.host.as_str(), d.port), ("c2.example", 8443));
    }

    #[test]
    fn ipv6_literals_keep_their_address_and_lose_their_brackets() {
        let d = dest("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(d.host, "2001:db8::1");
        assert_eq!(d.port, 8443);

        let bare = dest("CONNECT [2001:db8::1] HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(bare.host, "2001:db8::1");
        assert_eq!(bare.port, 443);
    }

    #[test]
    fn absolute_form_urls_are_split_at_the_path() {
        let d =
            dest("GET http://example.com/a/b?c=d HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert_eq!(d.host, "example.com");
        assert_eq!(d.port, 80);
        assert_eq!(d.via, ObservedVia::PlainHttp);
    }

    #[test]
    fn an_absolute_url_with_no_path_still_parses() {
        let d = dest("GET http://example.com HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(d.host, "example.com");
    }

    #[test]
    fn origin_form_falls_back_to_the_host_header() {
        let d = dest("GET /path HTTP/1.1\r\nHost: fallback.example:8080\r\n\r\n").unwrap();
        assert_eq!(d.host, "fallback.example");
        assert_eq!(d.port, 8080);
    }

    #[test]
    fn the_host_header_is_matched_regardless_of_case() {
        let head = parse_head("GET /p HTTP/1.1\r\nHOST:  Example.com \r\n\r\n").unwrap();
        assert_eq!(head.host_header, Some("Example.com"));
    }

    #[test]
    fn userinfo_is_discarded_rather_than_reported_as_the_host() {
        let d = dest("GET http://user:pass@example.com/p HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(
            d.host, "example.com",
            "credentials in a URL must never end up in a report as the destination"
        );
    }

    #[test]
    fn a_request_naming_no_host_is_rejected() {
        assert!(dest("GET /path HTTP/1.1\r\n\r\n").is_none());
        assert!(dest("CONNECT : HTTP/1.1\r\n\r\n").is_none());
        assert!(dest("\r\n\r\n").is_none());
    }

    #[test]
    fn a_nonsense_port_is_rejected_rather_than_silently_defaulted() {
        assert!(dest("CONNECT example.com:notaport HTTP/1.1\r\n\r\n").is_none());
        assert!(dest("CONNECT example.com:99999 HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn https_in_absolute_form_is_recorded_as_tunnelled() {
        let d = dest("GET https://example.com/p HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(d.port, 443);
        assert_eq!(d.via, ObservedVia::TlsTunnel);
    }
}
