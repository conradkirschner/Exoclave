//! Out-of-band observation of a device's traffic.
//!
//! The device is pointed at an HTTP proxy running here, and every destination
//! it asks for is recorded. No interception is attempted and no certificate is
//! installed: an HTTPS request through a proxy arrives as
//! `CONNECT host:443`, so the **hostname is in cleartext even though the
//! payload is not**. Hostnames are what the analysis needs, so the tool takes
//! the cheap half and leaves the payload alone.
//!
//! What makes this worth having is whose account it is. Everything collected
//! over ADB is the phone describing itself, and privileged code on the phone
//! can rewrite that description. A connection that arrived at this process is
//! a fact about the world, recorded by equipment the phone does not control.
//!
//! The limit is equally sharp, and [`ps_model::CaptureCompleteness`] carries
//! it into the report: an application is free to ignore the system proxy. So
//! **traffic seen here is evidence, and traffic not seen here proves nothing.**

pub mod parse;

use chrono::Utc;
use parse::{Destination, MAX_HEAD_BYTES};
use ps_model::{CaptureCompleteness, NetworkObservation, ObservationSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, warn};

/// How long to wait for a destination to accept a connection.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15);

/// How long to wait for a client to finish sending its request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("could not listen on {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// Shared state between the accept loop and the report.
#[derive(Debug, Default)]
struct Log {
    observations: Mutex<Vec<NetworkObservation>>,
}

impl Log {
    /// Record a destination the moment it is contacted, returning a handle to
    /// fill in the byte counts later.
    ///
    /// Recording on establishment rather than on close matters: a live view
    /// must show a host as soon as the device reaches for it, and a long-lived
    /// connection — a push channel, a websocket, a beacon holding the socket
    /// open — would otherwise never appear at all.
    fn record(&self, observation: NetworkObservation) -> usize {
        let mut guard = match self.observations.lock() {
            Ok(guard) => guard,
            // A poisoned lock means another task panicked while holding it.
            // Carrying on with the data is far better than propagating the
            // panic into every subsequent connection.
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.push(observation);
        guard.len() - 1
    }

    /// Fill in the byte counts once a connection has finished.
    fn settle(&self, index: usize, bytes_sent: u64, bytes_received: u64) {
        let mut guard = match self.observations.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(entry) = guard.get_mut(index) {
            entry.bytes_sent = bytes_sent;
            entry.bytes_received = bytes_received;
            entry.last_seen = Utc::now();
        }
    }

    fn snapshot(&self) -> Vec<NetworkObservation> {
        match self.observations.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

/// A running proxy, observing whatever is pointed at it.
#[derive(Debug)]
pub struct Tunnel {
    addr: SocketAddr,
    log: Arc<Log>,
    shutdown: watch::Sender<bool>,
    started_at: chrono::DateTime<Utc>,
}

impl Tunnel {
    /// Bind and start accepting.
    ///
    /// Pass port 0 to let the operating system choose; read it back from
    /// [`Tunnel::local_addr`].
    ///
    /// # Errors
    /// If the address cannot be bound.
    pub async fn start(bind: SocketAddr) -> Result<Self, TunnelError> {
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|source| TunnelError::Bind { addr: bind, source })?;

        let addr = listener
            .local_addr()
            .map_err(|source| TunnelError::Bind { addr: bind, source })?;

        let log = Arc::new(Log::default());
        let (shutdown, mut rx) = watch::channel(false);

        let accept_log = Arc::clone(&log);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Bias towards shutdown so stop() is prompt even under load.
                    biased;

                    _ = rx.changed() => {
                        if *rx.borrow() {
                            debug!("tunnel shutting down");
                            return;
                        }
                    }
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, peer)) => {
                                let log = Arc::clone(&accept_log);
                                tokio::spawn(async move {
                                    if let Err(error) = serve(stream, &log).await {
                                        debug!(%peer, %error, "proxied connection ended early");
                                    }
                                });
                            }
                            Err(error) => {
                                // A single failed accept is not fatal; a storm
                                // of them would be, so it is logged loudly.
                                warn!(%error, "accept failed");
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            addr,
            log,
            shutdown,
            started_at: Utc::now(),
        })
    }

    /// Address the device should be pointed at.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Everything seen so far, without stopping. Safe to poll for a live view.
    #[must_use]
    pub fn snapshot(&self, completeness: CaptureCompleteness) -> ObservationSet {
        let mut set = ObservationSet::new(self.started_at, Utc::now(), completeness);
        set.observations = self.log.snapshot();
        set.aggregated()
    }

    /// Stop accepting and return the session.
    ///
    /// In-flight connections are left to finish or be dropped with the
    /// runtime; their observations were recorded when they were established.
    #[must_use]
    pub fn stop(self, completeness: CaptureCompleteness) -> ObservationSet {
        // A send failure only means the accept loop already exited.
        let _ = self.shutdown.send(true);
        self.snapshot(completeness)
    }
}

/// Handle one proxied connection.
async fn serve(mut client: TcpStream, log: &Log) -> std::io::Result<()> {
    let Some((destination, leftover, head_len)) = read_request(&mut client).await? else {
        // Nothing usable was sent; there is no destination to record.
        return Ok(());
    };

    let first_seen = Utc::now();
    let authority = format!("{}:{}", destination.host, destination.port);

    // Recorded before the upstream is even reached: the device asking for a
    // host is the evidence, whether or not the host answers. A command-and-
    // control server that has been taken down is not less interesting.
    let index = log.record(observation(&destination, first_seen, 0, 0));

    let upstream = tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(&authority)).await;

    let mut upstream = match upstream {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            debug!(%authority, %error, "upstream refused");
            return Ok(());
        }
        Err(_) => {
            debug!(%authority, "upstream timed out");
            return Ok(());
        }
    };

    if destination.via == ps_model::ObservedVia::TlsTunnel && head_len > 0 {
        // CONNECT: acknowledge, then get out of the way. The head itself is
        // ours and must not be forwarded.
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        if !leftover.is_empty() {
            upstream.write_all(&leftover).await?;
        }
    } else {
        // Plain HTTP: the request belongs to the origin server. Absolute-form
        // targets are legal for an origin server to receive, so it is
        // forwarded unchanged rather than rewritten.
        upstream.write_all(&leftover).await?;
    }

    let (sent, received) = tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .unwrap_or((0, 0));

    log.settle(index, sent, received);
    Ok(())
}

fn observation(
    destination: &Destination,
    first_seen: chrono::DateTime<Utc>,
    bytes_sent: u64,
    bytes_received: u64,
) -> NetworkObservation {
    NetworkObservation {
        host: destination.host.clone(),
        port: destination.port,
        via: destination.via,
        first_seen,
        last_seen: Utc::now(),
        count: 1,
        bytes_sent,
        bytes_received,
    }
}

/// Read and parse the request head.
///
/// Returns the destination, any bytes to forward, and the length of the head
/// itself (zero when the head is to be forwarded rather than consumed).
type ParsedRequest = (Destination, Vec<u8>, usize);

async fn read_request(client: &mut TcpStream) -> std::io::Result<Option<ParsedRequest>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    let head_end = loop {
        if let Some(end) = parse::find_head_end(&buf) {
            break end;
        }
        if buf.len() >= MAX_HEAD_BYTES {
            debug!("request head exceeded the limit; dropping");
            return Ok(None);
        }

        let read = match tokio::time::timeout(HEAD_TIMEOUT, client.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => return Ok(None),
            Ok(Ok(n)) => n,
            Ok(Err(error)) => return Err(error),
        };
        buf.extend_from_slice(chunk.get(..read).unwrap_or_default());
    };

    let Some(head_str) = buf
        .get(..head_end)
        .and_then(|h| std::str::from_utf8(h).ok())
    else {
        return Ok(None);
    };
    let Some(head) = parse::parse_head(head_str) else {
        return Ok(None);
    };
    let Some(destination) = parse::destination(&head) else {
        return Ok(None);
    };

    let is_connect = head.method.eq_ignore_ascii_case("CONNECT");
    let forward = if is_connect {
        // Anything after the CONNECT head is already tunnel payload.
        buf.get(head_end..).unwrap_or_default().to_vec()
    } else {
        buf.clone()
    };

    Ok(Some((destination, forward, usize::from(is_connect))))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;
    use tokio::net::TcpListener;

    /// A throwaway origin server that echoes and then closes.
    async fn echo_server() -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut chunk = [0u8; 512];
            // Read whatever arrives, then answer once.
            if let Ok(n) = stream.read(&mut chunk).await {
                received.extend_from_slice(&chunk[..n]);
            }
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\nhi").await;
            received
        });

        (addr, handle)
    }

    #[tokio::test]
    async fn a_connect_request_is_recorded_with_its_hostname() {
        let (origin, origin_task) = echo_server().await;
        let tunnel = Tunnel::start("127.0.0.1:0".parse().unwrap()).await.unwrap();

        let mut client = TcpStream::connect(tunnel.local_addr()).await.unwrap();
        client
            .write_all(format!("CONNECT localhost:{} HTTP/1.1\r\n\r\n", origin.port()).as_bytes())
            .await
            .unwrap();

        // The proxy answers 200 before tunnelling.
        let mut response = [0u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert!(
            String::from_utf8_lossy(&response).contains("200"),
            "got: {}",
            String::from_utf8_lossy(&response)
        );

        client.write_all(b"payload").await.unwrap();
        client.shutdown().await.unwrap();

        let forwarded = origin_task.await.unwrap();
        assert_eq!(
            forwarded, b"payload",
            "the CONNECT head must not be forwarded to the origin"
        );

        // Give the recording task a moment to land.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let set = tunnel.stop(CaptureCompleteness::ProxiedOnly);

        let seen = set.observations.first().expect("one observation");
        assert_eq!(seen.host, "localhost");
        assert_eq!(seen.port, origin.port());
        assert_eq!(seen.via, ps_model::ObservedVia::TlsTunnel);
    }

    #[tokio::test]
    async fn a_plain_http_request_is_forwarded_intact() {
        let (origin, origin_task) = echo_server().await;
        let tunnel = Tunnel::start("127.0.0.1:0".parse().unwrap()).await.unwrap();

        let mut client = TcpStream::connect(tunnel.local_addr()).await.unwrap();
        let request = format!(
            "GET http://localhost:{}/probe HTTP/1.1\r\nHost: localhost\r\n\r\n",
            origin.port()
        );
        client.write_all(request.as_bytes()).await.unwrap();

        let forwarded = String::from_utf8(origin_task.await.unwrap()).unwrap();
        assert!(forwarded.contains("/probe"), "got: {forwarded}");

        tokio::time::sleep(Duration::from_millis(100)).await;
        let set = tunnel.stop(CaptureCompleteness::ProxiedOnly);
        assert_eq!(
            set.observations.first().map(|o| o.via),
            Some(ps_model::ObservedVia::PlainHttp)
        );
    }

    #[tokio::test]
    async fn a_destination_that_refuses_is_still_recorded() {
        let tunnel = Tunnel::start("127.0.0.1:0".parse().unwrap()).await.unwrap();

        // Port 1 on loopback: nothing is listening, so the connection is
        // refused immediately.
        let mut client = TcpStream::connect(tunnel.local_addr()).await.unwrap();
        client
            .write_all(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let _ = client.read(&mut [0u8; 64]).await;

        tokio::time::sleep(Duration::from_millis(150)).await;
        let set = tunnel.stop(CaptureCompleteness::ProxiedOnly);

        let seen = set
            .observations
            .first()
            .expect("a refused attempt still counts");
        assert_eq!(seen.host, "127.0.0.1");
        assert_eq!(seen.bytes_sent, 0);
    }

    #[tokio::test]
    async fn rubbish_does_not_create_an_observation_or_kill_the_listener() {
        let tunnel = Tunnel::start("127.0.0.1:0".parse().unwrap()).await.unwrap();

        let mut client = TcpStream::connect(tunnel.local_addr()).await.unwrap();
        client.write_all(b"not http at all\r\n\r\n").await.unwrap();
        client.shutdown().await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        // The listener must still be alive afterwards.
        assert!(TcpStream::connect(tunnel.local_addr()).await.is_ok());

        let set = tunnel.stop(CaptureCompleteness::ProxiedOnly);
        assert!(set.observations.is_empty());
    }

    #[tokio::test]
    async fn a_host_appears_in_a_live_snapshot_while_the_connection_is_still_open() {
        let (origin, _origin_task) = echo_server().await;
        let tunnel = Tunnel::start("127.0.0.1:0".parse().unwrap()).await.unwrap();

        let mut client = TcpStream::connect(tunnel.local_addr()).await.unwrap();
        client
            .write_all(
                format!("CONNECT beacon.example:{} HTTP/1.1\r\n\r\n", origin.port()).as_bytes(),
            )
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(150)).await;

        // The connection is deliberately left open. A beacon that holds its
        // socket must still show up, or the live view would be blind to
        // exactly the behaviour it exists to catch.
        let live = tunnel.snapshot(CaptureCompleteness::ProxiedOnly);
        assert_eq!(
            live.observations.first().map(|o| o.host.as_str()),
            Some("beacon.example"),
            "a held-open connection must appear before it closes"
        );

        drop(client);
    }

    #[tokio::test]
    async fn the_session_carries_its_completeness_into_the_report() {
        let tunnel = Tunnel::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let set = tunnel.stop(CaptureCompleteness::ProxiedOnly);

        assert!(!set.completeness.silence_is_evidence());
        assert!(set.completeness.absence_means().contains("proves nothing"));
    }
}
