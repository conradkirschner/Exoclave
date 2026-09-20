//! Native desktop interface for exoclave.
//!
//! Split deliberately in two. This library holds all the interface logic and
//! depends only on `egui` and [`ps_model`] — both pure Rust — so every screen
//! can be rendered and asserted on in CI with no window system, no GPU and no
//! phone. The windowing shell and the code that actually talks to a device
//! live behind the `desktop` feature, in `src/bin/exoclave-gui.rs`.
//!
//! Work runs off the UI thread through [`Backend`], which the tests replace
//! with one that answers immediately.
//!
//! There is no demonstration mode here and no sample data. A tool whose entire
//! purpose is to tell you the truth about a device should never put invented
//! findings on the screen; the fixtures that exercise the pipeline live in the
//! test suite, where they cannot be mistaken for a result.

pub mod theme;
pub mod view;

use ps_model::{DeviceEntry, Report};
use std::sync::mpsc::{Receiver, TryRecvError};

/// Outcome of a scan. The error is already human-readable.
pub type ScanResult = Result<Report, String>;

/// Outcome of asking adb what is attached.
pub type ProbeResult = Result<Vec<DeviceEntry>, String>;

/// How long to wait between connection checks, in seconds.
///
/// Short enough that plugging a cable in feels instant, long enough not to
/// hammer the adb server while the window sits open.
const PROBE_INTERVAL: f64 = 1.5;

/// Does the actual work, somewhere that is not the UI thread.
///
/// Each returned channel yields exactly one value. Implementations must not
/// block: these are called from inside a frame.
pub trait Backend: Send {
    /// Collect from, and analyse, one device.
    fn scan(&self, serial: String) -> Receiver<ScanResult>;
    /// Ask which devices are attached.
    fn probe(&self) -> Receiver<ProbeResult>;
}

/// What the main area is showing.
#[derive(Debug)]
pub enum Screen {
    /// Connection instructions and live device status.
    Connect,
    /// A scan is in flight against the named device.
    Scanning { device: String },
    /// A finished report.
    Report(Box<Report>),
    /// The scan failed; the string is shown to the user as-is.
    Failed(String),
}

/// The application.
pub struct ExoclaveApp {
    screen: Screen,
    devices: Vec<DeviceEntry>,
    probe_error: Option<String>,
    /// Until the first probe returns, the interface says "checking" rather
    /// than "nothing connected" — claiming absence before looking is how a
    /// user ends up chasing a problem that is not there.
    probed: bool,
    pending_scan: Option<Receiver<ScanResult>>,
    pending_probe: Option<Receiver<ProbeResult>>,
    next_probe_at: f64,
    backend: Box<dyn Backend>,
}

impl std::fmt::Debug for ExoclaveApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExoclaveApp")
            .field("screen", &self.screen)
            .field("devices", &self.devices)
            .field("probed", &self.probed)
            .finish_non_exhaustive()
    }
}

impl ExoclaveApp {
    #[must_use]
    pub fn new(backend: Box<dyn Backend>) -> Self {
        Self {
            screen: Screen::Connect,
            devices: Vec::new(),
            probe_error: None,
            probed: false,
            pending_scan: None,
            pending_probe: None,
            next_probe_at: 0.0,
            backend,
        }
    }

    #[must_use]
    pub const fn screen(&self) -> &Screen {
        &self.screen
    }

    #[must_use]
    pub fn devices(&self) -> &[DeviceEntry] {
        &self.devices
    }

    #[must_use]
    pub const fn has_probed(&self) -> bool {
        self.probed
    }

    #[must_use]
    pub fn probe_error(&self) -> Option<&str> {
        self.probe_error.as_deref()
    }

    /// Whether a scan is in flight.
    #[must_use]
    pub const fn is_scanning(&self) -> bool {
        self.pending_scan.is_some()
    }

    /// The first attached device we could actually scan, if any.
    #[must_use]
    pub fn scannable(&self) -> Option<&DeviceEntry> {
        self.devices.iter().find(|d| d.state.is_scannable())
    }

    /// Ask the backend what is attached, unless a check is already running.
    pub fn request_probe(&mut self) {
        if self.pending_probe.is_none() {
            self.pending_probe = Some(self.backend.probe());
        }
    }

    /// Start scanning the given device, unless a scan is already running.
    pub fn start_scan(&mut self, serial: String) {
        if self.is_scanning() {
            return;
        }
        let device = self
            .devices
            .iter()
            .find(|d| d.serial == serial)
            .map_or_else(|| serial.clone(), DeviceEntry::display_name);

        self.pending_scan = Some(self.backend.scan(serial));
        self.screen = Screen::Scanning { device };
    }

    /// Go back to the connection screen, discarding the current report.
    pub fn back_to_connect(&mut self) {
        if !self.is_scanning() {
            self.screen = Screen::Connect;
        }
    }

    /// Take any finished results. Call once per frame.
    pub fn poll(&mut self) {
        self.poll_probe();
        self.poll_scan();
    }

    fn poll_probe(&mut self) {
        let Some(rx) = &self.pending_probe else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(devices)) => {
                self.devices = devices;
                self.probe_error = None;
                self.probed = true;
                self.pending_probe = None;
            }
            Ok(Err(message)) => {
                // Keep the previous device list: a single failed check is not
                // evidence that the phone was unplugged.
                self.probe_error = Some(message);
                self.probed = true;
                self.pending_probe = None;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.probe_error = Some("The connection check did not complete.".to_owned());
                self.probed = true;
                self.pending_probe = None;
            }
        }
    }

    fn poll_scan(&mut self) {
        let Some(rx) = &self.pending_scan else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(report)) => {
                self.screen = Screen::Report(Box::new(report));
                self.pending_scan = None;
            }
            Ok(Err(message)) => {
                self.screen = Screen::Failed(message);
                self.pending_scan = None;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.screen = Screen::Failed(
                    "The scan stopped unexpectedly and reported nothing. \
                     This is a bug; please report it."
                        .to_owned(),
                );
                self.pending_scan = None;
            }
        }
    }

    /// Re-check the connection on a timer, so plugging a cable in is noticed
    /// without the user having to press anything.
    fn tick_probe(&mut self, now: f64) {
        if self.pending_probe.is_none() && now >= self.next_probe_at {
            self.next_probe_at = now + PROBE_INTERVAL;
            self.request_probe();
        }
    }

    /// Draw one frame.
    pub fn draw(&mut self, ui: &mut egui::Ui) {
        self.poll();

        let now = ui.input(|i| i.time);
        // Only poll for devices on the screen that shows them.
        if matches!(self.screen, Screen::Connect | Screen::Failed(_)) {
            self.tick_probe(now);
        }

        // Without input events the shell sleeps, so a result arriving from a
        // worker would not be noticed until the user moved the mouse.
        if self.is_scanning() || matches!(self.screen, Screen::Connect | Screen::Failed(_)) {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(400));
        }

        let mut action = None;
        egui::CentralPanel::default().show(ui, |ui| {
            view::header(ui);
            ui.add_space(theme::GAP_M);
            action = view::body(ui, self);
        });

        match action {
            Some(view::Action::Scan(serial)) => self.start_scan(serial),
            Some(view::Action::CheckAgain) => {
                self.next_probe_at = 0.0;
                self.request_probe();
            }
            Some(view::Action::Back) => self.back_to_connect(),
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use chrono::Utc;
    use ps_model::{DeviceIdentity, DeviceState};
    use std::sync::mpsc;

    struct Fake {
        scan: ScanResult,
        probe: ProbeResult,
    }

    impl Backend for Fake {
        fn scan(&self, _serial: String) -> Receiver<ScanResult> {
            ready(self.scan.clone())
        }
        fn probe(&self) -> Receiver<ProbeResult> {
            ready(self.probe.clone())
        }
    }

    fn ready<T: Send + 'static>(value: T) -> Receiver<T> {
        let (tx, rx) = mpsc::channel();
        let _ = tx.send(value);
        rx
    }

    fn report() -> Report {
        Report::new(DeviceIdentity::default(), Utc::now())
    }

    fn entry(serial: &str, state: DeviceState) -> DeviceEntry {
        DeviceEntry {
            serial: serial.to_owned(),
            state,
            model: Some("Mi_11".to_owned()),
        }
    }

    fn app(probe: ProbeResult) -> ExoclaveApp {
        ExoclaveApp::new(Box::new(Fake {
            scan: Ok(report()),
            probe,
        }))
    }

    #[test]
    fn before_the_first_check_the_interface_does_not_claim_the_phone_is_absent() {
        let app = app(Ok(vec![]));
        assert!(!app.has_probed());
        assert!(app.devices().is_empty());
    }

    #[test]
    fn a_ready_device_becomes_scannable() {
        let mut app = app(Ok(vec![entry("ABC", DeviceState::Ready)]));
        app.request_probe();
        app.poll();

        assert!(app.has_probed());
        assert_eq!(app.scannable().map(|d| d.serial.as_str()), Some("ABC"));
    }

    #[test]
    fn an_unauthorised_device_is_visible_but_not_scannable() {
        let mut app = app(Ok(vec![entry("ABC", DeviceState::Unauthorized)]));
        app.request_probe();
        app.poll();

        assert_eq!(app.devices().len(), 1);
        assert!(
            app.scannable().is_none(),
            "an unauthorised device must not be scannable"
        );
    }

    #[test]
    fn a_failed_check_does_not_erase_a_device_we_already_saw() {
        let mut app = ExoclaveApp::new(Box::new(Fake {
            scan: Ok(report()),
            probe: Ok(vec![entry("ABC", DeviceState::Ready)]),
        }));
        app.request_probe();
        app.poll();
        assert_eq!(app.devices().len(), 1);

        // A later check errors; the known device must survive it.
        let mut app = ExoclaveApp {
            backend: Box::new(Fake {
                scan: Ok(report()),
                probe: Err("adb not found".to_owned()),
            }),
            ..app
        };
        app.request_probe();
        app.poll();

        assert_eq!(app.devices().len(), 1, "a failed check is not an unplug");
        assert_eq!(app.probe_error(), Some("adb not found"));
    }

    #[test]
    fn scanning_moves_to_the_scanning_screen_and_then_to_a_report() {
        let mut app = app(Ok(vec![entry("ABC", DeviceState::Ready)]));
        app.request_probe();
        app.poll();

        app.start_scan("ABC".to_owned());
        match app.screen() {
            Screen::Scanning { device } => assert_eq!(device, "Mi 11"),
            other => panic!("expected scanning, got {other:?}"),
        }

        app.poll();
        assert!(matches!(app.screen(), Screen::Report(_)));
    }

    #[test]
    fn a_second_scan_cannot_start_while_one_is_running() {
        struct Never;
        impl Backend for Never {
            fn scan(&self, _serial: String) -> Receiver<ScanResult> {
                let (tx, rx) = mpsc::channel();
                std::mem::forget(tx);
                rx
            }
            fn probe(&self) -> Receiver<ProbeResult> {
                ready(Ok(vec![]))
            }
        }

        let mut app = ExoclaveApp::new(Box::new(Never));
        app.start_scan("ABC".to_owned());
        assert!(app.is_scanning());

        app.start_scan("XYZ".to_owned());
        match app.screen() {
            Screen::Scanning { device } => assert_eq!(device, "ABC"),
            other => panic!("expected the first scan to survive, got {other:?}"),
        }
    }

    #[test]
    fn a_worker_that_dies_silently_does_not_hang_the_interface() {
        struct Dies;
        impl Backend for Dies {
            fn scan(&self, _serial: String) -> Receiver<ScanResult> {
                let (_, rx) = mpsc::channel();
                rx
            }
            fn probe(&self) -> Receiver<ProbeResult> {
                ready(Ok(vec![]))
            }
        }

        let mut app = ExoclaveApp::new(Box::new(Dies));
        app.start_scan("ABC".to_owned());
        app.poll();

        assert!(matches!(app.screen(), Screen::Failed(_)));
        assert!(!app.is_scanning());
    }

    #[test]
    fn the_connection_check_is_rate_limited() {
        let mut app = app(Ok(vec![]));

        app.tick_probe(100.0);
        app.poll();
        let first_due = app.next_probe_at;
        assert!(first_due > 100.0);

        // A frame moments later must not trigger another check.
        app.tick_probe(100.1);
        assert!((app.next_probe_at - first_due).abs() < f64::EPSILON);

        // Once the interval has passed, it checks again.
        app.tick_probe(first_due + 0.1);
        assert!(app.next_probe_at > first_due);
    }
}

#[cfg(feature = "desktop")]
impl eframe::App for ExoclaveApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }
}
