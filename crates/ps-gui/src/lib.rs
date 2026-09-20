//! Native desktop interface for exoclave.
//!
//! Split deliberately in two. This library holds all the interface logic and
//! depends only on `egui` and [`ps_model`] — both pure Rust — so every screen
//! can be rendered and asserted on in CI with no window system, no GPU and no
//! phone. The windowing shell and the code that actually talks to a device
//! live behind the `desktop` feature, in `src/bin/exoclave-gui.rs`.
//!
//! Work runs off the UI thread through [`Launcher`], which the tests replace
//! with one that answers immediately.

pub mod theme;
pub mod view;

use ps_model::Report;
use std::sync::mpsc::{Receiver, TryRecvError};

/// Something the user asked the tool to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Job {
    /// Collect from a real device over ADB.
    ScanDevice,
    /// Fixture device with nothing wrong at app level.
    DemoHealthy,
    /// Fixture device exercising every detector.
    DemoCompromised,
}

impl Job {
    /// Button text.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ScanDevice => "Scan connected device",
            Self::DemoHealthy => "Demo: healthy",
            Self::DemoCompromised => "Demo: compromised",
        }
    }

    /// Progress text, shown while it runs.
    #[must_use]
    pub const fn progress(self) -> &'static str {
        match self {
            Self::ScanDevice => "Collecting from the device over ADB…",
            Self::DemoHealthy | Self::DemoCompromised => "Running the fixture device…",
        }
    }
}

/// Outcome of a job. The error is already human-readable.
pub type ScanResult = Result<Report, String>;

/// Starts work somewhere that is not the UI thread.
///
/// The returned channel yields exactly one result. Implementations must not
/// block: this is called from inside a frame.
pub trait Launcher: Send {
    fn launch(&self, job: Job) -> Receiver<ScanResult>;
}

/// What the main area is currently showing.
#[derive(Debug)]
pub enum View {
    /// Nothing run yet.
    Idle,
    /// A job is in flight.
    Running(Job),
    /// A finished report.
    Ready(Box<Report>),
    /// The job failed; the string is shown to the user as-is.
    Failed(String),
}

/// The application.
pub struct ExoclaveApp {
    view: View,
    pending: Option<Receiver<ScanResult>>,
    launcher: Box<dyn Launcher>,
}

impl std::fmt::Debug for ExoclaveApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExoclaveApp")
            .field("view", &self.view)
            .field("pending", &self.pending.is_some())
            .finish_non_exhaustive()
    }
}

impl ExoclaveApp {
    #[must_use]
    pub fn new(launcher: Box<dyn Launcher>) -> Self {
        Self {
            view: View::Idle,
            pending: None,
            launcher,
        }
    }

    /// Current view, for tests and for the shell's window title.
    #[must_use]
    pub const fn view(&self) -> &View {
        &self.view
    }

    /// Whether a job is in flight. Controls are disabled while it is.
    #[must_use]
    pub const fn is_busy(&self) -> bool {
        self.pending.is_some()
    }

    /// Start a job, unless one is already running.
    pub fn start(&mut self, job: Job) {
        if self.is_busy() {
            return;
        }
        self.pending = Some(self.launcher.launch(job));
        self.view = View::Running(job);
    }

    /// Take the result if the job has finished. Call once per frame.
    ///
    /// Returns `true` when the view changed, so the shell knows to repaint.
    pub fn poll(&mut self) -> bool {
        let Some(rx) = &self.pending else {
            return false;
        };

        match rx.try_recv() {
            Ok(Ok(report)) => {
                self.view = View::Ready(Box::new(report));
                self.pending = None;
                true
            }
            Ok(Err(message)) => {
                self.view = View::Failed(message);
                self.pending = None;
                true
            }
            Err(TryRecvError::Empty) => false,
            // The worker vanished without sending. Surface it rather than
            // spinning for ever on a channel that will never produce.
            Err(TryRecvError::Disconnected) => {
                self.view = View::Failed(
                    "The scan stopped unexpectedly and reported nothing. \
                     This is a bug; please report it."
                        .to_owned(),
                );
                self.pending = None;
                true
            }
        }
    }

    /// Draw one frame.
    pub fn draw(&mut self, ui: &mut egui::Ui) {
        self.poll();

        // Without input events the shell sleeps, so a result arriving from the
        // worker would not be picked up until the user moved the mouse.
        if self.is_busy() {
            ui.ctx().request_repaint();
        }

        egui::CentralPanel::default().show(ui, |ui| {
            if let Some(job) = view::header(ui, self.is_busy()) {
                self.start(job);
            }
            ui.add_space(theme::GAP_M);
            view::body(ui, &self.view);
        });
    }
}

#[cfg(feature = "desktop")]
impl eframe::App for ExoclaveApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use chrono::Utc;
    use ps_model::{DeviceIdentity, Report};
    use std::sync::mpsc;

    /// Answers immediately, so a frame can be rendered against a known state.
    struct Instant(ScanResult);

    impl Launcher for Instant {
        fn launch(&self, _job: Job) -> Receiver<ScanResult> {
            let (tx, rx) = mpsc::channel();
            let _ = tx.send(self.0.clone());
            rx
        }
    }

    /// Never answers, so the busy state can be observed.
    struct Never;

    impl Launcher for Never {
        fn launch(&self, _job: Job) -> Receiver<ScanResult> {
            let (tx, rx) = mpsc::channel();
            // Keep the sender alive, otherwise the channel reads as
            // disconnected rather than pending.
            std::mem::forget(tx);
            rx
        }
    }

    fn sample_report() -> Report {
        Report::new(
            DeviceIdentity {
                serial: "TEST".into(),
                model: Some("Pixel 8".into()),
                ..DeviceIdentity::default()
            },
            Utc::now(),
        )
    }

    fn app_with(launcher: Box<dyn Launcher>) -> ExoclaveApp {
        ExoclaveApp::new(launcher)
    }

    #[test]
    fn a_finished_job_becomes_a_report() {
        let mut app = app_with(Box::new(Instant(Ok(sample_report()))));
        app.start(Job::DemoHealthy);
        assert!(app.poll());
        assert!(matches!(app.view(), View::Ready(_)));
        assert!(!app.is_busy());
    }

    #[test]
    fn a_failed_job_surfaces_its_message() {
        let mut app = app_with(Box::new(Instant(Err("no device attached".into()))));
        app.start(Job::ScanDevice);
        app.poll();

        match app.view() {
            View::Failed(message) => assert!(message.contains("no device")),
            other => panic!("expected failure, got {other:?}"),
        }
    }

    #[test]
    fn a_second_job_cannot_start_while_one_is_running() {
        let mut app = app_with(Box::new(Never));
        app.start(Job::DemoHealthy);
        assert!(app.is_busy());

        app.start(Job::DemoCompromised);
        assert!(
            matches!(app.view(), View::Running(Job::DemoHealthy)),
            "the second job must not replace the first"
        );
    }

    #[test]
    fn a_worker_that_dies_silently_does_not_hang_the_interface() {
        struct Dies;
        impl Launcher for Dies {
            fn launch(&self, _job: Job) -> Receiver<ScanResult> {
                let (_, rx) = mpsc::channel();
                rx // sender dropped immediately
            }
        }

        let mut app = app_with(Box::new(Dies));
        app.start(Job::ScanDevice);
        assert!(app.poll());
        assert!(matches!(app.view(), View::Failed(_)));
        assert!(!app.is_busy());
    }
}
