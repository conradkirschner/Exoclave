//! Window shell for the exoclave desktop interface.
//!
//! Everything here is plumbing: open a window, and run adb off the UI thread
//! so the interface stays responsive while a slow or half-awake phone is
//! polled. All the interface logic lives in the `ps-gui` library, which has no
//! windowing dependency and is tested headlessly.

use anyhow::Result;
use ps_adb::{Device, ProcessShell, devices};
use ps_analyze::Observations;
use ps_gui::{Backend, ExoclaveApp, ProbeResult, ScanResult};
use std::sync::mpsc::{self, Receiver};
use tokio::runtime::Runtime;

fn main() -> Result<()> {
    // One runtime for the process, owned by the backend and kept alive for as
    // long as the window is.
    let runtime = Runtime::new()?;

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 840.0])
            .with_min_inner_size([760.0, 600.0])
            .with_title("Exoclave"),
        ..eframe::NativeOptions::default()
    };

    let result = eframe::run_native(
        "Exoclave",
        options,
        Box::new(move |cc| {
            let backend = TokioBackend {
                runtime,
                ctx: cc.egui_ctx.clone(),
            };
            Ok(Box::new(ExoclaveApp::new(Box::new(backend))))
        }),
    );

    // eframe's error type is not `std::error::Error` on every backend, so it
    // is flattened rather than propagated with `?`.
    result.map_err(|e| anyhow::anyhow!("could not open a window: {e}"))
}

/// Runs adb on a Tokio runtime and wakes the interface when it answers.
struct TokioBackend {
    runtime: Runtime,
    ctx: egui::Context,
}

impl TokioBackend {
    /// Spawn `work`, deliver its result on a channel, and nudge the window to
    /// redraw — it may be idle and asleep when the answer arrives.
    fn dispatch<T, F>(&self, work: F) -> Receiver<T>
    where
        T: Send + 'static,
        F: std::future::Future<Output = T> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        let ctx = self.ctx.clone();

        self.runtime.spawn(async move {
            let outcome = work.await;
            let _ = tx.send(outcome);
            ctx.request_repaint();
        });

        rx
    }
}

impl Backend for TokioBackend {
    fn scan(&self, serial: String) -> Receiver<ScanResult> {
        self.dispatch(async move {
            let shell = ProcessShell::default().with_serial(serial.clone());
            let device = Device::new(shell);

            let observations = Observations::collect(&device, &serial)
                .await
                .map_err(|e| e.to_string())?;

            // No indicator feed is wired into the desktop interface yet, so
            // this runs the heuristic detectors only. The report's coverage
            // statement says so rather than hiding it.
            let indicators = ps_analyze::IndicatorSet::new();
            Ok(ps_analyze::report(
                &observations,
                &indicators,
                chrono::Utc::now(),
            ))
        })
    }

    fn probe(&self) -> Receiver<ProbeResult> {
        self.dispatch(async {
            devices::list(&ProcessShell::default())
                .await
                .map_err(|e| e.to_string())
        })
    }
}
