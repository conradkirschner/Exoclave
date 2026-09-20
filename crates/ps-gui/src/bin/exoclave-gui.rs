//! Window shell for the exoclave desktop interface.
//!
//! Everything here is plumbing: open a window, and run scans on a worker so
//! the interface stays responsive while ADB is slow. All the interface logic
//! lives in the `ps-gui` library, which has no windowing dependency and is
//! tested headlessly.

use anyhow::Result;
use ps_adb::{Device, ProcessShell};
use ps_analyze::{Observations, demo};
use ps_gui::{ExoclaveApp, Job, Launcher, ScanResult};
use std::sync::mpsc::{self, Receiver};
use tokio::runtime::Runtime;

fn main() -> Result<()> {
    // One runtime for the process, owned by the launcher and kept alive for
    // as long as the window is.
    let runtime = Runtime::new()?;

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 820.0])
            .with_min_inner_size([760.0, 560.0])
            .with_title("Exoclave"),
        ..eframe::NativeOptions::default()
    };

    let result = eframe::run_native(
        "Exoclave",
        options,
        Box::new(move |cc| {
            let launcher = TokioLauncher {
                runtime,
                ctx: cc.egui_ctx.clone(),
            };
            Ok(Box::new(ExoclaveApp::new(Box::new(launcher))))
        }),
    );

    // eframe's error type is not `std::error::Error` on every backend, so it is
    // flattened rather than propagated with `?`.
    result.map_err(|e| anyhow::anyhow!("could not open a window: {e}"))
}

/// Runs jobs on a Tokio runtime and wakes the interface when they finish.
struct TokioLauncher {
    runtime: Runtime,
    ctx: egui::Context,
}

impl Launcher for TokioLauncher {
    fn launch(&self, job: Job) -> Receiver<ScanResult> {
        let (tx, rx) = mpsc::channel();
        let ctx = self.ctx.clone();

        self.runtime.spawn(async move {
            let outcome = execute(job).await;
            let _ = tx.send(outcome);
            // The window may be idle and asleep; nudge it to draw the result.
            ctx.request_repaint();
        });

        rx
    }
}

async fn execute(job: Job) -> ScanResult {
    match job {
        Job::DemoHealthy => demo::run_now(demo::Scenario::Healthy)
            .await
            .map_err(|e| e.to_string()),
        Job::DemoCompromised => demo::run_now(demo::Scenario::Compromised)
            .await
            .map_err(|e| e.to_string()),
        Job::ScanDevice => scan_device().await,
    }
}

async fn scan_device() -> ScanResult {
    let device = Device::new(ProcessShell::default());

    let observations = Observations::collect(&device, "(default device)")
        .await
        .map_err(|e| e.to_string())?;

    // No indicator feed is wired into the desktop interface yet, so this runs
    // the heuristic detectors only. The report's coverage statement says so.
    let indicators = ps_analyze::IndicatorSet::new();
    Ok(ps_analyze::report(
        &observations,
        &indicators,
        chrono::Utc::now(),
    ))
}
