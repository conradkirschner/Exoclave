//! Headless rendering tests.
//!
//! egui lays out and produces text shapes without a window, a GPU or a display
//! server, so the interface can be rendered in CI and asserted on as text.
//! These check the property the whole project rests on: that a report which
//! found nothing still tells the user what went unexamined, and never claims
//! the device is clean.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chrono::Utc;
use egui::{Pos2, RawInput, Rect, Vec2, epaint::Shape};
use ps_gui::{ExoclaveApp, Job, Launcher, ScanResult};
use ps_model::{
    Confidence, CoverageStatus, DeviceIdentity, Evidence, FindingBuilder, Report, Severity,
    SourceRef, ThreatTier, TierCoverage, TrustBasis,
};
use std::sync::mpsc::{self, Receiver};

struct Instant(ScanResult);

impl Launcher for Instant {
    fn launch(&self, _job: Job) -> Receiver<ScanResult> {
        let (tx, rx) = mpsc::channel();
        let _ = tx.send(self.0.clone());
        rx
    }
}

/// Render two frames and return every string that reached the screen.
///
/// Two passes because collapsing headers settle their open state on the second.
fn rendered_text(app: &mut ExoclaveApp) -> String {
    let ctx = egui::Context::default();
    let input = || RawInput {
        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(1280.0, 1024.0))),
        ..RawInput::default()
    };

    // egui hands back font-atlas updates that a real backend would upload to
    // the GPU. There is no GPU here, so they are discarded explicitly —
    // dropping them unhandled is a panic.
    let mut warmup = ctx.run_ui(input(), |ui| app.draw(ui));
    warmup.textures_delta.clear();

    let mut output = ctx.run_ui(input(), |ui| app.draw(ui));
    output.textures_delta.clear();

    let mut text = String::new();
    for clipped in &output.shapes {
        collect(&clipped.shape, &mut text);
    }
    text
}

fn collect(shape: &Shape, out: &mut String) {
    match shape {
        Shape::Text(t) => {
            out.push_str(t.galley.text());
            out.push('\n');
        }
        Shape::Vec(shapes) => {
            for s in shapes {
                collect(s, out);
            }
        }
        _ => {}
    }
}

fn quiet_report() -> Report {
    let mut report = Report::new(
        DeviceIdentity {
            serial: "TEST".into(),
            manufacturer: Some("Google".into()),
            model: Some("Pixel 8".into()),
            security_patch: Some("2026-08-01".into()),
            ..DeviceIdentity::default()
        },
        Utc::now(),
    );
    report.coverage = vec![
        TierCoverage {
            tier: ThreatTier::AppLevel,
            status: CoverageStatus::Covered,
            rationale: "Everything was collected.".to_owned(),
        },
        TierCoverage {
            tier: ThreatTier::RuntimeKernel,
            status: CoverageStatus::NotCovered,
            rationale: "Every input came from the device's own operating system.".to_owned(),
        },
    ];
    report
}

fn alarming_report() -> Report {
    let mut report = quiet_report();
    report.findings = vec![
        FindingBuilder::new("indicator.package-match", "TrackerPro is installed")
            .detail("Matches a known malicious indicator.")
            .severity(Severity::Critical)
            .confidence(Confidence::Confirmed)
            .tier(ThreatTier::AppLevel)
            .evidence(Evidence::new(
                SourceRef::new("adb/pm-list-packages.txt").at("com.demo.trackerpro"),
                TrustBasis::SelfReported,
                "com.demo.trackerpro",
            ))
            .build()
            .unwrap(),
    ];
    report
}

fn app_showing(report: Report) -> ExoclaveApp {
    let mut app = ExoclaveApp::new(Box::new(Instant(Ok(report))));
    app.start(Job::DemoHealthy);
    assert!(app.poll());
    app
}

#[test]
fn the_idle_screen_explains_what_to_do() {
    let mut app = ExoclaveApp::new(Box::new(Instant(Ok(quiet_report()))));
    let text = rendered_text(&mut app);

    assert!(text.contains("EXOCLAVE"), "got: {text}");
    assert!(text.contains("Nothing examined yet"), "got: {text}");
    assert!(text.contains("Scan connected device"), "got: {text}");
}

#[test]
fn a_report_that_found_nothing_still_shows_what_was_not_checked() {
    let mut app = app_showing(quiet_report());
    let text = rendered_text(&mut app);

    assert!(text.contains("NOT CHECKED"), "got: {text}");
    assert!(text.contains("not ruled out"), "got: {text}");
    assert!(text.contains("What this scan could check"), "got: {text}");
}

#[test]
fn the_interface_never_tells_the_user_the_device_is_clean() {
    for report in [quiet_report(), alarming_report()] {
        let mut app = app_showing(report);
        let text = rendered_text(&mut app).to_lowercase();

        assert!(!text.contains("clean"), "got: {text}");
        assert!(!text.contains("no threats"), "got: {text}");
        assert!(!text.contains("you are safe"), "got: {text}");
    }
}

#[test]
fn a_critical_finding_is_labelled_in_text_not_only_in_colour() {
    let mut app = app_showing(alarming_report());
    let text = rendered_text(&mut app);

    assert!(text.contains("CRITICAL"), "got: {text}");
    assert!(text.contains("TrackerPro is installed"), "got: {text}");
}

#[test]
fn a_serious_finding_is_expanded_by_default_with_its_caveat_visible() {
    let mut app = app_showing(alarming_report());
    let text = rendered_text(&mut app);

    assert!(
        text.contains("Matches a known malicious indicator"),
        "critical findings should open without a click; got: {text}"
    );
    assert!(
        text.contains("Code with system privileges could have altered this answer"),
        "the trust caveat must sit with the evidence; got: {text}"
    );
}

#[test]
fn a_failed_scan_shows_the_reason() {
    let mut app = ExoclaveApp::new(Box::new(Instant(Err(
        "no device is connected, or it has not authorised this computer".into(),
    ))));
    app.start(Job::ScanDevice);
    app.poll();

    let text = rendered_text(&mut app);
    assert!(text.contains("did not complete"), "got: {text}");
    assert!(text.contains("no device is connected"), "got: {text}");
}
