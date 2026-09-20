//! Headless rendering tests.
//!
//! egui lays out and produces text shapes without a window, a GPU or a display
//! server, so the interface can be rendered in CI and asserted on as text.
//! These check the properties the project rests on: that the connect screen
//! teaches rather than just failing, that a report which found nothing still
//! says what went unexamined, and that the word *clean* never reaches the
//! screen.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chrono::Utc;
use egui::{Pos2, RawInput, Rect, Vec2, epaint::Shape};
use ps_gui::{Backend, ExoclaveApp, ProbeResult, ScanResult};
use ps_model::{
    Confidence, CoverageStatus, DeviceEntry, DeviceIdentity, DeviceState, Evidence, FindingBuilder,
    Report, Severity, SourceRef, ThreatTier, TierCoverage, TrustBasis,
};
use std::sync::mpsc::{self, Receiver};

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

fn entry(state: DeviceState) -> DeviceEntry {
    DeviceEntry {
        serial: "1234ABCD".to_owned(),
        state,
        model: Some("Mi_11".to_owned()),
    }
}

fn quiet_report() -> Report {
    let mut report = Report::new(
        DeviceIdentity {
            serial: "TEST".into(),
            manufacturer: Some("Xiaomi".into()),
            model: Some("Mi 11".into()),
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

fn app_with(probe: ProbeResult, scan: ScanResult) -> ExoclaveApp {
    ExoclaveApp::new(Box::new(Fake { scan, probe }))
}

fn app_showing(report: Report) -> ExoclaveApp {
    let mut app = app_with(Ok(vec![entry(DeviceState::Ready)]), Ok(report));
    app.request_probe();
    app.poll();
    app.start_scan("1234ABCD".to_owned());
    app.poll();
    app
}

#[test]
fn the_connect_screen_teaches_the_usb_debugging_steps() {
    let mut app = app_with(Ok(vec![]), Ok(quiet_report()));
    let text = rendered_text(&mut app);

    assert!(text.contains("EXOCLAVE"), "got: {text}");
    assert!(text.contains("USB debugging"), "got: {text}");
    assert!(text.contains("Developer options"), "got: {text}");
    assert!(text.contains("Build number"), "got: {text}");
}

#[test]
fn the_connect_screen_names_the_xiaomi_path_because_it_differs() {
    let mut app = app_with(Ok(vec![]), Ok(quiet_report()));
    let text = rendered_text(&mut app);

    assert!(text.contains("MIUI"), "got: {text}");
    assert!(text.contains("Additional settings"), "got: {text}");
}

#[test]
fn a_charge_only_cable_is_offered_as_an_explanation_for_seeing_nothing() {
    let mut app = app_with(Ok(vec![]), Ok(quiet_report()));
    let text = rendered_text(&mut app);

    assert!(text.contains("No phone detected"), "got: {text}");
    assert!(
        text.contains("cable") && text.contains("data"),
        "a cable with no data wires is the most common cause; got: {text}"
    );
}

#[test]
fn an_unauthorised_phone_is_shown_with_the_action_that_fixes_it() {
    let mut app = app_with(
        Ok(vec![entry(DeviceState::Unauthorized)]),
        Ok(quiet_report()),
    );
    let text = rendered_text(&mut app);

    assert!(text.contains("Mi 11"), "got: {text}");
    assert!(text.contains("Allow USB debugging"), "got: {text}");
    assert!(
        !text.contains("Examine this phone"),
        "an unauthorised phone must not offer a scan; got: {text}"
    );
}

#[test]
fn a_ready_phone_offers_the_scan() {
    let mut app = app_with(Ok(vec![entry(DeviceState::Ready)]), Ok(quiet_report()));
    let text = rendered_text(&mut app);

    assert!(text.contains("Connected and authorised"), "got: {text}");
    assert!(text.contains("Examine this phone"), "got: {text}");
}

#[test]
fn a_missing_adb_is_explained_rather_than_shown_as_a_raw_error() {
    let mut app = app_with(
        Err("could not run `adb`: program not found".to_owned()),
        Ok(quiet_report()),
    );
    let text = rendered_text(&mut app);

    assert!(text.contains("Could not ask adb"), "got: {text}");
    assert!(text.contains("platform-tools"), "got: {text}");
}

#[test]
fn nothing_in_the_interface_offers_demonstration_or_sample_data() {
    for probe in [
        Ok(vec![]),
        Ok(vec![entry(DeviceState::Ready)]),
        Ok(vec![entry(DeviceState::Unauthorized)]),
    ] {
        let mut app = app_with(probe, Ok(quiet_report()));
        let text = rendered_text(&mut app).to_lowercase();

        for forbidden in ["demo", "sample", "example device", "mock"] {
            assert!(!text.contains(forbidden), "found {forbidden:?} in: {text}");
        }
    }
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

        // Checked as phrases rather than the bare word: the cleanup section is
        // legitimately headed "Cleanup", and a substring match on "clean"
        // would forbid the tool from offering to clean anything.
        for reassurance in [
            "is clean",
            "looks clean",
            "device is safe",
            "no threats",
            "you are safe",
            "nothing to worry",
        ] {
            assert!(
                !text.contains(reassurance),
                "found {reassurance:?} in: {text}"
            );
        }
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
fn a_failed_scan_shows_the_reason_and_a_way_back() {
    let mut app = app_with(
        Ok(vec![entry(DeviceState::Ready)]),
        Err("device is unauthorised: accept the USB debugging prompt on the phone".to_owned()),
    );
    app.request_probe();
    app.poll();
    app.start_scan("1234ABCD".to_owned());
    app.poll();

    let text = rendered_text(&mut app);
    assert!(text.contains("did not complete"), "got: {text}");
    assert!(text.contains("unauthorised"), "got: {text}");
    assert!(text.contains("Back"), "got: {text}");
}
