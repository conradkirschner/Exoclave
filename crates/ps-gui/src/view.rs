//! Screen drawing.
//!
//! The ordering here is a deliberate argument, not a layout convenience.
//! Coverage comes *before* findings, because the most misleading possible
//! reading of this tool is "it found nothing, so the phone is fine". A user who
//! stops reading after the first screenful must still have seen which tiers
//! went unexamined.

use crate::{Job, View, theme};
use egui::{Align, Layout, RichText, Ui};
use ps_model::{Finding, Report};

/// Title bar and the controls. Returns a job if the user started one.
pub fn header(ui: &mut Ui, busy: bool) -> Option<Job> {
    let mut started = None;

    ui.horizontal(|ui| {
        ui.label(RichText::new("EXOCLAVE").size(19.0).strong());
        ui.label(
            RichText::new("off-device examination")
                .size(12.0)
                .color(theme::muted(ui.visuals().dark_mode)),
        );

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            // Reverse order: right-to-left layout places the first added
            // widget furthest right.
            for job in [Job::DemoHealthy, Job::DemoCompromised, Job::ScanDevice] {
                if ui
                    .add_enabled(!busy, egui::Button::new(job.label()))
                    .clicked()
                {
                    started = Some(job);
                }
            }
        });
    });

    ui.separator();
    started
}

/// The main area.
pub fn body(ui: &mut Ui, view: &View) {
    match view {
        View::Idle => idle(ui),
        View::Running(job) => running(ui, *job),
        View::Failed(message) => failed(ui, message),
        View::Ready(report) => self::report(ui, report),
    }
}

fn idle(ui: &mut Ui) {
    let dark = ui.visuals().dark_mode;
    ui.add_space(theme::GAP_L);
    ui.label(RichText::new("Nothing examined yet.").size(15.0).strong());
    ui.add_space(theme::GAP_S);
    ui.label(
        RichText::new(
            "Connect an Android device with USB debugging enabled and choose \
             \u{201c}Scan connected device\u{201d}, or run one of the fixture \
             devices to see how a report reads.",
        )
        .color(theme::muted(dark)),
    );
}

fn running(ui: &mut Ui, job: Job) {
    ui.add_space(theme::GAP_L);
    ui.horizontal(|ui| {
        ui.spinner();
        ui.label(RichText::new(job.progress()).size(15.0));
    });
}

fn failed(ui: &mut Ui, message: &str) {
    let dark = ui.visuals().dark_mode;
    ui.add_space(theme::GAP_L);
    ui.label(
        RichText::new("The scan did not complete")
            .size(15.0)
            .strong()
            .color(theme::severity_colour(ps_model::Severity::High, dark)),
    );
    ui.add_space(theme::GAP_S);
    ui.label(message);
}

fn report(ui: &mut Ui, report: &Report) {
    let dark = ui.visuals().dark_mode;

    ui.horizontal(|ui| {
        ui.label(
            RichText::new(report.device.display_name())
                .size(16.0)
                .strong(),
        );
        if let Some(patch) = &report.device.security_patch {
            ui.label(
                RichText::new(format!("security patch {patch}"))
                    .size(12.0)
                    .color(theme::muted(dark)),
            );
        }
        ui.label(
            RichText::new(report.generated_at.format("%Y-%m-%d %H:%M UTC").to_string())
                .size(12.0)
                .color(theme::muted(dark)),
        );
    });

    ui.add_space(theme::GAP_M);
    verdict(ui, report);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_space(theme::GAP_L);
            coverage(ui, report);
            ui.add_space(theme::GAP_L);
            findings(ui, report);
            ui.add_space(theme::GAP_L);
            feeds(ui, report);
        });
}

fn verdict(ui: &mut Ui, report: &Report) {
    let dark = ui.visuals().dark_mode;
    let verdict = report.verdict();

    // Tint by the worst thing present, so the banner cannot read as reassuring
    // when it is not.
    let worst = report
        .findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(ps_model::Severity::Info);
    let accent = theme::severity_colour(worst, dark);

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(
            RichText::new(verdict.headline())
                .size(15.0)
                .strong()
                .color(accent),
        );
    });
}

fn coverage(ui: &mut Ui, report: &Report) {
    let dark = ui.visuals().dark_mode;

    ui.label(
        RichText::new("What this scan could check")
            .size(14.0)
            .strong(),
    );
    ui.add_space(theme::GAP_S);

    for entry in &report.coverage {
        let colour = theme::coverage_colour(entry.status, dark);
        ui.horizontal_top(|ui| {
            ui.label(
                RichText::new(theme::coverage_label(entry.status))
                    .monospace()
                    .size(11.0)
                    .strong()
                    .color(colour),
            );
            ui.vertical(|ui| {
                ui.label(RichText::new(entry.tier.plain_language()).size(13.0));
                ui.label(
                    RichText::new(&entry.rationale)
                        .size(12.0)
                        .color(theme::muted(dark)),
                );
            });
        });
        ui.add_space(theme::GAP_S);
    }
}

fn findings(ui: &mut Ui, report: &Report) {
    let dark = ui.visuals().dark_mode;
    let ordered = report.findings_credible_against(ps_model::ThreatTier::AppLevel);

    ui.label(RichText::new("Findings").size(14.0).strong());
    ui.add_space(theme::GAP_S);

    if ordered.is_empty() {
        ui.label(
            RichText::new("Nothing was raised. See the coverage list above for what that does and does not mean.")
                .color(theme::muted(dark)),
        );
        return;
    }

    for (index, finding) in ordered.iter().enumerate() {
        // Titles repeat — the same package can hold several privileges — so
        // the index disambiguates the collapsing header's identity.
        ui.push_id(index, |ui| finding_row(ui, finding, dark));
    }
}

fn finding_row(ui: &mut Ui, finding: &Finding, dark: bool) {
    let colour = theme::severity_colour(finding.severity, dark);
    let title = RichText::new(format!(
        "{}  {}",
        theme::severity_marker(finding.severity),
        finding.title
    ))
    .color(colour)
    .strong();

    egui::CollapsingHeader::new(title)
        .default_open(finding.severity >= ps_model::Severity::High)
        .show(ui, |ui| {
            ui.label(&finding.detail);
            ui.add_space(theme::GAP_S);

            ui.label(
                RichText::new(format!(
                    "confidence: {} \u{00b7} concerns: {}",
                    finding.confidence,
                    finding.tier.slug()
                ))
                .size(11.0)
                .color(theme::muted(dark)),
            );

            // The caveat is the point of this tool. It is never collapsed away
            // from the evidence it qualifies.
            if let Some(basis) = finding.weakest_basis() {
                ui.label(
                    RichText::new(basis.caveat())
                        .size(11.0)
                        .italics()
                        .color(theme::muted(dark)),
                );
            }

            for evidence in &finding.evidence {
                ui.label(
                    RichText::new(format!("source: {}", evidence.source))
                        .size(11.0)
                        .monospace()
                        .color(theme::muted(dark)),
                );
            }
        });
}

fn feeds(ui: &mut Ui, report: &Report) {
    if report.feeds.is_empty() {
        return;
    }
    let dark = ui.visuals().dark_mode;

    ui.label(RichText::new("Indicator feeds").size(14.0).strong());
    ui.add_space(theme::GAP_S);
    for feed in &report.feeds {
        ui.label(
            RichText::new(format!(
                "{} \u{00b7} {} \u{00b7} {}",
                feed.name,
                feed.license,
                feed.digest.get(..12).unwrap_or(&feed.digest)
            ))
            .size(11.0)
            .color(theme::muted(dark)),
        );
    }
}
