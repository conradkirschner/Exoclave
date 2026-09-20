//! Screen drawing.
//!
//! Two orderings here are deliberate arguments rather than layout convenience.
//!
//! On the connect screen, the live status sits *above* the instructions, so
//! someone who has already done the setup is not made to read it again — and
//! someone who has not gets told which step they are actually stuck on.
//!
//! On the report screen, coverage comes *before* findings, because the most
//! damaging possible misreading of this tool is "it found nothing, so the
//! phone is fine". A user who stops after the first screenful must still have
//! seen which tiers went unexamined.

use crate::{ExoclaveApp, Screen, theme};
use egui::{RichText, Ui};
use ps_model::{DeviceEntry, Finding, Report};

/// Something the user asked for while drawing a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Scan the device with this serial.
    Scan(String),
    /// Re-check the connection now.
    CheckAgain,
    /// Return to the connect screen.
    Back,
}

/// Title bar.
pub fn header(ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("EXOCLAVE").size(19.0).strong());
        ui.label(
            RichText::new("off-device examination of an Android phone")
                .size(12.0)
                .color(theme::muted(ui.visuals().dark_mode)),
        );
    });
    ui.separator();
}

/// The main area.
pub fn body(ui: &mut Ui, app: &ExoclaveApp) -> Option<Action> {
    match app.screen() {
        Screen::Connect => connect(ui, app),
        Screen::Scanning { device } => {
            scanning(ui, device);
            None
        }
        Screen::Failed(message) => failed(ui, message, app),
        Screen::Report(report) => report_screen(ui, report),
    }
}

// ---------------------------------------------------------------- connect ---

fn connect(ui: &mut Ui, app: &ExoclaveApp) -> Option<Action> {
    let mut action = None;

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            action = status_card(ui, app);
            ui.add_space(theme::GAP_L);
            instructions(ui);
            ui.add_space(theme::GAP_L);
            assurance(ui);
        });

    action
}

/// Live connection state. The first thing on the screen, because it is the
/// only part that changes.
fn status_card(ui: &mut Ui, app: &ExoclaveApp) -> Option<Action> {
    let dark = ui.visuals().dark_mode;
    let mut action = None;

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());

        if !app.has_probed() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Looking for a connected phone…").size(14.0));
            });
            return;
        }

        if let Some(error) = app.probe_error() {
            ui.label(
                RichText::new("Could not ask adb what is connected")
                    .size(14.0)
                    .strong()
                    .color(theme::severity_colour(ps_model::Severity::High, dark)),
            );
            ui.label(RichText::new(error).size(12.0).color(theme::muted(dark)));
            ui.add_space(theme::GAP_S);
            ui.label(
                RichText::new(
                    "Exoclave runs the `adb` command, so it has to be installed and on \
                     your PATH. It ships with the Android SDK platform-tools.",
                )
                .size(12.0)
                .color(theme::muted(dark)),
            );
        }

        match app.devices() {
            [] => {
                ui.label(
                    RichText::new("No phone detected")
                        .size(15.0)
                        .strong()
                        .color(theme::severity_colour(ps_model::Severity::Medium, dark)),
                );
                ui.add_space(theme::GAP_S);
                ui.label(
                    RichText::new(
                        "If the phone is plugged in and charging, the most likely causes are \
                         that USB debugging is not switched on yet, or that the cable carries \
                         power but no data. Work through the steps below.",
                    )
                    .size(12.0)
                    .color(theme::muted(dark)),
                );
            }
            devices => {
                for device in devices {
                    if let Some(chosen) = device_row(ui, device, app.is_scanning(), dark) {
                        action = Some(chosen);
                    }
                }
            }
        }

        ui.add_space(theme::GAP_M);
        if ui.button("Check again").clicked() {
            action = Some(Action::CheckAgain);
        }
    });

    action
}

fn device_row(ui: &mut Ui, device: &DeviceEntry, busy: bool, dark: bool) -> Option<Action> {
    let mut action = None;
    let scannable = device.state.is_scannable();

    let tint = if scannable {
        theme::coverage_colour(ps_model::CoverageStatus::Covered, dark)
    } else {
        theme::severity_colour(ps_model::Severity::Medium, dark)
    };

    ui.horizontal(|ui| {
        ui.label(RichText::new(device.display_name()).size(15.0).strong());
        ui.label(RichText::new(device.state.summary()).size(12.0).color(tint));
    });

    if let Some(step) = device.state.next_step() {
        ui.label(RichText::new(step).size(12.0).color(theme::muted(dark)));
    }

    if scannable {
        ui.add_space(theme::GAP_S);
        if ui
            .add_enabled(
                !busy,
                egui::Button::new(RichText::new("Examine this phone").strong()),
            )
            .clicked()
        {
            action = Some(Action::Scan(device.serial.clone()));
        }
    }

    ui.add_space(theme::GAP_S);
    action
}

fn instructions(ui: &mut Ui) {
    let dark = ui.visuals().dark_mode;

    ui.label(
        RichText::new("What you need to do on the phone")
            .size(15.0)
            .strong(),
    );
    ui.add_space(theme::GAP_S);
    ui.label(
        RichText::new(
            "Exoclave reads the phone over the Android Debug Bridge. That has to be \
             switched on by hand — deliberately, since it is what stops anyone reading \
             your phone just by plugging it in.",
        )
        .size(12.0)
        .color(theme::muted(dark)),
    );
    ui.add_space(theme::GAP_M);

    let steps: [(&str, &str); 5] = [
        (
            "Use a cable that carries data",
            "Many charging cables have no data wires. If the phone charges but nothing \
             appears here, try a different cable before anything else.",
        ),
        (
            "Unlock Developer options",
            "Settings \u{2192} About phone, then tap Build number seven times. On Xiaomi \
             (MIUI or HyperOS) tap MIUI version or OS version instead; on Samsung it is \
             under Software information.",
        ),
        (
            "Turn on USB debugging",
            "Settings \u{2192} Developer options \u{2192} USB debugging. On Xiaomi, \
             Developer options sits under Additional settings. Examining the phone needs \
             nothing more. Changing a setting on it \u{2014} cleanup, or routing its \
             traffic \u{2014} additionally needs \u{201c}USB debugging (Security \
             settings)\u{201d}, which Xiaomi gates behind a signed-in Mi account.",
        ),
        (
            "Connect by USB and unlock the screen",
            "Keep the phone unlocked while it is plugged in. Charging mode is fine; the \
             file-transfer mode is not required.",
        ),
        (
            "Accept the prompt on the phone",
            "A dialog asks \u{201c}Allow USB debugging?\u{201d}. Accept it and tick \
             \u{201c}Always allow from this computer\u{201d}. If it never appears, unplug \
             and replug the cable.",
        ),
    ];

    for (index, (title, detail)) in steps.iter().enumerate() {
        ui.horizontal_top(|ui| {
            ui.label(
                RichText::new(format!("{}.", index + 1))
                    .monospace()
                    .size(13.0)
                    .strong()
                    .color(theme::muted(dark)),
            );
            ui.vertical(|ui| {
                ui.label(RichText::new(*title).size(13.0).strong());
                ui.label(RichText::new(*detail).size(12.0).color(theme::muted(dark)));
            });
        });
        ui.add_space(theme::GAP_S);
    }
}

fn assurance(ui: &mut Ui) {
    let dark = ui.visuals().dark_mode;

    ui.separator();
    ui.add_space(theme::GAP_S);
    ui.label(
        RichText::new(
            "Exoclave installs nothing on the phone and changes nothing on it. It reads \
             what is already there and analyses it on this computer.",
        )
        .size(12.0)
        .color(theme::muted(dark)),
    );
    ui.label(
        RichText::new(
            "If you suspect stalkerware, put the phone in airplane mode before you start. \
             That prevents anyone wiping it remotely while you look.",
        )
        .size(12.0)
        .color(theme::muted(dark)),
    );
}

// ---------------------------------------------------------------- running ---

fn scanning(ui: &mut Ui, device: &str) {
    ui.add_space(theme::GAP_L);
    ui.horizontal(|ui| {
        ui.spinner();
        ui.label(RichText::new(format!("Reading {device} over ADB…")).size(15.0));
    });
    ui.add_space(theme::GAP_S);
    ui.label(
        RichText::new("Keep the phone unlocked and connected.")
            .size(12.0)
            .color(theme::muted(ui.visuals().dark_mode)),
    );
}

fn failed(ui: &mut Ui, message: &str, app: &ExoclaveApp) -> Option<Action> {
    let dark = ui.visuals().dark_mode;
    let mut action = None;

    ui.add_space(theme::GAP_L);
    ui.label(
        RichText::new("The scan did not complete")
            .size(15.0)
            .strong()
            .color(theme::severity_colour(ps_model::Severity::High, dark)),
    );
    ui.add_space(theme::GAP_S);
    ui.label(message);

    // The device may have recovered while this was on screen, so offer the way
    // back rather than making the user restart the program.
    if app.scannable().is_some() {
        ui.add_space(theme::GAP_M);
        ui.label(
            RichText::new("The phone is connected again.")
                .size(12.0)
                .color(theme::muted(dark)),
        );
    }

    ui.add_space(theme::GAP_M);
    if ui.button("Back").clicked() {
        action = Some(Action::Back);
    }
    action
}

// ----------------------------------------------------------------- report ---

fn report_screen(ui: &mut Ui, report: &Report) -> Option<Action> {
    let dark = ui.visuals().dark_mode;
    let mut action = None;

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
        if ui.button("Back").clicked() {
            action = Some(Action::Back);
        }
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
            cleanup(ui, report);
            ui.add_space(theme::GAP_L);
            feeds(ui, report);
        });

    action
}

/// What to do about what was found.
fn cleanup(ui: &mut Ui, report: &Report) {
    let dark = ui.visuals().dark_mode;
    let plan = ps_remediate::from_report(report);

    if plan.steps.is_empty() && plan.warnings.is_empty() {
        return;
    }

    ui.label(RichText::new("Cleanup").size(14.0).strong());
    ui.add_space(theme::GAP_S);

    for warning in &plan.warnings {
        ui.label(
            RichText::new(warning)
                .size(12.0)
                .color(theme::severity_colour(ps_model::Severity::Medium, dark)),
        );
        ui.add_space(theme::GAP_S);
    }

    let automatic = plan.automatic();
    if !automatic.is_empty() {
        ui.add_space(theme::GAP_S);
        ui.label(
            RichText::new("Exoclave can do these, in this order")
                .size(13.0)
                .strong(),
        );
        ui.label(
            RichText::new(
                "Ordering matters: capability is cut first, and device administrator \
                 rights have to go before an app can be removed at all.",
            )
            .size(11.0)
            .color(theme::muted(dark)),
        );
        ui.add_space(theme::GAP_S);

        for (index, step) in automatic.iter().enumerate() {
            ui.push_id(("auto", index), |ui| {
                egui::CollapsingHeader::new(RichText::new(&step.title).strong())
                    .default_open(true)
                    .show(ui, |ui| {
                        ui.label(RichText::new(&step.why).size(12.0));
                        if let Some(reversibility) = step.reversibility() {
                            ui.label(
                                RichText::new(format!("This {}.", reversibility.describes()))
                                    .size(11.0)
                                    .color(theme::muted(dark)),
                            );
                        }
                        if let Some(caution) = &step.caution {
                            ui.label(
                                RichText::new(caution)
                                    .size(11.0)
                                    .italics()
                                    .color(theme::muted(dark)),
                            );
                        }
                    });
            });
        }

        ui.add_space(theme::GAP_S);
        ui.label(
            RichText::new(
                "Carrying these out from the interface is not wired up yet, so for now \
                 they are a checklist rather than buttons.",
            )
            .size(11.0)
            .italics()
            .color(theme::muted(dark)),
        );
    }

    let manual = plan.manual();
    if !manual.is_empty() {
        ui.add_space(theme::GAP_M);
        ui.label(RichText::new("Only you can do these").size(13.0).strong());
        ui.add_space(theme::GAP_S);

        for (index, step) in manual.iter().enumerate() {
            ui.push_id(("manual", index), |ui| {
                egui::CollapsingHeader::new(RichText::new(&step.title).strong())
                    .default_open(true)
                    .show(ui, |ui| {
                        ui.label(RichText::new(&step.why).size(12.0));
                        ui.add_space(theme::GAP_S);
                        if let ps_remediate::Action::Manual { instructions } = &step.action {
                            for instruction in instructions {
                                ui.label(
                                    RichText::new(format!("\u{2022} {instruction}")).size(12.0),
                                );
                            }
                        }
                    });
            });
        }
    }
}

fn verdict(ui: &mut Ui, report: &Report) {
    let dark = ui.visuals().dark_mode;

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
            RichText::new(report.verdict().headline())
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
            RichText::new(
                "Nothing was raised. See the coverage list above for what that does and \
                 does not mean.",
            )
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
