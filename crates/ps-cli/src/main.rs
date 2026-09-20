//! exoclave command line.
//!
//! One rule governs the output of this binary: it never tells the user their
//! device is clean. It tells them what was checked, what was found, and — in
//! the same breath — which classes of compromise this kind of inspection
//! cannot see. See `ps-model` for why that distinction is structural rather
//! than editorial.

mod demo;
mod render;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use ps_adb::{Device, ProcessShell};
use ps_analyze::{IndicatorSet, Observations};
use ps_model::Report;
use std::path::{Path, PathBuf};
use tracing::warn;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "exoclave",
    version,
    about = "Examine an Android device from a computer it cannot tamper with.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Emit ANSI colour.
    #[arg(long, global = true, value_enum, default_value_t = ColourChoice::Auto)]
    colour: ColourChoice,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ColourChoice {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Collect device state over ADB and analyse it.
    Scan {
        /// Device serial. Required when more than one device is attached.
        #[arg(short, long)]
        serial: Option<String>,

        /// Path to the `adb` binary.
        #[arg(long, default_value = "adb", env = "PS_ADB_PATH")]
        adb: String,

        /// Indicator feed in exoclave feed format. Repeatable.
        #[arg(short, long = "feed", value_name = "FILE")]
        feeds: Vec<PathBuf>,

        /// Also write the full report as JSON.
        #[arg(long, value_name = "FILE")]
        json: Option<PathBuf>,
    },

    /// Run the real pipeline against a fixture device, with no phone attached.
    ///
    /// Same collectors, detectors and report as `scan` — only the transport is
    /// replaced. Useful for trying the tool out and for checking output
    /// changes in review.
    Demo {
        /// Which fixture device to examine.
        #[arg(value_enum, default_value_t = demo::Scenario::Compromised)]
        scenario: demo::Scenario,

        /// Also write the full report as JSON.
        #[arg(long, value_name = "FILE")]
        json: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("PS_LOG").unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Scan {
            serial,
            adb,
            feeds,
            json,
        } => {
            let report = scan(serial, &adb, &feeds).await?;
            emit(&report, json.as_deref(), cli.colour)
        }
        Command::Demo { scenario, json } => {
            let report = demo::run(scenario).await?;
            emit(&report, json.as_deref(), cli.colour)
        }
    }
}

/// Write the report out: JSON to a file if asked, rendered text to stdout.
fn emit(report: &Report, json: Option<&Path>, colour: ColourChoice) -> Result<()> {
    if let Some(path) = json {
        let encoded =
            serde_json::to_string_pretty(report).context("could not serialise the report")?;
        std::fs::write(path, encoded)
            .with_context(|| format!("could not write {}", path.display()))?;
    }

    let no_color = std::env::var_os("NO_COLOR").is_some();
    print!(
        "{}",
        render::report(report, resolve_colour(colour, no_color))
    );
    Ok(())
}

async fn scan(serial: Option<String>, adb: &str, feeds: &[PathBuf]) -> Result<Report> {
    let indicators = load_feeds(feeds)?;

    let mut shell = ProcessShell::default().with_program(adb);
    if let Some(serial) = serial.clone() {
        shell = shell.with_serial(serial);
    }

    let device = Device::new(shell);
    let label = serial.unwrap_or_else(|| "(default device)".to_owned());

    let observations = Observations::collect(&device, &label)
        .await
        .context("could not read basic properties from the device")?;

    for (input, reason) in observations.collection_gaps() {
        warn!(input, reason, "collector failed; coverage reduced");
    }

    Ok(ps_analyze::report(&observations, &indicators, Utc::now()))
}

fn load_feeds(paths: &[PathBuf]) -> Result<IndicatorSet> {
    let mut set = IndicatorSet::new();
    for path in paths {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("could not read feed {}", path.display()))?;
        set.load_feed(&raw)
            .with_context(|| format!("{} is not a valid indicator feed", path.display()))?;
    }
    if set.is_empty() {
        warn!("no indicator feeds loaded; known-malware matching is disabled");
    }
    Ok(set)
}

/// Colour policy, with the environment read by the caller so this stays a pure
/// function and can be tested without mutating process state.
const fn resolve_colour(choice: ColourChoice, no_color_set: bool) -> render::Colour {
    match choice {
        ColourChoice::Never => render::Colour::Never,
        // No TTY-detection dependency yet: honour the de facto standard
        // environment variable and otherwise stay colourful.
        ColourChoice::Auto if no_color_set => render::Colour::Never,
        ColourChoice::Always | ColourChoice::Auto => render::Colour::Always,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn no_color_is_honoured_in_auto_mode_but_never_overrides_an_explicit_choice() {
        assert_eq!(
            resolve_colour(ColourChoice::Auto, true),
            render::Colour::Never
        );
        assert_eq!(
            resolve_colour(ColourChoice::Auto, false),
            render::Colour::Always
        );
        assert_eq!(
            resolve_colour(ColourChoice::Always, true),
            render::Colour::Always
        );
    }

    #[test]
    fn a_missing_feed_file_is_an_error_with_the_path_in_it() {
        let err = load_feeds(&[PathBuf::from("does-not-exist.json")]).expect_err("should fail");
        assert!(err.to_string().contains("does-not-exist.json"));
    }
}
