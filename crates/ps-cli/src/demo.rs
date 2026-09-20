//! Command-line adapter for the shared fixture devices.
//!
//! The fixtures and the pipeline live in [`ps_analyze::demo`] so that every
//! front end shows the same thing. This module only maps the clap argument
//! onto them, which keeps clap out of the library crates.

use anyhow::Result;
use clap::ValueEnum;
use ps_analyze::demo;
use ps_model::Report;

/// Which fixture device to examine.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum Scenario {
    /// A device with nothing wrong with it at app level.
    Healthy,
    /// A device showing the full range of app-tier problems.
    Compromised,
}

impl From<Scenario> for demo::Scenario {
    fn from(value: Scenario) -> Self {
        match value {
            Scenario::Healthy => Self::Healthy,
            Scenario::Compromised => Self::Compromised,
        }
    }
}

/// Run the full pipeline against the chosen fixture.
pub(crate) async fn run(scenario: Scenario) -> Result<Report> {
    Ok(demo::run_now(scenario.into()).await?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use ps_model::Verdict;

    #[tokio::test]
    async fn the_cli_adapter_reaches_the_shared_fixtures() {
        let healthy = run(Scenario::Healthy).await.unwrap();
        assert!(matches!(
            healthy.verdict(),
            Verdict::NoIndicatorsFound { .. }
        ));

        let compromised = run(Scenario::Compromised).await.unwrap();
        assert!(matches!(
            compromised.verdict(),
            Verdict::IndicatorsFound { .. }
        ));
    }
}
