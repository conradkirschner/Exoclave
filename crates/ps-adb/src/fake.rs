//! A replaying [`Shell`] for tests and fixtures.
//!
//! Analysis modules are the part of this tool most likely to be wrong, and they
//! are the part hardest to exercise against real hardware. Capturing genuine
//! command output once and replaying it here lets the whole detection pipeline
//! run in CI, on a machine with no phone attached.

use crate::{AdbError, AdbResult, Shell};
use std::collections::BTreeMap;
use std::future::Future;

/// Replays canned output keyed by the space-joined argument vector.
///
/// ```text
/// let shell = FakeShell::new()
///     .with("shell getprop", "[ro.product.model]: [Pixel 9]\n");
/// let identity = Device::new(shell).identity("SERIAL").await?;
/// assert_eq!(identity.display_name(), "Pixel 9");
/// ```
#[derive(Debug, Default, Clone)]
pub struct FakeShell {
    responses: BTreeMap<String, String>,
}

impl FakeShell {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register output for one invocation. `args` is the space-joined argument
    /// vector, e.g. `"shell pm list users"`.
    #[must_use]
    pub fn with(mut self, args: &str, output: &str) -> Self {
        self.responses.insert(args.to_owned(), output.to_owned());
        self
    }

    /// Commands registered so far, for assertions about coverage.
    #[must_use]
    pub fn registered(&self) -> Vec<&str> {
        self.responses.keys().map(String::as_str).collect()
    }
}

impl Shell for FakeShell {
    // Not `async fn`: there is nothing to await, and clippy rightly objects to
    // an async function that never yields.
    fn exec(&self, args: Vec<String>) -> impl Future<Output = AdbResult<String>> + Send {
        let key = args.join(" ");
        let result = self
            .responses
            .get(&key)
            .cloned()
            .ok_or_else(|| AdbError::CommandFailed {
                status: 127,
                stderr: format!(
                    "FakeShell has no response registered for `{key}`; registered: {:?}",
                    self.registered()
                ),
            });
        std::future::ready(result)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[tokio::test]
    async fn unregistered_commands_fail_with_a_readable_message() {
        let shell = FakeShell::new().with("shell getprop", "");
        let err = shell
            .exec(vec!["shell".to_owned(), "whoami".to_owned()])
            .await
            .expect_err("should fail");

        let message = err.to_string();
        assert!(message.contains("shell whoami"), "got: {message}");
        assert!(message.contains("shell getprop"), "got: {message}");
    }
}
