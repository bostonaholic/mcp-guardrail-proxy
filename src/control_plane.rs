//! Seams for a remote control plane, with local defaults that need no network.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Why a control-plane operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ControlPlaneError {
    /// A local read or write failed.
    #[error("control plane I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A value could not be encoded or decoded as JSON.
    #[error("control plane serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// The provider cannot serve the request right now.
    #[error("control plane unavailable: {0}")]
    Unavailable(String),
}

/// Supplies the policy as TOML text.
pub trait PolicyProvider: Send + Sync {
    /// The raw TOML policy text.
    fn policy_source(&self) -> Result<String, ControlPlaneError>;
    /// A short label for where the policy comes from.
    fn describe(&self) -> String;
}

/// Receives one structured security event per decision.
pub trait AuditSink: Send + Sync {
    /// Records `event`; an error means the event was not durably recorded.
    fn emit(&self, event: &serde_json::Value) -> Result<(), ControlPlaneError>;
}

/// Decides whether a call that requires approval may proceed.
pub trait ApprovalBroker: Send + Sync {
    /// Asks for a verdict on `request`, without blocking on a human.
    fn request_approval(&self, request: &ApprovalRequest) -> ApprovalOutcome;
}

/// What an approver sees about a held call.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// The proxy session that holds the call.
    pub session_id: String,
    /// The id of the rule that requires approval.
    pub rule_id: String,
    /// The tool the call targets.
    pub tool_name: String,
    /// The rule's explanation.
    pub reason: String,
    /// The taint origins behind the decision, oldest first.
    pub taint_chain: Vec<String>,
}

/// The verdict of an [`ApprovalBroker`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// The call may proceed.
    Approved,
    /// The call is refused.
    Denied,
    /// No verdict yet; the host gets an approval-required error.
    Pending,
}

/// Reads the policy from a local TOML file on each request.
#[derive(Clone, Debug)]
pub struct FilePolicyProvider {
    path: PathBuf,
}

impl FilePolicyProvider {
    /// A provider for the TOML file at `path`; nothing is read until `policy_source`.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl PolicyProvider for FilePolicyProvider {
    fn policy_source(&self) -> Result<String, ControlPlaneError> {
        Ok(fs::read_to_string(&self.path)?)
    }

    fn describe(&self) -> String {
        self.path.display().to_string()
    }
}

/// An [`AuditSink`] that discards every event.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullAuditSink;

impl AuditSink for NullAuditSink {
    fn emit(&self, _event: &serde_json::Value) -> Result<(), ControlPlaneError> {
        Ok(())
    }
}

/// An [`ApprovalBroker`] that leaves every request pending.
#[derive(Clone, Copy, Debug, Default)]
pub struct PendingApprovalBroker;

impl ApprovalBroker for PendingApprovalBroker {
    fn request_approval(&self, _request: &ApprovalRequest) -> ApprovalOutcome {
        ApprovalOutcome::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_policy_provider_reads_toml_text() {
        let dir = tempfile::TempDir::new().expect("create a temp dir");
        let path = dir.path().join("policy.toml");
        let text = "# local policy\n[[rules]]\nid = \"deny-shell\"\ndescription = \"no shell\"\ntool_regex = '^Shell$'\ndecision = \"deny\"\nseverity = \"high\"\n";
        std::fs::write(&path, text).expect("write the policy file");
        let provider = FilePolicyProvider::new(path.clone());
        assert_eq!(
            provider.policy_source().expect("the file is readable"),
            text
        );
        assert_eq!(provider.describe(), path.display().to_string());
    }
}
