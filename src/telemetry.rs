//! JSONL security audit events with secret redaction, and a line writer shared with stderr.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::control_plane::{AuditSink, ControlPlaneError};
use crate::protocol::{Decision, Severity};
use crate::taint::TaintLevel;

/// The marker that tells an audit line apart from other lines on the same stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventKind {
    /// One guardrail decision about one `tools/call` or `resources/read`.
    #[serde(rename = "mcp_guardrail_audit")]
    McpGuardrailAudit,
}

/// One audit record: what was asked, what the policy decided, and why.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecurityAuditEvent {
    /// The record marker, always `mcp_guardrail_audit`.
    pub event: AuditEventKind,
    /// Milliseconds since the Unix epoch when the decision was made.
    pub timestamp_ms: u64,
    /// The proxy session that made the decision.
    pub session_id: String,
    /// The call's position in the session, starting at 1.
    pub sequence: u64,
    /// The JSON-RPC method, `tools/call` or `resources/read`.
    pub method: String,
    /// The tool name, or the resource URI for a resource read.
    pub tool_name: String,
    /// What the policy decided.
    pub decision: Decision,
    /// The id of the rule that decided.
    pub rule_id: String,
    /// How serious the matched rule rates the call.
    pub severity: Severity,
    /// The rule's explanation.
    pub reason: String,
    /// The session taint level before the call.
    pub taint_level: TaintLevel,
    /// The taint origins behind the decision, oldest first.
    pub taint_chain: Vec<String>,
    /// Whether the call went on to the child.
    pub forwarded: bool,
    /// Microseconds the decision took.
    pub latency_us: u64,
    /// The call's arguments as the host sent them.
    pub arguments: Value,
}

/// A secret kind and the pattern that finds it.
struct SecretPattern {
    kind: &'static str,
    regex: Regex,
}

/// The patterns in the order `redact_secrets` applies them.
fn secret_patterns() -> &'static [SecretPattern] {
    static PATTERNS: OnceLock<Vec<SecretPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let sources = [
            (
                "pem-private-key",
                r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
            ),
            ("bearer-token", r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*"),
            (
                "github-token",
                r"(?P<prefix>^|[^A-Za-z0-9]|%[0-9A-Fa-f]{2})ghp_[A-Za-z0-9]{36}\b",
            ),
            (
                "aws-access-key-id",
                r"(?P<prefix>^|[^A-Za-z0-9]|%[0-9A-Fa-f]{2})AKIA[0-9A-Z]{16}\b",
            ),
            (
                "sk-api-key",
                r"(?P<prefix>^|[^A-Za-z0-9]|%[0-9A-Fa-f]{2})sk-[A-Za-z0-9_\-]{16,}",
            ),
        ];
        sources
            .into_iter()
            .map(|(kind, source)| SecretPattern {
                kind,
                regex: Regex::new(source).expect("the secret pattern is a valid regex"),
            })
            .collect()
    })
}

/// Replaces each secret in `text` with `[REDACTED:<kind>]`. A pattern's `prefix` group, the
/// non-alphanumeric character or percent-encoded byte before a token, stays in the output.
pub fn redact_secrets(text: &str) -> String {
    let mut redacted = text.to_string();
    for pattern in secret_patterns() {
        let replacement = format!("${{prefix}}[REDACTED:{}]", pattern.kind);
        redacted = pattern
            .regex
            .replace_all(&redacted, replacement.as_str())
            .into_owned();
    }
    redacted
}

/// Redacts every string leaf and every object key in `value`.
pub fn redact_value(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(redact_secrets(text)),
        Value::Array(items) => Value::Array(items.iter().map(redact_value).collect()),
        Value::Object(entries) => {
            let mut redacted = Map::new();
            for (key, entry) in entries {
                redacted.insert(redact_secrets(key), redact_value(entry));
            }
            Value::Object(redacted)
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
    }
}

/// The audit line for `event`, with the four host-copied fields redacted.
pub fn redacted_event_value(event: &SecurityAuditEvent) -> Value {
    let mut value = serde_json::to_value(event).expect("an audit event serializes to JSON");
    if let Value::Object(fields) = &mut value {
        for name in ["tool_name", "reason"] {
            if let Some(Value::String(text)) = fields.get_mut(name) {
                *text = redact_secrets(text);
            }
        }
        if let Some(Value::Array(entries)) = fields.get_mut("taint_chain") {
            for entry in entries {
                if let Value::String(text) = entry {
                    *text = redact_secrets(text);
                }
            }
        }
        if let Some(arguments) = fields.get_mut("arguments") {
            *arguments = redact_value(arguments);
        }
    }
    value
}

/// Redacts `event` and sends it to `sink`.
pub fn emit_event(
    sink: &dyn AuditSink,
    event: &SecurityAuditEvent,
) -> Result<(), ControlPlaneError> {
    sink.emit(&redacted_event_value(event))
}

/// A writer and whether its last write left a partial line behind.
struct LineState {
    writer: Box<dyn Write + Send>,
    needs_newline: bool,
}

/// Writes whole lines to one destination; clones share the destination and its lock.
#[derive(Clone)]
pub struct SharedLineWriter {
    state: Arc<Mutex<LineState>>,
}

impl SharedLineWriter {
    /// A writer over the process's standard error.
    pub fn stderr() -> Self {
        Self::from_writer(Box::new(io::stderr()))
    }

    /// A writer over `writer`.
    pub fn from_writer(writer: Box<dyn Write + Send>) -> Self {
        Self {
            state: Arc::new(Mutex::new(LineState {
                writer,
                needs_newline: false,
            })),
        }
    }

    /// Writes `line` and a newline, then flushes.
    ///
    /// After a failed write the next call first writes a newline, so a partial
    /// line never joins the line that follows it.
    pub fn write_line(&self, line: &[u8]) -> io::Result<()> {
        self.try_write_line(line).map_err(|error| match error {
            ControlPlaneError::Io(io_error) => io_error,
            other => io::Error::other(other),
        })
    }

    /// `write_line`, with a poisoned lock reported as `Unavailable`.
    fn try_write_line(&self, line: &[u8]) -> Result<(), ControlPlaneError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ControlPlaneError::Unavailable("line writer lock poisoned".to_string()))?;
        let result = Self::write_locked(&mut state, line);
        if result.is_err() {
            state.needs_newline = true;
        }
        Ok(result?)
    }

    fn write_locked(state: &mut LineState, line: &[u8]) -> io::Result<()> {
        if state.needs_newline {
            state.writer.write_all(b"\n")?;
            state.needs_newline = false;
        }
        let mut buffer = Vec::with_capacity(line.len() + 1);
        buffer.extend_from_slice(line);
        buffer.push(b'\n');
        state.writer.write_all(&buffer)?;
        state.writer.flush()
    }
}

/// An [`AuditSink`] that writes one JSON object per line.
pub struct JsonlAuditSink {
    writer: SharedLineWriter,
}

impl JsonlAuditSink {
    /// Opens `path` for appending, creating it with mode 0600 when missing.
    pub fn create(path: &Path) -> io::Result<Self> {
        let mut options = OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        Ok(Self::from_writer(Box::new(file)))
    }

    /// A sink over `writer`.
    pub fn from_writer(writer: Box<dyn Write + Send>) -> Self {
        Self::from_shared(SharedLineWriter::from_writer(writer))
    }

    /// A sink over a line writer that other writers share.
    pub fn from_shared(writer: SharedLineWriter) -> Self {
        Self { writer }
    }
}

impl AuditSink for JsonlAuditSink {
    fn emit(&self, event: &Value) -> Result<(), ControlPlaneError> {
        let line = serde_json::to_vec(event)?;
        self.writer.try_write_line(&line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Decision, Severity};
    use crate::taint::TaintLevel;
    use serde_json::{Value, json};
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    const PLANTED_TOKEN: &str = "ghp_REPLAYfake0123456789abcdefghijklmnop";

    /// An in-memory writer whose bytes the test reads back.
    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedBuffer {
        fn text(&self) -> String {
            let bytes = self.0.lock().expect("buffer lock").clone();
            String::from_utf8(bytes).expect("the buffer holds UTF-8")
        }
    }

    impl Write for SharedBuffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("buffer lock").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Accepts 10 bytes on its first write, fails its second write, then
    /// accepts every later write.
    #[derive(Clone, Default)]
    struct FailsAfterTenBytes(Arc<Mutex<(usize, Vec<u8>)>>);

    impl FailsAfterTenBytes {
        fn text(&self) -> String {
            let bytes = self.0.lock().expect("writer lock").1.clone();
            String::from_utf8(bytes).expect("the writer holds UTF-8")
        }
    }

    impl Write for FailsAfterTenBytes {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut state = self.0.lock().expect("writer lock");
            state.0 += 1;
            match state.0 {
                1 => {
                    let accepted = bytes.len().min(10);
                    state.1.extend_from_slice(&bytes[..accepted]);
                    Ok(accepted)
                }
                2 => Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed")),
                _ => {
                    state.1.extend_from_slice(bytes);
                    Ok(bytes.len())
                }
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A tainted, denied `Shell` call event with the given host-supplied fields.
    fn audit_event(tool_name: &str, taint_chain: &[&str], arguments: Value) -> SecurityAuditEvent {
        SecurityAuditEvent {
            event: AuditEventKind::McpGuardrailAudit,
            timestamp_ms: 1_767_225_600_000,
            session_id: "session-1".to_string(),
            sequence: 2,
            method: "tools/call".to_string(),
            tool_name: tool_name.to_string(),
            decision: Decision::Deny,
            rule_id: "tainted-deny-shell-exec".to_string(),
            severity: Severity::Critical,
            reason: "shell call after untrusted input".to_string(),
            taint_level: TaintLevel::Tainted,
            taint_chain: taint_chain.iter().map(|entry| entry.to_string()).collect(),
            forwarded: false,
            latency_us: 42,
            arguments,
        }
    }

    #[test]
    fn emit_event_redacts_keys_tool_name_and_taint_chain() {
        let buffer = SharedBuffer::default();
        let sink = JsonlAuditSink::from_writer(Box::new(buffer.clone()));
        let event = audit_event(
            "lookup-ghp_REPLAYfake0123456789abcdefghijklmnop",
            &["1:fetch-ghp_REPLAYfake0123456789abcdefghijklmnop"],
            json!({"ghp_REPLAYfake0123456789abcdefghijklmnop": "key holds the token"}),
        );
        emit_event(&sink, &event).expect("the in-memory sink accepts the line");
        let text = buffer.text();
        let line: Value = serde_json::from_str(text.trim_end()).expect("one JSON line");
        assert!(
            !text.contains(PLANTED_TOKEN),
            "audit line leaks the token: {text}"
        );
        assert_eq!(line["tool_name"], "lookup-[REDACTED:github-token]");
        assert_eq!(
            line["taint_chain"],
            json!(["1:fetch-[REDACTED:github-token]"])
        );
        assert_eq!(
            line["arguments"]["[REDACTED:github-token]"],
            "key holds the token"
        );
    }

    #[test]
    fn audit_line_carries_event_field() {
        let buffer = SharedBuffer::default();
        let sink = JsonlAuditSink::from_writer(Box::new(buffer.clone()));
        let event = audit_event("Shell", &["1:WebFetch"], json!({"command": "ls"}));
        emit_event(&sink, &event).expect("the in-memory sink accepts the line");
        let text = buffer.text();
        let line: Value = serde_json::from_str(
            text.strip_suffix('\n')
                .expect("the audit line ends with a newline"),
        )
        .expect("the audit line is one JSON object");
        assert_eq!(line["event"], "mcp_guardrail_audit");
    }

    #[test]
    fn write_line_after_failed_write_starts_on_new_line() {
        let writer = FailsAfterTenBytes::default();
        let lines = SharedLineWriter::from_writer(Box::new(writer.clone()));
        let failed = lines.write_line(br#"{"event":"mcp_guardrail_audit","sequence":1}"#);
        lines
            .write_line(br#"{"event":"mcp_guardrail_audit","sequence":2}"#)
            .expect("the writer accepts the next line");
        let text = writer.text();
        let after_fragment = text
            .get(10..)
            .unwrap_or_else(|| panic!("the writer holds fewer than 10 bytes: {text:?}"));
        let next_line = after_fragment
            .strip_prefix('\n')
            .and_then(|rest| rest.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("the next line does not start on a new line: {text:?}"));
        let parsed: Value = serde_json::from_str(next_line).expect("the next line parses as JSON");
        assert!(failed.is_err(), "the failed write is reported");
        assert_eq!(&text[..10], r#"{"event":""#);
        assert_eq!(parsed["sequence"], 2);
    }

    /// One row per secret kind, a PEM block with no `END` line, and a percent-encoded token.
    const SECRET_ROWS: [(&str, &str); 8] = [
        (
            "key -----BEGIN RSA PRIVATE KEY-----\nMIIBreplayFAKEkeyMATERIAL\n-----END RSA PRIVATE KEY----- end",
            "key [REDACTED:pem-private-key] end",
        ),
        (
            "key -----BEGIN PRIVATE KEY-----\nMIIBreplayFAKEkeyMATERIAL\nno end line",
            "key [REDACTED:pem-private-key]",
        ),
        (
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyZXBsYXkifQ.c2lnbmF0dXJl",
            "Authorization: [REDACTED:bearer-token]",
        ),
        (
            "github ghp_REPLAYfake0123456789abcdefghijklmnop done",
            "github [REDACTED:github-token] done",
        ),
        (
            "aws AKIAREPLAYFAKE000001 done",
            "aws [REDACTED:aws-access-key-id] done",
        ),
        (
            "openai sk-proj-REPLAYfakeKEY0123456789abcdef",
            "openai [REDACTED:sk-api-key]",
        ),
        (
            "url https://x.example/?token%3Dghp_REPLAYfake0123456789abcdefghijklmnop end",
            "url https://x.example/?token%3D[REDACTED:github-token] end",
        ),
        (
            "GITHUB_TOKEN_ghp_REPLAYfake0123456789abcdefghijklmnop",
            "GITHUB_TOKEN_[REDACTED:github-token]",
        ),
    ];

    #[test]
    fn redact_secrets_replaces_each_secret_kind() {
        for (text, expected) in SECRET_ROWS {
            assert_eq!(redact_secrets(text), expected, "input {text:?}");
        }
    }
}
