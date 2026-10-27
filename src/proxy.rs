//! The stdio interceptor: judges each host frame, audits it, and only then forwards it upstream.

use std::future::Future;
use std::io;
use std::pin::pin;
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::mpsc;

use crate::control_plane::{ApprovalBroker, ApprovalOutcome, ApprovalRequest, AuditSink};
use crate::policy::{Evaluation, PolicyEngine};
use crate::protocol::{
    Decision, FrameError, GuardrailErrorData, INVALID_PARAMS_CODE, INVALID_REQUEST_CODE,
    JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, McpCall, RequestId, Severity, classify_call,
    encode_frame, guardrail_error_response, parse_error_response, parse_frame,
    protocol_error_response,
};
use crate::taint::SessionTaintState;
use crate::telemetry::{
    AuditEventKind, SecurityAuditEvent, SharedLineWriter, emit_event, redacted_event_value,
};

/// The longest host frame or child stdout line, excluding its `\n`; longer lines get `-32600`.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
/// The longest child stderr line relayed whole; longer lines are split into lines of this size.
pub const MAX_STDERR_LINE_BYTES: usize = 64 * 1024;
/// How long the relays may keep reading child output after the child exits.
pub const PIPE_DRAIN_GRACE: Duration = Duration::from_secs(1);

/// How long a child may run after its stdin closes before the proxy kills it.
const CHILD_EXIT_GRACE: Duration = Duration::from_secs(5);
/// Lines waiting for host output; a full queue stalls the producers instead of growing memory.
const WRITER_QUEUE_LINES: usize = 64;
const TOOLS_CALL_METHOD: &str = "tools/call";
const RESOURCES_READ_METHOD: &str = "resources/read";
/// The rule id reported when an audit event cannot be recorded; policy files may not use it.
const AUDIT_SINK_FAILURE_RULE_ID: &str = "audit-sink-failure";
const AUDIT_FALLBACK_PREFIX: &str = "audit-fallback: ";
const PIPE_STILL_OPEN_DIAGNOSTIC: &str = "mcp-guardrail-proxy: child pipe still open after exit";

/// Everything one proxy session needs.
pub struct ProxyConfig {
    /// The id stamped on every audit event and approval request.
    pub session_id: String,
    /// The upstream server's program and arguments; must not be empty.
    pub upstream_command: Vec<String>,
    /// The policy that judges each evaluated call.
    pub engine: PolicyEngine,
    /// Where audit events go; a failed emit blocks the call.
    pub audit_sink: Box<dyn AuditSink>,
    /// Who decides calls that require approval.
    pub approval_broker: Box<dyn ApprovalBroker>,
    /// The proxy's stderr: child stderr lines, `audit-fallback:` lines, and diagnostics.
    pub stderr: SharedLineWriter,
}

/// Why a proxy session failed.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// The upstream command could not be started; the message names the program.
    #[error("failed to start the upstream command: {0}")]
    Spawn(std::io::Error),
    /// Host input or host output failed.
    #[error("proxy I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A write to the child's stdin failed; holds the child's exit code, `None` after a signal.
    #[error("the upstream server stopped accepting frames (exit code {0:?})")]
    ChildExited(Option<i32>),
}

/// What happens to one host line.
#[derive(Debug)]
pub enum Verdict {
    /// Send this re-encoded frame, without a trailing newline, to the child.
    Forward(String),
    /// Answer the host with this response; the child gets nothing.
    Reply(JsonRpcResponse),
}

/// The per-session decision point: policy, approval, audit, and taint for each host frame.
pub struct Interceptor {
    engine: PolicyEngine,
    taint: SessionTaintState,
    sink: Box<dyn AuditSink>,
    broker: Box<dyn ApprovalBroker>,
    stderr: SharedLineWriter,
    session_id: String,
    sequence: u64,
}

impl Interceptor {
    /// A clean session; `stderr` receives the `audit-fallback:` line when the sink fails.
    pub fn new(
        session_id: String,
        engine: PolicyEngine,
        audit_sink: Box<dyn AuditSink>,
        approval_broker: Box<dyn ApprovalBroker>,
        stderr: SharedLineWriter,
    ) -> Self {
        Self {
            engine,
            taint: SessionTaintState::new(),
            sink: audit_sink,
            broker: approval_broker,
            stderr,
            session_id,
            sequence: 0,
        }
    }

    /// Judges one host line, without its `\n`.
    ///
    /// Only a `tools/call` or `resources/read` request is evaluated and audited; the audit
    /// event is recorded, and taint updated, before a forward is returned. Any other valid
    /// frame is forwarded re-encoded, so the child sees exactly the values the policy saw.
    pub fn handle_host_line(&mut self, line: &str) -> Verdict {
        let message = match parse_frame(line) {
            Ok(message) => message,
            Err(FrameError::InvalidJson(detail)) => {
                return Verdict::Reply(parse_error_response(&detail));
            }
            Err(FrameError::NotJsonRpc(detail)) => {
                return Verdict::Reply(invalid_request(&detail));
            }
        };
        let request = match &message {
            JsonRpcMessage::Request(request) if is_evaluated(&request.method) => request,
            JsonRpcMessage::Notification(notification) if is_evaluated(&notification.method) => {
                return Verdict::Reply(unaddressed_call());
            }
            _ => return Verdict::Forward(encode_frame(&message)),
        };
        if request.id == RequestId::Null {
            return Verdict::Reply(unaddressed_call());
        }
        let Some(call) = classify_call(request) else {
            return Verdict::Reply(protocol_error_response(
                request.id.clone(),
                INVALID_PARAMS_CODE,
                &format!(
                    "{} needs a string `{}` parameter",
                    request.method,
                    required_param(request)
                ),
            ));
        };
        match self.judge_call(&request.method, &call) {
            Ok(()) => Verdict::Forward(encode_frame(&message)),
            Err(data) => Verdict::Reply(guardrail_error_response(request.id.clone(), data)),
        }
    }

    /// Evaluates, audits, and records one call; `Err` carries the error the host gets.
    fn judge_call(&mut self, method: &str, call: &McpCall) -> Result<(), GuardrailErrorData> {
        self.sequence += 1;
        let sequence = self.sequence;
        let evaluation = self.engine.evaluate(call, &self.taint);
        let taint_chain = self.taint.taint_chain();
        let (decision, reason, approved) = self.apply_approval(&evaluation, call, &taint_chain);
        let forwarded = decision == Decision::Allow || approved;
        let event = SecurityAuditEvent {
            event: AuditEventKind::McpGuardrailAudit,
            timestamp_ms: unix_millis(),
            session_id: self.session_id.clone(),
            sequence,
            method: method.to_string(),
            tool_name: call.tool_name().to_string(),
            decision,
            rule_id: evaluation.rule_id.clone(),
            severity: evaluation.severity,
            reason,
            taint_level: self.taint.level(),
            taint_chain,
            forwarded,
            latency_us: evaluation.latency_us,
            arguments: audited_arguments(call),
        };
        if let Err(error) = emit_event(&*self.sink, &event) {
            let fallback = if forwarded {
                SecurityAuditEvent {
                    decision: Decision::Deny,
                    forwarded: false,
                    rule_id: AUDIT_SINK_FAILURE_RULE_ID.to_string(),
                    severity: Severity::Critical,
                    reason: format!("audit sink failed: {error}"),
                    ..event
                }
            } else {
                event
            };
            self.write_audit_fallback(&fallback);
            return Err(error_data(fallback));
        }
        if !forwarded {
            return Err(error_data(event));
        }
        self.taint.record_forwarded(
            sequence,
            call.tool_name(),
            evaluation.category,
            resource_uri(call),
        );
        Ok(())
    }

    /// The decision and reason after the broker rules on a `RequireApproval`, and whether it approved.
    fn apply_approval(
        &self,
        evaluation: &Evaluation,
        call: &McpCall,
        taint_chain: &[String],
    ) -> (Decision, String, bool) {
        if evaluation.decision != Decision::RequireApproval {
            return (evaluation.decision, evaluation.reason.clone(), false);
        }
        let request = ApprovalRequest {
            session_id: self.session_id.clone(),
            rule_id: evaluation.rule_id.clone(),
            tool_name: call.tool_name().to_string(),
            reason: evaluation.reason.clone(),
            taint_chain: taint_chain.to_vec(),
        };
        match self.broker.request_approval(&request) {
            ApprovalOutcome::Approved => {
                (Decision::RequireApproval, evaluation.reason.clone(), true)
            }
            ApprovalOutcome::Denied => (
                Decision::Deny,
                format!("approval denied: {}", evaluation.reason),
                false,
            ),
            ApprovalOutcome::Pending => {
                (Decision::RequireApproval, evaluation.reason.clone(), false)
            }
        }
    }

    /// Records on stderr the event of a call whose audit emit failed.
    fn write_audit_fallback(&self, event: &SecurityAuditEvent) {
        let line = format!("{AUDIT_FALLBACK_PREFIX}{}", redacted_event_value(event));
        // The host still gets the error reply; a broken stderr has nowhere left to report to.
        let _ = self.stderr.write_line(line.as_bytes());
    }
}

/// Whether policy evaluates `method`; every other method is relayed.
fn is_evaluated(method: &str) -> bool {
    method == TOOLS_CALL_METHOD || method == RESOURCES_READ_METHOD
}

/// The parameter that `classify_call` needs for an evaluated method.
fn required_param(request: &JsonRpcRequest) -> &'static str {
    if request.method == TOOLS_CALL_METHOD {
        "name"
    } else {
        "uri"
    }
}

fn invalid_request(detail: &str) -> JsonRpcResponse {
    protocol_error_response(RequestId::Null, INVALID_REQUEST_CODE, detail)
}

/// The reply to an evaluated method sent without a usable id; a server may still run a notification.
fn unaddressed_call() -> JsonRpcResponse {
    invalid_request("evaluated methods need a request id")
}

fn error_data(event: SecurityAuditEvent) -> GuardrailErrorData {
    GuardrailErrorData {
        rule_id: event.rule_id,
        decision: event.decision,
        severity: event.severity,
        reason: event.reason,
        taint_chain: event.taint_chain,
    }
}

fn audited_arguments(call: &McpCall) -> Value {
    match call {
        McpCall::ToolCall { arguments, .. } => arguments.clone(),
        McpCall::ResourceRead { uri } => json!({ "uri": uri }),
    }
}

fn resource_uri(call: &McpCall) -> Option<String> {
    match call {
        McpCall::ToolCall { .. } => None,
        McpCall::ResourceRead { uri } => Some(uri.clone()),
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Runs a session over the process's own stdin and stdout.
pub async fn run_stdio_proxy(config: ProxyConfig) -> Result<ExitStatus, ProxyError> {
    run_proxy_with_io(config, tokio::io::stdin(), tokio::io::stdout()).await
}

/// Spawns the upstream command and relays between it and the host until the session ends.
///
/// The session ends at host EOF (the child then gets stdin EOF and 5 s to exit before it is
/// killed) or when the child exits, whichever comes first. Child output is then drained for at
/// most `PIPE_DRAIN_GRACE`, and every queued host line is written before the return. Returns
/// `ChildExited` when a forward write to the child failed, and `Io` when host IO failed.
pub async fn run_proxy_with_io<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    config: ProxyConfig,
    host_in: R,
    host_out: W,
) -> Result<ExitStatus, ProxyError> {
    let ProxyConfig {
        session_id,
        upstream_command,
        engine,
        audit_sink,
        approval_broker,
        stderr,
    } = config;
    let mut child = spawn_upstream(&upstream_command)?;
    let pipes = ChildPipes::take(&mut child);
    let interceptor = Interceptor::new(
        session_id,
        engine,
        audit_sink,
        approval_broker,
        stderr.clone(),
    );
    let (queue, queued_lines) = mpsc::channel(WRITER_QUEUE_LINES);
    let (session, written) = tokio::join!(
        run_session(&mut child, interceptor, host_in, pipes, queue, &stderr),
        write_host_output(queued_lines, host_out),
    );
    written?;
    let (status, input_end) = session?;
    match input_end {
        InputEnd::ForwardFailed => Err(ProxyError::ChildExited(status.code())),
        InputEnd::ReadFailed(error) => Err(ProxyError::Io(error)),
        InputEnd::HostEof | InputEnd::ChildExitedFirst | InputEnd::HostOutputClosed => Ok(status),
    }
}

fn spawn_upstream(command: &[String]) -> Result<Child, ProxyError> {
    let (program, args) = command.split_first().ok_or_else(|| {
        ProxyError::Spawn(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the upstream command is empty",
        ))
    })?;
    Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| {
            ProxyError::Spawn(io::Error::new(error.kind(), format!("{program}: {error}")))
        })
}

/// The child's three piped standard streams, moved out of the `Child`.
struct ChildPipes {
    stdin: ChildStdin,
    stdout: ChildStdout,
    stderr: ChildStderr,
}

impl ChildPipes {
    fn take(child: &mut Child) -> Self {
        Self {
            stdin: child.stdin.take().expect("child stdin is piped"),
            stdout: child.stdout.take().expect("child stdout is piped"),
            stderr: child.stderr.take().expect("child stderr is piped"),
        }
    }
}

/// Why the proxy stopped reading host input.
enum InputEnd {
    HostEof,
    ChildExitedFirst,
    ForwardFailed,
    HostOutputClosed,
    ReadFailed(io::Error),
}

/// Runs host input, the child, and both relays until the child is gone and its output drained.
///
/// Every queue sender lives in a future owned here, so the writer's queue closes on return.
async fn run_session<R: AsyncRead + Unpin>(
    child: &mut Child,
    interceptor: Interceptor,
    host_in: R,
    pipes: ChildPipes,
    queue: mpsc::Sender<Vec<u8>>,
    stderr: &SharedLineWriter,
) -> io::Result<(ExitStatus, InputEnd)> {
    let mut relays = pin!(relay_child_output(
        pipes.stdout,
        pipes.stderr,
        queue.clone(),
        stderr
    ));
    let mut relays_done = false;
    let mut lifecycle = pin!(supervise_child(
        child,
        read_host_input(host_in, pipes.stdin, interceptor, queue)
    ));
    let end = loop {
        tokio::select! {
            end = &mut lifecycle => break end,
            () = &mut relays, if !relays_done => relays_done = true,
        }
    };
    let drained = relays_done || tokio::time::timeout(PIPE_DRAIN_GRACE, relays).await.is_ok();
    if !drained {
        write_diagnostic(stderr, PIPE_STILL_OPEN_DIAGNOSTIC);
    }
    end
}

/// Ends the session at whichever comes first, host input ending or the child exiting.
///
/// Host input pends forever while the host holds it open, so a child exit drops it mid-read.
async fn supervise_child(
    child: &mut Child,
    host_input: impl Future<Output = InputEnd>,
) -> io::Result<(ExitStatus, InputEnd)> {
    let input_end = tokio::select! {
        input_end = host_input => input_end,
        status = child.wait() => return Ok((status?, InputEnd::ChildExitedFirst)),
    };
    let status = match input_end {
        InputEnd::HostOutputClosed => {
            child.kill().await?;
            child.wait().await?
        }
        _ => wait_or_kill(child).await?,
    };
    Ok((status, input_end))
}

async fn wait_or_kill(child: &mut Child) -> io::Result<ExitStatus> {
    match tokio::time::timeout(CHILD_EXIT_GRACE, child.wait()).await {
        Ok(status) => status,
        Err(_elapsed) => {
            child.kill().await?;
            child.wait().await
        }
    }
}

/// Reads host frames, judges each, and forwards it or queues its reply.
///
/// Returning drops `child_stdin`, which is the child's EOF.
async fn read_host_input<R: AsyncRead + Unpin>(
    host_in: R,
    mut child_stdin: ChildStdin,
    mut interceptor: Interceptor,
    queue: mpsc::Sender<Vec<u8>>,
) -> InputEnd {
    let mut reader = BufReader::new(host_in);
    let mut line = Vec::new();
    loop {
        let read = tokio::select! {
            read = read_capped_line(&mut reader, &mut line) => read,
            () = queue.closed() => return InputEnd::HostOutputClosed,
        };
        let verdict = match read {
            Err(error) => return InputEnd::ReadFailed(error),
            Ok(CappedLine::Eof) => return InputEnd::HostEof,
            Ok(CappedLine::Oversize) => Verdict::Reply(invalid_request(&format!(
                "frame exceeds {MAX_FRAME_BYTES} bytes"
            ))),
            Ok(CappedLine::Complete) => {
                let frame = line.strip_suffix(b"\r").unwrap_or(&line);
                if frame.is_empty() {
                    continue;
                }
                match std::str::from_utf8(frame) {
                    Ok(text) => interceptor.handle_host_line(text),
                    Err(error) => Verdict::Reply(parse_error_response(&error.to_string())),
                }
            }
        };
        match verdict {
            Verdict::Forward(frame) => {
                let mut bytes = frame.into_bytes();
                bytes.push(b'\n');
                if child_stdin.write_all(&bytes).await.is_err() {
                    return InputEnd::ForwardFailed;
                }
            }
            Verdict::Reply(response) => {
                if queue.send(encode_reply(response)).await.is_err() {
                    return InputEnd::HostOutputClosed;
                }
            }
        }
    }
}

fn encode_reply(response: JsonRpcResponse) -> Vec<u8> {
    encode_frame(&JsonRpcMessage::Response(response)).into_bytes()
}

/// The outcome of reading one line of at most `MAX_FRAME_BYTES`.
enum CappedLine {
    /// The line, without its `\n`, is in the caller's buffer. A final line may lack the `\n`.
    Complete,
    /// The line was longer than the cap; its bytes were discarded through the next `\n`.
    Oversize,
    /// The stream ended with no further bytes.
    Eof,
}

/// Reads one line into `line`, never holding more than `MAX_FRAME_BYTES` of it in memory.
async fn read_capped_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
) -> io::Result<CappedLine> {
    line.clear();
    let mut started = false;
    let mut oversize = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(match (started, oversize) {
                (false, _) => CappedLine::Eof,
                (true, true) => CappedLine::Oversize,
                (true, false) => CappedLine::Complete,
            });
        }
        started = true;
        let newline = available.iter().position(|byte| *byte == b'\n');
        let content = &available[..newline.unwrap_or(available.len())];
        if !oversize {
            if line.len() + content.len() > MAX_FRAME_BYTES {
                oversize = true;
                line.clear();
            } else {
                line.extend_from_slice(content);
            }
        }
        let consumed = content.len() + usize::from(newline.is_some());
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(if oversize {
                CappedLine::Oversize
            } else {
                CappedLine::Complete
            });
        }
    }
}

async fn relay_child_output(
    stdout: ChildStdout,
    child_stderr: ChildStderr,
    queue: mpsc::Sender<Vec<u8>>,
    stderr: &SharedLineWriter,
) {
    tokio::join!(
        relay_child_stdout(stdout, queue, stderr),
        relay_child_stderr(child_stderr, stderr),
    );
}

/// Queues each child stdout line, as raw bytes, for host output.
async fn relay_child_stdout(
    stdout: ChildStdout,
    queue: mpsc::Sender<Vec<u8>>,
    stderr: &SharedLineWriter,
) {
    let mut reader = BufReader::new(stdout);
    let mut line = Vec::new();
    loop {
        let host_line = match read_capped_line(&mut reader, &mut line).await {
            Ok(CappedLine::Complete) => std::mem::take(&mut line),
            Ok(CappedLine::Oversize) => encode_reply(invalid_request(&format!(
                "upstream line exceeds {MAX_FRAME_BYTES} bytes"
            ))),
            Ok(CappedLine::Eof) => return,
            Err(error) => {
                write_diagnostic(
                    stderr,
                    &format!("mcp-guardrail-proxy: child stdout relay stopped: {error}"),
                );
                return;
            }
        };
        if queue.send(host_line).await.is_err() {
            return;
        }
    }
}

/// Copies child stderr lines to the proxy's stderr, splitting lines over `MAX_STDERR_LINE_BYTES`.
///
/// Bytes pass through unchanged, so a split can cut a multi-byte UTF-8 character.
async fn relay_child_stderr(child_stderr: ChildStderr, stderr: &SharedLineWriter) {
    let mut reader = BufReader::new(child_stderr);
    let mut pending = Vec::new();
    loop {
        let available = match reader.fill_buf().await {
            Ok(available) => available,
            Err(error) => {
                write_diagnostic(
                    stderr,
                    &format!("mcp-guardrail-proxy: child stderr relay stopped: {error}"),
                );
                return;
            }
        };
        if available.is_empty() {
            if !pending.is_empty() {
                write_relayed_line(stderr, &pending);
            }
            return;
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let mut content = &available[..newline.unwrap_or(available.len())];
        let consumed = content.len() + usize::from(newline.is_some());
        while !content.is_empty() {
            if pending.len() == MAX_STDERR_LINE_BYTES {
                write_relayed_line(stderr, &pending);
                pending.clear();
            }
            let room = MAX_STDERR_LINE_BYTES - pending.len();
            let (part, rest) = content.split_at(room.min(content.len()));
            pending.extend_from_slice(part);
            content = rest;
        }
        if newline.is_some() {
            write_relayed_line(stderr, &pending);
            pending.clear();
        }
        reader.consume(consumed);
    }
}

fn write_relayed_line(stderr: &SharedLineWriter, line: &[u8]) {
    // Keep draining on a failed write, so the child never blocks on a full stderr pipe.
    let _ = stderr.write_line(line);
}

fn write_diagnostic(stderr: &SharedLineWriter, message: &str) {
    // A diagnostic about the proxy's own stderr has nowhere else to go.
    let _ = stderr.write_line(message.as_bytes());
}

/// The single owner of host output: writes and flushes each queued line until the queue closes.
async fn write_host_output<W: AsyncWrite + Unpin>(
    mut queued_lines: mpsc::Receiver<Vec<u8>>,
    mut host_out: W,
) -> io::Result<()> {
    while let Some(mut line) = queued_lines.recv().await {
        line.push(b'\n');
        host_out.write_all(&line).await?;
        host_out.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::{
        ApprovalBroker, ApprovalOutcome, ApprovalRequest, AuditSink, ControlPlaneError,
        NullAuditSink, PendingApprovalBroker,
    };
    use crate::policy::PolicyEngine;
    use crate::protocol::{Decision, JsonRpcMessage, encode_frame};
    use crate::taint::TaintLevel;
    use crate::telemetry::{JsonlAuditSink, SecurityAuditEvent, SharedLineWriter};
    use serde_json::Value;
    use std::io::{self, Write};
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const DEFAULT_POLICY: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/policies/default-policy.toml");

    const PLANTED_TOKEN: &str = "ghp_REPLAYfake0123456789abcdefghijklmnop";

    /// Unanchored at the end, so a tool name can carry a planted token and
    /// still match.
    const APPROVAL_POLICY: &str = r#"
[[rules]]
id = "deny-shadow"
description = "reads the system password hashes"
tool_regex = '.*'
arg_regexes = ['/etc/shadow']
decision = "deny"
severity = "critical"

[[rules]]
id = "approve-writes"
description = "workspace writes need approval"
tool_regex = '^write_file'
decision = "require-approval"
severity = "medium"
"#;

    const WRITE_FILE_FRAME: &str = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"arguments":{"content":"retries = 3","path":"notes.md"},"name":"write_file"}}"#;

    /// An in-memory writer whose bytes the test reads back.
    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedBuffer {
        fn bytes(&self) -> Vec<u8> {
            self.0.lock().expect("buffer lock").clone()
        }

        fn text(&self) -> String {
            String::from_utf8(self.bytes()).expect("the buffer holds UTF-8")
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

    struct FixedBroker(ApprovalOutcome);

    impl ApprovalBroker for FixedBroker {
        fn request_approval(&self, _request: &ApprovalRequest) -> ApprovalOutcome {
            self.0
        }
    }

    struct FailingSink;

    impl AuditSink for FailingSink {
        fn emit(&self, _event: &Value) -> Result<(), ControlPlaneError> {
            Err(ControlPlaneError::Unavailable(
                "audit disk full".to_string(),
            ))
        }
    }

    fn interceptor(
        engine: PolicyEngine,
        sink: Box<dyn AuditSink>,
        approval: ApprovalOutcome,
        stderr: &SharedBuffer,
    ) -> Interceptor {
        Interceptor::new(
            "session-1".to_string(),
            engine,
            sink,
            Box::new(FixedBroker(approval)),
            SharedLineWriter::from_writer(Box::new(stderr.clone())),
        )
    }

    fn inline_engine(policy: &str) -> PolicyEngine {
        PolicyEngine::from_toml(policy).expect("the test policy loads")
    }

    fn default_engine() -> PolicyEngine {
        PolicyEngine::from_path(Path::new(DEFAULT_POLICY)).expect("the default policy loads")
    }

    fn audit_sink(buffer: &SharedBuffer) -> Box<dyn AuditSink> {
        Box::new(JsonlAuditSink::from_writer(Box::new(buffer.clone())))
    }

    /// The reply the host gets, as JSON. Panics when the call was forwarded.
    fn reply_json(verdict: Verdict) -> Value {
        match verdict {
            Verdict::Reply(response) => {
                serde_json::from_str(&encode_frame(&JsonRpcMessage::Response(response)))
                    .expect("the reply encodes as JSON")
            }
            Verdict::Forward(frame) => panic!("expected a reply, the call was forwarded: {frame}"),
        }
    }

    /// The frame sent to the child. Panics when the host got a reply instead.
    fn forwarded_frame(verdict: Verdict) -> String {
        match verdict {
            Verdict::Forward(frame) => frame,
            Verdict::Reply(response) => panic!(
                "expected a forward, the host got a reply: {}",
                encode_frame(&JsonRpcMessage::Response(response))
            ),
        }
    }

    fn audit_events(buffer: &SharedBuffer) -> Vec<SecurityAuditEvent> {
        buffer
            .text()
            .lines()
            .map(|line| serde_json::from_str(line).expect("each audit line is an event"))
            .collect()
    }

    struct FailedAuditRow {
        call: &'static str,
        frame: &'static str,
        approval: ApprovalOutcome,
        rule_id: &'static str,
    }

    const FAILED_AUDIT_ROWS: [FailedAuditRow; 3] = [
        FailedAuditRow {
            call: "allowed call",
            frame: r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"query":"ghp_REPLAYfake0123456789abcdefghijklmnop"},"name":"search-ghp_REPLAYfake0123456789abcdefghijklmnop"}}"#,
            approval: ApprovalOutcome::Pending,
            rule_id: "audit-sink-failure",
        },
        FailedAuditRow {
            call: "denied call",
            frame: r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"arguments":{"path":"/etc/shadow","token":"ghp_REPLAYfake0123456789abcdefghijklmnop"},"name":"read-ghp_REPLAYfake0123456789abcdefghijklmnop"}}"#,
            approval: ApprovalOutcome::Pending,
            rule_id: "deny-shadow",
        },
        FailedAuditRow {
            call: "broker-approved call",
            frame: r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"arguments":{"content":"ghp_REPLAYfake0123456789abcdefghijklmnop"},"name":"write_file-ghp_REPLAYfake0123456789abcdefghijklmnop"}}"#,
            approval: ApprovalOutcome::Approved,
            rule_id: "audit-sink-failure",
        },
    ];

    #[test]
    fn failed_audit_blocks_forward_and_writes_redacted_fallback() {
        for row in FAILED_AUDIT_ROWS {
            let stderr = SharedBuffer::default();
            let mut proxy = interceptor(
                inline_engine(APPROVAL_POLICY),
                Box::new(FailingSink),
                row.approval,
                &stderr,
            );
            let reply = reply_json(proxy.handle_host_line(row.frame));
            let text = stderr.text();
            let fallback_json = text
                .strip_prefix("audit-fallback: ")
                .and_then(|rest| rest.strip_suffix('\n'))
                .unwrap_or_else(|| {
                    panic!(
                        "{}: stderr is not one audit-fallback line: {text}",
                        row.call
                    )
                });
            let fallback: SecurityAuditEvent = serde_json::from_str(fallback_json)
                .expect("the fallback line holds an audit event");
            assert_eq!(reply["error"]["code"], -32001, "{}", row.call);
            assert_eq!(
                reply["error"]["data"]["rule_id"], row.rule_id,
                "{}",
                row.call
            );
            assert_eq!(fallback.rule_id, row.rule_id, "{}", row.call);
            assert_eq!(fallback.decision, Decision::Deny, "{}", row.call);
            assert!(!fallback.forwarded, "{}", row.call);
            assert!(
                text.contains("[REDACTED:github-token]"),
                "{}: {text}",
                row.call
            );
            assert!(!text.contains(PLANTED_TOKEN), "{}: {text}", row.call);
        }
    }

    #[test]
    fn approved_broker_forwards_and_audits_require_approval() {
        let audit = SharedBuffer::default();
        let mut proxy = interceptor(
            inline_engine(APPROVAL_POLICY),
            audit_sink(&audit),
            ApprovalOutcome::Approved,
            &SharedBuffer::default(),
        );
        let frame = forwarded_frame(proxy.handle_host_line(WRITE_FILE_FRAME));
        let events = audit_events(&audit);
        assert_eq!(frame, WRITE_FILE_FRAME);
        assert_eq!(events.len(), 1, "one audit line per evaluated call");
        assert_eq!(events[0].decision, Decision::RequireApproval);
        assert_eq!(events[0].rule_id, "approve-writes");
        assert!(events[0].forwarded);
    }

    #[test]
    fn denied_broker_replies_policy_denied_with_approval_reason() {
        let audit = SharedBuffer::default();
        let mut proxy = interceptor(
            inline_engine(APPROVAL_POLICY),
            audit_sink(&audit),
            ApprovalOutcome::Denied,
            &SharedBuffer::default(),
        );
        let reply = reply_json(proxy.handle_host_line(WRITE_FILE_FRAME));
        let events = audit_events(&audit);
        assert_eq!(reply["error"]["code"], -32001);
        assert_eq!(reply["error"]["data"]["decision"], "deny");
        assert_eq!(reply["error"]["data"]["rule_id"], "approve-writes");
        assert_eq!(
            reply["error"]["data"]["reason"],
            "approval denied: workspace writes need approval"
        );
        assert_eq!(events.len(), 1, "one audit line per evaluated call");
        assert_eq!(events[0].decision, Decision::Deny);
        assert!(!events[0].forwarded);
    }

    /// Evaluated methods without a usable request id.
    const UNADDRESSED_CALLS: [&str; 3] = [
        r#"{"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{},"name":"search_files"}}"#,
        r#"{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"arguments":{},"name":"search_files"}}"#,
        r#"{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///workspace/README.md"}}"#,
    ];

    #[test]
    fn evaluated_call_without_usable_id_gets_invalid_request() {
        for frame in UNADDRESSED_CALLS {
            let audit = SharedBuffer::default();
            let mut proxy = interceptor(
                inline_engine(""),
                audit_sink(&audit),
                ApprovalOutcome::Approved,
                &SharedBuffer::default(),
            );
            let reply = reply_json(proxy.handle_host_line(frame));
            assert_eq!(reply["error"]["code"], -32600, "{frame}");
            assert_eq!(reply["id"], Value::Null, "{frame}");
            assert_eq!(audit.text(), "", "{frame} must not be audited");
        }
    }

    #[test]
    fn duplicate_argument_keys_forward_the_value_the_policy_saw() {
        let audit = SharedBuffer::default();
        let mut proxy = interceptor(
            default_engine(),
            audit_sink(&audit),
            ApprovalOutcome::Pending,
            &SharedBuffer::default(),
        );
        let frame = forwarded_frame(proxy.handle_host_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"path":"/etc/shadow","path":"notes.txt"},"name":"read_file"}}"#,
        ));
        let events = audit_events(&audit);
        assert_eq!(
            frame,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"path":"notes.txt"},"name":"read_file"}}"#
        );
        assert_eq!(events.len(), 1, "one audit line per evaluated call");
        assert_eq!(events[0].arguments["path"], "notes.txt");
    }

    #[test]
    fn forwarded_source_call_taints_the_next_audit_line() {
        let audit = SharedBuffer::default();
        let mut proxy = interceptor(
            default_engine(),
            audit_sink(&audit),
            ApprovalOutcome::Pending,
            &SharedBuffer::default(),
        );
        let fetch = proxy.handle_host_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"url":"https://docs.example/guide"},"name":"WebFetch"}}"#,
        );
        let shell = proxy.handle_host_line(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"arguments":{"command":"ls"},"name":"Shell"}}"#,
        );
        let events = audit_events(&audit);
        forwarded_frame(fetch);
        assert_eq!(
            reply_json(shell)["error"]["data"]["rule_id"],
            "tainted-deny-shell-exec"
        );
        assert_eq!(events.len(), 2, "one audit line per evaluated call");
        assert_eq!(events[0].taint_level, TaintLevel::Clean);
        assert!(events[0].taint_chain.is_empty());
        assert_eq!(events[1].taint_level, TaintLevel::Tainted);
        assert_eq!(events[1].taint_chain, ["1:WebFetch"]);
    }

    #[test]
    fn child_stderr_line_over_64_kib_is_split_into_whole_lines() {
        let stderr = SharedBuffer::default();
        let config = ProxyConfig {
            session_id: "session-1".to_string(),
            upstream_command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf '%70000s\\n' '' | tr ' ' a >&2".to_string(),
            ],
            engine: inline_engine(""),
            audit_sink: Box::new(NullAuditSink),
            approval_broker: Box::new(PendingApprovalBroker),
            stderr: SharedLineWriter::from_writer(Box::new(stderr.clone())),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build a tokio runtime");
        let status = runtime
            .block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(10),
                    run_proxy_with_io(config, tokio::io::empty(), tokio::io::sink()),
                )
                .await
            })
            .expect("the proxy returns within 10 s")
            .expect("the proxy runs the child");
        let bytes = stderr.bytes();
        let line_lengths: Vec<usize> = bytes
            .split(|byte| *byte == b'\n')
            .map(<[u8]>::len)
            .collect();
        let expected = [
            vec![b'a'; 65_536],
            b"\n".to_vec(),
            vec![b'a'; 4_464],
            b"\n".to_vec(),
        ]
        .concat();
        assert!(status.success(), "child status {status:?}");
        assert_eq!(line_lengths, [65_536, 4_464, 0]);
        assert!(
            bytes == expected,
            "stderr holds bytes other than 'a' and newlines"
        );
    }
}
