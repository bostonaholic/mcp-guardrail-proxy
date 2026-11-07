//! Lists an upstream server's tools directly and through the proxy, and compares them.

use std::collections::BTreeMap;
use std::io;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{Instant, timeout_at};

use crate::control_plane::PendingApprovalBroker;
use crate::machines::framer::{LineEnd, LineFramer};
use crate::policy::PolicyEngine;
use crate::protocol::{
    JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, RequestId, encode_frame,
    parse_frame,
};
use crate::proxy::{
    CHILD_EXIT_GRACE, MAX_FRAME_BYTES, ProxyConfig, ProxyError, read_capped_line, run_proxy_with_io,
};
use crate::telemetry::{JsonlAuditSink, SharedLineWriter};

/// The text that starts each stderr line about a probe failure.
const CAUSE_PREFIX: &str = "mcp-guardrail-proxy: probe";
/// The MCP protocol version that the probe offers in `initialize`.
const PROTOCOL_VERSION: &str = "2025-06-18";
const JSONRPC_VERSION: &str = "2.0";
const INITIALIZE_ID: i64 = 1;
const TOOLS_LIST_ID: i64 = 2;
const INITIALIZE_METHOD: &str = "initialize";
const INITIALIZED_METHOD: &str = "notifications/initialized";
const TOOLS_LIST_METHOD: &str = "tools/list";
/// The size of each in-memory pipe between the probe and the proxied session.
const HOST_PIPE_BYTES: usize = 64 * 1024;
/// The session id of the proxied run.
const PROBE_SESSION_ID: &str = "probe";

/// The outcome of one probe.
pub struct ProbeReport {
    lines: Vec<String>,
    failures: Vec<String>,
    passed: bool,
}

impl ProbeReport {
    /// The report as stdout text: empty when the direct run failed, else ending in `result:`.
    pub fn render(&self) -> String {
        self.lines.join("\n")
    }

    /// One stderr line per cause of failure, each starting with `mcp-guardrail-proxy: probe`.
    pub fn failures(&self) -> &[String] {
        &self.failures
    }

    /// True only when both runs listed tools, the lists are equal, and the proxy session ended
    /// without an error.
    pub fn passed(&self) -> bool {
        self.passed
    }
}

/// Lists the tools of `upstream` directly, then through a proxy session under `engine`, and
/// compares the lists. Each run may take `timeout`. The proxied run is skipped when the direct
/// run fails.
pub async fn run_probe(
    upstream: &[String],
    engine: PolicyEngine,
    timeout: Duration,
) -> ProbeReport {
    let direct = run_direct(upstream, timeout).await;
    if direct.is_err() {
        return build_report(direct, None, None);
    }
    let (proxied, session_error) = run_proxied(upstream, engine, timeout).await;
    build_report(direct, Some(proxied), session_error)
}

/// Why one run did not list the tools.
#[derive(Debug, thiserror::Error)]
enum RunError {
    /// No reply to `method` came before the deadline.
    #[error("no {method} reply before the deadline")]
    TimedOut { method: &'static str },
    /// The upstream closed its output, or stopped reading its input, during `method`.
    #[error("the upstream closed during {method}")]
    Closed { method: &'static str },
    /// Any other cause, as the report prints it.
    #[error("{0}")]
    Failed(String),
}

impl RunError {
    /// The cause as the report prints it. A timeout names `timeout` in seconds. A close names
    /// the upstream's exit code when it is known.
    fn into_cause(self, timeout: Duration, exit_code: Option<i32>) -> String {
        match self {
            RunError::TimedOut { method } => {
                format!("no {method} reply within {} s", timeout.as_secs())
            }
            RunError::Closed { .. } => match exit_code {
                Some(code) => format!("{self}, exit code {code}"),
                None => self.to_string(),
            },
            RunError::Failed(cause) => cause,
        }
    }
}

fn malformed(method: &str, detail: &str) -> RunError {
    RunError::Failed(format!("malformed {method} result: {detail}"))
}

/// `text` with control characters and quotes escaped, so a server cannot send terminal escapes
/// or line breaks through the report.
fn escaped(text: &str) -> String {
    text.escape_debug().to_string()
}

/// The upstream program's spawn error, in the text the proxy uses for it.
fn spawn_error(program: &str, error: &io::Error) -> String {
    ProxyError::Spawn(io::Error::new(error.kind(), format!("{program}: {error}"))).to_string()
}

/// The direct run: the upstream on its own stdio, with stderr inherited.
async fn run_direct(upstream: &[String], timeout: Duration) -> Result<Vec<Value>, String> {
    let Some((program, args)) = upstream.split_first() else {
        return Err(ProxyError::Spawn(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the upstream command is empty",
        ))
        .to_string());
    };
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| spawn_error(program, &error))?;
    let mut stdin = child.stdin.take().expect("child stdin is piped");
    let mut stdout = BufReader::new(child.stdout.take().expect("child stdout is piped"));
    let listed = list_tools(&mut stdin, &mut stdout, Instant::now() + timeout).await;
    drop(stdin);
    drop(stdout);
    let exit_code = reap(&mut child).await;
    listed.map_err(|error| error.into_cause(timeout, exit_code))
}

/// Waits up to `CHILD_EXIT_GRACE` for `child` to exit, then kills it. Returns the exit code of a
/// child that exited on its own.
async fn reap(child: &mut Child) -> Option<i32> {
    match tokio::time::timeout(CHILD_EXIT_GRACE, child.wait()).await {
        Ok(Ok(status)) => status.code(),
        Ok(Err(_)) | Err(_) => {
            // A failed kill leaves the child to `kill_on_drop`.
            let _ = child.kill().await;
            None
        }
    }
}

/// The proxied run: a proxy session over in-memory host pipes, with the probe as its host.
/// Returns the run's outcome and the session's error, if any.
async fn run_proxied(
    upstream: &[String],
    engine: PolicyEngine,
    timeout: Duration,
) -> (Result<Vec<Value>, String>, Option<String>) {
    let (mut host_input, proxy_input) = tokio::io::duplex(HOST_PIPE_BYTES);
    let (proxy_output, host_output) = tokio::io::duplex(HOST_PIPE_BYTES);
    let stderr = SharedLineWriter::stderr();
    let config = ProxyConfig {
        session_id: PROBE_SESSION_ID.to_string(),
        upstream_command: upstream.to_vec(),
        engine,
        audit_sink: Box::new(JsonlAuditSink::from_shared(stderr.clone())),
        approval_broker: Box::new(PendingApprovalBroker),
        stderr,
    };
    let client = async move {
        let mut output = BufReader::new(host_output);
        let listed = list_tools(&mut host_input, &mut output, Instant::now() + timeout).await;
        // Host EOF for the proxy, which then ends its session.
        drop(host_input);
        // Reading host output to EOF keeps the proxy's writer from blocking on a full pipe. An
        // in-memory pipe read does not fail, and only the end of the read matters.
        let _ = tokio::io::copy(&mut output, &mut tokio::io::sink()).await;
        listed
    };
    let (session, listed) =
        tokio::join!(run_proxy_with_io(config, proxy_input, proxy_output), client);
    match session {
        Ok(status) => (
            listed.map_err(|error| error.into_cause(timeout, status.code())),
            None,
        ),
        Err(error) => (
            listed.map_err(|error| error.into_cause(timeout, None)),
            Some(error.to_string()),
        ),
    }
}

/// One run's handshake over `writer` (upstream input) and `reader` (upstream output), ending by
/// `deadline`: the tool list sorted by name, or the cause of the failure.
///
/// Sends `initialize`, `notifications/initialized`, and, when the server declares the `tools`
/// capability, `tools/list`. Each wait skips every line but the response to its own id or an
/// error with a null id.
async fn list_tools<W, R>(
    writer: &mut W,
    reader: &mut R,
    deadline: Instant,
) -> Result<Vec<Value>, RunError>
where
    W: AsyncWrite + Unpin,
    R: AsyncBufRead + Unpin,
{
    let initialize = request(INITIALIZE_ID, INITIALIZE_METHOD, Some(initialize_params()));
    send(writer, &initialize, INITIALIZE_METHOD, deadline).await?;
    let Value::Object(initialized) =
        await_result(reader, INITIALIZE_ID, INITIALIZE_METHOD, deadline).await?
    else {
        return Err(malformed(INITIALIZE_METHOD, "the result is not an object"));
    };
    let notification = JsonRpcMessage::Notification(JsonRpcNotification {
        jsonrpc: JSONRPC_VERSION.to_string(),
        method: INITIALIZED_METHOD.to_string(),
        params: None,
    });
    send(writer, &notification, INITIALIZED_METHOD, deadline).await?;
    let has_tools = initialized
        .get("capabilities")
        .and_then(|capabilities| capabilities.get("tools"))
        .is_some();
    if !has_tools {
        return Ok(Vec::new());
    }
    let tools_list = request(TOOLS_LIST_ID, TOOLS_LIST_METHOD, None);
    send(writer, &tools_list, TOOLS_LIST_METHOD, deadline).await?;
    sorted_tools(await_result(reader, TOOLS_LIST_ID, TOOLS_LIST_METHOD, deadline).await?)
}

fn initialize_params() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "mcp-guardrail-proxy probe", "version": env!("CARGO_PKG_VERSION")},
    })
}

fn request(id: i64, method: &str, params: Option<Value>) -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JSONRPC_VERSION.to_string(),
        id: RequestId::Number(id),
        method: method.to_string(),
        params,
    })
}

/// Writes `message` as one line by `deadline`. A closed pipe counts as the upstream closing.
async fn send<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &JsonRpcMessage,
    method: &'static str,
    deadline: Instant,
) -> Result<(), RunError> {
    let mut frame = encode_frame(message);
    frame.push('\n');
    let written = timeout_at(deadline, async {
        writer.write_all(frame.as_bytes()).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| RunError::TimedOut { method })?;
    written.map_err(|error| match error.kind() {
        io::ErrorKind::BrokenPipe => RunError::Closed { method },
        _ => RunError::Failed(format!("writing {method} failed: {error}")),
    })
}

/// Reads lines by `deadline` until the response to `id`, and returns its result. An error with
/// that id or a null id fails the run.
async fn await_result<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    id: i64,
    method: &'static str,
    deadline: Instant,
) -> Result<Value, RunError> {
    let mut framer = LineFramer::new(MAX_FRAME_BYTES);
    loop {
        let end = timeout_at(deadline, read_capped_line(reader, &mut framer))
            .await
            .map_err(|_| RunError::TimedOut { method })?
            .map_err(|error| {
                RunError::Failed(format!("reading the {method} reply failed: {error}"))
            })?;
        match end {
            LineEnd::Complete => {}
            LineEnd::Oversize => {
                return Err(RunError::Failed(format!(
                    "{method} reply line exceeds {MAX_FRAME_BYTES} bytes"
                )));
            }
            LineEnd::Eof => return Err(RunError::Closed { method }),
        }
        let Some(response) = awaited_response(framer.line(), id) else {
            continue;
        };
        if let Some(error) = response.error {
            return Err(RunError::Failed(format!(
                "{method} returned error {}: {}",
                error.code,
                escaped(&error.message)
            )));
        }
        return Ok(response
            .result
            .expect("parse_frame keeps only responses with a result or an error"));
    }
}

/// The response in `line` when it answers `id`, or when it is an error with a null id.
fn awaited_response(line: &[u8], id: i64) -> Option<JsonRpcResponse> {
    let text = std::str::from_utf8(line).ok()?;
    match parse_frame(text.strip_suffix('\r').unwrap_or(text)) {
        Ok(JsonRpcMessage::Response(response))
            if response.id == RequestId::Number(id)
                || (response.id == RequestId::Null && response.error.is_some()) =>
        {
            Some(response)
        }
        _ => None,
    }
}

/// The tools of a `tools/list` result, sorted by name. A list that pages, a tool without a
/// string name, and a name listed twice fail the run.
fn sorted_tools(result: Value) -> Result<Vec<Value>, RunError> {
    let Value::Object(mut result) = result else {
        return Err(malformed(TOOLS_LIST_METHOD, "the result is not an object"));
    };
    match result.get("nextCursor") {
        None | Some(Value::Null) => {}
        Some(Value::String(cursor)) if cursor.is_empty() => {}
        Some(Value::String(_)) => {
            return Err(RunError::Failed(format!(
                "{TOOLS_LIST_METHOD} is paginated, and the probe does not follow nextCursor"
            )));
        }
        Some(_) => return Err(malformed(TOOLS_LIST_METHOD, "nextCursor is not a string")),
    }
    let Some(Value::Array(tools)) = result.remove("tools") else {
        return Err(malformed(TOOLS_LIST_METHOD, "no tools array"));
    };
    let mut by_name = BTreeMap::new();
    for tool in tools {
        let Some(name) = tool.get("name").and_then(Value::as_str).map(str::to_string) else {
            return Err(malformed(TOOLS_LIST_METHOD, "a tool has no string name"));
        };
        if by_name.contains_key(&name) {
            return Err(malformed(
                TOOLS_LIST_METHOD,
                &format!("{} is listed twice", escaped(&name)),
            ));
        }
        by_name.insert(name, tool);
    }
    Ok(by_name.into_values().collect())
}

/// The name of a tool that `sorted_tools` accepted.
fn tool_name(tool: &Value) -> &str {
    tool["name"].as_str().unwrap_or_default()
}

/// The three difference lines, or none when the lists are equal. Both lists are sorted by name
/// with unique names.
fn difference_lines(direct: &[Value], proxied: &[Value]) -> Vec<String> {
    let direct: BTreeMap<&str, &Value> =
        direct.iter().map(|tool| (tool_name(tool), tool)).collect();
    let proxied: BTreeMap<&str, &Value> =
        proxied.iter().map(|tool| (tool_name(tool), tool)).collect();
    let only_direct: Vec<&str> = direct
        .keys()
        .copied()
        .filter(|name| !proxied.contains_key(name))
        .collect();
    let only_proxied: Vec<&str> = proxied
        .keys()
        .copied()
        .filter(|name| !direct.contains_key(name))
        .collect();
    let changed: Vec<&str> = direct
        .iter()
        .filter(|(name, tool)| proxied.get(*name).is_some_and(|other| other != *tool))
        .map(|(name, _)| *name)
        .collect();
    if only_direct.is_empty() && only_proxied.is_empty() && changed.is_empty() {
        return Vec::new();
    }
    vec![
        format!("only direct: {}", joined_names(&only_direct)),
        format!("only through the proxy: {}", joined_names(&only_proxied)),
        format!("definition differs: {}", joined_names(&changed)),
    ]
}

/// `names` escaped and joined by `, `, or `none`.
fn joined_names(names: &[&str]) -> String {
    if names.is_empty() {
        return "none".to_string();
    }
    names
        .iter()
        .map(|name| escaped(name))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The report for one probe: the direct run's outcome, the proxied run's outcome (`None` when it
/// did not run), and the proxy session's error, if any. Each `Err` holds the run's cause.
fn build_report(
    direct: Result<Vec<Value>, String>,
    proxied: Option<Result<Vec<Value>, String>>,
    session_error: Option<String>,
) -> ProbeReport {
    let direct = match direct {
        Ok(tools) => tools,
        Err(cause) => {
            return ProbeReport {
                lines: Vec::new(),
                failures: vec![format!("{CAUSE_PREFIX} direct: {cause}")],
                passed: false,
            };
        }
    };
    let mut lines = vec![format!("direct: {} tools", direct.len())];
    let mut failures = Vec::new();
    let mut lists_equal = false;
    match proxied.unwrap_or_else(|| Err("the run did not start".to_string())) {
        Ok(proxied) => {
            lines.push(format!("through the proxy: {} tools", proxied.len()));
            let differences = difference_lines(&direct, &proxied);
            lists_equal = differences.is_empty();
            if lists_equal {
                lines.push("tool lists: equal".to_string());
            } else {
                lines.push("tool lists: differ".to_string());
                lines.extend(differences);
                failures.push(format!("{CAUSE_PREFIX}: the tool lists differ"));
            }
        }
        Err(cause) => failures.push(format!("{CAUSE_PREFIX} through the proxy: {cause}")),
    }
    if let Some(error) = &session_error {
        failures.push(format!("{CAUSE_PREFIX} through the proxy: {error}"));
    }
    let passed = lists_equal && session_error.is_none();
    lines.push(format!("result: {}", if passed { "PASS" } else { "FAIL" }));
    ProbeReport {
        lines,
        failures,
        passed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Runs the handshake client against `script` as the upstream's stdout. Returns the listed
    /// tool names or the cause, and the text the client wrote to the upstream.
    fn drive_client(script: &[u8]) -> (Result<Vec<String>, String>, String) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build a tokio runtime");
        let mut written: Vec<u8> = Vec::new();
        let mut reader: &[u8] = script;
        let outcome = runtime.block_on(async {
            let deadline = Instant::now() + Duration::from_secs(5);
            list_tools(&mut written, &mut reader, deadline).await
        });
        let names = outcome
            .map(|tools| {
                tools
                    .iter()
                    .map(|tool| tool["name"].as_str().unwrap_or("<no name>").to_string())
                    .collect()
            })
            .map_err(|cause| cause.to_string());
        (
            names,
            String::from_utf8(written).expect("the client writes UTF-8"),
        )
    }

    const INITIALIZE_WITH_TOOLS: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"scripted","version":"0.0.0"}}}"#;

    #[test]
    fn probe_run_applies_the_reply_rules() {
        // Lines that are not the awaited reply are skipped: a line that is not JSON, a
        // notification, a server-to-client request that reuses id 1, and a response to id 99.
        let (outcome, _) = drive_client(
            concat!(
                "this line is not JSON\n",
                r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"starting"}}"#,
                "\n",
                r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
                "\n",
                r#"{"jsonrpc":"2.0","id":99,"result":{}}"#,
                "\n",
                r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"scripted","version":"0.0.0"}}}"#,
                "\n",
                r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"search_files","inputSchema":{"type":"object"}}]}}"#,
                "\n",
            )
            .as_bytes(),
        );
        assert_eq!(
            outcome,
            Ok(vec!["search_files".to_string()]),
            "skipped lines before the replies"
        );

        // An error reply with the awaited id fails the run and names the method, code, and message.
        let (outcome, _) = drive_client(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32603,\"message\":\"init exploded\"}}\n",
        );
        let cause = outcome.clone().err().unwrap_or_default();
        assert!(
            cause.contains("initialize")
                && cause.contains("-32603")
                && cause.contains("init exploded"),
            "error reply to initialize: {outcome:?}"
        );

        // An error reply with a null id fails the run that waits for it.
        let (outcome, _) = drive_client(
            format!(
                "{INITIALIZE_WITH_TOOLS}\n{}\n",
                r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"bad frame"}}"#
            )
            .as_bytes(),
        );
        let cause = outcome.clone().err().unwrap_or_default();
        assert!(
            cause.contains("tools/list") && cause.contains("-32600") && cause.contains("bad frame"),
            "null-id error during tools/list: {outcome:?}"
        );

        // An initialize result of null is malformed, never 0 tools.
        let (outcome, _) = drive_client(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}\n");
        let cause = outcome.clone().err().unwrap_or_default();
        assert!(
            cause.contains("malformed initialize result"),
            "null initialize result: {outcome:?}"
        );

        // No `capabilities.tools`: 0 tools, and no tools/list request is sent.
        let (outcome, written) = drive_client(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{\"resources\":{}},\"serverInfo\":{\"name\":\"scripted\",\"version\":\"0.0.0\"}}}\n",
        );
        assert_eq!(outcome, Ok(Vec::new()), "no tools capability");
        assert!(
            !written.contains("tools/list"),
            "the client asked for tools without the capability: {written}"
        );

        // A tools/list result with no `tools` array is malformed.
        let (outcome, _) = drive_client(
            format!("{INITIALIZE_WITH_TOOLS}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{}}}}\n")
                .as_bytes(),
        );
        let cause = outcome.clone().err().unwrap_or_default();
        assert!(
            cause.contains("malformed tools/list result"),
            "no tools array: {outcome:?}"
        );

        // A tool with no string `name` is malformed.
        let (outcome, _) = drive_client(
            format!(
                "{INITIALIZE_WITH_TOOLS}\n{}\n",
                r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":7}]}}"#
            )
            .as_bytes(),
        );
        let cause = outcome.clone().err().unwrap_or_default();
        assert!(
            cause.contains("malformed tools/list result"),
            "tool name is not a string: {outcome:?}"
        );

        // One name listed twice is malformed, and the cause names it in escaped form.
        let (outcome, _) = drive_client(
            format!(
                "{INITIALIZE_WITH_TOOLS}\n{}\n",
                r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"dup\u001bname"},{"name":"dup\u001bname"}]}}"#
            )
            .as_bytes(),
        );
        let cause = outcome.clone().err().unwrap_or_default();
        assert!(
            cause.contains("malformed tools/list result")
                && cause.contains("dup\\u{1b}name")
                && !cause.contains('\u{1b}'),
            "duplicate name with a control character: {outcome:?}"
        );

        // A non-empty string `nextCursor` fails the run as paginated.
        let (outcome, _) = drive_client(
            format!(
                "{INITIALIZE_WITH_TOOLS}\n{}\n",
                r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"}],"nextCursor":"abc"}}"#
            )
            .as_bytes(),
        );
        let cause = outcome.clone().err().unwrap_or_default();
        assert!(
            cause.contains("tools/list") && cause.contains("paginated"),
            "nextCursor \"abc\": {outcome:?}"
        );

        // `nextCursor` as null, absent, or "" ends the list.
        let (outcome, _) = drive_client(
            format!(
                "{INITIALIZE_WITH_TOOLS}\n{}\n",
                r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"}],"nextCursor":null}}"#
            )
            .as_bytes(),
        );
        assert_eq!(outcome, Ok(vec!["a".to_string()]), "nextCursor null");
        let (outcome, _) = drive_client(
            format!(
                "{INITIALIZE_WITH_TOOLS}\n{}\n",
                r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"}]}}"#
            )
            .as_bytes(),
        );
        assert_eq!(outcome, Ok(vec!["a".to_string()]), "nextCursor absent");
        let (outcome, _) = drive_client(
            format!(
                "{INITIALIZE_WITH_TOOLS}\n{}\n",
                r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"}],"nextCursor":""}}"#
            )
            .as_bytes(),
        );
        assert_eq!(outcome, Ok(vec!["a".to_string()]), "nextCursor \"\"");

        // A `nextCursor` of another type is malformed.
        let (outcome, _) = drive_client(
            format!(
                "{INITIALIZE_WITH_TOOLS}\n{}\n",
                r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"}],"nextCursor":7}}"#
            )
            .as_bytes(),
        );
        let cause = outcome.clone().err().unwrap_or_default();
        assert!(
            cause.contains("malformed tools/list result"),
            "nextCursor 7: {outcome:?}"
        );

        // A reply line over 4 MiB fails the run and names the frame size.
        let oversize = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"pad\":\"{}\"}}}}\n",
            "x".repeat(4 * 1024 * 1024)
        );
        let (outcome, _) = drive_client(oversize.as_bytes());
        let cause = outcome.err().unwrap_or_default();
        assert!(
            cause.contains("initialize") && cause.contains("4194304"),
            "oversize initialize reply: {cause}"
        );
    }
}
