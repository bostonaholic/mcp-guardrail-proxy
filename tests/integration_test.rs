//! End-to-end tests for the stdio proxy. This target uses `harness = false`.
//!
//! With `MCP_GUARDRAIL_MOCK_UPSTREAM` set, `main` runs as the mock upstream
//! MCP server that the tests spawn through the `env` utility. Otherwise `main`
//! runs each test in turn on a fresh tokio runtime, under a 10 s limit, and
//! prints `test <name> ... ok` or `test <name> ... FAILED`.

use std::future::Future;
use std::io::{BufRead, Write};
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::process::{ExitCode, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mcp_guardrail_proxy::control_plane::PendingApprovalBroker;
use mcp_guardrail_proxy::policy::PolicyEngine;
use mcp_guardrail_proxy::proxy::{MAX_FRAME_BYTES, ProxyConfig, ProxyError, run_proxy_with_io};
use mcp_guardrail_proxy::telemetry::{JsonlAuditSink, SharedLineWriter};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};

const DEFAULT_POLICY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/policies/default-policy.toml");
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const MOCK_STDERR_LINE: &str = r#"{"level":"info","msg":"mock-upstream ready"}"#;
const PIPE_DIAGNOSTIC: &str = "mcp-guardrail-proxy: child pipe still open after exit";
/// The text that marks each `probe` cause line on stderr.
const PROBE_CAUSE: &str = "mcp-guardrail-proxy: probe";
/// The environment that makes a child of the CLI run this test binary as the mock, logging to
/// `mock.log` in the CLI's working directory.
const MOCK_UPSTREAM_ENV: (&str, &str) = ("MCP_GUARDRAIL_MOCK_UPSTREAM", "1");
const MOCK_LOG_ENV: (&str, &str) = ("MCP_GUARDRAIL_MOCK_LOG", "mock.log");

// Host frames in canonical encoding: struct field order, sorted keys inside
// `params`, no spaces. The mock log compares them byte for byte.
const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{},"clientInfo":{"name":"test-host","version":"0.0.0"},"protocolVersion":"2025-06-18"}}"#;
const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#;
const TOOLS_LIST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
const SEARCH_FILES: &str = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"arguments":{"query":"TODO"},"name":"search_files"}}"#;
const SHADOW_READ: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"path":"/etc/shadow"},"name":"read_file"}}"#;
const WEB_FETCH: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"url":"https://docs.example/guide"},"name":"WebFetch"}}"#;
const SHELL_LS: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"arguments":{"command":"ls"},"name":"Shell"}}"#;
const READ_EMAIL: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"id":"msg-7"},"name":"read_email"}}"#;
const WRITE_FILE: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"arguments":{"content":"pub const RETRIES: u8 = 3;","path":"src/config.rs"},"name":"write_file"}}"#;
const SECRET_ISSUE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"body":"github ghp_REPLAYfake0123456789abcdefghijklmnop","title":"Leaked token"},"name":"create_issue"}}"#;
const SECRET_SHADOW_READ: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"arguments":{"note":"aws AKIAREPLAYFAKE000001","path":"/etc/shadow"},"name":"read_file"}}"#;
const BATCH: &str = r#"[{"jsonrpc":"2.0","id":2,"method":"tools/list"}]"#;
const SEARCH_AFTER_ERRORS: &str = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"arguments":{"query":"after errors"},"name":"search_files"}}"#;

fn main() -> ExitCode {
    if std::env::var_os("MCP_GUARDRAIL_MOCK_UPSTREAM").is_some() {
        return mock_upstream();
    }
    let results = [
        run_test(
            "relays_allowed_traffic_and_child_responses",
            relays_allowed_traffic_and_child_responses(),
        ),
        run_test(
            "denied_sensitive_read_sends_zero_bytes_to_child",
            denied_sensitive_read_sends_zero_bytes_to_child(),
        ),
        run_test(
            "queue_stays_open_until_both_relays_end",
            queue_stays_open_until_both_relays_end(),
        ),
        run_test(
            "host_output_failure_ends_session_with_child_not_reading",
            host_output_failure_ends_session_with_child_not_reading(),
        ),
        run_test(
            "tainted_shell_is_denied_after_untrusted_fetch",
            tainted_shell_is_denied_after_untrusted_fetch(),
        ),
        run_test(
            "tainted_workspace_write_requires_approval",
            tainted_workspace_write_requires_approval(),
        ),
        run_test(
            "audit_line_precedes_reply_and_redacts_secrets",
            audit_line_precedes_reply_and_redacts_secrets(),
        ),
        run_test(
            "malformed_frames_get_errors_and_session_continues",
            malformed_frames_get_errors_and_session_continues(),
        ),
        run_test(
            "host_eof_shuts_down_child_cleanly",
            host_eof_shuts_down_child_cleanly(),
        ),
        run_test(
            "child_exit_ends_session_with_its_code",
            child_exit_ends_session_with_its_code(),
        ),
        run_test(
            "child_exit_with_open_descendant_pipe_returns_after_drain_grace",
            child_exit_with_open_descendant_pipe_returns_after_drain_grace(),
        ),
        run_test(
            "cli_exits_when_child_exits_with_stdin_open",
            cli_exits_when_child_exits_with_stdin_open(),
        ),
        run_test(
            "cli_denies_shadow_read_with_the_embedded_default_policy",
            cli_denies_shadow_read_with_the_embedded_default_policy(),
        ),
        run_test(
            "cli_probe_passes_when_both_runs_list_the_same_tools",
            cli_probe_passes_when_both_runs_list_the_same_tools(),
        ),
        run_test(
            "cli_probe_fails_closed_and_names_the_cause",
            cli_probe_fails_closed_and_names_the_cause(),
        ),
        run_test(
            "cli_probe_reports_policy_fit_under_the_chosen_policy",
            cli_probe_reports_policy_fit_under_the_chosen_policy(),
        ),
    ];
    if results.iter().all(|passed| *passed) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Runs one test on a fresh runtime under `TEST_TIMEOUT` and prints its
/// result line. A panic or a timeout fails the test.
fn run_test(name: &str, test: impl Future<Output = ()>) -> bool {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build a tokio runtime");
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(async { tokio::time::timeout(TEST_TIMEOUT, test).await })
    }));
    let passed = matches!(outcome, Ok(Ok(())));
    if matches!(outcome, Ok(Err(_))) {
        eprintln!("{name} timed out after {TEST_TIMEOUT:?}");
    }
    println!("test {name} ... {}", if passed { "ok" } else { "FAILED" });
    passed
}

/// Whether the mock switch `name` is set to `1`.
fn mock_switch(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| value == "1")
}

/// The mock upstream MCP server. It appends every received line to
/// `MCP_GUARDRAIL_MOCK_LOG` and answers requests with one line each.
///
/// Each start counts the `initialize` lines already in its log, so a later
/// start in the same log knows it is not the first. Switches, each set to `1`:
/// - `MCP_GUARDRAIL_MOCK_INITIALIZE_ERROR`: answer `initialize` with an error.
/// - `MCP_GUARDRAIL_MOCK_SILENT`: never reply.
/// - `MCP_GUARDRAIL_MOCK_TOOLS_CHANGE_ON_SECOND_START`: list three tools, and
///   a changed list from the second start on.
/// - `MCP_GUARDRAIL_MOCK_SILENT_ON_SECOND_START`: from the second start on,
///   never reply, and at stdin EOF write 256 lines of 1 KiB before exiting.
fn mock_upstream() -> ExitCode {
    if let Some(code) = std::env::var_os("MCP_GUARDRAIL_MOCK_EXIT_CODE") {
        if std::env::var_os("MCP_GUARDRAIL_MOCK_HOLD_PIPES").is_some_and(|hold| hold == "1") {
            // A descendant that keeps the inherited stdout and stderr open
            // after the mock exits. The mock never waits for it.
            #[allow(
                clippy::zombie_processes,
                reason = "the descendant must outlive the mock, which exits at once"
            )]
            let _descendant = std::process::Command::new("sleep")
                .arg("5")
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn sleep");
        }
        let code: u8 = code
            .to_str()
            .and_then(|code| code.parse().ok())
            .expect("MCP_GUARDRAIL_MOCK_EXIT_CODE is 0 to 255");
        return ExitCode::from(code);
    }
    let log_path =
        std::env::var_os("MCP_GUARDRAIL_MOCK_LOG").expect("MCP_GUARDRAIL_MOCK_LOG is set");
    let earlier_starts = std::fs::read_to_string(&log_path)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains(r#""method":"initialize""#))
        .count();
    let start = earlier_starts + 1;
    let silent = mock_switch("MCP_GUARDRAIL_MOCK_SILENT")
        || (mock_switch("MCP_GUARDRAIL_MOCK_SILENT_ON_SECOND_START") && start > 1);
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .expect("open the mock log");
    let mut input = std::io::stdin().lock();
    let mut stdout = std::io::stdout();
    let mut line = String::new();
    loop {
        line.clear();
        if input.read_line(&mut line).expect("read a forwarded line") == 0 {
            if mock_switch("MCP_GUARDRAIL_MOCK_SILENT_ON_SECOND_START") && start > 1 {
                // More output than a 64 KiB pipe holds, sent only after input closed.
                let pending_line = format!("{}\n", "x".repeat(1023));
                for _ in 0..256 {
                    stdout
                        .write_all(pending_line.as_bytes())
                        .expect("write pending output");
                }
                stdout.flush().expect("flush stdout");
            }
            return ExitCode::SUCCESS;
        }
        log.write_all(line.as_bytes())
            .expect("append to the mock log");
        if silent {
            continue;
        }
        if let Some(reply) = mock_reply(line.trim_end_matches('\n'), start) {
            stdout
                .write_all(format!("{reply}\n").as_bytes())
                .expect("write a reply");
            stdout.flush().expect("flush stdout");
        }
    }
}

/// The mock's reply to one forwarded frame on its `start`-th start, or `None`
/// for a notification or a response.
fn mock_reply(line: &str, start: usize) -> Option<String> {
    let frame: Value = serde_json::from_str(line).expect("the proxy forwards JSON frames");
    let method = frame.get("method")?.as_str()?;
    let id = frame.get("id")?.clone();
    let params = &frame["params"];
    let (key, value) = match method {
        "initialize" => {
            std::io::stderr()
                .write_all(format!("{MOCK_STDERR_LINE}\n").as_bytes())
                .expect("write the stderr line");
            if mock_switch("MCP_GUARDRAIL_MOCK_INITIALIZE_ERROR") {
                (
                    "error",
                    json!({"code": -32603, "message": "mock initialize failure"}),
                )
            } else {
                (
                    "result",
                    json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}, "resources": {}}, "serverInfo": {"name": "mock-upstream", "version": "0.0.0"}}),
                )
            }
        }
        "tools/list" if mock_switch("MCP_GUARDRAIL_MOCK_TOOLS_CHANGE_ON_SECOND_START") => {
            if start == 1 {
                (
                    "result",
                    json!({"tools": [
                        {"name": "list_dir", "inputSchema": {"type": "object"}},
                        {"name": "read_file", "inputSchema": {"type": "object"}},
                        {"name": "search_files", "inputSchema": {"type": "object"}},
                    ]}),
                )
            } else {
                (
                    "result",
                    json!({"tools": [
                        {"name": "search_files", "inputSchema": {"type": "object"}},
                        {"name": "read_file", "inputSchema": {"type": "object", "required": ["path"]}},
                        {"name": "write_file", "inputSchema": {"type": "object"}},
                    ]}),
                )
            }
        }
        "tools/list" => (
            "result",
            json!({"tools": [{"name": "search_files", "inputSchema": {"type": "object"}}]}),
        ),
        "tools/call" => (
            "result",
            json!({"content": [{"type": "text", "text": format!("mock:{}", params["name"].as_str().unwrap_or_default())}], "isError": false}),
        ),
        "resources/read" => (
            "result",
            json!({"contents": [{"uri": params["uri"], "mimeType": "text/plain", "text": "mock resource"}]}),
        ),
        _ => (
            "error",
            json!({"code": -32601, "message": "Method not found"}),
        ),
    };
    let mut reply = json!({"jsonrpc": "2.0", "id": id});
    reply[key] = value;
    Some(reply.to_string())
}

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
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The upstream argv: the `env` utility sets the mock variables for the
/// child only, then runs this test binary as the mock.
fn mock_upstream_command(dir: &Path, extra_env: &[&str]) -> Vec<String> {
    let mut argv = vec![
        "env".to_string(),
        "MCP_GUARDRAIL_MOCK_UPSTREAM=1".to_string(),
        format!("MCP_GUARDRAIL_MOCK_LOG={}", dir.join("mock.log").display()),
    ];
    argv.extend(extra_env.iter().map(|assignment| assignment.to_string()));
    argv.push(
        std::env::current_exe()
            .expect("the test binary path")
            .display()
            .to_string(),
    );
    argv
}

/// A proxy over the mock with the default policy, an audit file in `dir`,
/// the pending broker, and `stderr` as its stderr writer.
fn proxy_config(dir: &Path, extra_env: &[&str], stderr: &SharedBuffer) -> ProxyConfig {
    ProxyConfig {
        session_id: "integration".to_string(),
        upstream_command: mock_upstream_command(dir, extra_env),
        engine: PolicyEngine::from_path(Path::new(DEFAULT_POLICY))
            .expect("the default policy loads"),
        audit_sink: Box::new(
            JsonlAuditSink::create(&dir.join("audit.jsonl")).expect("create the audit file"),
        ),
        approval_broker: Box::new(PendingApprovalBroker),
        stderr: SharedLineWriter::from_writer(Box::new(stderr.clone())),
    }
}

/// Host-side ends of two in-memory pipes, and the proxy-side ends.
struct HostPipes {
    to_proxy: DuplexStream,
    from_proxy: DuplexStream,
    proxy_in: DuplexStream,
    proxy_out: DuplexStream,
}

fn host_pipes() -> HostPipes {
    let (to_proxy, proxy_in) = tokio::io::duplex(64 * 1024);
    let (proxy_out, from_proxy) = tokio::io::duplex(64 * 1024);
    HostPipes {
        to_proxy,
        from_proxy,
        proxy_in,
        proxy_out,
    }
}

/// Writes `frames`, one per line, closes host input, and reads every host
/// output line until the proxy closes it.
async fn run_session(
    config: ProxyConfig,
    frames: Vec<Vec<u8>>,
) -> (Result<ExitStatus, ProxyError>, Vec<Value>) {
    let pipes = host_pipes();
    let mut to_proxy = pipes.to_proxy;
    let from_proxy = pipes.from_proxy;
    let host = async move {
        for frame in frames {
            to_proxy
                .write_all(&frame)
                .await
                .expect("write a host frame");
            to_proxy.write_all(b"\n").await.expect("write a newline");
        }
        drop(to_proxy);
        let mut lines = BufReader::new(from_proxy).lines();
        let mut replies = Vec::new();
        while let Some(line) = lines.next_line().await.expect("read host output") {
            let reply: Value = serde_json::from_str(&line)
                .unwrap_or_else(|error| panic!("host output line is not JSON ({error}): {line}"));
            replies.push(reply);
        }
        replies
    };
    tokio::join!(
        run_proxy_with_io(config, pipes.proxy_in, pipes.proxy_out),
        host
    )
}

/// Writes one frame and waits for the next host output line.
async fn send_and_read(
    to_proxy: &mut DuplexStream,
    from_proxy: &mut Lines<BufReader<DuplexStream>>,
    frame: &str,
) -> Value {
    to_proxy
        .write_all(format!("{frame}\n").as_bytes())
        .await
        .expect("write a host frame");
    let line = from_proxy
        .next_line()
        .await
        .expect("read host output")
        .expect("a reply before host output closes");
    serde_json::from_str(&line).expect("host output line is JSON")
}

fn frames(lines: &[&str]) -> Vec<Vec<u8>> {
    lines.iter().map(|line| line.as_bytes().to_vec()).collect()
}

fn reply_with_id(replies: &[Value], id: i64) -> &Value {
    replies
        .iter()
        .find(|reply| reply["id"] == id)
        .unwrap_or_else(|| panic!("no reply with id {id} in {replies:?}"))
}

fn mock_log(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("mock.log")).expect("the mock created its log")
}

fn audit_lines(text: &str) -> Vec<Value> {
    text.lines()
        .map(|line| serde_json::from_str(line).expect("each audit line is JSON"))
        .collect()
}

fn count_lines(text: &str, wanted: &str) -> usize {
    text.lines().filter(|line| *line == wanted).count()
}

async fn relays_allowed_traffic_and_child_responses() {
    let dir = TempDir::new().expect("create a temp dir");
    let stderr = SharedBuffer::default();
    let (status, replies) = run_session(
        proxy_config(dir.path(), &[], &stderr),
        frames(&[INITIALIZE, INITIALIZED, TOOLS_LIST, SEARCH_FILES]),
    )
    .await;
    status.expect("the session ends with the child status");
    assert_eq!(replies.len(), 3, "host output: {replies:?}");
    assert_eq!(replies[0]["id"], 1);
    assert_eq!(replies[0]["result"]["serverInfo"]["name"], "mock-upstream");
    assert_eq!(replies[1]["id"], 2);
    assert_eq!(replies[1]["result"]["tools"][0]["name"], "search_files");
    assert_eq!(replies[2]["id"], 3);
    assert_eq!(
        replies[2]["result"]["content"][0]["text"],
        "mock:search_files"
    );
    assert_eq!(
        mock_log(dir.path()),
        format!("{INITIALIZE}\n{INITIALIZED}\n{TOOLS_LIST}\n{SEARCH_FILES}\n")
    );
    assert_eq!(
        count_lines(&stderr.text(), MOCK_STDERR_LINE),
        1,
        "proxy stderr: {:?}",
        stderr.text()
    );
}

async fn denied_sensitive_read_sends_zero_bytes_to_child() {
    let dir = TempDir::new().expect("create a temp dir");
    let (status, replies) = run_session(
        proxy_config(dir.path(), &[], &SharedBuffer::default()),
        frames(&[SHADOW_READ]),
    )
    .await;
    status.expect("the session ends with the child status");
    assert_eq!(replies.len(), 1, "host output: {replies:?}");
    assert_eq!(replies[0]["id"], 1);
    assert_eq!(replies[0]["error"]["code"], -32001);
    assert_eq!(
        replies[0]["error"]["data"]["rule_id"],
        "deny-system-credential-files"
    );
    assert_eq!(mock_log(dir.path()), "", "the child received bytes");
}

async fn tainted_shell_is_denied_after_untrusted_fetch() {
    let dir = TempDir::new().expect("create a temp dir");
    let (status, replies) = run_session(
        proxy_config(dir.path(), &[], &SharedBuffer::default()),
        frames(&[WEB_FETCH, SHELL_LS]),
    )
    .await;
    status.expect("the session ends with the child status");
    let fetch = reply_with_id(&replies, 1);
    let shell = reply_with_id(&replies, 2);
    assert_eq!(fetch["result"]["content"][0]["text"], "mock:WebFetch");
    assert_eq!(shell["error"]["code"], -32001);
    assert_eq!(shell["error"]["data"]["rule_id"], "tainted-deny-shell-exec");
    assert_eq!(shell["error"]["data"]["taint_chain"], json!(["1:WebFetch"]));
    assert_eq!(mock_log(dir.path()), format!("{WEB_FETCH}\n"));
}

async fn tainted_workspace_write_requires_approval() {
    let dir = TempDir::new().expect("create a temp dir");
    let (status, replies) = run_session(
        proxy_config(dir.path(), &[], &SharedBuffer::default()),
        frames(&[READ_EMAIL, WRITE_FILE]),
    )
    .await;
    status.expect("the session ends with the child status");
    let write = reply_with_id(&replies, 2);
    assert_eq!(write["error"]["code"], -32002);
    assert_eq!(
        write["error"]["data"]["rule_id"],
        "tainted-approve-workspace-write"
    );
    assert_eq!(mock_log(dir.path()), format!("{READ_EMAIL}\n"));
}

async fn audit_line_precedes_reply_and_redacts_secrets() {
    let dir = TempDir::new().expect("create a temp dir");
    let audit_path = dir.path().join("audit.jsonl");
    let config = proxy_config(dir.path(), &[], &SharedBuffer::default());
    let pipes = host_pipes();
    let mut to_proxy = pipes.to_proxy;
    let mut from_proxy = BufReader::new(pipes.from_proxy).lines();
    let host = async {
        let issue_reply = send_and_read(&mut to_proxy, &mut from_proxy, SECRET_ISSUE).await;
        let audit_at_issue_reply =
            std::fs::read_to_string(&audit_path).expect("read the audit file");
        let shadow_reply = send_and_read(&mut to_proxy, &mut from_proxy, SECRET_SHADOW_READ).await;
        let audit_at_shadow_reply =
            std::fs::read_to_string(&audit_path).expect("read the audit file");
        drop(to_proxy);
        (
            issue_reply,
            audit_at_issue_reply,
            shadow_reply,
            audit_at_shadow_reply,
        )
    };
    let (status, (issue_reply, audit_at_issue_reply, shadow_reply, audit_at_shadow_reply)) = tokio::join!(
        run_proxy_with_io(config, pipes.proxy_in, pipes.proxy_out),
        host
    );
    status.expect("the session ends with the child status");
    let issue_audit = audit_lines(&audit_at_issue_reply);
    let shadow_audit = audit_lines(&audit_at_shadow_reply);
    assert_eq!(issue_reply["id"], 1);
    assert_eq!(
        issue_audit.len(),
        1,
        "audit at the first reply: {audit_at_issue_reply}"
    );
    assert_eq!(issue_audit[0]["tool_name"], "create_issue");
    assert_eq!(shadow_reply["id"], 2);
    assert_eq!(shadow_reply["error"]["code"], -32001);
    assert_eq!(
        shadow_audit.len(),
        2,
        "audit at the second reply: {audit_at_shadow_reply}"
    );
    assert_eq!(shadow_audit[1]["tool_name"], "read_file");
    assert_eq!(shadow_audit[1]["rule_id"], "deny-system-credential-files");
    assert!(
        !audit_at_shadow_reply.contains("ghp_REPLAYfake0123456789abcdefghijklmnop"),
        "audit leaks the GitHub token: {audit_at_shadow_reply}"
    );
    assert!(
        !audit_at_shadow_reply.contains("AKIAREPLAYFAKE000001"),
        "audit leaks the AWS key id: {audit_at_shadow_reply}"
    );
}

async fn malformed_frames_get_errors_and_session_continues() {
    let dir = TempDir::new().expect("create a temp dir");
    let oversize_frame = vec![b'a'; MAX_FRAME_BYTES + 1];
    let (status, replies) = run_session(
        proxy_config(dir.path(), &[], &SharedBuffer::default()),
        vec![
            b"{bad".to_vec(),
            BATCH.as_bytes().to_vec(),
            oversize_frame,
            SEARCH_AFTER_ERRORS.as_bytes().to_vec(),
        ],
    )
    .await;
    status.expect("the session ends with the child status");
    assert_eq!(replies.len(), 4, "host output: {replies:?}");
    assert_eq!(replies[0]["error"]["code"], -32700);
    assert_eq!(replies[0]["id"], Value::Null);
    assert_eq!(replies[1]["error"]["code"], -32600);
    assert_eq!(replies[1]["id"], Value::Null);
    assert_eq!(replies[2]["error"]["code"], -32600);
    assert_eq!(replies[2]["id"], Value::Null);
    assert_eq!(
        replies[2]["error"]["data"]["detail"],
        format!("frame exceeds {MAX_FRAME_BYTES} bytes")
    );
    assert_eq!(replies[3]["id"], 4);
    assert_eq!(
        replies[3]["result"]["content"][0]["text"],
        "mock:search_files"
    );
    assert_eq!(mock_log(dir.path()), format!("{SEARCH_AFTER_ERRORS}\n"));
}

async fn host_eof_shuts_down_child_cleanly() {
    let dir = TempDir::new().expect("create a temp dir");
    let pipes = host_pipes();
    let _from_proxy = pipes.from_proxy;
    drop(pipes.to_proxy);
    let status = run_proxy_with_io(
        proxy_config(dir.path(), &[], &SharedBuffer::default()),
        pipes.proxy_in,
        pipes.proxy_out,
    )
    .await
    .expect("the session ends with the child status");
    assert!(status.success(), "child status {status:?}");
}

async fn child_exit_ends_session_with_its_code() {
    let dir = TempDir::new().expect("create a temp dir");
    let pipes = host_pipes();
    // The host keeps both of its pipe ends open for the whole session.
    let _to_proxy = pipes.to_proxy;
    let _from_proxy = pipes.from_proxy;
    let status = run_proxy_with_io(
        proxy_config(
            dir.path(),
            &["MCP_GUARDRAIL_MOCK_EXIT_CODE=3"],
            &SharedBuffer::default(),
        ),
        pipes.proxy_in,
        pipes.proxy_out,
    )
    .await
    .expect("the session ends with the child status");
    assert_eq!(status.code(), Some(3));
}

async fn child_exit_with_open_descendant_pipe_returns_after_drain_grace() {
    let dir = TempDir::new().expect("create a temp dir");
    let stderr = SharedBuffer::default();
    let pipes = host_pipes();
    // The host keeps both of its pipe ends open for the whole session.
    let _to_proxy = pipes.to_proxy;
    let _from_proxy = pipes.from_proxy;
    let status = tokio::time::timeout(
        Duration::from_secs(3),
        run_proxy_with_io(
            proxy_config(
                dir.path(),
                &[
                    "MCP_GUARDRAIL_MOCK_EXIT_CODE=4",
                    "MCP_GUARDRAIL_MOCK_HOLD_PIPES=1",
                ],
                &stderr,
            ),
            pipes.proxy_in,
            pipes.proxy_out,
        ),
    )
    .await
    .expect("the proxy returns within 3 s")
    .expect("the session ends with the child status");
    assert_eq!(status.code(), Some(4));
    assert_eq!(
        count_lines(&stderr.text(), PIPE_DIAGNOSTIC),
        1,
        "proxy stderr: {:?}",
        stderr.text()
    );
}

/// `WriterDrains` in `specs/SessionLifecycle.tla`: with stdout closed and stderr still open, the
/// queue stays open. A debug assertion in `SessionLifecycle` fails this test if it closes early.
async fn queue_stays_open_until_both_relays_end() {
    let dir = TempDir::new().expect("create a temp dir");
    let stderr = SharedBuffer::default();
    let mut config = proxy_config(dir.path(), &[], &stderr);
    config.upstream_command = ["sh", "-c", "exec 1>&-; sleep 1"]
        .map(String::from)
        .to_vec();
    let (host_writer, proxy_input) = tokio::io::duplex(1024);
    drop(host_writer);
    let (proxy_output, _host_reader) = tokio::io::duplex(1024);
    let status = run_proxy_with_io(config, proxy_input, proxy_output)
        .await
        .expect("the session ends cleanly");
    assert!(status.success(), "status: {status:?}");
}

/// A host output that fails every write.
struct BrokenHostOutput;

impl tokio::io::AsyncWrite for BrokenHostOutput {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
        _bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// `WriterFailureFinishes` in `specs/SessionLifecycle.tla`: host input is stuck writing to a
/// child that never reads, and the dead host must still end the session.
async fn host_output_failure_ends_session_with_child_not_reading() {
    let dir = TempDir::new().expect("create a temp dir");
    let stderr = SharedBuffer::default();
    let mut config = proxy_config(dir.path(), &[], &stderr);
    config.upstream_command = ["sh", "-c", "sleep 1; echo line-for-the-host; exec sleep 60"]
        .map(String::from)
        .to_vec();
    let (mut host_writer, proxy_input) = tokio::io::duplex(64 * 1024);
    let padding = "x".repeat(1024 * 1024);
    let frame = format!(
        "{}\n",
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"pad": padding}})
    );
    let flood = tokio::spawn(async move {
        // More than a pipe holds, so a write to the child blocks.
        while host_writer.write_all(frame.as_bytes()).await.is_ok() {}
    });
    let outcome = run_proxy_with_io(config, proxy_input, BrokenHostOutput).await;
    flood.abort();
    assert!(
        matches!(outcome, Err(ProxyError::Io(_))),
        "outcome: {outcome:?}"
    );
}

async fn cli_exits_when_child_exits_with_stdin_open() {
    let mut cli = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-guardrail-proxy"))
        .args([
            "proxy",
            "--policy",
            DEFAULT_POLICY,
            "--",
            "env",
            "MCP_GUARDRAIL_MOCK_UPSTREAM=1",
            "MCP_GUARDRAIL_MOCK_EXIT_CODE=3",
        ])
        .arg(std::env::current_exe().expect("the test binary path"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn the CLI binary");
    // `Child::wait` drops a stdin handle still held in the `Child`, which
    // would give the CLI host EOF. Holding it here keeps host input open.
    let stdin = cli.stdin.take().expect("the CLI stdin is piped");
    let status = tokio::time::timeout(Duration::from_secs(3), cli.wait())
        .await
        .expect("the CLI exits within 3 s while its stdin stays open")
        .expect("wait for the CLI");
    assert_eq!(status.code(), Some(3));
    drop(stdin);
}

/// With no `--policy`, the binary enforces the embedded default policy. The
/// upstream is `cat`, so a forwarded frame would come back as a second line.
async fn cli_denies_shadow_read_with_the_embedded_default_policy() {
    let mut cli = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-guardrail-proxy"))
        .args(["proxy", "--", "cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn the CLI binary");
    let mut stdin = cli.stdin.take().expect("the CLI stdin is piped");
    stdin
        .write_all(SHADOW_READ.as_bytes())
        .await
        .expect("write the host frame");
    stdin.write_all(b"\n").await.expect("write a newline");
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(3), cli.wait_with_output())
        .await
        .expect("the CLI exits within 3 s after host EOF")
        .expect("wait for the CLI");
    assert!(
        output.status.success(),
        "proxy exit status: {:?}",
        output.status
    );
    let stdout = String::from_utf8(output.stdout).expect("the CLI stdout is UTF-8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "stdout: {stdout:?}");
    let reply: Value = serde_json::from_str(lines[0]).expect("the reply is JSON");
    assert_eq!(reply["id"], json!(1));
    assert_eq!(reply["error"]["code"], json!(-32001));
}

/// What one run of the CLI binary printed, and its exit code.
struct CliRun {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl CliRun {
    fn last_stdout_line(&self) -> Option<&str> {
        self.stdout.lines().last()
    }

    /// The stderr lines that hold the probe cause text.
    fn probe_cause_lines(&self) -> Vec<&str> {
        self.stderr
            .lines()
            .filter(|line| line.contains(PROBE_CAUSE))
            .collect()
    }
}

/// Runs the CLI binary with `args`, in `dir`, with `env` added to its own
/// environment. The CLI must exit within 3 s.
async fn run_cli(dir: &Path, env: &[(&str, &str)], args: &[&str]) -> CliRun {
    let cli = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-guardrail-proxy"))
        .args(args)
        .envs(env.iter().copied())
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn the CLI binary");
    let output = tokio::time::timeout(Duration::from_secs(3), cli.wait_with_output())
        .await
        .unwrap_or_else(|_| panic!("the CLI exits within 3 s: {args:?}"))
        .expect("wait for the CLI");
    CliRun {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// This test binary's path, which runs as the mock under `MOCK_UPSTREAM_ENV`.
fn mock_program() -> String {
    std::env::current_exe()
        .expect("the test binary path")
        .display()
        .to_string()
}

/// The upstream is this test binary with no `env` wrapper, so the mock
/// variables and the relative log path reach both runs only through the
/// probe's own environment and working directory.
async fn cli_probe_passes_when_both_runs_list_the_same_tools() {
    let dir = TempDir::new().expect("create a temp dir");
    let mock = mock_program();
    let run = run_cli(
        dir.path(),
        &[MOCK_UPSTREAM_ENV, MOCK_LOG_ENV],
        &["probe", "--", &mock],
    )
    .await;
    assert_eq!(
        run.code,
        Some(0),
        "stdout: {} stderr: {}",
        run.stdout,
        run.stderr
    );
    assert_eq!(
        count_lines(&run.stdout, "direct: 1 tools"),
        1,
        "stdout: {}",
        run.stdout
    );
    assert_eq!(
        count_lines(&run.stdout, "through the proxy: 1 tools"),
        1,
        "stdout: {}",
        run.stdout
    );
    assert_eq!(
        count_lines(&run.stdout, "tool lists: equal"),
        1,
        "stdout: {}",
        run.stdout
    );
    assert_eq!(
        run.last_stdout_line(),
        Some("result: PASS"),
        "stdout: {}",
        run.stdout
    );
    assert_eq!(
        count_lines(&run.stderr, MOCK_STDERR_LINE),
        2,
        "the mock's ready line from each run, stderr: {}",
        run.stderr
    );
    assert_eq!(
        run.probe_cause_lines(),
        Vec::<&str>::new(),
        "stderr: {}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("mcp_guardrail_audit"),
        "the probe wrote an audit line: {}",
        run.stderr
    );
}

/// One row per non-zero end the binary can reach. Each row gets its own
/// folder, because the mock counts its starts from its log.
async fn cli_probe_fails_closed_and_names_the_cause() {
    let mock = mock_program();

    // Usage errors: exit 2 and nothing on stdout.
    let dir = TempDir::new().expect("create a temp dir");
    let run = run_cli(
        dir.path(),
        &[MOCK_UPSTREAM_ENV, MOCK_LOG_ENV],
        &["probe", "--timeout", "0", "--", &mock],
    )
    .await;
    assert_eq!(run.code, Some(2), "--timeout 0, stderr: {}", run.stderr);
    assert_eq!(run.stdout, "", "--timeout 0");
    let run = run_cli(
        dir.path(),
        &[MOCK_UPSTREAM_ENV, MOCK_LOG_ENV],
        &["probe", "--timeout", "3601", "--", &mock],
    )
    .await;
    assert_eq!(run.code, Some(2), "--timeout 3601, stderr: {}", run.stderr);
    assert_eq!(run.stdout, "", "--timeout 3601");
    let run = run_cli(dir.path(), &[], &["probe", "--"]).await;
    assert_eq!(run.code, Some(2), "no upstream, stderr: {}", run.stderr);
    assert_eq!(run.stdout, "", "no upstream");

    // A missing program: the spawn error names it.
    let dir = TempDir::new().expect("create a temp dir");
    let run = run_cli(
        dir.path(),
        &[],
        &["probe", "--", "/nonexistent/mcp-guardrail-probe-missing"],
    )
    .await;
    assert_eq!(run.code, Some(1), "missing program, stderr: {}", run.stderr);
    assert_eq!(run.stdout, "", "missing program");
    let causes = run.probe_cause_lines();
    assert_eq!(causes.len(), 1, "missing program, stderr: {}", run.stderr);
    assert!(
        causes[0].contains(
            "failed to start the upstream command: /nonexistent/mcp-guardrail-probe-missing:"
        ),
        "missing program, stderr: {}",
        run.stderr
    );

    // The handshake fails: `initialize` gets an error reply.
    let dir = TempDir::new().expect("create a temp dir");
    let run = run_cli(
        dir.path(),
        &[
            MOCK_UPSTREAM_ENV,
            MOCK_LOG_ENV,
            ("MCP_GUARDRAIL_MOCK_INITIALIZE_ERROR", "1"),
        ],
        &["probe", "--", &mock],
    )
    .await;
    assert_eq!(
        run.code,
        Some(1),
        "initialize error, stderr: {}",
        run.stderr
    );
    assert_eq!(run.stdout, "", "initialize error");
    let causes = run.probe_cause_lines();
    assert_eq!(causes.len(), 1, "initialize error, stderr: {}", run.stderr);
    assert!(
        causes[0].contains("initialize")
            && causes[0].contains("-32603")
            && causes[0].contains("mock initialize failure"),
        "initialize error, stderr: {}",
        run.stderr
    );

    // The upstream exits before it replies: the cause names the step and the exit code.
    let dir = TempDir::new().expect("create a temp dir");
    let run = run_cli(
        dir.path(),
        &[
            MOCK_UPSTREAM_ENV,
            MOCK_LOG_ENV,
            ("MCP_GUARDRAIL_MOCK_EXIT_CODE", "3"),
        ],
        &["probe", "--", &mock],
    )
    .await;
    assert_eq!(run.code, Some(1), "early exit, stderr: {}", run.stderr);
    assert_eq!(run.stdout, "", "early exit");
    let causes = run.probe_cause_lines();
    assert_eq!(causes.len(), 1, "early exit, stderr: {}", run.stderr);
    assert!(
        causes[0].contains("initialize") && causes[0].contains("exit code 3"),
        "early exit, stderr: {}",
        run.stderr
    );

    // The upstream never answers: the direct run times out.
    let dir = TempDir::new().expect("create a temp dir");
    let run = run_cli(
        dir.path(),
        &[
            MOCK_UPSTREAM_ENV,
            MOCK_LOG_ENV,
            ("MCP_GUARDRAIL_MOCK_SILENT", "1"),
        ],
        &["probe", "--timeout", "1", "--", &mock],
    )
    .await;
    assert_eq!(run.code, Some(1), "silent, stderr: {}", run.stderr);
    assert_eq!(run.stdout, "", "silent");
    assert_eq!(
        run.probe_cause_lines(),
        ["mcp-guardrail-proxy: probe direct: no initialize reply within 1 s"],
        "silent, stderr: {}",
        run.stderr
    );

    // The tool list changes on the second start: one tool dropped, one added, one
    // redefined, and one unchanged tool listed in another position.
    let dir = TempDir::new().expect("create a temp dir");
    let run = run_cli(
        dir.path(),
        &[
            MOCK_UPSTREAM_ENV,
            MOCK_LOG_ENV,
            ("MCP_GUARDRAIL_MOCK_TOOLS_CHANGE_ON_SECOND_START", "1"),
        ],
        &["probe", "--", &mock],
    )
    .await;
    assert_eq!(run.code, Some(1), "lists differ, stderr: {}", run.stderr);
    assert_eq!(
        count_lines(&run.stdout, "direct: 3 tools"),
        1,
        "stdout: {}",
        run.stdout
    );
    assert_eq!(
        count_lines(&run.stdout, "through the proxy: 3 tools"),
        1,
        "stdout: {}",
        run.stdout
    );
    assert_eq!(
        count_lines(&run.stdout, "tool lists: differ"),
        1,
        "stdout: {}",
        run.stdout
    );
    assert_eq!(
        count_lines(&run.stdout, "only direct: list_dir"),
        1,
        "stdout: {}",
        run.stdout
    );
    assert_eq!(
        count_lines(&run.stdout, "only through the proxy: write_file"),
        1,
        "stdout: {}",
        run.stdout
    );
    assert_eq!(
        count_lines(&run.stdout, "definition differs: read_file"),
        1,
        "stdout: {}",
        run.stdout
    );
    assert_eq!(
        run.last_stdout_line(),
        Some("result: FAIL"),
        "stdout: {}",
        run.stdout
    );
    assert_eq!(
        run.probe_cause_lines(),
        ["mcp-guardrail-proxy: probe: the tool lists differ"],
        "lists differ, stderr: {}",
        run.stderr
    );

    // The second start never answers and has 256 KiB pending at stdin EOF: the
    // proxied run times out, and the probe still reads host output to its end.
    let dir = TempDir::new().expect("create a temp dir");
    let run = run_cli(
        dir.path(),
        &[
            MOCK_UPSTREAM_ENV,
            MOCK_LOG_ENV,
            ("MCP_GUARDRAIL_MOCK_SILENT_ON_SECOND_START", "1"),
        ],
        &["probe", "--timeout", "1", "--", &mock],
    )
    .await;
    assert_eq!(run.code, Some(1), "proxied timeout, stderr: {}", run.stderr);
    assert_eq!(
        count_lines(&run.stdout, "direct: 1 tools"),
        1,
        "stdout: {}",
        run.stdout
    );
    assert_eq!(
        run.last_stdout_line(),
        Some("result: FAIL"),
        "stdout: {}",
        run.stdout
    );
    assert_eq!(
        run.probe_cause_lines(),
        ["mcp-guardrail-proxy: probe through the proxy: no initialize reply within 1 s"],
        "proxied timeout, stderr: {}",
        run.stderr
    );
}

async fn cli_probe_reports_policy_fit_under_the_chosen_policy() {
    let mock = mock_program();

    // No `--policy`: the embedded default.
    let dir = TempDir::new().expect("create a temp dir");
    let run = run_cli(
        dir.path(),
        &[MOCK_UPSTREAM_ENV, MOCK_LOG_ENV],
        &["probe", "--", &mock],
    )
    .await;
    assert_eq!(
        count_lines(
            &run.stdout,
            "policy: embedded default: 15 rules, 4 taint sources"
        ),
        1,
        "stdout: {} stderr: {}",
        run.stdout,
        run.stderr
    );
    assert!(
        run.stdout
            .lines()
            .any(|line| line.starts_with("search_files: clean allow (default-allow)")),
        "stdout: {}",
        run.stdout
    );

    // A policy file that denies the mock's tool: its path is the label, and its rule decides.
    let dir = TempDir::new().expect("create a temp dir");
    let policy_path = dir.path().join("deny-search.toml");
    std::fs::write(
        &policy_path,
        r#"[[rules]]
id = "deny-search"
description = "Searching files is not allowed under this test policy"
tool_regex = '^search_files$'
decision = "deny"
severity = "high"
"#,
    )
    .expect("write the policy file");
    let policy = policy_path.display().to_string();
    let run = run_cli(
        dir.path(),
        &[MOCK_UPSTREAM_ENV, MOCK_LOG_ENV],
        &["probe", "--policy", &policy, "--", &mock],
    )
    .await;
    assert!(
        run.stdout
            .lines()
            .any(|line| line.starts_with(&format!("policy: {policy}:"))),
        "stdout: {} stderr: {}",
        run.stdout,
        run.stderr
    );
    assert!(
        run.stdout
            .lines()
            .any(|line| line.starts_with("search_files: clean deny (deny-search)")),
        "stdout: {}",
        run.stdout
    );

    // A policy file that does not load: exit 1 before any upstream starts.
    let dir = TempDir::new().expect("create a temp dir");
    let policy_path = dir.path().join("broken.toml");
    std::fs::write(&policy_path, "[[rules]]\nid = \"unfinished\"\n")
        .expect("write the policy file");
    let policy = policy_path.display().to_string();
    let run = run_cli(
        dir.path(),
        &[MOCK_UPSTREAM_ENV, MOCK_LOG_ENV],
        &["probe", "--policy", &policy, "--", &mock],
    )
    .await;
    assert_eq!(run.code, Some(1), "bad policy, stderr: {}", run.stderr);
    assert_eq!(run.stdout, "", "bad policy");
    assert!(
        run.stderr.contains("mcp-guardrail-proxy: policy error:"),
        "bad policy, stderr: {}",
        run.stderr
    );
    assert!(
        !dir.path().join("mock.log").exists(),
        "an upstream started before the policy loaded"
    );
}
