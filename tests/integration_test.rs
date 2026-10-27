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

/// The mock upstream MCP server. It appends every received line to
/// `MCP_GUARDRAIL_MOCK_LOG` and answers requests with one line each.
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
            return ExitCode::SUCCESS;
        }
        log.write_all(line.as_bytes())
            .expect("append to the mock log");
        if let Some(reply) = mock_reply(line.trim_end_matches('\n')) {
            stdout
                .write_all(format!("{reply}\n").as_bytes())
                .expect("write a reply");
            stdout.flush().expect("flush stdout");
        }
    }
}

/// The mock's reply to one forwarded frame, or `None` for a notification or
/// a response.
fn mock_reply(line: &str) -> Option<String> {
    let frame: Value = serde_json::from_str(line).expect("the proxy forwards JSON frames");
    let method = frame.get("method")?.as_str()?;
    let id = frame.get("id")?.clone();
    let params = &frame["params"];
    let (key, value) = match method {
        "initialize" => {
            std::io::stderr()
                .write_all(format!("{MOCK_STDERR_LINE}\n").as_bytes())
                .expect("write the stderr line");
            (
                "result",
                json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}, "resources": {}}, "serverInfo": {"name": "mock-upstream", "version": "0.0.0"}}),
            )
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
