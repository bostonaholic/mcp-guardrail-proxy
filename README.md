# mcp-guardrail-proxy

A stdio proxy that sits between an MCP host and an upstream MCP server. It checks each `tools/call` and `resources/read` frame against a TOML policy and a session taint state, writes a redacted audit line, and then forwards the frame or answers the host with a JSON-RPC error.

Taint means the session has read untrusted content, such as a web page or an email. After that, the policy can block calls that send data out, such as shell, messaging, and upload tools.

## Install

```sh
cargo install --path .
```

The crate is not on crates.io yet.

## Quick start

Wrap an upstream server from a shell. The upstream command is a placeholder.

```sh
mcp-guardrail-proxy proxy --policy policies/default-policy.toml \
  --audit-log ~/.local/state/mcp-guardrail/audit.jsonl -- <upstream-command> [args...]
```

Add `--session-id <id>` to choose the id stamped on each audit line. The default is `<pid>-<unix millis>`.

The proxy relays the MCP handshake unchanged. A host call like this one reads a system credential file:

```json
{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}}}
```

The host gets this reply, and the upstream server receives nothing:

```json
{"jsonrpc":"2.0","id":9,"error":{"code":-32001,"message":"Policy denied","data":{"decision":"deny","reason":"Reading system credential files is never allowed","rule_id":"deny-system-credential-files","severity":"critical","taint_chain":[]}}}
```

The error code is `-32001` for a policy denial and `-32002` for a call that needs approval. The `data` keys appear in sorted order.

Check a policy file before you use it:

```sh
mcp-guardrail-proxy check-policy --policy policies/default-policy.toml
# policy OK: policies/default-policy.toml: 14 rules, 4 taint sources
```

## Architecture

The library crate is `mcp_guardrail_proxy`. The data plane has these modules.

| Module | Role |
|---|---|
| `protocol` | JSON-RPC envelopes, frame parsing, call views, and error replies |
| `taint` | The session taint state machine, which only moves from clean to tainted |
| `policy` | The TOML policy engine and its classification of each call |
| `telemetry` | Audit events, secret redaction, and the shared line writer |
| `proxy` | The `Interceptor` decision point and the async stdio relay |
| `replay` | The corpus replay behind the `replay` command |
| `control_plane` | Traits for policy, audit, and approval, with local defaults |

`Interceptor::handle_host_line` judges each host line in this order:

1. Parse the line. A parse error gets a reply and no audit.
2. Forward a response, or a request with any method other than `tools/call` or `resources/read`, as it is.
3. Reject an evaluated method sent as a notification or with `id: null` (`-32600`). Reject bad params, such as a missing `name` or `uri` (`-32602`). Neither case is audited.
4. Count the call and run `PolicyEngine::evaluate` against the session taint.
5. If the decision is `require-approval`, ask the approval broker. `Approved` forwards the call. `Denied` becomes a deny. `Pending` stays an approval-required error.
6. Write the audit event with the taint level from before the call. If the audit sink fails, the proxy denies the call and writes an `audit-fallback:` line.
7. If the call is forwarded, record it in the taint state. Only a call that matches a taint source taints the session.
8. Return the re-encoded frame for the child, or the error reply for the host.

Step 7 comes before the return, so the taint update lands before the proxy reads the next host line.

### Library entry points

The three entry points are `Interceptor`, `PolicyEngine`, and `SessionTaintState`. Use them to embed the engine in a Rust host:

```rust
use std::path::Path;

use mcp_guardrail_proxy::control_plane::PendingApprovalBroker;
use mcp_guardrail_proxy::policy::PolicyEngine;
use mcp_guardrail_proxy::protocol::{JsonRpcMessage, encode_frame};
use mcp_guardrail_proxy::proxy::{Interceptor, Verdict};
use mcp_guardrail_proxy::telemetry::{JsonlAuditSink, SharedLineWriter};

let engine = PolicyEngine::from_path(Path::new("policies/default-policy.toml"))?;
let mut interceptor = Interceptor::new(
    session_id,
    engine,
    Box::new(JsonlAuditSink::create(Path::new("audit.jsonl"))?),
    Box::new(PendingApprovalBroker),
    SharedLineWriter::stderr(),
);
match interceptor.handle_host_line(line) {
    Verdict::Forward(frame) => send_to_server(frame),
    Verdict::Reply(response) => send_to_host(encode_frame(&JsonRpcMessage::Response(response))),
}
```

## Open-core control plane seam

`src/control_plane.rs` defines three traits. A remote control plane can implement them without a change to the engine.

| Trait | Job | Local default |
|---|---|---|
| `PolicyProvider` | Supplies the policy as TOML text | `FilePolicyProvider`, which reads a local file |
| `AuditSink` | Receives one structured event per decision | `JsonlAuditSink` writes JSON lines. `NullAuditSink` discards events. |
| `ApprovalBroker` | Decides if a `require-approval` call may proceed | `PendingApprovalBroker`, which leaves every request pending |

The engine takes policy text, and the interceptor takes boxed trait objects. `PolicyEngine::from_provider` builds an engine from any `PolicyProvider`. A remote provider fetches the TOML text and returns it from `policy_source`. A remote audit sink sends each event from `emit`. A remote approval broker returns `Approved` or `Denied` from `request_approval`. The default code makes no network calls.

## Policy

A policy file holds two TOML arrays. Every table rejects unknown fields, so a typo such as `when_taint` fails to load.

`[[taint_sources]]` fields:

| Field | Meaning |
|---|---|
| `id` | A unique name |
| `description` | Why the source is untrusted |
| `tool_regex` | Matches the tool name |
| `arg_regexes` | Optional. A source applies only if one regex matches the argument text. |

`[[rules]]` fields:

| Field | Meaning |
|---|---|
| `id` | A unique name |
| `description` | The reason text in replies and audit lines |
| `tool_regex` | Matches the tool name |
| `when_tainted` | Optional, default `false`. If `true`, the rule applies only in a tainted session. |
| `arg_regexes` | Optional. The rule applies only if one regex matches the argument text. |
| `decision` | `"allow"`, `"deny"`, or `"require-approval"` |
| `severity` | `"low"`, `"medium"`, `"high"`, or `"critical"` |

Regexes are unanchored searches. Use `^`, `$`, and `(?m)` to anchor them. The tool name is `params.name`, or `resources/read` for a resource read. The argument text joins every string value of `params.arguments` with newlines. For a resource read, it is the URI.

Source ids and rule ids share one namespace, and a repeat fails to load. The ids `default-allow` and `audit-sink-failure` are reserved.

When more than one rule applies, `deny` beats `require-approval`, and `require-approval` beats `allow`. Among rules with the winning decision, the first one in file order supplies the `rule_id`, `severity`, and `reason`. If no rule applies, the decision is `allow` with the rule id `default-allow`.

### Default policy

`policies/default-policy.toml` holds 4 taint sources and 14 rules.

| Taint source | Matches |
|---|---|
| `untrusted-web-fetch` | `webfetch`, `web_fetch`, `fetch`, `fetch_url`, `http_get`, `http_request`, `curl`, `wget`, `browser_navigate`, `navigate` |
| `untrusted-email-read` | Tool names that start with `read_email` |
| `untrusted-github-issue` | Tool names that start with `get_issue` or `github_get_issue` |
| `untrusted-external-resource` | `resources/read` of a URI that starts with `http://` or `https://` |

| # | Rule id | Applies to | Decision | Severity |
|---|---|---|---|---|
| 1 | `deny-system-credential-files` | Any tool, args name `/etc/shadow` or `/etc/passwd` | deny | critical |
| 2 | `deny-ssh-key-material` | Any tool, args name a `.ssh` path | deny | critical |
| 3 | `deny-aws-credentials` | Any tool, args name `.aws/credentials` | deny | critical |
| 4 | `deny-dotenv-files` | Any tool, args name a `.env` file or `.env.<suffix>` | deny | high |
| 5 | `deny-destructive-shell` | Shell tools, args hold `rm -rf`, `mkfs`, `dd if=`, or a fork bomb | deny | critical |
| 6 | `deny-env-dump` | Shell tools, args hold `printenv`, a bare `env`, or `/proc/<pid>/environ` | deny | high |
| 7 | `tainted-deny-shell-exec` | Shell tools, tainted session | deny | critical |
| 8 | `tainted-deny-outbound-messaging` | Slack, Discord, and Telegram send tools, `send_message`, `post_message`, tainted session | deny | critical |
| 9 | `tainted-deny-outbound-email` | Email send, reply, and forward tools, tainted session | deny | critical |
| 10 | `tainted-deny-webhook` | Tools with `webhook`, `http_post`, or `post_request` in the name, tainted session | deny | critical |
| 11 | `tainted-deny-file-upload` | Tools with `upload`, `put_object`, `create_gist`, or `share_file` in the name, tainted session | deny | critical |
| 12 | `tainted-deny-url-query-payload` | The fetch tools and `resources/read`, args hold a URL with a query string, tainted session | deny | high |
| 13 | `tainted-approve-workspace-write` | `write_file`, `edit_file`, `create_file`, `apply_patch`, `str_replace_editor`, `move_file`, `delete_file`, tainted session | require-approval | medium |
| 14 | `tainted-approve-pr-creation` | `create_pull_request`, `create_pr`, `merge_pull_request`, tainted session | require-approval | high |

Shell tools are `shell`, `bash`, `sh`, `zsh`, `exec`, `execute`, `execute_command`, `run_command`, `run_shell_command`, `run_terminal_cmd`, and `terminal`. Matching ignores case.

### Known false positives and misses

These rules use regexes, so they block some harmless calls:

- Rule 4 blocks a write of a `.gitignore` line `.env`.
- Rule 1 blocks documentation that cites `/etc/passwd`.
- Rule 2 blocks written content that holds a `.ssh/` path.
- Rule 6 blocks `mkdir env`, `python -m venv env`, and `cd env && make`, because a bare `env` word looks like an environment dump.

Regexes also miss obfuscated commands such as `r''m`, `$(echo rm)`, and base64. They miss relative or symlinked paths and `/etc/./shadow`. A tool whose name the default regexes do not list gets `default-allow`, even in a tainted session.

## Limits

Taint lives in one proxy process. A host that runs several MCP servers runs one proxy per server. A source call through one proxy does not taint another proxy. For example, a `read_email` call through one proxy leaves `Shell` in a second proxy at `default-allow`. Separate proxies give no cross-server protection.

To share taint between an untrusted-source server and a privileged-sink server, run both behind one MCP aggregator. An MCP aggregator is a server that fronts several servers as one stdio server. Wrap that aggregator in one proxy.

The policy reads only `params.name`, `params.arguments`, and `params.uri`. Other `params` fields, such as `_meta`, reach the child without a check. Batches, `tools/call` notifications, and null ids get errors.

## Audit log

The proxy writes one JSON line per evaluated call. Keys appear in sorted order, so select lines by the `event` value and not by position. The fields are `arguments`, `decision`, `event`, `forwarded`, `latency_us`, `method`, `reason`, `rule_id`, `sequence`, `session_id`, `severity`, `taint_chain`, `taint_level`, `timestamp_ms`, and `tool_name`.

This line comes from a real run. The host sent a `read_file` call for `/etc/shadow` with a planted GitHub token in the arguments.

```json
{"arguments":{"path":"/etc/shadow","token":"[REDACTED:github-token]"},"decision":"deny","event":"mcp_guardrail_audit","forwarded":false,"latency_us":262,"method":"tools/call","reason":"Reading system credential files is never allowed","rule_id":"deny-system-credential-files","sequence":1,"session_id":"demo-session","severity":"critical","taint_chain":[],"taint_level":"Clean","timestamp_ms":1793105588461,"tool_name":"read_file"}
```

### Where lines go

Without `--audit-log`, audit lines go to stderr. Child stderr lines, `audit-fallback:` lines, and `mcp-guardrail-proxy:` diagnostics also go to stderr. All of them pass through one line writer, so lines never interleave. Child stderr lines longer than 64 KiB arrive split.

The host must read the proxy's stderr, as it must for any stdio server. The proxy relays child stderr with or without `--audit-log`. A host that stops reading stderr stalls the proxy when the pipe fills.

To select audit lines from a mixed stream, use this filter:

```sh
jq -cR 'fromjson? | objects | select(.event == "mcp_guardrail_audit")'
```

The filter trusts the child's stderr. A child line that carries the audit `event` value passes the filter. A child that forges audit lines already runs every forwarded call. `--audit-log` writes audit lines to a file that the child stderr relay never writes.

An `audit-fallback:` line, or a `rule_id` of `audit-sink-failure`, means the audit sink failed. The proxy denies every call until the sink recovers.

### Redaction

Redaction applies to the audit line only. The child still gets the real arguments. The proxy redacts these fields:

- `tool_name`
- `reason`
- each `taint_chain` entry
- `arguments`, both keys and values

It replaces each match with `[REDACTED:<kind>]`. The kinds are `pem-private-key`, `bearer-token`, `github-token`, `aws-access-key-id`, and `sk-api-key`. If two keys in one object become the same key after redaction, the last value wins.

## Formal verification

`specs/McpGuardrailTaint.tla` models one session that handles calls one at a time. Each call moves through five phases: `Idle`, `Received`, `Evaluated`, `Audited`, `Done`.

The model has these variables:

- `sessionTaint`, either `Clean` or `Tainted`
- `taintHistory`, the taint and reset events
- `pendingCall`, the call in flight
- `decision`, the verdict for that call
- `forwardedToChild`, whether the child received the call
- `auditLog`, one entry per audited call
- `phase`, the current phase
- `callsCompleted`, bounded by `MaxCalls`

The model checks four invariants:

- `NoUnapprovedTaintedSinkForwarded`: a privileged-sink call never reaches the child in a tainted session unless an approval overrides it.
- `SensitiveArgsNeverForwarded`: a call with sensitive arguments never reaches the child.
- `MonotonicSessionTaint`: the session goes from tainted to clean only through a recorded reset.
- `CompleteAuditTrail`: every call has an audit entry that matches its decision, and a forward happens only after the audit entry.

The config also checks the variable types and one step property, `MonotonicTaintStep`.

### The three tiers

`scripts/verify-tla.sh` runs the first available tier and nothing else:

1. `tlc` is on your `PATH`. The script runs TLC on each spec.
2. `java` exists and `.tla-cache/tla2tools.jar` exists or downloads. `MCP_GUARDRAIL_OFFLINE=1` skips the download.
3. `cargo` exists, or `rustc` exists and there is no `Cargo.toml`. The script runs the Rust mirror in `tests/tla_trace_equivalence.rs`, one test per spec.

The script also runs `specs/McpGuardrailTaintBroken.tla`, which adds a `ForwardEarly` action. That action forwards a privileged-sink call before the taint check. The check passes only if this spec violates `NoUnapprovedTaintedSinkForwarded`. The shortest counterexample has 7 actions:

1. `Receive` of an `UntrustedSource` call with safe arguments
2. `Evaluate`
3. `Audit`
4. `Forward`, which taints the session
5. `Complete`
6. `Receive` of a `PrivilegedSink` call with safe arguments and no override
7. `ForwardEarly`

### Which tier this repository used

This repository's history was verified with tier 3 only, the Rust mirror, because no TLC was available. No tool has read the `.tla` text. A person with TLC should run tier 1 or tier 2 once. That run should report 3619 distinct states for `McpGuardrailTaint` at `MaxCalls = 3`. A different count means the spec and the mirror diverged.

The project skill `.claude/skills/verify-taint-invariants/SKILL.md` describes how to re-run the checks and prove that they catch a deliberate break.

## MCP client setup

Put the proxy in front of the upstream server in the client config. Use absolute paths. Replace `<upstream-command>` and `<arg>` with the server you want to guard.

Cursor, in `mcp.json`:

```json
{
  "mcpServers": {
    "guarded": {
      "command": "mcp-guardrail-proxy",
      "args": ["proxy", "--policy", "/abs/path/default-policy.toml", "--", "<upstream-command>", "<arg>"]
    }
  }
}
```

Claude Desktop, in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "guarded": {
      "command": "mcp-guardrail-proxy",
      "args": ["proxy", "--policy", "/abs/path/default-policy.toml", "--", "<upstream-command>", "<arg>"]
    }
  }
}
```

Grok Bot should take the same `mcpServers` shape, but nobody has tested its format. Check its documentation before you rely on this block.

```json
{
  "mcpServers": {
    "guarded": {
      "command": "mcp-guardrail-proxy",
      "args": ["proxy", "--policy", "/abs/path/default-policy.toml", "--", "<upstream-command>", "<arg>"]
    }
  }
}
```

## Replay and benchmarks

The replay command runs a corpus of 10 prompt-injection scenarios against a policy and reports the outcome:

```sh
mcp-guardrail-proxy replay --policy policies/default-policy.toml --corpus fixtures/replay-corpus.json
```

The recorded output:

```text
replay: 10/10 scenarios matched, 36/36 steps matched
blocked: tp 15, fp 0, fn 0 (precision 100.0%, recall 100.0%)
exfiltration: 7 steps, 0 false negatives
latency: max 151 us, mean 46.5 us (budget 1000 us)
result: PASS
```

This output came from a debug build with `[profile.dev.package."*"] opt-level = 3` on the author's machine. Latency varies by machine. The other lines are deterministic. The command exits 0 on `PASS` and 1 on `FAIL`.

## Development

These commands must all exit 0 before a change is done:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
MCP_GUARDRAIL_OFFLINE=1 ./scripts/verify-tla.sh
cargo run -- check-policy --policy policies/default-policy.toml
cargo run -- replay --policy policies/default-policy.toml --corpus fixtures/replay-corpus.json
! grep -rnE 'std::net|TcpStream|UdpSocket|reqwest|hyper' src tests
```

The last command proves that no source or test file opens a network connection.

After a change under `src`, `specs`, `tests`, `scripts`, `policies`, or `fixtures`, use the `verify-taint-invariants` skill in `.claude/skills/verify-taint-invariants/SKILL.md`. It checks that the verification still matches the tree and proves that the checks fail on a deliberate break.

## License

`MIT OR Apache-2.0`. See `LICENSE-MIT` and `LICENSE-APACHE`.
