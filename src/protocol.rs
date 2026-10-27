//! JSON-RPC 2.0 envelopes for MCP, frame parsing, call views, and error replies.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// JSON-RPC error code for a call that policy denied.
pub const POLICY_DENIED_CODE: i64 = -32001;
/// JSON-RPC error code for a call that needs human approval.
pub const APPROVAL_REQUIRED_CODE: i64 = -32002;
/// JSON-RPC error code for a frame that is not valid JSON.
pub const PARSE_ERROR_CODE: i64 = -32700;
/// JSON-RPC error code for a frame that is not a valid request.
pub const INVALID_REQUEST_CODE: i64 = -32600;
/// JSON-RPC error code for a request with unusable parameters.
pub const INVALID_PARAMS_CODE: i64 = -32602;

const JSONRPC_VERSION: &str = "2.0";
const TOOLS_CALL_METHOD: &str = "tools/call";
const RESOURCES_READ_METHOD: &str = "resources/read";

/// A JSON-RPC request id: a number, a string, or `null`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// An integer id.
    Number(i64),
    /// A string id.
    String(String),
    /// The `null` id, used when a request is too malformed to carry one.
    Null,
}

/// A JSON-RPC request: a method call that expects a response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// The protocol version, always `"2.0"` once parsed.
    pub jsonrpc: String,
    /// The id that the response echoes.
    pub id: RequestId,
    /// The method name.
    pub method: String,
    /// The method parameters, absent when the frame has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// A JSON-RPC notification: a method call with no id and no response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    /// The protocol version, always `"2.0"` once parsed.
    pub jsonrpc: String,
    /// The method name.
    pub method: String,
    /// The method parameters, absent when the frame has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// The error object of a JSON-RPC response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// The numeric error code.
    pub code: i64,
    /// A short description of the error.
    pub message: String,
    /// Extra structured detail, absent when there is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A JSON-RPC response: a `result` or an `error` for one request id.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// The protocol version, always `"2.0"` once parsed.
    pub jsonrpc: String,
    /// The id of the request that this answers.
    pub id: RequestId,
    /// The success value; an explicit JSON `null` stays `Some(Value::Null)`.
    #[serde(
        default,
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub result: Option<Value>,
    /// The failure object, absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// Keeps a present `null` as `Some(Value::Null)`, because a `null` result is a valid answer.
fn present_value<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

/// Any one JSON-RPC frame the proxy accepts.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum JsonRpcMessage {
    /// A request with an id.
    Request(JsonRpcRequest),
    /// A notification without an id.
    Notification(JsonRpcNotification),
    /// A response to an earlier request.
    Response(JsonRpcResponse),
}

/// Why a line is not an acceptable JSON-RPC frame.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// The line is not JSON, or nests deeper than `serde_json` allows.
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    /// The line is JSON but not a single JSON-RPC 2.0 message.
    #[error("not a JSON-RPC 2.0 message: {0}")]
    NotJsonRpc(String),
}

/// Parses one line into a JSON-RPC message, rejecting batches and anything not version 2.0.
pub fn parse_frame(line: &str) -> Result<JsonRpcMessage, FrameError> {
    let value: Value =
        serde_json::from_str(line).map_err(|error| FrameError::InvalidJson(error.to_string()))?;
    let object = match &value {
        Value::Object(object) => object,
        Value::Array(_) => {
            return Err(FrameError::NotJsonRpc(
                "batch requests are not supported".to_string(),
            ));
        }
        _ => {
            return Err(FrameError::NotJsonRpc(
                "frame is not a JSON object".to_string(),
            ));
        }
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some(JSONRPC_VERSION) {
        return Err(FrameError::NotJsonRpc(
            "jsonrpc must be the string \"2.0\"".to_string(),
        ));
    }
    let malformed = |error: serde_json::Error| FrameError::NotJsonRpc(error.to_string());
    if object.contains_key("method") {
        if object.contains_key("id") {
            serde_json::from_value(value)
                .map(JsonRpcMessage::Request)
                .map_err(malformed)
        } else {
            serde_json::from_value(value)
                .map(JsonRpcMessage::Notification)
                .map_err(malformed)
        }
    } else {
        let response: JsonRpcResponse = serde_json::from_value(value).map_err(malformed)?;
        if response.result.is_none() && response.error.is_none() {
            return Err(FrameError::NotJsonRpc(
                "response has neither result nor error".to_string(),
            ));
        }
        Ok(JsonRpcMessage::Response(response))
    }
}

/// Encodes a message as one compact line without a trailing newline.
pub fn encode_frame(msg: &JsonRpcMessage) -> String {
    serde_json::to_string(msg).expect("JSON-RPC envelopes always serialize")
}

/// The part of a request that policy evaluates.
#[derive(Clone, Debug, PartialEq)]
pub enum McpCall {
    /// A `tools/call` request.
    ToolCall {
        /// The tool name.
        name: String,
        /// The tool arguments; `{}` when the request sent none.
        arguments: Value,
    },
    /// A `resources/read` request.
    ResourceRead {
        /// The resource URI.
        uri: String,
    },
}

impl McpCall {
    /// The tool name, or the literal `resources/read` for a resource read.
    pub fn tool_name(&self) -> &str {
        match self {
            McpCall::ToolCall { name, .. } => name,
            McpCall::ResourceRead { .. } => RESOURCES_READ_METHOD,
        }
    }

    /// The text that policy regexes search: the URI, or every string argument leaf joined by newlines.
    ///
    /// Leaves come depth first with object keys in sorted order, unescaped. Keys, numbers, and
    /// booleans are left out.
    pub fn argument_text(&self) -> String {
        match self {
            McpCall::ToolCall { arguments, .. } => {
                let mut leaves = Vec::new();
                collect_string_leaves(arguments, &mut leaves);
                leaves.join("\n")
            }
            McpCall::ResourceRead { uri } => uri.clone(),
        }
    }
}

/// Appends every string leaf of `value` to `leaves`, depth first.
///
/// `serde_json::Map` is a `BTreeMap` without the `preserve_order` feature, so objects iterate in
/// sorted key order.
fn collect_string_leaves<'a>(value: &'a Value, leaves: &mut Vec<&'a str>) {
    match value {
        Value::String(text) => leaves.push(text),
        Value::Array(items) => items
            .iter()
            .for_each(|item| collect_string_leaves(item, leaves)),
        Value::Object(fields) => fields
            .values()
            .for_each(|field| collect_string_leaves(field, leaves)),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Views a request as a policy-evaluated call, or `None` for other methods and unusable parameters.
pub fn classify_call(req: &JsonRpcRequest) -> Option<McpCall> {
    let params = req.params.as_ref()?;
    match req.method.as_str() {
        TOOLS_CALL_METHOD => {
            let name = params.get("name")?.as_str()?.to_string();
            let arguments = match params.get("arguments") {
                None | Some(Value::Null) => Value::Object(Map::new()),
                Some(arguments) => arguments.clone(),
            };
            Some(McpCall::ToolCall { name, arguments })
        }
        RESOURCES_READ_METHOD => {
            let uri = params.get("uri")?.as_str()?.to_string();
            Some(McpCall::ResourceRead { uri })
        }
        _ => None,
    }
}

/// What the proxy does with a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    /// Forward the call.
    Allow,
    /// Refuse the call.
    Deny,
    /// Hold the call until a human approves it.
    RequireApproval,
}

/// How serious a matched rule is, ordered from lowest to highest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational.
    Low,
    /// Worth review.
    Medium,
    /// Likely harmful.
    High,
    /// Severe harm if allowed.
    Critical,
}

/// The `data` payload of a policy-denied or approval-required error.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GuardrailErrorData {
    /// The id of the rule that decided.
    pub rule_id: String,
    /// The decision that the rule made.
    pub decision: Decision,
    /// The severity of the rule.
    pub severity: Severity,
    /// A human-readable explanation.
    pub reason: String,
    /// The taint origins behind the decision, oldest first.
    pub taint_chain: Vec<String>,
}

/// Builds the error reply for a denied or approval-gated call; `Allow` is not an error and is not expected.
pub fn guardrail_error_response(id: RequestId, data: GuardrailErrorData) -> JsonRpcResponse {
    let (code, message) = match data.decision {
        Decision::RequireApproval => (APPROVAL_REQUIRED_CODE, "Approval required"),
        Decision::Deny | Decision::Allow => (POLICY_DENIED_CODE, "Policy denied"),
    };
    error_response(
        id,
        code,
        message,
        serde_json::to_value(&data).expect("guardrail error data always serializes"),
    )
}

/// Builds a standard JSON-RPC error reply whose `data` holds `{"detail": detail}`.
pub fn protocol_error_response(id: RequestId, code: i64, detail: &str) -> JsonRpcResponse {
    let message = match code {
        PARSE_ERROR_CODE => "Parse error",
        INVALID_REQUEST_CODE => "Invalid Request",
        INVALID_PARAMS_CODE => "Invalid params",
        _ => "Protocol error",
    };
    error_response(id, code, message, serde_json::json!({ "detail": detail }))
}

/// Builds the `-32700` reply with a `null` id for a line that is not JSON.
pub fn parse_error_response(detail: &str) -> JsonRpcResponse {
    protocol_error_response(RequestId::Null, PARSE_ERROR_CODE, detail)
}

fn error_response(id: RequestId, code: i64, message: &str, data: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: JSONRPC_VERSION.to_string(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.to_string(),
            data: Some(data),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    /// The host line for `response`, parsed back into JSON.
    fn response_json(response: JsonRpcResponse) -> Value {
        let line = encode_frame(&JsonRpcMessage::Response(response));
        serde_json::from_str(&line).expect("encode_frame writes one JSON object")
    }

    struct ErrorRow {
        decision: Decision,
        id: RequestId,
        id_json: &'static str,
        code: i64,
        message: &'static str,
        decision_text: &'static str,
    }

    const ERROR_ROWS: [ErrorRow; 3] = [
        ErrorRow {
            decision: Decision::Deny,
            id: RequestId::Number(0),
            id_json: "0",
            code: -32001,
            message: "Policy denied",
            decision_text: "deny",
        },
        ErrorRow {
            decision: Decision::RequireApproval,
            id: RequestId::Number(-7),
            id_json: "-7",
            code: -32002,
            message: "Approval required",
            decision_text: "require-approval",
        },
        ErrorRow {
            decision: Decision::Deny,
            id: RequestId::String(String::new()),
            id_json: r#""""#,
            code: -32001,
            message: "Policy denied",
            decision_text: "deny",
        },
    ];

    #[test]
    fn guardrail_error_response_carries_code_and_data_fields() {
        for row in ERROR_ROWS {
            let data = GuardrailErrorData {
                rule_id: "tainted-deny-shell-exec".to_string(),
                decision: row.decision,
                severity: Severity::Critical,
                reason: "shell call after untrusted input".to_string(),
                taint_chain: vec!["1:WebFetch".to_string()],
            };
            let reply = response_json(guardrail_error_response(row.id, data));
            let expected_id: Value = serde_json::from_str(row.id_json).expect("row id is JSON");
            assert_eq!(reply["id"], expected_id, "id {}", row.id_json);
            assert_eq!(reply["error"]["code"], row.code, "id {}", row.id_json);
            assert_eq!(reply["error"]["message"], row.message, "id {}", row.id_json);
            let data = &reply["error"]["data"];
            assert_eq!(
                data["rule_id"], "tainted-deny-shell-exec",
                "id {}",
                row.id_json
            );
            assert_eq!(data["decision"], row.decision_text, "id {}", row.id_json);
            assert_eq!(data["severity"], "critical", "id {}", row.id_json);
            assert_eq!(
                data["reason"], "shell call after untrusted input",
                "id {}",
                row.id_json
            );
            assert_eq!(
                data["taint_chain"],
                json!(["1:WebFetch"]),
                "id {}",
                row.id_json
            );
        }
    }

    #[derive(Debug, PartialEq)]
    enum Parsed {
        InvalidJson,
        NotJsonRpc,
        Accepted,
    }

    fn parsed(line: &str) -> Parsed {
        match parse_frame(line) {
            Err(FrameError::InvalidJson(_)) => Parsed::InvalidJson,
            Err(FrameError::NotJsonRpc(_)) => Parsed::NotJsonRpc,
            Ok(_) => Parsed::Accepted,
        }
    }

    /// A tool call whose `arguments` nest 130 arrays, past `serde_json`'s
    /// 128-level limit.
    const DEEP_FRAME: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"a":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]},"name":"search_files"}}"#;

    const INVALID_FRAMES: [(&str, Parsed); 9] = [
        ("{bad", Parsed::InvalidJson),
        (DEEP_FRAME, Parsed::InvalidJson),
        ("42", Parsed::NotJsonRpc),
        (r#""tools/call""#, Parsed::NotJsonRpc),
        (
            r#"[{"jsonrpc":"2.0","id":2,"method":"tools/list"}]"#,
            Parsed::NotJsonRpc,
        ),
        ("[]", Parsed::NotJsonRpc),
        (r#"{"id":3,"method":"tools/list"}"#, Parsed::NotJsonRpc),
        (
            r#"{"jsonrpc":"1.0","id":3,"method":"tools/list"}"#,
            Parsed::NotJsonRpc,
        ),
        (r#"{"jsonrpc":"2.0","id":4}"#, Parsed::NotJsonRpc),
    ];

    #[test]
    fn parse_frame_rejects_invalid_frames() {
        for (frame, expected) in INVALID_FRAMES {
            assert_eq!(parsed(frame), expected, "frame {frame}");
        }
    }

    /// Tool-call `arguments` and the text that the policy regexes search.
    const ARGUMENT_ROWS: [(&str, &str); 3] = [
        (
            r#"{"verbose":true,"env":{"HOME":"/root"},"command":"rm\t-rf /","retries":3,"args":["-x","y"]}"#,
            "-x\ny\nrm\t-rf /\n/root",
        ),
        ("null", ""),
        ("{}", ""),
    ];

    #[test]
    fn argument_text_joins_unescaped_string_leaves_in_sorted_key_order() {
        for (arguments, expected) in ARGUMENT_ROWS {
            let call = McpCall::ToolCall {
                name: "Shell".to_string(),
                arguments: serde_json::from_str(arguments).expect("row arguments are JSON"),
            };
            assert_eq!(call.argument_text(), expected, "arguments {arguments}");
        }

        let read = McpCall::ResourceRead {
            uri: "https://docs.example/guide?q=1".to_string(),
        };
        assert_eq!(read.argument_text(), "https://docs.example/guide?q=1");

        let without_arguments = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: RequestId::Number(1),
            method: "tools/call".to_string(),
            params: Some(json!({"name": "search_files"})),
        };
        let call = classify_call(&without_arguments).expect("a tools/call with a name is a call");
        assert_eq!(call.argument_text(), "");
    }
}
