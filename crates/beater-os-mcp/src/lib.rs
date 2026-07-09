//! Mediated MCP stdio gateway for tempOS local-shell adoption.
//!
//! This crate implements the first MCP-facing slice without trusting a tool
//! server as an authority boundary. `tools/call` requests are translated into
//! daemon-owned action admission, then executed only through the existing
//! local-shell gateway path: exact command digest, policy decision, execution
//! lease claim, sandboxed process, and receipt completion.
//!
//! The model-visible response is intentionally compact. It carries receipt and
//! digest evidence, not a second serialized copy of process output.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;

use beater_os_core::{DataClass, DecisionResult, RiskClass, SideEffectClass, TaintLabel};
use beater_os_sandbox::{SandboxLimits, safe_path_environment, validate_environment};
use beater_os_tool_gateway::{
    GatewayError, LocalToolInvocation, execute_local_tool, local_shell_tool_digest_with_environment,
};
use beater_osd::{DaemonError, LocalShellToolRegistration, Store};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
const DEFAULT_TOOL_NAME: &str = "tempos.local_shell";
const DEFAULT_MAX_REQUEST_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_MODEL_OUTPUT_BYTES: usize = 4 * 1024;
pub const MAX_CONFIGURED_REQUEST_BYTES: usize = 1024 * 1024;
pub const MAX_CONFIGURED_MODEL_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_TIMEOUT_SECS: u64 = 30;
const MAX_ARTIFACT_PATHS: usize = 32;
const MAX_TOOL_ARGS: usize = 64;
const MAX_TOOL_ARG_BYTES: usize = 4096;
const MAX_GRANTS: usize = 64;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_COMMAND_BYTES: usize = 128;
const MAX_CWD_BYTES: usize = 4096;
const MAX_EXPLANATION_BYTES: usize = 2048;

pub type McpResult<T> = Result<T, McpError>;

#[derive(Debug, Error)]
pub enum McpError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("daemon error: {0}")]
    Daemon(#[from] DaemonError),
    #[error("gateway error: {0}")]
    Gateway(#[from] GatewayError),
    #[error("mcp refused request: {0}")]
    Refused(String),
    #[error("unsupported MCP method {0}")]
    MethodNotFound(String),
}

#[derive(Clone, Debug)]
pub struct McpServerConfig {
    pub root: PathBuf,
    pub tool_name: String,
    pub max_request_bytes: usize,
    pub max_model_output_bytes: usize,
}

impl McpServerConfig {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            tool_name: DEFAULT_TOOL_NAME.to_string(),
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_model_output_bytes: DEFAULT_MAX_MODEL_OUTPUT_BYTES,
        }
    }
}

pub fn run_stdio_server<R: Read, W: Write>(
    config: McpServerConfig,
    input: R,
    mut output: W,
) -> McpResult<()> {
    validate_server_config(&config)?;
    let mut reader = BufReader::new(input);
    while let Some(request) = read_framed_request(&mut reader, config.max_request_bytes)? {
        match request {
            FramedJsonRpcRequest::Request(request) => {
                let Some(response) = handle_json_rpc(&config, request)? else {
                    continue;
                };
                write_framed_response(&mut output, &response)?;
            }
            FramedJsonRpcRequest::ProtocolError(response) => {
                write_framed_response(&mut output, &response)?;
            }
        }
    }
    Ok(())
}

fn validate_server_config(config: &McpServerConfig) -> McpResult<()> {
    if config.tool_name.trim().is_empty() {
        return Err(McpError::Refused("tool_name must not be empty".to_string()));
    }
    if config.max_request_bytes == 0 || config.max_request_bytes > MAX_CONFIGURED_REQUEST_BYTES {
        return Err(McpError::Refused(format!(
            "max_request_bytes must be between 1 and {MAX_CONFIGURED_REQUEST_BYTES}"
        )));
    }
    if config.max_model_output_bytes == 0
        || config.max_model_output_bytes > MAX_CONFIGURED_MODEL_OUTPUT_BYTES
    {
        return Err(McpError::Refused(format!(
            "max_model_output_bytes must be between 1 and {MAX_CONFIGURED_MODEL_OUTPUT_BYTES}"
        )));
    }
    Ok(())
}

#[derive(Debug)]
enum FramedJsonRpcRequest {
    Request(JsonRpcRequest),
    ProtocolError(JsonRpcResponse),
}

fn read_framed_request<R: BufRead>(
    reader: &mut R,
    max_request_bytes: usize,
) -> McpResult<Option<FramedJsonRpcRequest>> {
    let mut content_len = None;
    let mut frame_bytes = 0usize;
    let max_header_bytes = max_request_bytes.min(MAX_HEADER_BYTES);
    loop {
        let Some(header) =
            read_bounded_header_line(reader, max_header_bytes.saturating_sub(frame_bytes))?
        else {
            return if frame_bytes == 0 {
                Ok(None)
            } else {
                Err(McpError::Refused("truncated MCP header".to_string()))
            };
        };
        frame_bytes = frame_bytes
            .checked_add(header.len())
            .ok_or_else(|| McpError::Refused("MCP frame size overflow".to_string()))?;
        if frame_bytes > max_request_bytes {
            return Err(McpError::Refused(format!(
                "MCP frame exceeds max_request_bytes {max_request_bytes}"
            )));
        }
        let trimmed = header.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            if content_len.is_some() {
                break;
            }
            continue;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Err(McpError::Refused(format!(
                "malformed MCP header {trimmed:?}"
            )));
        };
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value.trim().parse::<usize>().map_err(|_| {
                McpError::Refused(format!("invalid Content-Length value {:?}", value.trim()))
            })?;
            if parsed > max_request_bytes {
                return Err(McpError::Refused(format!(
                    "MCP request body exceeds max_request_bytes {max_request_bytes}"
                )));
            }
            if content_len.is_some() {
                return Err(McpError::Refused(
                    "duplicate Content-Length header".to_string(),
                ));
            }
            content_len = Some(parsed);
        }
    }

    let len = content_len
        .ok_or_else(|| McpError::Refused("missing Content-Length header".to_string()))?;
    if len > max_request_bytes.saturating_sub(frame_bytes) {
        return Err(McpError::Refused(format!(
            "MCP frame exceeds max_request_bytes {max_request_bytes}"
        )));
    }
    let mut body = vec![0; len];
    reader.read_exact(&mut body)?;
    Ok(Some(parse_json_rpc_body(&body)))
}

fn parse_json_rpc_body(body: &[u8]) -> FramedJsonRpcRequest {
    let value = match serde_json::from_slice::<Value>(body) {
        Ok(value) => value,
        Err(err) => {
            return FramedJsonRpcRequest::ProtocolError(JsonRpcResponse::error(
                Value::Null,
                -32700,
                &format!("parse error: {err}"),
            ));
        }
    };
    match serde_json::from_value::<JsonRpcRequest>(value.clone()) {
        Ok(request) => FramedJsonRpcRequest::Request(request),
        Err(err) => FramedJsonRpcRequest::ProtocolError(JsonRpcResponse::error(
            recover_request_id(&value),
            -32600,
            &format!("invalid request: {err}"),
        )),
    }
}

fn recover_request_id(value: &Value) -> Value {
    let Some(id) = value.as_object().and_then(|object| object.get("id")) else {
        return Value::Null;
    };
    match id {
        Value::Null | Value::String(_) | Value::Number(_) => id.clone(),
        _ => Value::Null,
    }
}

fn read_bounded_header_line<R: BufRead>(
    reader: &mut R,
    remaining_frame_bytes: usize,
) -> McpResult<Option<String>> {
    if remaining_frame_bytes == 0 {
        return Err(McpError::Refused(
            "MCP header exceeds remaining frame budget".to_string(),
        ));
    }
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(McpError::Refused("truncated MCP header line".to_string()))
            };
        }
        let take = match available.iter().position(|byte| *byte == b'\n') {
            Some(position) => position + 1,
            None => available.len(),
        };
        if line.len().saturating_add(take) > MAX_HEADER_LINE_BYTES {
            return Err(McpError::Refused(format!(
                "MCP header line exceeds the {MAX_HEADER_LINE_BYTES}-byte cap"
            )));
        }
        if line.len().saturating_add(take) > remaining_frame_bytes {
            return Err(McpError::Refused(
                "MCP headers exceed aggregate header budget".to_string(),
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line.last() == Some(&b'\n') {
            let header = String::from_utf8(line)
                .map_err(|_| McpError::Refused("MCP header is not valid UTF-8".to_string()))?;
            return Ok(Some(header));
        }
    }
}

fn write_framed_response<W: Write>(writer: &mut W, response: &JsonRpcResponse) -> McpResult<()> {
    let body = serde_json::to_vec(response)?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

pub fn handle_json_rpc(
    config: &McpServerConfig,
    request: JsonRpcRequest,
) -> McpResult<Option<JsonRpcResponse>> {
    let response_id = match request.id.response_value() {
        Ok(response_id) => response_id,
        Err(message) => {
            return Ok(Some(JsonRpcResponse::error(Value::Null, -32600, &message)));
        }
    };
    if request.jsonrpc != "2.0" {
        return Ok(Some(JsonRpcResponse::error(
            response_id.unwrap_or(Value::Null),
            -32600,
            "jsonrpc must be 2.0",
        )));
    }
    let Some(id) = response_id else {
        handle_notification(request.method.as_str());
        return Ok(None);
    };
    let result = match request.method.as_str() {
        "initialize" => Ok(initialize_result()),
        "ping" | "shutdown" => Ok(json!({})),
        "tools/list" => Ok(tools_list_result(config)),
        "tools/call" => handle_tools_call(config, request.params.unwrap_or(Value::Null)),
        method => Err(McpError::MethodNotFound(method.to_string())),
    };
    Ok(Some(match result {
        Ok(value) => JsonRpcResponse::result(id, value),
        Err(error) => JsonRpcResponse::error(id, json_rpc_error_code(&error), &error.to_string()),
    }))
}

fn handle_notification(_method: &str) {}

fn json_rpc_error_code(error: &McpError) -> i64 {
    match error {
        McpError::Json(_) | McpError::Refused(_) => -32602,
        McpError::MethodNotFound(_) => -32601,
        McpError::Io(_) | McpError::Daemon(_) | McpError::Gateway(_) => -32000,
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": {
                "listChanged": false
            }
        },
        "serverInfo": {
            "name": "beater-os-mcp",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

fn tools_list_result(config: &McpServerConfig) -> Value {
    json!({
        "tools": [{
            "name": config.tool_name,
            "title": "tempOS mediated local shell",
            "description": "Executes one PATH-resolved local command only after tempOS admission, lease claim, sandbox execution, and receipt journaling.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["session_id", "command", "cwd", "grants"],
                "properties": {
                    "session_id": { "type": "string", "minLength": 1 },
                    "action_id": { "type": "string", "minLength": 1, "maxLength": MAX_IDENTIFIER_BYTES },
                    "command": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_COMMAND_BYTES,
                        "pattern": "^[^/]+$",
                        "description": "PATH-resolved command name; slash-containing paths are refused."
                    },
                    "args": {
                        "type": "array",
                        "maxItems": MAX_TOOL_ARGS,
                        "items": { "type": "string", "maxLength": MAX_TOOL_ARG_BYTES }
                    },
                    "cwd": { "type": "string", "minLength": 1, "maxLength": MAX_CWD_BYTES },
                    "env": {
                        "type": "object",
                        "propertyNames": {
                            "type": "string",
                            "pattern": "^BEATER_[A-Za-z0-9_]*$"
                        },
                        "additionalProperties": {
                            "type": "string",
                            "maxLength": SandboxLimits::default().max_environment_bytes
                        },
                        "maxProperties": SandboxLimits::default().max_environment_vars.saturating_sub(1),
                        "description": "Optional non-secret BEATER_* variables layered over the safe sandbox PATH. PATH, inherited environment values, and BEATER_* names that look like tokens/secrets/keys/passwords/auth/credentials are never accepted."
                    },
                    "grants": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": MAX_GRANTS,
                        "uniqueItems": true,
                        "items": { "type": "string", "minLength": 1, "maxLength": MAX_IDENTIFIER_BYTES }
                    },
                    "risk": { "type": "string", "enum": ["low", "medium", "high", "critical"] },
                    "side_effects": {
                        "type": "array",
                        "uniqueItems": true,
                        "items": {
                            "type": "string",
                            "enum": ["local_write"]
                        }
                    },
                    "data_classes": {
                        "type": "array",
                        "uniqueItems": true,
                        "items": {
                            "type": "string",
                            "enum": [
                                "public",
                                "internal",
                                "personal",
                                "customer",
                                "financial",
                                "secret",
                                "code",
                                "binary",
                                "untrusted_web",
                                "untrusted_email",
                                "untrusted_document",
                                "tool_output"
                            ]
                        }
                    },
                    "taint": {
                        "type": "array",
                        "uniqueItems": true,
                        "items": {
                            "type": "string",
                            "enum": [
                                "trusted_user_instruction",
                                "system_policy",
                                "developer_instruction",
                                "untrusted_web",
                                "untrusted_email",
                                "untrusted_document",
                                "tool_output",
                                "secret",
                                "personal_data",
                                "customer_data",
                                "financial_data",
                                "code",
                                "binary",
                                "payment_instruction"
                            ]
                        }
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_TIMEOUT_SECS
                    },
                    "max_output_bytes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": SandboxLimits::default().max_output_bytes
                    },
                    "max_model_output_bytes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": config.max_model_output_bytes
                    },
                    "explanation": { "type": "string", "maxLength": MAX_EXPLANATION_BYTES },
                    "idempotency_key": { "type": "string", "minLength": 1, "maxLength": MAX_IDENTIFIER_BYTES },
                    "receipt_id": { "type": "string", "minLength": 1, "maxLength": MAX_IDENTIFIER_BYTES }
                }
            },
            "outputSchema": local_shell_output_schema()
        }]
    })
}

fn local_shell_output_schema() -> Value {
    json!({
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "status",
                    "decision",
                    "session_id",
                    "action_id",
                    "lease_id",
                    "tool_ref",
                    "manifest_hash",
                    "decision_id",
                    "proposal_seq",
                    "proposal_hash",
                    "decision_seq",
                    "decision_hash",
                    "admission_journal_root_hash",
                    "lease_seq",
                    "lease_hash",
                    "tool_id",
                    "exit_code",
                    "receipt_id",
                    "receipt_hash",
                    "receipt_journal_seq",
                    "receipt_journal_hash",
                    "receipt_seq",
                    "receipt_root_hash",
                    "final_journal_root_hash",
                    "stdout_digest",
                    "stdout_truncated",
                    "stderr_truncated",
                    "created",
                    "created_count",
                    "created_truncated",
                    "modified",
                    "modified_count",
                    "modified_truncated",
                    "deleted",
                    "deleted_count",
                    "deleted_truncated",
                    "receipts",
                    "runnable_pending_actions",
                    "open_execution_leases"
                ],
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": ["ok", "failed", "timeout", "signaled"]
                    },
                    "decision": { "const": "allowed" },
                    "session_id": { "type": "string" },
                    "action_id": { "type": "string" },
                    "lease_id": { "type": "string" },
                    "tool_ref": { "type": "string" },
                    "manifest_hash": { "type": "string" },
                    "decision_id": { "type": "string" },
                    "proposal_seq": { "type": "integer", "minimum": 0 },
                    "proposal_hash": { "type": "string" },
                    "decision_seq": { "type": "integer", "minimum": 0 },
                    "decision_hash": { "type": "string" },
                    "admission_journal_root_hash": { "type": "string" },
                    "lease_seq": { "type": "integer", "minimum": 0 },
                    "lease_hash": { "type": "string" },
                    "tool_id": { "type": "string" },
                    "exit_code": { "type": ["integer", "null"] },
                    "stdout_digest": { "type": "string" },
                    "stdout_truncated": { "type": "boolean" },
                    "stderr_truncated": { "type": "boolean" },
                    "created": { "type": "array", "items": { "type": "string" } },
                    "created_count": { "type": "integer" },
                    "created_truncated": { "type": "boolean" },
                    "modified": { "type": "array", "items": { "type": "string" } },
                    "modified_count": { "type": "integer" },
                    "modified_truncated": { "type": "boolean" },
                    "deleted": { "type": "array", "items": { "type": "string" } },
                    "deleted_count": { "type": "integer" },
                    "deleted_truncated": { "type": "boolean" },
                    "receipt_id": { "type": "string" },
                    "receipt_hash": { "type": "string" },
                    "receipt_journal_seq": { "type": "integer", "minimum": 0 },
                    "receipt_journal_hash": { "type": "string" },
                    "receipt_seq": { "type": "integer", "minimum": 0 },
                    "receipt_root_hash": { "type": "string" },
                    "final_journal_root_hash": { "type": "string" },
                    "receipts": { "type": "integer" },
                    "runnable_pending_actions": { "type": "integer" },
                    "open_execution_leases": { "type": "integer" }
                }
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "status",
                    "decision",
                    "matched_rules",
                    "explanation",
                    "session_id",
                    "action_id",
                    "manifest_hash",
                    "decision_id",
                    "final_journal_root_hash"
                ],
                "properties": {
                    "status": { "const": "admission_refused" },
                    "decision": {
                        "type": "string",
                        "enum": [
                            "denied",
                            "needs_approval",
                            "needs_simulation",
                            "needs_narrowed_grant"
                        ]
                    },
                    "matched_rules": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "explanation": { "type": "string" },
                    "session_id": { "type": "string" },
                    "action_id": { "type": "string" },
                    "manifest_hash": { "type": "string" },
                    "decision_id": { "type": "string" },
                    "final_journal_root_hash": { "type": "string" }
                }
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "status",
                    "decision",
                    "session_id",
                    "action_id",
                    "error",
                    "final_journal_root_hash",
                    "open_execution_leases",
                    "open_execution_lease_statuses",
                    "open_execution_lease_ids",
                    "live_open_execution_leases",
                    "live_open_execution_lease_ids",
                    "expired_recoverable_execution_leases",
                    "expired_recoverable_execution_lease_ids",
                    "recovery_blocked",
                    "admission_blocked",
                    "admission_blockers"
                ],
                "properties": {
                    "status": { "const": "execution_incomplete" },
                    "decision": { "const": "allowed" },
                    "session_id": { "type": "string" },
                    "action_id": { "type": "string" },
                    "error": { "type": "string" },
                    "final_journal_root_hash": { "type": "string" },
                    "open_execution_leases": { "type": "integer", "minimum": 0 },
                    "open_execution_lease_statuses": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["action_id", "lease_id", "expires_at", "status"],
                            "properties": {
                                "action_id": { "type": "string" },
                                "lease_id": { "type": "string" },
                                "expires_at": { "type": "string" },
                                "status": {
                                    "type": "string",
                                    "enum": ["live_open", "expired_recoverable"]
                                }
                            }
                        }
                    },
                    "open_execution_lease_ids": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "live_open_execution_leases": { "type": "integer", "minimum": 0 },
                    "live_open_execution_lease_ids": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "expired_recoverable_execution_leases": { "type": "integer", "minimum": 0 },
                    "expired_recoverable_execution_lease_ids": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "recovery_blocked": { "type": "boolean" },
                    "admission_blocked": { "type": "boolean" },
                    "admission_blockers": {
                        "type": "array",
                        "items": { "type": "string" }
                    }
                }
            }
        ]
    })
}

fn handle_tools_call(config: &McpServerConfig, params: Value) -> McpResult<Value> {
    let call: ToolsCallParams = serde_json::from_value(params)?;
    if call.name.trim().is_empty() {
        return Err(McpError::Refused(
            "MCP tool name must not be empty".to_string(),
        ));
    }
    if call.name != config.tool_name {
        return Err(McpError::Refused(format!(
            "unknown MCP tool {}; expected {}",
            call.name, config.tool_name
        )));
    }
    if !call.arguments.is_object() {
        return Err(McpError::Refused(
            "MCP tools/call arguments must be a JSON object".to_string(),
        ));
    }
    let args: LocalShellToolArguments = serde_json::from_value(call.arguments)?;
    let outcome = execute_local_shell_call(config, args)?;
    Ok(json!({
        "content": [{
            "type": "text",
            "text": outcome.summary
        }],
        "structuredContent": outcome.structured,
        "isError": outcome.is_error
    }))
}

fn execute_local_shell_call(
    config: &McpServerConfig,
    args: LocalShellToolArguments,
) -> McpResult<McpToolOutcome> {
    validate_local_shell_args(&args)?;
    let timeout_secs = args.timeout_secs.unwrap_or(MAX_TIMEOUT_SECS);
    if timeout_secs == 0 || timeout_secs > MAX_TIMEOUT_SECS {
        return Err(McpError::Refused(format!(
            "timeout_secs must be between 1 and {MAX_TIMEOUT_SECS}"
        )));
    }
    let default_output_cap = SandboxLimits::default().max_output_bytes;
    let max_output_bytes = args.max_output_bytes.unwrap_or(default_output_cap);
    if max_output_bytes == 0 || max_output_bytes > default_output_cap {
        return Err(McpError::Refused(format!(
            "max_output_bytes must be between 1 and {default_output_cap}"
        )));
    }
    let max_model_output_bytes = args
        .max_model_output_bytes
        .unwrap_or(config.max_model_output_bytes);
    if max_model_output_bytes == 0 || max_model_output_bytes > config.max_model_output_bytes {
        return Err(McpError::Refused(format!(
            "max_model_output_bytes must be between 1 and {}",
            config.max_model_output_bytes
        )));
    }
    let action_id = args
        .action_id
        .clone()
        .unwrap_or_else(|| format!("mcp-local-shell-{}", Uuid::new_v4()));
    let environment = merged_safe_environment(&args.env)?;
    let cwd = canonical_cwd(&args.cwd)?;
    let limits = SandboxLimits {
        timeout: std::time::Duration::from_secs(timeout_secs),
        max_output_bytes,
        ..SandboxLimits::default()
    };
    validate_environment(&environment, &limits)
        .map_err(|err| McpError::Refused(err.to_string()))?;
    let command_digest =
        local_shell_tool_digest_with_environment(&cwd, &args.command, &args.args, &environment)?;
    let required_grants: BTreeSet<String> = args.grants.iter().cloned().collect();
    let store = Store::open(&config.root)?;
    let projection = store.project(&args.session_id)?;
    let side_effects: BTreeSet<SideEffectClass> = if args.side_effects.is_empty() {
        BTreeSet::from([SideEffectClass::LocalWrite])
    } else {
        args.side_effects.iter().copied().collect()
    };
    if !side_effects.is_subset(&BTreeSet::from([SideEffectClass::LocalWrite])) {
        return Err(McpError::Refused(
            "MCP local-shell side_effects may only declare local_write".to_string(),
        ));
    }
    let tool_version = {
        let prefix_len = command_digest.len().min(16);
        format!("local-{}", &command_digest[..prefix_len])
    };
    let registry = store.register_local_shell_tool(LocalShellToolRegistration {
        workspace_id: projection.session.workspace_id,
        tool_id: "shell".to_string(),
        version: tool_version.clone(),
        content_digest: command_digest.clone(),
        side_effects: side_effects.clone(),
        risk_class: args.risk,
    })?;
    let outcome = match execute_local_tool(
        &store,
        &registry,
        LocalToolInvocation {
            session_id: args.session_id.clone(),
            tool_id: "shell".to_string(),
            version: tool_version,
            expected_tool_digest: Some(command_digest),
            command: args.command,
            args: args.args,
            cwd,
            environment,
            required_grants,
            revoked_handles: BTreeSet::new(),
            action_id: action_id.clone(),
            risk_class: args.risk,
            expected_side_effects: side_effects,
            data_classes: args.data_classes.iter().copied().collect(),
            taint: args.taint.into_iter().collect(),
            idempotency_key: args
                .idempotency_key
                .clone()
                .or_else(|| Some(action_id.clone())),
            compensation_plan: None,
            receipt_id: args.receipt_id,
            human_explanation: args
                .explanation
                .clone()
                .unwrap_or_else(|| "MCP mediated local-shell action".to_string()),
            limits,
        },
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            if let Some(outcome) = execution_incomplete_outcome(
                &store,
                &args.session_id,
                &action_id,
                &error,
                max_model_output_bytes,
            )? {
                return Ok(outcome);
            }
            return Err(error.into());
        }
    };
    let decision = outcome.decision.result.clone();
    if decision != DecisionResult::Allowed {
        let denial_summary_text = denial_summary(&json!({
            "decision": decision.clone(),
            "action_id": action_id.clone(),
            "explanation": outcome.decision.explanation.clone()
        }));
        let structured = json!({
            "status": "admission_refused",
            "decision": decision,
            "matched_rules": outcome.decision.matched_rules.clone(),
            "explanation": outcome.decision.explanation.clone(),
            "session_id": args.session_id,
            "action_id": action_id,
            "manifest_hash": outcome.decision.manifest_hash.clone(),
            "decision_id": outcome.decision.decision_id.clone(),
            "final_journal_root_hash": outcome.admission.decision_record.hash.clone()
        });
        return Ok(McpToolOutcome {
            is_error: true,
            summary: cap_text(&denial_summary_text, max_model_output_bytes),
            structured,
        });
    }
    let execution = outcome
        .execution
        .ok_or_else(|| McpError::Refused("allowed MCP action produced no execution".to_string()))?;
    let receipt = outcome
        .receipt
        .ok_or_else(|| McpError::Refused("allowed MCP action produced no receipt".to_string()))?;
    let evidence = outcome.evidence.ok_or_else(|| {
        McpError::Refused("allowed MCP action produced no replay evidence".to_string())
    })?;
    let projection = store.project(&args.session_id)?;
    let scheduler = projection.scheduler_projection(chrono::Utc::now());
    let created = bounded_paths(&execution.diff.created);
    let modified = bounded_paths(&execution.diff.modified);
    let deleted = bounded_paths(&execution.diff.deleted);
    let status = execution.status_str().to_string();
    let is_error = status != "ok";
    let summary = execution_summary(&json!({
        "status": status.clone(),
        "action_id": outcome.manifest.action_id.clone(),
        "receipt_id": receipt.receipt_id.clone(),
        "stdout_truncated": execution.stdout_truncated,
        "stderr_truncated": execution.stderr_truncated,
        "created": created.clone(),
        "modified": modified.clone(),
        "deleted": deleted.clone()
    }));
    let structured = json!({
        "status": status,
        "decision": decision,
        "session_id": outcome.manifest.session_id.clone(),
        "action_id": outcome.manifest.action_id.clone(),
        "lease_id": evidence.lease_id.clone(),
        "tool_ref": evidence.tool_ref.clone(),
        "manifest_hash": outcome.decision.manifest_hash.clone(),
        "decision_id": outcome.decision.decision_id.clone(),
        "proposal_seq": evidence.proposal_seq,
        "proposal_hash": evidence.proposal_hash.clone(),
        "decision_seq": evidence.decision_seq,
        "decision_hash": evidence.decision_hash.clone(),
        "admission_journal_root_hash": evidence.admission_journal_root_hash.clone(),
        "lease_seq": evidence.lease_seq,
        "lease_hash": evidence.lease_hash.clone(),
        "tool_id": receipt.tool_id.clone(),
        "exit_code": execution.exit_code,
        "stdout_digest": execution.stdout_digest(),
        "stdout_truncated": execution.stdout_truncated,
        "stderr_truncated": execution.stderr_truncated,
        "created": created,
        "created_count": execution.diff.created.len(),
        "created_truncated": execution.diff.created.len() > MAX_ARTIFACT_PATHS,
        "modified": modified,
        "modified_count": execution.diff.modified.len(),
        "modified_truncated": execution.diff.modified.len() > MAX_ARTIFACT_PATHS,
        "deleted": deleted,
        "deleted_count": execution.diff.deleted.len(),
        "deleted_truncated": execution.diff.deleted.len() > MAX_ARTIFACT_PATHS,
        "receipt_id": receipt.receipt_id.clone(),
        "receipt_hash": receipt.receipt_hash.clone(),
        "receipt_journal_seq": evidence.receipt_journal_seq,
        "receipt_journal_hash": evidence.receipt_journal_hash.clone(),
        "receipt_seq": evidence.receipt_seq,
        "receipt_root_hash": evidence.receipt_root_hash.clone(),
        "final_journal_root_hash": evidence.final_journal_root_hash.clone(),
        "receipts": projection.receipts.len(),
        "runnable_pending_actions": scheduler.runnable_pending_action_ids.len(),
        "open_execution_leases": scheduler.open_execution_lease_ids.len()
    });
    Ok(McpToolOutcome {
        is_error,
        summary: cap_text(&summary, max_model_output_bytes),
        structured,
    })
}

fn execution_incomplete_outcome(
    store: &Store,
    session_id: &str,
    action_id: &str,
    error: &GatewayError,
    max_model_output_bytes: usize,
) -> McpResult<Option<McpToolOutcome>> {
    let projection = store.project(session_id)?;
    let scheduler = projection.scheduler_projection(chrono::Utc::now());
    if !scheduler
        .open_execution_lease_statuses
        .iter()
        .any(|lease| lease.action_id == action_id)
    {
        return Ok(None);
    }
    let final_journal_root_hash = store.load_journal(session_id)?.root_hash();
    let structured = json!({
        "status": "execution_incomplete",
        "decision": "allowed",
        "session_id": session_id,
        "action_id": action_id,
        "error": error.to_string(),
        "final_journal_root_hash": final_journal_root_hash,
        "open_execution_leases": scheduler.open_execution_lease_ids.len(),
        "open_execution_lease_statuses": scheduler.open_execution_lease_statuses,
        "open_execution_lease_ids": scheduler.open_execution_lease_ids,
        "live_open_execution_leases": scheduler.live_open_execution_lease_ids.len(),
        "live_open_execution_lease_ids": scheduler.live_open_execution_lease_ids,
        "expired_recoverable_execution_leases": scheduler.expired_recoverable_execution_lease_ids.len(),
        "expired_recoverable_execution_lease_ids": scheduler.expired_recoverable_execution_lease_ids,
        "recovery_blocked": scheduler.recovery_blocked,
        "admission_blocked": scheduler.admission_blocked,
        "admission_blockers": scheduler.admission_blockers
    });
    let summary = format!(
        "tempOS MCP local shell action {action_id} is execution_incomplete; open execution lease requires recovery: {error}"
    );
    Ok(Some(McpToolOutcome {
        is_error: true,
        summary: cap_text(&summary, max_model_output_bytes),
        structured,
    }))
}

fn validate_local_shell_args(args: &LocalShellToolArguments) -> McpResult<()> {
    validate_non_empty("session_id", &args.session_id, MAX_IDENTIFIER_BYTES)?;
    validate_non_empty("command", &args.command, MAX_COMMAND_BYTES)?;
    validate_non_empty("cwd", &args.cwd, MAX_CWD_BYTES)?;
    validate_optional_non_empty("action_id", args.action_id.as_deref(), MAX_IDENTIFIER_BYTES)?;
    validate_optional_non_empty(
        "idempotency_key",
        args.idempotency_key.as_deref(),
        MAX_IDENTIFIER_BYTES,
    )?;
    validate_optional_non_empty(
        "receipt_id",
        args.receipt_id.as_deref(),
        MAX_IDENTIFIER_BYTES,
    )?;
    if let Some(explanation) = args.explanation.as_deref()
        && explanation.len() > MAX_EXPLANATION_BYTES
    {
        return Err(McpError::Refused(format!(
            "explanation exceeds {MAX_EXPLANATION_BYTES} bytes"
        )));
    }
    if args.command.contains('/') {
        return Err(McpError::Refused(
            "MCP local-shell command must be PATH-resolved, not a path".to_string(),
        ));
    }
    if args.args.len() > MAX_TOOL_ARGS {
        return Err(McpError::Refused(format!(
            "args exceeds {MAX_TOOL_ARGS} entries"
        )));
    }
    for (index, value) in args.args.iter().enumerate() {
        if value.len() > MAX_TOOL_ARG_BYTES {
            return Err(McpError::Refused(format!(
                "args[{index}] exceeds {MAX_TOOL_ARG_BYTES} bytes"
            )));
        }
    }
    if args.grants.is_empty() {
        return Err(McpError::Refused(
            "MCP local-shell calls must declare at least one grant".to_string(),
        ));
    }
    if args.grants.len() > MAX_GRANTS {
        return Err(McpError::Refused(format!(
            "grants exceeds {MAX_GRANTS} entries"
        )));
    }
    let mut seen_grants = BTreeSet::new();
    for grant_id in &args.grants {
        validate_non_empty("grant id", grant_id, MAX_IDENTIFIER_BYTES)?;
        if !seen_grants.insert(grant_id.as_str()) {
            return Err(McpError::Refused(format!(
                "duplicate grant id {grant_id:?}"
            )));
        }
    }
    reject_duplicates("side_effects", &args.side_effects)?;
    reject_duplicates("data_classes", &args.data_classes)?;
    reject_duplicates("taint", &args.taint)?;
    Ok(())
}

fn validate_non_empty(field: &str, value: &str, max_bytes: usize) -> McpResult<()> {
    if value.trim().is_empty() {
        return Err(McpError::Refused(format!("{field} must not be empty")));
    }
    if value.len() > max_bytes {
        return Err(McpError::Refused(format!(
            "{field} exceeds {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn validate_optional_non_empty(
    field: &str,
    value: Option<&str>,
    max_bytes: usize,
) -> McpResult<()> {
    if let Some(value) = value {
        validate_non_empty(field, value, max_bytes)?;
    }
    Ok(())
}

fn reject_duplicates<T>(field: &str, values: &[T]) -> McpResult<()>
where
    T: Ord,
{
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(McpError::Refused(format!(
                "{field} must not contain duplicate entries"
            )));
        }
    }
    Ok(())
}

fn denial_summary(value: &Value) -> String {
    let decision = value
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let action_id = value
        .get("action_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let explanation = value
        .get("explanation")
        .and_then(Value::as_str)
        .unwrap_or("no explanation returned");
    format!("tempOS denied MCP local shell action {action_id}: decision={decision}; {explanation}")
}

fn execution_summary(value: &Value) -> String {
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let action_id = value
        .get("action_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let receipt = value
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let stdout_truncated = value
        .get("stdout_truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let stderr_truncated = value
        .get("stderr_truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let created = value
        .get("created")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let modified = value
        .get("modified")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let deleted = value
        .get("deleted")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    format!(
        "tempOS completed MCP local shell action {action_id}: status={status}; receipt={receipt}; fs_diff created={created} modified={modified} deleted={deleted}; stdout_truncated={stdout_truncated}; stderr_truncated={stderr_truncated}"
    )
}

fn bounded_paths(paths: &[String]) -> Vec<String> {
    paths.iter().take(MAX_ARTIFACT_PATHS).cloned().collect()
}

fn cap_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = 0;
    for (idx, character) in text.char_indices() {
        let next = idx + character.len_utf8();
        if next > max_bytes {
            break;
        }
        end = next;
    }
    text[..end].to_string()
}

fn merged_safe_environment(
    supplied: &BTreeMap<String, String>,
) -> McpResult<BTreeMap<String, String>> {
    let mut environment = safe_path_environment();
    for (name, value) in supplied {
        if name == "PATH" {
            return Err(McpError::Refused(
                "PATH is reserved for the sandbox safe system search path".to_string(),
            ));
        }
        if !name.starts_with("BEATER_") {
            return Err(McpError::Refused(format!(
                "environment variable {name:?} must start with BEATER_"
            )));
        }
        if environment_name_looks_secret(name) {
            return Err(McpError::Refused(format!(
                "environment variable {name:?} looks credential-bearing and is not accepted over MCP"
            )));
        }
        if environment.contains_key(name) {
            return Err(McpError::Refused(format!(
                "duplicate environment variable {name:?}"
            )));
        }
        environment.insert(name.clone(), value.clone());
    }
    Ok(environment)
}

fn environment_name_looks_secret(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "KEY",
        "PASSWORD",
        "AUTH",
        "BEARER",
        "CREDENTIAL",
    ]
    .iter()
    .any(|marker| upper.contains(marker))
}

fn canonical_cwd(cwd: &str) -> McpResult<String> {
    let path = fs::canonicalize(cwd)
        .map_err(|err| McpError::Refused(format!("cannot canonicalize cwd {cwd:?}: {err}")))?;
    if !path.is_dir() {
        return Err(McpError::Refused(format!("cwd {cwd:?} is not a directory")));
    }
    Ok(path.display().to_string())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: JsonRpcId,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Clone, Debug, Default)]
pub enum JsonRpcId {
    #[default]
    Missing,
    Value(Value),
}

impl<'de> Deserialize<'de> for JsonRpcId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Value::deserialize(deserializer).map(Self::Value)
    }
}

impl JsonRpcId {
    pub fn notification() -> Self {
        Self::Missing
    }

    pub fn from_value(value: Value) -> Self {
        Self::Value(value)
    }

    fn response_value(&self) -> Result<Option<Value>, String> {
        match self {
            Self::Missing => Ok(None),
            Self::Value(Value::Null) => Ok(Some(Value::Null)),
            Self::Value(value @ Value::String(_)) | Self::Value(value @ Value::Number(_)) => {
                Ok(Some(value.clone()))
            }
            Self::Value(_) => Err("jsonrpc id must be string, number, or null".to_string()),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    fn result(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    fn error(id: Value, code: i64, message: &str) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
            }),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolsCallParams {
    name: String,
    #[serde(default)]
    arguments: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalShellToolArguments {
    pub session_id: String,
    #[serde(default)]
    pub action_id: Option<String>,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub grants: Vec<String>,
    #[serde(default = "default_low_risk")]
    pub risk: RiskClass,
    #[serde(default)]
    pub side_effects: Vec<SideEffectClass>,
    #[serde(default)]
    pub data_classes: Vec<DataClass>,
    #[serde(default)]
    pub taint: Vec<TaintLabel>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub max_output_bytes: Option<usize>,
    #[serde(default)]
    pub max_model_output_bytes: Option<usize>,
    #[serde(default)]
    pub explanation: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub receipt_id: Option<String>,
}

fn default_low_risk() -> RiskClass {
    RiskClass::Low
}

struct McpToolOutcome {
    is_error: bool,
    summary: String,
    structured: Value,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::io::{BufReader, Write};

    use beater_os_core::{ActionKind, GrantConstraints, ResourceKind};
    use beater_os_runtime::{AgentRuntime, GrantRequest, SessionStart, default_root_grant_id};

    use super::*;

    #[test]
    fn lists_mediated_local_shell_tool() {
        let config = McpServerConfig::new(std::env::temp_dir());
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: JsonRpcId::from_value(json!(1)),
            method: "tools/list".to_string(),
            params: None,
        };
        let response = match handle_json_rpc(&config, request) {
            Ok(Some(response)) => response,
            other => panic!("unexpected response: {other:?}"),
        };
        let result = match response.result {
            Some(result) => result,
            None => panic!("tools/list should return result"),
        };
        assert_eq!(result["tools"][0]["name"], DEFAULT_TOOL_NAME);
        assert_eq!(
            result["tools"][0]["inputSchema"]["required"],
            json!(["session_id", "command", "cwd", "grants"])
        );
        assert_eq!(
            result["tools"][0]["inputSchema"]["properties"]["target_resource_kind"],
            Value::Null
        );
        assert_eq!(
            result["tools"][0]["inputSchema"]["properties"]["command"]["pattern"],
            "^[^/]+$"
        );
        assert_eq!(
            result["tools"][0]["inputSchema"]["properties"]["env"]["propertyNames"]["pattern"],
            "^BEATER_[A-Za-z0-9_]*$"
        );
        assert_eq!(
            result["tools"][0]["inputSchema"]["properties"]["env"]["maxProperties"],
            json!(
                SandboxLimits::default()
                    .max_environment_vars
                    .saturating_sub(1)
            )
        );
        assert_eq!(
            result["tools"][0]["inputSchema"]["properties"]["side_effects"]["items"]["enum"],
            json!(["local_write"])
        );
        assert_eq!(
            result["tools"][0]["outputSchema"]["oneOf"][0]["properties"]["status"]["enum"],
            json!(["ok", "failed", "timeout", "signaled"])
        );
        let required = result["tools"][0]["outputSchema"]["oneOf"][0]["required"]
            .as_array()
            .unwrap_or_else(|| panic!("success output schema required must be an array"));
        assert!(required.contains(&json!("proposal_hash")));
        assert!(required.contains(&json!("lease_hash")));
        assert!(required.contains(&json!("receipt_root_hash")));
        assert_eq!(
            result["tools"][0]["outputSchema"]["oneOf"]
                .as_array()
                .map_or(0, Vec::len),
            3
        );
    }

    #[test]
    fn oversized_stdio_frame_is_refused_before_json_parse() {
        let body = br#"{"jsonrpc":"2.0","id":7,"method":"initialize","params":{}}"#;
        let mut input = Vec::new();
        if let Err(err) = write!(&mut input, "Content-Length: {}\r\n\r\n", body.len()) {
            panic!("failed to write frame header: {err}");
        }
        input.extend_from_slice(body);
        let mut config = McpServerConfig::new(std::env::temp_dir());
        config.max_request_bytes = body.len() - 1;
        let mut output = Vec::new();
        let error = match run_stdio_server(config, &input[..], &mut output) {
            Ok(()) => panic!("oversized frame should fail before JSON parsing"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("max_request_bytes"));
        assert!(output.is_empty());
    }

    #[test]
    fn duplicate_content_length_header_is_refused() {
        let body = br#"{"jsonrpc":"2.0","id":7,"method":"initialize","params":{}}"#;
        let mut input = Vec::new();
        if let Err(err) = write!(
            &mut input,
            "Content-Length: {}\r\nContent-Length: {}\r\n\r\n",
            body.len(),
            body.len()
        ) {
            panic!("failed to write duplicate frame header: {err}");
        }
        input.extend_from_slice(body);
        let mut reader = BufReader::new(&input[..]);
        let error = match read_framed_request(&mut reader, DEFAULT_MAX_REQUEST_BYTES) {
            Ok(_) => panic!("duplicate Content-Length should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("duplicate Content-Length"));
    }

    #[test]
    fn malformed_json_frame_returns_json_rpc_parse_error() {
        let body = br#"{"jsonrpc":"2.0","id":7,"method":"initialize""#;
        let mut input = Vec::new();
        if let Err(err) = write!(&mut input, "Content-Length: {}\r\n\r\n", body.len()) {
            panic!("failed to write frame header: {err}");
        }
        input.extend_from_slice(body);
        let mut output = Vec::new();
        if let Err(err) = run_stdio_server(
            McpServerConfig::new(std::env::temp_dir()),
            &input[..],
            &mut output,
        ) {
            panic!("malformed JSON should be returned as JSON-RPC parse error: {err}");
        }
        let output_text = match String::from_utf8(output) {
            Ok(output_text) => output_text,
            Err(err) => panic!("output was not utf8: {err}"),
        };
        assert!(output_text.contains("\"code\":-32700"));
        assert!(output_text.contains("\"id\":null"));
    }

    #[test]
    fn oversized_header_line_is_refused_before_body_read() {
        let body = br#"{"jsonrpc":"2.0","id":7,"method":"initialize","params":{}}"#;
        let mut input = Vec::new();
        input.extend_from_slice(b"X-Long: ");
        input.extend(std::iter::repeat(b'a').take(MAX_HEADER_LINE_BYTES));
        input.extend_from_slice(b"\r\n");
        if let Err(err) = write!(&mut input, "Content-Length: {}\r\n\r\n", body.len()) {
            panic!("failed to write frame header: {err}");
        }
        input.extend_from_slice(body);
        let mut reader = BufReader::new(&input[..]);
        let error = match read_framed_request(&mut reader, DEFAULT_MAX_REQUEST_BYTES) {
            Ok(_) => panic!("oversized header line should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("header line exceeds"));
    }

    #[test]
    fn model_text_cap_is_byte_safe() {
        let capped = cap_text("abcédef", 4);
        assert_eq!(capped, "abc");
        let uncapped = cap_text("abc", 16);
        assert_eq!(uncapped, "abc");
    }

    #[test]
    fn invalid_json_rpc_id_is_refused_before_method_dispatch() {
        let config = McpServerConfig::new(std::env::temp_dir());
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: JsonRpcId::from_value(json!({ "not": "valid-id" })),
            method: "tools/list".to_string(),
            params: None,
        };
        let response = match handle_json_rpc(&config, request) {
            Ok(Some(response)) => response,
            other => panic!("unexpected response: {other:?}"),
        };
        let error = match response.error {
            Some(error) => error,
            None => panic!("invalid id should return request error"),
        };
        assert_eq!(response.id, Value::Null);
        assert_eq!(error.code, -32600);
        assert!(error.message.contains("jsonrpc id"));
    }

    #[test]
    fn tools_call_requires_object_arguments() {
        let config = McpServerConfig::new(std::env::temp_dir());
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: JsonRpcId::from_value(json!("call")),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": DEFAULT_TOOL_NAME,
                "arguments": []
            })),
        };
        let response = match handle_json_rpc(&config, request) {
            Ok(Some(response)) => response,
            other => panic!("unexpected response: {other:?}"),
        };
        let error = match response.error {
            Some(error) => error,
            None => panic!("array arguments should return invalid params"),
        };
        assert_eq!(error.code, -32602);
        assert!(error.message.contains("arguments must be a JSON object"));
    }

    #[test]
    fn local_shell_arguments_refuse_duplicate_grants_before_daemon_access() {
        let args = LocalShellToolArguments {
            session_id: "session".to_string(),
            action_id: None,
            command: "sh".to_string(),
            args: Vec::new(),
            cwd: ".".to_string(),
            env: BTreeMap::new(),
            grants: vec!["grant-a".to_string(), "grant-a".to_string()],
            risk: RiskClass::Low,
            side_effects: Vec::new(),
            data_classes: Vec::new(),
            taint: Vec::new(),
            timeout_secs: None,
            max_output_bytes: None,
            max_model_output_bytes: None,
            explanation: None,
            idempotency_key: None,
            receipt_id: None,
        };
        let error = match validate_local_shell_args(&args) {
            Ok(()) => panic!("duplicate grants should be refused"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("duplicate grant id"));
    }

    #[test]
    fn caller_supplied_secret_like_environment_names_are_refused() {
        let mut supplied = BTreeMap::new();
        supplied.insert("BEATER_API_TOKEN".to_string(), "not-forwarded".to_string());
        let error = match merged_safe_environment(&supplied) {
            Ok(_) => panic!("secret-like BEATER_* env names should be refused"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("credential-bearing"));
    }

    #[test]
    fn tool_descriptor_advertises_argument_and_grant_caps() {
        let config = McpServerConfig::new(std::env::temp_dir());
        let result = tools_list_result(&config);
        let input = &result["tools"][0]["inputSchema"]["properties"];
        assert_eq!(input["args"]["maxItems"], json!(MAX_TOOL_ARGS));
        assert_eq!(
            input["args"]["items"]["maxLength"],
            json!(MAX_TOOL_ARG_BYTES)
        );
        assert_eq!(input["grants"]["maxItems"], json!(MAX_GRANTS));
        assert_eq!(input["grants"]["uniqueItems"], json!(true));
        assert_eq!(input["action_id"]["maxLength"], json!(MAX_IDENTIFIER_BYTES));
    }

    #[test]
    fn tool_call_goes_through_admission_lease_and_receipt() {
        let root = std::env::temp_dir().join(format!("beater-os-mcp-test-{}", Uuid::new_v4()));
        let workdir = root.join("work");
        if let Err(err) = fs::create_dir_all(&workdir) {
            panic!("failed to create workdir: {err}");
        }
        let runtime = match AgentRuntime::open(&root) {
            Ok(runtime) => runtime,
            Err(err) => panic!("failed to open runtime: {err}"),
        };
        let session_id = "mcp-test-session";
        let mut start = SessionStart::new(
            "agent:mcp-test",
            "workspace:mcp-test",
            "prove MCP mediated local-shell dispatch",
        );
        start.session_id = Some(session_id.to_string());
        if let Err(err) = runtime.create_session(start) {
            panic!("failed to create session: {err}");
        }
        let canonical_workdir = match fs::canonicalize(&workdir) {
            Ok(path) => path.display().to_string(),
            Err(err) => panic!("failed to canonicalize workdir: {err}"),
        };
        let mut grant = GrantRequest::new(ResourceKind::FilePath, "*", [ActionKind::Execute]);
        grant.constraints = GrantConstraints {
            path_prefixes: BTreeSet::from([canonical_workdir]),
            ..Default::default()
        };
        if let Err(err) = runtime.issue_grant(session_id, grant) {
            panic!("failed to issue grant: {err}");
        }
        let call = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: JsonRpcId::from_value(json!("call-1")),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": DEFAULT_TOOL_NAME,
                "arguments": {
                    "session_id": session_id,
                    "action_id": "mcp-test-action",
                    "command": "sh",
                    "args": ["-c", "printf mcp-mediated > mcp-out.txt"],
                    "cwd": workdir.display().to_string(),
                    "grants": [default_root_grant_id(session_id)],
                    "timeout_secs": 30,
                    "receipt_id": "mcp-test-receipt"
                }
            })),
        };
        let response = match handle_json_rpc(&McpServerConfig::new(&root), call) {
            Ok(Some(response)) => response,
            other => panic!("unexpected response: {other:?}"),
        };
        if response.error.is_some() {
            panic!("tools/call failed: {:?}", response.error);
        }
        let result = match response.result {
            Some(result) => result,
            None => panic!("tools/call should return result"),
        };
        assert_eq!(result["isError"].as_bool(), Some(false));
        assert_eq!(
            result["structuredContent"]["receipt_id"],
            "mcp-test-receipt"
        );
        let output_path = workdir.join("mcp-out.txt");
        let output = match fs::read_to_string(&output_path) {
            Ok(output) => output,
            Err(err) => panic!("failed to read output: {err}"),
        };
        assert_eq!(output, "mcp-mediated");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn null_request_id_gets_null_response_id() {
        let config = McpServerConfig::new(std::env::temp_dir());
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: JsonRpcId::from_value(Value::Null),
            method: "tools/list".to_string(),
            params: None,
        };
        let response = match handle_json_rpc(&config, request) {
            Ok(Some(response)) => response,
            other => panic!("unexpected response: {other:?}"),
        };
        assert_eq!(response.id, Value::Null);
        assert!(response.result.is_some());
    }

    #[test]
    fn unsupported_method_uses_method_not_found_code() {
        let config = McpServerConfig::new(std::env::temp_dir());
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: JsonRpcId::from_value(json!("unknown")),
            method: "resources/list".to_string(),
            params: None,
        };
        let response = match handle_json_rpc(&config, request) {
            Ok(Some(response)) => response,
            other => panic!("unexpected response: {other:?}"),
        };
        let error = match response.error {
            Some(error) => error,
            None => panic!("unsupported method should return error"),
        };
        assert_eq!(error.code, -32601);
    }

    #[test]
    fn stdio_framing_round_trips_initialize() {
        let body = br#"{"jsonrpc":"2.0","id":7,"method":"initialize","params":{}}"#;
        let mut input = Vec::new();
        if let Err(err) = write!(&mut input, "Content-Length: {}\r\n\r\n", body.len()) {
            panic!("failed to write frame header: {err}");
        }
        input.extend_from_slice(body);
        let mut output = Vec::new();
        if let Err(err) = run_stdio_server(
            McpServerConfig::new(std::env::temp_dir()),
            &input[..],
            &mut output,
        ) {
            panic!("stdio server failed: {err}");
        }
        let output_text = match String::from_utf8(output) {
            Ok(output_text) => output_text,
            Err(err) => panic!("output was not utf8: {err}"),
        };
        assert!(output_text.contains("Content-Length:"));
        assert!(output_text.contains(MCP_PROTOCOL_VERSION));
    }
}
