use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io::Write;

use beater_os_core::{ActionKind, GrantConstraints, ResourceKind};
use beater_os_mcp::{McpServerConfig, run_stdio_server};
use beater_os_runtime::{AgentRuntime, GrantRequest, SessionStart, default_root_grant_id};
use beater_osd::Store;
use serde_json::{Value, json};
use uuid::Uuid;

fn main() -> Result<(), Box<dyn Error>> {
    let mut as_json = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--json" => as_json = true,
            other => return Err(format!("unsupported argument: {other}").into()),
        }
    }

    let root = std::env::temp_dir().join(format!("beater-os-mcp-smoke-{}", Uuid::new_v4()));
    let workdir = root.join("work");
    fs::create_dir_all(&workdir)?;
    let runtime = AgentRuntime::open(&root)?;
    let session_id = "mcp-smoke-session";
    let mut start = SessionStart::new(
        "agent:mcp-smoke",
        "workspace:mcp-smoke",
        "prove MCP stdio local-shell gateway",
    );
    start.session_id = Some(session_id.to_string());
    runtime.create_session(start)?;
    let canonical_workdir = fs::canonicalize(&workdir)?.display().to_string();
    let mut grant = GrantRequest::new(ResourceKind::FilePath, "*", [ActionKind::Execute]);
    grant.constraints = GrantConstraints {
        path_prefixes: BTreeSet::from([canonical_workdir]),
        ..Default::default()
    };
    runtime.issue_grant(session_id, grant)?;

    let messages = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "tempos.local_shell",
                "arguments": {
                    "session_id": session_id,
                    "action_id": "mcp-smoke-action",
                    "command": "sh",
                    "args": ["-c", "printf model-visible-stdout; printf mcp-stdio > mcp-stdio.txt"],
                    "cwd": workdir.display().to_string(),
                    "grants": [default_root_grant_id(session_id)],
                    "timeout_secs": 30,
                    "max_model_output_bytes": 96,
                    "receipt_id": "mcp-smoke-receipt"
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "tempos.local_shell",
                "arguments": {
                    "session_id": session_id,
                    "action_id": "mcp-smoke-denied-missing-grant",
                    "command": "sh",
                    "args": ["-c", "printf should-not-run > denied.txt"],
                    "cwd": workdir.display().to_string(),
                    "timeout_secs": 30
                }
            }
        }),
    ];
    let mut input = Vec::new();
    for message in messages {
        let body = serde_json::to_vec(&message)?;
        write!(&mut input, "Content-Length: {}\r\n\r\n", body.len())?;
        input.extend_from_slice(&body);
    }
    let mut output = Vec::new();
    run_stdio_server(McpServerConfig::new(&root), &input[..], &mut output)?;
    let frames = parse_response_frames(&output)?;
    if frames.len() != 4 {
        return Err(format!("expected 4 MCP responses, found {}", frames.len()).into());
    }
    let listed = &frames[1]["result"]["tools"];
    if listed.as_array().map_or(0, Vec::len) != 1
        || listed[0]["name"] != "tempos.local_shell"
        || listed[0]["inputSchema"]["additionalProperties"] != false
    {
        return Err(format!("unexpected tools/list response: {}", frames[1]).into());
    }
    let call = &frames[2];
    if call["error"] != Value::Null {
        return Err(format!("MCP tools/call failed: {}", call["error"]).into());
    }
    if call["result"]["isError"] != false {
        return Err(format!("MCP tools/call returned error: {}", call["result"]).into());
    }
    let Some(summary) = call["result"]["content"][0]["text"].as_str() else {
        return Err("MCP result text summary was not a string".into());
    };
    if summary.len() > 96 {
        return Err(format!("MCP text summary exceeded cap: {} bytes", summary.len()).into());
    }
    if call["result"]["structuredContent"]["stdout_digest"] == Value::Null
        || call["result"]["structuredContent"]["receipt_hash"] == Value::Null
        || call["result"]["structuredContent"]["final_journal_root_hash"] == Value::Null
        || call["result"]["structuredContent"]["lease_id"] == Value::Null
    {
        return Err(format!("MCP result missing execution evidence: {}", call["result"]).into());
    }
    let output_path = workdir.join("mcp-stdio.txt");
    let output_body = fs::read_to_string(&output_path)?;
    if output_body != "mcp-stdio" {
        return Err(format!("unexpected tool output: {output_body:?}").into());
    }
    let denied = &frames[3];
    if denied["error"]["code"] != -32602 {
        return Err(format!("missing-grant call should be rejected: {denied}").into());
    }
    let denied_path = workdir.join("denied.txt");
    if denied_path.exists() {
        return Err("missing-grant MCP call created denied.txt".into());
    }
    let projection = Store::open(&root)?.project(session_id)?;
    if projection.receipts.len() != 1 {
        return Err(format!(
            "expected exactly one receipt after denied call, found {}",
            projection.receipts.len()
        )
        .into());
    }
    let report = json!({
        "status": "ok",
        "responses": frames.len(),
        "session_id": session_id,
        "action_id": call["result"]["structuredContent"]["action_id"],
        "receipt_id": call["result"]["structuredContent"]["receipt_id"],
        "receipt_hash": call["result"]["structuredContent"]["receipt_hash"],
        "final_journal_root_hash": call["result"]["structuredContent"]["final_journal_root_hash"],
        "output": output_path.display().to_string()
    });
    let _ = fs::remove_dir_all(root);
    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("MCP stdio local-shell smoke OK");
        println!("  session: {}", report["session_id"]);
        println!("  action: {}", report["action_id"]);
        println!("  receipt: {}", report["receipt_id"]);
    }
    Ok(())
}

fn parse_response_frames(bytes: &[u8]) -> Result<Vec<Value>, Box<dyn Error>> {
    let mut frames = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let remaining = &bytes[cursor..];
        let marker = b"\r\n\r\n";
        let Some(header_end) = find_bytes(remaining, marker) else {
            return Err("response frame missing header terminator".into());
        };
        let headers = std::str::from_utf8(&remaining[..header_end])?;
        let mut content_len = None;
        for line in headers.lines() {
            let Some((name, value)) = line.split_once(':') else {
                return Err(format!("malformed response header: {line:?}").into());
            };
            if name.eq_ignore_ascii_case("content-length") {
                content_len = Some(value.trim().parse::<usize>()?);
            }
        }
        let body_start = cursor + header_end + marker.len();
        let len = match content_len {
            Some(len) => len,
            None => return Err("response frame missing content-length".into()),
        };
        let body_end = body_start + len;
        if body_end > bytes.len() {
            return Err("truncated response body".into());
        }
        frames.push(serde_json::from_slice(&bytes[body_start..body_end])?);
        cursor = body_end;
    }
    Ok(frames)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
