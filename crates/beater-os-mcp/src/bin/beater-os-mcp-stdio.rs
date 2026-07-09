use std::path::PathBuf;
use std::process::ExitCode;

use beater_os_mcp::{
    MAX_CONFIGURED_MODEL_OUTPUT_BYTES, MAX_CONFIGURED_REQUEST_BYTES, McpServerConfig,
    run_stdio_server,
};

const USAGE: &str = "\
beater-os-mcp-stdio - mediated MCP stdio gateway

USAGE:
    beater-os-mcp-stdio serve-local-shell --root <path> [options]

OPTIONS:
    --tool-name <name>            MCP tool name (default: tempos.local_shell)
    --max-request-bytes <bytes>   Maximum MCP stdio frame bytes
    --max-model-output-bytes <bytes>
                                  Maximum text fallback bytes returned to the model
";

fn main() -> ExitCode {
    match run(std::env::args().collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let config = parse_config(&args)?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_stdio_server(config, stdin.lock(), stdout.lock())
        .map_err(|err| format!("MCP stdio gateway failed: {err}"))
}

fn parse_config(args: &[String]) -> Result<McpServerConfig, String> {
    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        return Err(USAGE.to_string());
    }
    if args[1] != "serve-local-shell" {
        return Err(format!("{USAGE}unsupported command: {}", args[1]));
    }
    let mut root = None;
    let mut tool_name = None;
    let mut max_request_bytes = None;
    let mut max_model_output_bytes = None;
    let mut idx = 2;
    while idx < args.len() {
        match args[idx].as_str() {
            "--root" => root = Some(PathBuf::from(next_value(args, &mut idx, "--root")?)),
            "--tool-name" => tool_name = Some(next_value(args, &mut idx, "--tool-name")?),
            "--max-request-bytes" => {
                max_request_bytes = Some(parse_usize(
                    &next_value(args, &mut idx, "--max-request-bytes")?,
                    "--max-request-bytes",
                )?);
            }
            "--max-model-output-bytes" => {
                max_model_output_bytes = Some(parse_usize(
                    &next_value(args, &mut idx, "--max-model-output-bytes")?,
                    "--max-model-output-bytes",
                )?);
            }
            other => return Err(format!("{USAGE}unsupported option: {other}")),
        }
        idx += 1;
    }
    let root = root.ok_or_else(|| format!("{USAGE}missing --root"))?;
    let mut config = McpServerConfig::new(root);
    if let Some(tool_name) = tool_name {
        if tool_name.is_empty() {
            return Err("--tool-name must not be empty".to_string());
        }
        config.tool_name = tool_name;
    }
    if let Some(max_request_bytes) = max_request_bytes {
        if max_request_bytes == 0 || max_request_bytes > MAX_CONFIGURED_REQUEST_BYTES {
            return Err(format!(
                "--max-request-bytes must be between 1 and {MAX_CONFIGURED_REQUEST_BYTES}"
            ));
        }
        config.max_request_bytes = max_request_bytes;
    }
    if let Some(max_model_output_bytes) = max_model_output_bytes {
        if max_model_output_bytes == 0 || max_model_output_bytes > MAX_CONFIGURED_MODEL_OUTPUT_BYTES
        {
            return Err(format!(
                "--max-model-output-bytes must be between 1 and {MAX_CONFIGURED_MODEL_OUTPUT_BYTES}"
            ));
        }
        config.max_model_output_bytes = max_model_output_bytes;
    }
    Ok(config)
}

fn next_value(args: &[String], idx: &mut usize, name: &str) -> Result<String, String> {
    *idx += 1;
    args.get(*idx)
        .cloned()
        .ok_or_else(|| format!("{name} requires a value"))
}

fn parse_usize(value: &str, name: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("{name} must be a positive integer"))
}
