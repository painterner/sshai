use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use sshai_ssh::WorkspaceClient;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const MAX_MCP_MESSAGE: usize = 1024 * 1024;
const MCP_FALLBACK_VERSION: &str = "2025-11-25";

pub async fn serve(mut workspace: WorkspaceClient) -> Result<()> {
    let result = serve_inner(&mut workspace).await;
    let close = workspace.close().await;
    match (result, close) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error.into()),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn serve_inner(workspace: &mut WorkspaceClient) -> Result<()> {
    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        let read = input.read_until(b'\n', &mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        if buffer.len() > MAX_MCP_MESSAGE {
            bail!("MCP request exceeds {MAX_MCP_MESSAGE} bytes");
        }
        while matches!(buffer.last(), Some(b'\n' | b'\r')) {
            buffer.pop();
        }
        if buffer.is_empty() {
            continue;
        }
        let message: Value = match serde_json::from_slice(&buffer) {
            Ok(message) => message,
            Err(error) => {
                write_message(
                    &mut output,
                    &error_response(Value::Null, -32700, format!("parse error: {error}")),
                )
                .await?;
                continue;
            }
        };
        let Some(id) = message.get("id").cloned() else {
            continue;
        };
        let response = match handle_request(workspace, &message).await {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(error) => error_response(id, -32602, format!("{error:#}")),
        };
        write_message(&mut output, &response).await?;
    }
}

async fn handle_request(workspace: &mut WorkspaceClient, message: &Value) -> Result<Value> {
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        bail!("jsonrpc must be \"2.0\"");
    }
    let method = message
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing method"))?;
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
    match method {
        "initialize" => {
            let protocol = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(MCP_FALLBACK_VERSION);
            Ok(json!({
                "protocolVersion": protocol,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "sshai", "version": env!("CARGO_PKG_VERSION")},
                "instructions": "Operate on the remote workspace exclusively through these tools. Paths are relative to the negotiated remote root. Run build, test, Git, and shell commands with workspace_exec."
            }))
        }
        "server/discover" => Ok(json!({
            "serverInfo": {"name": "sshai", "version": env!("CARGO_PKG_VERSION")},
            "capabilities": {"tools": {}},
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": sshai_tools::definitions()})),
        "tools/call" => call_tool(workspace, &params).await,
        _ => bail!("method not found: {method}"),
    }
}

async fn call_tool(workspace: &mut WorkspaceClient, params: &Value) -> Result<Value> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field \"name\""))?;
    let arguments = params
        .get("arguments")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let result = sshai_tools::dispatch(workspace, name, &arguments).await;
    Ok(match result {
        Ok(value) => tool_result(value, false),
        Err(error) => tool_result(json!({"error": format!("{error:#}")}), true),
    })
}

fn tool_result(value: Value, is_error: bool) -> Value {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": value,
        "isError": is_error,
    })
}

fn error_response(id: Value, code: i64, message: String) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

async fn write_message(output: &mut tokio::io::Stdout, message: &Value) -> Result<()> {
    let mut encoded = serde_json::to_vec(message)?;
    encoded.push(b'\n');
    output.write_all(&encoded).await?;
    output.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_errors_are_machine_and_human_readable() {
        let result = tool_result(json!({"error": "denied"}), true);
        assert_eq!(result["isError"], true);
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("denied")
        );
    }

    #[test]
    fn errors_keep_json_rpc_shape() {
        let result = error_response(json!(7), -32602, "bad request".to_owned());
        assert_eq!(result["jsonrpc"], "2.0");
        assert_eq!(result["id"], 7);
        assert_eq!(result["error"]["code"], -32602);
    }
}
