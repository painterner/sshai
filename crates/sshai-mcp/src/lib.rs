use std::path::{Component, Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};
use sshai_ssh::{SftpClient, WorkspaceClient};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const MAX_MCP_MESSAGE: usize = 1024 * 1024;
const MCP_FALLBACK_VERSION: &str = "2025-11-25";

pub async fn serve(
    mut workspace: WorkspaceClient,
    sftp: SftpClient,
    local_root: PathBuf,
) -> Result<()> {
    let result = serve_inner(&mut workspace, &sftp, &local_root).await;
    let workspace_close = workspace.close().await;
    let sftp_close = sftp.close().await;
    match (result, workspace_close, sftp_close) {
        (Err(error), _, _) => Err(error),
        (Ok(()), Err(error), _) => Err(error.into()),
        (Ok(()), Ok(()), Err(error)) => Err(error.into()),
        (Ok(()), Ok(()), Ok(())) => Ok(()),
    }
}

async fn serve_inner(
    workspace: &mut WorkspaceClient,
    sftp: &SftpClient,
    local_root: &Path,
) -> Result<()> {
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
        let response = match handle_request(workspace, sftp, local_root, &message).await {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(error) => error_response(id, -32602, format!("{error:#}")),
        };
        write_message(&mut output, &response).await?;
    }
}

async fn handle_request(
    workspace: &mut WorkspaceClient,
    sftp: &SftpClient,
    local_root: &Path,
    message: &Value,
) -> Result<Value> {
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
                "instructions": "This is the REMOTE side of an sshai dual-workspace session. Native file and shell tools operate on LOCAL; workspace_* tools operate on REMOTE. Ordinary workspace paths are relative to the negotiated remote root. Use workspace_transfer for direct non-overwriting LOCAL/REMOTE copies; its remote_path may also be absolute. Only use workspace_transfer_overwrite after the user explicitly requests replacement. A remote cp command cannot read LOCAL files."
            }))
        }
        "server/discover" => Ok(json!({
            "serverInfo": {"name": "sshai", "version": env!("CARGO_PKG_VERSION")},
            "capabilities": {"tools": {}},
        })),
        "ping" => Ok(json!({})),
        "tools/list" => {
            let mut tools = sshai_tools::definitions();
            tools.push(transfer_definition(false));
            tools.push(transfer_definition(true));
            Ok(json!({"tools": tools}))
        }
        "tools/call" => call_tool(workspace, sftp, local_root, &params).await,
        _ => bail!("method not found: {method}"),
    }
}

async fn call_tool(
    workspace: &mut WorkspaceClient,
    sftp: &SftpClient,
    local_root: &Path,
    params: &Value,
) -> Result<Value> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field \"name\""))?;
    let arguments = params
        .get("arguments")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let result = match name {
        "workspace_transfer" => transfer(sftp, local_root, &arguments, false).await,
        "workspace_transfer_overwrite" => transfer(sftp, local_root, &arguments, true).await,
        _ => sshai_tools::dispatch(workspace, name, &arguments).await,
    };
    Ok(match result {
        Ok(value) => tool_result(value, false),
        Err(error) => tool_result(json!({"error": format!("{error:#}")}), true),
    })
}

fn transfer_definition(overwrite: bool) -> Value {
    let (name, description, destructive) = if overwrite {
        (
            "workspace_transfer_overwrite",
            "Copy a file or directory directly between LOCAL and REMOTE over SSH, replacing existing destination files. Use only when the user explicitly requested overwrite. Bytes do not pass through model context. local_path is relative to LOCAL. remote_path may be relative to the remote workspace root or an explicit absolute remote path. Symlinks are rejected.",
            true,
        )
    } else {
        (
            "workspace_transfer",
            "Copy a file or directory directly between LOCAL and REMOTE over SSH without replacing existing destination files. Bytes do not pass through model context. local_path is relative to LOCAL. remote_path may be relative to the remote workspace root or an explicit absolute remote path. Symlinks are rejected.",
            false,
        )
    };
    json!({
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": {
                "direction": {"type": "string", "enum": ["local_to_remote", "remote_to_local"]},
                "local_path": {"type": "string"},
                "remote_path": {"type": "string"},
                "recursive": {"type": "boolean"},
                "exclude": {"type": "array", "items": {"type": "string"}, "maxItems": 100}
            },
            "required": ["direction", "local_path", "remote_path"]
        },
        "annotations": {
            "readOnlyHint": false,
            "destructiveHint": destructive,
            "openWorldHint": false
        }
    })
}

async fn transfer(
    sftp: &SftpClient,
    local_root: &Path,
    arguments: &Map<String, Value>,
    overwrite: bool,
) -> Result<Value> {
    let direction = required_string(arguments, "direction")?;
    let local_path = required_string(arguments, "local_path")?;
    let remote_path = normalize_remote_path(&required_string(arguments, "remote_path")?)?;
    let recursive = optional_bool(arguments, "recursive").unwrap_or(false);
    if !overwrite && optional_bool(arguments, "overwrite").unwrap_or(false) {
        bail!(
            "workspace_transfer never overwrites; use workspace_transfer_overwrite after explicit user authorization"
        );
    }
    let excludes = string_array(arguments, "exclude")?;
    let local_path = resolve_local_path(local_root, &local_path)?;
    ensure_local_path_safe(local_root, &local_path)?;

    let stats = match direction.as_str() {
        "local_to_remote" => {
            sftp.upload_path(
                &local_path,
                remote_path.clone(),
                recursive,
                overwrite,
                &excludes,
            )
            .await?
        }
        "remote_to_local" => {
            sftp.download_path(
                remote_path.clone(),
                &local_path,
                recursive,
                overwrite,
                &excludes,
            )
            .await?
        }
        _ => bail!("direction must be local_to_remote or remote_to_local"),
    };

    Ok(json!({
        "direction": direction,
        "source": if direction == "local_to_remote" {
            format!("local:{}", local_path.display())
        } else {
            format!("remote:{remote_path}")
        },
        "destination": if direction == "local_to_remote" {
            format!("remote:{remote_path}")
        } else {
            format!("local:{}", local_path.display())
        },
        "bytes": stats.bytes,
        "files": stats.files,
        "directories": stats.directories,
    }))
}

fn resolve_local_path(local_root: &Path, input: &str) -> Result<PathBuf> {
    let path = Path::new(input);
    if input.is_empty() || path.is_absolute() {
        bail!("local_path must be a non-empty path relative to the local workspace root");
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("local_path must not contain parent traversal or an absolute prefix")
            }
        }
    }
    Ok(local_root.join(path))
}

fn normalize_remote_path(input: &str) -> Result<String> {
    if input.is_empty() {
        bail!("remote_path must not be empty");
    }
    let absolute = input.starts_with('/');
    let mut components = Vec::new();
    for component in input.split('/') {
        match component {
            "" | "." => {}
            ".." => bail!("remote_path must not contain parent traversal"),
            component => components.push(component),
        }
    }
    Ok(if components.is_empty() && absolute {
        "/".to_owned()
    } else if components.is_empty() {
        ".".to_owned()
    } else if absolute {
        format!("/{}", components.join("/"))
    } else {
        components.join("/")
    })
}

fn ensure_local_path_safe(local_root: &Path, path: &Path) -> Result<()> {
    if !path.starts_with(local_root) {
        bail!("local path escapes the local workspace root");
    }
    let relative = path
        .strip_prefix(local_root)
        .expect("prefix was checked above");
    let mut current = local_root.to_owned();
    for component in relative.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "refusing local symlink in transfer path {}",
                    current.display()
                )
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn required_string(arguments: &Map<String, Value>, key: &str) -> Result<String> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("missing string argument {key:?}"))
}

fn optional_bool(arguments: &Map<String, Value>, key: &str) -> Option<bool> {
    arguments.get(key).and_then(Value::as_bool)
}

fn string_array(arguments: &Map<String, Value>, key: &str) -> Result<Vec<String>> {
    arguments
        .get(key)
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| anyhow!("{key} must be an array of strings"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| anyhow!("{key} must contain only strings"))
                })
                .collect()
        })
        .transpose()
        .map(Option::unwrap_or_default)
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

    #[test]
    fn transfer_tool_is_mutating_and_requires_explicit_endpoints() {
        let tool = transfer_definition(false);
        assert_eq!(tool["name"], "workspace_transfer");
        assert_eq!(tool["annotations"]["readOnlyHint"], false);
        assert_eq!(tool["annotations"]["destructiveHint"], false);
        assert_eq!(
            tool["inputSchema"]["required"],
            json!(["direction", "local_path", "remote_path"])
        );

        let overwrite = transfer_definition(true);
        assert_eq!(overwrite["name"], "workspace_transfer_overwrite");
        assert_eq!(overwrite["annotations"]["destructiveHint"], true);
    }

    #[test]
    fn transfer_paths_are_workspace_relative() {
        let root = Path::new("/tmp/local-root");
        assert_eq!(
            resolve_local_path(root, "src/main.rs").unwrap(),
            PathBuf::from("/tmp/local-root/src/main.rs")
        );
        assert!(resolve_local_path(root, "../secret").is_err());
        assert!(resolve_local_path(root, "/etc/passwd").is_err());
        assert_eq!(
            normalize_remote_path("./src//main.rs").unwrap(),
            "src/main.rs"
        );
        assert!(normalize_remote_path("../secret").is_err());
        assert_eq!(normalize_remote_path("/etc/passwd").unwrap(), "/etc/passwd");
    }
}
