//! Shared remote-workspace tools used by both MCP and sshai's built-in agent.

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Map, Value, json};
use sshai_ssh::{MAX_WORKSPACE_READ, WorkspaceClient, WorkspaceFileKind, WorkspaceMutation};

/// Return MCP-compatible tool definitions.
pub fn definitions() -> Vec<Value> {
    vec![
        tool(
            "workspace_info",
            "Get the canonical remote workspace root and capabilities.",
            json!({"type":"object","properties":{}}),
            true,
            false,
        ),
        tool(
            "workspace_list",
            "List a remote directory. Continue with next_cursor when present.",
            json!({"type":"object","properties":{"path":{"type":"string"},"cursor":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":1000}}}),
            true,
            false,
        ),
        tool(
            "workspace_stat",
            "Get metadata for a remote path without following the final symlink.",
            json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
            true,
            false,
        ),
        tool(
            "workspace_read",
            "Read up to 512 KiB from a remote file. Use offset for subsequent chunks.",
            json!({"type":"object","properties":{"path":{"type":"string"},"offset":{"type":"integer","minimum":0},"length":{"type":"integer","minimum":1,"maximum":524288}},"required":["path"]}),
            true,
            false,
        ),
        tool(
            "workspace_hash",
            "Calculate the BLAKE3 digest of a remote file.",
            json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
            true,
            false,
        ),
        tool(
            "workspace_write",
            "Atomically create or replace a remote file. Existing files require expected_blake3 or overwrite=true.",
            json!({"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"},"data_base64":{"type":"string"},"expected_blake3":{"type":"string"},"overwrite":{"type":"boolean"},"mode":{"type":"integer","minimum":0,"maximum":511}},"required":["path"]}),
            false,
            true,
        ),
        tool(
            "workspace_edit",
            "Replace exactly one occurrence of old_text in a UTF-8 remote file using an atomic conflict-checked write.",
            json!({"type":"object","properties":{"path":{"type":"string"},"old_text":{"type":"string"},"new_text":{"type":"string"},"expected_blake3":{"type":"string"}},"required":["path","old_text","new_text"]}),
            false,
            true,
        ),
        tool(
            "workspace_mkdir",
            "Create a remote directory.",
            json!({"type":"object","properties":{"path":{"type":"string"},"recursive":{"type":"boolean"}},"required":["path"]}),
            false,
            false,
        ),
        tool(
            "workspace_rename",
            "Atomically rename a path within the remote workspace.",
            json!({"type":"object","properties":{"from":{"type":"string"},"to":{"type":"string"},"overwrite":{"type":"boolean"}},"required":["from","to"]}),
            false,
            true,
        ),
        tool(
            "workspace_remove",
            "Remove a file, symlink, or directory from the remote workspace.",
            json!({"type":"object","properties":{"path":{"type":"string"},"recursive":{"type":"boolean"}},"required":["path"]}),
            false,
            true,
        ),
        tool(
            "workspace_exec",
            "Run argv directly in the remote environment. Use this for all shell, Git, build, and test commands.",
            json!({"type":"object","properties":{"command":{"type":"array","items":{"type":"string"},"minItems":1},"cwd":{"type":"string"},"env":{"type":"object","additionalProperties":{"type":"string"}}},"required":["command"]}),
            false,
            true,
        ),
    ]
}

/// Return Responses API function-tool definitions from the canonical schemas.
pub fn function_definitions() -> Vec<Value> {
    definitions()
        .into_iter()
        .map(|definition| {
            json!({
                "type": "function",
                "name": definition["name"],
                "description": definition["description"],
                "parameters": definition["inputSchema"],
                "strict": false,
            })
        })
        .collect()
}

/// Whether a tool can change remote state or execute arbitrary code.
pub fn requires_approval(name: &str) -> bool {
    matches!(
        name,
        "workspace_write"
            | "workspace_edit"
            | "workspace_mkdir"
            | "workspace_rename"
            | "workspace_remove"
            | "workspace_exec"
    )
}

/// Invoke one canonical tool against an authenticated remote workspace.
pub async fn dispatch(
    workspace: &mut WorkspaceClient,
    name: &str,
    arguments: &Map<String, Value>,
) -> Result<Value> {
    match name {
        "workspace_info" => {
            let (root, capabilities) = workspace.open().await?;
            Ok(json!({"root": root, "capabilities": capabilities}))
        }
        "workspace_list" => {
            let path = optional_string(arguments, "path").unwrap_or_else(|| ".".to_owned());
            let cursor = optional_string(arguments, "cursor");
            let limit = optional_u64(arguments, "limit").unwrap_or(200).min(1_000) as u32;
            let (entries, next_cursor) = workspace.list(path, cursor, limit).await?;
            let entries = entries
                .into_iter()
                .map(|entry| {
                    json!({
                        "name": entry.name,
                        "kind": file_kind(entry.metadata.kind),
                        "size": entry.metadata.size,
                        "modified_unix_ms": entry.metadata.modified_unix_ms,
                        "mode": entry.metadata.mode,
                    })
                })
                .collect::<Vec<_>>();
            Ok(json!({"entries": entries, "next_cursor": next_cursor}))
        }
        "workspace_stat" => {
            let metadata = workspace
                .stat(required_argument_string(arguments, "path")?)
                .await?;
            Ok(json!({
                "kind": file_kind(metadata.kind),
                "size": metadata.size,
                "modified_unix_ms": metadata.modified_unix_ms,
                "mode": metadata.mode,
            }))
        }
        "workspace_read" => {
            let path = required_argument_string(arguments, "path")?;
            let offset = optional_u64(arguments, "offset").unwrap_or(0);
            let length = optional_u64(arguments, "length")
                .unwrap_or(u64::from(MAX_WORKSPACE_READ))
                .min(u64::from(MAX_WORKSPACE_READ)) as u32;
            let (data, eof) = workspace.read(path, offset, length).await?;
            match String::from_utf8(data) {
                Ok(text) => Ok(json!({"encoding": "utf-8", "text": text, "eof": eof})),
                Err(error) => Ok(json!({
                    "encoding": "base64",
                    "data": BASE64.encode(error.into_bytes()),
                    "eof": eof,
                })),
            }
        }
        "workspace_hash" => {
            let (algorithm, digest) = workspace
                .hash(required_argument_string(arguments, "path")?)
                .await?;
            Ok(json!({"algorithm": algorithm, "digest": digest}))
        }
        "workspace_write" => {
            let path = required_argument_string(arguments, "path")?;
            let data = content_bytes(arguments)?;
            let mode = optional_u64(arguments, "mode")
                .map(|value| u32::try_from(value).context("mode exceeds u32"))
                .transpose()?;
            let mutation = workspace
                .write(
                    path,
                    &data,
                    optional_string(arguments, "expected_blake3"),
                    optional_bool(arguments, "overwrite").unwrap_or(false),
                    mode,
                )
                .await?;
            Ok(mutation_json(mutation))
        }
        "workspace_edit" => {
            let mutation = workspace
                .edit(
                    required_argument_string(arguments, "path")?,
                    required_argument_string(arguments, "old_text")?,
                    required_argument_string(arguments, "new_text")?,
                    optional_string(arguments, "expected_blake3"),
                )
                .await?;
            Ok(mutation_json(mutation))
        }
        "workspace_mkdir" => {
            let mutation = workspace
                .mkdir(
                    required_argument_string(arguments, "path")?,
                    optional_bool(arguments, "recursive").unwrap_or(false),
                )
                .await?;
            Ok(mutation_json(mutation))
        }
        "workspace_rename" => {
            let mutation = workspace
                .rename(
                    required_argument_string(arguments, "from")?,
                    required_argument_string(arguments, "to")?,
                    optional_bool(arguments, "overwrite").unwrap_or(false),
                )
                .await?;
            Ok(mutation_json(mutation))
        }
        "workspace_remove" => {
            let mutation = workspace
                .remove(
                    required_argument_string(arguments, "path")?,
                    optional_bool(arguments, "recursive").unwrap_or(false),
                )
                .await?;
            Ok(mutation_json(mutation))
        }
        "workspace_exec" => {
            let command = arguments
                .get("command")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("command must be an array of strings"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| anyhow!("command elements must be strings"))
                })
                .collect::<Result<Vec<_>>>()?;
            if command.is_empty() {
                bail!("command must not be empty");
            }
            let cwd = optional_string(arguments, "cwd").unwrap_or_else(|| ".".to_owned());
            let env = arguments
                .get("env")
                .and_then(Value::as_object)
                .map(|values| {
                    values
                        .iter()
                        .map(|(key, value)| {
                            value
                                .as_str()
                                .map(|value| (key.clone(), value.to_owned()))
                                .ok_or_else(|| anyhow!("environment values must be strings"))
                        })
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?
                .unwrap_or_default();
            let result = workspace.exec(command, cwd, env).await?;
            Ok(json!({
                "exit_code": result.exit_code,
                "stdout": String::from_utf8_lossy(&result.stdout),
                "stderr": String::from_utf8_lossy(&result.stderr),
                "stdout_base64": BASE64.encode(&result.stdout),
                "stderr_base64": BASE64.encode(&result.stderr),
                "truncated": result.truncated,
            }))
        }
        _ => bail!("unknown tool: {name}"),
    }
}

fn tool(
    name: &str,
    description: &str,
    input_schema: Value,
    read_only: bool,
    destructive: bool,
) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
        "annotations": {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "openWorldHint": false,
        }
    })
}

fn mutation_json(mutation: WorkspaceMutation) -> Value {
    json!({
        "path": mutation.path,
        "metadata": mutation.metadata.map(|metadata| json!({
            "kind": file_kind(metadata.kind),
            "size": metadata.size,
            "modified_unix_ms": metadata.modified_unix_ms,
            "mode": metadata.mode,
        })),
        "blake3": mutation.blake3,
    })
}

fn content_bytes(arguments: &Map<String, Value>) -> Result<Vec<u8>> {
    match (
        optional_string(arguments, "content"),
        optional_string(arguments, "data_base64"),
    ) {
        (Some(content), None) => Ok(content.into_bytes()),
        (None, Some(data)) => BASE64.decode(data).context("invalid data_base64"),
        (Some(_), Some(_)) => bail!("provide only one of content or data_base64"),
        (None, None) => bail!("provide content or data_base64"),
    }
}

fn required_argument_string(arguments: &Map<String, Value>, key: &str) -> Result<String> {
    optional_string(arguments, key).ok_or_else(|| anyhow!("missing string argument {key:?}"))
}

fn optional_string(arguments: &Map<String, Value>, key: &str) -> Option<String> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn optional_u64(arguments: &Map<String, Value>, key: &str) -> Option<u64> {
    arguments.get(key).and_then(Value::as_u64)
}

fn optional_bool(arguments: &Map<String, Value>, key: &str) -> Option<bool> {
    arguments.get(key).and_then(Value::as_bool)
}

fn file_kind(kind: WorkspaceFileKind) -> &'static str {
    match kind {
        WorkspaceFileKind::File => "file",
        WorkspaceFileKind::Directory => "directory",
        WorkspaceFileKind::Symlink => "symlink",
        WorkspaceFileKind::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn tool_names_are_unique_and_stable() {
        let tools = definitions();
        let names = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names.len(),
            names.iter().copied().collect::<BTreeSet<_>>().len()
        );
        assert_eq!(names.len(), 11);
        assert_eq!(names[0], "workspace_info");
        assert_eq!(names[10], "workspace_exec");
    }

    #[test]
    fn function_schemas_derive_from_canonical_definitions() {
        let tools = function_definitions();
        assert_eq!(tools.len(), 11);
        assert!(tools.iter().all(|tool| tool["type"] == "function"));
        assert_eq!(tools[3]["parameters"]["required"][0], "path");
    }

    #[test]
    fn approval_policy_covers_all_side_effecting_tools() {
        for name in [
            "workspace_write",
            "workspace_edit",
            "workspace_mkdir",
            "workspace_rename",
            "workspace_remove",
            "workspace_exec",
        ] {
            assert!(requires_approval(name), "{name}");
        }
        assert!(!requires_approval("workspace_read"));
    }
}
