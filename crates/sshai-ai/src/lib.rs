//! Local model orchestration backed by the remote sshai workspace tools.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use reqwest::{Client, StatusCode, Url};
use serde_json::{Map, Value, json};
use sshai_ssh::WorkspaceClient;

const MAX_API_RESPONSE: usize = 4 * 1024 * 1024;
const DEFAULT_INSTRUCTIONS: &str = "You are the built-in sshai coding agent. The project exists only in the remote workspace exposed by the workspace_* tools. Inspect relevant instruction files before changing code. Use workspace tools for every project read, write, search, Git operation, build, and test. Paths are relative to the remote workspace root. Prefer conflict-checked workspace_edit for existing text files. Verify meaningful changes with remote commands before declaring success.";

#[async_trait]
pub trait ModelProvider: Send + Sync {
    async fn create_response(
        &self,
        instructions: &str,
        input: &[Value],
        tools: &[Value],
    ) -> Result<Value>;
}

pub struct OpenAiProvider {
    client: Client,
    endpoint: Url,
    api_key: String,
    model: String,
}

impl OpenAiProvider {
    pub fn new(api_key: String, model: impl Into<String>, base_url: &str) -> Result<Self> {
        if api_key.trim().is_empty() {
            bail!("OPENAI_API_KEY is empty");
        }
        let mut endpoint = Url::parse(base_url).context("invalid model API base URL")?;
        let secure = endpoint.scheme() == "https";
        let loopback = endpoint
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
        if !secure && !loopback {
            bail!("model API base URL must use HTTPS (HTTP is allowed only for loopback testing)");
        }
        endpoint.set_path(&format!(
            "{}/responses",
            endpoint.path().trim_end_matches('/')
        ));
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(360))
            .build()
            .context("cannot initialize model HTTP client")?;
        Ok(Self {
            client,
            endpoint,
            api_key,
            model: model.into(),
        })
    }

    pub fn model(&self) -> &str {
        &self.model
    }
}

#[async_trait]
impl ModelProvider for OpenAiProvider {
    async fn create_response(
        &self,
        instructions: &str,
        input: &[Value],
        tools: &[Value],
    ) -> Result<Value> {
        let response = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(&self.api_key)
            .json(&json!({
                "model": self.model,
                "instructions": instructions,
                "input": input,
                "tools": tools,
                "parallel_tool_calls": false,
                "store": false,
                "include": ["reasoning.encrypted_content"],
            }))
            .send()
            .await
            .context("model API request failed")?;
        decode_api_response(response.status(), response.bytes().await?).context("model API error")
    }
}

pub trait AgentUi {
    fn tool_started(&mut self, name: &str, arguments: &Map<String, Value>);
    fn approve(&mut self, name: &str, arguments: &Map<String, Value>) -> Result<bool>;
    fn tool_finished(&mut self, name: &str, result: &Value, failed: bool);
}

pub struct AgentSession<P> {
    provider: P,
    instructions: String,
    history: Vec<Value>,
    max_tool_calls: usize,
}

impl<P: ModelProvider> AgentSession<P> {
    pub fn new(provider: P, max_tool_calls: usize) -> Result<Self> {
        if max_tool_calls == 0 {
            bail!("max_tool_calls must be greater than zero");
        }
        Ok(Self {
            provider,
            instructions: DEFAULT_INSTRUCTIONS.to_owned(),
            history: Vec::new(),
            max_tool_calls,
        })
    }

    pub fn clear(&mut self) {
        self.history.clear();
    }

    pub async fn run_turn(
        &mut self,
        workspace: &mut WorkspaceClient,
        prompt: impl Into<String>,
        ui: &mut impl AgentUi,
    ) -> Result<String> {
        let prompt = prompt.into();
        if prompt.trim().is_empty() {
            bail!("prompt must not be empty");
        }
        self.history
            .push(json!({"role": "user", "content": prompt}));
        let tools = sshai_tools::function_definitions();
        let mut calls_used = 0_usize;

        loop {
            let response = self
                .provider
                .create_response(&self.instructions, &self.history, &tools)
                .await?;
            validate_response(&response)?;
            let output = response
                .get("output")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("model response is missing output"))?
                .clone();
            let calls = function_calls(&output)?;
            self.history.extend(output.clone());

            if calls.is_empty() {
                let text = output_text(&output);
                if text.is_empty() {
                    bail!("model completed without text or a tool call");
                }
                return Ok(text);
            }

            calls_used = calls_used.saturating_add(calls.len());
            if calls_used > self.max_tool_calls {
                bail!(
                    "model exceeded the per-turn limit of {} tool calls",
                    self.max_tool_calls
                );
            }

            for call in calls {
                ui.tool_started(&call.name, &call.arguments);
                let requires_approval = sshai_tools::requires_approval(&call.name);
                let approved = !requires_approval || ui.approve(&call.name, &call.arguments)?;
                let (result, failed) = if approved {
                    match sshai_tools::dispatch(workspace, &call.name, &call.arguments).await {
                        Ok(value) => (value, false),
                        Err(error) => (json!({"error": format!("{error:#}")}), true),
                    }
                } else {
                    (json!({"error": "user denied this tool call"}), true)
                };
                ui.tool_finished(&call.name, &result, failed);
                self.history.push(json!({
                    "type": "function_call_output",
                    "call_id": call.call_id,
                    "output": serde_json::to_string(&result)?,
                }));
            }
        }
    }
}

struct FunctionCall {
    call_id: String,
    name: String,
    arguments: Map<String, Value>,
}

fn function_calls(output: &[Value]) -> Result<Vec<FunctionCall>> {
    output
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("function_call"))
        .map(|item| {
            let call_id = required_string(item, "call_id")?.to_owned();
            let name = required_string(item, "name")?.to_owned();
            let raw = item
                .get("arguments")
                .ok_or_else(|| anyhow!("function call {name:?} is missing arguments"))?;
            let arguments = match raw {
                Value::String(encoded) => {
                    serde_json::from_str::<Value>(encoded).with_context(|| {
                        format!("function call {name:?} has invalid JSON arguments")
                    })?
                }
                value => value.clone(),
            };
            let arguments = arguments
                .as_object()
                .cloned()
                .ok_or_else(|| anyhow!("function call {name:?} arguments must be an object"))?;
            Ok(FunctionCall {
                call_id,
                name,
                arguments,
            })
        })
        .collect()
}

fn output_text(output: &[Value]) -> String {
    output
        .iter()
        .filter_map(|item| item.get("content").and_then(Value::as_array))
        .flatten()
        .filter_map(
            |content| match content.get("type").and_then(Value::as_str) {
                Some("output_text" | "text") => content.get("text").and_then(Value::as_str),
                Some("refusal") => content.get("refusal").and_then(Value::as_str),
                _ => None,
            },
        )
        .collect::<Vec<_>>()
        .join("\n")
}

fn validate_response(response: &Value) -> Result<()> {
    if let Some(error) = response.get("error").filter(|value| !value.is_null()) {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown model error");
        bail!("model returned an error: {message}");
    }
    if response.get("status").and_then(Value::as_str) == Some("incomplete") {
        bail!(
            "model response was incomplete: {}",
            response["incomplete_details"]
        );
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {key:?}"))
}

fn decode_api_response(status: StatusCode, bytes: impl AsRef<[u8]>) -> Result<Value> {
    let bytes = bytes.as_ref();
    if bytes.len() > MAX_API_RESPONSE {
        bail!("response exceeds {MAX_API_RESPONSE} bytes");
    }
    let value: Value = serde_json::from_slice(bytes).context("API returned invalid JSON")?;
    if !status.is_success() {
        let message = value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("request rejected");
        bail!("HTTP {status}: {message}");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn parses_string_and_object_function_arguments() {
        let output = vec![
            json!({"type":"function_call","call_id":"a","name":"workspace_read","arguments":"{\"path\":\"README.md\"}"}),
            json!({"type":"function_call","call_id":"b","name":"workspace_list","arguments":{"path":"."}}),
        ];
        let calls = function_calls(&output).unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].arguments["path"], "README.md");
        assert_eq!(calls[1].arguments["path"], ".");
    }

    #[test]
    fn combines_all_output_text_parts() {
        let output = vec![json!({
            "type":"message",
            "content":[
                {"type":"output_text","text":"first"},
                {"type":"output_text","text":"second"}
            ]
        })];
        assert_eq!(output_text(&output), "first\nsecond");
    }

    #[test]
    fn sanitizes_api_error_to_server_message() {
        let error = decode_api_response(
            StatusCode::UNAUTHORIZED,
            br#"{"error":{"message":"bad key","internal":"secret"}}"#,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "HTTP 401 Unauthorized: bad key");
    }

    #[test]
    fn rejects_insecure_non_loopback_endpoint() {
        let error = OpenAiProvider::new("key".to_owned(), "model", "http://example.com/v1")
            .err()
            .unwrap();
        assert!(error.to_string().contains("must use HTTPS"));
    }

    #[tokio::test]
    async fn provider_sends_a_responses_api_tool_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buffer[..read]);
                if let Some(position) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            while request.len() < header_end + content_length {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&buffer[..read]);
            }
            let body = br#"{"id":"response-1","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"done"}]}]}"#;
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            request
        });

        let provider = OpenAiProvider::new(
            "test-key".to_owned(),
            "test-model",
            &format!("http://{address}/v1"),
        )
        .unwrap();
        let response = provider
            .create_response(
                "instructions",
                &[json!({"role":"user","content":"hello"})],
                &sshai_tools::function_definitions(),
            )
            .await
            .unwrap();
        assert_eq!(response["id"], "response-1");

        let request = server.await.unwrap();
        let header_end = request
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap()
            + 4;
        let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
        assert!(headers.starts_with("post /v1/responses http/1.1"));
        assert!(headers.contains("authorization: bearer test-key"));
        let body: Value = serde_json::from_slice(&request[header_end..]).unwrap();
        assert_eq!(body["model"], "test-model");
        assert_eq!(body["store"], false);
        assert_eq!(body["tools"].as_array().unwrap().len(), 11);
    }
}
