use std::{
    collections::VecDeque,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};
use sshai_core::Target;
use sshai_ssh::{SftpClient, SshConnector, SshError, SshSession, WorkspaceClient};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{Mutex, RwLock, mpsc, oneshot},
    task::JoinSet,
    time::Instant,
};

const MAX_MCP_MESSAGE: usize = 1024 * 1024;
const MCP_FALLBACK_VERSION: &str = "2025-11-25";
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);
const TOOL_RECONNECT_WAIT: Duration = Duration::from_secs(45);
const RECONNECT_BASE: Duration = Duration::from_millis(250);
const RECONNECT_MAX: Duration = Duration::from_secs(30);

pub async fn serve(connector: SshConnector, target: Target, local_root: PathBuf) -> Result<()> {
    let status = Arc::new(RwLock::new(ConnectionStatus::new(target.to_string())));
    let (commands, command_rx) = mpsc::channel(128);
    let handle = RemoteHandle {
        commands,
        status: Arc::clone(&status),
    };
    let manager = tokio::spawn(connection_manager(
        connector, target, local_root, status, command_rx,
    ));
    let result = serve_inner(handle.clone()).await;
    handle.shutdown().await;
    let _ = manager.await;
    result
}

/// Serve MCP over an arbitrary bidirectional stream while opening workspace
/// channels on an already-authenticated SSH transport.
pub async fn serve_existing_session<S>(
    session: Arc<SshSession>,
    local_root: PathBuf,
    stream: S,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let status = Arc::new(RwLock::new(ConnectionStatus::existing(format!(
        "{}@{}:{}",
        session.target().user,
        session.target().host,
        session.target().port
    ))));
    let (commands, command_rx) = mpsc::channel(128);
    let handle = RemoteHandle {
        commands,
        status: Arc::clone(&status),
    };
    let manager = tokio::spawn(existing_session_manager(
        session, local_root, status, command_rx,
    ));
    let (input, output) = tokio::io::split(stream);
    let result = serve_io(handle.clone(), input, output).await;
    handle.shutdown().await;
    let _ = manager.await;
    result
}

struct RemoteConnection {
    session: Option<SshSession>,
    workspace: WorkspaceClient,
    sftp: SftpClient,
}

#[derive(Clone)]
struct RemoteHandle {
    commands: mpsc::Sender<ManagerCommand>,
    status: Arc<RwLock<ConnectionStatus>>,
}

struct PendingTool {
    name: String,
    arguments: Map<String, Value>,
    response: oneshot::Sender<Result<Value>>,
}

enum ManagerCommand {
    Tool(PendingTool),
    Shutdown,
}

#[derive(Clone)]
struct ConnectionStatus {
    target: String,
    transport: &'static str,
    reconnects_transport: bool,
    phase: &'static str,
    generation: u64,
    reconnect_attempt: u32,
    total_reconnects: u64,
    queue_depth: usize,
    connected_since_unix_ms: Option<u64>,
    outage_since_unix_ms: Option<u64>,
    last_heartbeat_unix_ms: Option<u64>,
    next_retry_unix_ms: Option<u64>,
    last_error: Option<String>,
}

impl ConnectionStatus {
    fn new(target: String) -> Self {
        Self {
            target,
            transport: "dedicated_ssh",
            reconnects_transport: true,
            phase: "connecting",
            generation: 0,
            reconnect_attempt: 0,
            total_reconnects: 0,
            queue_depth: 0,
            connected_since_unix_ms: None,
            outage_since_unix_ms: Some(now_unix_ms()),
            last_heartbeat_unix_ms: None,
            next_retry_unix_ms: Some(now_unix_ms()),
            last_error: None,
        }
    }

    fn existing(target: String) -> Self {
        Self {
            transport: "existing_session",
            reconnects_transport: false,
            ..Self::new(target)
        }
    }

    fn json(&self) -> Value {
        json!({
            "target": self.target,
            "transport": self.transport,
            "reconnects_transport": self.reconnects_transport,
            "phase": self.phase,
            "generation": self.generation,
            "reconnect_attempt": self.reconnect_attempt,
            "total_reconnects": self.total_reconnects,
            "queue_depth": self.queue_depth,
            "connected_since_unix_ms": self.connected_since_unix_ms,
            "outage_since_unix_ms": self.outage_since_unix_ms,
            "last_heartbeat_unix_ms": self.last_heartbeat_unix_ms,
            "next_retry_unix_ms": self.next_retry_unix_ms,
            "last_error": self.last_error,
            "heartbeat_interval_seconds": HEARTBEAT_INTERVAL.as_secs(),
            "max_reconnect_delay_seconds": RECONNECT_MAX.as_secs(),
        })
    }
}

impl RemoteHandle {
    async fn execute(&self, name: String, arguments: Map<String, Value>) -> Result<Value> {
        let (response, receive) = oneshot::channel();
        self.commands
            .send(ManagerCommand::Tool(PendingTool {
                name,
                arguments,
                response,
            }))
            .await
            .map_err(|_| anyhow!("SSH connection manager stopped"))?;
        match tokio::time::timeout(TOOL_RECONNECT_WAIT, receive).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => bail!("SSH connection manager stopped before returning the tool result"),
            Err(_) => bail!(
                "remote is still reconnecting in the background after {} seconds; call workspace_connection_info for status and retry later",
                TOOL_RECONNECT_WAIT.as_secs()
            ),
        }
    }

    async fn status(&self) -> Value {
        self.status.read().await.json()
    }

    async fn shutdown(&self) {
        let _ = self.commands.send(ManagerCommand::Shutdown).await;
    }
}

async fn connection_manager(
    connector: SshConnector,
    target: Target,
    local_root: PathBuf,
    status: Arc<RwLock<ConnectionStatus>>,
    mut commands: mpsc::Receiver<ManagerCommand>,
) {
    let mut connection = None;
    let mut pending = VecDeque::<PendingTool>::new();
    let mut reconnect_attempt = 0_u32;
    let mut next_retry = Instant::now();
    let mut last_connect_attempt = Instant::now() - Duration::from_secs(1);
    let mut heartbeat_at = Instant::now() + HEARTBEAT_INTERVAL;
    let mut jitter = jitter_seed();

    loop {
        while pending
            .front()
            .is_some_and(|tool| tool.response.is_closed())
        {
            pending.pop_front();
        }
        update_queue_depth(&status, pending.len()).await;

        if connection.is_some() && !pending.is_empty() {
            let tool = pending.pop_front().expect("pending tool was checked");
            let remote = connection.as_mut().expect("connection was checked");
            update_queue_depth(&status, pending.len()).await;
            let result = call_tool_once(remote, &local_root, &tool.name, &tool.arguments).await;
            match result {
                Ok(value) => {
                    let _ = tool.response.send(Ok(value));
                    heartbeat_at = Instant::now() + HEARTBEAT_INTERVAL;
                }
                Err(error) if is_connection_lost(&error) => {
                    mark_disconnected(&status, &error).await;
                    connection.take();
                    next_retry = Instant::now();
                    reconnect_attempt = 0;
                    if safe_to_retry(&tool.name) {
                        pending.push_front(tool);
                    } else {
                        let _ = tool.response.send(Err(anyhow!(
                            "SSH connection was lost during {}, so completion is uncertain. sshai is reconnecting in the background and did not repeat the operation; inspect remote state before retrying",
                            tool.name
                        )));
                    }
                }
                Err(error) => {
                    let _ = tool.response.send(Err(error));
                }
            }
            continue;
        }

        if let Some(remote) = connection.as_mut() {
            tokio::select! {
                command = commands.recv() => {
                    match command {
                        Some(ManagerCommand::Tool(tool)) => pending.push_back(tool),
                        Some(ManagerCommand::Shutdown) | None => break,
                    }
                }
                _ = tokio::time::sleep_until(heartbeat_at) => {
                    let heartbeat = tokio::time::timeout(HEARTBEAT_TIMEOUT, remote.workspace.open()).await;
                    match heartbeat {
                        Ok(Ok(_)) => {
                            let mut current = status.write().await;
                            current.last_heartbeat_unix_ms = Some(now_unix_ms());
                            current.last_error = None;
                            heartbeat_at = Instant::now() + HEARTBEAT_INTERVAL;
                        }
                        Ok(Err(error)) if !error.is_connection_lost() => {
                            let mut current = status.write().await;
                            current.last_heartbeat_unix_ms = Some(now_unix_ms());
                            current.last_error = Some(format!("heartbeat operation failed: {error}"));
                            heartbeat_at = Instant::now() + HEARTBEAT_INTERVAL;
                        }
                        Ok(Err(error)) => {
                            mark_disconnected(&status, &anyhow::Error::new(error)).await;
                            connection.take();
                            reconnect_attempt = 0;
                            next_retry = Instant::now();
                        }
                        Err(_) => {
                            mark_disconnected_message(&status, "heartbeat timed out").await;
                            connection.take();
                            reconnect_attempt = 0;
                            next_retry = Instant::now();
                        }
                    }
                }
            }
            continue;
        }

        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(ManagerCommand::Tool(tool)) => {
                        pending.push_back(tool);
                        if last_connect_attempt.elapsed() >= Duration::from_secs(1) {
                            next_retry = Instant::now();
                        }
                    }
                    Some(ManagerCommand::Shutdown) | None => break,
                }
            }
            _ = tokio::time::sleep_until(next_retry) => {
                last_connect_attempt = Instant::now();
                mark_connecting(&status, reconnect_attempt.saturating_add(1)).await;
                match connect_once(&connector, &target).await {
                    Ok(remote) => {
                        connection = Some(remote);
                        reconnect_attempt = 0;
                        heartbeat_at = Instant::now() + HEARTBEAT_INTERVAL;
                        mark_connected(&status).await;
                    }
                    Err(error) => {
                        reconnect_attempt = reconnect_attempt.saturating_add(1);
                        let delay = reconnect_delay(reconnect_attempt, &mut jitter);
                        next_retry = Instant::now() + delay;
                        mark_retry_wait(&status, reconnect_attempt, delay, &error).await;
                        tracing::debug!(
                            %target,
                            reconnect_attempt,
                            retry_seconds = delay.as_secs_f64(),
                            error = %format_args!("{error:#}"),
                            "MCP SSH reconnect attempt failed"
                        );
                    }
                }
            }
        }
    }

    if let Some(remote) = connection.take() {
        close_connection(remote).await;
    }
    for tool in pending {
        let _ = tool
            .response
            .send(Err(anyhow!("SSH connection manager stopped")));
    }
}

async fn existing_session_manager(
    session: Arc<SshSession>,
    local_root: PathBuf,
    status: Arc<RwLock<ConnectionStatus>>,
    mut commands: mpsc::Receiver<ManagerCommand>,
) {
    let mut connection = match open_existing_connection(&session).await {
        Ok(connection) => {
            mark_connected(&status).await;
            Some(connection)
        }
        Err(error) => {
            mark_disconnected(&status, &error).await;
            None
        }
    };

    while let Some(command) = commands.recv().await {
        match command {
            ManagerCommand::Shutdown => break,
            ManagerCommand::Tool(tool) => {
                if connection.is_none() {
                    match open_existing_connection(&session).await {
                        Ok(opened) => {
                            mark_connected(&status).await;
                            connection = Some(opened);
                        }
                        Err(error) => {
                            mark_disconnected(&status, &error).await;
                            let _ = tool.response.send(Err(anyhow!(
                                "the existing SSH session is unavailable: {error:#}"
                            )));
                            continue;
                        }
                    }
                }

                let result = call_tool_once(
                    connection.as_mut().expect("connection was opened"),
                    &local_root,
                    &tool.name,
                    &tool.arguments,
                )
                .await;
                if result.as_ref().is_err_and(is_connection_lost) {
                    if let Some(remote) = connection.take() {
                        close_connection(remote).await;
                    }
                    if let Err(error) = &result {
                        mark_disconnected(&status, error).await;
                    }
                }
                let _ = tool.response.send(result);
            }
        }
    }

    if let Some(remote) = connection.take() {
        close_connection(remote).await;
    }
}

async fn open_existing_connection(session: &SshSession) -> Result<RemoteConnection> {
    let mut workspace = session.workspace().await?;
    match session.sftp().await {
        Ok(sftp) => Ok(RemoteConnection {
            session: None,
            workspace,
            sftp,
        }),
        Err(error) => {
            let _ = workspace.close().await;
            Err(error.into())
        }
    }
}

async fn connect_once(connector: &SshConnector, target: &Target) -> Result<RemoteConnection> {
    let session = connector.connect(target).await?;
    let workspace = session.workspace().await?;
    let sftp = session.sftp().await?;
    Ok(RemoteConnection {
        session: Some(session),
        workspace,
        sftp,
    })
}

async fn close_connection(mut connection: RemoteConnection) {
    let _ = connection.workspace.close().await;
    let _ = connection.sftp.close().await;
    if let Some(session) = connection.session {
        let _ = session.disconnect().await;
    }
}

async fn update_queue_depth(status: &RwLock<ConnectionStatus>, depth: usize) {
    status.write().await.queue_depth = depth;
}

async fn mark_connecting(status: &RwLock<ConnectionStatus>, attempt: u32) {
    let mut current = status.write().await;
    current.phase = if current.generation == 0 {
        "connecting"
    } else {
        "reconnecting"
    };
    current.reconnect_attempt = attempt;
    current.next_retry_unix_ms = None;
}

async fn mark_connected(status: &RwLock<ConnectionStatus>) {
    let mut current = status.write().await;
    if current.generation > 0 {
        current.total_reconnects = current.total_reconnects.saturating_add(1);
    }
    current.generation = current.generation.saturating_add(1);
    current.phase = "connected";
    current.reconnect_attempt = 0;
    current.connected_since_unix_ms = Some(now_unix_ms());
    current.outage_since_unix_ms = None;
    current.last_heartbeat_unix_ms = Some(now_unix_ms());
    current.next_retry_unix_ms = None;
    current.last_error = None;
    tracing::debug!(
        target = %current.target,
        generation = current.generation,
        "MCP SSH connection established"
    );
}

async fn mark_disconnected(status: &RwLock<ConnectionStatus>, error: &anyhow::Error) {
    mark_disconnected_message(status, &format!("{error:#}")).await;
}

async fn mark_disconnected_message(status: &RwLock<ConnectionStatus>, message: &str) {
    let mut current = status.write().await;
    current.phase = "reconnecting";
    current.connected_since_unix_ms = None;
    current.outage_since_unix_ms.get_or_insert_with(now_unix_ms);
    current.next_retry_unix_ms = Some(now_unix_ms());
    current.last_error = Some(message.to_owned());
}

async fn mark_retry_wait(
    status: &RwLock<ConnectionStatus>,
    attempt: u32,
    delay: Duration,
    error: &anyhow::Error,
) {
    let mut current = status.write().await;
    current.phase = if current.generation == 0 {
        "connecting"
    } else {
        "reconnecting"
    };
    current.reconnect_attempt = attempt;
    current.outage_since_unix_ms.get_or_insert_with(now_unix_ms);
    current.next_retry_unix_ms =
        Some(now_unix_ms().saturating_add(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX)));
    current.last_error = Some(format!("{error:#}"));
}

fn reconnect_delay(attempt: u32, jitter: &mut u64) -> Duration {
    let exponent = attempt.saturating_sub(1).min(16);
    let multiplier = 1_u64 << exponent;
    let base_ms = u64::try_from(RECONNECT_BASE.as_millis())
        .unwrap_or(u64::MAX)
        .saturating_mul(multiplier);
    *jitter ^= *jitter << 13;
    *jitter ^= *jitter >> 7;
    *jitter ^= *jitter << 17;
    let percent = 75_u64 + (*jitter % 51);
    let jittered_ms = base_ms.saturating_mul(percent) / 100;
    Duration::from_millis(
        jittered_ms.min(u64::try_from(RECONNECT_MAX.as_millis()).unwrap_or(u64::MAX)),
    )
}

fn jitter_seed() -> u64 {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    seed ^ u64::from(std::process::id()) ^ 0x9e37_79b9_7f4a_7c15
}

fn now_unix_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

async fn serve_inner(remote: RemoteHandle) -> Result<()> {
    serve_io(remote, tokio::io::stdin(), tokio::io::stdout()).await
}

async fn serve_io<R, W>(remote: RemoteHandle, input: R, output: W) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut input = BufReader::new(input);
    let output = Arc::new(Mutex::new(output));
    let mut requests = JoinSet::new();
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        let read = input.read_until(b'\n', &mut buffer).await?;
        if read == 0 {
            break;
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
                write_message_locked(
                    &output,
                    &error_response(Value::Null, -32700, format!("parse error: {error}")),
                )
                .await?;
                continue;
            }
        };
        let Some(id) = message.get("id").cloned() else {
            continue;
        };
        let remote = remote.clone();
        let output = Arc::clone(&output);
        requests.spawn(async move {
            let response = match handle_request(&remote, &message).await {
                Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
                Err(error) => error_response(id, -32602, format!("{error:#}")),
            };
            write_message_locked(&output, &response).await
        });
        while let Some(result) = requests.try_join_next() {
            result.map_err(|error| anyhow!("MCP request task failed: {error}"))??;
        }
    }
    while let Some(result) = requests.join_next().await {
        result.map_err(|error| anyhow!("MCP request task failed: {error}"))??;
    }
    Ok(())
}

async fn handle_request(remote: &RemoteHandle, message: &Value) -> Result<Value> {
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
            let status = remote.status().await;
            let transport = status
                .get("transport")
                .and_then(Value::as_str)
                .unwrap_or("dedicated_ssh");
            let transport_instructions = if transport == "existing_session" {
                "This MCP server opens workspace and SFTP channels on the already-authenticated parent sshai session; it does not perform a second SSH login. If that parent transport closes, start a new sshai shell session."
            } else {
                "sshai proactively heartbeats REMOTE and reconnects forever with jittered exponential backoff. Calls arriving during reconnect wait in one ordered queue. Read-only workspace calls interrupted by transport loss are safely replayed; writes, execution, and transfers with uncertain completion are never repeated automatically. workspace_connection_info remains available while REMOTE is offline."
            };
            Ok(json!({
                "protocolVersion": protocol,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "sshai", "version": env!("CARGO_PKG_VERSION")},
                "instructions": format!("This is the REMOTE side of an sshai dual-workspace session. Native file and shell tools operate on LOCAL; workspace_* tools operate on REMOTE. Ordinary workspace paths are relative to the negotiated remote root. Use workspace_transfer for direct non-overwriting LOCAL/REMOTE copies; its remote_path may also be absolute. Only use workspace_transfer_overwrite after the user explicitly requests replacement. A remote cp command cannot read LOCAL files. {transport_instructions}")
            }))
        }
        "server/discover" => Ok(json!({
            "serverInfo": {"name": "sshai", "version": env!("CARGO_PKG_VERSION")},
            "capabilities": {"tools": {}},
        })),
        "ping" => Ok(json!({})),
        "tools/list" => {
            let mut tools = sshai_tools::definitions();
            tools.push(connection_status_definition());
            tools.push(transfer_definition(false));
            tools.push(transfer_definition(true));
            Ok(json!({"tools": tools}))
        }
        "tools/call" => call_tool(remote, &params).await,
        _ => bail!("method not found: {method}"),
    }
}

async fn call_tool(remote: &RemoteHandle, params: &Value) -> Result<Value> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field \"name\""))?;
    let arguments = params
        .get("arguments")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let result = if name == "workspace_connection_info" {
        Ok(remote.status().await)
    } else {
        remote.execute(name.to_owned(), arguments).await
    };
    Ok(match result {
        Ok(value) => tool_result(value, false),
        Err(error) => tool_result(json!({"error": format!("{error:#}")}), true),
    })
}

async fn call_tool_once(
    connection: &mut RemoteConnection,
    local_root: &Path,
    name: &str,
    arguments: &Map<String, Value>,
) -> Result<Value> {
    match name {
        "workspace_transfer" => transfer(&connection.sftp, local_root, arguments, false).await,
        "workspace_transfer_overwrite" => {
            transfer(&connection.sftp, local_root, arguments, true).await
        }
        _ => sshai_tools::dispatch(&mut connection.workspace, name, arguments).await,
    }
}

fn safe_to_retry(name: &str) -> bool {
    matches!(
        name,
        "workspace_info"
            | "workspace_list"
            | "workspace_stat"
            | "workspace_read"
            | "workspace_hash"
    )
}

fn is_connection_lost(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<SshError>()
            .is_some_and(SshError::is_connection_lost)
    })
}

fn connection_status_definition() -> Value {
    json!({
        "name": "workspace_connection_info",
        "description": "Report sshai's live SSH connection state, reconnect generation, queued calls, heartbeat, retry timing, and last transport error. This local status tool remains available while REMOTE is offline.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {
            "readOnlyHint": true,
            "destructiveHint": false,
            "openWorldHint": false
        }
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

async fn write_message_locked<W>(output: &Mutex<W>, message: &Value) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut encoded = serde_json::to_vec(message)?;
    encoded.push(b'\n');
    let mut output = output.lock().await;
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

    #[test]
    fn retries_only_side_effect_free_workspace_calls() {
        for name in [
            "workspace_info",
            "workspace_list",
            "workspace_stat",
            "workspace_read",
            "workspace_hash",
        ] {
            assert!(safe_to_retry(name), "{name}");
        }
        for name in [
            "workspace_write",
            "workspace_edit",
            "workspace_mkdir",
            "workspace_rename",
            "workspace_remove",
            "workspace_exec",
            "workspace_transfer",
            "workspace_transfer_overwrite",
        ] {
            assert!(!safe_to_retry(name), "{name}");
        }
    }

    #[test]
    fn recognizes_wrapped_transport_loss() {
        let error = anyhow::Error::new(SshError::Agent("channel closed".to_owned()))
            .context("workspace_info failed");
        assert!(is_connection_lost(&error));

        let error = anyhow::Error::new(SshError::Config("bad path".to_owned()));
        assert!(!is_connection_lost(&error));
    }

    #[test]
    fn reconnect_backoff_is_jittered_and_capped() {
        let mut jitter = 0x1234_5678_9abc_def0;
        let first = reconnect_delay(1, &mut jitter);
        assert!(first >= Duration::from_millis(187));
        assert!(first <= Duration::from_millis(312));

        for attempt in 2..40 {
            assert!(reconnect_delay(attempt, &mut jitter) <= RECONNECT_MAX);
        }
    }

    #[test]
    fn connection_status_tool_is_local_and_read_only() {
        let definition = connection_status_definition();
        assert_eq!(definition["name"], "workspace_connection_info");
        assert_eq!(definition["annotations"]["readOnlyHint"], true);

        let status = ConnectionStatus::new("host".to_owned()).json();
        assert_eq!(status["phase"], "connecting");
        assert_eq!(status["target"], "host");
        assert_eq!(status["queue_depth"], 0);

        let reused = ConnectionStatus::existing("host".to_owned()).json();
        assert_eq!(reused["transport"], "existing_session");
        assert_eq!(reused["reconnects_transport"], false);
    }

    #[tokio::test]
    async fn mcp_io_initializes_before_any_remote_tool_call() {
        let (commands, _command_rx) = mpsc::channel(1);
        let remote = RemoteHandle {
            commands,
            status: Arc::new(RwLock::new(ConnectionStatus::existing("host".to_owned()))),
        };
        let (client, server) = tokio::io::duplex(16 * 1024);
        let (client_read, mut client_write) = tokio::io::split(client);
        let task = tokio::spawn(async move {
            let (server_read, server_write) = tokio::io::split(server);
            serve_io(remote, server_read, server_write).await
        });

        client_write
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n")
            .await
            .unwrap();
        let mut response = String::new();
        BufReader::new(client_read)
            .read_line(&mut response)
            .await
            .unwrap();
        let response: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["serverInfo"]["name"], "sshai");
        assert!(
            response["result"]["instructions"]
                .as_str()
                .unwrap()
                .contains("does not perform a second SSH login")
        );

        drop(client_write);
        task.await.unwrap().unwrap();
    }
}
