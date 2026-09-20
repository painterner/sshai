use std::{
    env,
    future::Future,
    io::{IsTerminal, Read},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use russh::{ChannelMsg, Disconnect, Sig, client};
use sha2::{Digest, Sha256};
use sshai_core::Target;
use sshai_protocol::{ControlRequest, ControlResponse};
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    sync::{mpsc, oneshot},
};

#[cfg(not(unix))]
use tokio::io::AsyncReadExt;

use crate::{
    HostKeyPolicy, KeyInstallResult, ResolvedTarget, Result, SshConfig, SshError,
    agent::RemoteAgent, auth::authenticate, discover_public_identities, host_key::ClientHandler,
    sftp::SftpClient, workspace::WorkspaceClient,
};

#[derive(Clone, Debug, Default)]
pub struct ConnectOptions {
    pub config_file: Option<std::path::PathBuf>,
    pub host_key_policy: Option<HostKeyPolicy>,
    pub allow_password: bool,
    /// Override the local companion binary uploaded for remote agent sessions.
    pub worker_executable: Option<PathBuf>,
}

#[derive(Debug)]
pub struct CommandExit {
    pub code: Option<u32>,
    pub signal: Option<String>,
}

#[derive(Debug)]
pub struct SessionCommandResult {
    pub exit_code: u8,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug)]
pub struct SessionInputResult {
    pub forward: Vec<u8>,
    pub notice: Option<String>,
}

#[async_trait::async_trait]
pub trait SessionCommandHandler: Send {
    fn handles(&self, command: &str) -> bool;

    /// Update the local workspace used by local-side session commands. The
    /// multiplexer calls this when the local pane's shell changes directory.
    fn update_local_root(&mut self, _root: Option<PathBuf>) {}

    async fn handle_input(&mut self, input: Vec<u8>) -> SessionInputResult {
        SessionInputResult {
            forward: input,
            notice: None,
        }
    }

    async fn handle(
        &mut self,
        command: &str,
        arguments: &[String],
        session_index: usize,
        remote_cwd: Option<&str>,
        sessions: Vec<Option<Arc<SshSession>>>,
    ) -> SessionCommandResult;
}

struct CapturedCommand {
    code: Option<u32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct AgentBootstrap {
    started: Instant,
    remote_platform: RemotePlatform,
    remote_description: String,
    local_executable: PathBuf,
    digest: String,
    session_id: String,
    sftp: SftpClient,
    remote_bin_dir: String,
    remote_executable: String,
    remote_sessions_dir: String,
    remote_session_dir: String,
    remote_workspace_root: String,
    shell_launcher: String,
}

struct ProgressiveCleanup {
    remote_session_dir: String,
    remote_executable: String,
    session_id: String,
}

struct ProgressiveShellState {
    shell_launcher: String,
    cleanup: ProgressiveCleanup,
    initial_display: Vec<u8>,
}

const TERMINAL_SCROLLBACK_ROWS: usize = 10_000;
const MULTIPLEX_SWITCH_HINT: &str =
    "\x1b[1;36m[sshai] Shift+Left/Right switches hosts · Ctrl+Left local\x1b[0m\r\n";
const SWITCH_SEQUENCE_TIMEOUT: Duration = Duration::from_millis(30);
const SWITCH_PREFIX_TIMEOUT: Duration = Duration::from_secs(3);
const SWITCH_PREVIOUS: &[u8] = b"\x1b[1;6D";
const SWITCH_NEXT: &[u8] = b"\x1b[1;6C";
const SWITCH_PREVIOUS_SHIFT_LEFT: &[u8] = b"\x1b[1;2D";
const SWITCH_NEXT_SHIFT_RIGHT: &[u8] = b"\x1b[1;2C";
// Ctrl+Left always selects the local pane. Ctrl+Right returns to the next
// remote pane when the local pane is active, and otherwise advances hosts.
const SWITCH_LOCAL_CTRL_LEFT: &[u8] = b"\x1b[1;5D";
const SWITCH_NEXT_CTRL_RIGHT: &[u8] = b"\x1b[1;5C";
const SWITCH_PREFIX: u8 = 0x1d; // Ctrl+]
const LOCAL_PANE_LABEL: &str = "local";
const PASSTHROUGH_TOGGLE: u8 = 0x1c; // Ctrl+\\

enum MultiplexCommand {
    Input(Vec<u8>),
    Eof,
    Resize(u32, u32),
    ControlResponse(ControlResponse),
    Shutdown,
}

enum MultiplexEvent {
    Ready {
        index: usize,
        shell: Box<MultiplexedShell>,
    },
    Failed {
        index: usize,
        error: String,
    },
    Output {
        index: usize,
        data: Vec<u8>,
    },
    LocalOutput {
        data: Vec<u8>,
    },
    ControlRequest {
        index: usize,
        request: ControlRequest,
    },
    WorkerNotice {
        index: usize,
        message: String,
    },
    Exited {
        index: usize,
        code: Option<u32>,
        signal: Option<String>,
    },
    LocalExited {
        code: Option<u32>,
    },
}

struct MultiplexedShell {
    label: String,
    workspace_root: String,
    system_description: String,
    session: Arc<SshSession>,
    commands: mpsc::Sender<MultiplexCommand>,
    start: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
    terminal: VirtualTerminal,
    open: bool,
}

struct LocalShell {
    pid: u32,
    commands: mpsc::Sender<MultiplexCommand>,
    task: Option<tokio::task::JoinHandle<()>>,
    terminal: VirtualTerminal,
    open: bool,
}

struct LocalConnectionSummary {
    workspace_root: String,
    system_description: String,
}

struct VirtualTerminal {
    parser: vt100::Parser,
}

impl VirtualTerminal {
    fn new(columns: u32, rows: u32) -> Self {
        Self {
            parser: vt100::Parser::new(
                terminal_dimension(rows),
                terminal_dimension(columns),
                TERMINAL_SCROLLBACK_ROWS,
            ),
        }
    }

    fn process(&mut self, data: &[u8]) {
        self.parser.process(data);
    }

    fn resize(&mut self, columns: u32, rows: u32) {
        self.parser
            .screen_mut()
            .set_size(terminal_dimension(rows), terminal_dimension(columns));
    }

    fn snapshot(&self) -> Vec<u8> {
        self.parser.screen().contents_formatted()
    }
}

fn terminal_dimension(value: u32) -> u16 {
    value.clamp(1, u32::from(u16::MAX)) as u16
}

fn system_description(name: &str, arch: &str, memory_bytes: u64) -> String {
    let mut parts = vec![name.trim().to_owned(), arch.trim().to_owned()];
    if memory_bytes > 0 {
        let gib = memory_bytes as f64 / (1024_f64 * 1024_f64 * 1024_f64);
        let memory = if gib >= 0.75 {
            format!("{gib:.0} GiB")
        } else {
            format!("{} MiB", memory_bytes.div_ceil(1024 * 1024))
        };
        parts.push(memory);
    }
    parts
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

fn local_connection_summary() -> LocalConnectionSummary {
    let workspace_root = env::current_dir()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "?".to_owned());
    LocalConnectionSummary {
        workspace_root,
        system_description: system_description(
            &local_os_name(),
            std::env::consts::ARCH,
            local_memory_bytes(),
        ),
    }
}

fn local_os_name() -> String {
    #[cfg(target_os = "linux")]
    if let Ok(contents) = std::fs::read_to_string("/etc/os-release")
        && let Some(value) = contents.lines().find_map(|line| {
            line.strip_prefix("PRETTY_NAME=")
                .map(|value| value.trim_matches('"').to_owned())
        })
    {
        return value;
    }
    std::env::consts::OS.to_owned()
}

fn local_memory_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    if let Ok(contents) = std::fs::read_to_string("/proc/meminfo")
        && let Some(kibibytes) = contents.lines().find_map(|line| {
            line.strip_prefix("MemTotal:")
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
        })
    {
        return kibibytes.saturating_mul(1024);
    }
    0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InputAction {
    Previous,
    Next,
    Local,
}

/// Switchable panes, ordered with the local shell first so that it matches the
/// numbering of `sshai hosts` and stays reachable from a single-host session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Pane {
    Local,
    Remote(usize),
}

impl Pane {
    fn position(self) -> usize {
        match self {
            Self::Local => 0,
            Self::Remote(index) => index + 1,
        }
    }

    fn at(position: usize) -> Self {
        match position {
            0 => Self::Local,
            position => Self::Remote(position - 1),
        }
    }
}

const PREFIX_SWITCH_PREVIOUS: &[&[u8]] = &[b"\x1dh", b"\x1d[", b"\x1d\x1b[D", b"\x1d\x1bOD"];
const PREFIX_SWITCH_NEXT: &[&[u8]] = &[b"\x1dl", b"\x1d]", b"\x1d\x1b[C", b"\x1d\x1bOC"];
const LITERAL_SWITCH_PREFIX: &[u8] = b"\x1d\x1d";

enum ParsedInput {
    Data(Vec<u8>),
    Switch(InputAction),
    TogglePassthrough,
}

#[derive(Default)]
struct SwitchInputParser {
    pending: Vec<u8>,
}

impl SwitchInputParser {
    fn feed(&mut self, input: &[u8], multiplex: bool) -> Vec<ParsedInput> {
        let mut bytes = std::mem::take(&mut self.pending);
        bytes.extend_from_slice(input);
        let mut parsed = Vec::new();
        let mut data = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            let remaining = &bytes[index..];
            if remaining[0] == PASSTHROUGH_TOGGLE {
                if !data.is_empty() {
                    parsed.push(ParsedInput::Data(std::mem::take(&mut data)));
                }
                parsed.push(ParsedInput::TogglePassthrough);
                index += 1;
                continue;
            }
            if !multiplex {
                data.push(bytes[index]);
                index += 1;
                continue;
            }
            if let Some((length, switch)) = matched_switch(remaining) {
                if !data.is_empty() {
                    parsed.push(ParsedInput::Data(std::mem::take(&mut data)));
                }
                parsed.push(switch);
                index += length;
                continue;
            }
            if remaining.starts_with(LITERAL_SWITCH_PREFIX) {
                data.push(SWITCH_PREFIX);
                index += LITERAL_SWITCH_PREFIX.len();
                continue;
            }
            if switch_sequence_starts_with(remaining) {
                self.pending.extend_from_slice(remaining);
                break;
            }
            data.push(bytes[index]);
            index += 1;
        }
        if !data.is_empty() {
            parsed.push(ParsedInput::Data(data));
        }
        parsed
    }

    fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    fn pending_timeout(&self) -> Duration {
        if self.pending.first() == Some(&SWITCH_PREFIX) {
            SWITCH_PREFIX_TIMEOUT
        } else {
            SWITCH_SEQUENCE_TIMEOUT
        }
    }

    fn flush(&mut self) -> Option<Vec<u8>> {
        (!self.pending.is_empty()).then(|| std::mem::take(&mut self.pending))
    }
}

fn matched_switch(remaining: &[u8]) -> Option<(usize, ParsedInput)> {
    // Ctrl+Left selects the local pane; Ctrl+Right advances to the next remote.
    const SINGLE_CHORDS: &[(&[u8], InputAction)] = &[
        (SWITCH_PREVIOUS, InputAction::Previous),
        (SWITCH_NEXT, InputAction::Next),
        (SWITCH_NEXT_CTRL_RIGHT, InputAction::Next),
        (SWITCH_PREVIOUS_SHIFT_LEFT, InputAction::Previous),
        (SWITCH_NEXT_SHIFT_RIGHT, InputAction::Next),
    ];
    SINGLE_CHORDS
        .iter()
        .find(|(sequence, _)| remaining.starts_with(sequence))
        .map(|(sequence, action)| (sequence.len(), ParsedInput::Switch(*action)))
        .or_else(|| {
            PREFIX_SWITCH_PREVIOUS
                .iter()
                .find(|sequence| remaining.starts_with(sequence))
                .map(|sequence| (sequence.len(), ParsedInput::Switch(InputAction::Previous)))
        })
        .or_else(|| {
            PREFIX_SWITCH_NEXT
                .iter()
                .find(|sequence| remaining.starts_with(sequence))
                .map(|sequence| (sequence.len(), ParsedInput::Switch(InputAction::Next)))
        })
        .or_else(|| {
            remaining.starts_with(SWITCH_LOCAL_CTRL_LEFT).then_some((
                SWITCH_LOCAL_CTRL_LEFT.len(),
                ParsedInput::Switch(InputAction::Local),
            ))
        })
}

fn switch_sequence_starts_with(bytes: &[u8]) -> bool {
    SWITCH_PREVIOUS.starts_with(bytes)
        || SWITCH_NEXT.starts_with(bytes)
        || SWITCH_NEXT_CTRL_RIGHT.starts_with(bytes)
        || SWITCH_LOCAL_CTRL_LEFT.starts_with(bytes)
        || SWITCH_PREVIOUS_SHIFT_LEFT.starts_with(bytes)
        || SWITCH_NEXT_SHIFT_RIGHT.starts_with(bytes)
        || LITERAL_SWITCH_PREFIX.starts_with(bytes)
        || PREFIX_SWITCH_PREVIOUS
            .iter()
            .chain(PREFIX_SWITCH_NEXT)
            .any(|sequence| sequence.starts_with(bytes))
}

type AgentStartup<'a> = Pin<Box<dyn Future<Output = Result<RemoteAgent>> + Send + 'a>>;

#[derive(Clone, Copy)]
enum RemotePlatform {
    Linux,
    Macos,
}

#[derive(Clone, Copy, Debug)]
enum WorkerCompression {
    Zstd,
    Gzip,
    Xz,
}

impl WorkerCompression {
    fn name(self) -> &'static str {
        match self {
            Self::Zstd => "zstd",
            Self::Gzip => "gzip",
            Self::Xz => "xz",
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Zstd => "zst",
            Self::Gzip => "gz",
            Self::Xz => "xz",
        }
    }

    fn compress_arguments(self) -> &'static [&'static str] {
        match self {
            Self::Zstd => &["-q", "-3", "-c"],
            Self::Gzip => &["-6", "-c"],
            Self::Xz => &["-3", "-c"],
        }
    }

    fn decompress_command(self) -> &'static str {
        match self {
            Self::Zstd => "zstd -q -d -c",
            Self::Gzip => "gzip -d -c",
            Self::Xz => "xz -d -c",
        }
    }
}

#[derive(Clone)]
pub struct SshConnector {
    config: SshConfig,
    options: ConnectOptions,
}

pub struct SshSession {
    target: Arc<ResolvedTarget>,
    session: client::Handle<ClientHandler>,
    // Parent sessions keep ProxyJump transports alive.
    _parents: Vec<client::Handle<ClientHandler>>,
    auth_method: String,
    connected_at: Instant,
    worker_executable: Option<PathBuf>,
}

impl SshConnector {
    pub fn new(options: ConnectOptions) -> Result<Self> {
        let config = match &options.config_file {
            Some(path) => SshConfig::load(path)?,
            None => SshConfig::load_default()?,
        };
        Ok(Self { config, options })
    }

    pub fn config(&self) -> &SshConfig {
        &self.config
    }

    pub fn resolve(&self, target: &Target) -> Result<ResolvedTarget> {
        let mut target = self.config.resolve(target)?;
        if let Some(policy) = self.options.host_key_policy {
            target.host_key_policy = policy;
        }
        Ok(target)
    }

    pub async fn connect(&self, target: &Target) -> Result<SshSession> {
        let connect_started = Instant::now();
        let final_target = self.resolve(target)?;
        let mut route = Vec::new();
        self.build_route(&final_target, &mut Vec::new(), &mut route)?;
        route.push(final_target.clone());

        tracing::debug!(
            target = %target,
            host = %final_target.host,
            port = final_target.port,
            user = %final_target.user,
            hops = route.len(),
            "SSH connection starting"
        );

        let mut sessions: Vec<client::Handle<ClientHandler>> = Vec::with_capacity(route.len());
        let mut auth_methods = Vec::with_capacity(route.len());
        for (hop_index, next) in route.into_iter().enumerate() {
            let hop_started = Instant::now();
            let next = Arc::new(next);
            let mut session = if let Some(parent) = sessions.last() {
                let proxy_started = Instant::now();
                tracing::debug!(
                    host = %next.host,
                    port = next.port,
                    hop = hop_index + 1,
                    "opening ProxyJump channel"
                );
                let channel = parent
                    .channel_open_direct_tcpip(
                        next.host.clone(),
                        u32::from(next.port),
                        "127.0.0.1",
                        0,
                    )
                    .await?;
                tracing::debug!(
                    host = %next.host,
                    port = next.port,
                    elapsed_ms = proxy_started.elapsed().as_millis() as u64,
                    "ProxyJump channel opened"
                );
                let handshake_started = Instant::now();
                let session = self
                    .connect_stream(next.clone(), channel.into_stream())
                    .await?;
                tracing::debug!(
                    host = %next.host,
                    port = next.port,
                    elapsed_ms = handshake_started.elapsed().as_millis() as u64,
                    "SSH protocol handshake completed"
                );
                session
            } else {
                let tcp_started = Instant::now();
                tracing::debug!(
                    host = %next.host,
                    port = next.port,
                    hop = hop_index + 1,
                    "opening TCP connection"
                );
                let stream = match tokio::time::timeout(
                    next.connect_timeout,
                    TcpStream::connect((next.host.as_str(), next.port)),
                )
                .await
                {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(source)) => {
                        return Err(SshError::Connect {
                            host: next.host.clone(),
                            port: next.port,
                            source,
                        });
                    }
                    Err(_) => {
                        return Err(SshError::ConnectTimeout {
                            host: next.host.clone(),
                            port: next.port,
                            seconds: next.connect_timeout.as_secs(),
                        });
                    }
                };
                tracing::debug!(
                    host = %next.host,
                    port = next.port,
                    elapsed_ms = tcp_started.elapsed().as_millis() as u64,
                    "TCP connection established"
                );
                stream.set_nodelay(true)?;
                let handshake_started = Instant::now();
                let session = self.connect_stream(next.clone(), stream).await?;
                tracing::debug!(
                    host = %next.host,
                    port = next.port,
                    elapsed_ms = handshake_started.elapsed().as_millis() as u64,
                    "SSH protocol handshake completed"
                );
                session
            };
            let auth_started = Instant::now();
            tracing::debug!(host = %next.host, user = %next.user, "SSH authentication starting");
            let auth_method =
                authenticate(&mut session, &next, self.options.allow_password).await?;
            tracing::debug!(
                host = %next.host,
                method = %auth_method,
                elapsed_ms = auth_started.elapsed().as_millis() as u64,
                hop_elapsed_ms = hop_started.elapsed().as_millis() as u64,
                "SSH authentication succeeded"
            );
            auth_methods.push(auth_method);
            sessions.push(session);
        }

        let session = sessions.pop().ok_or_else(|| {
            SshError::Config("internal error: connection route is empty".to_owned())
        })?;
        let auth_method = auth_methods.pop().unwrap_or_else(|| "unknown".to_owned());
        tracing::debug!(
            host = %final_target.host,
            elapsed_ms = connect_started.elapsed().as_millis() as u64,
            "SSH connection ready"
        );
        Ok(SshSession {
            target: Arc::new(final_target),
            session,
            _parents: sessions,
            auth_method,
            connected_at: Instant::now(),
            worker_executable: self.options.worker_executable.clone(),
        })
    }

    /// Run one persistent PTY per target, plus a local shell pane, while keeping
    /// the first target usable before background connections to the remaining
    /// targets complete. A single target is valid: it still gets the local pane.
    pub async fn interactive_shell_multiplexed(
        &self,
        primary: Arc<SshSession>,
        targets: Vec<Target>,
        handler: &mut dyn SessionCommandHandler,
    ) -> Result<CommandExit> {
        if targets.is_empty() {
            return Err(SshError::Config(
                "multiplexed SSH requires at least one target".to_owned(),
            ));
        }
        let mut background_connector = self.clone();
        // Once the primary shell owns the terminal, a background connection
        // must never consume password, key-passphrase, keyboard-interactive,
        // or host-key confirmation input.
        background_connector.options.allow_password = false;
        run_multiplexed_shells(primary, background_connector, targets, handler).await
    }

    fn build_route(
        &self,
        target: &ResolvedTarget,
        seen: &mut Vec<String>,
        output: &mut Vec<ResolvedTarget>,
    ) -> Result<()> {
        if seen.len() >= 8 {
            return Err(SshError::Config(
                "ProxyJump depth exceeds the limit of 8".to_owned(),
            ));
        }
        for jump in &target.proxy_jump {
            if seen.contains(&jump.host) {
                return Err(SshError::Config(format!(
                    "ProxyJump cycle detected at {}",
                    jump.host
                )));
            }
            seen.push(jump.host.clone());
            let mut resolved = self.resolve(jump)?;
            let nested = std::mem::take(&mut resolved.proxy_jump);
            if !nested.is_empty() {
                let nested_target = ResolvedTarget {
                    proxy_jump: nested,
                    ..resolved.clone()
                };
                self.build_route(&nested_target, seen, output)?;
            }
            output.push(resolved);
            seen.pop();
        }
        Ok(())
    }

    async fn connect_stream<S>(
        &self,
        target: Arc<ResolvedTarget>,
        stream: S,
    ) -> Result<client::Handle<ClientHandler>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let config = client::Config {
            keepalive_interval: target.keepalive_interval,
            keepalive_max: target.keepalive_max,
            nodelay: true,
            ..Default::default()
        };
        let handler = ClientHandler::new(target.clone(), self.options.allow_password);
        tokio::time::timeout(
            target.connect_timeout,
            client::connect_stream(Arc::new(config), stream, handler),
        )
        .await
        .map_err(|_| SshError::ConnectTimeout {
            host: target.host.clone(),
            port: target.port,
            seconds: target.connect_timeout.as_secs(),
        })?
    }
}

impl SshSession {
    pub fn target(&self) -> &ResolvedTarget {
        &self.target
    }

    pub fn auth_method(&self) -> &str {
        &self.auth_method
    }

    pub fn connected_for(&self) -> Duration {
        self.connected_at.elapsed()
    }

    pub async fn ping(&self) -> Result<Duration> {
        let started = Instant::now();
        tokio::time::timeout(Duration::from_secs(5), self.session.send_ping())
            .await
            .map_err(|_| SshError::ConnectTimeout {
                host: self.target.host.clone(),
                port: self.target.port,
                seconds: 5,
            })??;
        Ok(started.elapsed())
    }

    pub async fn sftp(&self) -> Result<SftpClient> {
        self.sftp_at_root(self.target.path.as_deref()).await
    }

    /// An SFTP client whose relative paths resolve under `root`; `None` leaves
    /// them to the server's default, so callers can pass absolute paths.
    pub(crate) async fn sftp_at_root(&self, root: Option<&str>) -> Result<SftpClient> {
        let channel = self.session.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let session = russh_sftp::client::SftpSession::new(channel.into_stream()).await?;
        session.set_timeout(self.target.connect_timeout.as_secs().max(60));
        let base = match root {
            Some("~") | None => None,
            Some(path) => Some(session.canonicalize(path).await?),
        };
        Ok(SftpClient::new(session, base))
    }

    pub async fn exec(&self, arguments: &[String]) -> Result<CommandExit> {
        if arguments.is_empty() {
            return Err(SshError::Config(
                "remote command cannot be empty".to_owned(),
            ));
        }
        let command = build_command(self.target.path.as_deref(), arguments);
        self.exec_command(&command).await
    }

    pub async fn exec_command(&self, command: &str) -> Result<CommandExit> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command.as_bytes()).await?;
        let mut stdout = tokio::io::stdout();
        let mut stderr = tokio::io::stderr();
        let mut code = None;
        let mut signal = None;

        'command: loop {
            tokio::select! {
                message = channel.wait() => {
                    let Some(message) = message else { break 'command };
                    match message {
                        ChannelMsg::Data { data } => {
                            stdout.write_all(&data).await?;
                            stdout.flush().await?;
                        }
                        ChannelMsg::ExtendedData { data, .. } => {
                            stderr.write_all(&data).await?;
                            stderr.flush().await?;
                        }
                        ChannelMsg::ExitStatus { exit_status } => {
                            code = Some(exit_status);
                            break 'command;
                        }
                        ChannelMsg::ExitSignal { signal_name, .. } => {
                            signal = Some(format!("{signal_name:?}"));
                            break 'command;
                        }
                        ChannelMsg::Close => break 'command,
                        _ => {}
                    }
                }
                result = tokio::signal::ctrl_c() => {
                    result?;
                    channel.signal(Sig::INT).await?;
                }
            }
        }

        if code.is_none() && signal.is_none() {
            return Err(SshError::MissingExitStatus);
        }
        Ok(CommandExit { code, signal })
    }

    async fn capture_command(&self, command: &str) -> Result<CapturedCommand> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command.as_bytes()).await?;
        let mut result = CapturedCommand {
            code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => result.stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => result.stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => result.code = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
            if result.stdout.len() + result.stderr.len() > 1024 * 1024 {
                return Err(SshError::Agent(
                    "remote bootstrap command produced more than 1 MiB".to_owned(),
                ));
            }
        }
        Ok(result)
    }

    async fn start_agent(&self) -> Result<RemoteAgent> {
        let bootstrap = self.prepare_agent(false).await?;
        self.finish_agent(bootstrap, false).await
    }

    async fn prepare_agent(&self, progressive: bool) -> Result<AgentBootstrap> {
        let agent_started = Instant::now();
        tracing::debug!(host = %self.target.host, "remote agent startup beginning");

        let phase_started = Instant::now();
        let (remote_platform, remote_description) = self.verify_agent_platform().await?;
        tracing::debug!(
            elapsed_ms = phase_started.elapsed().as_millis() as u64,
            "remote platform verified"
        );

        let local_executable = locate_worker_executable(self.worker_executable.as_deref())?;
        let phase_started = Instant::now();
        let digest = executable_digest(&local_executable).await?;
        tracing::debug!(
            path = %local_executable.display(),
            elapsed_ms = phase_started.elapsed().as_millis() as u64,
            "local worker executable hashed"
        );
        let session_id = random_session_id()?;

        let phase_started = Instant::now();
        let sftp = self.sftp().await?;
        let remote_home = sftp.remote_home().await?;
        tracing::debug!(
            elapsed_ms = phase_started.elapsed().as_millis() as u64,
            "SFTP bootstrap channel ready"
        );
        let bundle = format!(
            "{}-{}-{}-{}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH,
            &digest[..16]
        );
        let remote_bin_dir =
            join_remote_path(&remote_home, &format!(".cache/sshai/worker/{bundle}"));
        let remote_executable = join_remote_path(&remote_bin_dir, "sshai-worker");
        let remote_sessions_dir = join_remote_path(&remote_home, ".cache/sshai/s");
        let remote_session_dir = join_remote_path(
            &remote_home,
            &format!(".cache/sshai/s/{}", &session_id[..24]),
        );
        let remote_workspace_root = match self.target.path.as_deref() {
            None | Some("~") => remote_home,
            Some(path) if path.starts_with('/') => path.to_owned(),
            Some(path) => join_remote_path(&remote_home, path),
        };
        let shell_launcher = join_remote_path(&remote_session_dir, "launch-shell");

        if progressive {
            let phase_started = Instant::now();
            sftp.ensure_dir_all(remote_sessions_dir.clone(), 0o700)
                .await?;
            if let Err(error) = self
                .prepare_remote_session(&remote_session_dir, &remote_executable, &session_id)
                .await
            {
                let cleanup = ProgressiveCleanup {
                    remote_session_dir: remote_session_dir.clone(),
                    remote_executable: remote_executable.clone(),
                    session_id: session_id.clone(),
                };
                let _ = self.cleanup_progressive_session(&cleanup).await;
                return Err(error);
            }
            tracing::debug!(
                elapsed_ms = phase_started.elapsed().as_millis() as u64,
                "remote shell shim prepared"
            );
        }

        Ok(AgentBootstrap {
            started: agent_started,
            remote_platform,
            remote_description,
            local_executable,
            digest,
            session_id,
            sftp,
            remote_bin_dir,
            remote_executable,
            remote_sessions_dir,
            remote_session_dir,
            remote_workspace_root,
            shell_launcher,
        })
    }

    async fn finish_agent(&self, bootstrap: AgentBootstrap, prepared: bool) -> Result<RemoteAgent> {
        let AgentBootstrap {
            started,
            remote_platform,
            remote_description: _,
            local_executable,
            digest,
            session_id,
            sftp,
            remote_bin_dir,
            remote_executable,
            remote_sessions_dir,
            remote_session_dir,
            remote_workspace_root,
            shell_launcher: _,
        } = bootstrap;
        let phase_started = Instant::now();
        sftp.ensure_dir_all(remote_bin_dir, 0o700).await?;
        tracing::debug!(
            elapsed_ms = phase_started.elapsed().as_millis() as u64,
            "remote worker cache directory ready"
        );

        let phase_started = Instant::now();
        let cached_digest = self
            .remote_sha256(&sftp, &remote_executable, remote_platform)
            .await?;
        let cache_hit = cached_digest.as_deref() == Some(&digest);
        tracing::debug!(
            cache_hit,
            elapsed_ms = phase_started.elapsed().as_millis() as u64,
            "remote worker cache checked"
        );
        if !cache_hit {
            let phase_started = Instant::now();
            let (bytes, compression) = self
                .upload_worker(&sftp, &local_executable, &remote_executable, &session_id)
                .await?;
            tracing::debug!(
                bytes,
                compression,
                elapsed_ms = phase_started.elapsed().as_millis() as u64,
                "remote worker executable uploaded"
            );

            let phase_started = Instant::now();
            let uploaded_digest = self
                .remote_sha256(&sftp, &remote_executable, remote_platform)
                .await?;
            if uploaded_digest.as_deref() != Some(&digest) {
                return Err(SshError::Agent(
                    "remote worker binary failed post-upload checksum verification".to_owned(),
                ));
            }
            tracing::debug!(
                elapsed_ms = phase_started.elapsed().as_millis() as u64,
                "uploaded worker executable verified"
            );
        }

        let phase_started = Instant::now();
        sftp.set_permissions(remote_executable.clone(), 0o700)
            .await?;

        if !prepared {
            sftp.ensure_dir_all(remote_sessions_dir.clone(), 0o700)
                .await?;
        }
        sftp.close().await?;
        tracing::debug!(
            elapsed_ms = phase_started.elapsed().as_millis() as u64,
            "remote agent session prepared"
        );
        let prepared_argument = if prepared { " --prepared" } else { "" };
        let worker_stderr = join_remote_path(
            &remote_sessions_dir,
            &format!(".{session_id}.worker-stderr"),
        );
        let command = format!(
            "umask 077; exec {} serve{prepared_argument} --session-id {} --session-dir {} --workspace-root {} 2>{}",
            shell_quote(&remote_executable),
            shell_quote(&session_id),
            shell_quote(&remote_session_dir),
            shell_quote(&remote_workspace_root),
            shell_quote(&worker_stderr),
        );
        let phase_started = Instant::now();
        let channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;
        let agent = match RemoteAgent::connect(channel.into_stream(), &session_id).await {
            Ok(agent) => {
                let _ = self
                    .capture_command(&format!("rm -f {}", shell_quote(&worker_stderr)))
                    .await;
                agent
            }
            Err(error) => {
                let stderr = self
                    .capture_command(&format!(
                        "if test -f {}; then cat {}; rm -f {}; fi",
                        shell_quote(&worker_stderr),
                        shell_quote(&worker_stderr),
                        shell_quote(&worker_stderr),
                    ))
                    .await
                    .ok()
                    .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
                    .filter(|message| !message.is_empty());
                return Err(match stderr {
                    Some(stderr) => {
                        SshError::Agent(format!("{error}; remote worker stderr: {stderr}"))
                    }
                    None => error,
                });
            }
        };
        tracing::debug!(
            elapsed_ms = phase_started.elapsed().as_millis() as u64,
            total_elapsed_ms = started.elapsed().as_millis() as u64,
            "remote agent ready"
        );
        Ok(agent)
    }

    async fn prepare_remote_session(
        &self,
        session_dir: &str,
        remote_worker: &str,
        session_id: &str,
    ) -> Result<()> {
        let files = session_support_files(session_dir, remote_worker, session_id);
        let bin_dir = join_remote_path(session_dir, "bin");
        let zsh_dir = join_remote_path(session_dir, "zsh");
        let fish_completions =
            join_remote_path(&join_remote_path(session_dir, "fish"), "completions");
        let mut command = format!(
            "set -e; umask 077; mkdir -p {} {} {} {}; chmod 700 {} {} {} {};",
            shell_quote(session_dir),
            shell_quote(&bin_dir),
            shell_quote(&zsh_dir),
            shell_quote(&fish_completions),
            shell_quote(session_dir),
            shell_quote(&bin_dir),
            shell_quote(&zsh_dir),
            shell_quote(&fish_completions),
        );
        for (path, contents, mode) in files {
            command.push_str(&format!(
                " printf '%s' {} > {} && chmod {mode:o} {};",
                shell_quote(&contents),
                shell_quote(&path),
                shell_quote(&path),
            ));
        }
        let output = self.capture_command(&command).await?;
        if output.code != Some(0) {
            return Err(SshError::Agent(format!(
                "cannot prepare remote shell shim: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    async fn upload_worker(
        &self,
        sftp: &SftpClient,
        local: &Path,
        remote: &str,
        session_id: &str,
    ) -> Result<(u64, &'static str)> {
        let supported = match self
            .capture_command(
                "for tool in zstd gzip xz; do command -v \"$tool\" >/dev/null 2>&1 && printf '%s\\n' \"$tool\"; done",
            )
            .await
        {
            Ok(output) if output.code == Some(0) => {
                String::from_utf8_lossy(&output.stdout).into_owned()
            }
            Ok(output) => {
                tracing::debug!(
                    exit_code = ?output.code,
                    stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                    "remote decompressor detection failed; uploading raw worker"
                );
                String::new()
            }
            Err(error) => {
                tracing::debug!(%error, "remote decompressor detection failed; uploading raw worker");
                String::new()
            }
        };

        for compression in [
            WorkerCompression::Zstd,
            WorkerCompression::Gzip,
            WorkerCompression::Xz,
        ] {
            if !supported.lines().any(|name| name == compression.name()) {
                continue;
            }
            let Some(compressed) = compress_worker(local, compression).await else {
                continue;
            };
            let raw_size = std::fs::metadata(local).map_err(SshError::Io)?.len();
            if compressed.len() as u64 >= raw_size {
                continue;
            }

            let remote_archive =
                format!("{remote}.{}.{}", &session_id[..24], compression.extension());
            if let Err(error) = sftp
                .upload_bytes(&compressed, remote_archive.clone(), true)
                .await
            {
                tracing::debug!(%error, format = compression.name(), "compressed worker upload failed; trying raw upload");
                break;
            }

            let remote_unpacked = format!("{remote}.{}.unpacked", &session_id[..24]);
            let archive = shell_quote(&remote_archive);
            let unpacked = shell_quote(&remote_unpacked);
            let destination = shell_quote(remote);
            let command = format!(
                "umask 077; \
                 if {} {archive} > {unpacked} && chmod 700 {unpacked} && mv -f {unpacked} {destination}; \
                 then status=0; else status=$?; fi; \
                 rm -f {archive} {unpacked}; exit $status",
                compression.decompress_command()
            );
            match self.capture_command(&command).await {
                Ok(output) if output.code == Some(0) => {
                    return Ok((compressed.len() as u64, compression.name()));
                }
                Ok(output) => {
                    tracing::debug!(
                        format = compression.name(),
                        exit_code = ?output.code,
                        stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                        "remote worker decompression failed; trying raw upload"
                    );
                }
                Err(error) => {
                    tracing::debug!(%error, format = compression.name(), "remote worker decompression failed; trying raw upload");
                }
            }
            break;
        }

        let remote_raw = format!("{remote}.{}.raw", &session_id[..24]);
        let bytes = sftp.upload(local, remote_raw.clone(), true).await?;
        let command = format!(
            "chmod 700 {} && mv -f {} {}",
            shell_quote(&remote_raw),
            shell_quote(&remote_raw),
            shell_quote(remote),
        );
        let output = self.capture_command(&command).await?;
        if output.code != Some(0) {
            return Err(SshError::Agent(format!(
                "cannot install uploaded worker: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok((bytes, "none"))
    }

    async fn remote_sha256(
        &self,
        sftp: &SftpClient,
        remote: &str,
        platform: RemotePlatform,
    ) -> Result<Option<String>> {
        let quoted = shell_quote(remote);
        let hash_command = match platform {
            RemotePlatform::Linux => "sha256sum",
            RemotePlatform::Macos => "shasum -a 256",
        };
        let command = format!(
            "if [ ! -e {quoted} ]; then exit 3; \
             elif [ -L {quoted} ] || [ ! -f {quoted} ]; then exit 4; \
             else {hash_command} {quoted}; fi"
        );
        let output = self.capture_command(&command).await?;
        match output.code {
            Some(0) => {
                let digest = String::from_utf8_lossy(&output.stdout)
                    .split_whitespace()
                    .next()
                    .filter(|value| {
                        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
                    .map(str::to_ascii_lowercase);
                if let Some(digest) = digest {
                    return Ok(Some(digest));
                }
            }
            Some(3) => return Ok(None),
            Some(4) => {
                return Err(SshError::Config(format!(
                    "refusing non-regular or symlinked remote worker file {remote}"
                )));
            }
            _ => {}
        }
        tracing::debug!(
            exit_code = ?output.code,
            stderr = %String::from_utf8_lossy(&output.stderr).trim(),
            "remote SHA-256 command failed; falling back to SFTP hashing"
        );
        sftp.sha256(remote.to_owned()).await
    }

    async fn verify_agent_platform(&self) -> Result<(RemotePlatform, String)> {
        let output = self
            .capture_command(
                "os=$(uname -s); arch=$(uname -m); printf '%s\\n%s\\n' \"$os\" \"$arch\"; \
                 if test -r /etc/os-release; then \
                   name=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | head -n 1); \
                   name=${name#\\\"}; name=${name%\\\"}; printf '%s\\n' \"${name:-$os}\"; \
                 elif command -v sw_vers >/dev/null 2>&1; then \
                   printf '%s %s\\n' \"$(sw_vers -productName)\" \"$(sw_vers -productVersion)\"; \
                 else printf '%s\\n' \"$os\"; fi; \
                 if test -r /proc/meminfo; then \
                   awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo; \
                 elif command -v sysctl >/dev/null 2>&1; then sysctl -n hw.memsize 2>/dev/null || printf '0\\n'; \
                 else printf '0\\n'; fi",
            )
            .await?;
        if output.code != Some(0) {
            return Err(SshError::Agent(format!(
                "cannot detect remote platform: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut lines = stdout.lines();
        let remote_os = lines.next().unwrap_or_default().trim();
        let remote_arch = lines.next().unwrap_or_default().trim();
        let remote_name = lines.next().unwrap_or(remote_os).trim();
        let memory_value = lines
            .next()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let os_matches = matches!(
            (std::env::consts::OS, remote_os),
            ("linux", "Linux") | ("macos", "Darwin")
        );
        let arch_matches = match std::env::consts::ARCH {
            "x86_64" => remote_arch == "x86_64" || remote_arch == "amd64",
            "aarch64" => remote_arch == "aarch64" || remote_arch == "arm64",
            local => local == remote_arch,
        };
        if !os_matches || !arch_matches {
            return Err(SshError::Agent(format!(
                "no bundled agent for remote {remote_os}/{remote_arch}; local binary is {}/{}",
                std::env::consts::OS,
                std::env::consts::ARCH
            )));
        }
        let platform = match remote_os {
            "Linux" => RemotePlatform::Linux,
            "Darwin" => RemotePlatform::Macos,
            _ => unreachable!("unsupported remote OS was rejected above"),
        };
        let memory_bytes = match platform {
            RemotePlatform::Linux => memory_value.saturating_mul(1024),
            RemotePlatform::Macos => memory_value,
        };
        Ok((
            platform,
            system_description(remote_name, remote_arch, memory_bytes),
        ))
    }

    pub async fn interactive_shell(&self) -> Result<CommandExit> {
        self.interactive_shell_inner(None, None, None, Vec::new(), None)
            .await
    }

    pub async fn interactive_shell_with_agent(&self) -> Result<CommandExit> {
        self.interactive_shell_progressive(None, Vec::new()).await
    }

    pub async fn interactive_shell_with_agent_handler(
        self: &Arc<Self>,
        handler: &mut dyn SessionCommandHandler,
    ) -> Result<CommandExit> {
        self.interactive_shell_progressive(Some(handler), vec![Some(Arc::clone(self))])
            .await
    }

    pub async fn workspace(&self) -> Result<WorkspaceClient> {
        Ok(WorkspaceClient::new(self.start_agent().await?))
    }

    async fn interactive_shell_progressive(
        &self,
        handler: Option<&mut dyn SessionCommandHandler>,
        handler_sessions: Vec<Option<Arc<SshSession>>>,
    ) -> Result<CommandExit> {
        let bootstrap = self.prepare_agent(true).await?;
        let initial_display = single_connection_overview(
            &local_connection_summary(),
            &format!(
                "{}@{}:{}",
                self.target.user, self.target.host, self.target.port
            ),
            &bootstrap.remote_workspace_root,
            &bootstrap.remote_description,
        )
        .into_bytes();
        let shell_launcher = bootstrap.shell_launcher.clone();
        let cleanup = ProgressiveCleanup {
            remote_session_dir: bootstrap.remote_session_dir.clone(),
            remote_executable: bootstrap.remote_executable.clone(),
            session_id: bootstrap.session_id.clone(),
        };
        let startup: AgentStartup<'_> = Box::pin(self.finish_agent(bootstrap, true));
        self.interactive_shell_inner(
            None,
            Some(startup),
            handler,
            handler_sessions,
            Some(ProgressiveShellState {
                shell_launcher,
                cleanup,
                initial_display,
            }),
        )
        .await
    }

    async fn interactive_shell_inner(
        &self,
        mut agent: Option<RemoteAgent>,
        mut startup: Option<AgentStartup<'_>>,
        mut handler: Option<&mut dyn SessionCommandHandler>,
        handler_sessions: Vec<Option<Arc<SshSession>>>,
        progressive: Option<ProgressiveShellState>,
    ) -> Result<CommandExit> {
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            return Err(SshError::Config(
                "interactive SSH requires a terminal".to_owned(),
            ));
        }

        let mut channel = self.session.channel_open_session().await?;
        let term = env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned());
        let (columns, rows) = terminal_size();
        channel
            .request_pty(true, &term, columns, rows, 0, 0, &[])
            .await?;

        let shell_launcher = progressive
            .as_ref()
            .map(|progressive| progressive.shell_launcher.as_str());
        match (self.target.path.as_deref(), shell_launcher) {
            (path, Some(shell_launcher)) => {
                let command = build_shell_command(path, Some(shell_launcher));
                channel.exec(true, command).await?;
            }
            (Some(path), None) => {
                let command = build_shell_command(Some(path), None);
                channel.exec(true, command).await?;
            }
            (None, None) => channel.request_shell(true).await?,
        }

        let mut raw_mode = Some(RawTerminalGuard::activate()?);
        let mut stdin = InteractiveStdin::new()?;
        let mut stdout = tokio::io::stdout();
        let mut input = [0_u8; 8192];
        let mut stdin_closed = false;
        let mut input_parser = SwitchInputParser::default();
        let mut passthrough = false;
        let mut code = None;
        let mut signal = None;

        if let Some(progressive) = progressive.as_ref() {
            stdout.write_all(&progressive.initial_display).await?;
            stdout.flush().await?;
        }

        let mut resize = ResizeEvents::new()?;

        'shell: loop {
            tokio::select! {
                biased;
                read = stdin.read(&mut input), if !stdin_closed => {
                    let read = read?;
                    if read == 0 {
                        stdin_closed = true;
                        channel.eof().await?;
                    } else {
                        for parsed in input_parser.feed(&input[..read], false) {
                            match parsed {
                                ParsedInput::Data(mut data) => {
                                    if !passthrough {
                                        if let Some(handler) = handler.as_deref_mut() {
                                            let result = handler.handle_input(data).await;
                                            data = result.forward;
                                            if let Some(notice) = result.notice {
                                                stdout
                                                    .write_all(
                                                        format!("\r\nsshai: {notice}\r\n").as_bytes(),
                                                    )
                                                    .await?;
                                                stdout.flush().await?;
                                            }
                                        }
                                    }
                                    if !data.is_empty() {
                                        channel.data_bytes(data).await?;
                                    }
                                }
                                ParsedInput::TogglePassthrough => {
                                    passthrough = !passthrough;
                                    channel
                                        .data_bytes(passthrough_export(passthrough))
                                        .await?;
                                    stdout
                                        .write_all(
                                            format!(
                                                "\r\n\x1b[1;33m[sshai] {} mode; Ctrl+\\ toggles\x1b[0m\r\n",
                                                if passthrough {
                                                    "remote passthrough"
                                                } else {
                                                    "smart"
                                                }
                                            )
                                            .as_bytes(),
                                        )
                                        .await?;
                                    stdout.flush().await?;
                                }
                                ParsedInput::Switch(_) => unreachable!(
                                    "single-host input parser does not parse pane switches"
                                ),
                            }
                        }
                    }
                }
                message = channel.wait() => {
                    let Some(message) = message else { break 'shell };
                    match message {
                        ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                            stdout.write_all(&data).await?;
                            stdout.flush().await?;
                        }
                        ChannelMsg::ExitStatus { exit_status } => {
                            code = Some(exit_status);
                            break 'shell;
                        }
                        ChannelMsg::ExitSignal { signal_name, .. } => {
                            signal = Some(format!("{signal_name:?}"));
                            break 'shell;
                        }
                        ChannelMsg::Close => break 'shell,
                        _ => {}
                    }
                }
                _ = resize.recv() => {
                    let (columns, rows) = terminal_size();
                    channel.window_change(columns, rows, 0, 0).await?;
                }
                startup_result = receive_agent_startup(&mut startup), if startup.is_some() => {
                    startup = None;
                    match startup_result {
                        Ok(started_agent) => agent = Some(started_agent),
                        Err(error) => {
                            if let Some(cleanup) = progressive
                                .as_ref()
                                .map(|progressive| &progressive.cleanup)
                            {
                                if let Err(mark_error) = self
                                    .write_agent_startup_error(&cleanup.remote_session_dir, &error)
                                    .await
                                {
                                    tracing::debug!(%mark_error, "could not write remote agent error marker");
                                }
                            }
                            stdout.write_all(format!("\r\nsshai: worker unavailable: {error}\r\n").as_bytes()).await?;
                            stdout.flush().await?;
                        }
                    }
                }
                request = receive_control_request(&mut agent) => {
                    match request {
                        Ok(request) => {
                            let external_command = request.argv.first().and_then(|command| {
                                handler
                                    .as_deref()
                                    .filter(|handler| handler.handles(command))
                                    .map(|_| command.clone())
                            });
                            let response = if let Some(command) = external_command {
                                drop(raw_mode.take());
                                let result = handler
                                    .as_deref_mut()
                                    .expect("external command requires a handler")
                                    .handle(
                                        &command,
                                        &request.argv[1..],
                                        0,
                                        request.cwd.as_deref(),
                                        handler_sessions.clone(),
                                    )
                                    .await;
                                raw_mode = Some(RawTerminalGuard::activate()?);
                                ControlResponse {
                                    id: request.id,
                                    exit_code: result.exit_code,
                                    stdout: result.stdout,
                                    stderr: result.stderr,
                                }
                            } else {
                                self.handle_control_request(request).await
                            };
                            if let Some(remote_agent) = agent.as_mut() {
                                if let Err(error) = remote_agent.respond(response).await {
                                    stdout.write_all(format!("\r\nsshai: control response failed: {error}\r\n").as_bytes()).await?;
                                    stdout.flush().await?;
                                    agent = None;
                                }
                            }
                        }
                        Err(error) => {
                            stdout.write_all(format!("\r\nsshai: remote agent stopped: {error}\r\n").as_bytes()).await?;
                            stdout.flush().await?;
                            agent = None;
                        }
                    }
                }
            }
        }

        drop(startup.take());
        let _ = channel.close().await;
        if let Some(agent) = agent.as_mut() {
            if let Err(error) = agent.shutdown().await {
                tracing::debug!(%error, "remote agent did not shut down cleanly");
            }
        }
        if let Some(cleanup) = progressive.map(|progressive| progressive.cleanup) {
            if let Err(error) = self.cleanup_progressive_session(&cleanup).await {
                tracing::debug!(%error, "could not clean progressive agent session");
            }
        }
        Ok(CommandExit { code, signal })
    }

    async fn write_agent_startup_error(&self, session_dir: &str, error: &SshError) -> Result<()> {
        let path = join_remote_path(session_dir, "agent.error");
        let message = format!("sshai: worker is unavailable: {error}\n");
        let command = format!(
            "umask 077; printf '%s' {} > {} && chmod 600 {}",
            shell_quote(&message),
            shell_quote(&path),
            shell_quote(&path),
        );
        let output = self.capture_command(&command).await?;
        if output.code != Some(0) {
            return Err(SshError::Agent(format!(
                "cannot write worker error marker: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    async fn cleanup_progressive_session(&self, cleanup: &ProgressiveCleanup) -> Result<()> {
        let temporary_prefix = format!(
            "{}.{}.",
            cleanup.remote_executable,
            &cleanup.session_id[..24]
        );
        let command = format!(
            "rm -rf {}; rm -f {}*",
            shell_quote(&cleanup.remote_session_dir),
            shell_quote(&temporary_prefix),
        );
        let output = self.capture_command(&command).await?;
        if output.code != Some(0) {
            return Err(SshError::Agent(format!(
                "cannot clean progressive session: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    async fn handle_control_request(&self, request: ControlRequest) -> ControlResponse {
        self.handle_control_request_with_local_root(request, None)
            .await
    }

    async fn handle_control_request_with_local_root(
        &self,
        request: ControlRequest,
        local_root: Option<&Path>,
    ) -> ControlResponse {
        let id = request.id;
        let result = match request.argv.first().map(String::as_str) {
            Some("copy-id") => self.control_copy_id(&request.argv[1..]).await,
            Some("get") => {
                self.control_transfer(
                    TransferDirection::Get,
                    &request.argv[1..],
                    request.cwd.as_deref(),
                    local_root,
                )
                .await
            }
            Some("put") => {
                self.control_transfer(
                    TransferDirection::Put,
                    &request.argv[1..],
                    request.cwd.as_deref(),
                    local_root,
                )
                .await
            }
            Some("info" | "hosts") => Ok(format!(
                "connected to {}@{}:{}\n",
                self.target.user, self.target.host, self.target.port
            )),
            Some("help") | Some("--help") | Some("-h") => Ok(control_help().to_owned()),
            // Hidden helper behind the remote shell's completion for `put`.
            Some("--complete-local") => control_complete_local(&request.argv[1..], local_root),
            Some(command) => Err(SshError::Agent(format!(
                "unknown session command {command:?}; use `sshai --agent {command}` for a local AI CLI, or try `sshai help`"
            ))),
            None => Err(SshError::Agent(
                "missing built-in command; try `sshai help`".to_owned(),
            )),
        };
        match result {
            Ok(stdout) => ControlResponse {
                id,
                exit_code: 0,
                stdout,
                stderr: String::new(),
            },
            Err(error) => ControlResponse {
                id,
                exit_code: 1,
                stdout: String::new(),
                stderr: format!("sshai: {error}\n"),
            },
        }
    }

    async fn control_copy_id(&self, arguments: &[String]) -> Result<String> {
        if matches!(arguments, [argument] if argument == "-h" || argument == "--help") {
            return Ok(
                "usage: sshai copy-id [-i LOCAL_KEY] [--authorized-keys REMOTE_PATH]\n".to_owned(),
            );
        }
        let (identity, authorized_keys) = parse_copy_id_arguments(arguments)?;
        let identities =
            discover_public_identities(identity.as_deref(), &self.target.identity_files).await?;
        let sftp = self.sftp().await?;
        let operation = async {
            let mut installed = 0_usize;
            let mut existing = 0_usize;
            let mut output = String::new();
            for identity in identities {
                output.push_str(&format!(
                    "key: {} ({})\n",
                    identity.fingerprint, identity.source
                ));
                match sftp
                    .install_authorized_key_at(
                        authorized_keys.as_deref(),
                        &identity.authorized_key,
                        &identity.key_blob,
                    )
                    .await?
                {
                    KeyInstallResult::Installed => installed += 1,
                    KeyInstallResult::AlreadyPresent => existing += 1,
                }
            }
            output.push_str(&format!(
                "installed: {installed}, already present: {existing}\n"
            ));
            Ok::<_, SshError>(output)
        }
        .await;
        let close = sftp.close().await;
        match (operation, close) {
            (Ok(output), Ok(())) => Ok(output),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    /// Transfer a file or directory over the session's own SSH connection, so
    /// that `get`/`put` inside the remote shell need no second authentication.
    async fn control_transfer(
        &self,
        direction: TransferDirection,
        arguments: &[String],
        remote_cwd: Option<&str>,
        local_root: Option<&Path>,
    ) -> Result<String> {
        if matches!(arguments, [argument] if argument == "-h" || argument == "--help") {
            return Ok(direction.usage().to_owned());
        }
        let parsed = parse_transfer_arguments(direction, arguments)?;
        let (remote_argument, local_argument) = match direction {
            TransferDirection::Get => (&parsed.source, &parsed.destination),
            TransferDirection::Put => (&parsed.destination, &parsed.source),
        };
        let mut local = expand_local_home(local_argument)?;
        if local.is_relative() {
            let base = match local_root {
                Some(root) => root.to_owned(),
                None => env::current_dir().map_err(SshError::Io)?,
            };
            local = base.join(local);
        }
        let mut local = clean_local_path(local);
        let sftp = self.sftp().await?;
        let operation = async {
            let home = sftp.remote_home().await?;
            let mut remote = resolve_remote_transfer_path(remote_cwd, &home, remote_argument);
            let stats = match direction {
                TransferDirection::Get => {
                    if !sftp.exists(remote.clone()).await? {
                        return Err(SshError::Config(format!(
                            "remote path {remote} does not exist"
                        )));
                    }
                    // An existing directory destination keeps the source name, like scp.
                    if local.is_dir() {
                        local = local.join(remote_transfer_name(&remote)?);
                    }
                    sftp.download_path(
                        remote.clone(),
                        &local,
                        parsed.recursive,
                        parsed.force,
                        &parsed.excludes,
                    )
                    .await?
                }
                TransferDirection::Put => {
                    if !local.exists() {
                        return Err(SshError::Config(format!(
                            "local path {} does not exist",
                            local.display()
                        )));
                    }
                    if sftp.is_dir(remote.clone()).await? {
                        remote = join_remote_path(&remote, &local_transfer_name(&local)?);
                    }
                    sftp.upload_path(
                        &local,
                        remote.clone(),
                        parsed.recursive,
                        parsed.force,
                        &parsed.excludes,
                    )
                    .await?
                }
            };
            let local = local.display().to_string();
            let (from, to) = match direction {
                TransferDirection::Get => (remote, local),
                TransferDirection::Put => (local, remote),
            };
            Ok::<_, SshError>(format!(
                "{} {from} -> {to}\ntransferred {} bytes in {} files and {} directories\n{}",
                direction.name(),
                stats.bytes,
                stats.files,
                stats.directories,
                stats
                    .warnings
                    .iter()
                    .map(|warning| format!("warning: {warning}\n"))
                    .collect::<String>(),
            ))
        }
        .await;
        let close = sftp.close().await;
        match (operation, close) {
            (Ok(output), Ok(())) => Ok(output),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    pub async fn disconnect(&self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "sshai session closed", "en")
            .await?;
        Ok(())
    }
}

async fn run_multiplexed_shells(
    primary: Arc<SshSession>,
    background_connector: SshConnector,
    targets: Vec<Target>,
    handler: &mut dyn SessionCommandHandler,
) -> Result<CommandExit> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(SshError::Config(
            "interactive SSH requires a terminal".to_owned(),
        ));
    }

    let total = targets.len();
    let panes = total + 1;
    let labels = targets.iter().map(ToString::to_string).collect::<Vec<_>>();
    let mut local_summary = local_connection_summary();
    let (events_tx, mut events_rx) = mpsc::channel(256);
    let primary_shell = prepare_multiplexed_shell(
        0,
        labels[0].clone(),
        Arc::clone(&primary),
        events_tx.clone(),
    )
    .await?;

    let mut raw_mode = Some(RawTerminalGuard::activate()?);
    let mut stdin = InteractiveStdin::new()?;
    let mut stdout = tokio::io::stdout();
    let mut input = [0_u8; 8192];
    let mut parser = SwitchInputParser::default();
    let mut resize = ResizeEvents::new()?;
    let mut stdin_closed = false;
    let mut passthrough = false;
    let mut active = Some(Pane::Remote(0));
    let mut pending_connections = total - 1;
    let mut statuses = vec!["connecting".to_owned(); total];
    statuses[0] = "connected".to_owned();
    let mut shells = (0..total)
        .map(|_| None)
        .collect::<Vec<Option<MultiplexedShell>>>();
    shells[0] = Some(primary_shell);
    let initial_display =
        initial_multiplexer_display(&labels[0], &local_summary, &shells, &labels, &statuses);
    shells[0]
        .as_mut()
        .expect("primary shell exists")
        .terminal
        .process(&initial_display);
    start_multiplexed_shell(shells[0].as_mut().expect("primary shell exists"));
    present_initial_multiplexed_shell(&mut stdout, &initial_display).await?;

    // The local shell runs as its own pane from the start so Ctrl+Left always
    // has somewhere to go, single-host sessions included. If it exits while
    // inactive, its pane can still be restarted on a later Ctrl+Left.
    let local_events = events_tx.clone();
    let mut local_available = true;
    let mut local = match prepare_local_shell(local_events.clone()).await {
        Ok(mut shell) => {
            shell.terminal.process(
                connection_overview(&local_summary, &shells, &labels, &statuses, true).as_bytes(),
            );
            Some(shell)
        }
        Err(error) => {
            tracing::debug!(%error, "local shell pane is unavailable");
            local_available = false;
            None
        }
    };

    let mut connection_tasks = Vec::with_capacity(total.saturating_sub(1));
    for (index, target) in targets.into_iter().enumerate().skip(1) {
        let connector = background_connector.clone();
        let events = events_tx.clone();
        let label = labels[index].clone();
        connection_tasks.push(tokio::spawn(async move {
            let result = async {
                let session = Arc::new(connector.connect(&target).await?);
                prepare_multiplexed_shell(index, label, session, events.clone()).await
            }
            .await;
            let event = match result {
                Ok(shell) => MultiplexEvent::Ready {
                    index,
                    shell: Box::new(shell),
                },
                Err(error) => MultiplexEvent::Failed {
                    index,
                    error: format!("{error}"),
                },
            };
            let _ = events.send(event).await;
        }));
    }
    drop(events_tx);

    let mut last_code = None;
    let mut last_signal = None;
    'multiplexer: loop {
        let pending_timeout = tokio::time::sleep(parser.pending_timeout());
        tokio::pin!(pending_timeout);
        tokio::select! {
            biased;
            read = stdin.read(&mut input), if !stdin_closed => {
                let read = read?;
                if read == 0 {
                    stdin_closed = true;
                    for shell in shells.iter().flatten().filter(|shell| shell.open) {
                        let _ = shell.commands.send(MultiplexCommand::Eof).await;
                    }
                    if let Some(shell) = local.as_ref().filter(|shell| shell.open) {
                        let _ = shell.commands.send(MultiplexCommand::Eof).await;
                    }
                } else {
                    for parsed in parser.feed(&input[..read], !passthrough) {
                        match parsed {
                            ParsedInput::Data(data) => {
                                let mut data = data;
                                let notice = if passthrough {
                                    None
                                } else {
                                    let result = handler.handle_input(data).await;
                                    data = result.forward;
                                    result.notice
                                };
                                if let Some(notice) = notice {
                                    let notice = format!("\r\nsshai: {notice}\r\n").into_bytes();
                                    if let Some(terminal) =
                                        pane_terminal_mut(&mut shells, local.as_mut(), active)
                                    {
                                        terminal.process(&notice);
                                    }
                                    stdout.write_all(&notice).await?;
                                    stdout.flush().await?;
                                }
                                if let Some(commands) = pane_commands(&shells, local.as_ref(), active) {
                                    if !data.is_empty() {
                                        let _ = commands.send(MultiplexCommand::Input(data)).await;
                                    }
                                }
                            }
                            ParsedInput::TogglePassthrough => {
                                passthrough = !passthrough;
                                if let Some(commands) = pane_commands(&shells, local.as_ref(), active) {
                                    let _ = commands
                                        .send(MultiplexCommand::Input(passthrough_export(passthrough)))
                                        .await;
                                }
                                let notice = format!(
                                    "\r\n\x1b[1;33m[sshai] {} mode; Ctrl+\\ toggles\x1b[0m\r\n",
                                    if passthrough { "remote passthrough" } else { "smart" }
                                )
                                .into_bytes();
                                if let Some(terminal) =
                                    pane_terminal_mut(&mut shells, local.as_mut(), active)
                                {
                                    terminal.process(&notice);
                                }
                                stdout.write_all(&notice).await?;
                                stdout.flush().await?;
                            }
                            ParsedInput::Switch(action) => {
                                let next = if action == InputAction::Local {
                                    Some(Pane::Local)
                                } else {
                                    active.and_then(|current| {
                                        adjacent_switchable_pane(
                                            &shells,
                                            local.as_ref(),
                                            local_available,
                                            current,
                                            action,
                                        )
                                    })
                                };
                                if let Some(next) = next {
                                        // An inactive local pane keeps its ring slot;
                                        // selecting it again can restart the shell.
                                        if next == Pane::Local
                                            && !local.as_ref().is_some_and(|shell| shell.open)
                                        {
                                            match prepare_local_shell(local_events.clone()).await {
                                                Ok(mut shell) => {
                                                    shell.terminal.process(
                                                        connection_overview(
                                                            &local_summary,
                                                            &shells,
                                                            &labels,
                                                            &statuses,
                                                            true,
                                                        )
                                                        .as_bytes(),
                                                    );
                                                    local = Some(shell);
                                                }
                                                Err(error) => {
                                                    local_available = false;
                                                    let notice = format!(
                                                        "\r\n\x1b[1;31m[sshai] cannot start the local shell: {error}\x1b[0m\r\n"
                                                    )
                                                    .into_bytes();
                                                    if let Some(terminal) =
                                                        pane_terminal_mut(&mut shells, local.as_mut(), active)
                                                    {
                                                        terminal.process(&notice);
                                                    }
                                                    stdout.write_all(&notice).await?;
                                                    stdout.flush().await?;
                                                    continue;
                                                }
                                            }
                                        }
                                        refresh_local_summary(&mut local_summary, local.as_ref());
                                        active = Some(next);
                                        if passthrough && matches!(next, Pane::Remote(_)) {
                                            if let Some(commands) = pane_commands(&shells, local.as_ref(), active) {
                                                let _ = commands
                                                    .send(MultiplexCommand::Input(passthrough_export(true)))
                                                    .await;
                                            }
                                        }
                                        render_pane(&mut stdout, &shells, local.as_ref(), next, panes).await?;
                                } else {
                                    write_multiplexer_status(
                                        &mut stdout,
                                        pending_connections,
                                        &statuses,
                                    )
                                    .await?;
                                }
                            }
                        }
                    }
                }
            }
            event = events_rx.recv() => {
                let Some(event) = event else { break 'multiplexer };
                match event {
                    MultiplexEvent::Ready { index, shell } => {
                        pending_connections = pending_connections.saturating_sub(1);
                        statuses[index] = "connected".to_owned();
                        shells[index] = Some(*shell);
                        let overview = connection_overview(
                            &local_summary,
                            &shells,
                            &labels,
                            &statuses,
                            true,
                        );
                        if let Some(shell) = shells[index].as_mut() {
                            shell.terminal.process(overview.as_bytes());
                            start_multiplexed_shell(shell);
                        }
                        refresh_connection_overviews(
                            &mut stdout,
                            &mut shells,
                            local.as_mut(),
                            active,
                            &local_summary,
                            &labels,
                            &statuses,
                        )
                        .await?;
                        if passthrough {
                            if let Some(shell) = shells[index].as_ref() {
                                let _ = shell
                                    .commands
                                    .send(MultiplexCommand::Input(passthrough_export(true)))
                                    .await;
                            }
                        }
                        if active.is_none() {
                            active = Some(Pane::Remote(index));
                            render_pane(
                                &mut stdout,
                                &shells,
                                local.as_ref(),
                                Pane::Remote(index),
                                panes,
                            )
                            .await?;
                        }
                    }
                    MultiplexEvent::Failed { index, error } => {
                        pending_connections = pending_connections.saturating_sub(1);
                        statuses[index] = format!("failed: {error}");
                        refresh_connection_overviews(
                            &mut stdout,
                            &mut shells,
                            local.as_mut(),
                            active,
                            &local_summary,
                            &labels,
                            &statuses,
                        )
                        .await?;
                        if active.is_none() && pending_connections == 0 {
                            break 'multiplexer;
                        }
                    }
                    MultiplexEvent::Output { index, data } => {
                        if let Some(shell) = shells.get_mut(index).and_then(Option::as_mut) {
                            shell.terminal.process(&data);
                            if active == Some(Pane::Remote(index)) {
                                stdout.write_all(&data).await?;
                                stdout.flush().await?;
                            }
                        }
                    }
                    MultiplexEvent::LocalOutput { data } => {
                        if let Some(shell) = local.as_mut() {
                            shell.terminal.process(&data);
                            if active == Some(Pane::Local) {
                                stdout.write_all(&data).await?;
                                stdout.flush().await?;
                            }
                        }
                    }
                    MultiplexEvent::WorkerNotice { index, message } => {
                        let notice = format!("\r\nsshai: {message}\r\n").into_bytes();
                        if let Some(shell) = shells.get_mut(index).and_then(Option::as_mut) {
                            shell.terminal.process(&notice);
                            if active == Some(Pane::Remote(index)) {
                                stdout.write_all(&notice).await?;
                                stdout.flush().await?;
                            }
                        }
                    }
                    MultiplexEvent::ControlRequest { index, request } => {
                        let Some(shell) = shells.get(index).and_then(Option::as_ref) else {
                            continue;
                        };
                        let local_cwd = local.as_ref().and_then(local_shell_cwd);
                        if let Some(cwd) = local_cwd.as_ref() {
                            local_summary.workspace_root = cwd.to_string_lossy().into_owned();
                        }
                        let session = Arc::clone(&shell.session);
                        let commands = shell.commands.clone();
                        let external_command = request.argv.first().and_then(|command| {
                            handler.handles(command).then(|| command.clone())
                        });
                        let shows_connections = matches!(
                            request.argv.as_slice(),
                            [command] if command == "info" || command == "hosts"
                        );
                        let response = if shows_connections {
                            ControlResponse {
                                id: request.id,
                                exit_code: 0,
                                stdout: connection_overview(
                                    &local_summary,
                                    &shells,
                                    &labels,
                                    &statuses,
                                    false,
                                ),
                                stderr: String::new(),
                            }
                        } else if let Some(command) = external_command {
                            handler.update_local_root(local_cwd.clone());
                            drop(raw_mode.take());
                            let result = handler
                                .handle(
                                    &command,
                                    &request.argv[1..],
                                    index,
                                    request.cwd.as_deref(),
                                    shells
                                        .iter()
                                        .map(|shell| {
                                            shell
                                                .as_ref()
                                                .filter(|shell| shell.open)
                                                .map(|shell| Arc::clone(&shell.session))
                                        })
                                        .collect(),
                                )
                                .await;
                            raw_mode = Some(RawTerminalGuard::activate()?);
                            ControlResponse {
                                id: request.id,
                                exit_code: result.exit_code,
                                stdout: result.stdout,
                                stderr: result.stderr,
                            }
                        } else {
                            // Built-in commands can transfer whole directories, so
                            // they answer from a task instead of stalling the panes.
                            tokio::spawn(async move {
                                let response = session
                                    .handle_control_request_with_local_root(
                                        request,
                                        local_cwd.as_deref(),
                                    )
                                    .await;
                                let _ = commands
                                    .send(MultiplexCommand::ControlResponse(response))
                                    .await;
                            });
                            continue;
                        };
                        let _ = commands
                            .send(MultiplexCommand::ControlResponse(response))
                            .await;
                    }
                    MultiplexEvent::Exited { index, code, signal } => {
                        let active_shell_exited_normally = closes_multiplexer_on_exit(
                            active,
                            index,
                            code,
                            signal.as_deref(),
                        );
                        last_code = code.or(last_code);
                        last_signal = signal.or(last_signal);
                        statuses[index] = "closed".to_owned();
                        if let Some(shell) = shells.get_mut(index).and_then(Option::as_mut) {
                            shell.open = false;
                        }
                        if active_shell_exited_normally {
                            break 'multiplexer;
                        }
                        refresh_connection_overviews(
                            &mut stdout,
                            &mut shells,
                            local.as_mut(),
                            active,
                            &local_summary,
                            &labels,
                            &statuses,
                        )
                        .await?;
                        if active == Some(Pane::Remote(index)) {
                            active = adjacent_open_pane(
                                &shells,
                                local.as_ref(),
                                Pane::Remote(index),
                                InputAction::Next,
                            );
                            if let Some(next) = active {
                                if passthrough && matches!(next, Pane::Remote(_)) {
                                    if let Some(commands) = pane_commands(&shells, local.as_ref(), active) {
                                        let _ = commands
                                            .send(MultiplexCommand::Input(passthrough_export(true)))
                                            .await;
                                    }
                                }
                                render_pane(&mut stdout, &shells, local.as_ref(), next, panes).await?;
                            } else if pending_connections > 0 {
                                stdout
                                    .write_all(b"\r\n\x1b[1;33m[sshai] waiting for background hosts...\x1b[0m\r\n")
                                    .await?;
                                stdout.flush().await?;
                            }
                        }
                        if active.is_none() && pending_connections == 0 {
                            break 'multiplexer;
                        }
                    }
                    MultiplexEvent::LocalExited { code } => {
                        if let Some(shell) = local.as_mut() {
                            shell.open = false;
                        }
                        if active == Some(Pane::Local) {
                            // `exit` in any active pane terminates the whole sshai
                            // session. Do not fall back to a remote pane here:
                            // that would require a second `exit` and would make
                            // local behave differently from remote hosts.
                            last_code = code.or(last_code);
                            break 'multiplexer;
                        }
                        if active.is_none() && pending_connections == 0 {
                            break 'multiplexer;
                        }
                    }
                }
            }
            _ = resize.recv() => {
                let (columns, rows) = terminal_size();
                for shell in shells.iter_mut().flatten().filter(|shell| shell.open) {
                    shell.terminal.resize(columns, rows);
                    let commands = shell.commands.clone();
                    let _ = commands.send(MultiplexCommand::Resize(columns, rows)).await;
                }
                if let Some(shell) = local.as_mut().filter(|shell| shell.open) {
                    shell.terminal.resize(columns, rows);
                    let commands = shell.commands.clone();
                    let _ = commands.send(MultiplexCommand::Resize(columns, rows)).await;
                }
            }
            _ = &mut pending_timeout, if parser.has_pending() => {
                if let Some(data) = parser.flush() {
                    if let Some(commands) = pane_commands(&shells, local.as_ref(), active) {
                        let _ = commands.send(MultiplexCommand::Input(data)).await;
                    }
                }
            }
        }
    }

    drop(raw_mode.take());
    drop(events_rx);
    for task in &connection_tasks {
        task.abort();
    }
    if let Some(shell) = local.as_ref().filter(|shell| shell.open) {
        let _ = shell.commands.send(MultiplexCommand::Shutdown).await;
    }
    for shell in shells.iter().flatten().filter(|shell| shell.open) {
        let _ = shell.commands.send(MultiplexCommand::Shutdown).await;
    }
    if let Some(task) = local.as_mut().and_then(|shell| shell.task.take()) {
        let _ = task.await;
    }
    for shell in shells.iter_mut().flatten() {
        if let Some(task) = shell.task.take() {
            let _ = task.await;
        }
        if let Err(error) = shell.session.disconnect().await {
            tracing::debug!(%error, target = %shell.label, "multiplexed session did not disconnect cleanly");
        }
    }

    Ok(CommandExit {
        code: last_code,
        signal: last_signal,
    })
}

/// Start the local shell pane on its own PTY. The pane is a plain login shell:
/// remote worker features such as `sshai --agent` stay with the SSH panes.
#[cfg(unix)]
async fn prepare_local_shell(events: mpsc::Sender<MultiplexEvent>) -> Result<LocalShell> {
    use std::{fs::File, process::Stdio};

    use nix::pty::{Winsize, openpty};

    let (columns, rows) = terminal_size();
    let window = Winsize {
        ws_row: terminal_dimension(rows),
        ws_col: terminal_dimension(columns),
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pair = openpty(Some(&window), None).map_err(std::io::Error::from)?;
    set_local_pty_nonblocking(&pair.master)?;
    let master = tokio::io::unix::AsyncFd::new(pair.master)?;
    let slave = File::from(pair.slave);
    let child_stdin = slave.try_clone()?;
    let child_stdout = slave.try_clone()?;
    let child_stderr = slave;
    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned());
    let mut command = tokio::process::Command::new(&shell);
    command
        .arg("-l")
        .env(
            "TERM",
            env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned()),
        )
        .env("COLUMNS", columns.to_string())
        .env("LINES", rows.to_string())
        .env("SSHAI_LOCAL_PANE", "1")
        .stdin(Stdio::from(child_stdin))
        .stdout(Stdio::from(child_stdout))
        .stderr(Stdio::from(child_stderr))
        .kill_on_drop(true);
    // SAFETY: only async-signal-safe libc calls run between fork and exec.
    unsafe {
        command.pre_exec(|| {
            if nix::libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if nix::libc::ioctl(0, nix::libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let process_group = nix::libc::getpgrp();
            if nix::libc::ioctl(0, nix::libc::TIOCSPGRP, &process_group) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| SshError::Config("local shell has no process id".to_owned()))?;
    let (commands, command_rx) = mpsc::channel(64);
    let task = tokio::spawn(run_local_shell_actor(master, child, command_rx, events));
    Ok(LocalShell {
        pid,
        commands,
        task: Some(task),
        terminal: VirtualTerminal::new(columns, rows),
        open: true,
    })
}

#[cfg(not(unix))]
async fn prepare_local_shell(_events: mpsc::Sender<MultiplexEvent>) -> Result<LocalShell> {
    Err(SshError::Config(
        "the local shell pane is not implemented on this platform".to_owned(),
    ))
}

/// Return the actual working directory of the local pane shell. On Linux the
/// kernel exposes this without asking the shell to echo a prompt marker, so it
/// works consistently across bash, zsh, fish, and custom shells.
#[cfg(target_os = "linux")]
fn local_shell_cwd(shell: &LocalShell) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{}/cwd", shell.pid)).ok()
}

#[cfg(not(target_os = "linux"))]
fn local_shell_cwd(_shell: &LocalShell) -> Option<PathBuf> {
    None
}

fn refresh_local_summary(summary: &mut LocalConnectionSummary, local: Option<&LocalShell>) {
    if let Some(cwd) = local.and_then(local_shell_cwd) {
        summary.workspace_root = cwd.to_string_lossy().into_owned();
    }
}

#[cfg(unix)]
async fn run_local_shell_actor(
    master: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    mut child: tokio::process::Child,
    mut commands: mpsc::Receiver<MultiplexCommand>,
    events: mpsc::Sender<MultiplexEvent>,
) {
    let mut buffer = [0_u8; 8192];
    let mut pty_open = true;
    let mut closing = false;
    let code = loop {
        tokio::select! {
            status = child.wait() => {
                break status
                    .ok()
                    .and_then(|status| status.code())
                    .map(|code| code.clamp(0, i32::MAX) as u32);
            }
            command = commands.recv(), if !closing => {
                match command {
                    Some(MultiplexCommand::Input(data)) => {
                        if write_local_pty(&master, &data).await.is_err() {
                            pty_open = false;
                        }
                    }
                    Some(MultiplexCommand::Eof) => {
                        let _ = write_local_pty(&master, &[0x04]).await;
                    }
                    Some(MultiplexCommand::Resize(columns, rows)) => {
                        let _ = resize_local_pty(&master, columns, rows);
                    }
                    // The local pane runs no sshai worker, so it never answers
                    // control requests.
                    Some(MultiplexCommand::ControlResponse(_)) => {}
                    Some(MultiplexCommand::Shutdown) | None => {
                        closing = true;
                        let _ = child.start_kill();
                    }
                }
            }
            read = read_local_pty(&master, &mut buffer), if pty_open => {
                match read {
                    Ok(0) => pty_open = false,
                    Ok(count) => {
                        if events
                            .send(MultiplexEvent::LocalOutput { data: buffer[..count].to_vec() })
                            .await
                            .is_err()
                        {
                            closing = true;
                            let _ = child.start_kill();
                        }
                    }
                    Err(_) => pty_open = false,
                }
            }
        }
    };
    let _ = events.send(MultiplexEvent::LocalExited { code }).await;
}

#[cfg(unix)]
async fn read_local_pty(
    master: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    buffer: &mut [u8],
) -> std::io::Result<usize> {
    loop {
        let mut readiness = master.readable().await?;
        let result = readiness.try_io(|inner| {
            nix::unistd::read(inner.get_ref(), buffer).map_err(std::io::Error::from)
        });
        match result {
            Ok(Ok(read)) => return Ok(read),
            // A closed shell reports EIO on the master side.
            Ok(Err(error)) if error.raw_os_error() == Some(nix::libc::EIO) => return Ok(0),
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
}

#[cfg(unix)]
async fn write_local_pty(
    master: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    data: &[u8],
) -> std::io::Result<()> {
    let mut written = 0;
    while written < data.len() {
        let mut readiness = master.writable().await?;
        let result = readiness.try_io(|inner| {
            nix::unistd::write(inner.get_ref(), &data[written..]).map_err(std::io::Error::from)
        });
        match result {
            Ok(Ok(0)) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero)),
            Ok(Ok(count)) => written += count,
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
    Ok(())
}

#[cfg(unix)]
fn resize_local_pty(
    master: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    columns: u32,
    rows: u32,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let window = nix::pty::Winsize {
        ws_row: terminal_dimension(rows),
        ws_col: terminal_dimension(columns),
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ reads the provided winsize and retains no pointer.
    if unsafe { nix::libc::ioctl(master.get_ref().as_raw_fd(), nix::libc::TIOCSWINSZ, &window) } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn set_local_pty_nonblocking(fd: &std::os::fd::OwnedFd) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    // SAFETY: fcntl only reads flags from the owned descriptor.
    let flags = unsafe { nix::libc::fcntl(fd.as_raw_fd(), nix::libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: F_SETFL updates only descriptor flags on the same descriptor.
    if unsafe {
        nix::libc::fcntl(
            fd.as_raw_fd(),
            nix::libc::F_SETFL,
            flags | nix::libc::O_NONBLOCK,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

async fn prepare_multiplexed_shell(
    index: usize,
    label: String,
    session: Arc<SshSession>,
    events: mpsc::Sender<MultiplexEvent>,
) -> Result<MultiplexedShell> {
    let bootstrap = session.prepare_agent(true).await?;
    let workspace_root = bootstrap.remote_workspace_root.clone();
    let system_description = bootstrap.remote_description.clone();
    let cleanup = ProgressiveCleanup {
        remote_session_dir: bootstrap.remote_session_dir.clone(),
        remote_executable: bootstrap.remote_executable.clone(),
        session_id: bootstrap.session_id.clone(),
    };
    let shell_launcher = bootstrap.shell_launcher.clone();
    let channel = session.session.channel_open_session().await?;
    let term = env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned());
    let (columns, rows) = terminal_size();
    channel
        .request_pty(true, &term, columns, rows, 0, 0, &[])
        .await?;
    let command = build_shell_command(session.target.path.as_deref(), Some(&shell_launcher));
    channel.exec(true, command).await?;

    let (commands, command_rx) = mpsc::channel(64);
    let (start, start_rx) = oneshot::channel();
    let actor_session = Arc::clone(&session);
    let task = tokio::spawn(async move {
        run_multiplexed_shell_actor(
            index,
            actor_session,
            channel,
            bootstrap,
            cleanup,
            command_rx,
            start_rx,
            events,
        )
        .await;
    });
    let terminal = VirtualTerminal::new(columns, rows);
    Ok(MultiplexedShell {
        label,
        workspace_root,
        system_description,
        session,
        commands,
        start: Some(start),
        task: Some(task),
        terminal,
        open: true,
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_multiplexed_shell_actor(
    index: usize,
    session: Arc<SshSession>,
    mut channel: russh::Channel<client::Msg>,
    bootstrap: AgentBootstrap,
    cleanup: ProgressiveCleanup,
    mut commands: mpsc::Receiver<MultiplexCommand>,
    start: oneshot::Receiver<()>,
    events: mpsc::Sender<MultiplexEvent>,
) {
    if start.await.is_err() {
        let _ = channel.close().await;
        let _ = session.cleanup_progressive_session(&cleanup).await;
        return;
    }
    let mut startup: Option<AgentStartup<'_>> =
        Some(Box::pin(session.finish_agent(bootstrap, true)));
    let mut agent = None;
    let mut code = None;
    let mut signal = None;

    'shell: loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(MultiplexCommand::Input(data)) => {
                        if channel.data_bytes(data).await.is_err() {
                            break 'shell;
                        }
                    }
                    Some(MultiplexCommand::Eof) => {
                        let _ = channel.eof().await;
                    }
                    Some(MultiplexCommand::Resize(columns, rows)) => {
                        let _ = channel.window_change(columns, rows, 0, 0).await;
                    }
                    Some(MultiplexCommand::ControlResponse(response)) => {
                        if let Some(remote_agent) = agent.as_mut()
                            && remote_agent.respond(response).await.is_err()
                        {
                            agent = None;
                        }
                    }
                    Some(MultiplexCommand::Shutdown) | None => break 'shell,
                }
            }
            message = channel.wait() => {
                let Some(message) = message else { break 'shell };
                match message {
                    ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                        if events
                            .send(MultiplexEvent::Output { index, data: data.to_vec() })
                            .await
                            .is_err()
                        {
                            break 'shell;
                        }
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        code = Some(exit_status);
                        break 'shell;
                    }
                    ChannelMsg::ExitSignal { signal_name, .. } => {
                        signal = Some(format!("{signal_name:?}"));
                        break 'shell;
                    }
                    ChannelMsg::Close => break 'shell,
                    _ => {}
                }
            }
            startup_result = receive_agent_startup(&mut startup), if startup.is_some() => {
                startup = None;
                match startup_result {
                    Ok(started_agent) => agent = Some(started_agent),
                    Err(error) => {
                        if let Err(mark_error) = session
                            .write_agent_startup_error(&cleanup.remote_session_dir, &error)
                            .await
                        {
                            tracing::debug!(%mark_error, "could not write multiplexed worker error marker");
                        }
                        let _ = events
                            .send(MultiplexEvent::WorkerNotice {
                                index,
                                message: format!("worker unavailable: {error}"),
                            })
                            .await;
                    }
                }
            }
            request = receive_control_request(&mut agent) => {
                match request {
                    Ok(request) => {
                        if events
                            .send(MultiplexEvent::ControlRequest { index, request })
                            .await
                            .is_err()
                        {
                            break 'shell;
                        }
                    }
                    Err(error) => {
                        let _ = events
                            .send(MultiplexEvent::WorkerNotice {
                                index,
                                message: format!("remote worker stopped: {error}"),
                            })
                            .await;
                        agent = None;
                    }
                }
            }
        }
    }

    drop(startup.take());
    let _ = channel.close().await;
    if let Some(agent) = agent.as_mut() {
        let _ = agent.shutdown().await;
    }
    if let Err(error) = session.cleanup_progressive_session(&cleanup).await {
        tracing::debug!(%error, "could not clean multiplexed worker session");
    }
    let _ = events
        .send(MultiplexEvent::Exited {
            index,
            code,
            signal,
        })
        .await;
}

fn start_multiplexed_shell(shell: &mut MultiplexedShell) {
    if let Some(start) = shell.start.take() {
        let _ = start.send(());
    }
}

fn pane_is_open(
    shells: &[Option<MultiplexedShell>],
    local: Option<&LocalShell>,
    pane: Pane,
) -> bool {
    match pane {
        Pane::Local => local.is_some_and(|shell| shell.open),
        Pane::Remote(index) => shells
            .get(index)
            .and_then(Option::as_ref)
            .is_some_and(|shell| shell.open),
    }
}

fn pane_commands(
    shells: &[Option<MultiplexedShell>],
    local: Option<&LocalShell>,
    pane: Option<Pane>,
) -> Option<mpsc::Sender<MultiplexCommand>> {
    match pane? {
        Pane::Local => local
            .filter(|shell| shell.open)
            .map(|shell| shell.commands.clone()),
        Pane::Remote(index) => shells
            .get(index)?
            .as_ref()
            .filter(|shell| shell.open)
            .map(|shell| shell.commands.clone()),
    }
}

fn pane_terminal_mut<'a>(
    shells: &'a mut [Option<MultiplexedShell>],
    local: Option<&'a mut LocalShell>,
    pane: Option<Pane>,
) -> Option<&'a mut VirtualTerminal> {
    match pane? {
        Pane::Local => local.map(|shell| &mut shell.terminal),
        Pane::Remote(index) => shells
            .get_mut(index)?
            .as_mut()
            .map(|shell| &mut shell.terminal),
    }
}

fn adjacent_pane(
    panes: usize,
    current: Pane,
    action: InputAction,
    accept: impl Fn(Pane) -> bool,
) -> Option<Pane> {
    let current = current.position();
    (1..panes)
        .map(|distance| match action {
            InputAction::Next => (current + distance) % panes,
            InputAction::Previous => (current + panes - distance) % panes,
            InputAction::Local => current,
        })
        .map(Pane::at)
        .find(|pane| accept(*pane))
}

fn adjacent_open_pane(
    shells: &[Option<MultiplexedShell>],
    local: Option<&LocalShell>,
    current: Pane,
    action: InputAction,
) -> Option<Pane> {
    adjacent_pane(shells.len() + 1, current, action, |pane| {
        pane_is_open(shells, local, pane)
    })
}

/// The pane `Shift+Left/Right` moves to. A local shell that exited keeps its
/// slot as long as local shells can run at all, so it can be restarted.
fn adjacent_switchable_pane(
    shells: &[Option<MultiplexedShell>],
    local: Option<&LocalShell>,
    local_available: bool,
    current: Pane,
    action: InputAction,
) -> Option<Pane> {
    adjacent_pane(shells.len() + 1, current, action, |pane| match pane {
        Pane::Local => local_available,
        Pane::Remote(_) => pane_is_open(shells, local, pane),
    })
}

fn closes_multiplexer_on_exit(
    active: Option<Pane>,
    exited: usize,
    code: Option<u32>,
    signal: Option<&str>,
) -> bool {
    active == Some(Pane::Remote(exited)) && (code.is_some() || signal.is_some())
}

fn passthrough_export(enabled: bool) -> Vec<u8> {
    format!("export SSHAI_PASSTHROUGH={}\n", if enabled { 1 } else { 0 }).into_bytes()
}

/// Rewrite the connection table in place in every pane. This deliberately
/// uses cursor movement instead of appending a second table, so a background
/// host changing from `connecting` to `connected` never pollutes scrollback.
async fn refresh_connection_overviews(
    stdout: &mut tokio::io::Stdout,
    shells: &mut [Option<MultiplexedShell>],
    local: Option<&mut LocalShell>,
    active: Option<Pane>,
    summary: &LocalConnectionSummary,
    labels: &[String],
    statuses: &[String],
) -> Result<()> {
    let mut local = local;
    let overview = connection_overview(summary, shells, labels, statuses, true);
    let repaint = connection_overview_repaint(&overview);
    for shell in shells.iter_mut() {
        if let Some(shell) = shell.as_mut().filter(|shell| shell.open) {
            shell.terminal.process(&repaint);
        }
    }
    if let Some(shell) = local.as_deref_mut().filter(|shell| shell.open) {
        shell.terminal.process(&repaint);
    }
    if active.is_some_and(|pane| pane_is_open(shells, local.as_deref(), pane)) {
        stdout.write_all(&repaint).await?;
        stdout.flush().await?;
    }
    Ok(())
}

fn connection_overview_repaint(overview: &str) -> Vec<u8> {
    let mut output = b"\x1b7".to_vec();
    for (row, line) in overview
        .split("\r\n")
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        output.extend_from_slice(format!("\x1b[{};1H\x1b[2K{line}", row + 1).as_bytes());
    }
    output.extend_from_slice(b"\x1b8");
    output
}

async fn render_pane(
    stdout: &mut tokio::io::Stdout,
    shells: &[Option<MultiplexedShell>],
    local: Option<&LocalShell>,
    pane: Pane,
    panes: usize,
) -> Result<()> {
    let (label, snapshot) = match pane {
        Pane::Local => {
            let shell = local.expect("rendered local shell must exist");
            (LOCAL_PANE_LABEL.to_owned(), shell.terminal.snapshot())
        }
        Pane::Remote(index) => {
            let shell = shells
                .get(index)
                .and_then(Option::as_ref)
                .expect("rendered shell must exist");
            (display_label(&shell.label), shell.terminal.snapshot())
        }
    };
    stdout
        .write_all(
            format!(
                "\x1b]0;sshai [{}/{panes}] {label} — Shift+←/→ · Ctrl+← local\x07",
                pane.position() + 1,
            )
            .as_bytes(),
        )
        .await?;
    stdout.write_all(&snapshot).await?;
    stdout.flush().await?;
    Ok(())
}

async fn present_initial_multiplexed_shell(
    stdout: &mut tokio::io::Stdout,
    display: &[u8],
) -> Result<()> {
    stdout.write_all(display).await?;
    stdout.flush().await?;
    Ok(())
}

fn initial_multiplexer_display(
    label: &str,
    local: &LocalConnectionSummary,
    shells: &[Option<MultiplexedShell>],
    labels: &[String],
    statuses: &[String],
) -> Vec<u8> {
    format!(
        "\x1b]0;sshai [2/{}] {} — Shift+←/→ · Ctrl+← local\x07{}",
        labels.len() + 1,
        display_label(label),
        connection_overview(local, shells, labels, statuses, true),
    )
    .into_bytes()
}

fn connection_overview(
    local: &LocalConnectionSummary,
    shells: &[Option<MultiplexedShell>],
    labels: &[String],
    statuses: &[String],
    ansi: bool,
) -> String {
    let newline = if ansi { "\r\n" } else { "\n" };
    let mut output = if ansi {
        format!("\x1b[1;36m[sshai connections]\x1b[0m{newline}")
    } else {
        format!("sshai connections{newline}")
    };
    let local_line = format!(
        "  1. local: {} ({}){newline}",
        display_label(&local.workspace_root),
        display_label(&local.system_description),
    );
    if ansi {
        output.push_str("\x1b[32m");
        output.push_str(&local_line);
        output.push_str("\x1b[0m");
    } else {
        output.push_str(&local_line);
    }
    for (index, label) in labels.iter().enumerate() {
        let mut line = format!("  {}. {}: ", index + 2, display_label(label));
        if let Some(shell) = shells.get(index).and_then(Option::as_ref) {
            line.push_str(&format!(
                "{} ({})",
                display_label(&shell.workspace_root),
                display_label(&shell.system_description),
            ));
        } else {
            line.push_str(&display_label(
                statuses
                    .get(index)
                    .map(String::as_str)
                    .unwrap_or("connecting"),
            ));
        }
        line.push_str(newline);
        if ansi {
            let color = if shells.get(index).and_then(Option::as_ref).is_some() {
                32
            } else if statuses
                .get(index)
                .is_some_and(|status| status.starts_with("failed:") || status == "closed")
            {
                31
            } else {
                33
            };
            output.push_str(&format!("\x1b[{color}m{line}\x1b[0m"));
        } else {
            output.push_str(&line);
        }
    }
    if ansi {
        output.push_str(MULTIPLEX_SWITCH_HINT);
    }
    output
}

fn single_connection_overview(
    local: &LocalConnectionSummary,
    label: &str,
    workspace_root: &str,
    remote_description: &str,
) -> String {
    let local = format!(
        "  1. local: {} ({})\r\n",
        display_label(&local.workspace_root),
        display_label(&local.system_description),
    );
    let remote = format!(
        "  2. {}: {} ({})\r\n",
        display_label(label),
        display_label(workspace_root),
        display_label(remote_description),
    );
    format!("\x1b[1;36m[sshai connections]\x1b[0m\r\n\x1b[32m{local}\x1b[0m\x1b[32m{remote}\x1b[0m")
}

async fn write_multiplexer_status(
    stdout: &mut tokio::io::Stdout,
    pending: usize,
    statuses: &[String],
) -> Result<()> {
    let failed = statuses
        .iter()
        .filter(|status| status.starts_with("failed:"))
        .count();
    stdout
        .write_all(
            format!(
                "\r\n\x1b[1;33m[sshai] no other connected host ({pending} connecting, {failed} failed)\x1b[0m\r\n"
            )
            .as_bytes(),
        )
        .await?;
    for (index, status) in statuses
        .iter()
        .enumerate()
        .filter(|(_, status)| status.starts_with("failed:"))
    {
        stdout
            .write_all(format!("  {}: {status}\r\n", index + 1).as_bytes())
            .await?;
    }
    stdout.flush().await?;
    Ok(())
}

fn display_label(label: &str) -> String {
    label
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}

fn build_command(path: Option<&str>, arguments: &[String]) -> String {
    let command = arguments
        .iter()
        .map(|argument| shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ");
    match path {
        Some(path) => format!("cd -- {} && exec {command}", shell_quote(path)),
        None => format!("exec {command}"),
    }
}

fn build_shell_command(path: Option<&str>, shell_launcher: Option<&str>) -> String {
    let mut commands = Vec::new();
    if let Some(path) = path {
        commands.push(format!("cd -- {}", shell_quote(path)));
    }
    commands.push(match shell_launcher {
        Some(shell_launcher) => format!("exec {}", shell_quote(shell_launcher)),
        None => "exec \"${SHELL:-/bin/sh}\" -l".to_owned(),
    });
    commands.join(" && ")
}

async fn receive_control_request(agent: &mut Option<RemoteAgent>) -> Result<ControlRequest> {
    match agent {
        Some(agent) => agent.receive().await,
        None => std::future::pending().await,
    }
}

async fn receive_agent_startup(startup: &mut Option<AgentStartup<'_>>) -> Result<RemoteAgent> {
    match startup {
        Some(startup) => startup.as_mut().await,
        None => std::future::pending().await,
    }
}

fn locate_worker_executable(configured: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = configured
        .map(Path::to_owned)
        .or_else(|| std::env::var_os("SSHAI_WORKER").map(PathBuf::from))
    {
        if path.is_file() {
            return Ok(path);
        }
        return Err(SshError::Config(format!(
            "cannot find the local sshai-worker companion at {}; reinstall sshai or set SSHAI_WORKER",
            path.display()
        )));
    }
    let current = std::env::current_exe().map_err(SshError::Io)?;
    let candidates = worker_candidate_paths(&current);
    candidates
        .iter()
        .find(|path| path.is_file())
        .cloned()
        .ok_or_else(|| {
            SshError::Config(format!(
                "cannot find a local sshai-worker companion; tried {}. Reinstall sshai or set SSHAI_WORKER",
                candidates
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
}

fn worker_candidate_paths(current_executable: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if cfg!(target_os = "linux") {
        candidates.push(current_executable.with_file_name("sshai-worker-static"));
    }
    candidates.push(
        current_executable.with_file_name(format!("sshai-worker{}", std::env::consts::EXE_SUFFIX)),
    );
    candidates
}

async fn compress_worker(path: &Path, compression: WorkerCompression) -> Option<Vec<u8>> {
    let mut command = tokio::process::Command::new(compression.name());
    command.args(compression.compress_arguments()).arg(path);
    let output = match tokio::time::timeout(Duration::from_secs(30), command.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            tracing::debug!(%error, format = compression.name(), "local worker compression unavailable");
            return None;
        }
        Err(_) => {
            tracing::debug!(
                format = compression.name(),
                "local worker compression timed out"
            );
            return None;
        }
    };
    if !output.status.success() {
        tracing::debug!(
            format = compression.name(),
            stderr = %String::from_utf8_lossy(&output.stderr).trim(),
            "local worker compression failed"
        );
        return None;
    }
    Some(output.stdout)
}

async fn executable_digest(path: &Path) -> Result<String> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::open(path)?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        Ok::<_, std::io::Error>(hex::encode(digest.finalize()))
    })
    .await
    .map_err(|error| SshError::Agent(format!("binary checksum task failed: {error}")))?
    .map_err(SshError::Io)
}

#[cfg(unix)]
fn random_session_id() -> Result<String> {
    let mut bytes = [0_u8; 32];
    let mut random = std::fs::File::open("/dev/urandom")?;
    random.read_exact(&mut bytes)?;
    Ok(hex::encode(bytes))
}

#[cfg(not(unix))]
fn random_session_id() -> Result<String> {
    Err(SshError::Agent(
        "remote-agent sessions are not implemented on this client platform".to_owned(),
    ))
}

pub(crate) fn join_remote_path(parent: &str, child: &str) -> String {
    format!(
        "{}/{}",
        parent.trim_end_matches('/'),
        child.trim_start_matches('/')
    )
}

/// Bash completion for the session shim, also loaded by zsh through
/// `bashcompinit`. `get` completes remote paths with the shell's own file
/// completion; `put` asks the local client for candidates.
const SESSION_BASH_COMPLETION: &str = r#"_sshai_session_words() {
  _sshai_session_sub=""
  _sshai_session_positional=0
  local index=1 word expect=0
  while [ "$index" -lt "$COMP_CWORD" ]; do
    word=${COMP_WORDS[$index]}
    index=$((index + 1))
    if [ "$expect" = 1 ]; then expect=0; continue; fi
    case "$word" in
      --exclude) expect=1 ;;
      --agent|--file)
        if [ -z "$_sshai_session_sub" ]; then _sshai_session_sub=$word
        else _sshai_session_positional=$((_sshai_session_positional + 1)); fi ;;
      -*|"") ;;
      *)
        if [ -z "$_sshai_session_sub" ]; then _sshai_session_sub=$word
        else _sshai_session_positional=$((_sshai_session_positional + 1)); fi ;;
    esac
  done
}

_sshai_session_complete() {
  local cur side shim
  local _sshai_session_sub _sshai_session_positional
  cur=${COMP_WORDS[COMP_CWORD]}
  COMPREPLY=()
  _sshai_session_words
  if [ -z "$_sshai_session_sub" ]; then
    compopt +o filenames 2>/dev/null
    COMPREPLY=($(compgen -W "get put copy-id info hosts help --agent --file" -- "$cur"))
    return 0
  fi
  case "$cur" in
    -*)
      compopt +o filenames 2>/dev/null
      case "$_sshai_session_sub" in
        get|put) COMPREPLY=($(compgen -W "-r --recursive --exclude --force -h --help" -- "$cur")) ;;
        copy-id) COMPREPLY=($(compgen -W "-i --identity= --authorized-keys" -- "$cur")) ;;
        *) COMPREPLY=($(compgen -W "-h --help" -- "$cur")) ;;
      esac
      return 0
      ;;
  esac
  side=remote
  case "$_sshai_session_sub" in
    get) if [ "$_sshai_session_positional" = 0 ]; then side=remote; else side=local; fi ;;
    put) if [ "$_sshai_session_positional" = 0 ]; then side=local; else side=remote; fi ;;
    copy-id) side=local ;;
    --agent)
      if [ "$_sshai_session_positional" = 0 ]; then side=agents; else side=none; fi ;;
    --file)
      if [ "$_sshai_session_positional" = 0 ]; then side=none; else side=remote; fi ;;
    info|hosts|help) side=none ;;
  esac
  case "$side" in
    local)
      # Completion must never wait for a worker that is still starting.
      if [ -n "$SSHAI_SESSION_SOCKET" ] && [ ! -S "$SSHAI_SESSION_SOCKET" ]; then
        return 0
      fi
      shim=${SSHAI_SESSION_BIN:+$SSHAI_SESSION_BIN/}sshai
      local IFS='
'
      COMPREPLY=($("$shim" --complete-local "$cur" 2>/dev/null))
      ;;
    remote)
      local IFS='
'
      COMPREPLY=($(compgen -f -- "$cur"))
      ;;
    agents)
      compopt +o filenames 2>/dev/null
      COMPREPLY=($(compgen -W "codex claude gemini opencode kimi" -- "$cur"))
      ;;
    *) COMPREPLY=() ;;
  esac
  # Keep the cursor inside a directory candidate instead of adding a space.
  # The loop avoids indexing, which differs between bash and zsh.
  if [ ${#COMPREPLY[@]} -eq 1 ]; then
    local only
    for only in "${COMPREPLY[@]}"; do
      case "$only" in
        */) compopt -o nospace 2>/dev/null ;;
      esac
    done
  fi
  return 0
}

complete -o filenames -F _sshai_session_complete sshai
"#;

/// Native zsh completion: zsh's `bashcompinit` has no `compopt`, so a
/// directory candidate needs `compadd -S ''` to keep the cursor inside it.
const SESSION_ZSH_COMPLETION: &str = r#"_sshai_session_complete() {
  local sub="" side="remote" current word shim
  local -i index=2 expect=0 positional=0
  local -a candidates directories plain
  current=${words[CURRENT]}
  while (( index < CURRENT )); do
    word=${words[index]}
    (( index++ ))
    if (( expect )); then expect=0; continue; fi
    case $word in
      --exclude) expect=1 ;;
      --agent|--file|-*|'')
        case $word in
          --agent|--file)
            if [[ -z $sub ]]; then sub=$word; else (( positional++ )); fi ;;
        esac ;;
      *)
        if [[ -z $sub ]]; then sub=$word; else (( positional++ )); fi ;;
    esac
  done
  if [[ -z $sub ]]; then
    compadd -- get put copy-id info hosts help --agent --file
    return 0
  fi
  if [[ $current == -* ]]; then
    case $sub in
      get|put) compadd -- -r --recursive --exclude --force -h --help ;;
      copy-id) compadd -- -i --identity= --authorized-keys ;;
      *) compadd -- -h --help ;;
    esac
    return 0
  fi
  case $sub in
    get) if (( positional == 0 )); then side=remote; else side=local; fi ;;
    put) if (( positional == 0 )); then side=local; else side=remote; fi ;;
    copy-id) side=local ;;
    --agent) if (( positional == 0 )); then side=agents; else side=none; fi ;;
    --file) if (( positional == 0 )); then side=none; else side=remote; fi ;;
    info|hosts|help) side=none ;;
  esac
  case $side in
    remote) _files ;;
    local)
      if [[ -n $SSHAI_SESSION_SOCKET && ! -S $SSHAI_SESSION_SOCKET ]]; then
        return 0
      fi
      shim=sshai
      [[ -n $SSHAI_SESSION_BIN ]] && shim=$SSHAI_SESSION_BIN/sshai
      candidates=( ${(f)"$($shim --complete-local $current 2>/dev/null)"} )
      directories=( ${(M)candidates:#*/} )
      plain=( ${candidates:#*/} )
      (( $#directories )) && compadd -S '' -- $directories
      (( $#plain )) && compadd -- $plain
      ;;
    agents) compadd -- codex claude gemini opencode kimi ;;
  esac
  return 0
}

compdef _sshai_session_complete sshai
"#;

/// Fish completion for the session shim, loaded through `fish_complete_path`.
const SESSION_FISH_COMPLETION: &str = r#"function __sshai_session_side --description 'which side sshai completes at the cursor'
    set -l tokens (commandline -opc)
    set -l sub ""
    set -l positional 0
    set -l expect 0
    for token in $tokens[2..-1]
        if test $expect -eq 1
            set expect 0
            continue
        end
        switch $token
            case --exclude
                set expect 1
            case --agent --file
                if test -z "$sub"
                    set sub $token
                else
                    set positional (math $positional + 1)
                end
            case '-*'
            case '*'
                if test -z "$sub"
                    set sub $token
                else
                    set positional (math $positional + 1)
                end
        end
    end
    if test -z "$sub"
        echo subcommand
        return 0
    end
    switch $sub
        case get
            if test $positional -eq 0
                echo remote
            else
                echo local
            end
        case put
            if test $positional -eq 0
                echo local
            else
                echo remote
            end
        case copy-id
            echo local
        case --agent
            if test $positional -eq 0
                echo agents
            else
                echo none
            end
        case --file
            if test $positional -eq 0
                echo none
            else
                echo remote
            end
        case info hosts help
            echo none
        case '*'
            echo remote
    end
end

function __sshai_session_local --description 'local path candidates from the sshai client'
    if set -q SSHAI_SESSION_SOCKET; and not test -S "$SSHAI_SESSION_SOCKET"
        return 0
    end
    set -l shim sshai
    if set -q SSHAI_SESSION_BIN
        set shim $SSHAI_SESSION_BIN/sshai
    end
    $shim --complete-local (commandline -ct) 2>/dev/null
end

complete -c sshai -f
complete -c sshai -n 'test (__sshai_session_side) = subcommand' -a 'get put copy-id info hosts help --agent --file'
complete -c sshai -n 'test (__sshai_session_side) = agents' -a 'codex claude gemini opencode kimi'
complete -c sshai -n 'test (__sshai_session_side) = local' -a '(__sshai_session_local)'
complete -c sshai -n 'test (__sshai_session_side) = remote' -a '(__fish_complete_path (commandline -ct))'
complete -c sshai -n 'contains -- (__sshai_session_side) local remote' -s r -l recursive -d 'Transfer a directory'
complete -c sshai -n 'contains -- (__sshai_session_side) local remote' -l exclude -r -d 'Skip a name or relative subtree'
complete -c sshai -n 'contains -- (__sshai_session_side) local remote' -l force -d 'Replace an existing destination'
"#;

fn session_support_files(
    session_dir: &str,
    remote_worker: &str,
    session_id: &str,
) -> Vec<(String, String, u32)> {
    let bin_dir = join_remote_path(session_dir, "bin");
    let zsh_dir = join_remote_path(session_dir, "zsh");
    let socket = join_remote_path(session_dir, "agent.sock");
    let error_file = join_remote_path(session_dir, "agent.error");
    let shim = join_remote_path(&bin_dir, "sshai");
    let launcher = join_remote_path(session_dir, "launch-shell");
    let bashrc = join_remote_path(session_dir, "bashrc");
    let shrc = join_remote_path(session_dir, "shrc");
    let completion = join_remote_path(session_dir, "completion.sh");
    let zsh_completion = join_remote_path(&zsh_dir, "completion.zsh");
    let fish_completions = join_remote_path(&join_remote_path(session_dir, "fish"), "completions");

    let quoted_socket = shell_quote(&socket);
    let quoted_error = shell_quote(&error_file);
    let shim_body = format!(
        "#!/bin/sh\n\
attempt=0\n\
if [ ! -S {quoted_socket} ]; then printf '%s\\n' 'sshai: worker is initializing...' >&2; fi\n\
while [ ! -S {quoted_socket} ]; do\n\
  if [ -f {quoted_error} ]; then cat {quoted_error} >&2; exit 75; fi\n\
  attempt=$((attempt + 1))\n\
  if [ \"$attempt\" -ge 30 ]; then printf '%s\\n' 'sshai: worker is unavailable' >&2; exit 75; fi\n\
  sleep 1\n\
done\n\
exec {} invoke --session-id {} --socket {quoted_socket} -- \"$@\"\n",
        shell_quote(remote_worker),
        shell_quote(session_id),
    );

    let quoted_bin = shell_quote(&bin_dir);
    let quoted_bashrc = shell_quote(&bashrc);
    let quoted_shrc = shell_quote(&shrc);
    let quoted_zsh_dir = shell_quote(&zsh_dir);
    let quoted_completion = shell_quote(&completion);
    let fish_init = shell_quote(&format!(
        "set -gx SSHAI_SESSION_BIN {}; set -gx SSHAI_SESSION_SOCKET {}; set -gx PATH {} $PATH; set -g fish_complete_path {} $fish_complete_path",
        fish_quote(&bin_dir),
        fish_quote(&socket),
        fish_quote(&bin_dir),
        fish_quote(&fish_completions),
    ));
    let launcher_body = format!(
        "#!/bin/sh\n\
shell=${{SHELL:-/bin/sh}}\n\
case ${{shell##*/}} in\n\
  bash) exec \"$shell\" --noprofile --rcfile {quoted_bashrc} -i ;;\n\
  zsh) export SSHAI_ORIGINAL_ZDOTDIR=\"${{ZDOTDIR:-$HOME}}\"; export ZDOTDIR={quoted_zsh_dir}; exec \"$shell\" -l ;;\n\
  fish) exec \"$shell\" --login --init-command {fish_init} ;;\n\
  *) export ENV={quoted_shrc}; exec \"$shell\" -i ;;\n\
esac\n"
    );
    let bashrc_body = format!(
        "# sshai: emulate bash login startup, then install the session shim last.\n\
if [ -r /etc/profile ]; then . /etc/profile; fi\n\
if [ -r \"$HOME/.bash_profile\" ]; then . \"$HOME/.bash_profile\"\n\
elif [ -r \"$HOME/.bash_login\" ]; then . \"$HOME/.bash_login\"\n\
elif [ -r \"$HOME/.profile\" ]; then . \"$HOME/.profile\"\n\
fi\n\
export PATH={quoted_bin}:\"$PATH\"\n\
export SSHAI_SESSION_BIN={quoted_bin}\n\
export SSHAI_SESSION_SOCKET={quoted_socket}\n\
if [ -r {quoted_completion} ]; then . {quoted_completion}; fi\n"
    );
    let shrc_body = format!(
        "if [ -r /etc/profile ]; then . /etc/profile; fi\n\
if [ -r \"$HOME/.profile\" ]; then . \"$HOME/.profile\"; fi\n\
export PATH={quoted_bin}:\"$PATH\"\n\
export SSHAI_SESSION_BIN={quoted_bin}\n\
export SSHAI_SESSION_SOCKET={quoted_socket}\n"
    );

    let mut files = vec![
        (shim, shim_body, 0o700),
        (launcher, launcher_body, 0o700),
        (bashrc, bashrc_body, 0o600),
        (shrc, shrc_body, 0o600),
        (completion, SESSION_BASH_COMPLETION.to_owned(), 0o600),
        (
            zsh_completion.clone(),
            SESSION_ZSH_COMPLETION.to_owned(),
            0o600,
        ),
        (
            join_remote_path(&fish_completions, "sshai.fish"),
            SESSION_FISH_COMPLETION.to_owned(),
            0o600,
        ),
    ];
    for name in [".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout"] {
        let mut body = format!(
            "original=\"${{SSHAI_ORIGINAL_ZDOTDIR:-$HOME}}/{name}\"\n\
if [[ -r \"$original\" ]]; then source \"$original\"; fi\n\
unset original\n\
export ZDOTDIR={quoted_zsh_dir}\n\
export PATH={quoted_bin}:$PATH\n\
export SSHAI_SESSION_BIN={quoted_bin}\n\
export SSHAI_SESSION_SOCKET={quoted_socket}\n"
        );
        // zsh reuses the bash function, but only once its own completion
        // system is initialized by the user's startup files.
        if name == ".zshrc" {
            let dump = shell_quote(&join_remote_path(&zsh_dir, "zcompdump"));
            let quoted_zsh_completion = shell_quote(&zsh_completion);
            body.push_str(&format!(
                "if ! whence -w compdef > /dev/null 2>&1; then\n\
  autoload -Uz compinit && compinit -i -d {dump}\n\
fi\n\
if whence -w compdef > /dev/null 2>&1; then\n\
  autoload -Uz _files > /dev/null 2>&1\n\
  source {quoted_zsh_completion}\n\
fi\n"
            ));
        }
        files.push((join_remote_path(&zsh_dir, name), body, 0o600));
    }
    for (name, arguments) in [
        ("code", "--file code"),
        ("codex", "--agent codex"),
        ("claude", "--agent claude"),
        ("gemini", "--agent gemini"),
        ("opencode", "--agent opencode"),
        ("kimi", "--agent kimi"),
    ] {
        let body = [
            "#!/bin/sh\n",
            "if [ \"${SSHAI_PASSTHROUGH:-0}\" = 1 ]; then\n",
            "  PATH=\"${PATH#\"$SSHAI_SESSION_BIN:\"}\"; export PATH\n",
            "  real=$(command -v ",
            name,
            " 2>/dev/null || true)\n",
            "  if [ -z \"$real\" ]; then printf '%s\\n' 'sshai: remote command ",
            name,
            " is not installed' >&2; exit 127; fi\n",
            "  exec \"$real\" \"$@\"\n",
            "fi\n",
            &format!("exec \"$SSHAI_SESSION_BIN/sshai\" {arguments} \"$@\"\n"),
        ]
        .concat();
        files.push((join_remote_path(&bin_dir, name), body, 0o700));
    }
    files
}

fn fish_quote(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn control_help() -> &'static str {
    "sshai session commands:\n\
  sshai --agent NAME [-- AGENT_ARGUMENTS...]  (codex, claude, gemini, opencode, ...)\n\
  sshai --file PROGRAM REMOTE_FILE  (edit locally; Ctrl+Q exits and keeps syncing)\n\
  sshai copy-id [-i LOCAL_KEY] [--authorized-keys REMOTE_PATH]\n\
  sshai get [-r] [--exclude PATTERN] [--force] REMOTE [LOCAL]\n\
  sshai put [-r] [--exclude PATTERN] [--force] LOCAL [REMOTE]\n\
  sshai info\n\
  sshai hosts\n\
  sshai help\n\
\n\
Agent names after --agent are resolved on the local machine. Known agents use built-in adapters;\n\
other executables must advertise MCP support and receive the generic MCP environment.\n\
`get` and `put` transfer over this session, so they never authenticate again. Directories\n\
need -r, --exclude is repeatable, and --force overwrites an existing destination. Remote paths\n\
are relative to the current remote directory, local paths to the directory sshai started in.\n\
These commands run through the encrypted session control channel. LOCAL_KEY is\n\
read on your local machine; quote paths containing '~' to prevent the remote\n\
shell from expanding them first, for example: sshai copy-id -i '~/.ssh/id_ed25519.pub'\n\
Shift+Left/Right switches hosts. Ctrl+Left always selects the local shell pane, in single-host\n\
and multi-host sessions alike; Ctrl+Right returns to the next remote host.\n\
Ctrl+Shift+Left/Right and Ctrl+] followed by Left/Right (or h/l) also switch panes.\n\
Ctrl+\\\\ toggles smart command wrappers; passthrough mode uses the remote commands.\n"
}

const LOCAL_COMPLETION_LIMIT: usize = 500;

fn control_complete_local(arguments: &[String], local_root: Option<&Path>) -> Result<String> {
    let prefix = arguments.first().map(String::as_str).unwrap_or_default();
    let cwd = match local_root {
        Some(root) => root.to_owned(),
        None => env::current_dir().map_err(SshError::Io)?,
    };
    let mut candidates = local_path_completions(prefix, &cwd)?;
    if candidates.is_empty() {
        return Ok(String::new());
    }
    candidates.push(String::new());
    Ok(candidates.join("\n"))
}

/// Local path candidates for a prefix typed in the remote shell: the typed
/// directory part is kept so the shell can insert a candidate verbatim, and
/// directories keep a trailing `/` so completion can continue into them.
fn local_path_completions(prefix: &str, cwd: &Path) -> Result<Vec<String>> {
    let (typed_directory, partial) = match prefix.rfind('/') {
        Some(index) => (&prefix[..=index], &prefix[index + 1..]),
        None => ("", prefix),
    };
    let base = if typed_directory.is_empty() {
        cwd.to_path_buf()
    } else {
        let expanded = expand_local_home(typed_directory)?;
        if expanded.is_absolute() {
            expanded
        } else {
            cwd.join(expanded)
        }
    };
    let mut candidates = Vec::new();
    // An unreadable directory simply has no candidates.
    let Ok(entries) = std::fs::read_dir(&base) else {
        return Ok(candidates);
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(partial) {
            continue;
        }
        // Hidden entries appear once the leading dot has been typed.
        if name.starts_with('.') && !partial.starts_with('.') {
            continue;
        }
        let directory = entry
            .file_type()
            .map(|kind| kind.is_dir())
            .unwrap_or_default()
            || entry.path().is_dir();
        let suffix = if directory { "/" } else { "" };
        candidates.push(format!("{typed_directory}{name}{suffix}"));
    }
    candidates.sort();
    candidates.truncate(LOCAL_COMPLETION_LIMIT);
    Ok(candidates)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransferDirection {
    Get,
    Put,
}

impl TransferDirection {
    fn name(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Put => "put",
        }
    }

    fn usage(self) -> &'static str {
        match self {
            Self::Get => "usage: sshai get [-r] [--exclude PATTERN] [--force] REMOTE [LOCAL]\n",
            Self::Put => "usage: sshai put [-r] [--exclude PATTERN] [--force] LOCAL [REMOTE]\n",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct TransferArguments {
    source: String,
    destination: String,
    recursive: bool,
    force: bool,
    excludes: Vec<String>,
}

fn parse_transfer_arguments(
    direction: TransferDirection,
    arguments: &[String],
) -> Result<TransferArguments> {
    let mut recursive = false;
    let mut force = false;
    let mut excludes = Vec::new();
    let mut positional = Vec::new();
    let mut options_ended = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if options_ended || !argument.starts_with('-') || argument == "-" {
            positional.push(argument.to_owned());
            index += 1;
            continue;
        }
        match argument {
            "--" => options_ended = true,
            "-r" | "-R" | "--recursive" => recursive = true,
            "-f" | "--force" => force = true,
            "--exclude" => {
                index += 1;
                let pattern = arguments.get(index).ok_or_else(|| {
                    SshError::Config(format!("--exclude needs a PATTERN; {}", direction.usage()))
                })?;
                excludes.push(pattern.clone());
            }
            value if value.starts_with("--exclude=") => {
                excludes.push(value["--exclude=".len()..].to_owned());
            }
            value => {
                return Err(SshError::Config(format!(
                    "unknown option {value:?}; {}",
                    direction.usage()
                )));
            }
        }
        index += 1;
    }
    let (source, destination) = match positional.as_slice() {
        // A missing destination means "here", resolved against the current
        // directory on the receiving side.
        [source] => (source.clone(), ".".to_owned()),
        [source, destination] => (source.clone(), destination.clone()),
        _ => return Err(SshError::Config(direction.usage().trim_end().to_owned())),
    };
    if source.is_empty() || destination.is_empty() {
        return Err(SshError::Config(format!(
            "paths must not be empty; {}",
            direction.usage()
        )));
    }
    Ok(TransferArguments {
        source,
        destination,
        recursive,
        force,
        excludes,
    })
}

/// Resolve a remote transfer path to an absolute one: `~` against the remote
/// home directory, anything else relative against the shell's current directory.
fn resolve_remote_transfer_path(remote_cwd: Option<&str>, remote_home: &str, path: &str) -> String {
    if path.starts_with('/') {
        let trimmed = path.trim_end_matches('/');
        return if trimmed.is_empty() {
            "/".to_owned()
        } else {
            trimmed.to_owned()
        };
    }
    let (base, relative) = match path.strip_prefix('~') {
        Some("") => (remote_home, ""),
        Some(rest) if rest.starts_with('/') => (remote_home, rest.trim_start_matches('/')),
        _ => {
            let base = match remote_cwd {
                Some(cwd) if !cwd.is_empty() && cwd != "." => cwd,
                _ => remote_home,
            };
            (base, path)
        }
    };
    let relative = relative
        .trim_start_matches("./")
        .trim_end_matches('/')
        .trim_start_matches('/');
    if relative.is_empty() || relative == "." {
        return base.trim_end_matches('/').to_owned();
    }
    join_remote_path(base, relative)
}

/// Drop `.` components so that a `.` destination reads as the directory itself.
fn clean_local_path(path: PathBuf) -> PathBuf {
    let cleaned = path
        .components()
        .filter(|component| !matches!(component, std::path::Component::CurDir))
        .collect::<PathBuf>();
    if cleaned.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        cleaned
    }
}

fn remote_transfer_name(remote: &str) -> Result<String> {
    remote
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            SshError::Config(format!(
                "cannot take a file name from the remote path {remote:?}"
            ))
        })
}

fn local_transfer_name(local: &Path) -> Result<String> {
    local
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or_else(|| {
            SshError::Config(format!(
                "cannot take a file name from the local path {}",
                local.display()
            ))
        })
}

fn parse_copy_id_arguments(arguments: &[String]) -> Result<(Option<PathBuf>, Option<String>)> {
    let mut identity = None;
    let mut authorized_keys = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        match argument.as_str() {
            "-i" | "--identity" => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| SshError::Config(format!("{argument} requires a local path")))?;
                identity = Some(expand_local_home(value)?);
            }
            "--authorized-keys" => {
                index += 1;
                let value = arguments.get(index).ok_or_else(|| {
                    SshError::Config("--authorized-keys requires a remote path".to_owned())
                })?;
                authorized_keys = Some(value.clone());
            }
            "-h" | "--help" => {
                return Err(SshError::Config(
                    "usage: sshai copy-id [-i LOCAL_KEY] [--authorized-keys REMOTE_PATH]"
                        .to_owned(),
                ));
            }
            value if value.starts_with("--identity=") => {
                identity = Some(expand_local_home(&value["--identity=".len()..])?);
            }
            value if value.starts_with("--authorized-keys=") => {
                authorized_keys = Some(value["--authorized-keys=".len()..].to_owned());
            }
            _ => {
                return Err(SshError::Config(format!(
                    "unknown copy-id argument {argument:?}; try `sshai help`"
                )));
            }
        }
        index += 1;
    }
    Ok((identity, authorized_keys))
}

fn expand_local_home(value: &str) -> Result<PathBuf> {
    if value == "~" {
        return dirs::home_dir()
            .ok_or_else(|| SshError::Config("cannot determine local home directory".to_owned()));
    }
    if let Some(rest) = value.strip_prefix("~/") {
        let home = dirs::home_dir()
            .ok_or_else(|| SshError::Config("cannot determine local home directory".to_owned()))?;
        return Ok(home.join(rest));
    }
    Ok(PathBuf::from(value))
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(unix)]
pub(crate) struct RawTerminalGuard {
    original: nix::sys::termios::Termios,
    original_flags: i32,
}

#[cfg(unix)]
impl RawTerminalGuard {
    pub(crate) fn activate() -> Result<Self> {
        use nix::sys::termios::{SetArg, cfmakeraw, tcgetattr, tcsetattr};

        let stdin = std::io::stdin();
        let original = tcgetattr(&stdin).map_err(std::io::Error::other)?;
        let mut raw = original.clone();
        cfmakeraw(&mut raw);
        tcsetattr(&stdin, SetArg::TCSANOW, &raw).map_err(std::io::Error::other)?;
        // Tokio's AsyncFd requires a non-blocking descriptor. Keeping this in
        // the same guard ensures both terminal attributes and flags are restored.
        // SAFETY: fcntl operates on the process-owned stdin descriptor.
        let original_flags =
            unsafe { nix::libc::fcntl(nix::libc::STDIN_FILENO, nix::libc::F_GETFL) };
        if original_flags < 0 {
            let _ = tcsetattr(&stdin, SetArg::TCSANOW, &original);
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: F_SETFL changes flags on the valid stdin descriptor.
        let result = unsafe {
            nix::libc::fcntl(
                nix::libc::STDIN_FILENO,
                nix::libc::F_SETFL,
                original_flags | nix::libc::O_NONBLOCK,
            )
        };
        if result < 0 {
            let _ = tcsetattr(&stdin, SetArg::TCSANOW, &original);
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            original,
            original_flags,
        })
    }
}

#[cfg(unix)]
impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        use nix::sys::termios::{SetArg, tcsetattr};
        // SAFETY: restores flags captured from the valid stdin descriptor.
        let _ = unsafe {
            nix::libc::fcntl(
                nix::libc::STDIN_FILENO,
                nix::libc::F_SETFL,
                self.original_flags,
            )
        };
        let _ = tcsetattr(std::io::stdin(), SetArg::TCSANOW, &self.original);
    }
}

#[cfg(not(unix))]
pub(crate) struct RawTerminalGuard;

#[cfg(not(unix))]
impl RawTerminalGuard {
    pub(crate) fn activate() -> Result<Self> {
        Err(SshError::Config(
            "interactive terminal mode is not implemented on this platform".to_owned(),
        ))
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct StdinDescriptor;

#[cfg(unix)]
impl std::os::fd::AsRawFd for StdinDescriptor {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        nix::libc::STDIN_FILENO
    }
}

#[cfg(unix)]
pub(crate) struct InteractiveStdin {
    inner: tokio::io::unix::AsyncFd<StdinDescriptor>,
}

#[cfg(unix)]
impl InteractiveStdin {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            inner: tokio::io::unix::AsyncFd::new(StdinDescriptor)?,
        })
    }

    pub(crate) async fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut readiness = self.inner.readable().await?;
            let result = readiness.try_io(|_| {
                // SAFETY: buffer is writable for its full length, and stdin is
                // a valid non-blocking descriptor while RawTerminalGuard lives.
                let read = unsafe {
                    nix::libc::read(
                        nix::libc::STDIN_FILENO,
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                    )
                };
                if read < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(read as usize)
                }
            });
            match result {
                Ok(Ok(read)) => return Ok(read),
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Err(error),
                Err(_) => continue,
            }
        }
    }
}

#[cfg(not(unix))]
pub(crate) struct InteractiveStdin {
    inner: tokio::io::Stdin,
}

#[cfg(not(unix))]
impl InteractiveStdin {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            inner: tokio::io::stdin(),
        })
    }

    pub(crate) async fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buffer).await
    }
}

#[cfg(unix)]
pub(crate) fn terminal_size() -> (u32, u32) {
    let mut size = nix::libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ writes to a valid winsize pointer and does not retain it.
    let result =
        unsafe { nix::libc::ioctl(nix::libc::STDOUT_FILENO, nix::libc::TIOCGWINSZ, &mut size) };
    if result == 0 && size.ws_col > 0 && size.ws_row > 0 {
        (u32::from(size.ws_col), u32::from(size.ws_row))
    } else {
        (80, 24)
    }
}

#[cfg(not(unix))]
pub(crate) fn terminal_size() -> (u32, u32) {
    (80, 24)
}

#[cfg(unix)]
pub(crate) struct ResizeEvents(tokio::signal::unix::Signal);

#[cfg(unix)]
impl ResizeEvents {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self(tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::window_change(),
        )?))
    }

    pub(crate) async fn recv(&mut self) {
        self.0.recv().await;
    }
}

#[cfg(not(unix))]
pub(crate) struct ResizeEvents;

#[cfg(not(unix))]
impl ResizeEvents {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self)
    }

    pub(crate) async fn recv(&mut self) {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_remote_arguments() {
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(
            build_command(
                Some("/srv/my app"),
                &["printf".into(), "%s\\n".into(), "a b".into()]
            ),
            "cd -- '/srv/my app' && exec 'printf' '%s\\n' 'a b'"
        );
    }

    #[test]
    fn shell_launcher_and_workspace_are_quoted() {
        assert_eq!(
            build_shell_command(Some("/srv/my app"), Some("/tmp/session's/launch-shell")),
            "cd -- '/srv/my app' && exec '/tmp/session'\\''s/launch-shell'"
        );
    }

    #[test]
    fn linux_prefers_the_portable_static_worker() {
        let candidates = worker_candidate_paths(Path::new("/opt/sshai/bin/sshai"));
        if cfg!(target_os = "linux") {
            assert_eq!(
                candidates[0],
                PathBuf::from("/opt/sshai/bin/sshai-worker-static")
            );
        }
        assert!(
            candidates
                .last()
                .unwrap()
                .ends_with(format!("sshai-worker{}", std::env::consts::EXE_SUFFIX))
        );
    }

    #[test]
    fn progressive_session_shim_waits_for_the_worker_socket() {
        let files = session_support_files(
            "/tmp/session",
            "/tmp/cache/sshai-worker",
            "0123456789abcdef0123456789abcdef",
        );
        let (_, shim, mode) = files
            .iter()
            .find(|(path, _, _)| path.ends_with("/bin/sshai"))
            .unwrap();

        assert_eq!(*mode, 0o700);
        assert!(shim.contains("worker is initializing"));
        assert!(shim.contains("while [ ! -S '/tmp/session/agent.sock' ]"));
        assert!(shim.contains("'/tmp/cache/sshai-worker' invoke"));
        let codex = files
            .iter()
            .find(|(path, _, _)| path.ends_with("/bin/codex"))
            .map(|(_, body, _)| body.as_str())
            .unwrap();
        assert!(codex.contains("SSHAI_PASSTHROUGH"));
        assert!(codex.contains("--agent codex"));
    }

    #[test]
    fn connection_overview_repaint_rewrites_in_place_without_scrollback() {
        let overview =
            "\x1b[1;36m[sshai connections]\r\n  1. local: /home\r\n  2. host: connected\r\n";
        let repaint = connection_overview_repaint(overview);
        assert!(repaint.starts_with(b"\x1b7\x1b[1;1H\x1b[2K"));
        assert!(
            repaint
                .windows(b"host: connected".len())
                .any(|window| window == b"host: connected")
        );
        assert!(repaint.ends_with(b"\x1b8"));
        assert!(!repaint.starts_with(b"\r\n"));
    }

    #[test]
    fn session_files_install_path_completion_for_every_shell() {
        let files = session_support_files(
            "/tmp/session",
            "/tmp/cache/sshai-worker",
            "0123456789abcdef0123456789abcdef",
        );
        let body = |suffix: &str| {
            files
                .iter()
                .find(|(path, _, _)| path.ends_with(suffix))
                .map(|(_, body, _)| body.clone())
                .unwrap_or_else(|| panic!("missing session file {suffix}"))
        };

        let bash = body("/completion.sh");
        assert!(bash.contains("complete -o filenames -F _sshai_session_complete sshai"));
        // `put` asks the client for local candidates; `get` uses the remote shell.
        assert!(bash.contains("--complete-local"));
        assert!(bash.contains("compgen -f -- \"$cur\""));

        let zsh = body("/zsh/completion.zsh");
        assert!(zsh.contains("compdef _sshai_session_complete sshai"));
        assert!(zsh.contains("compadd -S '' -- $directories"));

        let fish = body("/fish/completions/sshai.fish");
        assert!(fish.contains("complete -c sshai"));
        assert!(fish.contains("__sshai_session_local"));

        assert!(body("/bashrc").contains(". '/tmp/session/completion.sh'"));
        assert!(body("/zsh/.zshrc").contains("source '/tmp/session/zsh/completion.zsh'"));
        assert!(!body("/zsh/.zshenv").contains("completion.zsh"));
        let launcher = body("/launch-shell");
        assert!(launcher.contains("set -g fish_complete_path"));
        assert!(launcher.contains("/tmp/session/fish/completions"));
    }

    #[test]
    fn completes_local_paths_for_the_remote_shell() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        std::fs::create_dir(root.join("b_dir")).unwrap();
        std::fs::write(root.join("b_dir/inner.txt"), b"x").unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        std::fs::write(root.join(".hidden"), b"x").unwrap();

        // Directories keep a trailing slash so completion can descend.
        assert_eq!(
            local_path_completions("", root).unwrap(),
            vec!["a.txt".to_owned(), "b_dir/".to_owned()]
        );
        // Hidden entries appear only once the dot is typed.
        assert_eq!(
            local_path_completions(".", root).unwrap(),
            vec![".hidden".to_owned()]
        );
        assert_eq!(
            local_path_completions("b", root).unwrap(),
            vec!["b_dir/".to_owned()]
        );
        // The typed directory part comes back with the candidate.
        assert_eq!(
            local_path_completions("b_dir/", root).unwrap(),
            vec!["b_dir/inner.txt".to_owned()]
        );
        assert_eq!(
            local_path_completions("b_dir/i", root).unwrap(),
            vec!["b_dir/inner.txt".to_owned()]
        );
        let absolute = format!("{}/a", root.display());
        assert_eq!(
            local_path_completions(&absolute, root).unwrap(),
            vec![format!("{}/a.txt", root.display())]
        );
        assert!(local_path_completions("missing/", root).unwrap().is_empty());
        assert!(local_path_completions("zz", root).unwrap().is_empty());
    }

    #[test]
    fn parses_session_transfer_arguments() {
        let arguments = [
            "-r",
            "--exclude",
            ".git",
            "--exclude=target",
            "-f",
            "/srv/app",
            "app",
        ]
        .map(str::to_owned)
        .to_vec();
        let parsed = parse_transfer_arguments(TransferDirection::Get, &arguments).unwrap();
        assert_eq!(
            parsed,
            TransferArguments {
                source: "/srv/app".to_owned(),
                destination: "app".to_owned(),
                recursive: true,
                force: true,
                excludes: vec![".git".to_owned(), "target".to_owned()],
            }
        );

        // A single path means "into the current directory on the other side".
        let single =
            parse_transfer_arguments(TransferDirection::Put, &["dist/app".to_owned()]).unwrap();
        assert_eq!(single.destination, ".");
        assert!(!single.recursive && !single.force);

        // Paths after -- keep their leading dash.
        let escaped = parse_transfer_arguments(
            TransferDirection::Get,
            &["--".to_owned(), "-weird-name".to_owned()],
        )
        .unwrap();
        assert_eq!(escaped.source, "-weird-name");

        assert!(
            parse_transfer_arguments(TransferDirection::Get, &["--zip".to_owned()])
                .unwrap_err()
                .to_string()
                .contains("unknown option")
        );
        assert!(
            parse_transfer_arguments(TransferDirection::Get, &["--exclude".to_owned()]).is_err()
        );
        assert!(parse_transfer_arguments(TransferDirection::Get, &[]).is_err());
        assert!(
            parse_transfer_arguments(
                TransferDirection::Get,
                &["a".to_owned(), "b".to_owned(), "c".to_owned()]
            )
            .is_err()
        );
    }

    #[test]
    fn resolves_session_transfer_remote_paths() {
        let cwd = Some("/srv/app");
        let home = "/home/deploy";
        assert_eq!(
            resolve_remote_transfer_path(cwd, home, "config.toml"),
            "/srv/app/config.toml"
        );
        assert_eq!(
            resolve_remote_transfer_path(cwd, home, "./logs/today.log"),
            "/srv/app/logs/today.log"
        );
        assert_eq!(resolve_remote_transfer_path(cwd, home, "."), "/srv/app");
        assert_eq!(
            resolve_remote_transfer_path(cwd, home, "~/backup.tar"),
            "/home/deploy/backup.tar"
        );
        assert_eq!(resolve_remote_transfer_path(cwd, home, "~"), "/home/deploy");
        assert_eq!(
            resolve_remote_transfer_path(cwd, home, "/etc/hosts"),
            "/etc/hosts"
        );
        assert_eq!(
            resolve_remote_transfer_path(cwd, home, "/var/log/"),
            "/var/log"
        );
        assert_eq!(resolve_remote_transfer_path(cwd, home, "/"), "/");
        // Without a reported shell directory, relative paths follow the remote home.
        assert_eq!(
            resolve_remote_transfer_path(None, home, "notes.md"),
            "/home/deploy/notes.md"
        );
    }

    #[test]
    fn cleans_current_directory_components_from_local_paths() {
        assert_eq!(
            clean_local_path(PathBuf::from("/home/ka/./dist/./app")),
            PathBuf::from("/home/ka/dist/app")
        );
        assert_eq!(
            clean_local_path(PathBuf::from("/home/ka/.")),
            PathBuf::from("/home/ka")
        );
        assert_eq!(clean_local_path(PathBuf::from(".")), PathBuf::from("."));
    }

    #[test]
    fn derives_transfer_names_for_directory_destinations() {
        assert_eq!(
            remote_transfer_name("/srv/app/config.toml").unwrap(),
            "config.toml"
        );
        assert_eq!(remote_transfer_name("/srv/app/").unwrap(), "app");
        assert!(remote_transfer_name("/").is_err());
        assert_eq!(
            local_transfer_name(Path::new("/home/ka/dist/app")).unwrap(),
            "app"
        );
        assert!(local_transfer_name(Path::new("/")).is_err());
    }

    #[test]
    fn parses_remote_copy_id_arguments_as_local_paths() {
        let (identity, authorized_keys) = parse_copy_id_arguments(&[
            "--identity=/tmp/local key.pub".to_owned(),
            "--authorized-keys=.ssh/custom_keys".to_owned(),
        ])
        .unwrap();
        assert_eq!(identity, Some(PathBuf::from("/tmp/local key.pub")));
        assert_eq!(authorized_keys.as_deref(), Some(".ssh/custom_keys"));
    }

    #[test]
    fn parses_split_multi_host_switch_sequences_without_forwarding_them() {
        let mut parser = SwitchInputParser::default();
        let first = parser.feed(b"echo ok\n\x1b[1;", true);
        assert!(matches!(first.as_slice(), [ParsedInput::Data(data)] if data == b"echo ok\n"));
        assert!(parser.has_pending());

        let second = parser.feed(b"6Ctail", true);
        assert!(matches!(
            second.as_slice(),
            [ParsedInput::Switch(InputAction::Next), ParsedInput::Data(data)] if data == b"tail"
        ));
        assert!(!parser.has_pending());

        assert!(matches!(
            parser.feed(SWITCH_PREVIOUS, true).as_slice(),
            [ParsedInput::Switch(InputAction::Previous)]
        ));
    }

    #[test]
    fn parses_terminator_safe_multi_host_switch_prefix() {
        let mut parser = SwitchInputParser::default();
        assert!(parser.feed(&[SWITCH_PREFIX], true).is_empty());
        assert_eq!(parser.pending_timeout(), SWITCH_PREFIX_TIMEOUT);
        assert!(matches!(
            parser.feed(b"\x1b[C", true).as_slice(),
            [ParsedInput::Switch(InputAction::Next)]
        ));
        assert!(matches!(
            parser.feed(b"\x1dh", true).as_slice(),
            [ParsedInput::Switch(InputAction::Previous)]
        ));
        assert!(matches!(
            parser.feed(LITERAL_SWITCH_PREFIX, true).as_slice(),
            [ParsedInput::Data(data)] if data == &[SWITCH_PREFIX]
        ));
        assert!(matches!(
            parser.feed(&[PASSTHROUGH_TOGGLE], true).as_slice(),
            [ParsedInput::TogglePassthrough]
        ));
    }

    #[test]
    fn parses_single_chord_shift_arrow_host_switches() {
        let mut parser = SwitchInputParser::default();
        assert!(matches!(
            parser.feed(SWITCH_PREVIOUS_SHIFT_LEFT, true).as_slice(),
            [ParsedInput::Switch(InputAction::Previous)]
        ));
        assert!(matches!(
            parser.feed(SWITCH_NEXT_SHIFT_RIGHT, true).as_slice(),
            [ParsedInput::Switch(InputAction::Next)]
        ));
        assert!(parser.feed(b"\x1b", true).is_empty());
        assert!(matches!(
            parser.feed(b"[1;2C", true).as_slice(),
            [ParsedInput::Switch(InputAction::Next)]
        ));
    }

    #[test]
    fn forwards_incomplete_escape_sequence_after_timeout() {
        let mut parser = SwitchInputParser::default();
        assert!(parser.feed(b"\x1b", true).is_empty());
        assert_eq!(parser.flush().as_deref(), Some(b"\x1b".as_slice()));
    }

    #[test]
    fn multi_host_virtual_terminal_restores_only_the_visible_screen() {
        let mut terminal = VirtualTerminal::new(8, 2);
        terminal.process(b"first\r\nsecond\r\ntail");

        let snapshot = terminal.snapshot();
        let mut restored = vt100::Parser::new(2, 8, 0);
        restored.process(&snapshot);

        assert_eq!(restored.screen().contents(), "second\ntail");
        assert!(!snapshot.windows(5).any(|window| window == b"first"));
    }

    #[test]
    fn multi_host_virtual_terminal_includes_switch_hint_once() {
        let mut terminal = VirtualTerminal::new(80, 24);
        terminal.process(MULTIPLEX_SWITCH_HINT.as_bytes());
        terminal.process(b"prompt> ");

        let snapshot = terminal.snapshot();
        let mut restored = vt100::Parser::new(24, 80, 0);
        restored.process(&snapshot);
        let contents = restored.screen().contents();

        assert_eq!(
            contents
                .matches("[sshai] Shift+Left/Right switches hosts")
                .count(),
            1
        );
        assert!(contents.contains("prompt>"));
    }

    #[test]
    fn initial_multi_host_display_preserves_the_existing_terminal() {
        let local = LocalConnectionSummary {
            workspace_root: "/home/test".to_owned(),
            system_description: "Test Linux, x86_64, 4 GiB".to_owned(),
        };
        let labels = vec!["host1".to_owned(), "host2".to_owned()];
        let statuses = vec!["connected".to_owned(), "connecting".to_owned()];
        let shells = (0..2)
            .map(|_| None)
            .collect::<Vec<Option<MultiplexedShell>>>();
        let display = initial_multiplexer_display("host1", &local, &shells, &labels, &statuses);

        assert!(display.windows(7).any(|window| window == b"Shift+L"));
        let text = String::from_utf8_lossy(&display);
        assert!(text.contains("1. local: /home/test (Test Linux, x86_64, 4 GiB)"));
        assert!(text.contains("3. host2: connecting"));
        assert!(text.contains("\x1b[32m  1. local:"));
        assert!(text.contains("\x1b[33m  3. host2: connecting"));
        assert!(!display.windows(4).any(|window| window == b"\x1b[2J"));
        assert!(!display.windows(4).any(|window| window == b"\x1b[3J"));
        assert!(!display.windows(3).any(|window| window == b"\x1b[H"));
    }

    #[test]
    fn single_connection_overview_colors_connected_rows() {
        let local = LocalConnectionSummary {
            workspace_root: "/home/test".to_owned(),
            system_description: "Ubuntu, x86_64, 4 GiB".to_owned(),
        };
        let display = single_connection_overview(
            &local,
            "root@example",
            "/root/test",
            "Ubuntu, x86_64, 4 GiB",
        );
        assert!(display.contains("\x1b[32m  1. local:"));
        assert!(display.contains("\x1b[32m  2. root@example:"));
    }

    #[test]
    fn normal_exit_of_active_host_closes_the_whole_multiplexer() {
        assert!(closes_multiplexer_on_exit(
            Some(Pane::Remote(1)),
            1,
            Some(0),
            None
        ));
        assert!(closes_multiplexer_on_exit(
            Some(Pane::Remote(1)),
            1,
            None,
            Some("TERM")
        ));
        assert!(!closes_multiplexer_on_exit(
            Some(Pane::Remote(0)),
            1,
            Some(0),
            None
        ));
        assert!(!closes_multiplexer_on_exit(
            Some(Pane::Remote(1)),
            1,
            None,
            None
        ));
        // The remote-exit helper does not classify a local pane as remote.
        assert!(!closes_multiplexer_on_exit(
            Some(Pane::Local),
            1,
            Some(0),
            None
        ));
    }

    #[test]
    fn ctrl_left_selects_local_and_ctrl_right_advances_remote() {
        let mut parser = SwitchInputParser::default();
        assert!(matches!(
            parser.feed(b"\x1b[1;5D", true).as_slice(),
            [ParsedInput::Switch(InputAction::Local)]
        ));
        assert!(matches!(
            parser.feed(b"\x1b[1;5Cls", true).as_slice(),
            [ParsedInput::Switch(InputAction::Next), ParsedInput::Data(data)] if data == b"ls"
        ));
        assert!(!parser.has_pending());
    }

    #[test]
    fn pane_ring_starts_at_the_local_shell() {
        assert_eq!(Pane::Local.position(), 0);
        assert_eq!(Pane::Remote(0).position(), 1);
        assert_eq!(Pane::at(0), Pane::Local);
        assert_eq!(Pane::at(2), Pane::Remote(1));
    }

    #[test]
    fn single_host_sessions_switch_between_the_host_and_the_local_shell() {
        let shells = vec![None];
        // Without a running local shell the ring has nowhere else to go.
        assert_eq!(
            adjacent_open_pane(&shells, None, Pane::Remote(0), InputAction::Previous),
            None
        );

        let local = test_local_shell(true);
        assert_eq!(
            adjacent_open_pane(
                &shells,
                Some(&local),
                Pane::Remote(0),
                InputAction::Previous
            ),
            Some(Pane::Local)
        );
        assert_eq!(
            adjacent_open_pane(&shells, Some(&local), Pane::Remote(0), InputAction::Next),
            Some(Pane::Local)
        );
        assert_eq!(
            adjacent_open_pane(&shells, Some(&local), Pane::Local, InputAction::Next),
            None
        );

        let closed = test_local_shell(false);
        assert_eq!(
            adjacent_open_pane(
                &shells,
                Some(&closed),
                Pane::Remote(0),
                InputAction::Previous
            ),
            None
        );
        // Shift still reaches an exited local pane so that it can be restarted,
        // unless local shells cannot run at all.
        assert_eq!(
            adjacent_switchable_pane(
                &shells,
                Some(&closed),
                true,
                Pane::Remote(0),
                InputAction::Previous
            ),
            Some(Pane::Local)
        );
        assert_eq!(
            adjacent_switchable_pane(
                &shells,
                Some(&closed),
                false,
                Pane::Remote(0),
                InputAction::Previous
            ),
            None
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_shell_pane_runs_input_and_reports_its_exit() {
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let shell = prepare_local_shell(events_tx)
            .await
            .expect("local shell pane starts");
        shell
            .commands
            .send(MultiplexCommand::Input(
                b"printf sshai-local; exit 7\n".to_vec(),
            ))
            .await
            .expect("local shell accepts input");

        let mut output = Vec::new();
        let mut code = None;
        let collected = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(event) = events_rx.recv().await {
                match event {
                    MultiplexEvent::LocalOutput { data } => output.extend_from_slice(&data),
                    MultiplexEvent::LocalExited { code: exit } => {
                        code = exit;
                        return;
                    }
                    _ => {}
                }
            }
        })
        .await;

        assert!(collected.is_ok(), "local shell pane did not exit in time");
        assert_eq!(code, Some(7));
        assert!(
            String::from_utf8_lossy(&output).contains("sshai-local"),
            "missing local shell output: {}",
            String::from_utf8_lossy(&output)
        );
    }

    fn test_local_shell(open: bool) -> LocalShell {
        LocalShell {
            pid: 0,
            commands: mpsc::channel(1).0,
            task: None,
            terminal: VirtualTerminal::new(80, 24),
            open,
        }
    }
}
