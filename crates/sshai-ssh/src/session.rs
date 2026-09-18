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
const MULTIPLEX_SWITCH_HINT: &str = "\x1b[1;36m[sshai] Shift+Left/Right switches hosts\x1b[0m\r\n";
const SWITCH_SEQUENCE_TIMEOUT: Duration = Duration::from_millis(30);
const SWITCH_PREFIX_TIMEOUT: Duration = Duration::from_secs(3);
const SWITCH_PREVIOUS: &[u8] = b"\x1b[1;6D";
const SWITCH_NEXT: &[u8] = b"\x1b[1;6C";
const SWITCH_PREVIOUS_SHIFT_LEFT: &[u8] = b"\x1b[1;2D";
const SWITCH_NEXT_SHIFT_RIGHT: &[u8] = b"\x1b[1;2C";
const SWITCH_PREFIX: u8 = 0x1d; // Ctrl+]

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
}

const PREFIX_SWITCH_PREVIOUS: &[&[u8]] = &[b"\x1dh", b"\x1d[", b"\x1d\x1b[D", b"\x1d\x1bOD"];
const PREFIX_SWITCH_NEXT: &[&[u8]] = &[b"\x1dl", b"\x1d]", b"\x1d\x1b[C", b"\x1d\x1bOC"];
const LITERAL_SWITCH_PREFIX: &[u8] = b"\x1d\x1d";

enum ParsedInput {
    Data(Vec<u8>),
    Switch(InputAction),
}

#[derive(Default)]
struct SwitchInputParser {
    pending: Vec<u8>,
}

impl SwitchInputParser {
    fn feed(&mut self, input: &[u8]) -> Vec<ParsedInput> {
        let mut bytes = std::mem::take(&mut self.pending);
        bytes.extend_from_slice(input);
        let mut parsed = Vec::new();
        let mut data = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            let remaining = &bytes[index..];
            let matched = if remaining.starts_with(SWITCH_PREVIOUS) {
                Some((SWITCH_PREVIOUS.len(), InputAction::Previous))
            } else if remaining.starts_with(SWITCH_NEXT) {
                Some((SWITCH_NEXT.len(), InputAction::Next))
            } else if remaining.starts_with(SWITCH_PREVIOUS_SHIFT_LEFT) {
                Some((SWITCH_PREVIOUS_SHIFT_LEFT.len(), InputAction::Previous))
            } else if remaining.starts_with(SWITCH_NEXT_SHIFT_RIGHT) {
                Some((SWITCH_NEXT_SHIFT_RIGHT.len(), InputAction::Next))
            } else {
                PREFIX_SWITCH_PREVIOUS
                    .iter()
                    .find(|sequence| remaining.starts_with(sequence))
                    .map(|sequence| (sequence.len(), InputAction::Previous))
                    .or_else(|| {
                        PREFIX_SWITCH_NEXT
                            .iter()
                            .find(|sequence| remaining.starts_with(sequence))
                            .map(|sequence| (sequence.len(), InputAction::Next))
                    })
            };
            if let Some((length, action)) = matched {
                if !data.is_empty() {
                    parsed.push(ParsedInput::Data(std::mem::take(&mut data)));
                }
                parsed.push(ParsedInput::Switch(action));
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

fn switch_sequence_starts_with(bytes: &[u8]) -> bool {
    SWITCH_PREVIOUS.starts_with(bytes)
        || SWITCH_NEXT.starts_with(bytes)
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

    /// Run one persistent PTY per target while keeping the first target usable
    /// before background connections to the remaining targets complete.
    pub async fn interactive_shell_multiplexed(
        &self,
        primary: Arc<SshSession>,
        targets: Vec<Target>,
        handler: &mut dyn SessionCommandHandler,
    ) -> Result<CommandExit> {
        if targets.len() < 2 {
            return Err(SshError::Config(
                "multiplexed SSH requires at least two targets".to_owned(),
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
        let channel = self.session.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let session = russh_sftp::client::SftpSession::new(channel.into_stream()).await?;
        session.set_timeout(self.target.connect_timeout.as_secs().max(60));
        let base = match self.target.path.as_deref() {
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
        let mut command = format!(
            "set -e; umask 077; mkdir -p {} {} {}; chmod 700 {} {} {};",
            shell_quote(session_dir),
            shell_quote(&bin_dir),
            shell_quote(&zsh_dir),
            shell_quote(session_dir),
            shell_quote(&bin_dir),
            shell_quote(&zsh_dir),
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
                        let mut input = input[..read].to_vec();
                        if let Some(handler) = handler.as_deref_mut() {
                            let result = handler.handle_input(input).await;
                            input = result.forward;
                            if let Some(notice) = result.notice {
                                stdout
                                    .write_all(format!("\r\nsshai: {notice}\r\n").as_bytes())
                                    .await?;
                                stdout.flush().await?;
                            }
                        }
                        if !input.is_empty() {
                            channel.data_bytes(input).await?;
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
        let id = request.id;
        let result = match request.argv.first().map(String::as_str) {
            Some("copy-id") => self.control_copy_id(&request.argv[1..]).await,
            Some("info" | "hosts") => Ok(format!(
                "connected to {}@{}:{}\n",
                self.target.user, self.target.host, self.target.port
            )),
            Some("help") | Some("--help") | Some("-h") => Ok(control_help().to_owned()),
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
    let labels = targets.iter().map(ToString::to_string).collect::<Vec<_>>();
    let local_summary = local_connection_summary();
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
    let mut active = Some(0_usize);
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

    let mut connection_tasks = Vec::with_capacity(total - 1);
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
                } else {
                    for parsed in parser.feed(&input[..read]) {
                        match parsed {
                            ParsedInput::Data(data) => {
                                let mut data = data;
                                let result = handler.handle_input(data).await;
                                data = result.forward;
                                let notice = result.notice;
                                if let Some(notice) = notice {
                                    let notice = format!("\r\nsshai: {notice}\r\n").into_bytes();
                                    if let Some(active_index) = active {
                                        if let Some(shell) = shells
                                            .get_mut(active_index)
                                            .and_then(Option::as_mut)
                                        {
                                            shell.terminal.process(&notice);
                                        }
                                    }
                                    stdout.write_all(&notice).await?;
                                    stdout.flush().await?;
                                }
                                if let Some(commands) = active_shell_commands(&shells, active) {
                                    if !data.is_empty() {
                                        let _ = commands.send(MultiplexCommand::Input(data)).await;
                                    }
                                }
                            }
                            ParsedInput::Switch(action) => {
                                if let Some(current) = active {
                                    if let Some(next) = adjacent_open_shell(&shells, current, action) {
                                        active = Some(next);
                                        render_multiplexed_shell(&mut stdout, &shells[next], next, total).await?;
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
                        if active.is_none() {
                            active = Some(index);
                            render_multiplexed_shell(&mut stdout, &shells[index], index, total).await?;
                        }
                    }
                    MultiplexEvent::Failed { index, error } => {
                        pending_connections = pending_connections.saturating_sub(1);
                        statuses[index] = format!("failed: {error}");
                        if active.is_none() && pending_connections == 0 {
                            break 'multiplexer;
                        }
                    }
                    MultiplexEvent::Output { index, data } => {
                        if let Some(shell) = shells.get_mut(index).and_then(Option::as_mut) {
                            shell.terminal.process(&data);
                            if active == Some(index) {
                                stdout.write_all(&data).await?;
                                stdout.flush().await?;
                            }
                        }
                    }
                    MultiplexEvent::WorkerNotice { index, message } => {
                        let notice = format!("\r\nsshai: {message}\r\n").into_bytes();
                        if let Some(shell) = shells.get_mut(index).and_then(Option::as_mut) {
                            shell.terminal.process(&notice);
                            if active == Some(index) {
                                stdout.write_all(&notice).await?;
                                stdout.flush().await?;
                            }
                        }
                    }
                    MultiplexEvent::ControlRequest { index, request } => {
                        let Some(shell) = shells.get(index).and_then(Option::as_ref) else {
                            continue;
                        };
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
                            session.handle_control_request(request).await
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
                        if active == Some(index) {
                            active = adjacent_open_shell(&shells, index, InputAction::Next);
                            if let Some(next) = active {
                                render_multiplexed_shell(&mut stdout, &shells[next], next, total).await?;
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
                }
            }
            _ = resize.recv() => {
                let (columns, rows) = terminal_size();
                for shell in shells.iter_mut().flatten().filter(|shell| shell.open) {
                    shell.terminal.resize(columns, rows);
                    let commands = shell.commands.clone();
                    let _ = commands.send(MultiplexCommand::Resize(columns, rows)).await;
                }
            }
            _ = &mut pending_timeout, if parser.has_pending() => {
                if let Some(data) = parser.flush() {
                    if let Some(commands) = active_shell_commands(&shells, active) {
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
    for shell in shells.iter().flatten().filter(|shell| shell.open) {
        let _ = shell.commands.send(MultiplexCommand::Shutdown).await;
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

fn active_shell_commands(
    shells: &[Option<MultiplexedShell>],
    active: Option<usize>,
) -> Option<mpsc::Sender<MultiplexCommand>> {
    shells
        .get(active?)?
        .as_ref()
        .filter(|shell| shell.open)
        .map(|shell| shell.commands.clone())
}

fn adjacent_open_shell(
    shells: &[Option<MultiplexedShell>],
    current: usize,
    action: InputAction,
) -> Option<usize> {
    (1..shells.len())
        .map(|distance| match action {
            InputAction::Next => (current + distance) % shells.len(),
            InputAction::Previous => (current + shells.len() - distance) % shells.len(),
        })
        .find(|index| shells[*index].as_ref().is_some_and(|shell| shell.open))
}

fn closes_multiplexer_on_exit(
    active: Option<usize>,
    exited: usize,
    code: Option<u32>,
    signal: Option<&str>,
) -> bool {
    active == Some(exited) && (code.is_some() || signal.is_some())
}

async fn render_multiplexed_shell(
    stdout: &mut tokio::io::Stdout,
    shell: &Option<MultiplexedShell>,
    index: usize,
    total: usize,
) -> Result<()> {
    let shell = shell.as_ref().expect("rendered shell must exist");
    let label = display_label(&shell.label);
    let snapshot = shell.terminal.snapshot();
    stdout
        .write_all(
            format!(
                "\x1b]0;sshai [{}/{}] {label} — Shift+←/→\x07",
                index + 1,
                total
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
        "\x1b]0;sshai [1/{}] {} — Shift+←/→\x07{}",
        labels.len(),
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

fn join_remote_path(parent: &str, child: &str) -> String {
    format!(
        "{}/{}",
        parent.trim_end_matches('/'),
        child.trim_start_matches('/')
    )
}

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
    let fish_init = shell_quote(&format!("set -gx PATH {} $PATH", fish_quote(&bin_dir)));
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
export PATH={quoted_bin}:\"$PATH\"\n"
    );
    let shrc_body = format!(
        "if [ -r /etc/profile ]; then . /etc/profile; fi\n\
if [ -r \"$HOME/.profile\" ]; then . \"$HOME/.profile\"; fi\n\
export PATH={quoted_bin}:\"$PATH\"\n"
    );

    let mut files = vec![
        (shim, shim_body, 0o700),
        (launcher, launcher_body, 0o700),
        (bashrc, bashrc_body, 0o600),
        (shrc, shrc_body, 0o600),
    ];
    for name in [".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout"] {
        let body = format!(
            "original=\"${{SSHAI_ORIGINAL_ZDOTDIR:-$HOME}}/{name}\"\n\
if [[ -r \"$original\" ]]; then source \"$original\"; fi\n\
unset original\n\
export ZDOTDIR={quoted_zsh_dir}\n\
export PATH={quoted_bin}:$PATH\n"
        );
        files.push((join_remote_path(&zsh_dir, name), body, 0o600));
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
  sshai info\n\
  sshai hosts\n\
  sshai help\n\
\n\
Agent names after --agent are resolved on the local machine. Known agents use built-in adapters;\n\
other executables must advertise MCP support and receive the generic MCP environment.\n\
These commands run through the encrypted session control channel. LOCAL_KEY is\n\
read on your local machine; quote paths containing '~' to prevent the remote\n\
shell from expanding them first, for example: sshai copy-id -i '~/.ssh/id_ed25519.pub'\n\
In a multi-host session, use Shift+Left/Right to switch hosts. Ctrl+Shift+Left/Right and\n\
Ctrl+] followed by Left/Right (or h/l) are also supported.\n"
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
        let first = parser.feed(b"echo ok\n\x1b[1;");
        assert!(matches!(first.as_slice(), [ParsedInput::Data(data)] if data == b"echo ok\n"));
        assert!(parser.has_pending());

        let second = parser.feed(b"6Ctail");
        assert!(matches!(
            second.as_slice(),
            [ParsedInput::Switch(InputAction::Next), ParsedInput::Data(data)] if data == b"tail"
        ));
        assert!(!parser.has_pending());

        assert!(matches!(
            parser.feed(SWITCH_PREVIOUS).as_slice(),
            [ParsedInput::Switch(InputAction::Previous)]
        ));
    }

    #[test]
    fn parses_terminator_safe_multi_host_switch_prefix() {
        let mut parser = SwitchInputParser::default();
        assert!(parser.feed(&[SWITCH_PREFIX]).is_empty());
        assert_eq!(parser.pending_timeout(), SWITCH_PREFIX_TIMEOUT);
        assert!(matches!(
            parser.feed(b"\x1b[C").as_slice(),
            [ParsedInput::Switch(InputAction::Next)]
        ));
        assert!(matches!(
            parser.feed(b"\x1dh").as_slice(),
            [ParsedInput::Switch(InputAction::Previous)]
        ));
        assert!(matches!(
            parser.feed(LITERAL_SWITCH_PREFIX).as_slice(),
            [ParsedInput::Data(data)] if data == &[SWITCH_PREFIX]
        ));
    }

    #[test]
    fn parses_single_chord_shift_arrow_host_switches() {
        let mut parser = SwitchInputParser::default();
        assert!(matches!(
            parser.feed(SWITCH_PREVIOUS_SHIFT_LEFT).as_slice(),
            [ParsedInput::Switch(InputAction::Previous)]
        ));
        assert!(matches!(
            parser.feed(SWITCH_NEXT_SHIFT_RIGHT).as_slice(),
            [ParsedInput::Switch(InputAction::Next)]
        ));
        assert!(parser.feed(b"\x1b").is_empty());
        assert!(matches!(
            parser.feed(b"[1;2C").as_slice(),
            [ParsedInput::Switch(InputAction::Next)]
        ));
    }

    #[test]
    fn forwards_incomplete_escape_sequence_after_timeout() {
        let mut parser = SwitchInputParser::default();
        assert!(parser.feed(b"\x1b").is_empty());
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
        assert!(closes_multiplexer_on_exit(Some(1), 1, Some(0), None));
        assert!(closes_multiplexer_on_exit(Some(1), 1, None, Some("TERM")));
        assert!(!closes_multiplexer_on_exit(Some(0), 1, Some(0), None));
        assert!(!closes_multiplexer_on_exit(Some(1), 1, None, None));
    }
}
