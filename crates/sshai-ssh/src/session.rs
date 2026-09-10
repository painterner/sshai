use std::{
    env,
    io::{IsTerminal, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use russh::{ChannelMsg, Disconnect, Sig, client};
use sha2::{Digest, Sha256};
use sshai_core::Target;
use sshai_protocol::{ControlRequest, ControlResponse};
use tokio::{io::AsyncWriteExt, net::TcpStream};

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
}

#[derive(Debug)]
pub struct CommandExit {
    pub code: Option<u32>,
    pub signal: Option<String>,
}

struct CapturedCommand {
    code: Option<u32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

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
        })
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
        let handler = ClientHandler::new(target.clone());
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
        let agent_started = Instant::now();
        tracing::debug!(host = %self.target.host, "remote agent startup beginning");

        let phase_started = Instant::now();
        self.verify_agent_platform().await?;
        tracing::debug!(
            elapsed_ms = phase_started.elapsed().as_millis() as u64,
            "remote platform verified"
        );

        let local_executable = std::env::current_exe().map_err(SshError::Io)?;
        let phase_started = Instant::now();
        let digest = executable_digest(&local_executable).await?;
        tracing::debug!(
            path = %local_executable.display(),
            elapsed_ms = phase_started.elapsed().as_millis() as u64,
            "local agent executable hashed"
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
        let remote_bin_dir = join_remote_path(&remote_home, &format!(".cache/sshai/bin/{bundle}"));
        let remote_executable = join_remote_path(&remote_bin_dir, "sshai");
        let phase_started = Instant::now();
        sftp.ensure_dir_all(remote_bin_dir, 0o700).await?;
        tracing::debug!(
            elapsed_ms = phase_started.elapsed().as_millis() as u64,
            "remote agent cache directory ready"
        );

        let phase_started = Instant::now();
        let cached_digest = sftp.sha256(remote_executable.clone()).await?;
        let cache_hit = cached_digest.as_deref() == Some(&digest);
        tracing::debug!(
            cache_hit,
            elapsed_ms = phase_started.elapsed().as_millis() as u64,
            "remote agent cache checked"
        );
        if !cache_hit {
            let phase_started = Instant::now();
            sftp.upload(&local_executable, remote_executable.clone(), true)
                .await?;
            tracing::debug!(
                elapsed_ms = phase_started.elapsed().as_millis() as u64,
                "remote agent executable uploaded"
            );

            let phase_started = Instant::now();
            let uploaded_digest = sftp.sha256(remote_executable.clone()).await?;
            if uploaded_digest.as_deref() != Some(&digest) {
                return Err(SshError::Agent(
                    "remote agent binary failed post-upload checksum verification".to_owned(),
                ));
            }
            tracing::debug!(
                elapsed_ms = phase_started.elapsed().as_millis() as u64,
                "uploaded agent executable verified"
            );
        }

        let phase_started = Instant::now();
        sftp.set_permissions(remote_executable.clone(), 0o700)
            .await?;

        // Keep this path well below Unix sockaddr_un limits even for long home paths.
        // The full 256-bit token remains in the protocol; 96 bits name the directory.
        let remote_sessions_dir = join_remote_path(&remote_home, ".cache/sshai/s");
        sftp.ensure_dir_all(remote_sessions_dir, 0o700).await?;
        let remote_session_dir = join_remote_path(
            &remote_home,
            &format!(".cache/sshai/s/{}", &session_id[..24]),
        );
        let remote_workspace_root = match self.target.path.as_deref() {
            None | Some("~") => remote_home,
            Some(path) if path.starts_with('/') => path.to_owned(),
            Some(path) => join_remote_path(&remote_home, path),
        };
        sftp.close().await?;
        tracing::debug!(
            elapsed_ms = phase_started.elapsed().as_millis() as u64,
            "remote agent session prepared"
        );
        let command = format!(
            "exec {} worker serve --session-id {} --session-dir {} --workspace-root {}",
            shell_quote(&remote_executable),
            shell_quote(&session_id),
            shell_quote(&remote_session_dir),
            shell_quote(&remote_workspace_root),
        );
        let phase_started = Instant::now();
        let channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;
        let agent = RemoteAgent::connect(channel.into_stream(), &session_id).await?;
        tracing::debug!(
            elapsed_ms = phase_started.elapsed().as_millis() as u64,
            total_elapsed_ms = agent_started.elapsed().as_millis() as u64,
            "remote agent ready"
        );
        Ok(agent)
    }

    async fn verify_agent_platform(&self) -> Result<()> {
        let output = self.capture_command("uname -s; uname -m").await?;
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
        Ok(())
    }

    pub async fn interactive_shell(&self) -> Result<CommandExit> {
        self.interactive_shell_inner(None).await
    }

    pub async fn interactive_shell_with_agent(&self) -> Result<CommandExit> {
        let agent = self.start_agent().await?;
        self.interactive_shell_inner(Some(agent)).await
    }

    pub async fn workspace(&self) -> Result<WorkspaceClient> {
        Ok(WorkspaceClient::new(self.start_agent().await?))
    }

    async fn interactive_shell_inner(&self, mut agent: Option<RemoteAgent>) -> Result<CommandExit> {
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

        match (self.target.path.as_deref(), agent.as_ref()) {
            (path, Some(agent)) => {
                let command = build_shell_command(path, Some(&agent.shell_launcher));
                channel.exec(true, command).await?;
            }
            (Some(path), None) => {
                let command = build_shell_command(Some(path), None);
                channel.exec(true, command).await?;
            }
            (None, None) => channel.request_shell(true).await?,
        }

        let _raw_mode = RawTerminalGuard::activate()?;
        let mut stdin = InteractiveStdin::new()?;
        let mut stdout = tokio::io::stdout();
        let mut input = [0_u8; 8192];
        let mut stdin_closed = false;
        let mut code = None;
        let mut signal = None;

        let mut resize = ResizeEvents::new()?;

        'shell: loop {
            tokio::select! {
                read = stdin.read(&mut input), if !stdin_closed => {
                    let read = read?;
                    if read == 0 {
                        stdin_closed = true;
                        channel.eof().await?;
                    } else {
                        channel.data_bytes(input[..read].to_vec()).await?;
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
                request = receive_control_request(&mut agent) => {
                    match request {
                        Ok(request) => {
                            let response = self.handle_control_request(request).await;
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

        let _ = channel.close().await;
        if let Some(agent) = agent.as_mut() {
            if let Err(error) = agent.shutdown().await {
                tracing::debug!(%error, "remote agent did not shut down cleanly");
            }
        }
        Ok(CommandExit { code, signal })
    }

    async fn handle_control_request(&self, request: ControlRequest) -> ControlResponse {
        let id = request.id;
        let result = match request.argv.first().map(String::as_str) {
            Some("copy-id") => self.control_copy_id(&request.argv[1..]).await,
            Some("info") => Ok(format!(
                "connected to {}@{}:{}\n",
                self.target.user, self.target.host, self.target.port
            )),
            Some("help") | Some("--help") | Some("-h") => Ok(control_help().to_owned()),
            Some(command) => Err(SshError::Agent(format!(
                "unknown built-in command {command:?}; try `sshai help`"
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

fn control_help() -> &'static str {
    "sshai session commands:\n\
  sshai copy-id [-i LOCAL_KEY] [--authorized-keys REMOTE_PATH]\n\
  sshai info\n\
  sshai help\n\
\n\
These commands run through the encrypted session control channel. LOCAL_KEY is\n\
read on your local machine; quote paths containing '~' to prevent the remote\n\
shell from expanding them first, for example: sshai copy-id -i '~/.ssh/id_ed25519.pub'\n"
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
    fn parses_remote_copy_id_arguments_as_local_paths() {
        let (identity, authorized_keys) = parse_copy_id_arguments(&[
            "--identity=/tmp/local key.pub".to_owned(),
            "--authorized-keys=.ssh/custom_keys".to_owned(),
        ])
        .unwrap();
        assert_eq!(identity, Some(PathBuf::from("/tmp/local key.pub")));
        assert_eq!(authorized_keys.as_deref(), Some(".ssh/custom_keys"));
    }
}
