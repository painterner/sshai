use std::{
    io::{IsTerminal, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{ExitCode, Stdio},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use serde_json::{Map, Value};
use sshai_ai::{AgentSession, AgentUi, OpenAiProvider};
use sshai_core::Target;
use sshai_ssh::{
    Action, Conflict, ConflictPolicy, ConflictReason, ConnectOptions, CycleReport, HostKeyPolicy,
    KeyInstallResult, MAX_WORKSPACE_READ, SessionCommandHandler, SessionCommandResult,
    SessionInputResult, Side, SshConnector, SyncOptions, SyncSession, VCS_IGNORES, WorkspaceClient,
    WorkspaceMetadata, WorkspaceStreamExecOptions, discover_public_identities, state_file_name,
};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command as TokioCommand,
    sync::oneshot,
    task::JoinHandle,
};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "sshai",
    version,
    about = "A future-facing, pure-Rust SSH workspace transport for local AI tools",
    arg_required_else_help = true,
    args_conflicts_with_subcommands = true
)]
struct Cli {
    /// OpenSSH-compatible user configuration file.
    #[arg(short = 'F', long, global = true)]
    config: Option<PathBuf>,

    /// Fail when the host key is not already known.
    #[arg(long, global = true, conflicts_with_all = ["accept_new", "insecure"])]
    strict_host_key: bool,

    /// Automatically add previously unknown host keys.
    #[arg(long, global = true, conflicts_with = "insecure")]
    accept_new: bool,

    /// Disable host key verification. This is unsafe.
    #[arg(long, global = true)]
    insecure: bool,

    /// Never prompt for passwords or keyboard-interactive authentication.
    #[arg(long, global = true)]
    batch: bool,

    /// Increase diagnostics (`-v`, `-vv`).
    #[arg(short, long, global = true, action = ArgAction::Count)]
    verbose: u8,

    /// Launch a local MCP-capable AI agent against the selected remote target(s).
    #[arg(long, value_name = "NAME", requires = "target")]
    agent: Option<String>,

    /// Override the local read-write workspace used with --agent.
    #[arg(long, value_name = "DIR", requires = "agent")]
    local_dir: Option<PathBuf>,

    /// One target, or comma-separated targets. The first hosts the interactive shell.
    #[arg(value_name = "TARGET[,TARGET...]")]
    target: Option<TargetList>,

    /// Disable the per-session remote worker and its built-in commands.
    #[arg(long = "no-worker", alias = "no-agent", conflicts_with = "agent")]
    no_worker: bool,

    /// Arguments forwarded to the selected local agent after `--`.
    #[arg(last = true, requires = "agent", value_name = "AGENT_ARGUMENT")]
    agent_arguments: Vec<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TargetList(Vec<Target>);

impl TargetList {
    fn primary(&self) -> &Target {
        self.0.first().expect("target lists are never empty")
    }

    fn into_vec(self) -> Vec<Target> {
        self.0
    }
}

impl FromStr for TargetList {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let targets = value
            .split(',')
            .map(|value| {
                value
                    .parse::<Target>()
                    .map_err(|error| format!("invalid target {value:?}: {error}"))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if targets.is_empty() {
            return Err("at least one SSH target is required".to_owned());
        }
        Ok(Self(targets))
    }
}

impl std::fmt::Display for TargetList {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, target) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "{target}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Execute a command remotely and stream stdout/stderr.
    #[command(trailing_var_arg = true)]
    Exec {
        /// `host`, `user@host:port`, or `ssh://user@host:port/path`.
        target: Target,

        /// Command and arguments. Arguments are quoted individually.
        #[arg(required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Transfer bootstrap files through the pure-Rust SFTP channel.
    Sftp {
        /// `host`, `user@host:port`, or `ssh://user@host:port`.
        target: Target,

        #[command(subcommand)]
        operation: SftpOperation,
    },

    /// Keep a local and a remote directory synchronized in both directions.
    Sync {
        /// `host`, `user@host:port`, or `ssh://user@host:port`.
        target: Target,

        /// Local directory. Created when missing.
        local: PathBuf,

        /// Remote directory. Created when missing.
        remote: String,

        /// Synchronize once and exit instead of watching for changes.
        #[arg(long)]
        once: bool,

        /// Seconds to wait between cycles.
        #[arg(long, value_name = "SECONDS", default_value_t = 5)]
        interval: u64,

        /// Skip a file/directory name, or a relative subtree. Repeatable.
        #[arg(long = "ignore", value_name = "PATTERN")]
        ignores: Vec<String>,

        /// Also skip version-control directories (.git, .hg, .svn, .bzr, .jj).
        #[arg(long)]
        ignore_vcs: bool,

        /// What to do when both sides changed the same path.
        #[arg(long, value_enum, default_value_t = SyncConflict::Safe)]
        conflict: SyncConflict,

        /// Never propagate a deletion to the other side.
        #[arg(long)]
        no_delete: bool,

        /// Report what would change without touching either side.
        #[arg(long)]
        dry_run: bool,

        /// Where to remember the last synchronized state.
        #[arg(long, value_name = "PATH")]
        state: Option<PathBuf>,
    },

    /// Inspect files rooted in, or execute commands from, the remote workspace.
    Workspace {
        /// `host`, `user@host:port`, or `ssh://user@host:port/path`.
        target: Target,

        #[command(subcommand)]
        operation: WorkspaceOperation,
    },

    /// Serve the remote workspace as a local stdio MCP server.
    Mcp {
        /// `host`, `user@host:port`, or `ssh://user@host:port/path`.
        target: Target,

        /// Local workspace exposed to transfer tools. Defaults to sshai's current directory.
        #[arg(long, value_name = "DIR")]
        local_dir: Option<PathBuf>,
    },

    /// Internal stdio proxy for an already-authenticated interactive session.
    #[command(hide = true)]
    SessionMcpProxy {
        address: SocketAddr,
        #[arg(long, hide = true)]
        token: String,
    },

    /// Run sshai's built-in local AI agent against a remote workspace.
    #[command(trailing_var_arg = true)]
    Agent {
        /// `host`, `user@host:port`, or `ssh://user@host:port/path`.
        target: Target,

        /// Responses API model (or set OPENAI_MODEL).
        #[arg(long)]
        model: Option<String>,

        /// OpenAI-compatible API base URL (or set OPENAI_BASE_URL).
        #[arg(long)]
        api_base: Option<String>,

        /// Approval policy for remote mutations and command execution.
        #[arg(long, value_enum, default_value_t = ApprovalArg::Ask)]
        approval: ApprovalArg,

        /// Maximum remote tool calls in one user turn.
        #[arg(long, default_value_t = 24)]
        max_tool_calls: usize,

        /// A one-shot prompt. Omit it to open an interactive conversation.
        #[arg(allow_hyphen_values = true)]
        prompt: Vec<String>,
    },

    /// Install local public keys in the remote user's authorized_keys.
    CopyId {
        /// `host`, `user@host:port`, or `ssh://user@host:port`.
        target: Target,

        /// Public or private identity file. A neighboring `.pub` is preferred.
        #[arg(short = 'i', long = "identity")]
        identity: Option<PathBuf>,

        /// Override the remote authorized_keys path (relative to remote home or absolute).
        #[arg(long)]
        authorized_keys: Option<String>,
    },

    /// Resolve configuration and verify an SSH connection.
    Doctor {
        /// Target to diagnose. Omit it to only inspect local configuration.
        target: Option<Target>,

        /// Resolve configuration without connecting.
        #[arg(long)]
        config_only: bool,
    },
}

/// How `sshai sync` settles a path both sides changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SyncConflict {
    /// Report the conflict and change neither side.
    Safe,
    /// The local side wins.
    Local,
    /// The remote side wins.
    Remote,
    /// The more recently modified side wins.
    Newest,
}

impl From<SyncConflict> for ConflictPolicy {
    fn from(value: SyncConflict) -> Self {
        match value {
            SyncConflict::Safe => Self::Safe,
            SyncConflict::Local => Self::Local,
            SyncConflict::Remote => Self::Remote,
            SyncConflict::Newest => Self::Newest,
        }
    }
}

#[derive(Debug, Subcommand)]
enum SftpOperation {
    /// Download a remote file or directory.
    Get {
        remote: String,
        local: PathBuf,
        /// Recursively transfer a directory.
        #[arg(short = 'r', long)]
        recursive: bool,
        /// Exclude a file/directory name or relative subtree. Repeatable.
        #[arg(long = "exclude", value_name = "PATTERN")]
        excludes: Vec<String>,
        #[arg(long)]
        force: bool,
    },

    /// Upload a local file or directory.
    Put {
        local: PathBuf,
        remote: String,
        /// Recursively transfer a directory.
        #[arg(short = 'r', long)]
        recursive: bool,
        /// Exclude a file/directory name or relative subtree. Repeatable.
        #[arg(long = "exclude", value_name = "PATTERN")]
        excludes: Vec<String>,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
enum WorkspaceOperation {
    /// Open the workspace and print negotiated capabilities.
    Open,
    /// List a directory, with stable name-based pagination.
    List {
        #[arg(default_value = ".")]
        path: String,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value_t = 200)]
        limit: u32,
    },
    /// Read file metadata without following the final symlink.
    Stat { path: String },
    /// Read a bounded file range and write the bytes to stdout.
    Read {
        path: String,
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long, default_value_t = MAX_WORKSPACE_READ)]
        length: u32,
    },
    /// Calculate a BLAKE3 digest remotely.
    Hash { path: String },
    /// Execute a command with real-time output and optional PTY support.
    #[command(trailing_var_arg = true)]
    Exec {
        #[arg(long, default_value = ".")]
        cwd: String,
        #[arg(long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Allocate a remote pseudo-terminal and forward input and resize events.
        #[arg(long)]
        pty: bool,
        /// Execute exactly one command string through the remote login shell.
        #[arg(long)]
        shell: bool,
        #[arg(required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ApprovalArg {
    /// Ask before every remote mutation or command execution.
    Ask,
    /// Automatically approve remote mutations and command execution.
    Auto,
    /// Allow only read-only workspace tools.
    ReadOnly,
}

struct TerminalAgentUi {
    approval: ApprovalArg,
}

impl AgentUi for TerminalAgentUi {
    fn tool_started(&mut self, name: &str, arguments: &Map<String, Value>) {
        let arguments = serde_json::to_string(arguments).unwrap_or_else(|_| "{}".to_owned());
        eprintln!("→ {name} {arguments}");
    }

    fn approve(&mut self, name: &str, _arguments: &Map<String, Value>) -> Result<bool> {
        match self.approval {
            ApprovalArg::Auto => Ok(true),
            ApprovalArg::ReadOnly => {
                eprintln!("  denied by --approval read-only");
                Ok(false)
            }
            ApprovalArg::Ask if !std::io::stdin().is_terminal() => {
                eprintln!("  denied because approval requires an interactive terminal");
                Ok(false)
            }
            ApprovalArg::Ask => {
                eprint!("  approve {name}? [y/N] ");
                std::io::stderr().flush()?;
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                Ok(matches!(
                    answer.trim().to_ascii_lowercase().as_str(),
                    "y" | "yes"
                ))
            }
        }
    }

    fn tool_finished(&mut self, _name: &str, result: &Value, failed: bool) {
        if failed {
            let message = result
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("tool failed");
            eprintln!("  ✗ {message}");
        } else if let Some(exit) = result.get("exit_code") {
            eprintln!("  ✓ exit {exit}");
        } else if let Some(path) = result.get("path").and_then(Value::as_str) {
            eprintln!("  ✓ {path}");
        } else {
            eprintln!("  ✓");
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    match run(cli).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("sshai: {error:#}");
            ExitCode::from(255)
        }
    }
}

async fn run(cli: Cli) -> Result<u8> {
    let launch_directory =
        std::env::current_dir().context("cannot determine the local directory")?;
    let host_key_policy = requested_host_key_policy(&cli);
    let launch_config = cli.config.clone();
    let launch_flags = LaunchFlags {
        strict_host_key: cli.strict_host_key,
        accept_new: cli.accept_new,
        insecure: cli.insecure,
        batch: cli.batch,
        verbose: cli.verbose,
    };
    if let Some(agent) = cli.agent.as_deref() {
        let targets = cli
            .target
            .clone()
            .context("--agent requires an SSH target")?
            .into_vec();
        let local_root = resolve_local_root(&launch_directory, cli.local_dir.as_deref())?;
        return run_selected_agent(
            agent,
            targets,
            local_root,
            cli.agent_arguments.clone(),
            launch_config,
            launch_flags,
            None,
        )
        .await;
    }

    let command = cli.command;
    if let Some(Command::SessionMcpProxy { address, token }) = &command {
        run_session_mcp_proxy(*address, token).await?;
        return Ok(0);
    }

    let options = ConnectOptions {
        config_file: cli.config,
        host_key_policy,
        allow_password: !cli.batch,
        worker_executable: None,
    };
    let connector = SshConnector::new(options).context("failed to initialize SSH")?;

    if let Some(targets) = cli.target {
        let session = Arc::new(connector.connect(targets.primary()).await?);
        if cli.no_worker {
            if targets.0.len() > 1 {
                anyhow::bail!("multiple targets require the session worker; remove --no-worker");
            }
            let exit = session.interactive_shell().await?;
            session.disconnect().await?;
            return Ok(exit_code(exit.code, exit.signal.as_deref()));
        }

        let targets = targets.into_vec();
        let mut handler = AiSessionCommand {
            targets: targets.clone(),
            local_root: resolve_local_root(&launch_directory, None)?,
            config: launch_config,
            flags: launch_flags,
            file_edit: None,
        };
        // Single-host sessions also run through the multiplexer: it owns the
        // local shell pane and disconnects the sessions it opened.
        let exit = connector
            .interactive_shell_multiplexed(session, targets, &mut handler)
            .await?;
        return Ok(exit_code(exit.code, exit.signal.as_deref()));
    }

    let command = command.expect("clap requires either TARGET or a subcommand");
    match command {
        Command::Exec { target, command } => {
            let session = connector.connect(&target).await?;
            let exit = session.exec(&command).await?;
            session.disconnect().await?;
            Ok(exit_code(exit.code, exit.signal.as_deref()))
        }
        Command::Sftp { target, operation } => {
            let session = connector.connect(&target).await?;
            let sftp = session.sftp().await?;
            let bytes = match operation {
                SftpOperation::Get {
                    remote,
                    local,
                    recursive,
                    excludes,
                    force,
                } => {
                    sftp.download_path(remote, local, recursive, force, &excludes)
                        .await?
                }
                SftpOperation::Put {
                    local,
                    remote,
                    recursive,
                    excludes,
                    force,
                } => {
                    sftp.upload_path(local, remote, recursive, force, &excludes)
                        .await?
                }
            };
            sftp.close().await?;
            session.disconnect().await?;
            eprintln!(
                "transferred {} bytes in {} files and {} directories",
                bytes.bytes, bytes.files, bytes.directories
            );
            Ok(0)
        }
        Command::Sync {
            target,
            local,
            remote,
            once,
            interval,
            ignores,
            ignore_vcs,
            conflict,
            no_delete,
            dry_run,
            state,
        } => {
            let mut ignores = ignores;
            if ignore_vcs {
                ignores.extend(VCS_IGNORES.iter().map(|pattern| (*pattern).to_owned()));
            }
            run_sync(
                &connector,
                target,
                &launch_directory.join(local),
                &remote,
                SyncFlags {
                    once,
                    interval: Duration::from_secs(interval.max(1)),
                    ignores,
                    policy: conflict.into(),
                    propagate_deletes: !no_delete,
                    dry_run,
                    state,
                },
            )
            .await
        }
        Command::Workspace { target, operation } => {
            let session = connector.connect(&target).await?;
            let mut workspace = session.workspace().await?;
            let operation_result = run_workspace_operation(&mut workspace, operation).await;
            let close_result = workspace.close().await;
            let disconnect_result = session.disconnect().await;
            let code = operation_result?;
            close_result?;
            disconnect_result?;
            Ok(code)
        }
        Command::Mcp { target, local_dir } => {
            let local_root = resolve_local_root(&launch_directory, local_dir.as_deref())?;
            sshai_mcp::serve(connector, target, local_root).await?;
            Ok(0)
        }
        Command::SessionMcpProxy { .. } => unreachable!("session proxy returned before SSH setup"),
        Command::Agent {
            target,
            model,
            api_base,
            approval,
            max_tool_calls,
            prompt,
        } => {
            let session = connector.connect(&target).await?;
            let mut workspace = session.workspace().await?;
            let agent_result = run_builtin_agent(
                &mut workspace,
                &target,
                model,
                api_base,
                approval,
                max_tool_calls,
                prompt,
            )
            .await;
            let close_result = workspace.close().await;
            let disconnect_result = session.disconnect().await;
            let code = agent_result?;
            close_result?;
            disconnect_result?;
            Ok(code)
        }
        Command::CopyId {
            target,
            identity,
            authorized_keys,
        } => {
            let resolved = connector.resolve(&target)?;
            let identities =
                discover_public_identities(identity.as_deref(), &resolved.identity_files).await?;
            for identity in &identities {
                eprintln!("key: {} ({})", identity.fingerprint, identity.source);
            }

            let session = connector.connect(&target).await?;
            let sftp = session.sftp().await?;
            let mut installed = 0_usize;
            let mut existing = 0_usize;
            for identity in identities {
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
            sftp.close().await?;
            session.disconnect().await?;
            println!("installed: {installed}, already present: {existing}");
            Ok(0)
        }
        Command::Doctor {
            target,
            config_only,
        } => {
            println!(
                "configuration: {}",
                connector
                    .config()
                    .source()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "defaults (no ~/.ssh/config)".to_owned())
            );
            println!("SSH engine: russh (no ssh/scp/sftp subprocesses)");
            println!(
                "SSH agent: {}",
                std::env::var_os("SSH_AUTH_SOCK")
                    .map(|_| "available")
                    .unwrap_or("not detected")
            );

            if let Some(target) = target {
                let resolved = connector.resolve(&target)?;
                println!(
                    "target: {}@{}:{}",
                    resolved.user, resolved.host, resolved.port
                );
                println!(
                    "workspace: {}",
                    resolved.path.as_deref().unwrap_or("remote home")
                );
                println!("identity files: {}", resolved.identity_files.len());
                println!("jump hosts: {}", resolved.proxy_jump.len());
                println!("host key policy: {:?}", resolved.host_key_policy);

                if !config_only {
                    let session = connector.connect(&target).await?;
                    let latency = session.ping().await?;
                    println!("connection: ok");
                    println!("authentication: {}", session.auth_method());
                    println!("SSH ping: {} ms", latency.as_millis());
                    session.disconnect().await?;
                }
            }
            Ok(0)
        }
    }
}

#[derive(Clone, Copy)]
struct LaunchFlags {
    strict_host_key: bool,
    accept_new: bool,
    insecure: bool,
    batch: bool,
    verbose: u8,
}

#[derive(Clone, Debug)]
struct SessionMcpEndpoint {
    address: SocketAddr,
    token: String,
}

struct SessionMcpBridge {
    endpoints: Vec<Option<SessionMcpEndpoint>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl SessionMcpBridge {
    async fn start(
        sessions: &[Option<Arc<sshai_ssh::SshSession>>],
        local_root: &Path,
    ) -> Result<Self> {
        let mut endpoints = Vec::with_capacity(sessions.len());
        let mut tasks = Vec::new();
        for session in sessions {
            let Some(session) = session else {
                endpoints.push(None);
                continue;
            };
            let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .context("cannot bind the local session MCP bridge")?;
            let address = listener.local_addr()?;
            let token = random_bridge_token()?;
            endpoints.push(Some(SessionMcpEndpoint {
                address,
                token: token.clone(),
            }));
            let session = Arc::clone(session);
            let local_root = local_root.to_owned();
            tasks.push(tokio::spawn(async move {
                loop {
                    let Ok((mut stream, peer)) = listener.accept().await else {
                        break;
                    };
                    if !peer.ip().is_loopback() {
                        continue;
                    }
                    if !matches!(
                        tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            authenticate_bridge_stream(&mut stream, &token),
                        )
                        .await,
                        Ok(Ok(()))
                    ) {
                        continue;
                    }
                    let session = Arc::clone(&session);
                    let local_root = local_root.clone();
                    tokio::spawn(async move {
                        if let Err(error) =
                            sshai_mcp::serve_existing_session(session, local_root, stream).await
                        {
                            tracing::debug!(%error, "session MCP bridge stopped");
                        }
                    });
                }
            }));
        }
        Ok(Self { endpoints, tasks })
    }
}

impl Drop for SessionMcpBridge {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn authenticate_bridge_stream(
    stream: &mut tokio::net::TcpStream,
    expected: &str,
) -> Result<()> {
    let mut token = Vec::with_capacity(65);
    let mut byte = [0_u8; 1];
    while token.len() <= 64 {
        stream.read_exact(&mut byte).await?;
        if byte[0] == b'\n' {
            break;
        }
        token.push(byte[0]);
    }
    anyhow::ensure!(token.len() == 64, "invalid session MCP bridge token");
    anyhow::ensure!(
        token == expected.as_bytes(),
        "invalid session MCP bridge token"
    );
    Ok(())
}

fn random_bridge_token() -> Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("cannot generate a session MCP bridge token: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

struct AiSessionCommand {
    targets: Vec<Target>,
    local_root: PathBuf,
    config: Option<PathBuf>,
    flags: LaunchFlags,
    file_edit: Option<FileEditState>,
}

static FILE_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct FileEditState {
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<String>>>,
    temporary: PathBuf,
}

impl Drop for FileEditState {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.temporary);
    }
}

#[async_trait::async_trait]
impl SessionCommandHandler for AiSessionCommand {
    fn handles(&self, command: &str) -> bool {
        matches!(command, "--agent" | "--file")
    }

    async fn handle_input(&mut self, input: Vec<u8>) -> SessionInputResult {
        if self.file_edit.is_none() {
            return SessionInputResult {
                forward: input,
                notice: None,
            };
        }
        if !input.contains(&0x11) {
            return SessionInputResult {
                forward: Vec::new(),
                notice: None,
            };
        }

        let mut state = self.file_edit.take().expect("file edit state exists");
        if let Some(stop) = state.stop.take() {
            let _ = stop.send(());
        }
        let notice = match state.task.take().expect("file edit task exists").await {
            Ok(Ok(message)) => message,
            Ok(Err(error)) => format!("file edit stopped: {error:#}"),
            Err(error) => format!("file edit monitor stopped: {error}"),
        };
        SessionInputResult {
            forward: Vec::new(),
            notice: Some(notice),
        }
    }

    async fn handle(
        &mut self,
        command: &str,
        arguments: &[String],
        session_index: usize,
        remote_cwd: Option<&str>,
        sessions: Vec<Option<Arc<sshai_ssh::SshSession>>>,
    ) -> SessionCommandResult {
        let targets = targets_at_session_remote_cwd(&self.targets, session_index, remote_cwd);
        let sessions = sessions_at_session_index(sessions, session_index);
        if command == "--file" {
            if self.file_edit.is_some() {
                return SessionCommandResult {
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: "sshai --file: another remote file is already in edit mode; press Ctrl+Q first\n".to_owned(),
                };
            }
            return match start_remote_file(
                arguments,
                remote_cwd,
                sessions.first().and_then(Option::as_ref),
            )
            .await
            {
                Ok((message, state)) => {
                    self.file_edit = Some(state);
                    SessionCommandResult {
                        exit_code: 0,
                        stdout: message,
                        stderr: String::new(),
                    }
                }
                Err(error) => SessionCommandResult {
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: format!("sshai --file: {error:#}\n"),
                },
            };
        }
        let result = match arguments.split_first() {
            Some((agent, arguments)) => {
                match session_agent_arguments(&self.local_root, arguments) {
                    Ok((local_root, arguments)) => {
                        run_selected_agent(
                            agent,
                            targets,
                            local_root,
                            arguments,
                            self.config.clone(),
                            self.flags,
                            Some(sessions),
                        )
                        .await
                    }
                    Err(error) => Err(error),
                }
            }
            None => Err(anyhow::anyhow!(
                "missing agent name; usage: sshai --agent NAME [-- AGENT_ARGUMENTS...]"
            )),
        };
        match result {
            Ok(exit_code) => SessionCommandResult {
                exit_code,
                stdout: String::new(),
                stderr: String::new(),
            },
            Err(error) => SessionCommandResult {
                exit_code: 255,
                stdout: String::new(),
                stderr: format!("sshai {command}: {error:#}\n"),
            },
        }
    }
}

async fn start_remote_file(
    arguments: &[String],
    remote_cwd: Option<&str>,
    session: Option<&Arc<sshai_ssh::SshSession>>,
) -> Result<(String, FileEditState)> {
    let [program, remote_file] = arguments else {
        anyhow::bail!("usage: sshai --file PROGRAM REMOTE_FILE");
    };
    let session = session.context("the current SSH session is unavailable")?;
    let remote_path = resolve_remote_file_path(remote_cwd, remote_file);
    let temporary = local_file_temp_path(remote_file);
    let sftp = session.sftp().await?;
    let result = async {
        let before = sftp
            .sha256(remote_path.clone())
            .await?
            .ok_or_else(|| anyhow::anyhow!("remote file does not exist: {remote_path}"))?;
        sftp.download(remote_path.clone(), &temporary, true).await?;
        let original = fs::read(&temporary).await?;

        let child = TokioCommand::new(program)
            .arg(&temporary)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("cannot launch local file program {program:?}"))?;
        Ok((child, before, original))
    }
    .await;
    let (child, before, original) = match result {
        Ok(value) => value,
        Err(error) => {
            let _ = sftp.close().await;
            let _ = fs::remove_file(&temporary).await;
            return Err(error);
        }
    };
    let (stop, stop_rx) = oneshot::channel();
    let monitor_temporary = temporary.clone();
    let task = tokio::spawn(monitor_file_edit(
        sftp,
        monitor_temporary,
        remote_path.clone(),
        original,
        before,
        stop_rx,
        child,
    ));
    Ok((
        format!(
            "file edit mode active for {remote_path}; changes auto-upload, press Ctrl+Q to close\n"
        ),
        FileEditState {
            stop: Some(stop),
            task: Some(task),
            temporary,
        },
    ))
}

async fn monitor_file_edit(
    sftp: sshai_ssh::SftpClient,
    temporary: PathBuf,
    remote_path: String,
    mut last_contents: Vec<u8>,
    mut remote_digest: String,
    mut stop: oneshot::Receiver<()>,
    mut child: tokio::process::Child,
) -> Result<String> {
    let mut conflict: Option<String> = None;
    let result = loop {
        tokio::select! {
            _ = &mut stop => {
                let _ = child.kill().await;
                break if let Some(error) = conflict {
                    Err(anyhow::anyhow!(error))
                } else {
                    Ok(format!("file edit mode closed; latest changes uploaded for {remote_path}"))
                };
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                let contents = fs::read(&temporary).await?;
                if contents == last_contents || conflict.is_some() {
                    continue;
                }
                let current = sftp.sha256(remote_path.clone()).await?;
                if current.as_deref() != Some(remote_digest.as_str()) {
                    conflict = Some(format!(
                        "remote file changed while editing; automatic upload stopped for {remote_path}"
                    ));
                    continue;
                }
                sftp.upload(&temporary, remote_path.clone(), true).await?;
                remote_digest = sftp
                    .sha256(remote_path.clone())
                    .await?
                    .unwrap_or(remote_digest);
                last_contents = contents;
            }
        }
    };
    let close = sftp.close().await;
    let _ = fs::remove_file(&temporary).await;
    match (result, close) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
    }
}

fn resolve_remote_file_path(remote_cwd: Option<&str>, path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        let base = remote_cwd.unwrap_or(".").trim_end_matches('/');
        if base.is_empty() {
            format!("/{path}")
        } else if base == "." {
            path.to_owned()
        } else {
            format!("{base}/{path}")
        }
    }
}

fn local_file_temp_path(remote_file: &str) -> PathBuf {
    let name = Path::new(remote_file)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("remote-file");
    std::env::temp_dir().join(format!(
        "sshai-file-{}-{}-{name}",
        std::process::id(),
        FILE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

fn is_agent_name(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric())
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '+')
        })
}

fn targets_at_session_remote_cwd(
    targets: &[Target],
    session_index: usize,
    remote_cwd: Option<&str>,
) -> Vec<Target> {
    let mut targets = targets.to_vec();
    if session_index < targets.len() {
        let mut selected = targets.remove(session_index);
        if let Some(remote_cwd) = remote_cwd {
            selected.path = Some(remote_cwd.to_owned());
        }
        targets.insert(0, selected);
    }
    targets
}

fn sessions_at_session_index(
    mut sessions: Vec<Option<Arc<sshai_ssh::SshSession>>>,
    session_index: usize,
) -> Vec<Option<Arc<sshai_ssh::SshSession>>> {
    if session_index < sessions.len() {
        let selected = sessions.remove(session_index);
        sessions.insert(0, selected);
    }
    sessions
}

async fn run_selected_agent(
    agent: &str,
    targets: Vec<Target>,
    local_root: PathBuf,
    arguments: Vec<String>,
    config: Option<PathBuf>,
    flags: LaunchFlags,
    sessions: Option<Vec<Option<Arc<sshai_ssh::SshSession>>>>,
) -> Result<u8> {
    anyhow::ensure!(
        is_agent_name(agent),
        "invalid agent name {agent:?}; use an executable name, not a path"
    );
    let (targets, sessions) = match sessions {
        Some(sessions) => {
            let requested = targets.len();
            let mut connected_targets = Vec::new();
            let mut connected_sessions = Vec::new();
            for (index, target) in targets.into_iter().enumerate() {
                if let Some(Some(session)) = sessions.get(index) {
                    connected_targets.push(target);
                    connected_sessions.push(Some(Arc::clone(session)));
                }
            }
            anyhow::ensure!(
                !connected_targets.is_empty(),
                "the parent sshai session has no connected remote available to the agent"
            );
            let skipped = requested.saturating_sub(connected_targets.len());
            if skipped > 0 {
                eprintln!(
                    "sshai: {skipped} background target{} not yet connected; omitting {} from this agent session to avoid a second SSH login",
                    if skipped == 1 { " is" } else { "s are" },
                    if skipped == 1 { "it" } else { "them" },
                );
            }
            (connected_targets, Some(connected_sessions))
        }
        None => (targets, None),
    };
    let bridge = match sessions {
        Some(sessions) => Some(SessionMcpBridge::start(&sessions, &local_root).await?),
        None => None,
    };
    let endpoints = bridge.as_ref().map(|bridge| bridge.endpoints.as_slice());
    if let Some(endpoints) = endpoints {
        let reused = endpoints
            .iter()
            .filter(|endpoint| endpoint.is_some())
            .count();
        eprintln!(
            "sshai: reusing {reused} authenticated SSH session{} for agent MCP",
            if reused == 1 { "" } else { "s" }
        );
    }
    let result = match agent.to_ascii_lowercase().as_str() {
        "codex" => run_codex(targets, local_root, arguments, config, flags, endpoints).await,
        "claude" => run_claude(targets, local_root, arguments, config, flags, endpoints).await,
        _ => {
            run_detected_agent(
                agent, targets, local_root, arguments, config, flags, endpoints,
            )
            .await
        }
    };
    drop(bridge);
    result
}

async fn run_codex(
    targets: Vec<Target>,
    local_root: PathBuf,
    arguments: Vec<String>,
    config: Option<PathBuf>,
    flags: LaunchFlags,
    endpoints: Option<&[Option<SessionMcpEndpoint>]>,
) -> Result<u8> {
    anyhow::ensure!(
        !targets.is_empty(),
        "at least one remote target is required"
    );
    let executable = std::env::current_exe().context("cannot locate the sshai executable")?;
    let servers = remote_servers(&targets);
    let instructions = dual_workspace_instructions(&local_root, &servers);
    let instructions_override = format!(
        "developer_instructions={}",
        serde_json::to_string(&instructions)?
    );

    print_dual_workspace_banner(&local_root, &servers);
    let mut command = tokio::process::Command::new("codex");
    command
        .arg("-C")
        .arg(&local_root)
        .arg("--sandbox")
        .arg("workspace-write")
        .arg("-c")
        .arg(instructions_override);
    for (index, server) in servers.iter().enumerate() {
        let prefix = format!("mcp_servers.{}", server.name);
        let mcp_arguments = sshai_mcp_arguments(
            &server.target,
            &local_root,
            config.as_deref(),
            flags,
            session_endpoint(endpoints, index),
        );
        command
            .arg("-c")
            .arg(format!(
                "{prefix}.command={}",
                serde_json::to_string(&executable.to_string_lossy())?
            ))
            .arg("-c")
            .arg(format!(
                "{prefix}.args={}",
                serde_json::to_string(&mcp_arguments)?
            ))
            .arg("-c")
            .arg(format!("{prefix}.startup_timeout_sec=120"))
            .arg("-c")
            .arg(format!("{prefix}.tool_timeout_sec=330"))
            .arg("-c")
            .arg(format!("{prefix}.required=true"))
            .arg("-c")
            .arg(format!("{prefix}.default_tools_approval_mode=\"writes\""))
            .arg("-c")
            .arg(format!(
                "{prefix}.tools.workspace_transfer.approval_mode=\"approve\""
            ));
    }
    command
        .args(arguments)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true);
    let status = command
        .status()
        .await
        .context("cannot launch the local Codex CLI; ensure `codex` is in PATH")?;
    Ok(process_exit_code(status))
}

async fn run_claude(
    targets: Vec<Target>,
    local_root: PathBuf,
    arguments: Vec<String>,
    config: Option<PathBuf>,
    flags: LaunchFlags,
    endpoints: Option<&[Option<SessionMcpEndpoint>]>,
) -> Result<u8> {
    anyhow::ensure!(
        !targets.is_empty(),
        "at least one remote target is required"
    );
    let executable = std::env::current_exe().context("cannot locate the sshai executable")?;
    let servers = remote_servers(&targets);
    let instructions = dual_workspace_instructions(&local_root, &servers);
    let mcp_servers = stdio_mcp_servers(
        &executable,
        &servers,
        &local_root,
        config.as_deref(),
        flags,
        true,
        endpoints,
    );
    let mcp_config = serde_json::json!({"mcpServers": mcp_servers});

    print_dual_workspace_banner(&local_root, &servers);
    let mut command = tokio::process::Command::new("claude");
    command
        .current_dir(&local_root)
        .arg("--strict-mcp-config")
        .arg("--mcp-config")
        .arg(serde_json::to_string(&mcp_config)?)
        .arg("--append-system-prompt")
        .arg(instructions)
        .args(arguments)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true);
    let status = command
        .status()
        .await
        .context("cannot launch the local Claude CLI; ensure `claude` is in PATH")?;
    Ok(process_exit_code(status))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DetectedAgent {
    Gemini,
    OpenCode,
    GenericMcp {
        mcp_config_flag: bool,
        prompt_flag: AgentPromptFlag,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentPromptFlag {
    None,
    AppendSystem,
    System,
    Interactive,
}

async fn run_detected_agent(
    agent: &str,
    targets: Vec<Target>,
    local_root: PathBuf,
    arguments: Vec<String>,
    config: Option<PathBuf>,
    flags: LaunchFlags,
    endpoints: Option<&[Option<SessionMcpEndpoint>]>,
) -> Result<u8> {
    anyhow::ensure!(
        !targets.is_empty(),
        "at least one remote target is required"
    );
    let mut help = probe_agent_help(agent).await?;
    if !help.to_ascii_lowercase().contains("mcp") {
        if let Ok(mcp_help) = probe_agent_output(agent, &["mcp", "--help"]).await {
            help.push_str(&mcp_help);
        }
    }
    let adapter = detect_agent_adapter(agent, &help)?;
    match adapter {
        DetectedAgent::Gemini => {
            run_gemini(targets, local_root, arguments, config, flags, endpoints).await
        }
        DetectedAgent::OpenCode => {
            run_opencode(targets, local_root, arguments, config, flags, endpoints).await
        }
        DetectedAgent::GenericMcp {
            mcp_config_flag,
            prompt_flag,
        } => {
            run_generic_mcp_agent(
                agent,
                targets,
                local_root,
                arguments,
                config,
                flags,
                mcp_config_flag,
                prompt_flag,
                endpoints,
            )
            .await
        }
    }
}

async fn probe_agent_help(agent: &str) -> Result<String> {
    probe_agent_output(agent, &["--help"]).await
}

async fn probe_agent_output(agent: &str, arguments: &[&str]) -> Result<String> {
    let mut command = tokio::process::Command::new(agent);
    command
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(std::time::Duration::from_secs(5), command.output())
        .await
        .with_context(|| format!("timed out while probing local agent {agent:?}"))?
        .with_context(|| format!("local agent {agent:?} was not found in PATH"))?;
    let mut help = String::from_utf8_lossy(&output.stdout).into_owned();
    help.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(help)
}

fn detect_agent_adapter(agent: &str, help: &str) -> Result<DetectedAgent> {
    match agent.to_ascii_lowercase().as_str() {
        "gemini" => return Ok(DetectedAgent::Gemini),
        "opencode" => return Ok(DetectedAgent::OpenCode),
        _ => {}
    }
    let lower = help.to_ascii_lowercase();
    let mcp_config_flag = lower.contains("--mcp-config");
    if !mcp_config_flag && !lower.contains("mcp") && !lower.contains("model context protocol") {
        anyhow::bail!(
            "local command {agent:?} does not advertise MCP support; refusing to launch an arbitrary local executable"
        );
    }
    let prompt_flag = if lower.contains("--append-system-prompt") {
        AgentPromptFlag::AppendSystem
    } else if lower.contains("--system-prompt") {
        AgentPromptFlag::System
    } else if lower.contains("--prompt-interactive") {
        AgentPromptFlag::Interactive
    } else {
        AgentPromptFlag::None
    };
    Ok(DetectedAgent::GenericMcp {
        mcp_config_flag,
        prompt_flag,
    })
}

async fn run_gemini(
    targets: Vec<Target>,
    local_root: PathBuf,
    arguments: Vec<String>,
    config: Option<PathBuf>,
    flags: LaunchFlags,
    endpoints: Option<&[Option<SessionMcpEndpoint>]>,
) -> Result<u8> {
    let executable = std::env::current_exe().context("cannot locate the sshai executable")?;
    let servers = remote_servers(&targets);
    let instructions = dual_workspace_instructions(&local_root, &servers);
    let temporary = tempfile::Builder::new()
        .prefix("sshai-gemini-")
        .tempdir()
        .context("cannot create the Gemini session configuration directory")?;
    let settings_path = temporary.path().join("settings.json");
    let mut settings = load_json_object_from_env_or_path(
        "GEMINI_CLI_SYSTEM_SETTINGS_PATH",
        Path::new("/etc/gemini-cli/settings.json"),
    )?;
    merge_object_field(
        &mut settings,
        "mcpServers",
        stdio_mcp_servers(
            &executable,
            &servers,
            &local_root,
            config.as_deref(),
            flags,
            false,
            endpoints,
        ),
    );
    std::fs::write(&settings_path, serde_json::to_vec_pretty(&settings)?)?;

    print_agent_workspace_banner("gemini", "Gemini settings/MCP", &local_root, &servers);
    let mut command = tokio::process::Command::new("gemini");
    command
        .current_dir(&local_root)
        .env("GEMINI_CLI_SYSTEM_SETTINGS_PATH", &settings_path)
        .arg("--prompt-interactive")
        .arg(instructions)
        .args(arguments)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true);
    let status = command
        .status()
        .await
        .context("cannot launch the local Gemini CLI; ensure `gemini` is in PATH")?;
    Ok(process_exit_code(status))
}

async fn run_opencode(
    targets: Vec<Target>,
    local_root: PathBuf,
    arguments: Vec<String>,
    config: Option<PathBuf>,
    flags: LaunchFlags,
    endpoints: Option<&[Option<SessionMcpEndpoint>]>,
) -> Result<u8> {
    let executable = std::env::current_exe().context("cannot locate the sshai executable")?;
    let servers = remote_servers(&targets);
    let instructions = dual_workspace_instructions(&local_root, &servers);
    let temporary = tempfile::Builder::new()
        .prefix("sshai-opencode-")
        .tempdir()
        .context("cannot create the OpenCode session configuration directory")?;
    let instructions_path = temporary.path().join("instructions.md");
    std::fs::write(&instructions_path, &instructions)?;

    let mut settings = load_json_object_from_env("OPENCODE_CONFIG_CONTENT")?;
    let mut mcp = Map::new();
    for (index, server) in servers.iter().enumerate() {
        let mut command = vec![executable.to_string_lossy().into_owned()];
        command.extend(sshai_mcp_arguments(
            &server.target,
            &local_root,
            config.as_deref(),
            flags,
            session_endpoint(endpoints, index),
        ));
        mcp.insert(
            server.name.clone(),
            serde_json::json!({
                "type": "local",
                "command": command,
                "enabled": true,
                "timeout": 330_000,
            }),
        );
    }
    merge_object_field(&mut settings, "mcp", mcp);
    settings
        .entry("instructions".to_owned())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("OPENCODE_CONFIG_CONTENT instructions must be an array"))?
        .push(Value::String(
            instructions_path.to_string_lossy().into_owned(),
        ));

    print_agent_workspace_banner(
        "opencode",
        "OPENCODE_CONFIG_CONTENT/MCP",
        &local_root,
        &servers,
    );
    let mut command = tokio::process::Command::new("opencode");
    command
        .current_dir(&local_root)
        .env("OPENCODE_CONFIG_CONTENT", serde_json::to_string(&settings)?)
        .args(arguments)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true);
    let status = command
        .status()
        .await
        .context("cannot launch the local OpenCode CLI; ensure `opencode` is in PATH")?;
    Ok(process_exit_code(status))
}

#[allow(clippy::too_many_arguments)]
async fn run_generic_mcp_agent(
    agent: &str,
    targets: Vec<Target>,
    local_root: PathBuf,
    arguments: Vec<String>,
    config: Option<PathBuf>,
    flags: LaunchFlags,
    mcp_config_flag: bool,
    prompt_flag: AgentPromptFlag,
    endpoints: Option<&[Option<SessionMcpEndpoint>]>,
) -> Result<u8> {
    let executable = std::env::current_exe().context("cannot locate the sshai executable")?;
    let servers = remote_servers(&targets);
    let instructions = dual_workspace_instructions(&local_root, &servers);
    let temporary = tempfile::Builder::new()
        .prefix("sshai-generic-agent-")
        .tempdir()
        .context("cannot create the generic MCP session directory")?;
    let config_path = temporary.path().join("mcp.json");
    let instructions_path = temporary.path().join("instructions.md");
    let mcp_config = serde_json::json!({
        "mcpServers": stdio_mcp_servers(
            &executable,
            &servers,
            &local_root,
            config.as_deref(),
            flags,
            true,
            endpoints,
        )
    });
    std::fs::write(&config_path, serde_json::to_vec_pretty(&mcp_config)?)?;
    std::fs::write(&instructions_path, &instructions)?;

    print_agent_workspace_banner(agent, "generic MCP environment", &local_root, &servers);
    let mut command = tokio::process::Command::new(agent);
    command
        .current_dir(&local_root)
        .env("SSHAI_MCP_CONFIG_PATH", &config_path)
        .env("MCP_CONFIG_PATH", &config_path)
        .env("SSHAI_INSTRUCTIONS_PATH", &instructions_path)
        .env("SSHAI_LOCAL_ROOT", &local_root)
        .env(
            "SSHAI_REMOTE_TARGETS",
            serde_json::to_string(&targets.iter().map(Target::to_string).collect::<Vec<_>>())?,
        );
    if mcp_config_flag {
        command.arg("--mcp-config").arg(&config_path);
    }
    match prompt_flag {
        AgentPromptFlag::AppendSystem => {
            command.arg("--append-system-prompt").arg(&instructions);
        }
        AgentPromptFlag::System => {
            command.arg("--system-prompt").arg(&instructions);
        }
        AgentPromptFlag::Interactive => {
            command.arg("--prompt-interactive").arg(&instructions);
        }
        AgentPromptFlag::None => {
            eprintln!(
                "sshai: {agent} has no recognized prompt flag; context is available at {}",
                instructions_path.display()
            );
        }
    }
    command
        .args(arguments)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true);
    let status = command
        .status()
        .await
        .with_context(|| format!("cannot launch local agent {agent:?}"))?;
    Ok(process_exit_code(status))
}

fn stdio_mcp_servers(
    executable: &Path,
    servers: &[RemoteServer],
    local_root: &Path,
    config: Option<&Path>,
    flags: LaunchFlags,
    include_type: bool,
    endpoints: Option<&[Option<SessionMcpEndpoint>]>,
) -> Map<String, Value> {
    servers
        .iter()
        .enumerate()
        .map(|(index, server)| {
            let mut value = serde_json::json!({
                "command": executable.to_string_lossy(),
                "args": sshai_mcp_arguments(
                    &server.target,
                    local_root,
                    config,
                    flags,
                    session_endpoint(endpoints, index),
                ),
            });
            if include_type {
                value
                    .as_object_mut()
                    .expect("MCP server config is an object")
                    .insert("type".to_owned(), Value::String("stdio".to_owned()));
            }
            (server.name.clone(), value)
        })
        .collect()
}

fn load_json_object_from_env(name: &str) -> Result<Map<String, Value>> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => serde_json::from_str::<Value>(&value)?
            .as_object()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("{name} must contain a JSON object")),
        _ => Ok(Map::new()),
    }
}

fn load_json_object_from_env_or_path(name: &str, default: &Path) -> Result<Map<String, Value>> {
    let path = std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| default.to_owned());
    match std::fs::read(&path) {
        Ok(contents) => serde_json::from_slice::<Value>(&contents)?
            .as_object()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("{} must contain a JSON object", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Map::new()),
        Err(error) => Err(error.into()),
    }
}

fn merge_object_field(target: &mut Map<String, Value>, key: &str, incoming: Map<String, Value>) {
    let existing = target
        .entry(key.to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(existing) = existing.as_object_mut() {
        existing.extend(incoming);
    } else {
        *existing = Value::Object(incoming);
    }
}

fn print_agent_workspace_banner(
    agent: &str,
    adapter: &str,
    local_root: &Path,
    servers: &[RemoteServer],
) {
    print_dual_workspace_banner(local_root, servers);
    eprintln!("  Agent  {agent} ({adapter})");
}

#[derive(Clone, Debug)]
struct RemoteServer {
    name: String,
    target: Target,
}

fn dual_workspace_instructions(local_root: &Path, servers: &[RemoteServer]) -> String {
    let remote_lines = servers
        .iter()
        .map(|server| format!("- REMOTE `{}`: `{}`", server.name, server.target))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "# sshai dual workspace\n\n\
    This session connects equally capable read-write workspaces:\n\
    - LOCAL: `{}` on `{}/{}`. Native filesystem, shell, and edit tools operate here.\n\
    {remote_lines}\n\
    Unqualified paths and ordinary shell/file tools mean LOCAL. Paths described as `local:` mean LOCAL.\n\
    Paths described as `remote:` mean the primary REMOTE. For multiple remotes, use the MCP server name shown above. Ordinary MCP workspace paths are relative to that server's remote workspace root; `workspace_transfer.remote_path` may instead be an explicit absolute remote path.\n\
    Both workspaces may be inspected, edited, built, tested, or used as the source or destination according to the user's request.\n\
    Before modifying a REMOTE, call that server's `workspace_info` and inspect relevant remote instruction files such as AGENTS.md. Local project instructions apply to local work; each remote's instruction files apply only to that remote.\n\
    Use `workspace_exec` for remote Git, builds, tests, formatters, package managers, and system inspection. Use the native shell for local commands.\n\
    Use `workspace_transfer` for non-overwriting file or directory copies between LOCAL and REMOTE so bulk bytes travel directly over SSH instead of through model context. Use `workspace_transfer_overwrite` only when the user explicitly asks to replace existing destination files.\n\
    When the user asks to upload or copy LOCAL content to REMOTE, call `workspace_transfer`; never use remote `cp`, `rsync`, or `workspace_exec` as if a remote process could see LOCAL files.\n\
The user explicitly selected every listed REMOTE when launching sshai. An unqualified reference to `remote` means the primary REMOTE, so do not require the user to repeat its hostname. An explicit request to upload the LOCAL current directory authorizes a non-overwriting transfer of that directory; do not inspect every file merely to ask for the same authorization again.\n\
    For REMOTE-to-REMOTE copies, transfer through an explicit temporary LOCAL path and remove it afterwards; never route bulk file bytes through model context.\n\
    When an operation is destructive or its destination is ambiguous, state LOCAL or the named REMOTE explicitly before acting. Never silently synchronize, copy secrets, or assume identically named paths refer to the same machine.\n",
        local_root.display(),
        std::env::consts::OS,
        std::env::consts::ARCH,
    )
}

fn print_dual_workspace_banner(local_root: &Path, servers: &[RemoteServer]) {
    eprintln!("sshai dual workspace");
    eprintln!(
        "  Local  [rw] {}/{}  {}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        local_root.display()
    );
    for server in servers {
        eprintln!("  Remote [rw] {:<18} {}", server.name, server.target);
    }
}

fn remote_servers(targets: &[Target]) -> Vec<RemoteServer> {
    let mut used = std::collections::BTreeSet::new();
    targets
        .iter()
        .enumerate()
        .map(|(index, target)| {
            let base = format!("sshai_{}", sanitize_server_name(&target.host));
            let mut name = base.clone();
            let mut suffix = 2;
            while !used.insert(name.clone()) {
                name = format!("{base}_{suffix}");
                suffix += 1;
            }
            if name == "sshai_" {
                name = format!("sshai_remote_{}", index + 1);
            }
            RemoteServer {
                name,
                target: target.clone(),
            }
        })
        .collect()
}

fn sanitize_server_name(host: &str) -> String {
    let mut name = host
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    if name.starts_with(|character: char| character.is_ascii_digit()) {
        name.insert_str(0, "host_");
    }
    name
}

fn session_agent_arguments(
    default_local_root: &Path,
    arguments: &[String],
) -> Result<(PathBuf, Vec<String>)> {
    let mut local_dir = None;
    let mut forwarded = Vec::with_capacity(arguments.len());
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            forwarded.extend_from_slice(&arguments[index + 1..]);
            break;
        }
        if argument == "--local-dir" {
            index += 1;
            let path = arguments
                .get(index)
                .context("--local-dir requires a local path")?;
            if local_dir.replace(PathBuf::from(path)).is_some() {
                anyhow::bail!("--local-dir may only be specified once");
            }
        } else if let Some(path) = argument.strip_prefix("--local-dir=") {
            if path.is_empty() {
                anyhow::bail!("--local-dir requires a local path");
            }
            if local_dir.replace(PathBuf::from(path)).is_some() {
                anyhow::bail!("--local-dir may only be specified once");
            }
        } else {
            forwarded.push(argument.clone());
        }
        index += 1;
    }
    let local_root = resolve_local_root(default_local_root, local_dir.as_deref())?;
    Ok((local_root, forwarded))
}

fn resolve_local_root(base: &Path, requested: Option<&Path>) -> Result<PathBuf> {
    let requested = requested.unwrap_or(base);
    let expanded = expand_local_home(requested)?;
    let candidate = if expanded.is_absolute() {
        expanded
    } else {
        base.join(expanded)
    };
    let canonical = candidate
        .canonicalize()
        .with_context(|| format!("cannot open local workspace {}", candidate.display()))?;
    if !canonical.is_dir() {
        anyhow::bail!(
            "local workspace is not a directory: {}",
            canonical.display()
        );
    }
    Ok(canonical)
}

fn expand_local_home(path: &Path) -> Result<PathBuf> {
    let text = path.to_string_lossy();
    if text == "~" || text.starts_with("~/") {
        let home = std::env::var_os("HOME").context("cannot expand ~ because HOME is not set")?;
        let suffix = text.strip_prefix("~/").unwrap_or("");
        return Ok(PathBuf::from(home).join(suffix));
    }
    Ok(path.to_owned())
}

fn process_exit_code(status: std::process::ExitStatus) -> u8 {
    status
        .code()
        .map(|code| u8::try_from(code.clamp(0, 255)).unwrap_or(255))
        .unwrap_or(128)
}

struct SyncFlags {
    once: bool,
    interval: Duration,
    ignores: Vec<String>,
    policy: ConflictPolicy,
    propagate_deletes: bool,
    dry_run: bool,
    state: Option<PathBuf>,
}

async fn run_sync(
    connector: &SshConnector,
    target: Target,
    local: &Path,
    remote: &str,
    flags: SyncFlags,
) -> Result<u8> {
    // The remote worker is rooted at the synchronized directory, so every
    // remote path it sees stays inside it.
    let mut rooted = target.clone();
    rooted.path = Some(remote.to_owned());
    let endpoint = format!(
        "{}{}",
        rooted
            .user
            .as_deref()
            .map(|user| format!("{user}@"))
            .unwrap_or_default(),
        rooted
            .port
            .map(|port| format!("{}:{port}", rooted.host))
            .unwrap_or_else(|| rooted.host.clone()),
    );
    let state_path = match flags.state.clone() {
        Some(path) => path,
        None => default_sync_state_path(local, &endpoint, remote)?,
    };
    let session = Arc::new(connector.connect(&rooted).await?);
    let result = async {
        let mut sync = SyncSession::open(
            &session,
            local,
            remote,
            SyncOptions {
                ignores: flags.ignores.clone(),
                policy: flags.policy,
                propagate_deletes: flags.propagate_deletes,
                dry_run: flags.dry_run,
                state_path: state_path.clone(),
            },
        )
        .await?;
        let first_run = !sync.has_ancestor();
        eprintln!(
            "sshai sync: {} <-> {endpoint}:{}",
            sync.local_root().display(),
            sync.remote_root(),
        );
        eprintln!(
            "  state {}{}{}",
            sync.state_path().display(),
            if first_run {
                "; first run, so nothing is deleted"
            } else {
                ""
            },
            if flags.dry_run { "; dry run" } else { "" },
        );

        let mut exit = 0_u8;
        let mut cycle = 0_u64;
        loop {
            cycle += 1;
            let report = sync.cycle().await?;
            if cycle == 1 || !report.is_quiet() {
                print_sync_report(&report);
            }
            if !report.conflicts.is_empty() || !report.failures.is_empty() {
                exit = 1;
            }
            if flags.once || flags.dry_run {
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep(flags.interval) => {}
                result = tokio::signal::ctrl_c() => {
                    result.map_err(anyhow::Error::from)?;
                    eprintln!("sshai sync: stopped");
                    exit = 0;
                    break;
                }
            }
        }
        sync.close().await?;
        Ok::<u8, anyhow::Error>(exit)
    }
    .await;
    let disconnect = session.disconnect().await;
    let exit = result?;
    disconnect?;
    Ok(exit)
}

fn default_sync_state_path(local: &Path, endpoint: &str, remote: &str) -> Result<PathBuf> {
    let base = dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .context("cannot determine a local state directory; pass --state")?;
    let canonical = local.canonicalize().unwrap_or_else(|_| local.to_path_buf());
    Ok(base
        .join("sshai")
        .join("sync")
        .join(state_file_name(&canonical, endpoint, remote)))
}

fn print_sync_report(report: &CycleReport) {
    for action in &report.applied {
        let (marker, label, path) = match action {
            Action::CopyFile { to, path } => (arrow(*to), "", path),
            Action::CreateDirectory { side, path } => (arrow(*side), "mkdir ", path),
            Action::Delete { side, path, .. } => (arrow(*side), "delete ", path),
        };
        println!("  {marker} {label}{path}");
    }
    for (action, error) in &report.failures {
        println!("  ! {} failed: {error}", action.path());
    }
    for conflict in &report.conflicts {
        println!("  x {} ({})", conflict.path, conflict_reason(conflict));
    }
    for (side, path) in &report.withheld_deletes {
        println!(
            "  - {path} was deleted on the other side; kept on {} (--no-delete)",
            side.name()
        );
    }
    let verb = if report.dry_run {
        "would change"
    } else {
        "applied"
    };
    eprintln!(
        "  {} local / {} remote entries, {} unchanged, hashed {}/{}, {verb} {}{}{}{} in {:.1}s",
        report.local_entries,
        report.remote_entries,
        report.unchanged,
        report.hashed_local,
        report.hashed_remote,
        report.applied.len(),
        if report.conflicts.is_empty() {
            String::new()
        } else {
            format!(", {} conflicts", report.conflicts.len())
        },
        if report.failures.is_empty() {
            String::new()
        } else {
            format!(", {} failed", report.failures.len())
        },
        if report.skipped_symlinks == 0 {
            String::new()
        } else {
            format!(", skipped {} symlinks", report.skipped_symlinks)
        },
        report.duration.as_secs_f64(),
    );
}

/// Which way an action moves, from the local side's point of view.
fn arrow(side: Side) -> &'static str {
    match side {
        Side::Local => "<-",
        Side::Remote => "->",
    }
}

fn conflict_reason(conflict: &Conflict) -> String {
    match conflict.reason {
        ConflictReason::BothChanged => "both sides changed".to_owned(),
        ConflictReason::DeletedAndChanged { deleted } => {
            format!(
                "deleted on {}, changed on {}",
                deleted.name(),
                deleted.other().name()
            )
        }
        ConflictReason::KindMismatch => "a file on one side, a directory on the other".to_owned(),
        ConflictReason::DirectoryHasChanges { deleted } => format!(
            "deleted on {}, but still holds content on {}",
            deleted.name(),
            deleted.other().name()
        ),
        ConflictReason::DirectoryHoldsIgnored { deleted } => format!(
            "deleted on {}, but still holds ignored content on {}",
            deleted.name(),
            deleted.other().name()
        ),
    }
}

async fn run_session_mcp_proxy(address: SocketAddr, token: &str) -> Result<()> {
    anyhow::ensure!(
        address.ip().is_loopback(),
        "session MCP bridge must be loopback-only"
    );
    anyhow::ensure!(token.len() == 64, "invalid session MCP bridge token");
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .with_context(|| format!("cannot connect to the parent sshai session at {address}"))?;
    stream.write_all(token.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    let (mut bridge_read, mut bridge_write) = stream.into_split();
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let upload = async {
        tokio::io::copy(&mut stdin, &mut bridge_write).await?;
        bridge_write.shutdown().await
    };
    let download = async {
        tokio::io::copy(&mut bridge_read, &mut stdout).await?;
        stdout.flush().await
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

fn sshai_mcp_arguments(
    target: &Target,
    local_root: &Path,
    config: Option<&std::path::Path>,
    flags: LaunchFlags,
    endpoint: Option<&SessionMcpEndpoint>,
) -> Vec<String> {
    if let Some(endpoint) = endpoint {
        return vec![
            "session-mcp-proxy".to_owned(),
            endpoint.address.to_string(),
            "--token".to_owned(),
            endpoint.token.clone(),
        ];
    }
    let mut arguments = Vec::new();
    if let Some(config) = config {
        arguments.push("-F".to_owned());
        arguments.push(config.to_string_lossy().into_owned());
    }
    if flags.strict_host_key {
        arguments.push("--strict-host-key".to_owned());
    }
    if flags.accept_new {
        arguments.push("--accept-new".to_owned());
    }
    if flags.insecure {
        arguments.push("--insecure".to_owned());
    }
    if flags.batch {
        arguments.push("--batch".to_owned());
    }
    for _ in 0..flags.verbose {
        arguments.push("-v".to_owned());
    }
    arguments.push("mcp".to_owned());
    arguments.push(target.to_string());
    arguments.push("--local-dir".to_owned());
    arguments.push(local_root.to_string_lossy().into_owned());
    arguments
}

fn session_endpoint(
    endpoints: Option<&[Option<SessionMcpEndpoint>]>,
    index: usize,
) -> Option<&SessionMcpEndpoint> {
    endpoints?.get(index)?.as_ref()
}

async fn run_builtin_agent(
    workspace: &mut WorkspaceClient,
    target: &Target,
    model: Option<String>,
    api_base: Option<String>,
    approval: ApprovalArg,
    max_tool_calls: usize,
    prompt: Vec<String>,
) -> Result<u8> {
    let api_key = std::env::var("OPENAI_API_KEY").context(
        "the built-in agent requires local OPENAI_API_KEY; it is never sent to the remote host",
    )?;
    let model = model
        .or_else(|| std::env::var("OPENAI_MODEL").ok())
        .unwrap_or_else(|| "gpt-5.4-mini".to_owned());
    let api_base = api_base
        .or_else(|| std::env::var("OPENAI_BASE_URL").ok())
        .unwrap_or_else(|| "https://api.openai.com/v1".to_owned());
    let provider = OpenAiProvider::new(api_key, model, &api_base)?;
    let model_name = provider.model().to_owned();
    let mut agent = AgentSession::new(provider, max_tool_calls)?;
    let (root, _) = workspace.open().await?;
    let mut ui = TerminalAgentUi { approval };

    if !prompt.is_empty() {
        let answer = agent.run_turn(workspace, prompt.join(" "), &mut ui).await?;
        println!("{answer}");
        return Ok(0);
    }

    if !std::io::stdin().is_terminal() {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input)?;
        let answer = agent.run_turn(workspace, input, &mut ui).await?;
        println!("{answer}");
        return Ok(0);
    }

    eprintln!("sshai agent · {model_name} · {target} · {root}");
    eprintln!("Commands: /clear, /help, /exit");
    loop {
        eprint!("> ");
        std::io::stderr().flush()?;
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input)? == 0 {
            break;
        }
        let input = input.trim();
        match input {
            "" => continue,
            "/exit" | "/quit" => break,
            "/clear" => {
                agent.clear();
                eprintln!("conversation cleared");
            }
            "/help" => eprintln!(
                "Enter a request for the remote workspace. /clear resets model context; /exit closes the SSH session."
            ),
            prompt => match agent.run_turn(workspace, prompt, &mut ui).await {
                Ok(answer) => println!("{answer}"),
                Err(error) => eprintln!("agent: {error:#}"),
            },
        }
    }
    Ok(0)
}

async fn run_workspace_operation(
    workspace: &mut WorkspaceClient,
    operation: WorkspaceOperation,
) -> Result<u8> {
    match operation {
        WorkspaceOperation::Open => {
            let (root, capabilities) = workspace.open().await?;
            println!("root: {root}");
            println!("capabilities: {}", capabilities.join(", "));
            Ok(0)
        }
        WorkspaceOperation::List {
            path,
            cursor,
            limit,
        } => {
            let (entries, next_cursor) = workspace.list(path, cursor, limit).await?;
            for entry in entries {
                println!(
                    "{}\t{}\t{}",
                    file_kind(&entry.metadata),
                    entry.metadata.size,
                    entry.name
                );
            }
            if let Some(cursor) = next_cursor {
                eprintln!("next cursor: {cursor}");
            }
            Ok(0)
        }
        WorkspaceOperation::Stat { path } => {
            let metadata = workspace.stat(path).await?;
            println!("kind: {}", file_kind(&metadata));
            println!("size: {}", metadata.size);
            if let Some(modified) = metadata.modified_unix_ms {
                println!("modified_unix_ms: {modified}");
            }
            if let Some(mode) = metadata.mode {
                println!("mode: {:o}", mode);
            }
            Ok(0)
        }
        WorkspaceOperation::Read {
            path,
            offset,
            length,
        } => {
            let (data, _) = workspace.read(path, offset, length).await?;
            let mut stdout = tokio::io::stdout();
            stdout.write_all(&data).await?;
            stdout.flush().await?;
            Ok(0)
        }
        WorkspaceOperation::Hash { path } => {
            let (algorithm, digest) = workspace.hash(path).await?;
            println!("{algorithm}:{digest}");
            Ok(0)
        }
        WorkspaceOperation::Exec {
            cwd,
            env,
            pty,
            shell,
            command,
        } => {
            let env = env
                .into_iter()
                .map(|value| {
                    value.split_once('=').map_or_else(
                        || anyhow::bail!("--env requires KEY=VALUE, got {value:?}"),
                        |(key, value)| Ok((key.to_owned(), value.to_owned())),
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            if shell && command.len() != 1 {
                anyhow::bail!(
                    "--shell requires exactly one quoted command string, for example: --shell -- 'ls | head'"
                );
            }
            let result = workspace
                .exec_to_terminal(WorkspaceStreamExecOptions {
                    argv: command,
                    cwd,
                    env,
                    pty,
                    shell,
                })
                .await?;
            Ok(match (result.exit_code, result.signal) {
                (Some(code), _) => u8::try_from(code.clamp(0, 255)).unwrap_or(255),
                (None, Some(signal)) => {
                    u8::try_from((128_i32 + signal).clamp(0, 255)).unwrap_or(255)
                }
                (None, None) => 255,
            })
        }
    }
}

fn file_kind(metadata: &WorkspaceMetadata) -> &'static str {
    match metadata.kind {
        sshai_ssh::WorkspaceFileKind::File => "file",
        sshai_ssh::WorkspaceFileKind::Directory => "directory",
        sshai_ssh::WorkspaceFileKind::Symlink => "symlink",
        sshai_ssh::WorkspaceFileKind::Other => "other",
    }
}

fn requested_host_key_policy(cli: &Cli) -> Option<HostKeyPolicy> {
    if cli.strict_host_key {
        Some(HostKeyPolicy::Strict)
    } else if cli.accept_new {
        Some(HostKeyPolicy::AcceptNew)
    } else if cli.insecure {
        Some(HostKeyPolicy::Insecure)
    } else {
        None
    }
}

fn init_logging(verbose: u8) {
    let default = match verbose {
        0 => "warn",
        1 => "sshai=debug,sshai_ssh=debug",
        _ => "debug",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(verbose > 1)
        .with_writer(std::io::stderr)
        .init();
}

fn exit_code(code: Option<u32>, signal: Option<&str>) -> u8 {
    match code {
        Some(code) => u8::try_from(code.min(255)).unwrap_or(255),
        None if signal.is_some() => 128,
        None => 255,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_bare_target_as_the_interactive_shell() {
        let cli = Cli::try_parse_from(["sshai", "ka@ka2:2222", "-v", "--no-agent"]).unwrap();

        let target = cli.target.unwrap().primary().clone();
        assert_eq!(target.host, "ka2");
        assert_eq!(target.user.as_deref(), Some("ka"));
        assert_eq!(target.port, Some(2222));
        assert_eq!(target.to_string(), "ka@ka2:2222");
        assert!(cli.command.is_none());
        assert_eq!(cli.verbose, 1);
        assert!(cli.no_worker);
    }

    #[test]
    fn still_recognizes_named_subcommands() {
        let cli = Cli::try_parse_from(["sshai", "doctor", "ka@ka2", "--config-only"]).unwrap();

        assert!(cli.target.is_none());
        assert!(matches!(
            cli.command,
            Some(Command::Doctor {
                target: Some(_),
                config_only: true
            })
        ));
    }

    #[test]
    fn rejects_the_removed_ssh_subcommand_form() {
        assert!(Cli::try_parse_from(["sshai", "ssh", "ka@ka2"]).is_err());
    }

    #[test]
    fn rejects_mixing_a_target_with_a_subcommand() {
        assert!(Cli::try_parse_from(["sshai", "ka@ka2", "exec", "true"]).is_err());
    }

    #[test]
    fn session_codex_uses_the_remote_working_directory() {
        let targets = vec![
            "ssh://ka@ka2/initial".parse().unwrap(),
            "ssh://build/opt/build".parse().unwrap(),
        ];
        let targets = targets_at_session_remote_cwd(&targets, 0, Some("/srv/project"));

        assert_eq!(targets[0].to_string(), "ssh://ka@ka2/srv/project");
        assert_eq!(targets[1].to_string(), "ssh://build/opt/build");
    }

    #[test]
    fn session_agent_promotes_the_selected_remote() {
        let targets = vec![
            "ssh://ka@ka2/initial".parse().unwrap(),
            "ssh://build/opt/build".parse().unwrap(),
        ];
        let targets = targets_at_session_remote_cwd(&targets, 1, Some("/srv/current"));

        assert_eq!(targets[0].to_string(), "ssh://build/srv/current");
        assert_eq!(targets[1].to_string(), "ssh://ka@ka2/initial");
    }

    #[test]
    fn parses_explicit_agent_and_session_command() {
        let cli = Cli::try_parse_from(["sshai", "--agent", "claude", "ka@ka2", "--", "--version"])
            .unwrap();
        assert_eq!(cli.agent.as_deref(), Some("claude"));
        assert_eq!(cli.target.unwrap().to_string(), "ka@ka2");
        assert_eq!(cli.agent_arguments, ["--version"]);
        assert!(cli.command.is_none());

        let handler = AiSessionCommand {
            targets: vec!["ka@ka2".parse().unwrap()],
            local_root: std::env::current_dir().unwrap(),
            config: None,
            flags: LaunchFlags {
                strict_host_key: false,
                accept_new: false,
                insecure: false,
                batch: false,
                verbose: 0,
            },
            file_edit: None,
        };
        assert!(handler.handles("--agent"));
        assert!(handler.handles("--file"));
        assert!(!handler.handles("codex"));
        assert!(!handler.handles("claude"));
        assert!(!handler.handles("info"));
    }

    #[test]
    fn parses_direct_agent_local_directory() {
        let cli = Cli::try_parse_from([
            "sshai",
            "--agent",
            "codex",
            "--local-dir",
            ".",
            "ssh://ka@ka2/srv/project",
            "--",
            "--version",
        ])
        .unwrap();
        assert_eq!(cli.agent.as_deref(), Some("codex"));
        assert_eq!(cli.local_dir.as_deref(), Some(Path::new(".")));
        assert_eq!(cli.target.unwrap().to_string(), "ssh://ka@ka2/srv/project");
        assert_eq!(cli.agent_arguments, ["--version"]);
    }

    #[test]
    fn session_agent_extracts_local_directory_without_forwarding_it() {
        let base = std::env::current_dir().unwrap();
        let (root, forwarded) = session_agent_arguments(
            &base,
            &[
                "--local-dir=.".to_owned(),
                "--model".to_owned(),
                "test".to_owned(),
            ],
        )
        .unwrap();

        assert_eq!(root, base.canonicalize().unwrap());
        assert_eq!(forwarded, ["--model", "test"]);

        let (_, forwarded) =
            session_agent_arguments(&base, &["--".to_owned(), "--version".to_owned()]).unwrap();
        assert_eq!(forwarded, ["--version"]);
    }

    #[test]
    fn dual_workspace_prompt_assigns_native_tools_to_local() {
        let target: Target = "ssh://ka@ka2/srv/project".parse().unwrap();
        let servers = remote_servers(&[target]);
        let instructions = dual_workspace_instructions(Path::new("/local/project"), &servers);

        assert!(instructions.contains("ordinary shell/file tools mean LOCAL"));
        assert!(instructions.contains("workspace_transfer"));
        assert!(instructions.contains("never use remote `cp`"));
        assert!(instructions.contains("ssh://ka@ka2/srv/project"));
    }

    #[test]
    fn parses_multiple_interactive_and_agent_targets() {
        let cli = Cli::try_parse_from(["sshai", "host1,ssh://dev@host2/srv/app"]).unwrap();
        let targets = cli.target.unwrap().into_vec();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].host, "host1");
        assert_eq!(targets[1].to_string(), "ssh://dev@host2/srv/app");

        let cli = Cli::try_parse_from(["sshai", "--agent", "codex", "host1,host2"]).unwrap();
        assert_eq!(cli.agent.as_deref(), Some("codex"));
        assert_eq!(cli.target.unwrap().0.len(), 2);
    }

    #[test]
    fn bare_agent_like_name_is_always_an_ssh_target() {
        for host in ["codex", "claude", "gemini", "kimi"] {
            let cli = Cli::try_parse_from(["sshai", host]).unwrap();
            assert_eq!(cli.target.unwrap().to_string(), host);
            assert!(cli.agent.is_none());
            assert!(cli.command.is_none());
        }
    }

    #[test]
    fn explicit_agent_requires_a_target() {
        assert!(Cli::try_parse_from(["sshai", "--agent", "codex"]).is_err());
    }

    #[test]
    fn remote_server_names_are_stable_and_unique() {
        let targets = [
            "root@Build.Example".parse().unwrap(),
            "ssh://dev@build.example/srv".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
        ];
        let servers = remote_servers(&targets);
        assert_eq!(servers[0].name, "sshai_build_example");
        assert_eq!(servers[1].name, "sshai_build_example_2");
        assert_eq!(servers[2].name, "sshai_host_10_0_0_2");
    }

    #[test]
    fn parses_recursive_sftp_transfers_and_excludes() {
        let cli = Cli::try_parse_from([
            "sshai",
            "sftp",
            "host",
            "put",
            "-r",
            "--exclude",
            ".git",
            "--exclude",
            "node_modules",
            "./project",
            "/srv/project",
            "--force",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Sftp {
                operation: SftpOperation::Put {
                    recursive: true,
                    excludes,
                    force: true,
                    ..
                },
                ..
            }) if excludes == [".git", "node_modules"]
        ));

        let cli = Cli::try_parse_from([
            "sshai",
            "sftp",
            "host",
            "get",
            "--recursive",
            "/srv/project",
            "./project",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Sftp {
                operation: SftpOperation::Get {
                    recursive: true,
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn detects_known_and_generic_mcp_agent_adapters() {
        assert_eq!(
            detect_agent_adapter("gemini", "anything").unwrap(),
            DetectedAgent::Gemini
        );
        assert_eq!(
            detect_agent_adapter("opencode", "anything").unwrap(),
            DetectedAgent::OpenCode
        );
        assert_eq!(
            detect_agent_adapter(
                "custom-agent",
                "Supports MCP with --mcp-config and --append-system-prompt"
            )
            .unwrap(),
            DetectedAgent::GenericMcp {
                mcp_config_flag: true,
                prompt_flag: AgentPromptFlag::AppendSystem,
            }
        );
        assert!(detect_agent_adapter("ls", "list directory contents").is_err());
    }

    #[test]
    fn merges_session_mcp_without_discarding_existing_config() {
        let mut settings = serde_json::json!({
            "mcpServers": {"existing": {"command": "existing"}},
            "theme": "dark"
        })
        .as_object()
        .unwrap()
        .clone();
        merge_object_field(
            &mut settings,
            "mcpServers",
            serde_json::json!({"sshai_host": {"command": "sshai"}})
                .as_object()
                .unwrap()
                .clone(),
        );

        assert_eq!(settings["theme"], "dark");
        assert!(settings["mcpServers"]["existing"].is_object());
        assert!(settings["mcpServers"]["sshai_host"].is_object());
    }

    #[test]
    fn session_mcp_arguments_reuse_the_parent_transport() {
        let target: Target = "root@example.com:2222".parse().unwrap();
        let endpoint = SessionMcpEndpoint {
            address: "127.0.0.1:43123".parse().unwrap(),
            token: "ab".repeat(32),
        };
        let arguments = sshai_mcp_arguments(
            &target,
            Path::new("/local"),
            None,
            LaunchFlags {
                strict_host_key: false,
                accept_new: false,
                insecure: false,
                batch: false,
                verbose: 0,
            },
            Some(&endpoint),
        );

        assert_eq!(arguments[0], "session-mcp-proxy");
        assert_eq!(arguments[1], "127.0.0.1:43123");
        assert!(!arguments.iter().any(|argument| argument == "mcp"));
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.contains("example.com"))
        );
    }

    #[test]
    fn parses_internal_session_mcp_proxy() {
        let token = "cd".repeat(32);
        let cli = Cli::try_parse_from([
            "sshai",
            "session-mcp-proxy",
            "127.0.0.1:43123",
            "--token",
            &token,
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::SessionMcpProxy { address, token: parsed })
                if address == "127.0.0.1:43123".parse().unwrap() && parsed == token
        ));
    }
}
