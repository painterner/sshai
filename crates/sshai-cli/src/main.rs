use std::{
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
};

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use serde_json::{Map, Value};
use sshai_ai::{AgentSession, AgentUi, OpenAiProvider};
use sshai_core::Target;
use sshai_ssh::{
    ConnectOptions, HostKeyPolicy, KeyInstallResult, MAX_WORKSPACE_READ, SessionCommandHandler,
    SessionCommandResult, SshConnector, WorkspaceClient, WorkspaceMetadata,
    WorkspaceStreamExecOptions, discover_public_identities,
};
use tokio::io::AsyncWriteExt;
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
        /// `host`, `user@host:/path`, or `ssh://user@host:port/path`.
        target: Target,

        /// Command and arguments. Arguments are quoted individually.
        #[arg(required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Transfer bootstrap files through the pure-Rust SFTP channel.
    Sftp {
        /// `host`, `user@host`, or `ssh://user@host:port`.
        target: Target,

        #[command(subcommand)]
        operation: SftpOperation,
    },

    /// Inspect files rooted in, or execute commands from, the remote workspace.
    Workspace {
        /// `host`, `user@host:/path`, or `ssh://user@host:port/path`.
        target: Target,

        #[command(subcommand)]
        operation: WorkspaceOperation,
    },

    /// Serve the remote workspace as a local stdio MCP server.
    Mcp {
        /// `host`, `user@host:/path`, or `ssh://user@host:port/path`.
        target: Target,

        /// Local workspace exposed to transfer tools. Defaults to sshai's current directory.
        #[arg(long, value_name = "DIR")]
        local_dir: Option<PathBuf>,
    },

    /// Run sshai's built-in local AI agent against a remote workspace.
    #[command(trailing_var_arg = true)]
    Agent {
        /// `host`, `user@host:/path`, or `ssh://user@host:port/path`.
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
        /// `host`, `user@host`, or `ssh://user@host:port`.
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
        )
        .await;
    }

    let command = cli.command;

    let options = ConnectOptions {
        config_file: cli.config,
        host_key_policy,
        allow_password: !cli.batch,
        worker_executable: None,
    };
    let connector = SshConnector::new(options).context("failed to initialize SSH")?;

    if let Some(targets) = cli.target {
        let session = connector.connect(targets.primary()).await?;
        let exit = if cli.no_worker {
            if targets.0.len() > 1 {
                anyhow::bail!("multiple targets require the session worker; remove --no-worker");
            }
            session.interactive_shell().await?
        } else {
            let mut handler = AiSessionCommand {
                targets: targets.into_vec(),
                local_root: resolve_local_root(&launch_directory, None)?,
                config: launch_config,
                flags: launch_flags,
            };
            session
                .interactive_shell_with_agent_handler(&mut handler)
                .await?
        };
        session.disconnect().await?;
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
            let session = connector.connect(&target).await?;
            let workspace = session.workspace().await?;
            let sftp = session.sftp().await?;
            let local_root = resolve_local_root(&launch_directory, local_dir.as_deref())?;
            let serve_result = sshai_mcp::serve(workspace, sftp, local_root).await;
            let disconnect_result = session.disconnect().await;
            serve_result?;
            disconnect_result?;
            Ok(0)
        }
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

struct AiSessionCommand {
    targets: Vec<Target>,
    local_root: PathBuf,
    config: Option<PathBuf>,
    flags: LaunchFlags,
}

#[async_trait::async_trait]
impl SessionCommandHandler for AiSessionCommand {
    fn handles(&self, command: &str) -> bool {
        command == "--agent"
    }

    async fn handle(
        &mut self,
        command: &str,
        arguments: &[String],
        remote_cwd: Option<&str>,
    ) -> SessionCommandResult {
        let targets = targets_at_primary_remote_cwd(&self.targets, remote_cwd);
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

fn is_agent_name(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric())
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '+')
        })
}

fn targets_at_primary_remote_cwd(targets: &[Target], remote_cwd: Option<&str>) -> Vec<Target> {
    let mut targets = targets.to_vec();
    if let (Some(primary), Some(remote_cwd)) = (targets.first_mut(), remote_cwd) {
        primary.path = Some(remote_cwd.to_owned());
    }
    targets
}

async fn run_selected_agent(
    agent: &str,
    targets: Vec<Target>,
    local_root: PathBuf,
    arguments: Vec<String>,
    config: Option<PathBuf>,
    flags: LaunchFlags,
) -> Result<u8> {
    anyhow::ensure!(
        is_agent_name(agent),
        "invalid agent name {agent:?}; use an executable name, not a path"
    );
    match agent.to_ascii_lowercase().as_str() {
        "codex" => run_codex(targets, local_root, arguments, config, flags).await,
        "claude" => run_claude(targets, local_root, arguments, config, flags).await,
        _ => run_detected_agent(agent, targets, local_root, arguments, config, flags).await,
    }
}

async fn run_codex(
    targets: Vec<Target>,
    local_root: PathBuf,
    arguments: Vec<String>,
    config: Option<PathBuf>,
    flags: LaunchFlags,
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
    for server in &servers {
        let prefix = format!("mcp_servers.{}", server.name);
        let mcp_arguments =
            sshai_mcp_arguments(&server.target, &local_root, config.as_deref(), flags);
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
        DetectedAgent::Gemini => run_gemini(targets, local_root, arguments, config, flags).await,
        DetectedAgent::OpenCode => {
            run_opencode(targets, local_root, arguments, config, flags).await
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
    for server in &servers {
        let mut command = vec![executable.to_string_lossy().into_owned()];
        command.extend(sshai_mcp_arguments(
            &server.target,
            &local_root,
            config.as_deref(),
            flags,
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
) -> Map<String, Value> {
    servers
        .iter()
        .map(|server| {
            let mut value = serde_json::json!({
                "command": executable.to_string_lossy(),
                "args": sshai_mcp_arguments(&server.target, local_root, config, flags),
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

fn sshai_mcp_arguments(
    target: &Target,
    local_root: &Path,
    config: Option<&std::path::Path>,
    flags: LaunchFlags,
) -> Vec<String> {
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
        let cli = Cli::try_parse_from(["sshai", "ka@ka2", "-v", "--no-agent"]).unwrap();

        assert_eq!(cli.target.unwrap().to_string(), "ka@ka2");
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
            "ka@ka2:/initial".parse().unwrap(),
            "build:/opt/build".parse().unwrap(),
        ];
        let targets = targets_at_primary_remote_cwd(&targets, Some("/srv/project"));

        assert_eq!(targets[0].to_string(), "ka@ka2:/srv/project");
        assert_eq!(targets[1].to_string(), "build:/opt/build");
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
        };
        assert!(handler.handles("--agent"));
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
            "ka@ka2:/srv/project",
            "--",
            "--version",
        ])
        .unwrap();
        assert_eq!(cli.agent.as_deref(), Some("codex"));
        assert_eq!(cli.local_dir.as_deref(), Some(Path::new(".")));
        assert_eq!(cli.target.unwrap().to_string(), "ka@ka2:/srv/project");
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
        let target: Target = "ka@ka2:/srv/project".parse().unwrap();
        let servers = remote_servers(&[target]);
        let instructions = dual_workspace_instructions(Path::new("/local/project"), &servers);

        assert!(instructions.contains("ordinary shell/file tools mean LOCAL"));
        assert!(instructions.contains("workspace_transfer"));
        assert!(instructions.contains("never use remote `cp`"));
        assert!(instructions.contains("ka@ka2:/srv/project"));
    }

    #[test]
    fn parses_multiple_interactive_and_agent_targets() {
        let cli = Cli::try_parse_from(["sshai", "host1,dev@host2:/srv/app"]).unwrap();
        let targets = cli.target.unwrap().into_vec();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].host, "host1");
        assert_eq!(targets[1].to_string(), "dev@host2:/srv/app");

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
            "dev@build.example:/srv".parse().unwrap(),
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
}
