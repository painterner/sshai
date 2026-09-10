use std::{
    io::{IsTerminal, Read, Write},
    path::PathBuf,
    process::ExitCode,
};

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use serde_json::{Map, Value};
use sshai_ai::{AgentSession, AgentUi, OpenAiProvider};
use sshai_core::Target;
use sshai_ssh::{
    ConnectOptions, HostKeyPolicy, KeyInstallResult, MAX_WORKSPACE_READ, SshConnector,
    WorkspaceClient, WorkspaceMetadata, WorkspaceStreamExecOptions, discover_public_identities,
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

    /// `host`, `user@host:/path`, or `ssh://user@host:port/path` for an interactive shell.
    #[arg(value_name = "TARGET")]
    target: Option<Target>,

    /// Disable the per-session remote agent and its built-in commands.
    #[arg(long)]
    no_agent: bool,

    #[command(subcommand)]
    command: Option<Command>,
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

    /// Launch the locally authenticated Codex CLI against a remote workspace.
    #[command(trailing_var_arg = true)]
    Codex {
        /// `host`, `user@host:/path`, or `ssh://user@host:port/path`.
        target: Target,

        /// Arguments forwarded to the local Codex CLI.
        #[arg(allow_hyphen_values = true)]
        arguments: Vec<String>,
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

    /// Internal remote-worker entry points.
    #[command(hide = true)]
    Worker {
        #[command(subcommand)]
        operation: WorkerOperation,
    },
}

#[derive(Debug, Subcommand)]
enum SftpOperation {
    /// Download one remote file.
    Get {
        remote: String,
        local: PathBuf,
        #[arg(long)]
        force: bool,
    },

    /// Upload one local file.
    Put {
        local: PathBuf,
        remote: String,
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

#[derive(Debug, Subcommand)]
enum WorkerOperation {
    #[command(hide = true)]
    Serve {
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        session_dir: PathBuf,
        #[arg(long)]
        workspace_root: PathBuf,
    },

    #[command(hide = true, trailing_var_arg = true)]
    Invoke {
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        socket: PathBuf,
        #[arg(required = true, allow_hyphen_values = true)]
        argv: Vec<String>,
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
    let host_key_policy = requested_host_key_policy(&cli);
    let launch_config = cli.config.clone();
    let launch_flags = LaunchFlags {
        strict_host_key: cli.strict_host_key,
        accept_new: cli.accept_new,
        insecure: cli.insecure,
        batch: cli.batch,
        verbose: cli.verbose,
    };
    let command = cli.command;
    if let Some(Command::Worker { operation }) = command {
        return run_worker(operation).await;
    }
    if let Some(Command::Codex { target, arguments }) = command {
        return run_codex(target, arguments, launch_config, launch_flags).await;
    }

    let options = ConnectOptions {
        config_file: cli.config,
        host_key_policy,
        allow_password: !cli.batch,
    };
    let connector = SshConnector::new(options).context("failed to initialize SSH")?;

    if let Some(target) = cli.target {
        let session = connector.connect(&target).await?;
        let exit = if cli.no_agent {
            session.interactive_shell().await?
        } else {
            session.interactive_shell_with_agent().await?
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
                    force,
                } => sftp.download(remote, local, force).await?,
                SftpOperation::Put {
                    local,
                    remote,
                    force,
                } => sftp.upload(local, remote, force).await?,
            };
            sftp.close().await?;
            session.disconnect().await?;
            eprintln!("transferred {bytes} bytes");
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
        Command::Mcp { target } => {
            let session = connector.connect(&target).await?;
            let workspace = session.workspace().await?;
            let serve_result = sshai_mcp::serve(workspace).await;
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
        Command::Worker { .. } => unreachable!("worker command handled before SSH initialization"),
        Command::Codex { .. } => unreachable!("Codex command handled before SSH initialization"),
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

async fn run_codex(
    target: Target,
    arguments: Vec<String>,
    config: Option<PathBuf>,
    flags: LaunchFlags,
) -> Result<u8> {
    let executable = std::env::current_exe().context("cannot locate the sshai executable")?;
    let temporary = tempfile::Builder::new()
        .prefix("sshai-codex-")
        .tempdir()
        .context("cannot create the local Codex bridge directory")?;
    let instructions = format!(
        "# Remote sshai workspace\n\n\
This local directory is only a control shell for the remote workspace `{target}`.\n\
Do not inspect, create, edit, delete, or execute project files with local filesystem or shell tools.\n\
Use the `sshai` MCP tools for every project operation:\n\
- use `workspace_list`, `workspace_stat`, `workspace_read`, and `workspace_hash` to inspect files;\n\
- use `workspace_write`, `workspace_edit`, `workspace_mkdir`, `workspace_rename`, and `workspace_remove` to modify files;\n\
- use `workspace_exec` for every shell, Git, build, test, formatter, and package-manager command.\n\
All paths passed to these tools are relative to the remote workspace root.\n\
Read relevant remote instruction files such as AGENTS.md before making changes.\n"
    );
    std::fs::write(temporary.path().join("AGENTS.md"), instructions)?;

    let mcp_arguments = sshai_mcp_arguments(&target, config.as_deref(), flags);
    let command_override = format!(
        "mcp_servers.sshai.command={}",
        serde_json::to_string(&executable.to_string_lossy())?
    );
    let args_override = format!(
        "mcp_servers.sshai.args={}",
        serde_json::to_string(&mcp_arguments)?
    );

    let mut command = tokio::process::Command::new("codex");
    command
        .arg("-C")
        .arg(temporary.path())
        .arg("--sandbox")
        .arg("read-only")
        .arg("-c")
        .arg(command_override)
        .arg("-c")
        .arg(args_override)
        .arg("-c")
        .arg("mcp_servers.sshai.startup_timeout_sec=120")
        .arg("-c")
        .arg("mcp_servers.sshai.tool_timeout_sec=330")
        .arg("-c")
        .arg("mcp_servers.sshai.required=true")
        .arg("-c")
        .arg("mcp_servers.sshai.default_tools_approval_mode=\"writes\"")
        .args(arguments)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true);
    let status = command
        .status()
        .await
        .context("cannot launch the local Codex CLI; ensure `codex` is in PATH")?;
    Ok(status
        .code()
        .map(|code| u8::try_from(code.clamp(0, 255)).unwrap_or(255))
        .unwrap_or(128))
}

fn sshai_mcp_arguments(
    target: &Target,
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

async fn run_worker(operation: WorkerOperation) -> Result<u8> {
    match operation {
        WorkerOperation::Serve {
            session_id,
            session_dir,
            workspace_root,
        } => {
            sshai_agent::serve(sshai_agent::ServeOptions {
                session_id,
                session_dir,
                workspace_root,
            })
            .await?;
            Ok(0)
        }
        WorkerOperation::Invoke {
            session_id,
            socket,
            argv,
        } => {
            sshai_agent::invoke(sshai_agent::InvokeOptions {
                session_id,
                socket,
                argv,
            })
            .await
        }
    }
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
        assert!(cli.no_agent);
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
}
