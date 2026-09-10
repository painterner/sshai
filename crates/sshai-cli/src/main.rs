use std::{path::PathBuf, process::ExitCode};

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand};
use sshai_core::Target;
use sshai_ssh::{
    ConnectOptions, HostKeyPolicy, KeyInstallResult, SshConnector, discover_public_identities,
};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "sshai",
    version,
    about = "A future-facing, pure-Rust SSH workspace transport for local AI tools"
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

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Open an interactive remote shell with PTY support.
    Ssh {
        /// `host`, `user@host:/path`, or `ssh://user@host:port/path`.
        target: Target,

        /// Disable the per-session remote agent and its built-in commands.
        #[arg(long)]
        no_agent: bool,
    },

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

    /// Internal remote-agent entry points.
    #[command(hide = true)]
    Agent {
        #[command(subcommand)]
        operation: AgentOperation,
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
enum AgentOperation {
    #[command(hide = true)]
    Serve {
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        session_dir: PathBuf,
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
    let command = cli.command;
    if let Command::Agent { operation } = command {
        return run_agent(operation).await;
    }

    let options = ConnectOptions {
        config_file: cli.config,
        host_key_policy,
        allow_password: !cli.batch,
    };
    let connector = SshConnector::new(options).context("failed to initialize SSH")?;

    match command {
        Command::Ssh { target, no_agent } => {
            let session = connector.connect(&target).await?;
            let exit = if no_agent {
                session.interactive_shell().await?
            } else {
                session.interactive_shell_with_agent().await?
            };
            session.disconnect().await?;
            Ok(exit_code(exit.code, exit.signal.as_deref()))
        }
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
        Command::Agent { .. } => unreachable!("agent command handled before SSH initialization"),
    }
}

async fn run_agent(operation: AgentOperation) -> Result<u8> {
    match operation {
        AgentOperation::Serve {
            session_id,
            session_dir,
        } => {
            sshai_agent::serve(sshai_agent::ServeOptions {
                session_id,
                session_dir,
            })
            .await?;
            Ok(0)
        }
        AgentOperation::Invoke {
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
