use std::{io, path::PathBuf};

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SshError>;

#[derive(Debug, Error)]
pub enum SshError {
    #[error("SSH configuration error: {0}")]
    Config(String),

    #[error("could not connect to {host}:{port}: {source}")]
    Connect {
        host: String,
        port: u16,
        #[source]
        source: io::Error,
    },

    #[error("connection to {host}:{port} timed out after {seconds}s")]
    ConnectTimeout {
        host: String,
        port: u16,
        seconds: u64,
    },

    #[error("host key verification failed for {host}:{port}: {message}")]
    HostKey {
        host: String,
        port: u16,
        message: String,
    },

    #[error("authentication failed for {user}@{host}: {attempts}")]
    Authentication {
        user: String,
        host: String,
        attempts: String,
    },

    #[error("failed to load SSH key {path}: {message}")]
    PrivateKey { path: PathBuf, message: String },

    #[error("remote command terminated without reporting an exit status")]
    MissingExitStatus,

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Russh(#[from] russh::Error),

    #[error(transparent)]
    RusshKey(#[from] russh::keys::Error),

    #[error(transparent)]
    SshKey(#[from] russh::keys::ssh_key::Error),

    #[error(transparent)]
    Sftp(#[from] russh_sftp::client::error::Error),

    #[error(transparent)]
    Protocol(#[from] sshai_protocol::ProtocolError),

    #[error("remote sshai agent error: {0}")]
    Agent(String),
}
