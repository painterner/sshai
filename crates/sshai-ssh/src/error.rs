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

impl SshError {
    /// Whether retrying through a newly authenticated SSH session may recover
    /// from this error. Configuration, authorization, and remote operation
    /// failures deliberately return false.
    pub fn is_connection_lost(&self) -> bool {
        match self {
            Self::Connect { .. } | Self::ConnectTimeout { .. } => true,
            Self::Io(error) => matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::UnexpectedEof
            ),
            Self::Russh(error) => matches!(
                error,
                russh::Error::Disconnect
                    | russh::Error::HUP
                    | russh::Error::ConnectionTimeout
                    | russh::Error::KeepaliveTimeout
                    | russh::Error::InactivityTimeout
                    | russh::Error::SendError
                    | russh::Error::RecvError
                    | russh::Error::WrongChannel
            ),
            Self::Protocol(sshai_protocol::ProtocolError::Closed) => true,
            Self::Protocol(sshai_protocol::ProtocolError::Io(error)) => matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::UnexpectedEof
            ),
            Self::Sftp(error) => {
                let message = error.to_string().to_ascii_lowercase();
                message.contains("eof")
                    || message.contains("senderror")
                    || message.contains("recverror")
                    || message.contains("channel closed")
                    || message.contains("connection closed")
                    || message == "timeout"
            }
            Self::Agent(message) => {
                let message = message.to_ascii_lowercase();
                message.contains("channel closed")
                    || message.contains("control channel closed")
                    || message.contains("remote agent stopped")
                    || message.contains("remote worker stopped")
                    || message.contains("startup timed out")
                    || message.contains("connection closed")
                    || message.contains("broken pipe")
            }
            Self::Config(_)
            | Self::HostKey { .. }
            | Self::Authentication { .. }
            | Self::PrivateKey { .. }
            | Self::MissingExitStatus
            | Self::RusshKey(_)
            | Self::SshKey(_)
            | Self::Protocol(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_only_transport_failures_as_reconnectable() {
        assert!(SshError::Protocol(sshai_protocol::ProtocolError::Closed).is_connection_lost());
        assert!(SshError::Russh(russh::Error::HUP).is_connection_lost());
        assert!(SshError::Agent("channel closed".to_owned()).is_connection_lost());
        assert!(!SshError::Config("bad path".to_owned()).is_connection_lost());
        assert!(!SshError::Agent("workspace not_found".to_owned()).is_connection_lost());
    }
}
