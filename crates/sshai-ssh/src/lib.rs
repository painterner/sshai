//! Pure-Rust SSH transport for sshai.
//!
//! All `russh` types are intentionally kept inside this crate so the rest of
//! sshai depends on a small, stable transport API.

mod agent;
mod auth;
mod config;
mod error;
mod host_key;
mod identity;
mod session;
mod sftp;
mod sync;
mod workspace;

pub use config::{HostKeyPolicy, ResolvedTarget, SshConfig};
pub use error::{Result, SshError};
pub use identity::{PublicIdentity, discover_public_identities};
pub use session::{
    CommandExit, ConnectOptions, SessionCommandHandler, SessionCommandResult, SessionInputResult,
    SshConnector, SshSession,
};
pub use sftp::{KeyInstallResult, SftpClient, SftpTransferStats};
pub use sshai_protocol::{
    MAX_WORKSPACE_READ, WorkspaceEntry, WorkspaceFileKind, WorkspaceMetadata,
};
pub use sync::{
    Action, Conflict, ConflictPolicy, ConflictReason, CycleReport, Side, SyncOptions, SyncSession,
    VCS_IGNORES, state_file_name,
};
pub use workspace::{
    WorkspaceClient, WorkspaceExecResult, WorkspaceMutation, WorkspaceStreamExecOptions,
    WorkspaceStreamExecResult,
};
