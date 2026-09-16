use std::io;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u16 = 4;
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;
pub const MAX_WORKSPACE_READ: u32 = 512 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentToClient {
    Ready {
        protocol: u16,
        session_id: String,
        bin_dir: String,
        shell_launcher: String,
        workspace_root: String,
        capabilities: Vec<String>,
    },
    Request(ControlRequest),
    WorkspaceResponse(WorkspaceResponse),
    ExecEvent(ExecEvent),
    Fatal {
        message: String,
    },
    Stopped,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientToAgent {
    Response(ControlResponse),
    WorkspaceRequest(WorkspaceRequest),
    ExecStart(ExecStartRequest),
    ExecControl(ExecControl),
    Shutdown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlRequest {
    pub id: u64,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlResponse {
    pub id: u64,
    pub exit_code: u8,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShimRequest {
    pub protocol: u16,
    pub session_id: String,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShimResponse {
    pub protocol: u16,
    pub exit_code: u8,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceRequest {
    pub id: u64,
    pub operation: WorkspaceOperation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum WorkspaceOperation {
    Open,
    List {
        path: String,
        cursor: Option<String>,
        limit: u32,
    },
    Stat {
        path: String,
    },
    Read {
        path: String,
        offset: u64,
        length: u32,
    },
    Hash {
        path: String,
    },
    Write {
        path: String,
        data_base64: String,
        expected_blake3: Option<String>,
        overwrite: bool,
        mode: Option<u32>,
    },
    Edit {
        path: String,
        old_text: String,
        new_text: String,
        expected_blake3: Option<String>,
    },
    Mkdir {
        path: String,
        recursive: bool,
    },
    Rename {
        from: String,
        to: String,
        overwrite: bool,
    },
    Remove {
        path: String,
        recursive: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceResponse {
    pub id: u64,
    pub outcome: WorkspaceOutcome,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WorkspaceOutcome {
    Ok { value: WorkspaceValue },
    Error { code: String, message: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "value", rename_all = "snake_case")]
pub enum WorkspaceValue {
    Open {
        root: String,
        capabilities: Vec<String>,
    },
    List {
        entries: Vec<WorkspaceEntry>,
        next_cursor: Option<String>,
    },
    Stat {
        metadata: WorkspaceMetadata,
    },
    Read {
        data_base64: String,
        eof: bool,
    },
    Hash {
        algorithm: String,
        digest: String,
    },
    Mutation {
        path: String,
        metadata: Option<WorkspaceMetadata>,
        blake3: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceEntry {
    pub name: String,
    pub metadata: WorkspaceMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceMetadata {
    pub kind: WorkspaceFileKind,
    pub size: u64,
    pub modified_unix_ms: Option<u64>,
    pub mode: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceFileKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecStartRequest {
    pub request_id: u64,
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: Vec<(String, String)>,
    pub mode: ExecMode,
    pub shell: bool,
    pub term: Option<String>,
    pub terminal: Option<TerminalSize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecMode {
    Pipe,
    Pty,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TerminalSize {
    pub columns: u16,
    pub rows: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecControl {
    pub process_id: u64,
    pub action: ExecControlAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ExecControlAction {
    Input { data_base64: String },
    Resize { size: TerminalSize },
    Signal { signal: ExecSignal },
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecSignal {
    Interrupt,
    Terminate,
    Kill,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ExecEvent {
    Started {
        request_id: u64,
        process_id: u64,
    },
    Output {
        process_id: u64,
        stream: ExecStream,
        data_base64: String,
    },
    Exited {
        process_id: u64,
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
    Failed {
        request_id: u64,
        process_id: Option<u64>,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecStream {
    Stdout,
    Stderr,
    Pty,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("control channel closed")]
    Closed,
    #[error("control frame is too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("invalid control frame: {0}")]
    InvalidFrame(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, ProtocolError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let length = match reader.read_u32().await {
        Ok(length) => length as usize,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(ProtocolError::Closed);
        }
        Err(error) => return Err(error.into()),
    };
    if length == 0 || length > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge(length));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}

pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(value)?;
    if payload.is_empty() || payload.len() > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge(payload.len()));
    }
    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_fragment_safe_frames() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let expected = ClientToAgent::Response(ControlResponse {
            id: 42,
            exit_code: 7,
            stdout: "out".to_owned(),
            stderr: "err".to_owned(),
        });
        let send = tokio::spawn(async move { write_frame(&mut writer, &expected).await });
        let received: ClientToAgent = read_frame(&mut reader).await.unwrap();
        send.await.unwrap().unwrap();
        match received {
            ClientToAgent::Response(response) => {
                assert_eq!(response.id, 42);
                assert_eq!(response.exit_code, 7);
            }
            ClientToAgent::WorkspaceRequest(_) => panic!("unexpected workspace request"),
            ClientToAgent::ExecStart(_) | ClientToAgent::ExecControl(_) => {
                panic!("unexpected exec message")
            }
            ClientToAgent::Shutdown => panic!("unexpected shutdown"),
        }
    }

    #[tokio::test]
    async fn rejects_oversized_frame_before_allocating_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer.write_u32((MAX_FRAME_SIZE + 1) as u32).await.unwrap();
        let error = read_frame::<_, ShimRequest>(&mut reader).await.unwrap_err();
        assert!(matches!(error, ProtocolError::FrameTooLarge(_)));
    }

    #[tokio::test]
    async fn shim_request_carries_the_remote_working_directory() {
        let (mut writer, mut reader) = tokio::io::duplex(512);
        let expected = ShimRequest {
            protocol: PROTOCOL_VERSION,
            session_id: "0123456789abcdef0123456789abcdef".to_owned(),
            argv: vec!["codex".to_owned(), "--help".to_owned()],
            cwd: Some("/srv/project".to_owned()),
        };
        let send = tokio::spawn(async move { write_frame(&mut writer, &expected).await });
        let received: ShimRequest = read_frame(&mut reader).await.unwrap();
        send.await.unwrap().unwrap();

        assert_eq!(received.protocol, PROTOCOL_VERSION);
        assert_eq!(received.argv, ["codex", "--help"]);
        assert_eq!(received.cwd.as_deref(), Some("/srv/project"));
    }
}
