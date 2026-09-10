use std::io;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentToClient {
    Ready {
        protocol: u16,
        session_id: String,
        bin_dir: String,
        shell_launcher: String,
    },
    Request(ControlRequest),
    Fatal {
        message: String,
    },
    Stopped,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientToAgent {
    Response(ControlResponse),
    Shutdown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlRequest {
    pub id: u64,
    pub argv: Vec<String>,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShimResponse {
    pub protocol: u16,
    pub exit_code: u8,
    pub stdout: String,
    pub stderr: String,
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
}
