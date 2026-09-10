use sshai_protocol::{
    AgentToClient, ClientToAgent, ControlRequest, ControlResponse, PROTOCOL_VERSION, read_frame,
    write_frame,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{Result, SshError};

trait AgentIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AgentIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(crate) struct RemoteAgent {
    io: Box<dyn AgentIo>,
    pub(crate) shell_launcher: String,
}

impl RemoteAgent {
    pub(crate) async fn connect<T>(io: T, expected_session_id: &str) -> Result<Self>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut io: Box<dyn AgentIo> = Box::new(io);
        let ready = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            read_frame::<_, AgentToClient>(&mut io),
        )
        .await
        .map_err(|_| SshError::Agent("startup timed out".to_owned()))??;
        match ready {
            AgentToClient::Ready {
                protocol,
                session_id,
                bin_dir: _,
                shell_launcher,
            } => {
                if protocol != PROTOCOL_VERSION {
                    return Err(SshError::Agent(format!(
                        "protocol mismatch: local={PROTOCOL_VERSION}, remote={protocol}"
                    )));
                }
                if session_id != expected_session_id {
                    return Err(SshError::Agent(
                        "remote agent returned a different session ID".to_owned(),
                    ));
                }
                Ok(Self { io, shell_launcher })
            }
            AgentToClient::Fatal { message } => Err(SshError::Agent(message)),
            AgentToClient::Request(_) => Err(SshError::Agent(
                "received a request before the ready handshake".to_owned(),
            )),
            AgentToClient::Stopped => Err(SshError::Agent(
                "remote agent stopped during startup".to_owned(),
            )),
        }
    }

    pub(crate) async fn receive(&mut self) -> Result<ControlRequest> {
        match read_frame::<_, AgentToClient>(&mut self.io).await? {
            AgentToClient::Request(request) => Ok(request),
            AgentToClient::Fatal { message } => Err(SshError::Agent(message)),
            AgentToClient::Ready { .. } => Err(SshError::Agent(
                "received a duplicate ready handshake".to_owned(),
            )),
            AgentToClient::Stopped => Err(SshError::Agent("remote agent stopped".to_owned())),
        }
    }

    pub(crate) async fn respond(&mut self, response: ControlResponse) -> Result<()> {
        write_frame(&mut self.io, &ClientToAgent::Response(response)).await?;
        Ok(())
    }

    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        write_frame(&mut self.io, &ClientToAgent::Shutdown).await?;
        let stopped = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_frame::<_, AgentToClient>(&mut self.io),
        )
        .await
        .map_err(|_| SshError::Agent("shutdown timed out".to_owned()))??;
        match stopped {
            AgentToClient::Stopped => Ok(()),
            AgentToClient::Fatal { message } => Err(SshError::Agent(message)),
            _ => Err(SshError::Agent(
                "unexpected message while stopping remote agent".to_owned(),
            )),
        }
    }
}
