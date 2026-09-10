use sshai_protocol::{
    AgentToClient, ClientToAgent, ControlRequest, ControlResponse, ExecControl, ExecControlAction,
    ExecEvent, ExecStartRequest, PROTOCOL_VERSION, WorkspaceOperation, WorkspaceOutcome,
    WorkspaceValue, read_frame, write_frame,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{Result, SshError};

trait AgentIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AgentIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(crate) struct RemoteAgent {
    io: Box<dyn AgentIo>,
    pub(crate) shell_launcher: String,
    pub(crate) workspace_root: String,
    pub(crate) capabilities: Vec<String>,
    next_request_id: u64,
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
                workspace_root,
                capabilities,
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
                Ok(Self {
                    io,
                    shell_launcher,
                    workspace_root,
                    capabilities,
                    next_request_id: 1,
                })
            }
            AgentToClient::Fatal { message } => Err(SshError::Agent(message)),
            AgentToClient::Request(_) => Err(SshError::Agent(
                "received a request before the ready handshake".to_owned(),
            )),
            AgentToClient::WorkspaceResponse(_) => Err(SshError::Agent(
                "received a workspace response before the ready handshake".to_owned(),
            )),
            AgentToClient::ExecEvent(_) => Err(SshError::Agent(
                "received an exec event before the ready handshake".to_owned(),
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
            AgentToClient::WorkspaceResponse(_) => Err(SshError::Agent(
                "received an unexpected workspace response".to_owned(),
            )),
            AgentToClient::ExecEvent(_) => Err(SshError::Agent(
                "received an unexpected exec event".to_owned(),
            )),
            AgentToClient::Stopped => Err(SshError::Agent("remote agent stopped".to_owned())),
        }
    }

    pub(crate) async fn respond(&mut self, response: ControlResponse) -> Result<()> {
        write_frame(&mut self.io, &ClientToAgent::Response(response)).await?;
        Ok(())
    }

    pub(crate) async fn workspace_request(
        &mut self,
        operation: WorkspaceOperation,
    ) -> Result<WorkspaceValue> {
        let id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or_else(|| SshError::Agent("workspace request ID space exhausted".to_owned()))?;
        write_frame(
            &mut self.io,
            &ClientToAgent::WorkspaceRequest(sshai_protocol::WorkspaceRequest { id, operation }),
        )
        .await?;
        match read_frame::<_, AgentToClient>(&mut self.io).await? {
            AgentToClient::WorkspaceResponse(response) if response.id == id => {
                match response.outcome {
                    WorkspaceOutcome::Ok { value } => Ok(value),
                    WorkspaceOutcome::Error { code, message } => {
                        Err(SshError::Agent(format!("workspace {code}: {message}")))
                    }
                }
            }
            AgentToClient::WorkspaceResponse(response) => Err(SshError::Agent(format!(
                "workspace response ID mismatch: expected {id}, received {}",
                response.id
            ))),
            AgentToClient::Fatal { message } => Err(SshError::Agent(message)),
            AgentToClient::Stopped => Err(SshError::Agent("remote agent stopped".to_owned())),
            AgentToClient::Request(_) | AgentToClient::Ready { .. } => Err(SshError::Agent(
                "unexpected control message during workspace request".to_owned(),
            )),
            AgentToClient::ExecEvent(_) => Err(SshError::Agent(
                "unexpected exec event during workspace request".to_owned(),
            )),
        }
    }

    pub(crate) async fn start_exec(&mut self, mut request: ExecStartRequest) -> Result<u64> {
        let request_id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or_else(|| SshError::Agent("exec request ID space exhausted".to_owned()))?;
        request.request_id = request_id;
        write_frame(&mut self.io, &ClientToAgent::ExecStart(request)).await?;
        match read_frame::<_, AgentToClient>(&mut self.io).await? {
            AgentToClient::ExecEvent(ExecEvent::Started {
                request_id: received,
                process_id,
            }) if received == request_id => Ok(process_id),
            AgentToClient::ExecEvent(ExecEvent::Failed {
                request_id: received,
                message,
                ..
            }) if received == request_id => Err(SshError::Agent(message)),
            message => Err(SshError::Agent(format!(
                "unexpected message while starting exec: {message:?}"
            ))),
        }
    }

    pub(crate) async fn next_exec_event(&mut self, process_id: u64) -> Result<ExecEvent> {
        match read_frame::<_, AgentToClient>(&mut self.io).await? {
            AgentToClient::ExecEvent(event)
                if exec_event_process_id(&event) == Some(process_id) =>
            {
                Ok(event)
            }
            message => Err(SshError::Agent(format!(
                "unexpected message while running process {process_id}: {message:?}"
            ))),
        }
    }

    pub(crate) async fn exec_control(
        &mut self,
        process_id: u64,
        action: ExecControlAction,
    ) -> Result<()> {
        write_frame(
            &mut self.io,
            &ClientToAgent::ExecControl(ExecControl { process_id, action }),
        )
        .await?;
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

fn exec_event_process_id(event: &ExecEvent) -> Option<u64> {
    match event {
        ExecEvent::Started { process_id, .. }
        | ExecEvent::Output { process_id, .. }
        | ExecEvent::Exited { process_id, .. } => Some(*process_id),
        ExecEvent::Failed { process_id, .. } => *process_id,
    }
}
