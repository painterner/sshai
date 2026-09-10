use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use sshai_protocol::{
    ExecControlAction, ExecEvent, ExecMode, ExecSignal, ExecStartRequest, ExecStream,
    MAX_WORKSPACE_READ, TerminalSize, WorkspaceEntry, WorkspaceMetadata, WorkspaceOperation,
    WorkspaceValue,
};
use tokio::io::AsyncWriteExt;

use crate::{
    Result, SshError,
    agent::RemoteAgent,
    session::{InteractiveStdin, RawTerminalGuard, ResizeEvents, terminal_size},
};

#[derive(Debug)]
pub struct WorkspaceExecResult {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug)]
pub struct WorkspaceStreamExecOptions {
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: Vec<(String, String)>,
    pub pty: bool,
    pub shell: bool,
}

#[derive(Debug)]
pub struct WorkspaceStreamExecResult {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

pub struct WorkspaceClient {
    agent: RemoteAgent,
}

impl WorkspaceClient {
    pub(crate) fn new(agent: RemoteAgent) -> Self {
        Self { agent }
    }

    pub fn root(&self) -> &str {
        &self.agent.workspace_root
    }

    pub fn capabilities(&self) -> &[String] {
        &self.agent.capabilities
    }

    pub async fn open(&mut self) -> Result<(String, Vec<String>)> {
        match self
            .agent
            .workspace_request(WorkspaceOperation::Open)
            .await?
        {
            WorkspaceValue::Open { root, capabilities } => Ok((root, capabilities)),
            value => Err(unexpected("open", &value)),
        }
    }

    pub async fn list(
        &mut self,
        path: impl Into<String>,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<(Vec<WorkspaceEntry>, Option<String>)> {
        match self
            .agent
            .workspace_request(WorkspaceOperation::List {
                path: path.into(),
                cursor,
                limit,
            })
            .await?
        {
            WorkspaceValue::List {
                entries,
                next_cursor,
            } => Ok((entries, next_cursor)),
            value => Err(unexpected("list", &value)),
        }
    }

    pub async fn stat(&mut self, path: impl Into<String>) -> Result<WorkspaceMetadata> {
        match self
            .agent
            .workspace_request(WorkspaceOperation::Stat { path: path.into() })
            .await?
        {
            WorkspaceValue::Stat { metadata } => Ok(metadata),
            value => Err(unexpected("stat", &value)),
        }
    }

    pub async fn read(
        &mut self,
        path: impl Into<String>,
        offset: u64,
        length: u32,
    ) -> Result<(Vec<u8>, bool)> {
        if length == 0 || length > MAX_WORKSPACE_READ {
            return Err(SshError::Config(format!(
                "read length must be between 1 and {MAX_WORKSPACE_READ} bytes"
            )));
        }
        match self
            .agent
            .workspace_request(WorkspaceOperation::Read {
                path: path.into(),
                offset,
                length,
            })
            .await?
        {
            WorkspaceValue::Read { data_base64, eof } => {
                let data = BASE64
                    .decode(data_base64)
                    .map_err(|error| SshError::Agent(format!("invalid read payload: {error}")))?;
                Ok((data, eof))
            }
            value => Err(unexpected("read", &value)),
        }
    }

    pub async fn hash(&mut self, path: impl Into<String>) -> Result<(String, String)> {
        match self
            .agent
            .workspace_request(WorkspaceOperation::Hash { path: path.into() })
            .await?
        {
            WorkspaceValue::Hash { algorithm, digest } => Ok((algorithm, digest)),
            value => Err(unexpected("hash", &value)),
        }
    }

    pub async fn exec(
        &mut self,
        argv: Vec<String>,
        cwd: impl Into<String>,
        env: Vec<(String, String)>,
    ) -> Result<WorkspaceExecResult> {
        match self
            .agent
            .workspace_request(WorkspaceOperation::Exec {
                argv,
                cwd: cwd.into(),
                env,
            })
            .await?
        {
            WorkspaceValue::Exec {
                exit_code,
                stdout_base64,
                stderr_base64,
                truncated,
            } => {
                let stdout = BASE64.decode(stdout_base64).map_err(|error| {
                    SshError::Agent(format!("invalid exec stdout payload: {error}"))
                })?;
                let stderr = BASE64.decode(stderr_base64).map_err(|error| {
                    SshError::Agent(format!("invalid exec stderr payload: {error}"))
                })?;
                Ok(WorkspaceExecResult {
                    exit_code,
                    stdout,
                    stderr,
                    truncated,
                })
            }
            value => Err(unexpected("exec", &value)),
        }
    }

    pub async fn exec_to_terminal(
        &mut self,
        options: WorkspaceStreamExecOptions,
    ) -> Result<WorkspaceStreamExecResult> {
        if options.pty
            && (!std::io::IsTerminal::is_terminal(&std::io::stdin())
                || !std::io::IsTerminal::is_terminal(&std::io::stdout()))
        {
            return Err(SshError::Config(
                "PTY workspace execution requires a terminal".to_owned(),
            ));
        }
        let terminal = options.pty.then(current_terminal_size);
        let process_id = self
            .agent
            .start_exec(ExecStartRequest {
                request_id: 0,
                argv: options.argv,
                cwd: options.cwd,
                env: options.env,
                mode: if options.pty {
                    ExecMode::Pty
                } else {
                    ExecMode::Pipe
                },
                shell: options.shell,
                term: options
                    .pty
                    .then(|| std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned())),
                terminal,
            })
            .await?;
        if options.pty {
            self.run_pty(process_id).await
        } else {
            self.run_pipe(process_id).await
        }
    }

    async fn run_pipe(&mut self, process_id: u64) -> Result<WorkspaceStreamExecResult> {
        let mut interrupts = 0_u8;
        loop {
            tokio::select! {
                event = self.agent.next_exec_event(process_id) => {
                    if let Some(result) = write_exec_event(event?, process_id).await? {
                        return Ok(result);
                    }
                }
                interrupt = tokio::signal::ctrl_c() => {
                    interrupt?;
                    interrupts = interrupts.saturating_add(1);
                    let action = if interrupts == 1 {
                        ExecControlAction::Signal { signal: ExecSignal::Interrupt }
                    } else {
                        ExecControlAction::Cancel
                    };
                    self.agent.exec_control(process_id, action).await?;
                }
            }
        }
    }

    async fn run_pty(&mut self, process_id: u64) -> Result<WorkspaceStreamExecResult> {
        let _raw_mode = RawTerminalGuard::activate()?;
        let mut stdin = InteractiveStdin::new()?;
        let mut resize = ResizeEvents::new()?;
        let mut input = [0_u8; 16 * 1024];
        loop {
            tokio::select! {
                read = stdin.read(&mut input) => {
                    let read = read?;
                    if read > 0 {
                        self.agent.exec_control(
                            process_id,
                            ExecControlAction::Input {
                                data_base64: BASE64.encode(&input[..read]),
                            },
                        ).await?;
                    }
                }
                _ = resize.recv() => {
                    self.agent.exec_control(
                        process_id,
                        ExecControlAction::Resize { size: current_terminal_size() },
                    ).await?;
                }
                event = self.agent.next_exec_event(process_id) => {
                    if let Some(result) = write_exec_event(event?, process_id).await? {
                        return Ok(result);
                    }
                }
            }
        }
    }

    pub async fn close(&mut self) -> Result<()> {
        self.agent.shutdown().await
    }
}

async fn write_exec_event(
    event: ExecEvent,
    expected_process_id: u64,
) -> Result<Option<WorkspaceStreamExecResult>> {
    match event {
        ExecEvent::Output {
            process_id,
            stream,
            data_base64,
        } if process_id == expected_process_id => {
            let data = BASE64
                .decode(data_base64)
                .map_err(|error| SshError::Agent(format!("invalid exec output: {error}")))?;
            match stream {
                ExecStream::Stdout | ExecStream::Pty => {
                    let mut stdout = tokio::io::stdout();
                    stdout.write_all(&data).await?;
                    stdout.flush().await?;
                }
                ExecStream::Stderr => {
                    let mut stderr = tokio::io::stderr();
                    stderr.write_all(&data).await?;
                    stderr.flush().await?;
                }
            }
            Ok(None)
        }
        ExecEvent::Exited {
            process_id,
            exit_code,
            signal,
        } if process_id == expected_process_id => {
            Ok(Some(WorkspaceStreamExecResult { exit_code, signal }))
        }
        ExecEvent::Failed {
            process_id,
            message,
            ..
        } if process_id == Some(expected_process_id) => Err(SshError::Agent(message)),
        event => Err(SshError::Agent(format!(
            "unexpected exec event for process {expected_process_id}: {event:?}"
        ))),
    }
}

fn current_terminal_size() -> TerminalSize {
    let (columns, rows) = terminal_size();
    TerminalSize {
        columns: u16::try_from(columns).unwrap_or(u16::MAX),
        rows: u16::try_from(rows).unwrap_or(u16::MAX),
    }
}

fn unexpected(operation: &str, value: &WorkspaceValue) -> SshError {
    SshError::Agent(format!(
        "unexpected workspace response for {operation}: {value:?}"
    ))
}
