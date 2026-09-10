use std::{
    collections::HashMap,
    fs::File,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::process::{CommandExt, ExitStatusExt},
    },
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use nix::{
    pty::{Winsize, openpty},
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use sshai_protocol::{
    ExecControl, ExecControlAction, ExecEvent, ExecMode, ExecSignal, ExecStartRequest, ExecStream,
    TerminalSize,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::{Mutex, mpsc},
};

use crate::workspace::WorkspaceRoot;

const EXEC_TIMEOUT: Duration = Duration::from_secs(300);
const EVENT_BUFFER: usize = 64;

#[derive(Debug)]
enum ProcessControl {
    Input(Vec<u8>),
    Resize(TerminalSize),
    Signal(ExecSignal),
    Cancel,
}

pub(crate) struct ExecManager {
    next_process_id: AtomicU64,
    processes: Mutex<HashMap<u64, ProcessRecord>>,
    events: mpsc::Sender<ExecEvent>,
    shutting_down: AtomicBool,
}

#[derive(Clone)]
struct ProcessRecord {
    controls: mpsc::Sender<ProcessControl>,
    os_pid: Arc<AtomicI32>,
}

impl ExecManager {
    pub(crate) fn new() -> (Arc<Self>, mpsc::Receiver<ExecEvent>) {
        let (events, receiver) = mpsc::channel(EVENT_BUFFER);
        (
            Arc::new(Self {
                next_process_id: AtomicU64::new(1),
                processes: Mutex::new(HashMap::new()),
                events,
                shutting_down: AtomicBool::new(false),
            }),
            receiver,
        )
    }

    pub(crate) async fn start(
        self: &Arc<Self>,
        workspace: WorkspaceRoot,
        request: ExecStartRequest,
    ) {
        let request_id = request.request_id;
        if self.shutting_down.load(Ordering::Acquire) {
            self.failed(request_id, None, anyhow!("agent is shutting down"))
                .await;
            return;
        }
        let cwd = match workspace.resolve_exec_cwd(&request.cwd).await {
            Ok(cwd) => cwd,
            Err(error) => {
                self.failed(request_id, None, error).await;
                return;
            }
        };
        if let Err(error) = validate_request(&request) {
            self.failed(request_id, None, error).await;
            return;
        }
        if self.shutting_down.load(Ordering::Acquire) {
            self.failed(request_id, None, anyhow!("agent is shutting down"))
                .await;
            return;
        }

        let process_id = self.next_process_id.fetch_add(1, Ordering::Relaxed);
        let (control_tx, control_rx) = mpsc::channel(32);
        let os_pid = Arc::new(AtomicI32::new(0));
        self.processes.lock().await.insert(
            process_id,
            ProcessRecord {
                controls: control_tx,
                os_pid: os_pid.clone(),
            },
        );
        let manager = self.clone();
        tokio::spawn(async move {
            let result = match request.mode {
                ExecMode::Pipe => {
                    run_pipe(
                        process_id,
                        request_id,
                        request,
                        cwd,
                        control_rx,
                        &manager.events,
                        &os_pid,
                    )
                    .await
                }
                ExecMode::Pty => {
                    run_pty(
                        process_id,
                        request_id,
                        request,
                        cwd,
                        control_rx,
                        &manager.events,
                        &os_pid,
                    )
                    .await
                }
            };
            manager.processes.lock().await.remove(&process_id);
            if let Err(error) = result {
                manager.failed(request_id, Some(process_id), error).await;
            }
        });
    }

    pub(crate) async fn control(&self, control: ExecControl) -> Result<()> {
        let action = match control.action {
            ExecControlAction::Input { data_base64 } => ProcessControl::Input(
                BASE64
                    .decode(data_base64)
                    .context("invalid exec input payload")?,
            ),
            ExecControlAction::Resize { size } => ProcessControl::Resize(size),
            ExecControlAction::Signal { signal } => ProcessControl::Signal(signal),
            ExecControlAction::Cancel => ProcessControl::Cancel,
        };
        let sender = self
            .processes
            .lock()
            .await
            .get(&control.process_id)
            .map(|record| record.controls.clone())
            .ok_or_else(|| anyhow!("unknown process ID {}", control.process_id))?;
        sender
            .send(action)
            .await
            .map_err(|_| anyhow!("process {} has already exited", control.process_id))
    }

    pub(crate) async fn shutdown_all(&self) {
        self.shutting_down.store(true, Ordering::Release);
        let processes = self
            .processes
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for process in processes {
            let os_pid = process.os_pid.load(Ordering::Acquire);
            if os_pid > 0 {
                let _ = kill_process_group(os_pid, Signal::SIGKILL);
            }
            let _ = process.controls.send(ProcessControl::Cancel).await;
        }
    }

    async fn failed(&self, request_id: u64, process_id: Option<u64>, error: anyhow::Error) {
        let _ = self
            .events
            .send(ExecEvent::Failed {
                request_id,
                process_id,
                message: format!("{error:#}"),
            })
            .await;
    }
}

async fn run_pipe(
    process_id: u64,
    request_id: u64,
    request: ExecStartRequest,
    cwd: std::path::PathBuf,
    mut controls: mpsc::Receiver<ProcessControl>,
    events: &mpsc::Sender<ExecEvent>,
    os_pid_slot: &AtomicI32,
) -> Result<()> {
    let argv = command_argv(&request)?;
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .current_dir(cwd)
        .envs(request.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command.as_std_mut().process_group(0);
    let mut child = command.spawn().context("cannot spawn workspace command")?;
    let os_pid = child
        .id()
        .ok_or_else(|| anyhow!("missing child process ID"))?;
    os_pid_slot.store(os_pid as i32, Ordering::Release);
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("missing stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("missing stderr"))?;
    events
        .send(ExecEvent::Started {
            request_id,
            process_id,
        })
        .await?;
    let stdout_task = tokio::spawn(pump_output(
        stdout,
        process_id,
        ExecStream::Stdout,
        events.clone(),
    ));
    let stderr_task = tokio::spawn(pump_output(
        stderr,
        process_id,
        ExecStream::Stderr,
        events.clone(),
    ));
    let timeout = tokio::time::sleep(EXEC_TIMEOUT);
    tokio::pin!(timeout);
    let status = loop {
        tokio::select! {
            status = child.wait() => break status?,
            _ = &mut timeout => {
                signal_group(os_pid, ExecSignal::Kill)?;
                break child.wait().await?;
            }
            control = controls.recv() => match control {
                Some(ProcessControl::Signal(signal)) => signal_group(os_pid, signal)?,
                Some(ProcessControl::Cancel) | None => signal_group(os_pid, ExecSignal::Kill)?,
                Some(ProcessControl::Input(_)) | Some(ProcessControl::Resize(_)) => {}
            }
        }
    };
    stdout_task.await??;
    stderr_task.await??;
    send_exit(events, process_id, status.code(), status.signal()).await
}

async fn run_pty(
    process_id: u64,
    request_id: u64,
    request: ExecStartRequest,
    cwd: std::path::PathBuf,
    mut controls: mpsc::Receiver<ProcessControl>,
    events: &mpsc::Sender<ExecEvent>,
    os_pid_slot: &AtomicI32,
) -> Result<()> {
    let size = request.terminal.unwrap_or(TerminalSize {
        columns: 80,
        rows: 24,
    });
    let term = request
        .term
        .clone()
        .unwrap_or_else(|| "xterm-256color".to_owned());
    let pair = openpty(Some(&winsize(size)), None).context("cannot allocate remote PTY")?;
    set_nonblocking(&pair.master)?;
    let master = Arc::new(tokio::io::unix::AsyncFd::new(pair.master)?);
    let slave = File::from(pair.slave);
    let stdin = slave.try_clone()?;
    let stdout = slave.try_clone()?;
    let stderr = slave;
    let argv = command_argv(&request)?;
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .current_dir(cwd)
        .envs(request.env)
        .env("TERM", term)
        .env("COLUMNS", size.columns.to_string())
        .env("LINES", size.rows.to_string())
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true);
    // SAFETY: this callback only invokes async-signal-safe libc operations between fork/exec.
    unsafe {
        command.pre_exec(|| {
            if nix::libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if nix::libc::ioctl(0, nix::libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let process_group = nix::libc::getpgrp();
            if nix::libc::ioctl(0, nix::libc::TIOCSPGRP, &process_group) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .context("cannot spawn PTY workspace command")?;
    drop(command);
    let os_pid = child
        .id()
        .ok_or_else(|| anyhow!("missing child process ID"))?;
    os_pid_slot.store(os_pid as i32, Ordering::Release);
    events
        .send(ExecEvent::Started {
            request_id,
            process_id,
        })
        .await?;
    let output_task = tokio::spawn(pump_pty(master.clone(), process_id, events.clone()));
    let timeout = tokio::time::sleep(EXEC_TIMEOUT);
    tokio::pin!(timeout);
    let status = loop {
        tokio::select! {
            status = child.wait() => break status?,
            _ = &mut timeout => {
                signal_group(os_pid, ExecSignal::Kill)?;
                break child.wait().await?;
            }
            control = controls.recv() => match control {
                Some(ProcessControl::Input(data)) => write_pty(&master, &data).await?,
                Some(ProcessControl::Resize(size)) => resize_pty(&master, size)?,
                Some(ProcessControl::Signal(signal)) => signal_group(os_pid, signal)?,
                Some(ProcessControl::Cancel) | None => signal_group(os_pid, ExecSignal::Kill)?,
            }
        }
    };
    output_task.await??;
    send_exit(events, process_id, status.code(), status.signal()).await
}

fn command_argv(request: &ExecStartRequest) -> Result<Vec<String>> {
    if request.argv.is_empty() {
        bail!("exec argv cannot be empty");
    }
    if request
        .env
        .iter()
        .any(|(key, _)| key.is_empty() || key.contains('='))
    {
        bail!("environment variable names must be non-empty and cannot contain '='");
    }
    if !request.shell {
        return Ok(request.argv.clone());
    }
    if request.argv.len() != 1 {
        bail!("--shell requires exactly one command string");
    }
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned());
    let option = if request.mode == ExecMode::Pty {
        "-lic"
    } else {
        "-lc"
    };
    Ok(vec![shell, option.to_owned(), request.argv[0].clone()])
}

fn validate_request(request: &ExecStartRequest) -> Result<()> {
    let _ = command_argv(request)?;
    if request.mode == ExecMode::Pty && request.terminal.is_none() {
        bail!("PTY execution requires a terminal size");
    }
    Ok(())
}

async fn pump_output<R>(
    mut reader: R,
    process_id: u64,
    stream: ExecStream,
    events: mpsc::Sender<ExecEvent>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        events
            .send(ExecEvent::Output {
                process_id,
                stream,
                data_base64: BASE64.encode(&buffer[..read]),
            })
            .await?;
    }
    Ok(())
}

async fn pump_pty(
    master: Arc<tokio::io::unix::AsyncFd<OwnedFd>>,
    process_id: u64,
    events: mpsc::Sender<ExecEvent>,
) -> Result<()> {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let mut readiness = master.readable().await?;
        let read = readiness
            .try_io(|inner| nix::unistd::read(inner.get_ref(), &mut buffer).map_err(errno_to_io));
        match read {
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => {
                events
                    .send(ExecEvent::Output {
                        process_id,
                        stream: ExecStream::Pty,
                        data_base64: BASE64.encode(&buffer[..read]),
                    })
                    .await?;
            }
            Ok(Err(error)) if error.raw_os_error() == Some(nix::libc::EIO) => break,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => continue,
        }
    }
    Ok(())
}

async fn write_pty(master: &tokio::io::unix::AsyncFd<OwnedFd>, data: &[u8]) -> Result<()> {
    let mut written = 0;
    while written < data.len() {
        let mut readiness = master.writable().await?;
        let result = readiness.try_io(|inner| {
            nix::unistd::write(inner.get_ref(), &data[written..]).map_err(errno_to_io)
        });
        match result {
            Ok(Ok(0)) => bail!("remote PTY closed while writing input"),
            Ok(Ok(count)) => written += count,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => continue,
        }
    }
    Ok(())
}

fn resize_pty(master: &tokio::io::unix::AsyncFd<OwnedFd>, size: TerminalSize) -> Result<()> {
    let size = winsize(size);
    // SAFETY: TIOCSWINSZ reads a valid winsize pointer and does not retain it.
    let result =
        unsafe { nix::libc::ioctl(master.get_ref().as_raw_fd(), nix::libc::TIOCSWINSZ, &size) };
    if result < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn winsize(size: TerminalSize) -> Winsize {
    Winsize {
        ws_row: size.rows,
        ws_col: size.columns,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
    // SAFETY: fcntl operates on a live owned descriptor and does not retain it.
    let flags = unsafe { nix::libc::fcntl(fd.as_raw_fd(), nix::libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: same valid descriptor, setting only O_NONBLOCK in the existing flags.
    if unsafe {
        nix::libc::fcntl(
            fd.as_raw_fd(),
            nix::libc::F_SETFL,
            flags | nix::libc::O_NONBLOCK,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn signal_group(os_pid: u32, signal: ExecSignal) -> Result<()> {
    let signal = match signal {
        ExecSignal::Interrupt => Signal::SIGINT,
        ExecSignal::Terminate => Signal::SIGTERM,
        ExecSignal::Kill => Signal::SIGKILL,
    };
    kill_process_group(os_pid as i32, signal)
}

fn kill_process_group(os_pid: i32, signal: Signal) -> Result<()> {
    match killpg(Pid::from_raw(os_pid), signal) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

async fn send_exit(
    events: &mpsc::Sender<ExecEvent>,
    process_id: u64,
    exit_code: Option<i32>,
    signal: Option<i32>,
) -> Result<()> {
    events
        .send(ExecEvent::Exited {
            process_id,
            exit_code,
            signal,
        })
        .await
        .map_err(Into::into)
}

fn errno_to_io(error: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(mode: ExecMode, command: &str) -> ExecStartRequest {
        ExecStartRequest {
            request_id: 77,
            argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), command.to_owned()],
            cwd: ".".to_owned(),
            env: vec![("SSHAI_TEST".to_owned(), "works".to_owned())],
            mode,
            shell: false,
            term: (mode == ExecMode::Pty).then(|| "xterm-256color".to_owned()),
            terminal: (mode == ExecMode::Pty).then_some(TerminalSize {
                columns: 80,
                rows: 24,
            }),
        }
    }

    #[tokio::test]
    async fn streams_pipe_stdout_stderr_and_exit() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = WorkspaceRoot::open(temporary.path()).await.unwrap();
        let (manager, mut events) = ExecManager::new();
        manager
            .start(
                workspace,
                request(
                    ExecMode::Pipe,
                    "printf '%s' \"$SSHAI_TEST\"; printf err >&2",
                ),
            )
            .await;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
                .await
                .unwrap()
                .unwrap();
            match event {
                ExecEvent::Started { request_id: 77, .. } => {}
                ExecEvent::Output {
                    stream,
                    data_base64,
                    ..
                } => match stream {
                    ExecStream::Stdout => stdout.extend(BASE64.decode(data_base64).unwrap()),
                    ExecStream::Stderr => stderr.extend(BASE64.decode(data_base64).unwrap()),
                    ExecStream::Pty => panic!("unexpected PTY output"),
                },
                ExecEvent::Exited { exit_code, .. } => {
                    assert_eq!(exit_code, Some(0));
                    break;
                }
                ExecEvent::Failed { message, .. } => panic!("exec failed: {message}"),
                _ => panic!("unexpected event"),
            }
        }
        assert_eq!(stdout, b"works");
        assert_eq!(stderr, b"err");
    }

    #[tokio::test]
    async fn pty_accepts_input_and_resize() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = WorkspaceRoot::open(temporary.path()).await.unwrap();
        let (manager, mut events) = ExecManager::new();
        manager
            .start(workspace, request(ExecMode::Pty, "read line; stty size"))
            .await;

        let process_id = match tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .unwrap()
            .unwrap()
        {
            ExecEvent::Started { process_id, .. } => process_id,
            event => panic!("unexpected initial event: {event:?}"),
        };
        manager
            .control(ExecControl {
                process_id,
                action: ExecControlAction::Resize {
                    size: TerminalSize {
                        columns: 100,
                        rows: 40,
                    },
                },
            })
            .await
            .unwrap();
        manager
            .control(ExecControl {
                process_id,
                action: ExecControlAction::Input {
                    data_base64: BASE64.encode(b"go\n"),
                },
            })
            .await
            .unwrap();

        let mut output = Vec::new();
        loop {
            let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
                .await
                .unwrap()
                .unwrap();
            match event {
                ExecEvent::Output { data_base64, .. } => {
                    output.extend(BASE64.decode(data_base64).unwrap())
                }
                ExecEvent::Exited { exit_code, .. } => {
                    assert_eq!(exit_code, Some(0));
                    break;
                }
                ExecEvent::Failed { message, .. } => panic!("PTY exec failed: {message}"),
                _ => {}
            }
        }
        let output = String::from_utf8_lossy(&output);
        assert!(output.contains("40 100"), "PTY output was {output:?}");
    }
}
