use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    io::Read,
    net::SocketAddr,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::process::ExitStatusExt,
    },
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Json, Router,
    body::Body,
    extract::{
        Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{delete, get},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use clap::Parser;
use nix::{
    pty::{Winsize, openpty},
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    io::unix::AsyncFd,
    process::Command,
    sync::{Mutex, RwLock, broadcast, mpsc},
};
use tracing_subscriber::EnvFilter;

const HISTORY_LIMIT: usize = 4 * 1024 * 1024;
const INDEX_HTML: &str = include_str!("../assets/index.html");
const APP_JS: &[u8] = include_bytes!("../assets/app.js");
const APP_CSS: &[u8] = include_bytes!("../assets/app.css");

#[derive(Debug, Parser)]
#[command(
    name = "termm",
    about = "Native multi-pane terminal companion for sshai"
)]
struct Cli {
    /// Default sshai target list inherited by New and Split actions.
    #[arg(value_name = "TARGET[,TARGET...]")]
    target: Option<String>,

    /// Local working directory inherited by new panes.
    #[arg(long, value_name = "DIR")]
    cwd: Option<PathBuf>,

    /// Address for the local-only UI server.
    #[arg(long, default_value = "127.0.0.1:7636")]
    bind: SocketAddr,

    /// sshai executable launched inside remote panes.
    #[arg(long, default_value = "sshai")]
    sshai: PathBuf,

    /// Do not open the UI in the system browser.
    #[arg(long)]
    no_open: bool,
}

#[derive(Clone)]
struct AppState {
    context: TermmContext,
    token: String,
    sessions: Arc<RwLock<HashMap<String, Arc<TerminalSession>>>>,
    next_id: Arc<AtomicU64>,
}

#[derive(Clone, Debug, Serialize)]
struct TermmContext {
    default_target: Option<String>,
    local_cwd: String,
    sshai_path: String,
}

struct TerminalSession {
    info: RwLock<SessionInfo>,
    control: mpsc::Sender<PtyControl>,
    events: broadcast::Sender<SessionEvent>,
    history: Mutex<History>,
}

#[derive(Clone, Debug, Serialize)]
struct SessionInfo {
    id: String,
    title: String,
    target: Option<String>,
    local_cwd: String,
    phase: &'static str,
    created_unix_ms: u64,
    exit_code: Option<i32>,
    signal: Option<i32>,
    last_sequence: u64,
}

#[derive(Clone, Debug)]
struct OutputChunk {
    sequence: u64,
    data: Vec<u8>,
}

#[derive(Clone, Debug)]
enum SessionEvent {
    Output(OutputChunk),
    Status(SessionInfo),
}

#[derive(Default)]
struct History {
    chunks: VecDeque<OutputChunk>,
    bytes: usize,
}

impl History {
    fn push(&mut self, chunk: OutputChunk) {
        self.bytes = self.bytes.saturating_add(chunk.data.len());
        self.chunks.push_back(chunk);
        while self.bytes > HISTORY_LIMIT && self.chunks.len() > 1 {
            if let Some(removed) = self.chunks.pop_front() {
                self.bytes = self.bytes.saturating_sub(removed.data.len());
            }
        }
    }

    fn after(&self, sequence: u64) -> Vec<OutputChunk> {
        self.chunks
            .iter()
            .filter(|chunk| chunk.sequence > sequence)
            .cloned()
            .collect()
    }
}

#[derive(Debug)]
enum PtyControl {
    Input(Vec<u8>),
    Resize { columns: u16, rows: u16 },
    Signal(Signal),
    Terminate,
}

struct PtyExit {
    code: Option<i32>,
    signal: Option<i32>,
    terminated: bool,
}

#[derive(Debug, Deserialize)]
struct CreateSession {
    target: Option<String>,
    cwd: Option<String>,
    title: Option<String>,
    columns: Option<u16>,
    rows: Option<u16>,
}

#[derive(Debug, Serialize)]
struct CreateResponse {
    session: SessionInfo,
}

#[derive(Debug, Deserialize)]
struct AttachQuery {
    after: Option<u64>,
    token: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    Resize { columns: u16, rows: u16 },
    Signal { signal: String },
    Terminate,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("termm=info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    if !cli.bind.ip().is_loopback() {
        bail!(
            "termm UI must bind to a loopback address, not {}",
            cli.bind.ip()
        );
    }
    let cwd = cli
        .cwd
        .unwrap_or(std::env::current_dir().context("cannot determine current directory")?)
        .canonicalize()
        .context("cannot open the termm local working directory")?;
    let context = TermmContext {
        default_target: cli.target,
        local_cwd: cwd.to_string_lossy().into_owned(),
        sshai_path: cli.sshai.to_string_lossy().into_owned(),
    };
    let state = AppState {
        context,
        token: random_token()?,
        sessions: Arc::new(RwLock::new(HashMap::new())),
        next_id: Arc::new(AtomicU64::new(1)),
    };
    let app = Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/app.css", get(app_css))
        .route("/api/context", get(get_context))
        .route("/api/sessions", get(list_sessions).post(create_session))
        .route("/api/sessions/{id}", delete(terminate_session))
        .route("/api/sessions/{id}/ws", get(attach_session))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind(cli.bind).await?;
    let address = listener.local_addr()?;
    let url = format!("http://{address}/?token={}", state.token);
    eprintln!("termm: {url}");
    if !cli.no_open {
        open_browser(&url);
    }
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn app_js() -> Response {
    static_response(APP_JS, "text/javascript; charset=utf-8")
}

async fn app_css() -> Response {
    static_response(APP_CSS, "text/css; charset=utf-8")
}

fn static_response(bytes: &'static [u8], content_type: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(bytes))
        .expect("static response is valid")
}

async fn get_context(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TermmContext>, ApiError> {
    authorize(&state, &headers)?;
    Ok(Json(state.context))
}

async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionInfo>>, ApiError> {
    authorize(&state, &headers)?;
    let sessions = state
        .sessions
        .read()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut values = Vec::with_capacity(sessions.len());
    for session in sessions {
        values.push(session.info.read().await.clone());
    }
    values.sort_by_key(|session| session.created_unix_ms);
    Ok(Json(values))
}

async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateSession>,
) -> Result<Json<CreateResponse>, ApiError> {
    authorize(&state, &headers)?;
    let target = request
        .target
        .or_else(|| state.context.default_target.clone());
    let cwd = request
        .cwd
        .unwrap_or_else(|| state.context.local_cwd.clone());
    let cwd = PathBuf::from(&cwd)
        .canonicalize()
        .with_context(|| format!("cannot open local working directory {cwd}"))?;
    if !cwd.is_dir() {
        return Err(anyhow!(
            "local working directory is not a directory: {}",
            cwd.display()
        )
        .into());
    }
    let sequence = state.next_id.fetch_add(1, Ordering::Relaxed);
    let id = format!("{:x}-{sequence:x}", now_unix_ms());
    let title = request
        .title
        .unwrap_or_else(|| target.clone().unwrap_or_else(|| "local shell".to_owned()));
    let info = SessionInfo {
        id: id.clone(),
        title,
        target,
        local_cwd: cwd.to_string_lossy().into_owned(),
        phase: "starting",
        created_unix_ms: now_unix_ms(),
        exit_code: None,
        signal: None,
        last_sequence: 0,
    };
    let (control, control_rx) = mpsc::channel(128);
    let (events, _) = broadcast::channel(256);
    let session = Arc::new(TerminalSession {
        info: RwLock::new(info.clone()),
        control,
        events,
        history: Mutex::new(History::default()),
    });
    state
        .sessions
        .write()
        .await
        .insert(id, Arc::clone(&session));
    let context = state.context.clone();
    tokio::spawn(run_pty(
        session,
        context,
        cwd,
        request.columns.unwrap_or(100).max(2),
        request.rows.unwrap_or(30).max(2),
        control_rx,
    ));
    Ok(Json(CreateResponse { session: info }))
}

async fn terminate_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    authorize(&state, &headers)?;
    let session = state
        .sessions
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| ApiError::not_found(format!("unknown terminal session {id}")))?;
    session
        .control
        .send(PtyControl::Terminate)
        .await
        .map_err(|_| anyhow!("terminal session has already stopped"))?;
    Ok(StatusCode::ACCEPTED)
}

async fn attach_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<AttachQuery>,
    upgrade: WebSocketUpgrade,
) -> Result<impl IntoResponse, ApiError> {
    if query.token != state.token {
        return Err(ApiError::unauthorized());
    }
    let session = state
        .sessions
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| ApiError::not_found(format!("unknown terminal session {id}")))?;
    Ok(
        upgrade
            .on_upgrade(move |socket| terminal_socket(socket, session, query.after.unwrap_or(0))),
    )
}

async fn terminal_socket(mut socket: WebSocket, session: Arc<TerminalSession>, after: u64) {
    let mut events = session.events.subscribe();
    let info = session.info.read().await.clone();
    if send_status(&mut socket, &info).await.is_err() {
        return;
    }
    let history = session.history.lock().await.after(after);
    let mut delivered = after;
    for chunk in history {
        delivered = delivered.max(chunk.sequence);
        if send_output(&mut socket, &chunk).await.is_err() {
            return;
        }
    }
    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Binary(data))) => {
                        if session.control.send(PtyControl::Input(data.to_vec())).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        let Ok(message) = serde_json::from_str::<ClientMessage>(&text) else {
                            continue;
                        };
                        let control = match message {
                            ClientMessage::Resize { columns, rows } => PtyControl::Resize {
                                columns: columns.max(2),
                                rows: rows.max(2),
                            },
                            ClientMessage::Signal { signal } => match signal.as_str() {
                                "interrupt" => PtyControl::Signal(Signal::SIGINT),
                                "terminate" => PtyControl::Signal(Signal::SIGTERM),
                                "kill" => PtyControl::Signal(Signal::SIGKILL),
                                _ => continue,
                            },
                            ClientMessage::Terminate => PtyControl::Terminate,
                        };
                        if session.control.send(control).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(Message::Ping(data))) => {
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                }
            }
            event = events.recv() => {
                match event {
                    Ok(SessionEvent::Output(chunk)) if chunk.sequence > delivered => {
                        delivered = chunk.sequence;
                        if send_output(&mut socket, &chunk).await.is_err() {
                            break;
                        }
                    }
                    Ok(SessionEvent::Output(_)) => {}
                    Ok(SessionEvent::Status(info)) => {
                        if send_status(&mut socket, &info).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let info = session.info.read().await.clone();
                        if send_status(&mut socket, &info).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

async fn send_output(socket: &mut WebSocket, chunk: &OutputChunk) -> Result<()> {
    socket
        .send(Message::Text(
            json!({
                "type": "output",
                "sequence": chunk.sequence,
                "data_base64": BASE64.encode(&chunk.data),
            })
            .to_string()
            .into(),
        ))
        .await?;
    Ok(())
}

async fn send_status(socket: &mut WebSocket, info: &SessionInfo) -> Result<()> {
    socket
        .send(Message::Text(
            json!({"type": "status", "session": info})
                .to_string()
                .into(),
        ))
        .await?;
    Ok(())
}

async fn run_pty(
    session: Arc<TerminalSession>,
    context: TermmContext,
    cwd: PathBuf,
    columns: u16,
    rows: u16,
    mut controls: mpsc::Receiver<PtyControl>,
) {
    let remote = session.info.read().await.target.is_some();
    let mut attempt = 0_u32;
    loop {
        let result = run_pty_inner(
            Arc::clone(&session),
            context.clone(),
            cwd.clone(),
            columns,
            rows,
            &mut controls,
        )
        .await;
        match result {
            Ok(exit) if exit.terminated || !remote || exit.code == Some(0) => {
                update_phase(&session, "exited", exit.code, exit.signal).await;
                return;
            }
            Ok(exit) => {
                attempt = attempt.saturating_add(1);
                publish_output(
                    &session,
                    format!(
                        "\r\n\x1b[1;33mtermm: sshai transport exited ({:?}/{:?}); reconnecting…\x1b[0m\r\n",
                        exit.code, exit.signal
                    )
                    .into_bytes(),
                )
                .await;
            }
            Err(error) if remote => {
                attempt = attempt.saturating_add(1);
                publish_output(
                    &session,
                    format!("\r\n\x1b[1;33mtermm: {error:#}; reconnecting…\x1b[0m\r\n")
                        .into_bytes(),
                )
                .await;
            }
            Err(error) => {
                publish_output(&session, format!("\r\ntermm: {error:#}\r\n").into_bytes()).await;
                update_phase(&session, "failed", None, None).await;
                return;
            }
        }
        update_phase(&session, "reconnecting", None, None).await;
        let delay = Duration::from_millis(
            250_u64
                .saturating_mul(1_u64 << attempt.saturating_sub(1).min(5))
                .min(10_000),
        );
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            control = controls.recv() => {
                if matches!(control, Some(PtyControl::Terminate) | None) {
                    update_phase(&session, "exited", None, None).await;
                    return;
                }
            }
        }
    }
}

async fn run_pty_inner(
    session: Arc<TerminalSession>,
    context: TermmContext,
    cwd: PathBuf,
    columns: u16,
    rows: u16,
    controls: &mut mpsc::Receiver<PtyControl>,
) -> Result<PtyExit> {
    let pair = openpty(
        Some(&Winsize {
            ws_row: rows,
            ws_col: columns,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }),
        None,
    )?;
    set_nonblocking(&pair.master)?;
    let master = Arc::new(AsyncFd::new(pair.master)?);
    let slave = File::from(pair.slave);
    let stdin = slave.try_clone()?;
    let stdout = slave.try_clone()?;
    let stderr = slave;
    let info = session.info.read().await.clone();
    let (program, arguments) = match info.target {
        Some(target) if !target.trim().is_empty() => (context.sshai_path, vec![target]),
        _ => (
            std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned()),
            vec!["-l".to_owned()],
        ),
    };
    let mut command = Command::new(program);
    command
        .args(arguments)
        .current_dir(cwd)
        .env("TERM", "xterm-256color")
        .env("COLORTERM", "truecolor")
        .env("COLUMNS", columns.to_string())
        .env("LINES", rows.to_string())
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true);
    // SAFETY: only async-signal-safe libc calls are made between fork and exec.
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
    let mut child = command.spawn().context("cannot launch terminal command")?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow!("terminal child has no PID"))? as i32;
    update_phase(&session, "running", None, None).await;
    let mut buffer = [0_u8; 16 * 1024];
    let mut terminated = false;
    let status = loop {
        tokio::select! {
            status = child.wait() => break status?,
            control = controls.recv() => match control {
                Some(PtyControl::Input(data)) => write_pty(&master, &data).await?,
                Some(PtyControl::Resize { columns, rows }) => resize_pty(&master, columns, rows)?,
                Some(PtyControl::Signal(signal)) => signal_group(pid, signal)?,
                Some(PtyControl::Terminate) => {
                    terminated = true;
                    signal_group(pid, Signal::SIGTERM)?;
                }
                None => {}
            },
            read = read_pty(&master, &mut buffer) => {
                match read? {
                    0 => continue,
                    count => publish_output(&session, buffer[..count].to_vec()).await,
                }
            }
        }
    };
    Ok(PtyExit {
        code: status.code(),
        signal: status.signal(),
        terminated,
    })
}

async fn publish_output(session: &TerminalSession, data: Vec<u8>) {
    if data.is_empty() {
        return;
    }
    let sequence = {
        let mut info = session.info.write().await;
        info.last_sequence = info.last_sequence.saturating_add(1);
        info.last_sequence
    };
    let chunk = OutputChunk { sequence, data };
    session.history.lock().await.push(chunk.clone());
    let _ = session.events.send(SessionEvent::Output(chunk));
}

async fn update_phase(
    session: &TerminalSession,
    phase: &'static str,
    exit_code: Option<i32>,
    signal: Option<i32>,
) {
    let info = {
        let mut info = session.info.write().await;
        info.phase = phase;
        info.exit_code = exit_code;
        info.signal = signal;
        info.clone()
    };
    let _ = session.events.send(SessionEvent::Status(info));
}

async fn read_pty(master: &AsyncFd<OwnedFd>, buffer: &mut [u8]) -> Result<usize> {
    loop {
        let mut readiness = master.readable().await?;
        let result = readiness
            .try_io(|inner| nix::unistd::read(inner.get_ref(), buffer).map_err(errno_to_io));
        match result {
            Ok(Ok(read)) => return Ok(read),
            Ok(Err(error)) if error.raw_os_error() == Some(nix::libc::EIO) => return Ok(0),
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => continue,
        }
    }
}

async fn write_pty(master: &AsyncFd<OwnedFd>, data: &[u8]) -> Result<()> {
    let mut written = 0;
    while written < data.len() {
        let mut readiness = master.writable().await?;
        let result = readiness.try_io(|inner| {
            nix::unistd::write(inner.get_ref(), &data[written..]).map_err(errno_to_io)
        });
        match result {
            Ok(Ok(0)) => bail!("terminal PTY closed while writing input"),
            Ok(Ok(count)) => written += count,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => continue,
        }
    }
    Ok(())
}

fn resize_pty(master: &AsyncFd<OwnedFd>, columns: u16, rows: u16) -> Result<()> {
    let size = Winsize {
        ws_row: rows,
        ws_col: columns,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ reads the provided winsize and retains no pointer.
    if unsafe { nix::libc::ioctl(master.get_ref().as_raw_fd(), nix::libc::TIOCSWINSZ, &size) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn signal_group(pid: i32, signal: Signal) -> Result<()> {
    match killpg(Pid::from_raw(pid), signal) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
    // SAFETY: fcntl operates on the owned descriptor and retains no pointer.
    let flags = unsafe { nix::libc::fcntl(fd.as_raw_fd(), nix::libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: this updates only descriptor flags on the same live descriptor.
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

fn errno_to_io(error: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error as i32)
}

fn now_unix_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

fn random_token() -> Result<String> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let authorized = headers
        .get("x-termm-token")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == state.token);
    if authorized {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

fn open_browser(url: &str) {
    let command = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    if let Err(error) = std::process::Command::new(command).arg(url).spawn() {
        tracing::warn!(%error, "could not open the termm UI automatically");
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

struct ApiError {
    status: StatusCode,
    error: anyhow::Error,
}

impl ApiError {
    fn not_found(message: String) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error: anyhow!(message),
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: anyhow!("missing or invalid termm access token"),
        }
    }
}

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(error: E) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: error.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({"error": format!("{:#}", self.error)})),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_is_bounded_and_replays_after_sequence() {
        let mut history = History::default();
        history.push(OutputChunk {
            sequence: 1,
            data: vec![b'a'; HISTORY_LIMIT],
        });
        history.push(OutputChunk {
            sequence: 2,
            data: b"tail".to_vec(),
        });
        let replay = history.after(1);
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].data, b"tail");
        assert!(history.bytes <= HISTORY_LIMIT);
    }

    #[test]
    fn context_and_session_json_are_stable() {
        let context = TermmContext {
            default_target: Some("host1,host2".to_owned()),
            local_cwd: "/local".to_owned(),
            sshai_path: "sshai".to_owned(),
        };
        let value = serde_json::to_value(context).unwrap();
        assert_eq!(value["default_target"], "host1,host2");
    }
}
