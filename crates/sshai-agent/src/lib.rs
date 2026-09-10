use std::path::PathBuf;

use anyhow::Result;

#[cfg(not(unix))]
use anyhow::bail;

#[derive(Clone, Debug)]
pub struct ServeOptions {
    pub session_id: String,
    pub session_dir: PathBuf,
    pub workspace_root: PathBuf,
}

#[cfg(unix)]
mod exec;
#[cfg(unix)]
mod workspace;

#[derive(Clone, Debug)]
pub struct InvokeOptions {
    pub session_id: String,
    pub socket: PathBuf,
    pub argv: Vec<String>,
}

#[cfg(unix)]
mod unix {
    use std::{
        collections::HashMap,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };

    use anyhow::{Context, Result, anyhow, bail};
    use sshai_protocol::{
        AgentToClient, ClientToAgent, ControlRequest, ControlResponse, PROTOCOL_VERSION,
        ShimRequest, ShimResponse, read_frame, write_frame,
    };
    use tokio::{
        io::{AsyncWriteExt, Stdout},
        net::{UnixListener, UnixStream},
        sync::{Mutex, oneshot, watch},
        task::JoinSet,
    };

    use super::exec::ExecManager;
    use super::workspace::WorkspaceRoot;
    use super::{InvokeOptions, ServeOptions};

    type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<ControlResponse>>>>;
    type SharedWriter = Arc<Mutex<Stdout>>;

    pub async fn serve(options: ServeOptions) -> Result<()> {
        validate_session_id(&options.session_id)?;
        prepare_session_directory(&options.session_dir).await?;
        let mut cleanup_guard = SessionDirectoryGuard(Some(options.session_dir.clone()));
        let workspace = WorkspaceRoot::open(&options.workspace_root).await?;
        let socket_path = options.session_dir.join("agent.sock");
        let bin_dir = options.session_dir.join("bin");
        tokio::fs::create_dir(&bin_dir).await?;
        set_mode(&bin_dir, 0o700).await?;

        let executable = std::env::current_exe().context("cannot locate remote sshai binary")?;
        write_shim(
            &bin_dir.join("sshai"),
            &executable,
            &socket_path,
            &options.session_id,
        )
        .await?;
        let shell_launcher = write_shell_support(&options.session_dir, &bin_dir).await?;

        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("cannot bind {}", socket_path.display()))?;
        set_mode(&socket_path, 0o600).await?;

        let writer = Arc::new(Mutex::new(tokio::io::stdout()));
        write_agent_message(
            &writer,
            &AgentToClient::Ready {
                protocol: PROTOCOL_VERSION,
                session_id: options.session_id.clone(),
                bin_dir: bin_dir.to_string_lossy().into_owned(),
                shell_launcher: shell_launcher.to_string_lossy().into_owned(),
                workspace_root: workspace.display(),
                capabilities: WorkspaceRoot::capabilities(),
            },
        )
        .await?;

        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let (exec_manager, mut exec_events) = ExecManager::new();
        let event_writer = writer.clone();
        let event_dispatcher = tokio::spawn(async move {
            while let Some(event) = exec_events.recv().await {
                if let Err(error) =
                    write_agent_message(&event_writer, &AgentToClient::ExecEvent(event)).await
                {
                    tracing::debug!(%error, "cannot send exec event");
                    break;
                }
            }
        });
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let reader_pending = pending.clone();
        let reader_writer = writer.clone();
        let reader_workspace = workspace.clone();
        let reader_exec_manager = exec_manager.clone();
        let reader = tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            loop {
                match read_frame::<_, ClientToAgent>(&mut stdin).await {
                    Ok(ClientToAgent::Response(response)) => {
                        if let Some(sender) = reader_pending.lock().await.remove(&response.id) {
                            let _ = sender.send(response);
                        }
                    }
                    Ok(ClientToAgent::WorkspaceRequest(request)) => {
                        let writer = reader_writer.clone();
                        let workspace = reader_workspace.clone();
                        tokio::spawn(async move {
                            let response = workspace.handle(request).await;
                            if let Err(error) = write_agent_message(
                                &writer,
                                &AgentToClient::WorkspaceResponse(response),
                            )
                            .await
                            {
                                tracing::debug!(%error, "cannot send workspace response");
                            }
                        });
                    }
                    Ok(ClientToAgent::ExecStart(request)) => {
                        let manager = reader_exec_manager.clone();
                        let workspace = reader_workspace.clone();
                        tokio::spawn(async move { manager.start(workspace, request).await });
                    }
                    Ok(ClientToAgent::ExecControl(control)) => {
                        if let Err(error) = reader_exec_manager.control(control).await {
                            tracing::debug!(%error, "cannot deliver exec control message");
                        }
                    }
                    Ok(ClientToAgent::Shutdown) => break,
                    Err(error) => {
                        tracing::debug!(%error, "agent control input closed");
                        break;
                    }
                }
            }
            let _ = shutdown_tx.send(true);
        });

        let request_ids = Arc::new(AtomicU64::new(1));
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let session_id = options.session_id.clone();
                    let pending = pending.clone();
                    let writer = writer.clone();
                    let request_ids = request_ids.clone();
                    connections.spawn(async move {
                        if let Err(error) = handle_shim(
                            stream,
                            &session_id,
                            request_ids,
                            pending,
                            writer,
                        ).await {
                            tracing::warn!(%error, "remote shim request failed");
                        }
                    });
                }
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "remote shim task failed");
                    }
                }
            }
        }

        connections.abort_all();
        exec_manager.shutdown_all().await;
        pending.lock().await.clear();
        reader.abort();
        event_dispatcher.abort();
        drop(listener);
        if let Err(error) = tokio::fs::remove_dir_all(&options.session_dir).await {
            tracing::debug!(%error, path = %options.session_dir.display(), "could not clean agent session directory");
        } else {
            cleanup_guard.0 = None;
        }
        write_agent_message(&writer, &AgentToClient::Stopped).await?;
        Ok(())
    }

    pub async fn invoke(options: InvokeOptions) -> Result<u8> {
        validate_session_id(&options.session_id)?;
        if options.argv.is_empty() {
            bail!("missing sshai command; try `sshai help`");
        }
        let mut stream = UnixStream::connect(&options.socket)
            .await
            .with_context(|| format!("cannot connect to {}", options.socket.display()))?;
        write_frame(
            &mut stream,
            &ShimRequest {
                protocol: PROTOCOL_VERSION,
                session_id: options.session_id,
                argv: options.argv,
            },
        )
        .await?;
        let response = tokio::time::timeout(
            Duration::from_secs(300),
            read_frame::<_, ShimResponse>(&mut stream),
        )
        .await
        .map_err(|_| anyhow!("local sshai command timed out"))??;
        if !response.stdout.is_empty() {
            let mut stdout = tokio::io::stdout();
            stdout.write_all(response.stdout.as_bytes()).await?;
            stdout.flush().await?;
        }
        if !response.stderr.is_empty() {
            let mut stderr = tokio::io::stderr();
            stderr.write_all(response.stderr.as_bytes()).await?;
            stderr.flush().await?;
        }
        Ok(response.exit_code)
    }

    async fn handle_shim(
        mut stream: UnixStream,
        session_id: &str,
        request_ids: Arc<AtomicU64>,
        pending: Pending,
        writer: SharedWriter,
    ) -> Result<()> {
        let request = tokio::time::timeout(
            Duration::from_secs(10),
            read_frame::<_, ShimRequest>(&mut stream),
        )
        .await
        .map_err(|_| anyhow!("shim request timed out"))??;
        if request.protocol != PROTOCOL_VERSION {
            return write_shim_error(
                &mut stream,
                format!(
                    "protocol mismatch: shim={}, agent={PROTOCOL_VERSION}",
                    request.protocol
                ),
            )
            .await;
        }
        if request.session_id != session_id {
            return write_shim_error(&mut stream, "session token mismatch".to_owned()).await;
        }
        if request.argv.is_empty() {
            return write_shim_error(&mut stream, "missing sshai command".to_owned()).await;
        }

        let id = request_ids.fetch_add(1, Ordering::Relaxed);
        let (response_tx, response_rx) = oneshot::channel();
        pending.lock().await.insert(id, response_tx);
        if let Err(error) = write_agent_message(
            &writer,
            &AgentToClient::Request(ControlRequest {
                id,
                argv: request.argv,
            }),
        )
        .await
        {
            pending.lock().await.remove(&id);
            return Err(error);
        }

        let response = tokio::time::timeout(Duration::from_secs(300), response_rx)
            .await
            .map_err(|_| anyhow!("local sshai command timed out"))?
            .map_err(|_| anyhow!("local sshai control channel closed"))?;
        write_frame(
            &mut stream,
            &ShimResponse {
                protocol: PROTOCOL_VERSION,
                exit_code: response.exit_code,
                stdout: response.stdout,
                stderr: response.stderr,
            },
        )
        .await?;
        Ok(())
    }

    async fn write_agent_message(writer: &SharedWriter, message: &AgentToClient) -> Result<()> {
        let mut writer = writer.lock().await;
        write_frame(&mut *writer, message).await?;
        Ok(())
    }

    async fn write_shim_error(stream: &mut UnixStream, message: String) -> Result<()> {
        write_frame(
            stream,
            &ShimResponse {
                protocol: PROTOCOL_VERSION,
                exit_code: 255,
                stdout: String::new(),
                stderr: format!("sshai: {message}\n"),
            },
        )
        .await?;
        Ok(())
    }

    async fn prepare_session_directory(path: &Path) -> Result<()> {
        if path.exists() {
            bail!("agent session directory already exists: {}", path.display());
        }
        tokio::fs::create_dir_all(path).await?;
        set_mode(path, 0o700).await
    }

    async fn write_shim(
        path: &Path,
        executable: &Path,
        socket: &Path,
        session_id: &str,
    ) -> Result<()> {
        let script = format!(
            "#!/bin/sh\nexec {} worker invoke --session-id {} --socket {} -- \"$@\"\n",
            shell_quote(&executable.to_string_lossy()),
            shell_quote(session_id),
            shell_quote(&socket.to_string_lossy()),
        );
        tokio::fs::write(path, script).await?;
        set_mode(path, 0o700).await
    }

    async fn write_shell_support(session_dir: &Path, bin_dir: &Path) -> Result<std::path::PathBuf> {
        let launcher = session_dir.join("launch-shell");
        let bashrc = session_dir.join("bashrc");
        let shrc = session_dir.join("shrc");
        let zsh_dir = session_dir.join("zsh");
        tokio::fs::create_dir(&zsh_dir).await?;
        set_mode(&zsh_dir, 0o700).await?;

        let quoted_bin = shell_quote(&bin_dir.to_string_lossy());
        let quoted_bashrc = shell_quote(&bashrc.to_string_lossy());
        let quoted_shrc = shell_quote(&shrc.to_string_lossy());
        let quoted_zsh_dir = shell_quote(&zsh_dir.to_string_lossy());
        let fish_init = shell_quote(&format!(
            "set -gx PATH {} $PATH",
            fish_quote(&bin_dir.to_string_lossy())
        ));
        let launcher_body = format!(
            "#!/bin/sh\n\
shell=${{SHELL:-/bin/sh}}\n\
case ${{shell##*/}} in\n\
  bash) exec \"$shell\" --noprofile --rcfile {quoted_bashrc} -i ;;\n\
  zsh) export ZDOTDIR={quoted_zsh_dir}; exec \"$shell\" -l ;;\n\
  fish) exec \"$shell\" --login --init-command {fish_init} ;;\n\
  *) export ENV={quoted_shrc}; exec \"$shell\" -i ;;\n\
esac\n"
        );
        write_mode(&launcher, launcher_body, 0o700).await?;

        let bashrc_body = format!(
            "# sshai: emulate bash login startup, then install the session shim last.\n\
if [ -r /etc/profile ]; then . /etc/profile; fi\n\
if [ -r \"$HOME/.bash_profile\" ]; then . \"$HOME/.bash_profile\"\n\
elif [ -r \"$HOME/.bash_login\" ]; then . \"$HOME/.bash_login\"\n\
elif [ -r \"$HOME/.profile\" ]; then . \"$HOME/.profile\"\n\
fi\n\
export PATH={quoted_bin}:\"$PATH\"\n"
        );
        write_mode(&bashrc, bashrc_body, 0o600).await?;

        let shrc_body = format!(
            "if [ -r /etc/profile ]; then . /etc/profile; fi\n\
if [ -r \"$HOME/.profile\" ]; then . \"$HOME/.profile\"; fi\n\
export PATH={quoted_bin}:\"$PATH\"\n"
        );
        write_mode(&shrc, shrc_body, 0o600).await?;

        let original_zdotdir = std::env::var("ZDOTDIR")
            .or_else(|_| std::env::var("HOME"))
            .context("remote environment has neither ZDOTDIR nor HOME")?;
        for name in [".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout"] {
            let original = Path::new(&original_zdotdir).join(name);
            let source = shell_quote(&original.to_string_lossy());
            let body = format!(
                "if [[ -r {source} ]]; then source {source}; fi\n\
export ZDOTDIR={quoted_zsh_dir}\n\
export PATH={quoted_bin}:$PATH\n"
            );
            write_mode(&zsh_dir.join(name), body, 0o600).await?;
        }

        Ok(launcher)
    }

    async fn write_mode(path: &Path, contents: String, mode: u32) -> Result<()> {
        tokio::fs::write(path, contents).await?;
        set_mode(path, mode).await
    }

    async fn set_mode(path: &Path, mode: u32) -> Result<()> {
        let permissions = std::fs::Permissions::from_mode(mode);
        tokio::fs::set_permissions(path, permissions).await?;
        Ok(())
    }

    fn validate_session_id(value: &str) -> Result<()> {
        if value.len() < 32
            || value.len() > 128
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("invalid agent session ID");
        }
        Ok(())
    }

    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    fn fish_quote(value: &str) -> String {
        format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
    }

    struct SessionDirectoryGuard(Option<PathBuf>);

    impl Drop for SessionDirectoryGuard {
        fn drop(&mut self) {
            if let Some(path) = self.0.take() {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn validates_unpredictable_hex_session_ids() {
            assert!(validate_session_id("0123456789abcdef0123456789abcdef").is_ok());
            assert!(validate_session_id("short").is_err());
            assert!(validate_session_id("0123456789abcdef0123456789abcde/").is_err());
        }

        #[test]
        fn quotes_remote_paths() {
            assert_eq!(shell_quote("/tmp/a'b"), "'/tmp/a'\\''b'");
        }
    }
}

pub async fn serve(options: ServeOptions) -> Result<()> {
    #[cfg(unix)]
    {
        unix::serve(options).await
    }
    #[cfg(not(unix))]
    {
        let _ = options;
        bail!("sshai agent currently requires a Unix remote host")
    }
}

pub async fn invoke(options: InvokeOptions) -> Result<u8> {
    #[cfg(unix)]
    {
        unix::invoke(options).await
    }
    #[cfg(not(unix))]
    {
        let _ = options;
        bail!("sshai agent shim currently requires a Unix remote host")
    }
}
