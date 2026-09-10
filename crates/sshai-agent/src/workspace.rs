use std::{
    io::SeekFrom,
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use sshai_protocol::{
    MAX_WORKSPACE_READ, WorkspaceEntry, WorkspaceFileKind, WorkspaceMetadata, WorkspaceOperation,
    WorkspaceOutcome, WorkspaceRequest, WorkspaceResponse, WorkspaceValue,
};
use tokio::{
    fs,
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt},
    process::Command,
};

const MAX_LIST_ENTRIES: u32 = 1_000;
const MAX_EXEC_OUTPUT_PER_STREAM: usize = 192 * 1024;
const EXEC_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub(crate) struct WorkspaceRoot {
    canonical: Arc<PathBuf>,
}

impl WorkspaceRoot {
    pub(crate) async fn open(path: &Path) -> Result<Self> {
        let canonical = fs::canonicalize(path)
            .await
            .with_context(|| format!("cannot open workspace root {}", path.display()))?;
        let metadata = fs::metadata(&canonical).await?;
        if !metadata.is_dir() {
            bail!("workspace root is not a directory: {}", canonical.display());
        }
        Ok(Self {
            canonical: Arc::new(canonical),
        })
    }

    pub(crate) fn display(&self) -> String {
        self.canonical.to_string_lossy().into_owned()
    }

    pub(crate) fn capabilities() -> Vec<String> {
        [
            "open",
            "list",
            "stat",
            "read",
            "blake3",
            "exec",
            "exec_stream",
            "pty",
            "signals",
            "resize",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    pub(crate) async fn handle(&self, request: WorkspaceRequest) -> WorkspaceResponse {
        let id = request.id;
        let outcome = match self.perform(request.operation).await {
            Ok(value) => WorkspaceOutcome::Ok { value },
            Err(error) => WorkspaceOutcome::Error {
                code: classify_error(&error).to_owned(),
                message: format!("{error:#}"),
            },
        };
        WorkspaceResponse { id, outcome }
    }

    async fn perform(&self, operation: WorkspaceOperation) -> Result<WorkspaceValue> {
        match operation {
            WorkspaceOperation::Open => Ok(WorkspaceValue::Open {
                root: self.display(),
                capabilities: Self::capabilities(),
            }),
            WorkspaceOperation::List {
                path,
                cursor,
                limit,
            } => self.list(&path, cursor.as_deref(), limit).await,
            WorkspaceOperation::Stat { path } => self.stat(&path).await,
            WorkspaceOperation::Read {
                path,
                offset,
                length,
            } => self.read(&path, offset, length).await,
            WorkspaceOperation::Hash { path } => self.hash(&path).await,
            WorkspaceOperation::Exec { argv, cwd, env } => self.exec(argv, &cwd, env).await,
        }
    }

    async fn list(&self, path: &str, cursor: Option<&str>, limit: u32) -> Result<WorkspaceValue> {
        let directory = self.resolve_existing(path).await?;
        if !fs::metadata(&directory).await?.is_dir() {
            bail!("not a directory: {path}");
        }
        let limit = limit.clamp(1, MAX_LIST_ENTRIES) as usize;
        let mut reader = fs::read_dir(&directory).await?;
        let mut names = Vec::new();
        while let Some(entry) = reader.next_entry().await? {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("workspace contains a file name that is not valid UTF-8"))?;
            if cursor.is_none_or(|cursor| name.as_str() > cursor) {
                names.push(name);
            }
        }
        names.sort_unstable();
        let has_more = names.len() > limit;
        names.truncate(limit);

        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            let metadata = fs::symlink_metadata(directory.join(&name)).await?;
            entries.push(WorkspaceEntry {
                name,
                metadata: workspace_metadata(&metadata),
            });
        }
        let next_cursor = has_more
            .then(|| entries.last().map(|entry| entry.name.clone()))
            .flatten();
        Ok(WorkspaceValue::List {
            entries,
            next_cursor,
        })
    }

    async fn stat(&self, path: &str) -> Result<WorkspaceValue> {
        let candidate = self.resolve_leaf(path).await?;
        let metadata = fs::symlink_metadata(candidate).await?;
        Ok(WorkspaceValue::Stat {
            metadata: workspace_metadata(&metadata),
        })
    }

    async fn read(&self, path: &str, offset: u64, length: u32) -> Result<WorkspaceValue> {
        if length == 0 || length > MAX_WORKSPACE_READ {
            bail!("read length must be between 1 and {MAX_WORKSPACE_READ} bytes");
        }
        let candidate = self.resolve_existing(path).await?;
        let metadata = fs::metadata(&candidate).await?;
        if !metadata.is_file() {
            bail!("not a regular file: {path}");
        }
        let mut file = fs::File::open(candidate).await?;
        file.seek(SeekFrom::Start(offset)).await?;
        let mut data = vec![0_u8; length as usize];
        let mut read = 0;
        while read < data.len() {
            let count = file.read(&mut data[read..]).await?;
            if count == 0 {
                break;
            }
            read += count;
        }
        data.truncate(read);
        Ok(WorkspaceValue::Read {
            data_base64: BASE64.encode(&data),
            eof: offset.saturating_add(read as u64) >= metadata.len(),
        })
    }

    async fn hash(&self, path: &str) -> Result<WorkspaceValue> {
        let candidate = self.resolve_existing(path).await?;
        if !fs::metadata(&candidate).await?.is_file() {
            bail!("not a regular file: {path}");
        }
        let mut file = fs::File::open(candidate).await?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(WorkspaceValue::Hash {
            algorithm: "blake3".to_owned(),
            digest: hasher.finalize().to_hex().to_string(),
        })
    }

    async fn exec(
        &self,
        argv: Vec<String>,
        cwd: &str,
        env: Vec<(String, String)>,
    ) -> Result<WorkspaceValue> {
        let executable = argv
            .first()
            .ok_or_else(|| anyhow!("exec argv cannot be empty"))?;
        if env
            .iter()
            .any(|(key, _)| key.is_empty() || key.contains('='))
        {
            bail!("environment variable names must be non-empty and cannot contain '='");
        }
        let cwd = self.resolve_existing(cwd).await?;
        if !fs::metadata(&cwd).await?.is_dir() {
            bail!("exec cwd is not a directory");
        }

        let mut command = Command::new(executable);
        command
            .args(&argv[1..])
            .current_dir(cwd)
            .envs(env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().context("cannot spawn workspace command")?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("missing stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("missing stderr"))?;
        let stdout_task = tokio::spawn(read_bounded(stdout));
        let stderr_task = tokio::spawn(read_bounded(stderr));
        let status = match tokio::time::timeout(EXEC_TIMEOUT, child.wait()).await {
            Ok(status) => status?,
            Err(_) => {
                let _ = child.kill().await;
                bail!(
                    "workspace command timed out after {} seconds",
                    EXEC_TIMEOUT.as_secs()
                );
            }
        };
        let (stdout, stdout_truncated) = stdout_task.await??;
        let (stderr, stderr_truncated) = stderr_task.await??;
        Ok(WorkspaceValue::Exec {
            exit_code: status.code(),
            stdout_base64: BASE64.encode(stdout),
            stderr_base64: BASE64.encode(stderr),
            truncated: stdout_truncated || stderr_truncated,
        })
    }

    async fn resolve_existing(&self, path: &str) -> Result<PathBuf> {
        let relative = validate_relative(path)?;
        let canonical = fs::canonicalize(self.canonical.join(relative)).await?;
        if !canonical.starts_with(self.canonical.as_ref()) {
            bail!("path escapes the workspace root: {path}");
        }
        Ok(canonical)
    }

    pub(crate) async fn resolve_exec_cwd(&self, path: &str) -> Result<PathBuf> {
        let cwd = self.resolve_existing(path).await?;
        if !fs::metadata(&cwd).await?.is_dir() {
            bail!("exec cwd is not a directory");
        }
        Ok(cwd)
    }

    async fn resolve_leaf(&self, path: &str) -> Result<PathBuf> {
        let relative = validate_relative(path)?;
        if relative.as_os_str().is_empty() {
            return Ok(self.canonical.as_ref().clone());
        }
        let parent = relative.parent().unwrap_or_else(|| Path::new(""));
        let name = relative
            .file_name()
            .ok_or_else(|| anyhow!("invalid workspace path"))?;
        let canonical_parent = fs::canonicalize(self.canonical.join(parent)).await?;
        if !canonical_parent.starts_with(self.canonical.as_ref()) {
            bail!("path escapes the workspace root: {path}");
        }
        Ok(canonical_parent.join(name))
    }
}

fn validate_relative(path: &str) -> Result<PathBuf> {
    let path = if path.is_empty() { "." } else { path };
    let mut result = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(value) => result.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("workspace paths must be relative and cannot contain '..': {path}")
            }
        }
    }
    Ok(result)
}

async fn read_bounded<R>(mut reader: R) -> Result<(Vec<u8>, bool)>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = MAX_EXEC_OUTPUT_PER_STREAM.saturating_sub(output.len());
        let keep = remaining.min(read);
        output.extend_from_slice(&buffer[..keep]);
        truncated |= keep < read;
    }
    Ok((output, truncated))
}

fn workspace_metadata(metadata: &std::fs::Metadata) -> WorkspaceMetadata {
    let file_type = metadata.file_type();
    let kind = if file_type.is_file() {
        WorkspaceFileKind::File
    } else if file_type.is_dir() {
        WorkspaceFileKind::Directory
    } else if file_type.is_symlink() {
        WorkspaceFileKind::Symlink
    } else {
        WorkspaceFileKind::Other
    };
    let modified_unix_ms = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .and_then(|value| u64::try_from(value.as_millis()).ok());
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::MetadataExt;
        Some(metadata.mode())
    };
    #[cfg(not(unix))]
    let mode = None;
    WorkspaceMetadata {
        kind,
        size: metadata.len(),
        modified_unix_ms,
        mode,
    }
}

fn classify_error(error: &anyhow::Error) -> &'static str {
    if let Some(io) = error.downcast_ref::<std::io::Error>() {
        return match io.kind() {
            std::io::ErrorKind::NotFound => "not_found",
            std::io::ErrorKind::PermissionDenied => "permission_denied",
            _ => "io_error",
        };
    }
    let message = error.to_string();
    if message.contains("path") || message.contains("relative") || message.contains("directory") {
        "invalid_path"
    } else if message.contains("timed out") {
        "timeout"
    } else {
        "invalid_request"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_absolute_and_parent_paths() {
        assert!(validate_relative("../secret").is_err());
        assert!(validate_relative("/etc/passwd").is_err());
        assert_eq!(
            validate_relative("src/./main.rs").unwrap(),
            Path::new("src/main.rs")
        );
    }

    #[tokio::test]
    async fn reads_hashes_lists_and_executes_inside_workspace() {
        let temporary = tempfile::tempdir().unwrap();
        tokio::fs::write(temporary.path().join("alpha.txt"), b"abcdef")
            .await
            .unwrap();
        tokio::fs::write(temporary.path().join("beta.txt"), b"second")
            .await
            .unwrap();
        let workspace = WorkspaceRoot::open(temporary.path()).await.unwrap();

        let listed = workspace
            .perform(WorkspaceOperation::List {
                path: ".".to_owned(),
                cursor: None,
                limit: 1,
            })
            .await
            .unwrap();
        match listed {
            WorkspaceValue::List {
                entries,
                next_cursor,
            } => {
                assert_eq!(entries[0].name, "alpha.txt");
                assert_eq!(next_cursor.as_deref(), Some("alpha.txt"));
            }
            _ => panic!("unexpected list response"),
        }

        let read = workspace
            .perform(WorkspaceOperation::Read {
                path: "alpha.txt".to_owned(),
                offset: 2,
                length: 3,
            })
            .await
            .unwrap();
        match read {
            WorkspaceValue::Read { data_base64, eof } => {
                assert_eq!(BASE64.decode(data_base64).unwrap(), b"cde");
                assert!(!eof);
            }
            _ => panic!("unexpected read response"),
        }

        let hash = workspace
            .perform(WorkspaceOperation::Hash {
                path: "alpha.txt".to_owned(),
            })
            .await
            .unwrap();
        match hash {
            WorkspaceValue::Hash { algorithm, digest } => {
                assert_eq!(algorithm, "blake3");
                assert_eq!(digest, blake3::hash(b"abcdef").to_hex().as_str());
            }
            _ => panic!("unexpected hash response"),
        }

        let exec = workspace
            .perform(WorkspaceOperation::Exec {
                argv: vec![
                    "sh".to_owned(),
                    "-c".to_owned(),
                    "printf %s \"$PWD\"".to_owned(),
                ],
                cwd: ".".to_owned(),
                env: Vec::new(),
            })
            .await
            .unwrap();
        match exec {
            WorkspaceValue::Exec {
                exit_code,
                stdout_base64,
                ..
            } => {
                assert_eq!(exit_code, Some(0));
                assert_eq!(
                    BASE64.decode(stdout_base64).unwrap(),
                    temporary.path().as_os_str().as_encoded_bytes()
                );
            }
            _ => panic!("unexpected exec response"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlinks_that_escape_workspace() {
        use std::os::unix::fs::symlink;

        let workspace_dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        symlink(outside.path(), workspace_dir.path().join("escape")).unwrap();
        let workspace = WorkspaceRoot::open(workspace_dir.path()).await.unwrap();
        let error = workspace.resolve_existing("escape").await.unwrap_err();
        assert!(error.to_string().contains("escapes the workspace root"));

        let stat = workspace
            .perform(WorkspaceOperation::Stat {
                path: "escape".to_owned(),
            })
            .await
            .unwrap();
        match stat {
            WorkspaceValue::Stat { metadata } => {
                assert_eq!(metadata.kind, WorkspaceFileKind::Symlink)
            }
            _ => panic!("unexpected stat response"),
        }
    }
}
