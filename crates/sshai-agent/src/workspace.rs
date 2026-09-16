use std::{
    io::SeekFrom,
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::UNIX_EPOCH,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use sshai_protocol::{
    MAX_WORKSPACE_READ, WorkspaceEntry, WorkspaceFileKind, WorkspaceMetadata, WorkspaceOperation,
    WorkspaceOutcome, WorkspaceRequest, WorkspaceResponse, WorkspaceValue,
};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::Mutex,
};

const MAX_LIST_ENTRIES: u32 = 1_000;
const MAX_WORKSPACE_WRITE: usize = 512 * 1024;
const MAX_EDIT_FILE: u64 = 16 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub(crate) struct WorkspaceRoot {
    canonical: Arc<PathBuf>,
    mutations: Arc<Mutex<()>>,
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
            mutations: Arc::new(Mutex::new(())),
        })
    }

    pub(crate) fn display(&self) -> String {
        self.canonical.to_string_lossy().into_owned()
    }

    pub(crate) fn capabilities() -> Vec<String> {
        let mut capabilities = [
            "open",
            "list",
            "stat",
            "read",
            "blake3",
            "write_atomic",
            "edit",
            "mkdir",
            "rename",
            "remove",
            "exec",
            "exec_stream",
            "pty",
            "signals",
            "resize",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        capabilities.push(format!("environment.os={}", std::env::consts::OS));
        capabilities.push(format!("environment.arch={}", std::env::consts::ARCH));
        capabilities.push(format!("environment.family={}", std::env::consts::FAMILY));
        if let Ok(shell) = std::env::var("SHELL") {
            capabilities.push(format!("environment.shell={shell}"));
        }
        capabilities
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
            WorkspaceOperation::Write {
                path,
                data_base64,
                expected_blake3,
                overwrite,
                mode,
            } => {
                self.write(
                    &path,
                    &data_base64,
                    expected_blake3.as_deref(),
                    overwrite,
                    mode,
                )
                .await
            }
            WorkspaceOperation::Edit {
                path,
                old_text,
                new_text,
                expected_blake3,
            } => {
                self.edit(&path, &old_text, &new_text, expected_blake3.as_deref())
                    .await
            }
            WorkspaceOperation::Mkdir { path, recursive } => self.mkdir(&path, recursive).await,
            WorkspaceOperation::Rename {
                from,
                to,
                overwrite,
            } => self.rename(&from, &to, overwrite).await,
            WorkspaceOperation::Remove { path, recursive } => self.remove(&path, recursive).await,
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
        Ok(WorkspaceValue::Hash {
            algorithm: "blake3".to_owned(),
            digest: hash_file(&candidate).await?,
        })
    }

    async fn write(
        &self,
        path: &str,
        data_base64: &str,
        expected_blake3: Option<&str>,
        overwrite: bool,
        mode: Option<u32>,
    ) -> Result<WorkspaceValue> {
        let data = BASE64
            .decode(data_base64)
            .context("invalid workspace write payload")?;
        if data.len() > MAX_WORKSPACE_WRITE {
            bail!("write payload exceeds {MAX_WORKSPACE_WRITE} bytes");
        }
        if mode.is_some_and(|mode| mode & !0o777 != 0) {
            bail!("file mode may only contain Unix permission bits (0000-0777)");
        }
        let _guard = self.mutations.lock().await;
        self.write_atomic_unlocked(path, &data, expected_blake3, overwrite, mode)
            .await
    }

    async fn edit(
        &self,
        path: &str,
        old_text: &str,
        new_text: &str,
        expected_blake3: Option<&str>,
    ) -> Result<WorkspaceValue> {
        if old_text.is_empty() {
            bail!("old_text cannot be empty");
        }
        let _guard = self.mutations.lock().await;
        let candidate = self.resolve_existing(path).await?;
        let metadata = fs::metadata(&candidate).await?;
        if !metadata.is_file() {
            bail!("not a regular file: {path}");
        }
        if metadata.len() > MAX_EDIT_FILE {
            bail!("file is too large for text edit (maximum {MAX_EDIT_FILE} bytes)");
        }
        let contents = fs::read(&candidate).await?;
        let source_digest = blake3::hash(&contents).to_hex().to_string();
        if let Some(expected) = expected_blake3 {
            validate_expected_digest(expected)?;
            if !source_digest.eq_ignore_ascii_case(expected) {
                bail!("write conflict: expected BLAKE3 {expected}, found {source_digest}");
            }
        }
        let text = std::str::from_utf8(&contents).context("file is not valid UTF-8")?;
        let mut matches = text.match_indices(old_text);
        let (start, _) = matches
            .next()
            .ok_or_else(|| anyhow!("old_text was not found"))?;
        if matches.next().is_some() {
            bail!("old_text is not unique; provide more surrounding context");
        }
        let mut edited = String::with_capacity(text.len() - old_text.len() + new_text.len());
        edited.push_str(&text[..start]);
        edited.push_str(new_text);
        edited.push_str(&text[start + old_text.len()..]);
        if edited.len() > MAX_WORKSPACE_WRITE {
            bail!("edited file exceeds the {MAX_WORKSPACE_WRITE}-byte atomic write limit");
        }
        self.write_atomic_unlocked(path, edited.as_bytes(), Some(&source_digest), true, None)
            .await
    }

    async fn mkdir(&self, path: &str, recursive: bool) -> Result<WorkspaceValue> {
        let _guard = self.mutations.lock().await;
        let relative = mutable_relative(path)?;
        let target = if recursive {
            let mut current = self.canonical.as_ref().clone();
            for component in relative.components() {
                let Component::Normal(name) = component else {
                    unreachable!("mutable_relative only returns normal components")
                };
                current.push(name);
                match fs::symlink_metadata(&current).await {
                    Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                    Ok(_) => bail!(
                        "refusing non-directory or symlinked path {}",
                        current.display()
                    ),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        fs::create_dir(&current).await?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            current
        } else {
            let target = self.resolve_leaf(path).await?;
            fs::create_dir(&target).await?;
            target
        };
        mutation_value(path, Some(fs::symlink_metadata(target).await?), None)
    }

    async fn rename(&self, from: &str, to: &str, overwrite: bool) -> Result<WorkspaceValue> {
        let _guard = self.mutations.lock().await;
        mutable_relative(from)?;
        mutable_relative(to)?;
        let source = self.resolve_leaf(from).await?;
        fs::symlink_metadata(&source).await?;
        let destination = self.resolve_leaf(to).await?;
        if !overwrite && path_exists(&destination).await? {
            bail!("destination already exists: {to}");
        }
        fs::rename(source, &destination).await?;
        mutation_value(to, Some(fs::symlink_metadata(destination).await?), None)
    }

    async fn remove(&self, path: &str, recursive: bool) -> Result<WorkspaceValue> {
        let _guard = self.mutations.lock().await;
        mutable_relative(path)?;
        let target = self.resolve_leaf(path).await?;
        let metadata = fs::symlink_metadata(&target).await?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            if recursive {
                fs::remove_dir_all(target).await?;
            } else {
                fs::remove_dir(target).await?;
            }
        } else {
            fs::remove_file(target).await?;
        }
        mutation_value(path, None, None)
    }

    async fn write_atomic_unlocked(
        &self,
        path: &str,
        data: &[u8],
        expected_blake3: Option<&str>,
        overwrite: bool,
        requested_mode: Option<u32>,
    ) -> Result<WorkspaceValue> {
        mutable_relative(path)?;
        let target = self.resolve_leaf(path).await?;
        let existing = match fs::symlink_metadata(&target).await {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if let Some(metadata) = &existing {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("refusing to replace non-regular or symlinked file: {path}");
            }
            if expected_blake3.is_none() && !overwrite {
                bail!("file already exists; provide expected_blake3 or set overwrite=true");
            }
        } else if expected_blake3.is_some() {
            bail!("file does not exist but expected_blake3 was provided");
        }
        verify_expected_hash(&target, expected_blake3).await?;

        let parent = target
            .parent()
            .ok_or_else(|| anyhow!("workspace file has no parent directory"))?;
        let temporary = parent.join(format!(
            ".sshai-write-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let operation = async {
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .await?;
            let mode = requested_mode.or_else(|| existing.as_ref().and_then(permission_mode));
            if let Some(mode) = mode {
                set_permissions(&temporary, mode).await?;
            }
            file.write_all(data).await?;
            file.flush().await?;
            file.sync_all().await?;
            drop(file);
            // Recheck immediately before the atomic replace to catch concurrent edits.
            verify_expected_hash(&target, expected_blake3).await?;
            if existing.is_none() && !overwrite && path_exists(&target).await? {
                bail!("write conflict: file was created concurrently: {path}");
            }
            fs::rename(&temporary, &target).await?;
            if let Err(error) = sync_directory(parent).await {
                tracing::warn!(%error, path = %parent.display(), "atomic write committed but directory fsync is unavailable");
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if operation.is_err() {
            let _ = fs::remove_file(&temporary).await;
        }
        operation?;
        let metadata = fs::symlink_metadata(&target).await?;
        mutation_value(
            path,
            Some(metadata),
            Some(blake3::hash(data).to_hex().to_string()),
        )
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

fn mutable_relative(path: &str) -> Result<PathBuf> {
    let relative = validate_relative(path)?;
    if relative.as_os_str().is_empty() {
        bail!("refusing to mutate the workspace root");
    }
    Ok(relative)
}

async fn path_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path).await {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

async fn verify_expected_hash(path: &Path, expected: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    validate_expected_digest(expected)?;
    let actual = hash_file(path).await?;
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("write conflict: expected BLAKE3 {expected}, found {actual}");
    }
    Ok(())
}

fn validate_expected_digest(expected: &str) -> Result<()> {
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("expected_blake3 must be a 64-character hexadecimal digest");
    }
    Ok(())
}

async fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn mutation_value(
    path: &str,
    metadata: Option<std::fs::Metadata>,
    blake3: Option<String>,
) -> Result<WorkspaceValue> {
    Ok(WorkspaceValue::Mutation {
        path: path.to_owned(),
        metadata: metadata.as_ref().map(workspace_metadata),
        blake3,
    })
}

#[cfg(unix)]
fn permission_mode(metadata: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.mode() & 0o777)
}

#[cfg(not(unix))]
fn permission_mode(_metadata: &std::fs::Metadata) -> Option<u32> {
    None
}

#[cfg(unix)]
async fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_permissions(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

async fn sync_directory(path: &Path) -> Result<()> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || FileSync::sync(path))
        .await
        .map_err(|error| anyhow!("directory sync task failed: {error}"))??;
    Ok(())
}

struct FileSync;

impl FileSync {
    fn sync(path: PathBuf) -> std::io::Result<()> {
        std::fs::File::open(path)?.sync_all()
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
    async fn reads_hashes_and_lists_inside_workspace() {
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
    }

    #[tokio::test]
    async fn atomically_writes_edits_and_detects_conflicts() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = WorkspaceRoot::open(temporary.path()).await.unwrap();
        let created = workspace
            .perform(WorkspaceOperation::Write {
                path: "notes.txt".to_owned(),
                data_base64: BASE64.encode(b"alpha beta"),
                expected_blake3: None,
                overwrite: false,
                mode: Some(0o640),
            })
            .await
            .unwrap();
        let digest = match created {
            WorkspaceValue::Mutation {
                blake3: Some(digest),
                ..
            } => digest,
            _ => panic!("unexpected write response"),
        };
        assert_eq!(
            tokio::fs::read(temporary.path().join("notes.txt"))
                .await
                .unwrap(),
            b"alpha beta"
        );

        let conflict = workspace
            .perform(WorkspaceOperation::Write {
                path: "notes.txt".to_owned(),
                data_base64: BASE64.encode(b"unsafe overwrite"),
                expected_blake3: None,
                overwrite: false,
                mode: None,
            })
            .await
            .unwrap_err();
        assert!(conflict.to_string().contains("already exists"));

        workspace
            .perform(WorkspaceOperation::Edit {
                path: "notes.txt".to_owned(),
                old_text: "beta".to_owned(),
                new_text: "gamma".to_owned(),
                expected_blake3: Some(digest.clone()),
            })
            .await
            .unwrap();
        assert_eq!(
            tokio::fs::read(temporary.path().join("notes.txt"))
                .await
                .unwrap(),
            b"alpha gamma"
        );

        let stale = workspace
            .perform(WorkspaceOperation::Edit {
                path: "notes.txt".to_owned(),
                old_text: "gamma".to_owned(),
                new_text: "delta".to_owned(),
                expected_blake3: Some(digest),
            })
            .await
            .unwrap_err();
        assert!(stale.to_string().contains("write conflict"));
    }

    #[tokio::test]
    async fn creates_renames_and_removes_paths() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = WorkspaceRoot::open(temporary.path()).await.unwrap();
        workspace
            .perform(WorkspaceOperation::Mkdir {
                path: "a/b".to_owned(),
                recursive: true,
            })
            .await
            .unwrap();
        tokio::fs::write(temporary.path().join("a/b/file"), b"x")
            .await
            .unwrap();
        workspace
            .perform(WorkspaceOperation::Rename {
                from: "a/b/file".to_owned(),
                to: "a/b/renamed".to_owned(),
                overwrite: false,
            })
            .await
            .unwrap();
        workspace
            .perform(WorkspaceOperation::Remove {
                path: "a".to_owned(),
                recursive: true,
            })
            .await
            .unwrap();
        assert!(!temporary.path().join("a").exists());
        assert!(
            workspace
                .perform(WorkspaceOperation::Remove {
                    path: ".".to_owned(),
                    recursive: true,
                })
                .await
                .is_err()
        );
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

        let write_error = workspace
            .perform(WorkspaceOperation::Write {
                path: "escape".to_owned(),
                data_base64: BASE64.encode(b"do not escape"),
                expected_blake3: None,
                overwrite: true,
                mode: None,
            })
            .await
            .unwrap_err();
        assert!(write_error.to_string().contains("symlinked"));

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
