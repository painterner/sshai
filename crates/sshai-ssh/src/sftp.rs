use std::{
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use russh_sftp::{
    client::SftpSession,
    protocol::{FileAttributes, OpenFlags},
};
use sha2::{Digest, Sha256};
use sshai_protocol::WorkspaceFileKind;
use tokio::{
    fs::{self, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt, copy},
};

use crate::{Result, SshError};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const MAX_AUTHORIZED_KEYS_SIZE: u64 = 16 * 1024 * 1024;
const MAX_TRANSFER_ENTRIES: u64 = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyInstallResult {
    Installed,
    AlreadyPresent,
}

/// One entry of a remote directory listing.
#[derive(Clone, Debug)]
pub struct RemoteDirEntry {
    pub name: String,
    pub kind: WorkspaceFileKind,
    pub size: u64,
    pub modified_ms: Option<u64>,
    pub executable: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SftpTransferStats {
    pub bytes: u64,
    pub files: u64,
    pub directories: u64,
}

/// A small stable wrapper around `russh-sftp` used for bootstrap transfers.
pub struct SftpClient {
    inner: SftpSession,
    base: Option<String>,
}

impl SftpClient {
    pub(crate) fn new(inner: SftpSession, base: Option<String>) -> Self {
        Self { inner, base }
    }

    pub async fn canonicalize(&self, path: impl Into<String>) -> Result<String> {
        Ok(self.inner.canonicalize(path).await?)
    }

    pub async fn remote_home(&self) -> Result<String> {
        Ok(self.inner.canonicalize(".").await?)
    }

    pub async fn exists(&self, remote: impl Into<String>) -> Result<bool> {
        Ok(self
            .inner
            .try_exists(self.remote_path(remote.into()))
            .await?)
    }

    /// Whether the remote path is a directory, following the final symlink.
    /// A path that does not exist is reported as `false`.
    pub async fn is_dir(&self, remote: impl Into<String>) -> Result<bool> {
        let remote = self.remote_path(remote.into());
        if !self.inner.try_exists(remote.clone()).await? {
            return Ok(false);
        }
        Ok(self.inner.metadata(remote).await?.is_dir())
    }

    /// One directory listing with the metadata the protocol already carries,
    /// so a scan needs no extra round trip per entry.
    pub async fn read_dir_entries(&self, remote: impl Into<String>) -> Result<Vec<RemoteDirEntry>> {
        let remote = self.remote_path(remote.into());
        let mut entries = Vec::new();
        for entry in self.inner.read_dir(remote).await? {
            let metadata = entry.metadata();
            let kind = if metadata.is_symlink() {
                WorkspaceFileKind::Symlink
            } else if metadata.is_dir() {
                WorkspaceFileKind::Directory
            } else if metadata.is_regular() {
                WorkspaceFileKind::File
            } else {
                WorkspaceFileKind::Other
            };
            entries.push(RemoteDirEntry {
                name: entry.file_name(),
                kind,
                size: metadata.size.unwrap_or_default(),
                // SFTP reports whole seconds.
                modified_ms: metadata.mtime.map(|seconds| u64::from(seconds) * 1000),
                executable: metadata.permissions.is_some_and(|mode| mode & 0o111 != 0),
            });
        }
        Ok(entries)
    }

    /// Create the parent directories of a remote path.
    pub async fn ensure_parent_dir(&self, remote: &str) -> Result<()> {
        self.ensure_parent_directory(remote).await
    }

    pub async fn set_permissions(&self, remote: impl Into<String>, mode: u32) -> Result<()> {
        self.inner
            .set_metadata(
                self.remote_path(remote.into()),
                FileAttributes {
                    permissions: Some(mode),
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }

    /// Hash a regular remote file without invoking any remote command.
    pub async fn sha256(&self, remote: impl Into<String>) -> Result<Option<String>> {
        let remote = self.remote_path(remote.into());
        if !self.inner.try_exists(remote.clone()).await? {
            return Ok(None);
        }
        let metadata = self.inner.symlink_metadata(remote.clone()).await?;
        if metadata.is_symlink() || !metadata.is_regular() {
            return Err(SshError::Config(format!(
                "refusing to hash non-regular or symlinked remote file {remote}"
            )));
        }

        let mut file = self.inner.open(remote).await?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let result = async {
            loop {
                let read = file.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                digest.update(&buffer[..read]);
            }
            Ok::<_, SshError>(hex::encode(digest.finalize()))
        }
        .await;
        let close = file.close().await;
        match (result, close) {
            (Ok(digest), Ok(())) => Ok(Some(digest)),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    pub async fn ensure_dir_all(&self, remote: impl Into<String>, mode: u32) -> Result<()> {
        let path = self.ensure_directory_components(remote).await?;
        self.set_permissions(path, mode).await
    }

    /// Create missing directory components without changing permissions on an existing path.
    pub async fn create_dir_all(&self, remote: impl Into<String>) -> Result<()> {
        self.ensure_directory_components(remote).await?;
        Ok(())
    }

    async fn ensure_directory_components(&self, remote: impl Into<String>) -> Result<String> {
        let path = self.remote_path(remote.into());
        let absolute = path.starts_with('/');
        let mut current = if absolute {
            "/".to_owned()
        } else {
            String::new()
        };
        for component in path.split('/').filter(|component| !component.is_empty()) {
            if component == "." {
                continue;
            }
            if component == ".." {
                return Err(SshError::Config(format!(
                    "refusing parent traversal in remote directory {path:?}"
                )));
            }
            current = if current == "/" {
                format!("/{component}")
            } else if current.is_empty() {
                component.to_owned()
            } else {
                format!("{current}/{component}")
            };
            if !self.inner.try_exists(current.clone()).await? {
                self.inner.create_dir(current.clone()).await?;
            } else {
                let metadata = self.inner.symlink_metadata(current.clone()).await?;
                if metadata.is_symlink() || !metadata.is_dir() {
                    return Err(SshError::Config(format!(
                        "refusing non-directory or symlinked path {current}"
                    )));
                }
            }
        }
        Ok(path)
    }

    pub async fn download(
        &self,
        remote: impl Into<String>,
        local: impl AsRef<Path>,
        overwrite: bool,
    ) -> Result<u64> {
        let local = local.as_ref();
        if local.exists() && !overwrite {
            return Err(SshError::Config(format!(
                "local file {} already exists; pass --force to replace it",
                local.display()
            )));
        }

        let temporary = temporary_path(local);
        let mut source = self.inner.open(self.remote_path(remote.into())).await?;
        let mut destination = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .await?;

        let copied = match copy(&mut source, &mut destination).await {
            Ok(copied) => copied,
            Err(error) => {
                let _ = fs::remove_file(&temporary).await;
                return Err(error.into());
            }
        };
        destination.flush().await?;
        destination.sync_all().await?;
        source.close().await?;
        drop(destination);

        if overwrite && local.exists() {
            fs::remove_file(local).await?;
        }
        fs::rename(&temporary, local).await?;
        Ok(copied)
    }

    pub async fn upload(
        &self,
        local: impl AsRef<Path>,
        remote: impl Into<String>,
        overwrite: bool,
    ) -> Result<u64> {
        let local = local.as_ref();
        let remote = self.remote_path(remote.into());
        if self.inner.try_exists(remote.clone()).await? && !overwrite {
            return Err(SshError::Config(format!(
                "remote file {remote} already exists; pass --force to replace it"
            )));
        }

        let temporary = format!(
            "{remote}.sshai-upload-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let mut source = fs::File::open(local).await?;
        let mut destination = self.inner.create(temporary.clone()).await?;
        let copied = match copy(&mut source, &mut destination).await {
            Ok(copied) => copied,
            Err(error) => {
                let _ = destination.close().await;
                let _ = self.inner.remove_file(temporary).await;
                return Err(error.into());
            }
        };
        if let Err(error) = destination.flush().await {
            let _ = destination.close().await;
            let _ = self.inner.remove_file(temporary).await;
            return Err(error.into());
        }
        if let Err(error) = destination.sync_all().await {
            let _ = destination.close().await;
            let _ = self.inner.remove_file(temporary).await;
            return Err(error.into());
        }
        destination.close().await?;

        if overwrite && self.inner.try_exists(remote.clone()).await? {
            self.inner.remove_file(remote.clone()).await?;
        }
        if let Err(error) = self.inner.rename(temporary.clone(), remote).await {
            let _ = self.inner.remove_file(temporary).await;
            return Err(error.into());
        }
        Ok(copied)
    }

    pub async fn upload_path(
        &self,
        local: impl AsRef<Path>,
        remote: impl Into<String>,
        recursive: bool,
        overwrite: bool,
        excludes: &[String],
    ) -> Result<SftpTransferStats> {
        let local = local.as_ref();
        ensure_no_local_symlink(local)?;
        let source = local.canonicalize().map_err(SshError::Io)?;
        let metadata = std::fs::symlink_metadata(&source).map_err(SshError::Io)?;
        if metadata.file_type().is_symlink() {
            return Err(SshError::Config(format!(
                "refusing to transfer local symlink {}",
                source.display()
            )));
        }
        let remote = remote.into();
        if metadata.is_file() {
            self.ensure_parent_directory(&remote).await?;
            let bytes = self.upload(&source, remote.clone(), overwrite).await?;
            self.set_permissions(remote, local_mode(&metadata, false))
                .await?;
            return Ok(SftpTransferStats {
                bytes,
                files: 1,
                directories: 0,
            });
        }
        if !metadata.is_dir() {
            return Err(SshError::Config(
                "local source is neither a regular file nor a directory".to_owned(),
            ));
        }
        if !recursive {
            return Err(SshError::Config(
                "local source is a directory; pass --recursive".to_owned(),
            ));
        }

        let mut stats = SftpTransferStats::default();
        let mut stack = vec![(source, remote, PathBuf::new())];
        while let Some((local, remote, relative)) = stack.pop() {
            if transfer_excluded(&relative, excludes) {
                continue;
            }
            ensure_transfer_limit(stats)?;
            let metadata = std::fs::symlink_metadata(&local).map_err(SshError::Io)?;
            if metadata.file_type().is_symlink() {
                return Err(SshError::Config(format!(
                    "refusing to transfer local symlink {}",
                    local.display()
                )));
            }
            if metadata.is_dir() {
                if remote != "." {
                    self.create_dir_all(remote.clone()).await?;
                }
                stats.directories += 1;
                let mut children = std::fs::read_dir(&local)
                    .map_err(SshError::Io)?
                    .collect::<std::io::Result<Vec<_>>>()
                    .map_err(SshError::Io)?;
                children.sort_by_key(std::fs::DirEntry::file_name);
                for child in children.into_iter().rev() {
                    let name = child.file_name();
                    stack.push((
                        child.path(),
                        join_remote_path(&remote, &name.to_string_lossy()),
                        relative.join(name),
                    ));
                }
            } else if metadata.is_file() {
                self.ensure_parent_directory(&remote).await?;
                stats.bytes += self.upload(&local, remote.clone(), overwrite).await?;
                self.set_permissions(remote, local_mode(&metadata, false))
                    .await?;
                stats.files += 1;
            } else {
                return Err(SshError::Config(format!(
                    "refusing to transfer special local file {}",
                    local.display()
                )));
            }
        }
        Ok(stats)
    }

    pub async fn download_path(
        &self,
        remote: impl Into<String>,
        local: impl AsRef<Path>,
        recursive: bool,
        overwrite: bool,
        excludes: &[String],
    ) -> Result<SftpTransferStats> {
        let remote = self.remote_path(remote.into());
        let local = local.as_ref();
        ensure_no_local_symlink(local)?;
        let metadata = self.inner.symlink_metadata(remote.clone()).await?;
        if metadata.is_symlink() {
            return Err(SshError::Config(format!(
                "refusing to transfer remote symlink {remote}"
            )));
        }
        if metadata.is_regular() {
            ensure_local_parent(local)?;
            let bytes = self.download(remote, local, overwrite).await?;
            set_local_permissions(local, metadata.permissions, false)?;
            return Ok(SftpTransferStats {
                bytes,
                files: 1,
                directories: 0,
            });
        }
        if !metadata.is_dir() {
            return Err(SshError::Config(
                "remote source is neither a regular file nor a directory".to_owned(),
            ));
        }
        if !recursive {
            return Err(SshError::Config(
                "remote source is a directory; pass --recursive".to_owned(),
            ));
        }

        let mut stats = SftpTransferStats::default();
        let mut stack = vec![(remote, local.to_owned(), PathBuf::new())];
        while let Some((remote, local, relative)) = stack.pop() {
            if transfer_excluded(&relative, excludes) {
                continue;
            }
            ensure_transfer_limit(stats)?;
            ensure_local_directory(&local)?;
            stats.directories += 1;

            let mut entries = self.inner.read_dir(remote).await?.collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries.into_iter().rev() {
                let name = entry.file_name();
                let child_relative = relative.join(&name);
                if transfer_excluded(&child_relative, excludes) {
                    continue;
                }
                let child_remote = entry.path();
                let child_local = local.join(&name);
                let metadata = entry.metadata();
                if metadata.is_dir() {
                    stack.push((child_remote, child_local, child_relative));
                } else if metadata.is_regular() {
                    ensure_transfer_limit(stats)?;
                    ensure_local_parent(&child_local)?;
                    stats.bytes += self.download(child_remote, &child_local, overwrite).await?;
                    set_local_permissions(&child_local, metadata.permissions, false)?;
                    stats.files += 1;
                } else if metadata.is_symlink() {
                    return Err(SshError::Config(format!(
                        "refusing to transfer remote symlink {child_remote}"
                    )));
                } else {
                    return Err(SshError::Config(format!(
                        "refusing to transfer special remote file {child_remote}"
                    )));
                }
            }
        }
        Ok(stats)
    }

    async fn ensure_parent_directory(&self, remote: &str) -> Result<()> {
        let parent = remote
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .unwrap_or(".");
        if parent != "." && !parent.is_empty() {
            self.create_dir_all(parent.to_owned()).await?;
        }
        Ok(())
    }

    pub(crate) async fn upload_bytes(
        &self,
        data: &[u8],
        remote: impl Into<String>,
        overwrite: bool,
    ) -> Result<u64> {
        let remote = self.remote_path(remote.into());
        if self.inner.try_exists(remote.clone()).await? && !overwrite {
            return Err(SshError::Config(format!(
                "remote file {remote} already exists; pass --force to replace it"
            )));
        }

        let temporary = format!(
            "{remote}.sshai-upload-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let mut destination = self.inner.create(temporary.clone()).await?;
        if let Err(error) = destination.write_all(data).await {
            let _ = destination.close().await;
            let _ = self.inner.remove_file(temporary.clone()).await;
            return Err(error.into());
        }
        if let Err(error) = destination.flush().await {
            let _ = destination.close().await;
            let _ = self.inner.remove_file(temporary.clone()).await;
            return Err(error.into());
        }
        if let Err(error) = destination.sync_all().await {
            let _ = destination.close().await;
            let _ = self.inner.remove_file(temporary.clone()).await;
            return Err(error.into());
        }
        destination.close().await?;
        if overwrite && self.inner.try_exists(remote.clone()).await? {
            self.inner.remove_file(remote.clone()).await?;
        }
        if let Err(error) = self.inner.rename(temporary.clone(), remote).await {
            let _ = self.inner.remove_file(temporary).await;
            return Err(error.into());
        }
        Ok(data.len() as u64)
    }

    pub async fn close(&self) -> Result<()> {
        self.inner.close().await?;
        Ok(())
    }

    /// Add one validated public key to the remote user's authorized_keys.
    ///
    /// The method is idempotent, rejects a symlinked authorized_keys file,
    /// and enforces OpenSSH's recommended 0700/0600 permissions.
    pub async fn install_authorized_key(
        &self,
        authorized_key: &str,
        key_blob: &str,
    ) -> Result<KeyInstallResult> {
        self.install_authorized_key_at(None, authorized_key, key_blob)
            .await
    }

    /// Install a key at an explicit remote authorized_keys path.
    /// Relative paths are resolved from the remote home directory.
    pub async fn install_authorized_key_at(
        &self,
        path: Option<&str>,
        authorized_key: &str,
        key_blob: &str,
    ) -> Result<KeyInstallResult> {
        if authorized_key.contains(['\r', '\n']) {
            return Err(SshError::Config(
                "authorized key must contain exactly one line".to_owned(),
            ));
        }
        if !authorized_key
            .split_whitespace()
            .any(|field| field == key_blob)
        {
            return Err(SshError::Config(
                "authorized key line does not contain the expected key blob".to_owned(),
            ));
        }

        let home = self.inner.canonicalize(".").await?;
        let authorized_keys = match path {
            Some(path) if path.starts_with('/') => path.to_owned(),
            Some(path) => join_remote_path(&home, path),
            None => join_remote_path(&join_remote_path(&home, ".ssh"), "authorized_keys"),
        };
        let ssh_directory = authorized_keys
            .rsplit_once('/')
            .map(|(parent, _)| parent.to_owned())
            .filter(|parent| !parent.is_empty())
            .ok_or_else(|| {
                SshError::Config(format!(
                    "authorized_keys path {authorized_keys:?} has no parent directory"
                ))
            })?;
        if !self.inner.try_exists(ssh_directory.clone()).await? {
            self.inner.create_dir(ssh_directory.clone()).await?;
        } else {
            let metadata = self.inner.symlink_metadata(ssh_directory.clone()).await?;
            if metadata.is_symlink() || !metadata.is_dir() {
                return Err(SshError::Config(format!(
                    "refusing to use non-directory or symlinked path {ssh_directory}"
                )));
            }
        }
        self.inner
            .set_metadata(
                ssh_directory.clone(),
                FileAttributes {
                    permissions: Some(0o700),
                    ..Default::default()
                },
            )
            .await?;

        let exists = self.inner.try_exists(authorized_keys.clone()).await?;
        let mut needs_separator = false;
        if exists {
            let metadata = self.inner.symlink_metadata(authorized_keys.clone()).await?;
            if metadata.is_symlink() {
                return Err(SshError::Config(format!(
                    "refusing to update symlinked file {authorized_keys}"
                )));
            }
            if metadata.len() > MAX_AUTHORIZED_KEYS_SIZE {
                return Err(SshError::Config(format!(
                    "refusing to read {authorized_keys}: file exceeds 16 MiB"
                )));
            }
            let contents = self.inner.read(authorized_keys.clone()).await?;
            let contents = String::from_utf8(contents)
                .map_err(|_| SshError::Config(format!("{authorized_keys} is not valid UTF-8")))?;
            if authorized_keys_contains(&contents, key_blob) {
                self.set_authorized_keys_permissions(authorized_keys)
                    .await?;
                return Ok(KeyInstallResult::AlreadyPresent);
            }
            needs_separator = !contents.is_empty() && !contents.ends_with('\n');
        }

        let flags = if exists {
            OpenFlags::WRITE | OpenFlags::APPEND
        } else {
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE
        };
        let mut file = self
            .inner
            .open_with_flags_and_attributes(
                authorized_keys.clone(),
                flags,
                FileAttributes {
                    permissions: Some(0o600),
                    ..Default::default()
                },
            )
            .await?;
        if needs_separator {
            file.write_all(b"\n").await?;
        }
        file.write_all(authorized_key.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        file.sync_all().await?;
        file.close().await?;
        self.set_authorized_keys_permissions(authorized_keys)
            .await?;
        Ok(KeyInstallResult::Installed)
    }

    async fn set_authorized_keys_permissions(&self, path: String) -> Result<()> {
        self.inner
            .set_metadata(
                path,
                FileAttributes {
                    permissions: Some(0o600),
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }

    fn remote_path(&self, path: String) -> String {
        if path.starts_with('/') || self.base.is_none() {
            return path;
        }
        let base = self
            .base
            .as_deref()
            .unwrap_or_default()
            .trim_end_matches('/');
        format!("{base}/{path}")
    }
}

fn join_remote_path(parent: &str, child: &str) -> String {
    if parent == "." || parent.is_empty() {
        child.to_owned()
    } else if parent == "/" {
        format!("/{child}")
    } else {
        format!("{}/{}", parent.trim_end_matches('/'), child)
    }
}

fn transfer_excluded(relative: &Path, excludes: &[String]) -> bool {
    if relative.as_os_str().is_empty() {
        return false;
    }
    let normalized = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>();
    excludes.iter().any(|exclude| {
        let exclude = exclude.trim_matches('/');
        if exclude.is_empty() {
            return false;
        }
        if exclude.contains('/') {
            let path = normalized.join("/");
            path == exclude || path.starts_with(&format!("{exclude}/"))
        } else {
            normalized.iter().any(|component| component == exclude)
        }
    })
}

fn ensure_transfer_limit(stats: SftpTransferStats) -> Result<()> {
    if stats.files + stats.directories >= MAX_TRANSFER_ENTRIES {
        return Err(SshError::Config(format!(
            "transfer exceeds {MAX_TRANSFER_ENTRIES} filesystem entries"
        )));
    }
    Ok(())
}

fn ensure_no_local_symlink(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(SshError::Config(format!(
                    "refusing local symlink in transfer path {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(SshError::Io(error)),
        }
    }
    Ok(())
}

fn ensure_local_parent(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        SshError::Config(format!(
            "local destination {} has no parent",
            path.display()
        ))
    })?;
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    ensure_local_directory(parent)
}

fn ensure_local_directory(path: &Path) -> Result<()> {
    ensure_no_local_symlink(path)?;
    std::fs::create_dir_all(path).map_err(SshError::Io)?;
    ensure_no_local_symlink(path)
}

#[cfg(unix)]
fn local_mode(metadata: &std::fs::Metadata, _directory: bool) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn local_mode(_metadata: &std::fs::Metadata, directory: bool) -> u32 {
    if directory { 0o755 } else { 0o644 }
}

#[cfg(unix)]
fn set_local_permissions(path: &Path, permissions: Option<u32>, _directory: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(mode) = permissions {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o777))
            .map_err(SshError::Io)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_local_permissions(_path: &Path, _permissions: Option<u32>, _directory: bool) -> Result<()> {
    Ok(())
}

fn authorized_keys_contains(contents: &str, key_blob: &str) -> bool {
    contents.lines().any(|line| {
        let line = line.trim();
        !line.is_empty()
            && !line.starts_with('#')
            && line.split_whitespace().any(|field| field == key_blob)
    })
}

fn temporary_path(destination: &Path) -> std::path::PathBuf {
    let suffix = format!(
        ".sshai-download-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let name = destination
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".to_owned());
    destination.with_file_name(format!("{name}{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAITestBlob";

    #[test]
    fn detects_plain_and_optioned_authorized_keys() {
        assert!(authorized_keys_contains(
            &format!("ssh-ed25519 {BLOB} laptop\n"),
            BLOB
        ));
        assert!(authorized_keys_contains(
            &format!("from=\"10.0.0.0/8\" ssh-ed25519 {BLOB} restricted\n"),
            BLOB
        ));
    }

    #[test]
    fn ignores_comments_and_different_keys() {
        assert!(!authorized_keys_contains(
            &format!("# ssh-ed25519 {BLOB}\nssh-ed25519 other"),
            BLOB
        ));
    }

    #[test]
    fn transfer_excludes_names_and_relative_subtrees() {
        let excludes = vec!["node_modules".to_owned(), "build/cache".to_owned()];
        assert!(transfer_excluded(
            Path::new("web/node_modules/pkg"),
            &excludes
        ));
        assert!(transfer_excluded(Path::new("build/cache/item"), &excludes));
        assert!(!transfer_excluded(Path::new("build/output"), &excludes));
    }

    #[test]
    fn remote_path_join_handles_root_and_relative_destinations() {
        assert_eq!(join_remote_path("/", "file"), "/file");
        assert_eq!(join_remote_path(".", "file"), "file");
        assert_eq!(join_remote_path("dir", "file"), "dir/file");
        assert!(ensure_local_parent(Path::new("file")).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn transfer_rejects_local_symlink_components() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let real = temporary.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = temporary.path().join("link");
        symlink(&real, &link).unwrap();

        assert!(ensure_no_local_symlink(&link.join("file")).is_err());
        assert!(ensure_no_local_symlink(&real.join("file")).is_ok());
    }
}
