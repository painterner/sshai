use std::{
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use russh_sftp::{
    client::SftpSession,
    protocol::{FileAttributes, OpenFlags},
};
use sha2::{Digest, Sha256};
use tokio::{
    fs::{self, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt, copy},
};

use crate::{Result, SshError};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const MAX_AUTHORIZED_KEYS_SIZE: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyInstallResult {
    Installed,
    AlreadyPresent,
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
        self.set_permissions(path, mode).await
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
    format!("{}/{}", parent.trim_end_matches('/'), child)
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
}
