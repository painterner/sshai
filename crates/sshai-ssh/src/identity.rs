use std::{
    collections::HashSet,
    io::IsTerminal,
    path::{Path, PathBuf},
};

use russh::keys::{
    self, PublicKeyBase64,
    agent::{AgentIdentity, client::AgentClient},
    ssh_key::{HashAlg, PublicKey},
};
use zeroize::Zeroizing;

use crate::{Result, SshError};

#[derive(Clone, Debug)]
pub struct PublicIdentity {
    pub authorized_key: String,
    pub key_blob: String,
    pub fingerprint: String,
    pub source: String,
}

/// Discover public identities using ssh-copy-id compatible priorities.
///
/// An explicit identity selects exactly one key. Without one, identities from
/// SSH Agent are preferred; configured identity files are the fallback.
pub async fn discover_public_identities(
    explicit: Option<&Path>,
    configured_private_keys: &[PathBuf],
) -> Result<Vec<PublicIdentity>> {
    let identities = if let Some(path) = explicit {
        vec![load_identity_file(path).await?]
    } else {
        let agent = identities_from_agent().await.unwrap_or_else(|error| {
            tracing::debug!(%error, "could not discover copy-id keys from SSH Agent");
            Vec::new()
        });
        if agent.is_empty() {
            let mut files = Vec::new();
            for private_key in configured_private_keys {
                let public_key = companion_public_key(private_key);
                if public_key.is_file() {
                    files.push(load_public_key_file(&public_key)?);
                }
            }
            files
        } else {
            agent
        }
    };

    let mut seen = HashSet::new();
    let identities = identities
        .into_iter()
        .filter(|identity| seen.insert(identity.key_blob.clone()))
        .collect::<Vec<_>>();
    if identities.is_empty() {
        return Err(SshError::Config(
            "no public keys found; use `sshai copy-id -i ~/.ssh/id_ed25519.pub HOST`".to_owned(),
        ));
    }
    Ok(identities)
}

async fn load_identity_file(path: &Path) -> Result<PublicIdentity> {
    let public_companion = companion_public_key(path);
    if path.extension().is_some_and(|extension| extension == "pub") {
        return load_public_key_file(path);
    }
    if public_companion.is_file() {
        return load_public_key_file(&public_companion);
    }

    let path = path.to_owned();
    let load_path = path.clone();
    let first = tokio::task::spawn_blocking(move || keys::load_secret_key(load_path, None))
        .await
        .map_err(|error| SshError::PrivateKey {
            path: path.clone(),
            message: error.to_string(),
        })?;
    let private_key = match first {
        Ok(key) => key,
        Err(keys::Error::KeyIsEncrypted) if std::io::stdin().is_terminal() => {
            let display = path.display().to_string();
            let password = tokio::task::spawn_blocking(move || {
                rpassword::prompt_password(format!("Passphrase for key {display}: "))
            })
            .await
            .map_err(|error| SshError::PrivateKey {
                path: path.clone(),
                message: error.to_string(),
            })??;
            let password = Zeroizing::new(password);
            let load_path = path.clone();
            let password = password.to_string();
            tokio::task::spawn_blocking(move || {
                let password = Zeroizing::new(password);
                keys::load_secret_key(load_path, Some(password.as_str()))
            })
            .await
            .map_err(|error| SshError::PrivateKey {
                path: path.clone(),
                message: error.to_string(),
            })?
            .map_err(|error| SshError::PrivateKey {
                path: path.clone(),
                message: error.to_string(),
            })?
        }
        Err(error) => {
            return Err(SshError::PrivateKey {
                path,
                message: error.to_string(),
            });
        }
    };
    identity_from_key(
        private_key.public_key().clone(),
        format!("derived from {}", path.display()),
    )
}

fn load_public_key_file(path: &Path) -> Result<PublicIdentity> {
    let contents = std::fs::read_to_string(path).map_err(|error| SshError::PrivateKey {
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    let line = contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| SshError::PrivateKey {
            path: path.to_owned(),
            message: "public key file is empty".to_owned(),
        })?;
    let key = PublicKey::from_openssh(line).map_err(|error| SshError::PrivateKey {
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    identity_from_key(key, path.display().to_string())
}

#[cfg(unix)]
async fn identities_from_agent() -> Result<Vec<PublicIdentity>> {
    let mut agent = AgentClient::connect_env().await?;
    let mut identities = Vec::new();
    for identity in agent.request_identities().await? {
        if let AgentIdentity::PublicKey { key, comment } = identity {
            let source = if comment.is_empty() {
                "SSH Agent".to_owned()
            } else {
                format!("SSH Agent: {}", sanitize_comment(&comment))
            };
            identities.push(identity_from_key(key, source)?);
        }
    }
    Ok(identities)
}

#[cfg(not(unix))]
async fn identities_from_agent() -> Result<Vec<PublicIdentity>> {
    Ok(Vec::new())
}

fn identity_from_key(key: PublicKey, source: String) -> Result<PublicIdentity> {
    let key_blob = key.public_key_base64();
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    let authorized_key = key.to_openssh()?;
    Ok(PublicIdentity {
        authorized_key: authorized_key.trim().to_owned(),
        key_blob,
        fingerprint,
        source,
    })
}

fn companion_public_key(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(".pub");
    PathBuf::from(value)
}

fn sanitize_comment(comment: &str) -> String {
    comment.replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_companion_public_key_path() {
        assert_eq!(
            companion_public_key(Path::new("/tmp/id_ed25519")),
            PathBuf::from("/tmp/id_ed25519.pub")
        );
    }

    #[test]
    fn sanitizes_agent_comments() {
        assert_eq!(sanitize_comment("work\nkey\rname"), "work key name");
    }
}
