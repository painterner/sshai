use std::{
    io::{self, IsTerminal, Write},
    sync::Arc,
};

use russh::{client, keys::PublicKeyOrCertificate};

use crate::{HostKeyPolicy, ResolvedTarget, SshError};

#[derive(Clone)]
pub(crate) struct ClientHandler {
    target: Arc<ResolvedTarget>,
    allow_prompt: bool,
}

impl ClientHandler {
    pub(crate) fn new(target: Arc<ResolvedTarget>, allow_prompt: bool) -> Self {
        Self {
            target,
            allow_prompt,
        }
    }
}

impl client::Handler for ClientHandler {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = server_key.public_key();
        let target = &self.target;

        if target.host_key_policy == HostKeyPolicy::Insecure {
            eprintln!(
                "Warning: host key verification is disabled for {}.",
                target.host
            );
            return Ok(true);
        }

        for path in &target.known_hosts_files {
            match russh::keys::known_hosts::check_known_hosts_path(
                &target.host,
                target.port,
                &key,
                path,
            ) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(russh::keys::Error::KeyChanged { line }) => {
                    return Err(SshError::HostKey {
                        host: target.host.clone(),
                        port: target.port,
                        message: format!("the key differs from {} line {line}", path.display()),
                    });
                }
                Err(error) => {
                    return Err(SshError::HostKey {
                        host: target.host.clone(),
                        port: target.port,
                        message: format!("cannot read {}: {error}", path.display()),
                    });
                }
            }
        }

        let fingerprint = key.fingerprint(russh::keys::ssh_key::HashAlg::Sha256);
        match target.host_key_policy {
            HostKeyPolicy::Strict => Err(SshError::HostKey {
                host: target.host.clone(),
                port: target.port,
                message: format!("unknown host key {fingerprint}"),
            }),
            HostKeyPolicy::AcceptNew => {
                learn_host_key(target, &key)?;
                eprintln!(
                    "Warning: added {} ({fingerprint}) to known_hosts.",
                    target.host
                );
                Ok(true)
            }
            HostKeyPolicy::Ask => {
                if !self.allow_prompt || !io::stdin().is_terminal() {
                    return Err(SshError::HostKey {
                        host: target.host.clone(),
                        port: target.port,
                        message: format!(
                            "unknown host key {fingerprint}; background/batch connections cannot prompt"
                        ),
                    });
                }
                eprintln!(
                    "The authenticity of host '{}' cannot be established.",
                    target.host
                );
                eprintln!("Key fingerprint is {fingerprint}.");
                eprint!("Trust this host and add it to known_hosts? [y/N] ");
                io::stderr().flush()?;
                let accepted = tokio::task::spawn_blocking(|| {
                    let mut answer = String::new();
                    io::stdin().read_line(&mut answer)?;
                    Ok::<_, io::Error>(matches!(
                        answer.trim().to_ascii_lowercase().as_str(),
                        "y" | "yes"
                    ))
                })
                .await
                .map_err(|error| io::Error::other(error.to_string()))??;
                if accepted {
                    learn_host_key(target, &key)?;
                }
                Ok(accepted)
            }
            HostKeyPolicy::Insecure => unreachable!("handled before known_hosts lookup"),
        }
    }
}

fn learn_host_key(
    target: &ResolvedTarget,
    key: &russh::keys::ssh_key::PublicKey,
) -> Result<(), SshError> {
    let Some(path) = target.known_hosts_files.first() else {
        return Err(SshError::HostKey {
            host: target.host.clone(),
            port: target.port,
            message: "no UserKnownHostsFile is configured".to_owned(),
        });
    };
    russh::keys::known_hosts::learn_known_hosts_path(&target.host, target.port, key, path).map_err(
        |error| SshError::HostKey {
            host: target.host.clone(),
            port: target.port,
            message: format!("cannot update {}: {error}", path.display()),
        },
    )
}
