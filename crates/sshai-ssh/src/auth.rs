use std::{io::IsTerminal, path::Path, sync::Arc};

use russh::{
    client::{self, KeyboardInteractiveAuthResponse},
    keys::{
        self, PrivateKeyWithHashAlg,
        agent::{AgentIdentity, client::AgentClient},
    },
};
use zeroize::Zeroizing;

use crate::{ResolvedTarget, Result, SshError, host_key::ClientHandler};

pub(crate) async fn authenticate(
    session: &mut client::Handle<ClientHandler>,
    target: &ResolvedTarget,
    allow_password: bool,
) -> Result<String> {
    let mut attempts = Vec::new();

    if !target.identities_only {
        match authenticate_agent(session, target).await {
            Ok(Some(description)) => return Ok(description),
            Ok(None) => attempts.push("SSH agent: no accepted identity".to_owned()),
            Err(error) => {
                tracing::debug!(%error, "SSH agent authentication unavailable");
                attempts.push(format!("SSH agent: {error}"));
            }
        }
    }

    for path in &target.identity_files {
        if !path.is_file() {
            continue;
        }
        match authenticate_key_file(session, target, path, allow_password).await {
            Ok(true) => return Ok(format!("key {}", path.display())),
            Ok(false) => attempts.push(format!("key {}: rejected", path.display())),
            Err(error) => attempts.push(format!("key {}: {error}", path.display())),
        }
    }

    if allow_password && std::io::stdin().is_terminal() {
        match authenticate_keyboard_interactive(session, target).await {
            Ok(true) => return Ok("keyboard-interactive".to_owned()),
            Ok(false) => attempts.push("keyboard-interactive: rejected".to_owned()),
            Err(error) => attempts.push(format!("keyboard-interactive: {error}")),
        }

        let prompt = format!("{}@{} password: ", target.user, target.host);
        let password = tokio::task::spawn_blocking(move || rpassword::prompt_password(prompt))
            .await
            .map_err(|error| SshError::Authentication {
                user: target.user.clone(),
                host: target.host.clone(),
                attempts: error.to_string(),
            })??;
        let password = Zeroizing::new(password);
        if session
            .authenticate_password(&target.user, password.as_str())
            .await?
            .success()
        {
            return Ok("password".to_owned());
        }
        attempts.push("password: rejected".to_owned());
    }

    Err(SshError::Authentication {
        user: target.user.clone(),
        host: target.host.clone(),
        attempts: if attempts.is_empty() {
            "no usable authentication methods".to_owned()
        } else {
            attempts.join("; ")
        },
    })
}

#[cfg(unix)]
async fn authenticate_agent(
    session: &mut client::Handle<ClientHandler>,
    target: &ResolvedTarget,
) -> Result<Option<String>> {
    let mut agent = match &target.identity_agent {
        Some(path) => AgentClient::connect_uds(path).await?,
        None => AgentClient::connect_env().await?,
    };
    let identities = agent.request_identities().await?;
    for identity in identities {
        let comment = identity.comment().to_owned();
        let hash = session.best_supported_rsa_hash().await?.flatten();
        let result = match &identity {
            AgentIdentity::PublicKey { key, .. } => {
                session
                    .authenticate_publickey_with(&target.user, key.clone(), hash, &mut agent)
                    .await
            }
            AgentIdentity::Certificate { certificate, .. } => {
                session
                    .authenticate_certificate_with(
                        &target.user,
                        certificate.clone(),
                        hash,
                        &mut agent,
                    )
                    .await
            }
        };
        match result {
            Ok(result) if result.success() => {
                let description = if comment.is_empty() {
                    "SSH agent".to_owned()
                } else {
                    format!("SSH agent ({comment})")
                };
                return Ok(Some(description));
            }
            Ok(_) => {}
            Err(error) => tracing::debug!(%error, "SSH agent identity failed"),
        }
    }
    Ok(None)
}

#[cfg(not(unix))]
async fn authenticate_agent(
    _session: &mut client::Handle<ClientHandler>,
    _target: &ResolvedTarget,
) -> Result<Option<String>> {
    Ok(None)
}

async fn authenticate_key_file(
    session: &mut client::Handle<ClientHandler>,
    target: &ResolvedTarget,
    path: &Path,
    allow_prompt: bool,
) -> Result<bool> {
    let key = match keys::load_secret_key(path, None) {
        Ok(key) => key,
        Err(keys::Error::KeyIsEncrypted) if allow_prompt && std::io::stdin().is_terminal() => {
            let display = path.display().to_string();
            let password = tokio::task::spawn_blocking(move || {
                rpassword::prompt_password(format!("Passphrase for key {display}: "))
            })
            .await
            .map_err(|error| SshError::PrivateKey {
                path: path.to_owned(),
                message: error.to_string(),
            })??;
            let password = Zeroizing::new(password);
            keys::load_secret_key(path, Some(password.as_str())).map_err(|error| {
                SshError::PrivateKey {
                    path: path.to_owned(),
                    message: error.to_string(),
                }
            })?
        }
        Err(error) => {
            return Err(SshError::PrivateKey {
                path: path.to_owned(),
                message: error.to_string(),
            });
        }
    };

    let hash = session.best_supported_rsa_hash().await?.flatten();
    let auth = session
        .authenticate_publickey(
            &target.user,
            PrivateKeyWithHashAlg::new(Arc::new(key), hash),
        )
        .await?;
    Ok(auth.success())
}

async fn authenticate_keyboard_interactive(
    session: &mut client::Handle<ClientHandler>,
    target: &ResolvedTarget,
) -> Result<bool> {
    let mut response = session
        .authenticate_keyboard_interactive_start(&target.user, None::<String>)
        .await?;
    loop {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                if !name.is_empty() {
                    eprintln!("{name}");
                }
                if !instructions.is_empty() {
                    eprintln!("{instructions}");
                }
                let mut answers = Vec::with_capacity(prompts.len());
                for prompt in prompts {
                    let text = prompt.prompt;
                    let echo = prompt.echo;
                    let answer = tokio::task::spawn_blocking(move || {
                        if echo {
                            eprint!("{text}");
                            use std::io::Write;
                            std::io::stderr().flush()?;
                            let mut answer = String::new();
                            std::io::stdin().read_line(&mut answer)?;
                            Ok::<_, std::io::Error>(answer.trim_end().to_owned())
                        } else {
                            rpassword::prompt_password(text)
                        }
                    })
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))??;
                    answers.push(answer);
                }
                response = session
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
}
