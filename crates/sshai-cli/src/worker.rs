use std::{path::PathBuf, process::ExitCode};

use anyhow::{Context, Result, bail};

#[tokio::main]
async fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("sshai-worker: {error:#}");
            ExitCode::from(255)
        }
    }
}

async fn run(arguments: Vec<String>) -> Result<u8> {
    let Some(command) = arguments.first().map(String::as_str) else {
        bail!("expected `serve` or `invoke`");
    };
    match command {
        "serve" => {
            let options = parse_options(&arguments[1..], false)?;
            sshai_agent::serve(sshai_agent::ServeOptions {
                session_id: options.session_id,
                session_dir: options
                    .session_dir
                    .context("serve requires --session-dir")?,
                workspace_root: options
                    .workspace_root
                    .context("serve requires --workspace-root")?,
                prepared: options.prepared,
            })
            .await?;
            Ok(0)
        }
        "invoke" => {
            let options = parse_options(&arguments[1..], true)?;
            sshai_agent::invoke(sshai_agent::InvokeOptions {
                session_id: options.session_id,
                socket: options.socket.context("invoke requires --socket")?,
                argv: options.argv,
            })
            .await
        }
        other => bail!("unknown command {other:?}; expected `serve` or `invoke`"),
    }
}

struct WorkerOptions {
    session_id: String,
    session_dir: Option<PathBuf>,
    workspace_root: Option<PathBuf>,
    socket: Option<PathBuf>,
    argv: Vec<String>,
    prepared: bool,
}

fn parse_options(arguments: &[String], accept_argv: bool) -> Result<WorkerOptions> {
    let mut session_id = None;
    let mut session_dir = None;
    let mut workspace_root = None;
    let mut socket = None;
    let mut prepared = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--" {
            if !accept_argv {
                bail!("unexpected arguments after --");
            }
            let argv = arguments[index + 1..].to_vec();
            if argv.is_empty() {
                bail!("invoke requires a command after --");
            }
            return Ok(WorkerOptions {
                session_id: session_id.context("missing --session-id")?,
                session_dir,
                workspace_root,
                socket,
                argv,
                prepared,
            });
        }

        if argument == "--prepared" && !accept_argv {
            prepared = true;
            index += 1;
            continue;
        }

        index += 1;
        let value = arguments
            .get(index)
            .with_context(|| format!("{argument} requires a value"))?;
        match argument.as_str() {
            "--session-id" => session_id = Some(value.clone()),
            "--session-dir" if !accept_argv => session_dir = Some(PathBuf::from(value)),
            "--workspace-root" if !accept_argv => workspace_root = Some(PathBuf::from(value)),
            "--socket" if accept_argv => socket = Some(PathBuf::from(value)),
            _ => bail!("unknown option {argument:?}"),
        }
        index += 1;
    }

    if accept_argv {
        bail!("invoke requires -- followed by a command");
    }
    Ok(WorkerOptions {
        session_id: session_id.context("missing --session-id")?,
        session_dir,
        workspace_root,
        socket,
        argv: Vec::new(),
        prepared,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_serve_options() {
        let arguments = vec![
            "--session-id".to_owned(),
            "abc".to_owned(),
            "--prepared".to_owned(),
            "--session-dir".to_owned(),
            "/tmp/session".to_owned(),
            "--workspace-root".to_owned(),
            "/srv/project".to_owned(),
        ];
        let options = parse_options(&arguments, false).unwrap();
        assert_eq!(options.session_id, "abc");
        assert_eq!(options.session_dir, Some(PathBuf::from("/tmp/session")));
        assert_eq!(options.workspace_root, Some(PathBuf::from("/srv/project")));
        assert!(options.prepared);
    }

    #[test]
    fn preserves_invoke_arguments_after_separator() {
        let arguments = vec![
            "--session-id".to_owned(),
            "abc".to_owned(),
            "--socket".to_owned(),
            "/tmp/agent.sock".to_owned(),
            "--".to_owned(),
            "claude".to_owned(),
            "--version".to_owned(),
        ];
        let options = parse_options(&arguments, true).unwrap();
        assert_eq!(options.socket, Some(PathBuf::from("/tmp/agent.sock")));
        assert_eq!(options.argv, ["claude", "--version"]);
    }
}
