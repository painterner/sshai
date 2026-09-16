use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A user supplied SSH destination and optional remote workspace path.
///
/// Supported forms:
/// - `host`
/// - `user@host`
/// - `host:/absolute/path`
/// - `user@host:/absolute/path`
/// - `ssh://user@host:2222/absolute/path`
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub path: Option<String>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ParseTargetError {
    #[error("SSH target is empty")]
    Empty,
    #[error("SSH URI must contain a host")]
    MissingHost,
    #[error("invalid SSH port: {0}")]
    InvalidPort(String),
    #[error("IPv6 targets must use the ssh:// URI form")]
    AmbiguousIpv6,
}

impl FromStr for Target {
    type Err = ParseTargetError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            return Err(ParseTargetError::Empty);
        }

        if let Some(rest) = value.strip_prefix("ssh://") {
            return parse_uri(rest);
        }

        if value.starts_with('[') || value.matches(':').count() > 1 {
            return Err(ParseTargetError::AmbiguousIpv6);
        }

        let (authority, path) = match value.split_once(':') {
            Some((authority, "")) => (authority, None),
            Some((authority, path)) => (authority, Some(path.to_owned())),
            None => (value, None),
        };
        let (user, host) = split_user(authority);
        if host.is_empty() {
            return Err(ParseTargetError::MissingHost);
        }

        Ok(Self {
            host: host.to_owned(),
            user,
            port: None,
            path,
        })
    }
}

fn parse_uri(rest: &str) -> Result<Target, ParseTargetError> {
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, Some(format!("/{path}"))),
        None => (rest, None),
    };
    let (user, host_port) = split_user(authority);

    let (host, port) = if let Some(bracketed) = host_port.strip_prefix('[') {
        let Some((host, suffix)) = bracketed.split_once(']') else {
            return Err(ParseTargetError::MissingHost);
        };
        let port = suffix.strip_prefix(':').map(parse_port).transpose()?;
        (host.to_owned(), port)
    } else if let Some((host, port)) = host_port.rsplit_once(':') {
        (host.to_owned(), Some(parse_port(port)?))
    } else {
        (host_port.to_owned(), None)
    };

    if host.is_empty() {
        return Err(ParseTargetError::MissingHost);
    }

    Ok(Target {
        host,
        user,
        port,
        path,
    })
}

fn split_user(authority: &str) -> (Option<String>, &str) {
    match authority.rsplit_once('@') {
        Some((user, host)) if !user.is_empty() => (Some(user.to_owned()), host),
        _ => (None, authority),
    }
}

fn parse_port(port: &str) -> Result<u16, ParseTargetError> {
    port.parse::<u16>()
        .map_err(|_| ParseTargetError::InvalidPort(port.to_owned()))
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port.is_some() || self.host.contains(':') {
            f.write_str("ssh://")?;
            if let Some(user) = &self.user {
                write!(f, "{user}@")?;
            }
            if self.host.contains(':') {
                write!(f, "[{}]", self.host)?;
            } else {
                f.write_str(&self.host)?;
            }
            if let Some(port) = self.port {
                write!(f, ":{port}")?;
            }
            if let Some(path) = &self.path {
                if !path.starts_with('/') {
                    f.write_str("/")?;
                }
                f.write_str(path)?;
            }
            return Ok(());
        }

        if let Some(user) = &self.user {
            write!(f, "{user}@")?;
        }
        f.write_str(&self.host)?;
        if let Some(path) = &self.path {
            write!(f, ":{path}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scp_style_target() {
        let target: Target = "alice@example.com:/srv/app".parse().unwrap();
        assert_eq!(target.user.as_deref(), Some("alice"));
        assert_eq!(target.host, "example.com");
        assert_eq!(target.path.as_deref(), Some("/srv/app"));
        assert_eq!(target.port, None);
    }

    #[test]
    fn parses_uri_with_ipv6_and_port() {
        let target: Target = "ssh://alice@[2001:db8::1]:2222/srv/app".parse().unwrap();
        assert_eq!(target.user.as_deref(), Some("alice"));
        assert_eq!(target.host, "2001:db8::1");
        assert_eq!(target.port, Some(2222));
        assert_eq!(target.path.as_deref(), Some("/srv/app"));
    }

    #[test]
    fn rejects_ambiguous_ipv6() {
        assert_eq!(
            "2001:db8::1".parse::<Target>().unwrap_err(),
            ParseTargetError::AmbiguousIpv6
        );
    }

    #[test]
    fn empty_scp_path_means_remote_home() {
        let target: Target = "example.com:".parse().unwrap();
        assert_eq!(target.path, None);
    }

    #[test]
    fn display_round_trips_an_explicit_port_and_ipv6() {
        for value in [
            "ssh://alice@example.com:2222/srv/app",
            "ssh://alice@[2001:db8::1]:2222/srv/app",
        ] {
            let target: Target = value.parse().unwrap();
            assert_eq!(target.to_string().parse::<Target>().unwrap(), target);
        }
    }
}
