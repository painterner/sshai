use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use sshai_core::Target;

use crate::{Result, SshError};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HostKeyPolicy {
    Strict,
    AcceptNew,
    #[default]
    Ask,
    Insecure,
}

#[derive(Clone, Debug)]
pub struct ResolvedTarget {
    pub alias: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub path: Option<String>,
    pub identity_files: Vec<PathBuf>,
    pub identity_agent: Option<PathBuf>,
    pub identities_only: bool,
    pub proxy_jump: Vec<Target>,
    pub known_hosts_files: Vec<PathBuf>,
    pub host_key_policy: HostKeyPolicy,
    pub connect_timeout: Duration,
    pub keepalive_interval: Option<Duration>,
    pub keepalive_max: usize,
}

#[derive(Clone, Debug, Default)]
pub struct SshConfig {
    blocks: Vec<HostBlock>,
    source: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct HostBlock {
    patterns: Vec<String>,
    options: Vec<(String, String)>,
}

impl SshConfig {
    pub fn load_default() -> Result<Self> {
        let Some(home) = dirs::home_dir() else {
            return Ok(Self::default());
        };
        let path = home.join(".ssh/config");
        if !path.exists() {
            return Ok(Self::default());
        }
        Self::load(path)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|error| {
            SshError::Config(format!("cannot read {}: {error}", path.display()))
        })?;
        let mut config = Self {
            blocks: vec![HostBlock {
                patterns: vec!["*".to_owned()],
                options: Vec::new(),
            }],
            source: Some(path.to_owned()),
        };

        for (index, raw_line) in content.lines().enumerate() {
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = split_option(line) else {
                return Err(SshError::Config(format!(
                    "{}:{}: expected an option and a value",
                    path.display(),
                    index + 1
                )));
            };
            if key.eq_ignore_ascii_case("host") {
                let patterns = split_words(value);
                if patterns.is_empty() {
                    return Err(SshError::Config(format!(
                        "{}:{}: Host requires a pattern",
                        path.display(),
                        index + 1
                    )));
                }
                config.blocks.push(HostBlock {
                    patterns,
                    options: Vec::new(),
                });
            } else if key.eq_ignore_ascii_case("match") {
                return Err(SshError::Config(format!(
                    "{}:{}: Match blocks are not supported in v0.1; refusing to ignore them",
                    path.display(),
                    index + 1
                )));
            } else if key.eq_ignore_ascii_case("include") {
                return Err(SshError::Config(format!(
                    "{}:{}: Include is not supported in v0.1; pass -F with a flattened config",
                    path.display(),
                    index + 1
                )));
            } else {
                config
                    .blocks
                    .last_mut()
                    .expect("the global block always exists")
                    .options
                    .push((key.to_ascii_lowercase(), unquote(value)));
            }
        }

        Ok(config)
    }

    pub fn resolve(&self, target: &Target) -> Result<ResolvedTarget> {
        self.resolve_with_stack(target, &mut Vec::new())
    }

    fn resolve_with_stack(
        &self,
        target: &Target,
        stack: &mut Vec<String>,
    ) -> Result<ResolvedTarget> {
        if stack.len() >= 8 {
            return Err(SshError::Config(
                "ProxyJump depth exceeds the limit of 8".to_owned(),
            ));
        }
        if stack.contains(&target.host) {
            return Err(SshError::Config(format!(
                "ProxyJump cycle detected at {}",
                target.host
            )));
        }
        stack.push(target.host.clone());

        let options = self.options_for(&target.host);
        if let Some(command) = options.get("proxycommand") {
            return Err(SshError::Config(format!(
                "ProxyCommand {command:?} is not supported by the pure-Rust transport; use ProxyJump"
            )));
        }
        let host = options
            .get("hostname")
            .map(|host| host.replace("%h", &target.host))
            .unwrap_or_else(|| target.host.clone());
        let port = match (target.port, options.get("port")) {
            (Some(port), _) => port,
            (None, Some(value)) => parse_number("Port", value)?,
            (None, None) => 22,
        };
        let user = target
            .user
            .clone()
            .or_else(|| options.get("user").cloned())
            .unwrap_or_else(default_user);

        let identity_files = collect_values(&self.blocks, &target.host, "identityfile")
            .into_iter()
            .map(|path| expand_path(&path, &host, &user))
            .collect::<Vec<_>>();
        let identity_files = if identity_files.is_empty() {
            default_identity_files()
        } else {
            identity_files
        };

        let identity_agent = options
            .get("identityagent")
            .filter(|value| !value.eq_ignore_ascii_case("none"))
            .map(|path| expand_path(path, &host, &user));

        let proxy_jump = options
            .get("proxyjump")
            .filter(|value| !value.eq_ignore_ascii_case("none"))
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(parse_jump_target)
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();

        for jump in &proxy_jump {
            self.resolve_with_stack(jump, stack)?;
        }
        stack.pop();

        let known_hosts_files = collect_values(&self.blocks, &target.host, "userknownhostsfile")
            .into_iter()
            .flat_map(|value| split_words(&value))
            .filter(|value| !value.eq_ignore_ascii_case("none"))
            .map(|path| expand_path(&path, &host, &user))
            .collect::<Vec<_>>();
        let known_hosts_files = if known_hosts_files.is_empty() {
            let mut files = dirs::home_dir()
                .map(|home| vec![home.join(".ssh/known_hosts")])
                .unwrap_or_default();
            let global = PathBuf::from("/etc/ssh/ssh_known_hosts");
            if global.is_file() {
                files.push(global);
            }
            files
        } else {
            known_hosts_files
        };

        Ok(ResolvedTarget {
            alias: target.host.clone(),
            host,
            port,
            user,
            path: target.path.clone(),
            identity_files,
            identity_agent,
            identities_only: match options.get("identitiesonly") {
                Some(value) => parse_bool("IdentitiesOnly", value)?,
                None => false,
            },
            proxy_jump,
            known_hosts_files,
            host_key_policy: parse_host_key_policy(options.get("stricthostkeychecking"))?,
            connect_timeout: Duration::from_secs(match options.get("connecttimeout") {
                Some(value) => parse_number("ConnectTimeout", value)?,
                None => 30,
            }),
            keepalive_interval: match options.get("serveraliveinterval") {
                Some(value) => {
                    let seconds = parse_number("ServerAliveInterval", value)?;
                    (seconds > 0).then(|| Duration::from_secs(seconds))
                }
                None => None,
            },
            keepalive_max: match options.get("serveralivecountmax") {
                Some(value) => parse_number("ServerAliveCountMax", value)?,
                None => 3,
            },
        })
    }

    pub fn source(&self) -> Option<&Path> {
        self.source.as_deref()
    }

    fn options_for(&self, alias: &str) -> HashMap<String, String> {
        let mut result = HashMap::new();
        for block in &self.blocks {
            if host_block_matches(&block.patterns, alias) {
                for (key, value) in &block.options {
                    result.entry(key.clone()).or_insert_with(|| value.clone());
                }
            }
        }
        result
    }
}

fn collect_values(blocks: &[HostBlock], alias: &str, requested: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut values = Vec::new();
    for block in blocks {
        if !host_block_matches(&block.patterns, alias) {
            continue;
        }
        for (key, value) in &block.options {
            if key == requested && seen.insert(value.clone()) {
                values.push(value.clone());
            }
        }
    }
    values
}

fn parse_jump_target(value: &str) -> Result<Target> {
    if value.starts_with("ssh://") {
        return value
            .parse()
            .map_err(|error| SshError::Config(format!("invalid ProxyJump {value:?}: {error}")));
    }
    let (authority, port) = match value.rsplit_once(':') {
        Some((authority, port)) if !authority.contains(':') => {
            let port = port
                .parse::<u16>()
                .map_err(|_| SshError::Config(format!("invalid port in ProxyJump {value:?}")))?;
            (authority, Some(port))
        }
        _ => (value, None),
    };
    let (user, host) = match authority.rsplit_once('@') {
        Some((user, host)) => (Some(user.to_owned()), host),
        None => (None, authority),
    };
    if host.is_empty() {
        return Err(SshError::Config(format!(
            "invalid ProxyJump target {value:?}"
        )));
    }
    Ok(Target {
        host: host.to_owned(),
        user,
        port,
        path: None,
    })
}

fn split_option(line: &str) -> Option<(&str, &str)> {
    if let Some((key, value)) = line.split_once('=') {
        let key = key.trim();
        let value = value.trim();
        if !key.is_empty() && !value.is_empty() {
            return Some((key, value));
        }
    }
    let split = line.find(char::is_whitespace)?;
    let (key, value) = line.split_at(split);
    let value = value.trim();
    (!key.is_empty() && !value.is_empty()).then_some((key, value))
}

fn strip_comment(line: &str) -> &str {
    let mut single = false;
    let mut double = false;
    for (index, character) in line.char_indices() {
        match character {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '#' if !single && !double => return &line[..index],
            _ => {}
        }
    }
    line
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value[1..value.len() - 1].to_owned()
    } else {
        value.to_owned()
    }
}

fn split_words(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .map(unquote)
        .filter(|word| !word.is_empty())
        .collect()
}

fn host_block_matches(patterns: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let mut positive = false;
    for raw in patterns {
        let (negated, pattern) = raw
            .strip_prefix('!')
            .map_or((false, raw.as_str()), |pattern| (true, pattern));
        if wildcard_match(&pattern.to_ascii_lowercase(), &host) {
            if negated {
                return false;
            }
            positive = true;
        }
    }
    positive
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;
    for token in pattern {
        let mut current = vec![false; value.len() + 1];
        if *token == b'*' {
            current[0] = previous[0];
        }
        for index in 1..=value.len() {
            current[index] = match *token {
                b'*' => previous[index] || current[index - 1],
                b'?' => previous[index - 1],
                byte => previous[index - 1] && byte == value[index - 1],
            };
        }
        previous = current;
    }
    previous[value.len()]
}

fn expand_path(value: &str, host: &str, user: &str) -> PathBuf {
    let home = dirs::home_dir().unwrap_or_default();
    let mut expanded = value
        .replace("%h", host)
        .replace("%r", user)
        .replace("%d", &home.to_string_lossy());
    if expanded == "~" {
        return home;
    }
    if let Some(rest) = expanded.strip_prefix("~/") {
        return home.join(rest);
    }
    if expanded == "SSH_AUTH_SOCK" {
        expanded = env::var("SSH_AUTH_SOCK").unwrap_or_default();
    } else if expanded.contains("${SSH_AUTH_SOCK}") {
        expanded = expanded.replace(
            "${SSH_AUTH_SOCK}",
            &env::var("SSH_AUTH_SOCK").unwrap_or_default(),
        );
    }
    PathBuf::from(expanded)
}

fn default_identity_files() -> Vec<PathBuf> {
    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };
    ["id_ed25519", "id_ecdsa", "id_rsa"]
        .into_iter()
        .map(|name| home.join(".ssh").join(name))
        .filter(|path| path.is_file())
        .collect()
}

fn default_user() -> String {
    env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_owned())
}

fn parse_host_key_policy(value: Option<&String>) -> Result<HostKeyPolicy> {
    match value.map(|value| value.to_ascii_lowercase()) {
        None => Ok(HostKeyPolicy::Ask),
        Some(value) if matches!(value.as_str(), "yes" | "true") => Ok(HostKeyPolicy::Strict),
        Some(value) if value == "accept-new" => Ok(HostKeyPolicy::AcceptNew),
        Some(value) if value == "ask" => Ok(HostKeyPolicy::Ask),
        Some(value) if matches!(value.as_str(), "no" | "false" | "off") => {
            Ok(HostKeyPolicy::Insecure)
        }
        Some(value) => Err(SshError::Config(format!(
            "unsupported StrictHostKeyChecking value {value:?}"
        ))),
    }
}

fn parse_bool(name: &str, value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" => Ok(true),
        "no" | "false" | "off" => Ok(false),
        _ => Err(SshError::Config(format!("invalid {name} value {value:?}"))),
    }
}

fn parse_number<T>(name: &str, value: &str) -> Result<T>
where
    T: std::str::FromStr,
{
    value
        .parse()
        .map_err(|_| SshError::Config(format!("invalid {name} value {value:?}")))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn matches_wildcards_and_negation() {
        assert!(host_block_matches(
            &["*.example.com".into(), "!blocked.example.com".into()],
            "api.example.com"
        ));
        assert!(!host_block_matches(
            &["*.example.com".into(), "!blocked.example.com".into()],
            "blocked.example.com"
        ));
    }

    #[test]
    fn resolves_first_value_like_openssh() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            "Host prod\n  HostName server.example.com\n  User deploy\n  Port 2222\nHost *\n  User fallback\n  ServerAliveInterval 15"
        )
        .unwrap();
        let config = SshConfig::load(file.path()).unwrap();
        let target: Target = "prod".parse().unwrap();
        let resolved = config.resolve(&target).unwrap();
        assert_eq!(resolved.host, "server.example.com");
        assert_eq!(resolved.user, "deploy");
        assert_eq!(resolved.port, 2222);
        assert_eq!(resolved.keepalive_interval, Some(Duration::from_secs(15)));
    }

    #[test]
    fn detects_proxy_jump_cycle() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "Host a\n  ProxyJump b\nHost b\n  ProxyJump a").unwrap();
        let config = SshConfig::load(file.path()).unwrap();
        let target: Target = "a".parse().unwrap();
        assert!(config.resolve(&target).is_err());
    }

    #[test]
    fn rejects_invalid_numeric_options() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "Host bad\n  Port definitely-not-a-port").unwrap();
        let config = SshConfig::load(file.path()).unwrap();
        let target: Target = "bad".parse().unwrap();
        assert!(config.resolve(&target).is_err());
    }
}
