# sshai v0.1 architecture

## Boundary

```text
sshai-cli
   │
   ▼
sshai-core ─── Target
   │
   ├──────────────► sshai-protocol ─── versioned, bounded frames
   │                         ▲
   ▼                         │
sshai-ssh ─── SSH / PTY / SFTP / local control dispatcher
                             │
                             ▼
                       sshai-agent ─── Unix socket / session shim
   │
   ▼
russh + russh-sftp + Tokio
```

Only `sshai-ssh` may expose or depend on `russh` internals. Other future crates consume the stable `SshConnector`, `SshSession`, and `SftpClient` API.

## Connection state machine

```text
Target input
  → resolve ~/.ssh/config
  → construct ProxyJump route
  → TCP connect to first hop
  → SSH key exchange
  → verify host key
  → authenticate
  → open direct-tcpip for next hop
  → nested SSH key exchange/authentication
  → return final SshSession
```

Every jump host is independently verified and authenticated. A jump host only transports encrypted SSH bytes for the next connection.

## Channel model

One authenticated `SshSession` can open concurrent channels:

```text
session channel + exec request       remote command
session channel + PTY + shell        interactive shell
session channel + SFTP subsystem     bootstrap transfer
session channel + agent stdio        built-in control protocol
direct-tcpip channel                 ProxyJump or forwarding
```

Parent sessions are retained by the final session so nested ProxyJump streams cannot be dropped early.

## Trust model

Host key policy is resolved from SSH config and may be overridden by CLI flags:

```text
Strict       unknown keys fail
Ask          unknown keys require an interactive confirmation
AcceptNew    unknown keys are persisted automatically
Insecure     verification is explicitly disabled with a warning
```

Known host key changes always fail unless the caller explicitly selects the insecure policy.

## Authentication model

Authentication is attempted in this order:

```text
SSH Agent
configured/default IdentityFile
keyboard-interactive
password
```

`IdentitiesOnly yes` skips unconstrained SSH Agent identities. Password and keyboard-interactive prompts are disabled by `--batch` or when stdin is not a terminal.

## ProxyJump

ProxyJump does not invoke an external command. It opens `direct-tcpip` on the authenticated parent and passes its channel stream to `russh::client::connect_stream`:

```text
TCP → SSH jump A → direct-tcpip → SSH jump B → direct-tcpip → SSH target
```

The resolver rejects cycles and limits nesting depth to eight.

## Session agent control plane

Interactive SSH enables the agent by default:

```text
local sshai
  ├─ SFTP: detect platform, SHA-256 verify/cache/upload same binary
  ├─ PTY channel: remote interactive shell
  └─ control channel: remote `sshai agent serve`
                           │
                           ├─ 0700 random session directory
                           ├─ 0600 Unix socket
                           ├─ session-only `bin/sshai` shim
                           └─ shell launcher (bash/zsh/fish/POSIX)
```

When a user runs `sshai copy-id` inside the remote shell, the shim sends a framed request to the Unix socket. The agent forwards it over its dedicated SSH channel; the local dispatcher performs the SFTP operation and returns stdout, stderr, and an exit code synchronously. Terminal keystrokes and screen output are never parsed.

Frames are big-endian length-prefixed JSON with a 1 MiB bound and explicit protocol version. A 256-bit random session token binds each shim to its agent. The socket and containing directory provide the local-user boundary; the token also prevents accidental cross-session routing.

EOF or an explicit shutdown frame stops the agent and removes the complete session directory. Content-addressed executable caches are retained, but are streamed through SHA-256 before execution and immediately after upload.

The protocol crate does not depend on `russh`, leaving the transport replaceable and making future file sync and AI adapters independently testable.
