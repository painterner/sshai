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
                             ▲
                             │
                       sshai-tools ─── canonical schemas + dispatcher
                          ▲       ▲
                          │       │
                  sshai-mcp     sshai-ai
                  stdio MCP     local model loop
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
  └─ control channel: remote `sshai worker serve`
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

## Workspace RPC v1

The same control channel also carries local-to-agent workspace requests. Request IDs make responses unambiguous and allow the remote agent to execute independent requests concurrently:

```text
open                         canonical root + negotiated capabilities
list(path, cursor, limit)    sorted, name-based pagination
stat(path)                   lstat-style metadata for the final component
read(path, offset, length)   bounded range read, base64 payload
hash(path)                   streaming BLAKE3
exec.start(argv, cwd, env)   streaming process start
exec.input / resize          PTY input and window changes
exec.signal / cancel         process-group control
exec.output / exited         backpressured events and final status
```

Filesystem paths are relative-only. The agent normalizes components, canonicalizes the target or its parent, and verifies it remains under the canonical workspace root. This rejects absolute paths, parent traversal, and symlink escapes while still allowing `stat` to report a final symlink itself.

`exec` constrains and canonicalizes its initial working directory, validates environment names, and uses argv directly without a shell by default. Pipe mode streams distinct stdout/stderr chunks through a bounded event queue. PTY mode uses `openpty`, creates a new session and foreground process group, forwards stdin/`TERM`/window resize, and merges output with normal terminal semantics. `--shell` is explicit and requires one command string.

Every command has both a protocol process ID and an OS process group. The first Ctrl-C sends `SIGINT`; a second cancels with `SIGKILL`. Timeout, explicit cancellation, control-channel EOF, and agent shutdown target the complete process group so descendants cannot be orphaned. This remains execution isolation, not an OS sandbox: the process retains the authenticated remote user's normal permissions.

## Mutations and optimistic concurrency

Workspace RPC v3 adds atomic write, unique text edit, mkdir, rename, and remove. Mutations are serialized within one agent. A write targets a create-new temporary file in the destination directory, applies validated permissions, flushes and `fsync`s the file, rechecks the expected BLAKE3 immediately before replacement, atomically renames, and syncs the parent directory. Failed operations remove their temporary file.

Existing files require an expected BLAKE3 or an explicit overwrite flag. Text edit reads a bounded UTF-8 file, requires `old_text` to occur exactly once, derives a BLAKE3 condition from the bytes it read, and uses the same atomic write path. All mutation parents pass the same canonical root and symlink-escape validation as reads.

## MCP and Codex adapter

`sshai-tools` owns the deterministic JSON schemas, side-effect classification, argument validation, and dispatch to one authenticated `WorkspaceClient`. Both model entry points use this canonical implementation.

`sshai mcp TARGET` is a local stdio MCP server. It returns tool failures as `isError` results so the model can self-correct and keeps diagnostics off protocol stdout. Mutating and arbitrary-exec tools carry conservative destructive annotations.

`sshai codex TARGET` launches the existing local Codex executable in a temporary control directory. It injects the MCP command and arguments with process-local `-c` overrides, leaves the user's Codex home and authentication untouched, forces the empty local shell workspace read-only, and supplies both MCP server instructions and an `AGENTS.md` directing all project operations to the remote tools. No persistent Codex configuration is written.

## Built-in AI agent

`sshai agent TARGET` runs the model orchestration locally and gives it Responses API function tools derived from the same canonical definitions as MCP. Conversation input, model output items, function calls, and function outputs are retained locally for the session and sent statelessly with `store=false`; encrypted reasoning content is requested so reasoning-capable models can continue across tool calls without server-side response storage.

The API credential is read only from the local environment and is used only in the HTTPS Authorization header. The remote worker receives workspace RPC frames, never the model credential. Read-only tools run directly. Mutations and arbitrary execution pass through the CLI approval policy before dispatch. A per-turn tool-call bound prevents an erroneous model loop from executing indefinitely.
