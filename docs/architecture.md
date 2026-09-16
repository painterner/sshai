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
  ├─ exec: prepare a small launcher/shim
  ├─ PTY channel: open the remote interactive shell immediately
  ├─ background SFTP: adaptively compress and upload/cache sshai-worker
  ├─ background exec: verify the worker with the remote SHA-256 utility
  └─ control channel: remote `sshai-worker serve` adopts the prepared session
                           │
                           ├─ 0700 random session directory
                           ├─ 0600 Unix socket
                           ├─ session-only `bin/sshai` shim
                           └─ shell launcher (bash/zsh/fish/POSIX)
```

When a user runs `sshai copy-id` inside the remote shell, the shim sends a framed request to the Unix socket. The agent forwards it over its dedicated SSH channel; the local dispatcher performs the SFTP operation and returns stdout, stderr, and an exit code synchronously. `sshai --agent codex` and `sshai --agent claude` use the same control path, include the primary remote current working directory, temporarily restore the local terminal, and let the selected local AI CLI inherit it. The local directory from which the outer `sshai` session started remains the local read-write workspace. When the child exits, the client restores raw mode and resumes the existing remote shell. Terminal keystrokes and screen output are never parsed.

An interactive target list such as `sshai build,test,prod` connects and opens the first target's PTY synchronously, then starts all secondary SSH connections in the background without delaying first-host input. Background authentication is deliberately non-interactive so password, key-passphrase, keyboard-interactive, and unknown-host prompts cannot steal the raw terminal; SSH Agent/public-key authentication and pre-established host trust continue normally. Each successful target owns an independent PTY, progressive worker, cwd, and foreground process. `Ctrl+Shift+Left/Right` byte sequences switch the input/output focus among live PTYs. Inactive output is retained in a bounded per-host replay buffer rather than mixed into the visible terminal, and terminal resize events are broadcast to every live PTY.

The AI adapters retain the complete ordered target list and inject one independently named MCP server per remote host. When an Agent is launched from a secondary PTY, that target is promoted to primary and receives the PTY's current cwd; all other targets remain available as named MCP remotes.

The session command dispatcher invokes a local AI CLI only for the explicit `sshai --agent NAME` form. Bare words retain SSH-host semantics and can never be reclassified by executable discovery. Codex, Claude, Gemini, and OpenCode have built-in ephemeral adapters. Other executables are probed with `--help`; sshai launches them only when they advertise MCP support, passing a temporary `mcpServers` document through a recognized `--mcp-config` flag or the generic `MCP_CONFIG_PATH`/`SSHAI_*` environment contract. Names with path separators and commands without MCP evidence are rejected, preventing the entry point from becoming an unrestricted remote-to-local process launcher.

Interactive sessions use progressive bootstrap. The launcher and a socket-waiting shim are prepared before PTY startup, but worker cache validation, upload, decompression, verification, and startup continue as a lower-priority future after the shell is visible. PTY input/output branches are biased ahead of bootstrap polling. An early shim invocation waits for the socket; a bootstrap failure writes an error marker and leaves the shell usable. Shell exit cancels unfinished work and removes session-scoped temporary paths.

Frames are big-endian length-prefixed JSON with a 1 MiB bound and explicit protocol version. A 256-bit random session token binds each shim to its agent. The socket and containing directory provide the local-user boundary; the token also prevents accidental cross-session routing.

EOF or an explicit shutdown frame stops the agent and removes the complete session directory. Content-addressed worker caches are retained and verified before execution and immediately after upload. Hashing runs on the remote host and returns only the digest; hosts without `sha256sum` or `shasum` fall back to SFTP streaming. On a cache miss, one remote probe discovers `zstd`, `gzip`, and `xz`; the client uses the first low-latency format available on both sides, uploads a session-unique temporary archive, remotely decompresses it to a temporary worker, atomically replaces the cache entry, and verifies the raw digest. Every optional compression failure falls back to a raw upload.

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

Workspace RPC v4 adds atomic write, unique text edit, mkdir, rename, remove, streaming execution, and the remote working directory on session commands. Mutations are serialized within one agent. A write targets a create-new temporary file in the destination directory, applies validated permissions, flushes and `fsync`s the file, rechecks the expected BLAKE3 immediately before replacement, atomically renames, and syncs the parent directory. Failed operations remove their temporary file.

Existing files require an expected BLAKE3 or an explicit overwrite flag. Text edit reads a bounded UTF-8 file, requires `old_text` to occur exactly once, derives a BLAKE3 condition from the bytes it read, and uses the same atomic write path. All mutation parents pass the same canonical root and symlink-escape validation as reads.

## MCP and Codex adapter

`sshai-tools` owns the deterministic JSON schemas, side-effect classification, argument validation, and dispatch to one authenticated `WorkspaceClient`. Both model entry points use this canonical implementation.

`sshai mcp TARGET` is a local stdio MCP server. It returns tool failures as `isError` results so the model can self-correct and keeps diagnostics off protocol stdout. Mutating and arbitrary-exec tools carry conservative destructive annotations. It also owns an SFTP channel for `workspace_transfer`, which streams files and recursively walks directories without routing bytes through model context. Local paths remain bounded by the selected local root; remote transfer paths may be workspace-relative or explicit absolute paths under the authenticated SSH user's normal permissions. The same recursive engine backs `sshai sftp get/put --recursive`, including repeatable exclusions, overwrite policy, permission preservation for regular files, symlink/special-file rejection, and a bounded directory walk.

The MCP server runs one connection-manager task per target rather than treating its first `SshSession`, workspace worker, and SFTP channel as permanent. The manager probes an idle connection every 15 seconds, invalidates a failed generation, and rebuilds all three indefinitely with jittered exponential backoff capped at 30 seconds. All remote tool calls pass through its bounded channel and serialized queue, so reconnection is single-flight. Calls can wait up to 45 seconds for recovery without blocking local `workspace_connection_info` requests or other JSON-RPC responses.

Read-only workspace calls interrupted by transport loss remain queued and are replayed on a new generation. Mutations, execution, and transfers are never replayed automatically because a lost response cannot prove the remote side did not commit; they return an explicit uncertain-completion error while reconnection proceeds in the background. The local status tool exposes phase, generation, total reconnect count, queue depth, heartbeat timestamp, retry deadline, and the last error even while the remote is unavailable.

`sshai --agent codex TARGET[,TARGET...]` launches the existing local Codex executable in the selected local project directory with the `workspace-write` sandbox. It injects one process-local MCP configuration per named remote plus `developer_instructions` defining unqualified/native tools as local and each MCP namespace as remote. `sshai --agent claude` applies the same model with native local tools, strict session-only MCP configuration, and an appended system prompt. Neither adapter writes persistent AI CLI configuration or changes local authentication. `workspace_info` reports remote OS, architecture, family, and shell so the model can account for cross-platform differences.

Codex keeps the server default at `writes`, but applies the documented per-tool `approve` override to the non-overwriting `workspace_transfer`. The separate `workspace_transfer_overwrite` remains destructive and approval-gated. This lets an explicit user upload request proceed without a redundant auto-review while preserving review for replacement and other remote mutations.

## Built-in AI agent

`sshai agent TARGET` runs the model orchestration locally and gives it Responses API function tools derived from the same canonical definitions as MCP. Conversation input, model output items, function calls, and function outputs are retained locally for the session and sent statelessly with `store=false`; encrypted reasoning content is requested so reasoning-capable models can continue across tool calls without server-side response storage.

The API credential is read only from the local environment and is used only in the HTTPS Authorization header. The remote worker receives workspace RPC frames, never the model credential. Read-only tools run directly. Mutations and arbitrary execution pass through the CLI approval policy before dispatch. A per-turn tool-call bound prevents an erroneous model loop from executing indefinitely.
