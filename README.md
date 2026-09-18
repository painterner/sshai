# sshai

`sshai` is a remote workspace tool for locally installed AI CLIs. Authentication and the AI CLI stay on your local machine, while source code and execution remain on the remote host.

The current `v0.1` release provides a pure-Rust SSH foundation without invoking the system `ssh`, `scp`, or `sftp` commands:

- SSH2 connections and multi-channel sessions based on `russh`
- Common `~/.ssh/config` options
- Strict `known_hosts` verification, interactive confirmation, and `accept-new`
- SSH agent, private-key, keyboard-interactive, and password authentication
- Native single-hop and multi-hop ProxyJump support
- Remote command execution with separately streamed stdout and stderr
- Interactive PTYs, raw terminal mode, window resizing, and signal forwarding
- Secure uploads and downloads based on `russh-sftp`
- Pure-Rust `copy-id` with idempotent remote `authorized_keys` updates
- A session-isolated remote agent, Unix socket, and `sshai` shim enabled by default
- A dedicated SSH control channel through which remote session commands can invoke local capabilities synchronously
- A local stdio MCP server that exposes remote workspaces to AI CLIs
- Automatic MCP SSH reconnection, with safe retries for read-only calls and no replay of writes with uncertain outcomes
- One-time MCP injection for `sshai --agent codex TARGET`, without moving local Codex credentials
- One-time MCP injection for `sshai --agent claude TARGET`, without moving local Claude credentials
- A built-in `sshai agent` model loop that shares the MCP remote tools and approval boundaries
- Configuration and connection diagnostics through `doctor`

## Build

```bash
cargo build --workspace --release
```

The local CLI and lightweight remote worker are produced at:

```text
target/release/sshai
target/release/sshai-worker
```

The installation script is recommended. On Linux, it also builds a fully static `sshai-worker-static`, which avoids glibc compatibility problems between the local system and older remote hosts:

```bash
./scripts/install.sh --with-termm
```

Omit `--with-termm` to install only the CLI and worker. A regular `cargo install --locked --path crates/sshai-cli --force` also works, but its dynamically linked worker requires a remote Linux system with a glibc version at least as new as the build machine. At runtime, sshai prefers a static worker found next to the CLI. Ensure that `~/.cargo/bin` is in `PATH`, then verify the installation with `sshai --version`.

`termm` is a separate subproject and binary that provides native sshai tabs, click-to-create sessions, horizontal and vertical splits, and broker-owned PTYs:

```bash
termm
termm build-server,test-server --cwd ~/projects/app
```

`termm` opens a Tauri desktop window directly. It does not launch Chrome, listen on a local HTTP port, or create a browser profile. The frontend communicates with the Rust PTY broker over Tauri IPC. New tabs and splits inherit the startup targets, local working directory, and sshai configuration. If a remote sshai transport exits unexpectedly, it is restarted in the same pane. See [`termm/README.md`](termm/README.md) for details.

## Usage

Open a remote shell:

```bash
sshai dev-server
sshai user@example.com:2222
sshai ssh://user@example.com:2222/srv/project
sshai build-server,test-server,prod-server
```

Bare targets may use `host`, `user@host`, `host:port`, or `user@host:port`. Text after the colon is always interpreted as an SSH port; the SCP-style `host:/path` form is not supported. To select an initial remote workspace, use `ssh://user@host:port/path`.

With multiple hosts, sshai connects to the first host and opens its shell immediately without waiting for the others. On initial entry, it appends a one-line shortcut hint without clearing the terminal or its scrollback. Virtual-screen rendering takes over only after the first host switch. The remaining hosts connect in parallel in the background, including PTY and worker startup.

Press `Shift+Left` or `Shift+Right` once to cycle through connected hosts. The older `Ctrl+Shift+Left` and `Ctrl+Shift+Right` shortcuts are still recognized, although Terminator uses them for pane resizing by default. As a fallback, press `Ctrl+]`, followed by `Left`, `Right`, `h`, or `l`. Pressing `Ctrl+]` twice sends a literal `Ctrl+]` to the remote host. Traditional terminals cannot reliably distinguish `Ctrl+Shift+[` or `Ctrl+Shift+]` from ordinary `Esc` or `Ctrl+]`, nor `Ctrl+Shift+J/L` from newline or clear-screen control characters, so sshai does not reserve those combinations.

Each host retains its own shell, current directory, foreground process, and VT100 screen state. Switching restores only that host's visible screen; it does not clear shared scrollback, replay old output, or continuously add scrollback lines. Running `exit` normally on the active host closes every host and returns to the local shell once. An unexpected disconnect without an exit status leaves the other live hosts available.

At session startup, sshai lists the local workspace and every target with its working directory, operating system, CPU architecture, and memory. A target still connecting in the background is marked `connecting`. Run `sshai hosts` or its alias `sshai info` at any time to see the latest state, including connected, failed, and closed targets:

```text
sshai connections
  1. local: /home/ka (Ubuntu 24.04 LTS, x86_64, 4 GiB)
  2. build: /root/test (Ubuntu 22.04 LTS, x86_64, 2 GiB)
  3. test: connecting
```

Background connections never prompt for passwords, private-key passphrases, keyboard-interactive responses, or unknown-host confirmation because doing so would take input away from the first shell. Configure an SSH agent, public-key authentication, and `known_hosts` in advance. A failed background host does not affect other hosts; if no alternative host is available when you switch, sshai displays the pending and failed states.

By default, an interactive shell performs the following startup sequence:

1. Detect the remote OS and CPU, then create a session launcher and shim of only a few KiB.
2. Open the PTY and remote shell immediately.
3. On a separate SSH channel, validate the lightweight `sshai-worker`. If it is not cached, detect `zstd`, `gzip`, and `xz`, then upload it over SFTP using the best available compression.
4. After the worker is ready, create a `0600` Unix socket. The shim is already available through the injected `PATH`.
5. When the shell exits or the SSH control channel closes, cancel any active bootstrap and remove the session directory and token-bearing temporary uploads.

Terminal input and output take priority over background bootstrap work. If you run a session command such as `sshai info` or `sshai --agent codex` before the worker is ready, the shim reports `worker is initializing` and waits for the socket. An upload, decompression, or worker startup failure disables session commands but does not close the already-open remote shell.

After login, local capabilities are available without leaving the remote shell:

```bash
sshai info
sshai help
sshai --agent codex
sshai --agent claude
sshai --agent gemini
sshai --agent opencode
sshai --agent kimi
sshai copy-id
sshai copy-id -i '~/.ssh/id_ed25519.pub'
```

In a normal worker-enabled session, common commands have a shorter smart form. Typing `codex`, `claude`, `gemini`, `opencode`, or `kimi` invokes the corresponding local AI CLI. Typing `code remote.txt` opens the remote file in local editing mode. These commands are wrapped only inside sshai's private session `PATH`; they do not modify the remote system. Press `Ctrl+\` to toggle passthrough mode, where the same names resolve to real remote executables. Press it again to restore smart mode.

Running `sshai --file PROGRAM REMOTE_FILE` opens a remote file in a program on the current local machine and enters file-editing mode. The file is downloaded through the existing authenticated SSH/SFTP transport to a temporary local file. sshai checks for changes every 500 ms and uploads them automatically. Press `Ctrl+Q` to leave editing mode. If another process changes the remote file during editing, sshai stops synchronization and refuses to overwrite it. This mode is intended for GUI viewers and editors such as `code`; terminal editors require exclusive terminal ownership and are not recommended alongside the remote shell.

Running `sshai --agent codex` or `sshai --agent claude` inside a session temporarily hands the terminal to the corresponding local AI CLI. The directory from which local sshai was launched becomes the writable local workspace, and the remote shell's current directory becomes the primary remote workspace. Exiting the AI CLI returns to the remote shell. The agent's MCP workspace reuses the current authenticated SSH transport through a token-protected local loopback bridge and opens new worker/SFTP channels without logging in again. Use `sshai --agent codex --local-dir '/another/local/directory'` to override the local directory. Quote the path so the remote shell does not expand it first.

Comma-separated targets create one local plus multiple remote AI workspaces. The interactive shell starts on the first target immediately, and the remaining targets become switchable as they connect. Running `sshai --agent NAME` on any host makes that host the primary remote workspace and exposes every target as a separately named MCP workspace:

```bash
cd ~/projects/control-plane
sshai build-server,test-server,prod-server

# Run this in any host shell; all three remotes remain independently accessible.
sshai --agent codex
```

The `-i` option refers to a local file. Quote `~` as shown earlier so the remote shell does not expand it. Requests travel over a separate encrypted SSH channel; sshai does not parse or match terminal input text. For a single host that cannot run the worker, use `sshai --no-worker HOST`. The older `--no-agent` name remains as a compatibility alias.

Use `-v` on a slow connection to display millisecond timings for TCP connection setup, the SSH handshake, authentication, SFTP cache validation, and remote worker startup. `-vv` also enables debug logging from the underlying SSH library:

```bash
sshai dev-server -v
sshai dev-server -vv
```

If you need only a conventional remote shell, use `--no-worker` to skip platform detection, SFTP validation, and worker startup. Connection latency will then be closer to the system `ssh` client:

```bash
sshai --no-worker dev-server
```

Inspect a remote workspace through Workspace RPC:

```bash
sshai workspace ssh://dev-server/srv/project open
sshai workspace ssh://dev-server/srv/project list . --limit 200
sshai workspace ssh://dev-server/srv/project stat Cargo.toml
sshai workspace ssh://dev-server/srv/project read README.md
sshai workspace ssh://dev-server/srv/project hash Cargo.lock
sshai workspace ssh://dev-server/srv/project exec -- cargo test
sshai workspace ssh://dev-server/srv/project exec --cwd crates/core --env RUST_LOG=debug -- cargo test
sshai workspace ssh://dev-server/srv/project exec --pty -- ls --color=auto -C
sshai workspace ssh://dev-server/srv/project exec --pty --shell -- 'ls'
```

`list`, `stat`, `read`, and `hash` accept only relative paths within the workspace root. Absolute paths, `..`, and symbolic links that resolve outside the root are rejected. `list` uses stable name-cursor pagination, and each `read` call returns at most 512 KiB.

Workspace `exec` launches an argv vector directly by default, without a shell, and streams independent stdout and stderr events. This behavior is suitable for AI clients and scripts. `--pty` allocates a remote pseudo-terminal and forwards stdin, `TERM`, window dimensions, resize events, and terminal signals. It is suitable for color output, column layouts, and interactive programs; stdout and stderr are combined according to terminal semantics. `--shell` accepts one complete command string and runs it through the remote login shell, explicitly enabling aliases, pipelines, and redirection. The execution directory must be inside the workspace, but the process retains the permissions of the remote SSH user. Commands time out after 300 seconds, and an SSH or agent disconnect terminates the entire remote process group.

## Local AI access to local and remote workspaces

Start an already authenticated local Codex CLI:

```bash
sshai --agent codex ssh://dev-server/srv/project
sshai --agent codex ssh://dev-server/srv/project -- "Fix the tests and run cargo test remotely"
sshai --agent codex ssh://dev-server/srv/project -- exec "Review error handling in this project"
sshai --agent codex --local-dir ~/projects/app ssh://build-server/src,ssh://test-server/srv/app
```

`sshai --agent codex` neither copies nor modifies Codex credentials and does not persist changes to `~/.codex/config.toml`. Codex runs with a `workspace-write` sandbox in the local workspace. Its normal file, editing, and shell tools operate locally, while host-named `sshai_*` MCP tools operate on the corresponding remote workspace. sshai displays every workspace and location at startup to disambiguate identical paths.

An already authenticated local Claude Code installation can use the same remote tools:

```bash
sshai --agent claude ssh://dev-server/srv/project
sshai --agent claude ssh://dev-server/srv/project -- "Review and fix the tests"
sshai --agent claude --local-dir ~/projects/app build-server,test-server
```

`sshai --agent claude` preserves Claude's local file and command tools in the local workspace, then injects named remote workspaces through a strict, session-only `--mcp-config`. It does not persist changes to Claude's MCP configuration.

Both the local form `sshai --agent AGENT TARGET[,TARGET...] [-- ARGUMENTS...]` and the remote-session form `sshai --agent AGENT [-- ARGUMENTS...]` resolve the agent name from the local `PATH`. A bare positional argument is always an SSH target, so `sshai codex` connects to a host named `codex`; it does not start the Codex CLI.

- `codex`, `claude`, `gemini`, and `opencode` use built-in session adapters.
- Gemini receives MCP configuration through a temporary `GEMINI_CLI_SYSTEM_SETTINGS_PATH` and receives the dual-workspace instructions through its interactive prompt.
- OpenCode receives MCP configuration through a temporary `OPENCODE_CONFIG_CONTENT` value and an instruction file.
- Other names are probed with `--help` for `--mcp-config`, prompt, and MCP support.
- If `--mcp-config` is recognized, sshai passes a temporary standard MCP JSON file directly.
- Otherwise, sshai provides the generic `MCP_CONFIG_PATH`, `SSHAI_MCP_CONFIG_PATH`, `SSHAI_INSTRUCTIONS_PATH`, `SSHAI_LOCAL_ROOT`, and `SSHAI_REMOTE_TARGETS` environment variables.
- Names that declare no MCP support or contain path separators are rejected.

The generic environment convention cannot guarantee that every third-party CLI will read the configuration automatically. A client without `--mcp-config` must support `MCP_CONFIG_PATH` itself or receive a small built-in adapter in a future release. The process never writes persistent project or agent configuration.

Other compatible clients can connect to the MCP server directly:

```bash
sshai mcp ssh://dev-server/srv/project --local-dir ~/projects/app
```

The MCP server provides `workspace_info`, `workspace_list`, `workspace_stat`, `workspace_read`, `workspace_hash`, `workspace_write`, `workspace_edit`, `workspace_mkdir`, `workspace_rename`, `workspace_remove`, `workspace_exec`, and `workspace_transfer`. `workspace_info` also reports the remote OS, CPU architecture, and shell. `workspace_transfer` moves files or directories directly between the local workspace and that remote host over SFTP without placing file contents in model context. Local paths must remain under the local workspace root. Remote paths may be relative to the remote workspace or explicitly absolute, such as `/tmp/example`. Symbolic links and special files are rejected, and directory copies require `recursive=true`.

The normal `workspace_transfer` operation never overwrites an existing destination and is pre-approved for the active sshai session in Codex, preventing a duplicate approval prompt after the user has explicitly requested an upload. Only `workspace_transfer_overwrite` may replace files. It remains classified as a write operation and its prompt requires explicit overwrite authorization from the user.

An AI client can transfer between two remote hosts through an explicit temporary path in the local workspace. Transfers support `exclude` filters for names or relative subtrees and are limited to 100,000 filesystem entries per operation. Writes use a temporary file in the destination directory, `fsync`, and an atomic rename. Edits automatically use the BLAKE3 hash of the content that was read as an optimistic concurrency condition.

The stdio MCP server reserves stdin and stdout for JSON-RPC and cannot use them for SSH password prompts. Run `sshai copy-id HOST` first to configure public-key authentication.

Every 15 seconds, the MCP server sends a workspace heartbeat over idle connections. If the SSH transport, worker, or SFTP channel disconnects, it rebuilds the complete connection in place, so local agents such as Codex, Claude, and Gemini do not need to exit. Reconnection continues indefinitely with exponential backoff from 250 ms to 30 seconds and ±25% random jitter. Each target has one connection manager. Calls received during reconnection enter the same serialized queue and wait for up to 45 seconds; after a call times out, reconnection continues in the background.

If `workspace_info`, `workspace_list`, `workspace_stat`, `workspace_read`, or `workspace_hash` is interrupted in transit, it remains queued and is retried safely on the new connection. Writes, edits, removals, command execution, and file transfers may already have taken effect before the disconnect, so sshai does not replay them automatically; it asks the agent to inspect remote state first. `workspace_connection_info` does not depend on the remote host and remains available offline. It reports the connection phase, generation, reconnect count, queue depth, heartbeat, next retry time, and latest error. All diagnostics go to stderr and never contaminate MCP JSON-RPC output.

The design for natively resumable terminals is documented in [`docs/terminal.md`](docs/terminal.md). The frontend manages tabs, click-to-create sessions, and splits, while the remote `sshai-worker` owns persistent PTYs, output sequence numbers, and reattachment after disconnects. This provides the core persistence of tmux without requiring users to learn tmux commands.

Run sshai's built-in agent:

```bash
export OPENAI_API_KEY=...

# Interactive session
sshai agent ssh://dev-server/srv/project

# One-shot task
sshai agent ssh://dev-server/srv/project -- "Fix the failing tests and verify the result"

# Automatically approve remote commands and changes on a controlled development host
sshai agent ssh://dev-server/srv/project --approval auto -- "Run the tests and fix any failures"
```

The built-in agent calls the Responses API locally. Model credentials never enter the SSH transport or remote host. The default model is `gpt-5.4-mini`; change it with `--model` or `OPENAI_MODEL`. The default API endpoint is `https://api.openai.com/v1`. Compatible services may be selected with `--api-base` or `OPENAI_BASE_URL`; non-loopback endpoints must use HTTPS.

Approval policies include:

- `ask` (default): reads run automatically; writes, removals, and commands require confirmation.
- `auto`: all remote tools are approved automatically.
- `read-only`: all writes and command execution are denied.

Interactive mode supports `/clear` to reset model context and `/exit` to end the session. MCP and the built-in agent use the same tool schema and dispatcher from `sshai-tools`, preventing behavioral differences between entry points. Model text and remote command output are currently returned as complete responses; incremental rendering is planned for a future release.

Run a command in a remote workspace:

```bash
sshai exec ssh://dev-server/srv/project -- cargo test
sshai exec ssh://dev-server/srv/project -- printf '%s\n' 'hello world'
```

Inspect the resolved configuration and test the connection:

```bash
sshai doctor dev-server
sshai doctor dev-server --config-only
```

Transfer files or directories through SFTP:

```bash
sshai sftp dev-server put ./artifact.tar.gz /tmp/artifact.tar.gz
sshai sftp dev-server get /var/log/app.log ./app.log

# Recursively upload and download directories
sshai sftp dev-server put -r ./project /srv/project
sshai sftp dev-server get -r /srv/project ./project

# Exclude matching names or relative subtrees; the option may be repeated
sshai sftp dev-server put -r ./project /srv/project \
  --exclude .git \
  --exclude node_modules \
  --exclude build/cache \
  --force
```

Directory sources require an explicit `-r` or `--recursive`. Existing files are not overwritten by default; `--force` permits per-file replacement. An `--exclude name` filter excludes matching names at any depth. A filter containing `/` matches a relative subtree within the source directory. Uploads and downloads reject symbolic links and special files and are limited to 100,000 filesystem entries per operation.

Install an SSH public key:

```bash
# Prefer public keys available through the SSH agent
sshai copy-id dev-server

# Install only the selected public key; a private-key path is also accepted
sshai copy-id -i ~/.ssh/id_ed25519.pub dev-server
```

`copy-id` creates or updates remote `~/.ssh/authorized_keys`, enforces mode `0700` on `.ssh` and `0600` on `authorized_keys`, and skips keys that are already installed.

For a server with a custom authorized-keys path, specify it explicitly:

```bash
sshai copy-id -i ~/.ssh/id_ed25519.pub \
  --authorized-keys /custom/path/authorized_keys dev-server
```

By default, sshai asks before adding an unknown host to `known_hosts`. To accept new hosts automatically:

```bash
sshai --accept-new exec dev-server -- uname -a
```

For non-interactive use:

```bash
sshai --batch --strict-host-key exec dev-server -- true
```

## SSH configuration support

`v0.1` supports:

```text
Host
HostName
User
Port
IdentityFile
IdentityAgent
IdentitiesOnly
ProxyJump
UserKnownHostsFile
StrictHostKeyChecking
ConnectTimeout
ServerAliveInterval
ServerAliveCountMax
```

To prevent silent connections to the wrong host, sshai currently reports `Match`, `Include`, and `ProxyCommand` as unsupported instead of ignoring them. `ProxyJump` is implemented natively with nested Rust SSH channels.

## Security boundaries

- sshai verifies `known_hosts` by default and fails closed when a host key changes.
- `--insecure` displays a warning and is intended only for temporary environments where the risk is explicitly accepted.
- Command arguments are individually quoted as POSIX shell arguments; workspace paths are never concatenated as unescaped command text.
- The SSH agent performs local signatures only. Private keys are never sent to a remote host.
- Decrypted private keys and passwords remain in memory only for the time required to authenticate.
- SFTP refuses overwrites by default. Replacement requires an explicit `--force`.
- The agent control protocol uses versioned, length-limited frames, and every shim request validates a random session token.
- Workspace RPC v4 uses independent request and process IDs plus structured errors. It supports reads, atomic writes, unique-text edits, directory operations, streaming pipe/PTY execution, and propagation of the session command working directory.
- MCP write tools use conservative destructive and read-only annotations so the AI client can enforce approvals.
- The shim exists only in the current session's `PATH`; its socket has mode `0600` and its session directory has mode `0700`.
- Before execution, a cached worker is checked with a remote SHA-256 utility and checked again after upload. sshai falls back to streaming SFTP verification only when the remote host has no hashing utility.
- Compression capability is probed only after a cache miss. sshai prefers low-latency `zstd`, followed by `gzip` and `xz`. Missing local or remote tools, compression failures, and decompression failures fall back automatically to an uncompressed upload. The remote cache always stores the verified original worker, and temporary compressed files are removed.

## Current scope

The current agent requires a Unix remote host whose OS and CPU can run the `sshai-worker` companion installed with the local CLI. sshai looks for the worker next to its own executable by default; set `SSHAI_WORKER` to select one explicitly. A static musl worker is recommended for Linux distribution portability. A future bootstrap layer may select signed release artifacts for each detected remote platform.

This release provides a reliable agent/shim control plane, Workspace RPC, a shared tool layer, stdio MCP, Codex and Claude adapters, and sshai's built-in AI agent. Additional adapters, model-output streaming, and incremental file synchronization can build on the same tool layer and versioned protocol.

See [docs/architecture.md](docs/architecture.md) for the detailed design.
