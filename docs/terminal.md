# sshai native terminal

## Current implementation

The top-level `termm/` project now provides the first runnable layer: a Tauri desktop process, broker-owned local PTYs, xterm.js UI, tabs, horizontal/vertical splits, context inheritance, bounded sequence replay, pane reattachment, saved layouts, and abnormal sshai transport relaunch. Rust commands and frontend events communicate over Tauri IPC, so there is no external browser process, local HTTP listener, WebSocket, browser profile, or bearer token. Its IPC layer uses the same session/replay concepts defined below.

The remaining persistence boundary is remote: today a transport relaunch creates a new remote shell because the original PTY still belongs to the failed SSH channel. The persistent worker protocol below is required before processes survive a complete SSH transport loss or a `termm` broker restart.

## Why this is not only a terminal UI

A terminal emulator renders bytes and sends keystrokes. It cannot preserve a remote process after a direct SSH PTY disappears: the remote shell commonly receives hangup, its PTY is destroyed, and reconnecting creates a different process. tmux solves this by running a persistent server on the remote host that owns the PTY while clients attach and detach.

sshai can provide the same persistence without exposing tmux to the user. The UI can be simpler—New, Split, Move, Close, host tabs, connection badges—but a persistent `sshai-worker` PTY service is still required behind it.

## User experience

- **New** inherits the focused pane's local workspace, SSH config, selected host set, environment profile, and remote cwd. The user may change only the host or starting directory.
- **Split right/down** creates or attaches another terminal without replacing the current pane.
- A pane header shows host, user, cwd, latency, connected/reconnecting state, and the persistent session ID.
- Tabs and panes are draggable; keyboard switching remains available.
- Closing the application detaches by default. Explicit **Terminate** ends the remote shell.
- Reopening sshai lists resumable sessions and restores the previous layout.
- Agent actions can open a terminal pane for a named remote, and a terminal pane can launch `sshai --agent NAME` using the same local/remote context.

## Components

```text
sshai Terminal UI
  ├─ terminal emulator/rendering
  ├─ tabs, split tree, commands and key bindings
  └─ local session broker
       ├─ current local workspace and SSH configuration
       ├─ target/connection manager
       ├─ MCP server registry
       └─ attach/replay client
                  │ SSH reconnect
                  ▼
       persistent sshai-worker PTY service
          ├─ session metadata + owner permissions
          ├─ PTY master + child process group
          ├─ bounded scrollback/output journal
          ├─ monotonic output sequence numbers
          └─ attach token, TTL and cleanup policy
```

The UI should reuse a production terminal-emulation core rather than reimplement ANSI/VT parsing. The sshai-specific value is session lifecycle, context inheritance, multi-host layout, and Agent integration.

## Recoverable PTY protocol

The worker protocol needs these operations in addition to today's ephemeral SSH channel:

```text
terminal.create(argv, cwd, env, term, size, ttl) -> session_id, resume_token
terminal.list() -> owned resumable sessions
terminal.attach(session_id, resume_token, after_sequence) -> snapshot + output stream
terminal.input(session_id, bytes)
terminal.resize(session_id, columns, rows)
terminal.signal(session_id, signal)
terminal.detach(session_id)
terminal.terminate(session_id)
terminal.ack(session_id, through_sequence)
```

Output frames carry monotonically increasing sequence numbers. After reconnect, the client supplies its last acknowledged sequence; the worker replays the missing bounded journal and then resumes live output. If the journal was truncated, it sends a fresh terminal snapshot plus the new sequence boundary.

## Local context inheritance

The CLI or desktop app owns a local broker socket under `$XDG_RUNTIME_DIR/sshai`. Each window registers a context containing:

- local workspace root;
- ordered SSH targets and focused target;
- SSH config and host-key policy;
- remote cwd per host;
- active Agent adapter and MCP server names;
- terminal environment profile, excluding secrets by default.

Clicking **New** clones this context and requests a new remote PTY. Clicking **Split** additionally updates the saved layout tree. This makes creation contextual and visual rather than requiring tmux commands.

## Persistence and security

- Persistent sessions live under a remote user-private directory with mode `0700`; metadata and sockets use `0600`.
- Resume tokens are random, scoped to one session, stored only in the local broker, and never placed in shell history.
- The worker accepts attach operations only through an authenticated SSH channel and validates both remote Unix ownership and the resume token.
- Detached sessions have configurable idle and absolute TTLs. Expiry terminates the complete process group and removes journals.
- Scrollback is bounded and optionally disabled for sensitive sessions.
- Environment inheritance uses an allowlist; credentials are never copied merely because they exist locally.

## Delivery order

1. Persistent worker-owned PTY with attach/detach and replay tests.
2. CLI commands for `terminal new/list/attach/kill`, proving recovery without a GUI.
3. Local broker and context inheritance.
4. Tabs/splits UI using the same protocol.
5. Saved layouts, drag/drop, Agent-to-terminal actions, and optional tmux import/fallback.

tmux can remain an optional compatibility backend, but it is not part of the user-facing model.
