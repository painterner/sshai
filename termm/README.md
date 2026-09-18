# termm

`termm` is the Tauri desktop terminal companion for sshai. Its Rust process owns every PTY and renders the xterm.js interface in the operating system WebView; it does not start Chrome, expose a local HTTP port, or create a browser profile.

## Run

```bash
# Local shells
termm

# Every New/Split action inherits this sshai target set and local cwd
termm build-server,test-server --cwd ~/projects/app
```

The window and broker start in one process. Frontend requests use Tauri IPC, while terminal output is delivered through Tauri events and recovered from the broker's bounded replay journal when a pane is remounted.

## Current features

- xterm.js terminal rendering with true color and resize propagation;
- native Tauri window backed by the operating system WebView;
- integrated dark title bar with drag, resize, minimize, maximize, and close controls;
- restored window size, position, and maximized state across launches;
- New workspace tabs and horizontal/vertical splits;
- focused-pane Detach and Terminate actions;
- inherited target list, local cwd, and sshai executable;
- one broker-owned local PTY per pane;
- 4 MiB sequence-numbered replay per session;
- page reload/layout recovery through local storage;
- IPC event reattachment without restarting the shell;
- automatic relaunch of a remote `sshai` transport after abnormal exit, with capped backoff;
- explicit `exit` or Terminate does not reconnect.

## Build

```bash
cd termm/web
npm install
npm run build

cd ../..
cargo build -p termm --release
```

Generated web assets are embedded into the Rust binary, so Node.js is not required at runtime.

## Persistence boundary

The current broker keeps sessions alive while the `termm` process is running and restores a remounted pane from replay history. If the SSH transport dies it opens a new remote shell in the same pane; it cannot yet preserve a process that was owned by the destroyed remote SSH PTY.

True cross-SSH process persistence requires the worker-owned `terminal.create/list/attach/input/resize/detach/terminate/ack` protocol described in [`../docs/terminal.md`](../docs/terminal.md). That remote daemon is the next backend milestone; the UI and local sequence/replay model are already shaped around the same protocol.
