# termm

`termm` is the native multi-pane terminal companion for sshai. A local broker owns every PTY, while the browser UI is only an attachable view. Reloading or closing the page therefore does not terminate shells.

## Run

```bash
# Local shells
termm

# Every New/Split action inherits this sshai target set and local cwd
termm build-server,test-server --cwd ~/projects/app
```

The broker listens only on loopback and prints/opens a URL containing a random 256-bit access token. API and WebSocket requests without that token are rejected.

## Current features

- xterm.js terminal rendering with true color and resize propagation;
- New workspace tabs and horizontal/vertical splits;
- focused-pane Detach and Terminate actions;
- inherited target list, local cwd, and sshai executable;
- one broker-owned local PTY per pane;
- 4 MiB sequence-numbered replay per session;
- page reload/layout recovery through local storage;
- WebSocket reattachment without restarting the shell;
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

The current broker keeps sessions alive while the `termm` process is running and restores its UI after browser refreshes. If the SSH transport dies it opens a new remote shell in the same pane; it cannot yet preserve a process that was owned by the destroyed remote SSH PTY.

True cross-SSH process persistence requires the worker-owned `terminal.create/list/attach/input/resize/detach/terminate/ack` protocol described in [`../docs/terminal.md`](../docs/terminal.md). That remote daemon is the next backend milestone; the UI and local sequence/replay model are already shaped around the same protocol.
