import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import "@xterm/xterm/css/xterm.css";
import "./style.css";

type Context = {
  default_target: string | null;
  local_cwd: string;
  sshai_path: string;
};

type SessionInfo = {
  id: string;
  title: string;
  target: string | null;
  local_cwd: string;
  phase: string;
  created_unix_ms: number;
  exit_code: number | null;
  signal: number | null;
  last_sequence: number;
};

type OutputMessage = {
  sequence: number;
  data_base64: string;
};

type SessionSnapshot = {
  session: SessionInfo;
  output: OutputMessage[];
};

type SessionEvent =
  | ({ type: "output"; session_id: string } & OutputMessage)
  | { type: "status"; session_id: string; session: SessionInfo };

type PaneNode = {
  kind: "pane";
  paneId: string;
  sessionId: string;
  sequence: number;
};

type SplitNode = {
  kind: "split";
  direction: "row" | "column";
  first: LayoutNode;
  second: LayoutNode;
};

type LayoutNode = PaneNode | SplitNode;

type WorkspaceTab = {
  id: string;
  title: string;
  root: LayoutNode;
};

type SavedState = {
  tabs: WorkspaceTab[];
  activeTabId: string | null;
  focusedPaneId: string | null;
  target: string;
  cwd: string;
};

const state: SavedState = {
  tabs: [],
  activeTabId: null,
  focusedPaneId: null,
  target: "",
  cwd: "",
};

let context: Context;
const sessions = new Map<string, SessionInfo>();
const views = new Map<string, PaneView>();
const app = document.querySelector<HTMLDivElement>("#app")!;
const appWindow = getCurrentWindow();

type ResizeDirection = "North" | "NorthEast" | "East" | "SouthEast" | "South" | "SouthWest" | "West" | "NorthWest";

class PaneView {
  readonly terminal: Terminal;
  readonly fit: FitAddon;
  private resizeObserver?: ResizeObserver;
  private inputBuffer = "";
  private inputTimer?: number;
  private inputChain: Promise<unknown> = Promise.resolve();

  constructor(
    readonly pane: PaneNode,
    readonly element: HTMLElement,
  ) {
    // A new xterm instance has no prior screen state, so always request the
    // broker's bounded replay even when the saved layout knows a later seq.
    this.pane.sequence = 0;
    this.terminal = new Terminal({
      allowProposedApi: false,
      cursorBlink: true,
      cursorStyle: "bar",
      fontFamily: '"JetBrains Mono", "SFMono-Regular", Consolas, monospace',
      fontSize: 13,
      lineHeight: 1.18,
      scrollback: 10_000,
      theme: {
        background: "#0b0f14",
        foreground: "#d9e2ef",
        cursor: "#68d391",
        selectionBackground: "#29445f",
        black: "#111827",
        red: "#fb7185",
        green: "#68d391",
        yellow: "#f6c177",
        blue: "#60a5fa",
        magenta: "#c4a7e7",
        cyan: "#5eead4",
        white: "#d9e2ef",
        brightBlack: "#64748b",
        brightRed: "#fda4af",
        brightGreen: "#86efac",
        brightYellow: "#fde68a",
        brightBlue: "#93c5fd",
        brightMagenta: "#d8b4fe",
        brightCyan: "#99f6e4",
        brightWhite: "#f8fafc",
      },
    });
    this.fit = new FitAddon();
    this.terminal.loadAddon(this.fit);
    const mount = element.querySelector<HTMLElement>(".terminal-mount")!;
    this.terminal.open(mount);
    this.terminal.onData((data) => {
      this.inputBuffer += data;
      this.inputTimer ??= window.setTimeout(() => this.flushInput(), 3);
    });
    this.terminal.onTitleChange((title) => {
      const titleElement = this.element.querySelector<HTMLElement>(".pane-title");
      if (titleElement && title.trim()) titleElement.textContent = title;
    });
    this.resizeObserver = new ResizeObserver(() => this.resize());
    this.resizeObserver.observe(mount);
    void this.attach();
    requestAnimationFrame(() => this.resize());
  }

  focus() {
    this.terminal.focus();
  }

  dispose() {
    if (this.inputBuffer) this.flushInput();
    else window.clearTimeout(this.inputTimer);
    this.resizeObserver?.disconnect();
    this.terminal.dispose();
  }

  applyEvent(message: SessionEvent) {
    if (message.type === "output") {
      if (message.sequence <= this.pane.sequence) return;
      this.pane.sequence = message.sequence;
      this.terminal.write(base64Bytes(message.data_base64));
      scheduleSave();
    } else {
      this.updateHeader(message.session);
    }
  }

  private async attach() {
    try {
      const snapshot = await invoke<SessionSnapshot>("session_snapshot", {
        id: this.pane.sessionId,
        after: 0,
      });
      sessions.set(snapshot.session.id, snapshot.session);
      this.updateHeader(snapshot.session);
      for (const output of snapshot.output) {
        this.applyEvent({
          type: "output",
          session_id: this.pane.sessionId,
          ...output,
        });
      }
      this.setConnectionState("attached");
      this.resize();
    } catch (error) {
      this.setConnectionState("unavailable");
      this.terminal.writeln(`\r\n\x1b[31mtermm: ${String(error)}\x1b[0m`);
    }
  }

  private flushInput() {
    this.inputTimer = undefined;
    const data = this.inputBuffer;
    this.inputBuffer = "";
    if (!data) return;
    const bytes = Array.from(new TextEncoder().encode(data));
    this.inputChain = this.inputChain
      .then(() => invoke("terminal_input", { id: this.pane.sessionId, data: bytes }))
      .catch((error) => this.setConnectionState(String(error)));
  }

  private resize() {
    try {
      this.fit.fit();
      void invoke("terminal_resize", {
        id: this.pane.sessionId,
        columns: this.terminal.cols,
        rows: this.terminal.rows,
      }).catch(() => this.setConnectionState("unavailable"));
    } catch {
      // The pane may be between DOM layouts.
    }
  }

  private updateHeader(info: SessionInfo) {
    const title = this.element.querySelector<HTMLElement>(".pane-title");
    const phase = this.element.querySelector<HTMLElement>(".pane-phase");
    if (title) title.textContent = info.title;
    if (phase) {
      phase.textContent = info.phase;
      phase.dataset.phase = info.phase;
    }
  }

  private setConnectionState(value: string) {
    const stateElement = this.element.querySelector<HTMLElement>(".pane-attach");
    if (stateElement) stateElement.textContent = value;
  }
}

async function bootstrap() {
  await listen<SessionEvent>("session-event", ({ payload }) => {
    if (payload.type === "status") {
      sessions.set(payload.session.id, payload.session);
      refreshStatusbar();
    }
    for (const view of views.values()) {
      if (view.pane.sessionId === payload.session_id) view.applyEvent(payload);
    }
  });
  context = await invoke<Context>("get_context");
  const liveSessions = await invoke<SessionInfo[]>("list_sessions");
  liveSessions.forEach((session) => sessions.set(session.id, session));
  const saved = loadState();
  if (saved) Object.assign(state, saved);
  state.target ||= context.default_target ?? "";
  state.cwd ||= context.local_cwd;
  state.tabs = state.tabs
    .map((tab) => ({ ...tab, root: pruneMissing(tab.root) }))
    .filter((tab): tab is WorkspaceTab => tab.root !== null);
  if (!state.tabs.length) await newTab();
  if (!state.tabs.some((tab) => tab.id === state.activeTabId)) {
    state.activeTabId = state.tabs[0]?.id ?? null;
  }
  render();
}

function render() {
  for (const view of views.values()) view.dispose();
  views.clear();
  const active = state.tabs.find((tab) => tab.id === state.activeTabId);
  app.replaceChildren();

  const shell = element("div", "shell");
  shell.append(toolbar());
  shell.append(tabbar());
  const stage = element("main", "stage");
  if (active) stage.append(renderNode(active.root));
  shell.append(stage);
  shell.append(statusbar());
  shell.append(resizeHandles());
  app.append(shell);
  requestAnimationFrame(() => {
    const focused = state.focusedPaneId ? views.get(state.focusedPaneId) : undefined;
    (focused ?? views.values().next().value)?.focus();
  });
  saveState();
}

function toolbar() {
  const bar = element("header", "toolbar");
  bar.setAttribute("data-tauri-drag-region", "");
  const brand = element("div", "brand");
  brand.innerHTML = `<span class="brand-mark">&gt;_</span><span>termm</span>`;
  brand.setAttribute("data-tauri-drag-region", "");
  brand.querySelectorAll("span").forEach((item) => item.setAttribute("data-tauri-drag-region", ""));
  bar.append(brand);
  bar.append(button("＋ New", () => void newTab()));
  bar.append(button("Split ↔", () => void splitFocused("row")));
  bar.append(button("Split ↕", () => void splitFocused("column")));
  bar.append(button("Detach", detachFocused, "quiet"));
  bar.append(button("Terminate", () => void terminateFocused(), "danger"));
  const spacer = element("div", "spacer");
  spacer.setAttribute("data-tauri-drag-region", "");
  bar.append(spacer);
  const target = document.createElement("input");
  target.className = "context-input target-input";
  target.placeholder = "host or host1,host2";
  target.value = state.target;
  target.onchange = () => {
    state.target = target.value.trim();
    saveState();
  };
  target.title = "Target inherited by New and Split";
  bar.append(target);
  const cwd = document.createElement("input");
  cwd.className = "context-input cwd-input";
  cwd.value = state.cwd;
  cwd.onchange = () => {
    state.cwd = cwd.value.trim();
    saveState();
  };
  cwd.title = "Local cwd inherited by New and Split";
  bar.append(cwd);
  bar.append(windowControls());
  return bar;
}

function windowControls() {
  const controls = element("div", "window-controls");
  controls.append(
    windowControl("−", "Minimize", () => appWindow.minimize()),
    windowControl("□", "Maximize or restore", () => appWindow.toggleMaximize()),
    windowControl("×", "Close", () => appWindow.close(), "close"),
  );
  return controls;
}

function windowControl(label: string, title: string, action: () => Promise<void>, className = "") {
  const control = document.createElement("button");
  control.className = `window-control ${className}`.trim();
  control.type = "button";
  control.title = title;
  control.setAttribute("aria-label", title);
  control.textContent = label;
  control.onclick = (event) => {
    event.stopPropagation();
    void action();
  };
  return control;
}

function resizeHandles() {
  const handles = element("div", "resize-handles");
  const directions: Array<[string, ResizeDirection]> = [
    ["n", "North"],
    ["ne", "NorthEast"],
    ["e", "East"],
    ["se", "SouthEast"],
    ["s", "South"],
    ["sw", "SouthWest"],
    ["w", "West"],
    ["nw", "NorthWest"],
  ];
  for (const [className, direction] of directions) {
    const handle = element("div", `resize-handle ${className}`);
    handle.onmousedown = (event) => {
      if (event.button !== 0) return;
      event.preventDefault();
      void appWindow.startResizeDragging(direction);
    };
    handles.append(handle);
  }
  return handles;
}

function tabbar() {
  const tabs = element("nav", "tabbar");
  for (const tab of state.tabs) {
    const item = button(tab.title, () => {
      state.activeTabId = tab.id;
      state.focusedPaneId = firstPane(tab.root)?.paneId ?? null;
      render();
    }, tab.id === state.activeTabId ? "tab active" : "tab");
    item.title = "Switch workspace";
    tabs.append(item);
  }
  return tabs;
}

function statusbar() {
  const bar = element("footer", "statusbar");
  bar.id = "statusbar";
  const running = [...sessions.values()].filter((session) => session.phase === "running").length;
  bar.innerHTML = `<span>${running} running</span><span>${sessions.size} broker sessions</span><span>Local: ${escapeHtml(state.cwd)}</span><span>Target: ${escapeHtml(state.target || "local")}</span>`;
  return bar;
}

function refreshStatusbar() {
  const bar = document.querySelector<HTMLElement>("#statusbar");
  if (!bar) return;
  const running = [...sessions.values()].filter((session) => session.phase === "running").length;
  bar.innerHTML = `<span>${running} running</span><span>${sessions.size} broker sessions</span><span>Local: ${escapeHtml(state.cwd)}</span><span>Target: ${escapeHtml(state.target || "local")}</span>`;
}

function renderNode(node: LayoutNode): HTMLElement {
  if (node.kind === "split") {
    const split = element("section", `split ${node.direction}`);
    split.append(renderNode(node.first), renderNode(node.second));
    return split;
  }
  const info = sessions.get(node.sessionId);
  const pane = element("section", `pane${node.paneId === state.focusedPaneId ? " focused" : ""}`);
  pane.dataset.pane = node.paneId;
  pane.onclick = () => {
    if (state.focusedPaneId !== node.paneId) {
      state.focusedPaneId = node.paneId;
      document.querySelectorAll(".pane.focused").forEach((item) => item.classList.remove("focused"));
      pane.classList.add("focused");
      saveState();
    }
  };
  const header = element("div", "pane-header");
  header.innerHTML = `<span class="pane-dot"></span><span class="pane-title">${escapeHtml(info?.title ?? node.sessionId)}</span><span class="pane-target">${escapeHtml(info?.target ?? "local")}</span><span class="pane-spacer"></span><span class="pane-attach">attaching</span><span class="pane-phase" data-phase="${escapeHtml(info?.phase ?? "unknown")}">${escapeHtml(info?.phase ?? "unknown")}</span>`;
  const mount = element("div", "terminal-mount");
  pane.append(header, mount);
  const view = new PaneView(node, pane);
  views.set(node.paneId, view);
  return pane;
}

async function newTab() {
  const session = await createBrokerSession();
  const pane = makePane(session.id);
  const tab: WorkspaceTab = {
    id: randomId("tab"),
    title: session.title,
    root: pane,
  };
  state.tabs.push(tab);
  state.activeTabId = tab.id;
  state.focusedPaneId = pane.paneId;
  if (context) render();
}

async function splitFocused(direction: "row" | "column") {
  const tab = activeTab();
  if (!tab || !state.focusedPaneId) return;
  const session = await createBrokerSession();
  const pane = makePane(session.id);
  tab.root = replacePane(tab.root, state.focusedPaneId, (existing) => ({
    kind: "split",
    direction,
    first: existing,
    second: pane,
  }));
  state.focusedPaneId = pane.paneId;
  render();
}

function detachFocused() {
  removeFocused(false);
}

async function terminateFocused() {
  const pane = focusedPane();
  if (!pane) return;
  await invoke("terminate_session", { id: pane.sessionId });
  removeFocused(true);
}

function removeFocused(terminated: boolean) {
  const tab = activeTab();
  const paneId = state.focusedPaneId;
  if (!tab || !paneId) return;
  const pane = findPane(tab.root, paneId);
  tab.root = removePane(tab.root, paneId) ?? tab.root;
  if (tab.root.kind === "pane" && tab.root.paneId === paneId) {
    state.tabs = state.tabs.filter((value) => value.id !== tab.id);
    state.activeTabId = state.tabs[0]?.id ?? null;
  }
  if (terminated && pane) sessions.delete(pane.sessionId);
  const nextTab = activeTab();
  state.focusedPaneId = nextTab ? firstPane(nextTab.root)?.paneId ?? null : null;
  if (!state.tabs.length) {
    void newTab();
    return;
  }
  render();
}

async function createBrokerSession(): Promise<SessionInfo> {
  const response = await invoke<{ session: SessionInfo }>("create_session", {
    request: {
      target: state.target || null,
      cwd: state.cwd,
      columns: 100,
      rows: 30,
    },
  });
  sessions.set(response.session.id, response.session);
  return response.session;
}

function makePane(sessionId: string): PaneNode {
  return { kind: "pane", paneId: randomId("pane"), sessionId, sequence: 0 };
}

function activeTab() {
  return state.tabs.find((tab) => tab.id === state.activeTabId);
}

function focusedPane() {
  const tab = activeTab();
  return tab && state.focusedPaneId ? findPane(tab.root, state.focusedPaneId) : null;
}

function findPane(node: LayoutNode, paneId: string): PaneNode | null {
  if (node.kind === "pane") return node.paneId === paneId ? node : null;
  return findPane(node.first, paneId) ?? findPane(node.second, paneId);
}

function firstPane(node: LayoutNode): PaneNode | null {
  return node.kind === "pane" ? node : firstPane(node.first) ?? firstPane(node.second);
}

function replacePane(node: LayoutNode, paneId: string, replace: (pane: PaneNode) => LayoutNode): LayoutNode {
  if (node.kind === "pane") return node.paneId === paneId ? replace(node) : node;
  return { ...node, first: replacePane(node.first, paneId, replace), second: replacePane(node.second, paneId, replace) };
}

function removePane(node: LayoutNode, paneId: string): LayoutNode | null {
  if (node.kind === "pane") return node.paneId === paneId ? null : node;
  const first = removePane(node.first, paneId);
  const second = removePane(node.second, paneId);
  if (!first) return second;
  if (!second) return first;
  return { ...node, first, second };
}

function pruneMissing(node: LayoutNode): LayoutNode | null {
  if (node.kind === "pane") return sessions.has(node.sessionId) ? node : null;
  const first = pruneMissing(node.first);
  const second = pruneMissing(node.second);
  if (!first) return second;
  if (!second) return first;
  return { ...node, first, second };
}

function button(label: string, action: () => void, className = "") {
  const value = document.createElement("button");
  value.className = `button ${className}`.trim();
  value.textContent = label;
  value.onclick = action;
  return value;
}

function element<K extends keyof HTMLElementTagNameMap>(tag: K, className: string) {
  const value = document.createElement(tag);
  value.className = className;
  return value;
}

function randomId(prefix: string) {
  return `${prefix}-${crypto.randomUUID()}`;
}

function base64Bytes(value: string) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function escapeHtml(value: string) {
  return value.replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]!);
}

let saveTimer: number | undefined;
function scheduleSave() {
  window.clearTimeout(saveTimer);
  saveTimer = window.setTimeout(saveState, 120);
}

function saveState() {
  localStorage.setItem("termm.layout.v1", JSON.stringify(state));
}

function loadState(): SavedState | null {
  try {
    const value = localStorage.getItem("termm.layout.v1");
    return value ? (JSON.parse(value) as SavedState) : null;
  } catch {
    return null;
  }
}

bootstrap()
  .catch((error) => {
    app.innerHTML = `<div class="fatal"><h1>termm failed to start</h1><pre>${escapeHtml(String(error))}</pre></div>`;
  })
  .finally(async () => {
    await appWindow.show();
    await appWindow.setFocus();
  })
  .catch((error) => console.error("termm could not reveal its window", error));
