# sshai

`sshai` 是面向本地 AI CLI 的远程工作区工具。认证与 AI CLI 留在本机，代码和执行环境留在远程主机。

当前 `v0.1` 实现纯 Rust SSH 基座，不调用系统的 `ssh`、`scp` 或 `sftp`：

- 基于 `russh` 的 SSH2 连接和多 Channel 会话
- `~/.ssh/config` 常用配置解析
- `known_hosts` 严格校验、交互确认和 `accept-new`
- SSH Agent、私钥、keyboard-interactive 和密码认证
- 原生单级/多级 ProxyJump
- 远程命令执行，分别流式输出 stdout/stderr
- 交互式 PTY、raw terminal、窗口 resize 和信号转发
- 基于 `russh-sftp` 的安全上传、下载
- 纯 Rust `copy-id`，幂等维护远端 `authorized_keys`
- 默认启用按会话隔离的远端 agent、Unix socket 和 `sshai` shim
- 独立 SSH 控制 Channel，远端内置命令同步调用本地能力
- 本地 stdio MCP Server，将远端工作区暴露给 AI CLI
- MCP SSH 断线自动重连；只读调用安全重试，状态不确定的写操作不重复执行
- `sshai --agent codex TARGET` 一次性注入 MCP 配置，本地 Codex 登录态无需迁移
- `sshai --agent claude TARGET` 一次性注入 MCP 配置，本地 Claude 登录态无需迁移
- `sshai agent` 内置本地模型循环，共用 MCP 的远程工具与审批边界
- `doctor` 配置与连接诊断

## 构建

```bash
cargo build --release
```

本地 CLI 和远端薄 worker 位于：

```text
target/release/sshai
target/release/sshai-worker
```

安装到 Cargo 的用户级命令目录后，就可以在其他路径直接运行：

```bash
cargo install --locked --path crates/sshai-cli --force
cargo install --locked --path termm --force
```

第一条命令会同时安装 `sshai` 和 `sshai-worker`，第二条安装 `termm`。确保 `~/.cargo/bin` 已加入 `PATH`；随后用 `sshai --version` 验证。

`termm` 是独立子工程和二进制，提供 sshai 原生的标签页、点击新建、横纵分屏和 broker-owned PTY：

```bash
termm
termm build-server,test-server --cwd ~/projects/app
```

`termm` 现在直接启动 Tauri 桌面窗口，不再启动 Chrome、监听本地 HTTP 端口或创建浏览器 profile。前端通过 Tauri IPC 与 Rust PTY broker 通信；New 与 Split 会继承启动时的 targets、本地 cwd 和 sshai 配置，异常退出的远端 sshai transport 会在同一 pane 内自动拉起。详见 [`termm/README.md`](termm/README.md)。

## 使用

打开远程 Shell：

```bash
sshai dev-server
sshai user@example.com:/srv/project
sshai ssh://user@example.com:2222/srv/project
sshai build-server,test-server,prod-server
```

多主机形式会先连接并立即打开第一台主机的 Shell，不等待其他主机。其余主机在后台并行完成连接、PTY 和 worker 启动；连接成功后可用 `Ctrl+Shift+←` / `Ctrl+Shift+→` 在仍然存活的主机之间循环切换。每台主机保留独立的 Shell、当前目录和前台程序，后台输出不会混入当前屏幕；切回时会用每台主机最近最多 4 MiB 的终端输出重建画面。

后台连接不会读取密码、私钥口令、keyboard-interactive 或未知主机确认，以免抢占已经交给第一台主机的键盘。应预先使用 SSH Agent、公钥和 `known_hosts`；某台后台主机失败不会影响其他主机，按切换键且没有其他可用主机时会显示连接中及失败状态。

交互式 Shell 默认会：

1. 检测远端 OS/CPU，并创建只有几 KiB 的会话 launcher/shim；
2. 立即打开 PTY 和远端 Shell；
3. 在独立 SSH Channel 中后台校验薄 `sshai-worker`，缓存缺失时探测 `zstd`、`gzip`、`xz` 并通过 SFTP 自适应压缩上传；
4. worker ready 后创建权限为 `0600` 的 Unix socket，预先注入 PATH 的 shim 自动可用；
5. 在 Shell 退出或 SSH 控制 Channel 断开后自动取消 bootstrap，并删除会话目录和带 session token 的临时上传文件。

Shell 的终端输入和输出优先于后台 bootstrap。若在 worker ready 前执行 `sshai info`、`sshai --agent codex` 等会话命令，shim 会显示 `worker is initializing` 并等待 socket；上传、解压或 worker 启动失败只会禁用会话内置命令，不会关闭已经打开的远端 Shell。

登录后可以直接调用本地能力，不需要退出远端 Shell：

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

会话内执行 `sshai --agent codex` 或 `sshai --agent claude` 会把终端临时交给对应的本机 AI CLI。本机启动 `sshai` 时的目录是可读写的 local 工作区，远端 Shell 的当前目录是 primary remote 工作区；AI CLI 退出后回到原远端 Shell。可用 `sshai --agent codex --local-dir '/本机/其他目录'` 覆盖 local 目录；请引用路径，避免先被远端 Shell 展开。

逗号分隔的目标会建立一个本机 + 多远端 AI 会话。交互 Shell 从第一个目标立即开始，其他目标连接完成后可切换；任意主机内的 `sshai --agent NAME` 都会把当前主机作为 primary remote，并将所有目标分别注入为具名 MCP 工作区：

```bash
cd ~/projects/control-plane
sshai build-server,test-server,prod-server

# 在任一主机的 Shell 中执行；三个远端都可独立读写和执行
sshai --agent codex
```

`-i` 指向的是本机文件；请像上例一样引用 `~`，避免它先被远端 Shell 展开。请求通过独立的加密 SSH Channel 传输，不解析或匹配终端输入字符。若只连接一个不支持 worker 的主机，可显式使用 `sshai --no-worker HOST`（旧的 `--no-agent` 仍作为兼容别名）。

连接较慢时使用 `-v` 可查看 TCP、SSH 握手、认证、SFTP 缓存校验及远端 agent 启动各阶段的毫秒耗时；`-vv` 还会开启底层 SSH 库的 debug 日志：

```bash
sshai dev-server -v
sshai dev-server -vv
```

若只需要普通远程 Shell，不需要会话内置命令，可使用 `--no-worker` 跳过平台检测、SFTP 校验和 worker 启动，连接时延会更接近系统 `ssh`：

```bash
sshai --no-worker dev-server
```

通过 Workspace RPC 检查远端工作区：

```bash
sshai workspace dev-server:/srv/project open
sshai workspace dev-server:/srv/project list . --limit 200
sshai workspace dev-server:/srv/project stat Cargo.toml
sshai workspace dev-server:/srv/project read README.md
sshai workspace dev-server:/srv/project hash Cargo.lock
sshai workspace dev-server:/srv/project exec -- cargo test
sshai workspace dev-server:/srv/project exec --cwd crates/core --env RUST_LOG=debug -- cargo test
sshai workspace dev-server:/srv/project exec --pty -- ls --color=auto -C
sshai workspace dev-server:/srv/project exec --pty --shell -- 'ls'
```

`list/stat/read/hash` 只能访问工作区根目录内的相对路径；绝对路径、`..` 和指向根目录外的符号链接都会被拒绝。`list` 使用稳定的名称游标分页，`read` 每次最多读取 512 KiB。

Workspace `exec` 默认直接使用 argv 启动进程，不经过 Shell，以独立 stdout/stderr 事件实时返回，适合 AI 和脚本。`--pty` 会分配远端伪终端、转发 stdin、`TERM`、窗口尺寸、resize 和终端信号，适合颜色、列布局和交互程序；PTY 中 stdout/stderr 按终端语义合流。`--shell` 要求一个完整命令字符串，并通过远端登录 Shell 执行，以显式启用 alias、管道和重定向。执行工作目录必须位于工作区内，但进程仍拥有远端 SSH 用户本身的权限。命令有 300 秒超时，SSH/Agent 断开会终止整个远端进程组。

## 本地 AI 协同操作本机与多个远端工作区

直接启动本机已经登录的 Codex CLI：

```bash
sshai --agent codex dev-server:/srv/project
sshai --agent codex dev-server:/srv/project -- "修复测试并在远端运行 cargo test"
sshai --agent codex dev-server:/srv/project -- exec "检查这个项目的错误处理"
sshai --agent codex --local-dir ~/projects/app build-server:/src,test-server:/srv/app
```

`sshai --agent codex` 不复制或修改 Codex 登录凭据，也不持久修改 `~/.codex/config.toml`。Codex 在 local 工作区以 `workspace-write` sandbox 运行；普通文件、编辑和 Shell 工具操作 local，按主机命名的 `sshai_*` MCP 工具操作对应 remote。启动时会显示每个工作区的位置，避免同名路径混淆。

本机已经登录 Claude Code 时，也可以使用相同的远程工具：

```bash
sshai --agent claude dev-server:/srv/project
sshai --agent claude dev-server:/srv/project -- "检查并修复测试"
sshai --agent claude --local-dir ~/projects/app build-server,test-server
```

`sshai --agent claude` 在 local 工作区保留本机文件和命令工具，并使用 strict、会话级 `--mcp-config` 注入具名 remote，不会持久修改 Claude 的 MCP 配置。

本地入口 `sshai --agent AGENT TARGET[,TARGET...] [-- ARGUMENTS...]` 与远程会话入口 `sshai --agent AGENT [-- ARGUMENTS...]` 都会在本机 `PATH` 中解析 Agent 名称。裸位置参数始终是 SSH 主机，因此 `sshai codex` 会连接名为 `codex` 的主机，不会启动 Codex：

- `codex`、`claude`、`gemini`、`opencode` 使用内置会话适配器；
- Gemini 通过临时 `GEMINI_CLI_SYSTEM_SETTINGS_PATH` 注入 MCP，并用交互 Prompt 传递双工作区说明；
- OpenCode 通过临时 `OPENCODE_CONFIG_CONTENT` 注入 MCP 和 instruction 文件；
- 其他名称会先执行 `--help` 探测 `--mcp-config`、Prompt 参数和 MCP 能力；
- 能识别 `--mcp-config` 时直接传入临时标准 MCP JSON；否则使用 `MCP_CONFIG_PATH`、`SSHAI_MCP_CONFIG_PATH`、`SSHAI_INSTRUCTIONS_PATH`、`SSHAI_LOCAL_ROOT` 和 `SSHAI_REMOTE_TARGETS` 通用环境约定；
- 不声明 MCP 能力或包含路径分隔符的名称会被拒绝。

通用环境约定不保证任意第三方 CLI 都会自动读取；对于不支持 `--mcp-config` 的客户端，需要该客户端原生支持 `MCP_CONFIG_PATH`，或后续增加一个薄的内置适配器。整个过程不会写入项目或 Agent 的持久配置。

也可以把 MCP Server 接入其他兼容客户端：

```bash
sshai mcp dev-server:/srv/project --local-dir ~/projects/app
```

MCP 提供 `workspace_info/list/stat/read/hash/write/edit/mkdir/rename/remove/exec/transfer`。`workspace_info` 同时报告远端 OS、CPU 架构和 Shell。`workspace_transfer` 在 local 与该 remote 之间通过 SFTP 直接传输文件或目录，不把文件内容送进模型上下文；local 路径必须位于本机工作区根内，remote 路径既可相对远端工作区，也可显式指定 `/tmp/example` 之类的绝对路径。符号链接和特殊文件会被拒绝，目录复制需要 `recursive=true`。

普通 `workspace_transfer` 永不覆盖已有目标文件，并在 Codex 中对当前 sshai 会话预先批准，避免用户已经明确要求上传后又被自动审批器重复拦截。只有 `workspace_transfer_overwrite` 可以替换文件，它仍按写操作请求审批，并且提示要求用户必须明确授权覆盖。

多 remote 之间可以由 AI 明确使用一个 local 临时路径中转。传输支持 `exclude` 名称或相对子树过滤，并限制单次最多 100,000 个文件系统条目。写文件使用同目录临时文件、`fsync` 和原子 rename；编辑会自动以读取内容的 BLAKE3 作为乐观并发条件。

stdio MCP 的 stdin/stdout 专用于 JSON-RPC，不能用于 SSH 密码交互。建议先运行 `sshai copy-id HOST` 配置公钥认证。

MCP Server 每 15 秒在空闲连接上进行一次 workspace 心跳，SSH、worker 或 SFTP channel 断开后会原地重建完整连接，Codex、Claude、Gemini 等本机 Agent 无需退出。重连无限持续，采用从 250 ms 增长到最多 30 秒并带 ±25% 随机抖动的指数退避。一个目标只有一个连接管理器；重连期间到达的工具调用进入同一个串行队列，最多等待 45 秒，超时后重连仍在后台继续。

`workspace_info/list/stat/read/hash` 如果在传输中断开，会保留在队列并在新连接上安全重试。写入、编辑、删除、命令执行和文件传输可能已经在断线前生效，因此不会自动重复；sshai 会要求 Agent 先检查远端状态。`workspace_connection_info` 不依赖远端，在离线期间仍可报告连接阶段、连接代数、累计重连、队列深度、心跳、下次重试时间和最近错误。所有诊断只写 stderr，不污染 MCP JSON-RPC。

原生可恢复 Terminal 的设计见 [`docs/terminal.md`](docs/terminal.md)：前端负责标签页、点击新建和分屏，远端 `sshai-worker` 负责持久 PTY、输出序列和断线重附着。这会提供 tmux 的核心持久性，但不要求用户学习 tmux 命令。

运行 sshai 自己的内置 Agent：

```bash
export OPENAI_API_KEY=...

# 交互会话
sshai agent dev-server:/srv/project

# 单次任务
sshai agent dev-server:/srv/project -- "修复失败的测试并验证"

# 自动批准远端命令和修改，适合受控的开发机
sshai agent dev-server:/srv/project --approval auto -- "运行测试并修复问题"
```

内置 Agent 在本地调用 Responses API，模型凭证不会进入 SSH 通道或远端主机。默认模型是 `gpt-5.4-mini`；可以使用 `--model` 或 `OPENAI_MODEL` 修改。默认 API 地址是 `https://api.openai.com/v1`；兼容服务可以通过 `--api-base` 或 `OPENAI_BASE_URL` 指定，非本机地址必须使用 HTTPS。

审批策略包括：

- `ask`（默认）：读取自动执行，写入、删除和命令执行逐次确认；
- `auto`：自动批准所有远程工具；
- `read-only`：拒绝一切写入和命令执行。

交互模式支持 `/clear` 清空模型上下文和 `/exit` 结束会话。MCP 与内置 Agent 都使用 `sshai-tools` 中同一份工具 schema 和 dispatcher，避免两种入口产生不同的远端行为。当前模型输出按完整 response 返回；模型文本和远程命令输出的增量展示将在后续版本加入。

在远程工作区执行命令：

```bash
sshai exec dev-server:/srv/project -- cargo test
sshai exec dev-server:/srv/project -- printf '%s\n' 'hello world'
```

检查解析后的配置并建立连接：

```bash
sshai doctor dev-server
sshai doctor dev-server --config-only
```

通过 SFTP 传输文件或目录：

```bash
sshai sftp dev-server put ./artifact.tar.gz /tmp/artifact.tar.gz
sshai sftp dev-server get /var/log/app.log ./app.log

# 递归上传和下载目录
sshai sftp dev-server put -r ./project /srv/project
sshai sftp dev-server get -r /srv/project ./project

# 排除同名目录或相对子树，可重复指定
sshai sftp dev-server put -r ./project /srv/project \
  --exclude .git \
  --exclude node_modules \
  --exclude build/cache \
  --force
```

目录源必须显式使用 `-r`/`--recursive`。默认拒绝覆盖已有文件，`--force` 允许逐文件覆盖；`--exclude name` 会排除任意层级的同名项，包含 `/` 时按源目录内的相对子树匹配。上传和下载都会拒绝符号链接及特殊文件，并限制单次最多 100,000 个文件系统条目。

安装 SSH 公钥：

```bash
# 优先安装 SSH Agent 中的公钥
sshai copy-id dev-server

# 只安装指定公钥；也可以传入私钥路径
sshai copy-id -i ~/.ssh/id_ed25519.pub dev-server
```

`copy-id` 会创建或更新远端 `~/.ssh/authorized_keys`，确保 `.ssh` 为 `0700`、`authorized_keys` 为 `0600`，并跳过已经存在的公钥。

如果服务器使用自定义路径，可以显式指定：

```bash
sshai copy-id -i ~/.ssh/id_ed25519.pub \
  --authorized-keys /custom/path/authorized_keys dev-server
```

默认情况下，未知主机会询问是否写入 `known_hosts`。自动接受新主机：

```bash
sshai --accept-new exec dev-server -- uname -a
```

非交互运行：

```bash
sshai --batch --strict-host-key exec dev-server -- true
```

## SSH 配置支持

`v0.1` 支持：

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

为了避免静默连接到错误主机，`Match`、`Include` 和 `ProxyCommand` 当前会明确报错。`ProxyJump` 由嵌套的 Rust SSH Channel 原生实现。

## 安全边界

- 默认验证 `known_hosts`，host key 变化会硬失败。
- `--insecure` 会显示警告，只用于明确接受风险的临时环境。
- 命令参数按 POSIX shell 参数逐个引用，工作区路径不会直接拼接为未转义文本。
- SSH Agent 只负责本地签名，私钥不会发送到远程主机。
- 加密私钥和密码只在内存中短暂存在。
- SFTP 默认拒绝覆盖；覆盖必须显式传入 `--force`。
- agent 控制协议使用带长度上限的版本化帧；每个 shim 请求都校验随机会话令牌。
- Workspace RPC v4 使用独立 request/process ID 和结构化错误，支持读取、原子写入、唯一文本编辑、目录操作、流式 pipe/PTY exec，以及会话命令工作目录传递。
- MCP 写入工具提供保守的 destructive/read-only annotations，交由 AI 客户端执行审批。
- shim 只存在于当前会话的 `PATH`，socket 为 `0600`，会话目录为 `0700`。
- 缓存 worker 在执行前由远端 SHA-256 工具校验，上传后再次校验；缺少远端哈希工具时才回退到 SFTP 流式校验。
- 压缩能力只在缓存缺失时探测，优先选择低延迟的 `zstd`，其次为 `gzip`、`xz`；本地或远端工具缺失、压缩或解压失败时自动回退到原始上传。远端缓存始终保存校验后的原始 worker，临时压缩文件会被清理。

## 当前范围

当前 agent 要求远端为 Unix，且远端 OS/CPU 能运行随本地 CLI 安装的 `sshai-worker` companion。`sshai` 默认在自身旁边查找该文件，也可通过 `SSHAI_WORKER` 显式指定。Linux 跨发行版发布建议使用静态 musl worker；未来可在 bootstrap 层按远端平台选择签名发布产物。

这一版已经建立可靠的 agent/shim 控制平面、Workspace RPC、共享工具层、stdio MCP、Codex/Claude 适配器和 sshai 内置 AI Agent。Gemini 适配器、模型流式输出以及文件 watch/增量同步可继续建立在同一工具层和版本化协议上。

详细设计见 [docs/architecture.md](docs/architecture.md)。
