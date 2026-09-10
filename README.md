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
- `sshai codex` 一次性注入 MCP 配置，本地 Codex 登录态无需迁移
- `sshai agent` 内置本地模型循环，共用 MCP 的远程工具与审批边界
- `doctor` 配置与连接诊断

## 构建

```bash
cargo build --release
```

二进制位于：

```text
target/release/sshai
```

安装到 Cargo 的用户级命令目录后，就可以在其他路径直接运行：

```bash
cargo install --path crates/sshai-cli --force
```

确保 `~/.cargo/bin` 已加入 `PATH`；随后用 `sshai --version` 验证。

## 使用

打开远程 Shell：

```bash
sshai dev-server
sshai user@example.com:/srv/project
sshai ssh://user@example.com:2222/srv/project
```

交互式 Shell 默认会：

1. 检测远端 OS/CPU 是否与本地 agent 二进制兼容；
2. 通过 SFTP 按 SHA-256 校验并缓存上传当前 `sshai` 二进制；
3. 创建权限为 `0700` 的随机会话目录和权限为 `0600` 的 Unix socket；
4. 用适配 bash、zsh、fish 和 POSIX shell 的启动器注入会话 shim；
5. 在 Shell 退出或 SSH 控制 Channel 断开后自动删除会话目录。

登录后可以直接调用本地能力，不需要退出远端 Shell：

```bash
sshai info
sshai help
sshai copy-id
sshai copy-id -i '~/.ssh/id_ed25519.pub'
```

`-i` 指向的是本机文件；请像上例一样引用 `~`，避免它先被远端 Shell 展开。请求通过独立的加密 SSH Channel 传输，不解析或匹配终端输入字符。若要连接不支持 agent 的主机，可显式使用 `sshai --no-agent HOST`。

连接较慢时使用 `-v` 可查看 TCP、SSH 握手、认证、SFTP 缓存校验及远端 agent 启动各阶段的毫秒耗时；`-vv` 还会开启底层 SSH 库的 debug 日志：

```bash
sshai dev-server -v
sshai dev-server -vv
```

若只需要普通远程 Shell，不需要会话内置命令，可使用 `--no-agent` 跳过平台检测、SFTP 校验和 agent 启动，连接时延会更接近系统 `ssh`：

```bash
sshai --no-agent dev-server
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

## 本地 AI 操作远端工作区

直接启动本机已经登录的 Codex CLI：

```bash
sshai codex dev-server:/srv/project
sshai codex dev-server:/srv/project -- "修复测试并在远端运行 cargo test"
sshai codex dev-server:/srv/project -- exec "检查这个项目的错误处理"
```

`sshai codex` 不复制或修改 Codex 登录凭据，也不持久修改 `~/.codex/config.toml`。它创建一个会话级本地壳目录，通过命令行配置注入 `sshai` stdio MCP，并强制本地 Codex sandbox 为只读。Codex 的项目读取、写入、Git、构建和测试由 MCP 工具发送到远端 Agent；会话结束后壳目录自动删除。

也可以把 MCP Server 接入其他兼容客户端：

```bash
sshai mcp dev-server:/srv/project
```

MCP 提供 `workspace_info/list/stat/read/hash/write/edit/mkdir/rename/remove/exec`。写文件使用同目录临时文件、`fsync` 和原子 rename；编辑会自动以读取内容的 BLAKE3 作为乐观并发条件。覆盖现有文件必须提供 `expected_blake3` 或显式设置 `overwrite=true`。

stdio MCP 的 stdin/stdout 专用于 JSON-RPC，不能用于 SSH 密码交互。建议先运行 `sshai copy-id HOST` 配置公钥认证。

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

通过 SFTP 传输文件：

```bash
sshai sftp dev-server put ./sshai-agent ~/.cache/sshai/sshai-agent
sshai sftp dev-server get /var/log/app.log ./app.log
```

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
- Workspace RPC v3 使用独立 request/process ID 和结构化错误，支持读取、原子写入、唯一文本编辑、目录操作以及流式 pipe/PTY exec。
- MCP 写入工具提供保守的 destructive/read-only annotations，交由 AI 客户端执行审批。
- shim 只存在于当前会话的 `PATH`，socket 为 `0600`，会话目录为 `0700`。
- 缓存 agent 在执行前通过 SFTP 流式 SHA-256 校验，上传后再次校验。

## 当前范围

当前 agent 要求远端为 Unix，且远端 OS/CPU 能运行本地构建出的同一二进制。Linux 跨发行版发布建议使用静态 musl 构建；未来可在 bootstrap 层按远端平台选择签名发布产物。

这一版已经建立可靠的 agent/shim 控制平面、Workspace RPC、共享工具层、stdio MCP、Codex 适配器和 sshai 内置 AI Agent。Claude/Gemini 适配器、模型流式输出以及文件 watch/增量同步可继续建立在同一工具层和版本化协议上。

详细设计见 [docs/architecture.md](docs/architecture.md)。
