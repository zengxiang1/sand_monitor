# 望楼（wanglou）开发规格

轻量 VPS 监控。核心安全目标：**面板或任意一台 VPS 被攻破，都不能扩散到其他机器。**

设计稿在 `docs/design/`：`overview.html` 是架构与威胁模型，`*.dc.html` 是各页面的界面稿（HTML，可直接看结构和文案）。

## 不可违反的安全约束

这些是验收的硬性条件，任何一条不满足即不通过。

1. **agent 只出不进**
   - agent 不监听任何端口（不得出现 `net.Listen`、`http.ListenAndServe`、`http.Server` 等）。
   - agent 不执行任何外部命令（不得 import `os/exec`，不得调用 `syscall.Exec`、`syscall.ForkExec`）。
   - agent 不读取、不解析服务端响应体，只看状态码；读完响应后丢弃（`io.Copy(io.Discard, ...)`，限长）。
   - agent 没有自更新、没有远程配置下发。配置只来自本地文件和命令行参数。
2. **每节点独立密钥**
   - agent 在本机生成 Ed25519 密钥对，私钥文件权限 0400，永不发送。
   - 服务端只保存公钥。没有任何全局共享密钥。
3. **上报验签与防重放**
   - 签名串（UTF-8，`\n` 分隔，末尾无换行）：
     ```
     wanglou-v1
     <node>
     <seq>
     <ts>
     <hex(sha256(body))>
     ```
   - 请求头：`X-Wanglou-Node`、`X-Wanglou-Seq`（uint64，十进制）、`X-Wanglou-Ts`（Unix 秒）、`X-Wanglou-Sig`（标准 base64 的 Ed25519 签名）。
   - 服务端校验顺序：请求体限长 64 KiB → 头部格式 → 节点存在且未吊销 → 签名 → `|now - ts| <= 60s` → `seq > last_seq`（持久化）→ 单节点限流（默认每秒 2 次，突发 5）。
   - 任何失败都返回无响应体的 4xx（401/400/413/429），不泄露失败原因；原因只写服务端日志并计数。成功返回 204。
4. **服务端不持有能控制 agent 的任何东西**：没有下行通道、没有命令队列、没有 WebSocket。
5. **最小依赖**：允许 `modernc.org/sqlite`（纯 Go，保证 `CGO_ENABLED=0`）和 `github.com/BurntSushi/toml`。其他第三方依赖需要先说明理由。

## 仓库结构

```
go.mod                      module wanglou
cmd/wanglou-agent/          agent 入口
cmd/wanglou-server/         服务端入口
internal/proto/             上报数据结构、签名串、Sign/Verify
internal/agent/             采集循环、上报客户端、配置、密钥
internal/agent/collect/     采集器；Linux 读 /proc，其他平台给可编译的桩实现
internal/server/ingest/     接收端 HTTP handler
internal/server/store/      SQLite 存储与迁移
internal/server/alert/      告警判定与通知（Telegram、Webhook）
deploy/systemd/             agent 与 server 的 systemd 单元
Makefile                    build / test / lint / cross-compile
```

## 第一阶段范围（本次）

### agent（`wanglou-agent`）

子命令：

- `init --name <node> --server <https-url> [--key /etc/wanglou/node.key] [--config /etc/wanglou/agent.toml]`：生成密钥（文件已存在则拒绝覆盖，除非 `--force`）、写配置，打印公钥（格式 `wanglou-ed25519 <base64> <node>`）和指纹（`SHA256:` + 无填充 base64 的公钥 SHA-256）。
- `fingerprint [--key ...]`：打印指纹。
- `run [--config ...]`：主循环，默认每 5 秒上报一次；`seq` 从当前 Unix 纳秒开始单调递增（重启后仍大于旧值）。网络失败指数退避，最长 60 秒，不丢弃 seq 单调性。
- `version`

上报 JSON（字段名固定，单位写在注释里）：

```json
{
  "v": 1,
  "cpu": 12.4,                 // 百分比，两次采样差值
  "load": [0.21, 0.18, 0.12],
  "mem": [812, 2048],          // MiB 已用 / 总量（已用 = total - available）
  "swap": [0, 512],            // MiB
  "disk": [18.2, 40.0],        // GiB，根分区 已用 / 总量
  "net": [1532, 8841],         // bytes/s 上行 / 下行，排除 lo 和常见虚拟网卡
  "net_total": [123456, 7890], // 累计字节 上行 / 下行（自开机，供流量统计）
  "conn": [41, 6],             // TCP / UDP 连接数
  "up": 864000,                // 秒
  "login": [{"u": "root", "from": "203.0.113.7", "t": 1761551990}],
  "bin": "sha256:<hex>",       // agent 自身可执行文件哈希，启动时算一次
  "os": "linux",
  "arch": "amd64"
}
```

- 采集只读 `/proc/stat`、`/proc/meminfo`、`/proc/loadavg`、`/proc/uptime`、`/proc/net/dev`、`/proc/net/tcp{,6}`、`/proc/net/udp{,6}`、`statfs("/")`、`/var/log/wtmp`（读不到时 `login` 为空，不报错）。
- `login` 只上报自上次上报以来的新记录（按 wtmp 记录时间去重）。
- 解析逻辑与文件读取分离，解析函数用 `testdata/` 里的样例文件做单元测试。

### 服务端（`wanglou-server`）

子命令：

- `serve [--config /etc/wanglou/server.toml]`：启动接收端（默认 `:8443`，支持 TLS 证书路径，或明确的 `--insecure-http` 仅用于本地开发）。
- `node add --name <node> --pubkey "<wanglou-ed25519 ...>"`：登记，打印指纹。
- `node list`：名称、指纹、状态、最近上报时间。
- `node revoke --name <node>`：吊销，之后该节点上报一律 401。
- `migrate`

存储（SQLite，WAL）：

- `nodes(name PK, pubkey, fingerprint, created_at, revoked_at, last_seq, last_seen, last_ip, bin_hash)`
- `metrics(node, ts, cpu, load1, load5, load15, mem_used, mem_total, swap_used, swap_total, disk_used, disk_total, net_tx, net_rx, net_total_tx, net_total_rx, tcp, udp, uptime)`，索引 `(node, ts)`
- `logins(node, ts, user, from_ip, known)`
- `events(id, ts, node, kind, detail, notified)`
- 原始数据保留 7 天的清理任务（降采样留到第二阶段）。

告警（`internal/server/alert`）：

- 失联：超过 3 个上报周期（默认 15 秒）没有成功上报 → `offline` 事件；恢复 → `recovered` 事件。
- 新登录：来源 IP 不在该节点的已知 IP 列表里 → `login_new_ip` 事件（首次接入时的 IP 视为已知）。
- 二进制变化：`bin` 与上次不同 → `bin_changed` 事件。
- 资源：内存或磁盘 ≥ 90% 持续 5 分钟 → `resource` 事件（阈值可配）。
- 通知器接口 `Notifier`，实现 Telegram（bot token + chat id）和通用 Webhook（POST JSON）。通知失败重试 3 次，不阻塞接收端。

### 部署文件

- `deploy/systemd/wanglou-agent.service`：`User=wanglou`，`NoNewPrivileges=yes`，`ProtectSystem=strict`，`ProtectHome=yes`，`PrivateTmp=yes`，`PrivateDevices=yes`，`CapabilityBoundingSet=`（空），`RestrictAddressFamilies=AF_INET AF_INET6`，`SystemCallFilter=@system-service`，`MemoryMax=24M`，`CPUQuota=5%`，`Restart=always`。
- `deploy/systemd/wanglou-server.service`：同等加固，`ReadWritePaths=/var/lib/wanglou`。

## Docker 部署（第一阶段补充）

目标：服务端一条命令起来（`cp .env.example .env` 填好域名后 `docker compose up -d`）；agent 推荐用二进制 + systemd，同时提供可选的容器方式。

### 镜像

- 根目录 `Dockerfile`，多阶段构建：`golang:1.26-alpine` 编译（`CGO_ENABLED=0 -trimpath -ldflags='-s -w'`），运行阶段用 `gcr.io/distroless/static-debian12:nonroot`。
- 两个构建目标：`--target server`（只含 `wanglou-server`）和 `--target agent`（只含 `wanglou-agent`）。各自只放自己的二进制。
- 以 uid 65532 运行，不需要任何 capability，兼容只读根文件系统。
- `.dockerignore` 排除 `.git`、`bin`、`docs/design`、数据库和密钥文件。

### 服务端在容器里的配置

- 配置文件变为可选：支持环境变量覆盖，命名 `WANGLOU_<KEY 大写>`（如 `WANGLOU_DATABASE`、`WANGLOU_TELEGRAM_TOKEN`）。环境变量优先于文件；未知的 `WANGLOU_*` 变量报错退出。
- 新增“反向代理后的明文模式”：`listen_plain = true` 必须同时配置 `trusted_proxies`（CIDR 列表），否则拒绝启动。只有当对端地址在 `trusted_proxies` 内时才读取 `X-Forwarded-For`，取最右侧不属于可信代理的地址作为客户端 IP；否则一律用 `RemoteAddr`。这个 IP 用于第 4 项的按 IP 限流和 `last_ip`。原有 `--insecure-http`（只允许回环地址）保持不变。
- 新增 `GET /healthz`：返回空响应体的 204，不查数据库以外的任何东西，不泄露版本信息。新增子命令 `wanglou-server healthcheck [--url http://127.0.0.1:8080/healthz]` 供容器健康检查使用（distroless 里没有 curl）。

### `deploy/docker/compose.yml`

- `caddy` 服务：官方镜像，自动申请 HTTPS 证书，只对外暴露 80/443；`Caddyfile` 把 `${DOMAIN}` 反代到 `wanglou-server:8080`。
- `wanglou-server` 服务：不对外暴露端口，只在内部网络；`read_only: true`、`cap_drop: [ALL]`、`security_opt: [no-new-privileges:true]`、`mem_limit: 256m`；数据卷挂到 `/data`（数据库 `/data/wanglou.db`）；健康检查用 `healthcheck` 子命令；`trusted_proxies` 设为 compose 内部网络网段。
- `deploy/docker/.env.example`：`DOMAIN`、`ACME_EMAIL`、`WANGLOU_TELEGRAM_TOKEN`、`WANGLOU_TELEGRAM_CHAT_ID`、`WANGLOU_WEBHOOK_URL`，以及镜像来源变量（默认本地构建，可改为拉取预构建镜像）。
- 登记节点：`docker compose exec wanglou-server wanglou-server node add --name ... --pubkey "..."`，写进 README。
- 另附一份不带 Caddy、使用自有证书的说明（挂载证书文件）。

### agent 容器（可选）

- agent 配置新增 `proc_root`（默认 `/proc`）、`root_fs`（默认 `/`，用于 statfs）、`wtmp_path`（默认 `/var/log/wtmp`），`init` 命令支持对应参数。
- `deploy/docker/agent.compose.yml`：`network_mode: host`（让 `/proc/net/dev` 反映宿主网络）、`pid: host`，只读挂载 `/proc:/host/proc:ro`、`/:/host/root:ro`、`/var/log/wtmp:/host/wtmp:ro`，状态目录（密钥、seq、登录游标）挂到 `/var/lib/wanglou`；`read_only: true`、`cap_drop: [ALL]`、`no-new-privileges`。
- 生成密钥用一次性命令：`docker run --rm -v <state>:/var/lib/wanglou <agent-image> init --name ... --server ...`，私钥写在挂载目录里，权限 0400，属主 65532。
- 容器方式下 agent 仍然不监听端口、不执行命令；`make check-agent-surface` 继续通过。

### CI

- `.github/workflows/ci.yml`：push 和 PR 时运行 `go vet`、`go test`、`make check-agent-surface`、`make check-files`。
- `.github/workflows/docker.yml`：推送 `v*` 标签或 main 分支时构建 `linux/amd64`、`linux/arm64` 两个架构的 server 和 agent 镜像，推到 Docker Hub：`docker.io/<DOCKERHUB_USERNAME>/sand-monitor-server` 和 `sand-monitor-agent`。
  - 凭据只来自仓库 Secrets：`DOCKERHUB_USERNAME`、`DOCKERHUB_TOKEN`（Docker Hub 访问令牌，不是密码）。工作流里不写死任何用户名。
  - Secrets 不存在时（例如 fork 或 PR）只构建不推送，工作流不失败。
  - 标签：`v1.2.3` → `1.2.3`、`1.2`、`latest`；main 分支 → `edge` 和 `sha-<短哈希>`。
  - 工作流权限 `contents: read`；第三方 action 固定到具体版本（`docker/setup-qemu-action`、`docker/setup-buildx-action`、`docker/login-action`、`docker/metadata-action`、`docker/build-push-action`）。
- `deploy/docker/.env.example` 的镜像来源默认指向 Docker Hub：`WANGLOU_SERVER_IMAGE=zengxiang1/sand-monitor-server:latest`、`WANGLOU_AGENT_IMAGE=zengxiang1/sand-monitor-agent:latest`；compose 同时保留 `build:`，没有预构建镜像时可本地构建。

### 验收

- `docker build --target server .` 和 `--target agent .` 成功，镜像里只有对应的一个二进制。
- `docker compose -f deploy/docker/compose.yml config` 校验通过。
- 新增测试：环境变量覆盖与未知变量报错；`listen_plain` 缺少 `trusted_proxies` 时拒绝启动；`X-Forwarded-For` 只在可信代理下生效、伪造的头被忽略；`/healthz`；agent 的 `proc_root`/`root_fs`/`wtmp_path`。
- README 增加“Docker 一键部署”章节：服务端 3 步起来，agent 两种方式（推荐 systemd，备选容器）。

## 不在第一阶段

面板 Web 界面和登录、续费与流量、公开状态页、降采样。接口和表结构不要提前为它们做过度设计，但 `net_total` 要存下来。（面板见下方“第二阶段”。）

## 验收标准

1. `go vet ./...` 和 `go test ./...` 全部通过；`CGO_ENABLED=0 GOOS=linux GOARCH=amd64` 和 `arm64` 都能编译出两个二进制。
2. agent 二进制（stripped）不超过 8 MB。
3. 静态检查：`cmd/wanglou-agent` 与 `internal/agent/...` 的依赖闭包里没有 `os/exec`、`net.Listen*`、`net/http` 的服务端用法。提供 `make check-agent-surface` 自动检查（用 `go list -deps` + grep 即可）。
4. 测试覆盖：签名正确/错误、篡改请求体、时间戳过期、seq 重放与回退、未登记节点、已吊销节点、限流、请求体超限、各 /proc 解析函数、失联与恢复判定、新 IP 登录判定。
5. 端到端测试：用 `httptest` 起接收端，真实 agent 上报客户端签名发送，数据落库可查。
6. `README.md`：本地开发运行步骤（macOS 上可用桩采集器跑通全流程）、部署步骤、安全模型一段话。

---

# 第二阶段：面板 Web 界面

范围：登录 + TOTP、总览、节点详情、接入节点。界面以 `docs/design/Main.dc.html`、`Node.dc.html`、`Enroll.dc.html` 为准（布局、配色、文案、信息层级）。“续费与流量”“公开页”属于后续阶段：本阶段导航里不显示这两项，总览里的“7 天内到期”“流量超过 80%”两块也不做。

第一阶段的全部安全约束继续有效。面板的定位是**只读面板**：面板上的任何操作只改服务端数据库里的记录，没有任何代码路径会连接、登录或控制 agent。

## 架构

- 同一个 `wanglou-server` 进程，开第二个监听端口给面板。接收端和面板的 handler、端口完全分开：接收端端口上访问面板路径返回 404，反之亦然。
- 新包 `internal/server/panel/`：路由、认证、会话、CSRF、页面数据查询。模板和静态资源放在 `internal/server/panel/web/`，用 `embed` 编进二进制。
- 只用标准库：`html/template` 服务端渲染，`net/http` 1.22+ 的方法路由，`crypto/pbkdf2`（Go 1.24+ 标准库）做口令哈希，TOTP 自己按 RFC 6238 实现（HMAC-SHA1，6 位，30 秒）。**不新增任何第三方依赖。**
- 前端不用框架、不加载任何外部资源（不用 Google Fonts，换成系统字体栈；不用 CDN）。图表在服务端算好坐标，用 `html/template` 输出内联 SVG。
- 自动刷新：一段很小的、放在 `/static/` 下的 JS，每 5 秒请求同一页面的片段版本（例如 `?fragment=1`），用服务端渲染好的 HTML 替换容器内容。JS 不得用数据字符串拼 HTML。页面不开 JS 也能完整显示，只是不会自动刷新。
- 节点上报的所有字符串（登录用户名、来源 IP、bin 哈希、os/arch 等）一律视为攻击者可控，只能经 `html/template` 自动转义输出，不能出现在 `template.HTML`、`template.JS`、`template.URL` 等不转义类型里。

## 配置（新增键，环境变量 `WANGLOU_<KEY>` 同样适用）

| 键 | 默认 | 说明 |
|---|---|---|
| `panel_listen` | 空（不启用面板） | 例如 `:8081`。启用后同进程开面板端口。 |
| `public_ingest_url` | 空 | 接入页里显示给用户复制的接收端地址，例如 `https://monitor.example.com`。为空时显示占位符。必须是 https，`--insecure-http` 时才允许 http。 |
| `panel_cookie_secure` | `true` | 只有在 `--insecure-http` 下才允许设为 `false`。 |

传输方式跟随接收端：配置了 TLS 证书则面板也用同一张证书走 TLS；`listen_plain` 时面板也是明文并用同一份 `trusted_proxies` 解析客户端 IP（逻辑与接收端一致，抽成共用函数，不要复制粘贴）；`--insecure-http` 时 `panel_listen` 也必须绑定回环地址。`panel_listen` 与 `listen` 相同时拒绝启动。

## 管理员账号（命令行）

账号只能在服务器上用命令行创建，面板里没有注册入口。

- `wanglou-server admin add --user <name> [--password-stdin]`：默认生成 24 位随机口令并打印一次；`--password-stdin` 从标准输入读一行（至少 12 个字符）。同时生成 TOTP 密钥（20 字节随机数，base32 无填充），打印密钥和 `otpauth://totp/wanglou:<user>?secret=...&issuer=wanglou&algorithm=SHA1&digits=6&period=30`。
- `admin passwd --user <name> [--password-stdin]`：重置口令。
- `admin reset-totp --user <name>`：重置 TOTP 密钥。
- `admin list`：用户名、创建时间、最近登录时间。不输出任何哈希或密钥。
- `admin remove --user <name>`。
- `passwd`、`reset-totp`、`remove` 都会让该用户的全部会话立即失效。
- 用户名规则同节点名（`proto.ValidNode`）。

## 认证与会话

- 登录表单一次提交用户名、口令、6 位验证码。任何失败都只显示同一句“用户名、口令或验证码错误”，HTTP 状态一致，并且不存在的用户也要跑一次同等成本的哈希比对，避免靠耗时判断用户是否存在。
- 口令：PBKDF2-HMAC-SHA256，60 万次迭代，16 字节随机盐。存储格式自描述（算法、迭代次数、盐、哈希），比对用常量时间。
- TOTP：接受当前步长及前后各 1 步；同一用户已用过的步长（含更早的）一律拒绝（持久化 `totp_last_step`），防止验证码重放。
- 限速（内存实现即可）：同一 IP 15 分钟内失败 5 次后返回 429；同一用户名 15 分钟内失败 10 次后锁定该用户 15 分钟。锁定期间即使输入正确也拒绝，提示文案不变。
- 会话：32 字节随机令牌放在 Cookie 里；数据库只存令牌的 SHA-256。Cookie 名 `__Host-wanglou_session`，`Secure; HttpOnly; SameSite=Strict; Path=/`，不设 Domain。`panel_cookie_secure=false` 时改名为 `wanglou_session` 并去掉 `Secure`。空闲 12 小时失效，绝对有效期 7 天。登录成功时签发新令牌（防会话固定）。登出删除服务端会话。
- CSRF：所有改变状态的请求只用 POST。每个会话一个随机 CSRF 令牌，放在表单隐藏字段里，服务端常量时间比对。另外所有 POST（包括登录）都要校验 `Origin` 头：必须存在且主机部分与请求 `Host` 一致，否则 403。
- 未登录访问页面重定向到 `/login`；访问片段或其他非页面请求返回 401。只有 `/login` 和 `/static/*` 免登录。
- 所有面板响应带安全头：
  - `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`
  - `X-Content-Type-Options: nosniff`、`Referrer-Policy: same-origin`、`X-Frame-Options: DENY`（不能用 `no-referrer`：按 Fetch 规范，那样浏览器提交同源表单时 `Origin` 会变成 `null`，所有 POST 都会被来源校验拒绝）
  - 登录后的页面 `Cache-Control: no-store`
  - 因此模板里**不能有内联 `<script>`、内联事件属性和 `style=""` 属性**，设计稿里的内联样式要改写成 `/static/` 下的样式表。
- 审计：登录成功/失败、登出、吊销、启用节点、静音、确认事件、标记常用 IP、生成注册码，写入 `audit_log(ts, user, ip, action, detail)`。登录失败同时写服务端日志（不记录提交的口令和验证码）。

## 页面

所有页面共用设计稿的页头：品牌名、导航（总览 / 节点详情 / 接入节点）、“只读面板 · 无下行通道”标识、当前用户、登出按钮。页脚保留“这个面板只读取节点主动上报的数据，无法连接、登录或控制任何服务器。”

### 总览 `GET /`

- 统计卡：服务器总数、在线、失联、告警中（resource 告警处于 active 的节点数）。
- 未确认的 `login_new_ip` 事件横幅（设计稿里的“有一次新的 SSH 登录”）：显示节点、用户、时间、来源 IP；按钮“是我本人，忽略”（`POST /events/{id}/ack`，只确认这条事件）和“查看节点”。多条时逐条列出，最多 5 条，其余显示数量。
- 服务器表：节点名、备注（位置与配置）、状态、CPU 近 2.5 分钟迷你折线（最近 30 个点，服务端 SVG）、内存、磁盘、网络上下行速率、最近上报（相对时间）。状态：正常 / 告警 / 失联 / 从未上报 / 已吊销。已吊销的节点排在最后并淡化。
- 最近事件：最近 20 条，显示时间、类型（中文）、节点、描述。标注已配置的通知渠道名称（“Telegram”“Webhook”），不显示 chat id、token、URL。
- 接收端统计：自进程启动以来接受的上报数、按原因分类的拒收数（来自 ingest handler 的内存计数器，新增一个只读的 `Stats()` 方法）。

### 节点详情 `GET /nodes/{name}?range=1h|24h|7d`

- 头部：名称、状态、备注、最近上报 IP、上报周期、最近上报时间。
- 静音：`POST /nodes/{name}/mute`，可选 1 小时 / 8 小时 / 24 小时 / 取消静音。静音期间事件照常记录和显示，但不推送（分发器把这些事件标为已处理，不调用通知器）。头部显示“告警已静音至 HH:MM”。
- 吊销：确认步骤（单独的确认页或 `<details>`，不能靠 JS `confirm()`），文案用设计稿的原文；`POST /nodes/{name}/revoke` 调用与命令行相同的 `store.Revoke`。
- 备注编辑：`POST /nodes/{name}/note`，最多 64 个字符。
- 关键指标卡：CPU、负载、内存、Swap、磁盘、连接数、运行时长。
- 历史图：CPU、内存、磁盘、网络上下行。按所选时间范围在 SQL 里分桶取平均，每条曲线最多 360 个点；7 天范围也要在 200 ms 内出图（节点 5 秒一条数据，7 天约 12 万行，测试里要构造这个量级）。
- 身份与完整性：公钥指纹、agent 二进制哈希、os/arch、登记时间、最近上报 IP。
- 登录记录：最近 50 条，列：时间、用户、来源 IP、判断（常用 / 新 IP）。设计稿里的“终端”列不做（agent 不采集）。对新 IP 提供“将 x.x.x.x 标为常用”（`POST /nodes/{name}/known-ip`），之后该 IP 的登录不再告警。

### 接入节点 `GET /enroll`

流程按设计稿三步走：

1. **安装并生成密钥**：输入节点名（校验规则同 `proto.ValidNode`）和选填备注，页面显示可复制的命令，节点名和 `public_ingest_url` 已填好，例如 `sudo wanglou-agent init --name <name> --server <url>`。
2. **把公钥交给面板**，两种方式二选一：
   - 粘贴公钥：`POST /enroll/preview` 解析 `wanglou-ed25519 ...` 行（公钥行里的名称必须与节点名一致），不写库，进入第 3 步。
   - 一次性注册码：`POST /enroll/codes` 生成 `XXXX-XXXX` 格式的码（字母表去掉易混字符，至少 40 bit 熵），10 分钟有效，只能成功使用一次。库里只存码的 SHA-256。页面显示码、剩余时间和要在服务器上运行的 `sudo wanglou-agent enroll <码>`，并通过片段刷新等待 agent 提交。
3. **核对指纹后启用**：把指纹按设计稿分组显示，必须勾选“两边的指纹完全一致”才能提交 `POST /enroll/confirm`。提交时服务端再次校验节点名未被占用、注册码未过期、公钥未被替换（表单里带的公钥必须与库里/预览时的一致），然后调用 `store.AddNode` 并写入备注。成功后显示“已启用，正在等待第一次上报”。

在第 3 步之前，节点不存在于 `nodes` 表，接收端对它的上报一律 401。也就是说，注册码就算被猜中，攻击者也只能提交一把待审核的公钥，管理员核对指纹时会发现不一致。

#### 注册码的接收端与 agent 部分

- 接收端新增 `POST /enroll`（在接收端端口上，不在面板端口上）。请求体 JSON `{"code":"K7QF-29XM","pubkey":"wanglou-ed25519 <base64> <name>"}`，限长 4 KiB。走与上报相同的按 IP 预认证限流，另加单 IP 每分钟 10 次的限制。码不存在、过期、已用、名称不匹配都返回无响应体的 4xx（统一 400 或 404，不区分原因）；成功 204。没有任何有效注册码时直接 404。
- agent 新增子命令 `enroll <CODE> [--config ...]`：读取本地配置里的接收端地址和私钥路径，计算公钥行，POST 到 `<server>/enroll`，只看状态码，204 时打印指纹并提示去面板核对，其他状态打印“注册失败”。复用现有上报客户端的 HTTPS 要求、`--insecure-http` 规则、超时和丢弃响应体逻辑。`make check-agent-surface` 必须继续通过。

## 存储变更（迁移到 `user_version=3`，要能从第一阶段的库原地升级）

- `nodes` 加列：`note TEXT NOT NULL DEFAULT ''`、`os TEXT NOT NULL DEFAULT ''`、`arch TEXT NOT NULL DEFAULT ''`、`muted_until INTEGER NOT NULL DEFAULT 0`。`Accept` 时更新 `os`、`arch`（各截断到 32 字节）。
- `events` 加列：`acked_at INTEGER NOT NULL DEFAULT 0`。
- 新表：`admins(user PK, pw_hash, totp_secret, totp_last_step, created_at, last_login)`、`sessions(token_hash PK, user, csrf, created_at, last_seen, ip)`、`enroll_codes(code_hash PK, name, note, created_at, expires_at, pubkey, used_at)`、`audit_log(id, ts, user, ip, action, detail)`。
- 清理任务：删除过期会话和超过 1 天的注册码；`audit_log` 保留 90 天。

## Docker 与文档

- `compose.yml`：`wanglou-server` 增加 `WANGLOU_PANEL_LISTEN: ":8081"`、`WANGLOU_PUBLIC_INGEST_URL: https://${DOMAIN}`。
- `Caddyfile` 增加 `{$PANEL_DOMAIN} { reverse_proxy wanglou-server:8081 }`；`.env.example` 增加 `PANEL_DOMAIN`，注释建议把面板放在 Cloudflare Access、Tailscale 或 Caddy `basic_auth` 后面。
- README：创建管理员（`docker compose exec wanglou-server wanglou-server admin add --user admin`），把密钥添加到验证器 App，访问面板；本地开发时如何同时跑接收端和面板；agent 用注册码接入的步骤。
- `docs/SPEC.md` 本节即规格，代码与它不一致时以本节为准，有偏离要在交付说明里列出。

## 第二阶段验收

1. 第一阶段全部验收项继续通过（`make check`）。
2. 不新增第三方依赖；`go.mod` 的 require 列表不变。
3. 新增 `make check-panel-assets`：`internal/server/panel/web/` 下没有 `http://`、`https://` 外链（`otpauth://` 等非网络协议、SVG 命名空间除外），模板里没有内联 `<script>` 内容、`on*=` 事件属性和 `style=` 属性。并入 `make check`。
4. 测试至少覆盖：
   - RFC 6238 附录 B 的 SHA1 测试向量；TOTP 前后一步窗口；同一步长重放被拒。
   - PBKDF2 哈希生成与校验，错误口令失败。
   - 登录：错误口令、错误验证码、不存在的用户都返回相同响应；IP 限速 429；用户锁定期间正确凭据也失败；成功后 Cookie 属性正确、会话令牌轮换。
   - 会话：空闲超时、绝对超时、登出后令牌失效、`admin passwd` 后旧会话失效。
   - 每一个需要登录的路由未登录时被拒（页面重定向、片段 401），用路由表遍历测试，不要逐个手写漏掉。
   - CSRF：缺少令牌、令牌错误、`Origin` 缺失或不同源都返回 403。
   - 所有面板响应都带上述安全头。
   - XSS：上报的登录用户名为 `<script>alert(1)</script>`、`"><img src=x onerror=1>` 时，节点页和总览输出中只出现转义后的文本。
   - 面板吊销后，同一节点的签名上报返回 401。
   - 注册码：生成、agent 提交成功、过期、重复使用、名称不匹配、未确认前上报 401、确认后上报 204、确认时篡改公钥被拒。
   - 历史图分桶：12 万行数据下 7 天范围点数不超过 360，耗时在测试里断言。
   - 迁移：用第一阶段 schema 建的库能升级到 v3，原有数据保留。
   - 面板端口与接收端端口路由互不可见。
5. 端到端（我会亲自做）：本地 `--insecure-http` 起接收端和面板，`admin add` 建号，用生成的密钥算验证码登录，用注册码接入一台本机 agent，在浏览器里核对三个页面与设计稿一致，并确认自动刷新、静音、吊销、标记常用 IP 都按预期工作。

---

# 第三阶段：续费与流量、公开状态页

范围：续费与流量页、总览里的“续费与流量”区块和行内标签、公开页设置、公开状态页导出、外部心跳。界面以 `docs/design/Billing.dc.html`、`PublicSettings.dc.html`、`Status.dc.html` 和 `Main.dc.html` 里的“续费与流量”区块为准（布局、配色、文案、信息层级）。面板导航改为：总览 / 节点详情 / 续费与流量 / 公开页 / 接入节点。

前两阶段的全部安全约束和面板约束（CSP、无内联样式/脚本、CSRF + Origin、审计、只用标准库）继续有效。另加两条：

1. **agent 不改。** 本阶段不改 `cmd/wanglou-agent`、`internal/agent/...`、`internal/proto`。到期日、价格、额度只存在面板数据库里，已用流量由服务端根据每次上报的 `net_total` 累加。
2. **公开页是导出的静态文件。** `wanglou-server` 不为公开页提供任何 HTTP 路由：不在接收端端口上，也不在面板端口上。服务端按设置定时把 `index.html`、`status.json`、`status.css` 写进一个目录，由独立的静态文件服务器（compose 里是 Caddy `file_server`）对外提供。导出内容只能来自专门的白名单结构体，**不得直接序列化 `store.Node` 或任何存储层结构**。公开页所在的机器（或容器）没有面板账号、接收端和任何密钥，被攻破最多只能篡改这一页的显示内容。

## 配置（新增键，环境变量同样适用）

| 键 | 默认 | 说明 |
|---|---|---|
| `timezone` | `Local` | IANA 时区名，例如 `Asia/Shanghai`。到期日、重置日、按天统计的可用率、09:00 的提醒时间都按这个时区算。服务端 `import _ "time/tzdata"`，容器里没有时区库也能用。名字无效则拒绝启动。 |
| `public_dir` | 空（不导出） | 公开页导出目录。为空时公开页设置仍可编辑，但页面上提示“未配置 public_dir，不会导出”。 |
| `public_url` | 空 | 公开页的访问地址，只用于在设置页显示和拼出带口令的链接。必须是 https，`--insecure-http` 时才允许 http。 |
| `heartbeat_url` | 空（不启用） | 外部心跳地址（Healthchecks 一类服务）。必须是 https，`--insecure-http` 时才允许 http。 |

## 存储变更（迁移到 `user_version=4`，第一阶段和第二阶段的库都要能原地升级）

- `billing(node TEXT PRIMARY KEY REFERENCES nodes(name), provider TEXT NOT NULL, expiry TEXT NOT NULL, cycle TEXT NOT NULL, currency TEXT NOT NULL, price TEXT NOT NULL, auto_renew INTEGER NOT NULL, quota_gb INTEGER NOT NULL, reset_day INTEGER NOT NULL, direction TEXT NOT NULL, remind_days TEXT NOT NULL, remind_pct TEXT NOT NULL, predict INTEGER NOT NULL, notify TEXT NOT NULL, updated_at INTEGER NOT NULL)`
  - 取值和校验：
    - `expiry`：`YYYY-MM-DD` 或空。
    - `cycle`：`month|quarter|half|year|once`。
    - `currency`：`CNY|USD|EUR`。
    - `price`：匹配 `^\d{1,7}(\.\d{1,2})?$`，或者为空。
    - `quota_gb`：0 到 10000000 的整数，0 表示不限。
    - `reset_day`：0 到 28，0 表示跟随到期日。
    - `direction`：`both|out|in|max`。
    - `remind_days`：逗号分隔，取值是 `30,14,7,3,1` 的子集。
    - `remind_pct`：逗号分隔，取值是 `50,80,90,95,100` 的子集。
    - `notify`：逗号分隔，取值是 `telegram,webhook` 的子集。空表示只记录、不发送。
    - `provider`：最多 64 个字符。
- `traffic(node TEXT PRIMARY KEY REFERENCES nodes(name), cycle_start TEXT NOT NULL, used_tx TEXT NOT NULL, used_rx TEXT NOT NULL, adjust TEXT NOT NULL, last_tx TEXT NOT NULL, last_rx TEXT NOT NULL, last_up REAL NOT NULL, first_seen INTEGER NOT NULL)`
  - 无符号计数按十进制字符串存，`adjust` 是有符号整数。
  - 所有节点都记账，不管有没有账单信息。
- `daily(node TEXT NOT NULL REFERENCES nodes(name), day TEXT NOT NULL, tx TEXT NOT NULL, rx TEXT NOT NULL, online INTEGER NOT NULL, PRIMARY KEY(node, day))`：按 `timezone` 的本地日期统计。
- `reminders(node TEXT NOT NULL, key TEXT NOT NULL, ts INTEGER NOT NULL, channels TEXT NOT NULL, PRIMARY KEY(node, key))`：提醒去重和已发送记录。
- `kv(key TEXT PRIMARY KEY, value TEXT NOT NULL)`：存公开页的 `public.draft`、`public.published`、`public.exported_at`。
- `events` 加列 `targets TEXT NOT NULL DEFAULT ''`。
- 清理任务：`daily` 保留 60 天，`reminders` 保留 400 天。

## 流量与在线时长记账（在 `Accept` 的同一个事务里）

- **增量**：每个方向分别计算。
  - 第一次上报只记基线，增量为 0，同时写 `first_seen`。
  - 之后，如果 `report.Up >= last_up` 且计数没有变小，增量 = 当前值 − 上次值。
  - 否则视为重启，增量 = 当前值。
  - 单次增量超过 1 TB（10^12 字节）视为异常，记为 0，只更新基线。
  - 累加用饱和加法，不能溢出。
- 增量加到 `traffic.used_*`，同时加到当天的 `daily.tx/rx`。
- **计费口径** `counted`：
  - `both` = tx + rx
  - `out` = tx
  - `in` = rx
  - `max` = max(tx, rx)

  在此基础上再加 `adjust`，结果小于 0 时按 0 算。GB 一律按 10^9 字节（和服务商口径一致），1000 GB 显示为 1 TB。
- **周期**：
  - 周期起点是本地日期中“不晚于今天、且日号等于重置日”的最近一天，时间取 00:00。
  - `reset_day=0` 时，重置日取到期日的日号。月份没有那么多天时取当月最后一天。
  - 没有账单信息的节点按自然月算（每月 1 日）。
  - 发现周期起点变了，就把 `used_tx`、`used_rx`、`adjust` 清零并更新 `cycle_start`。有账单信息的节点同时记一条 `traffic_reset` 事件，`notified=1`，即“只记录，不发送”。
  - 这个滚动逻辑抽成一个函数，上报时和定时检查时都会调用。
- **校准**：管理员填写“本周期已用 X GB”时，令 `adjust = X·10^9 − 按当前口径算出的已用量`，之后在这个值上继续累加。
- **在线时长**：
  - 如果上一次上报距今不超过 `3 × 上报周期`，把这段间隔计入 `daily.online`。间隔跨越本地零点时，按零点拆到两天。
  - 否则这段间隔算作离线，不计入。
- **每天的可用情况**：
  - 观测时长 = 当天与 `[first_seen, 现在]` 的重叠时长。
  - 离线时长 = 观测时长 − 在线时长。
  - 判定：
    - 观测时长为 0：无数据。
    - 离线不超过 60 秒：全天在线。
    - 离线少于 1 小时：短暂中断。
    - 其余：中断超过 1 小时。
  - 45 天可用率 = 在线总和 ÷ 观测总和，向下保留 2 位小数，完全相等时显示 `100%`；没有观测数据时显示 `—`。

## 提醒（服务端每 60 秒检查一次）

判定写成纯函数，输入是账单、流量和当前时间，输出是应发的提醒，单独测试。只处理未吊销、并且有账单信息的节点。

- **到期提醒（手动续费）**：
  - 到期前 N 天（N 取自 `remind_days`）提醒一次，文案：“还有 N 天到期，需要手动续费”。
  - 到期当天必定提醒一次：“今天到期”。
  - 到期后第 1 天提醒一次：“已过期 1 天，记得续费”。
  - 去重键 `exp:<到期日>:<N>`，到期当天 N=0，过期 N=-1。改了到期日就会重新开始提醒。
- **自动续费**：
  - 忽略 `remind_days`，只在到期前 3 天提醒一次：“3 天后自动扣费（<价格>），确认余额”。去重键 `auto:<到期日>`。
  - 到期日过后的第二天 00:00 起，周期不是 `once` 的，到期日自动顺延一个周期。同时记 `billing` 事件，`notified=1`，文案“已按自动续费顺延到 YYYY-MM-DD”，并写审计。
- **触发时间**：按日期触发的提醒，在当天本地时间 09:00 之后的第一次检查发出。服务端整天没运行就跳过这一天，**不补发过期日期的提醒**。
- **流量阈值**：
  - 条件：`quota_gb > 0`，并且本周期用量百分比 ≥ `remind_pct` 里某个阈值，且该阈值还没提醒过。
  - 去重键 `pct:<cycle_start>:<阈值>`。
  - 同一次检查中如果跨过多个阈值，只发最高的那一条，较低的阈值一并标记为已发。
  - 文案：“本周期流量用到 90%（930 GB / 1 TB）”。
  - 流量提醒随时可发，不等 09:00。
- **预测**：
  - 条件：`predict=1`、`quota_gb > 0`，并且还没用满。
  - 速度 = 最近 3 个完整本地日里有数据的那几天的计费用量之和 ÷ 天数。一个完整日都没有时不预测。
  - 预计用完时间早于下次重置时，每个周期提醒一次，去重键 `pred:<cycle_start>`。文案：“按现在的速度 MM-DD 用完，MM-DD 才重置”。
  - 页面上的预测文字（表格和总览共用一个函数）：
    - 节点失联：“节点失联，统计暂停”。
    - 会在重置前用完：“按现在的速度 MM-DD 用完”。
    - 其他情况：“预计重置前用到 N%”。
    - 数据不足：不显示。
- **发送**：
  - 一条提醒写成一个事件，`kind` 为 `billing` 或 `traffic`，`targets` 等于账单里的 `notify`。`reminders` 行在同一个事务里写入。
  - `notify` 为空时，事件直接写 `notified=1`。
  - 分发器的 `Notifier` 接口加 `Kind() string`（`telegram` / `webhook`）。`targets` 非空时只投递给列出的渠道，其他渠道视为已处理。`targets` 为空的旧事件行为不变。
  - `billing`、`traffic` 事件**不受节点静音影响**；静音只针对告警。
  - 事件类型的中文名：`billing` → 续费，`traffic` 和 `traffic_reset` → 流量。

## 外部心跳

- 配置了 `heartbeat_url` 时，每 60 秒对它发一次 GET，不带任何数据。
- 前提：离线检查和提醒检查都在最近 2 分钟内成功跑过。任一卡住就停止心跳，让外部服务报警。
- 请求超时 10 秒，不跟随重定向，响应体限长读取后丢弃。
- 总览的接收端卡片增加“外部心跳”一行：显示“N 分钟前”“未配置”或“失败（N 分钟前成功过）”。地址本身不显示。

## 页面：续费与流量 `GET /billing`（`?edit=<node>` 打开编辑器）

- **说明文字**：照抄设计稿，右侧显示“今天 YYYY-MM-DD”（本地时区）。
- **统计卡**：
  - 7 天内到期：0 ≤ 剩余天数 ≤ 7。副标题列出最多 2 台，格式“name 还剩 N 天”。
  - 流量超过 80%：副标题“name 93% · name 81%”，最多 2 台。
  - 30 天内要续费：副标题“其中 N 台已开自动续费”。
  - 未来 7 天提醒：副标题“下一条：MM-DD name”。
- **服务器表**：
  - 包含所有未吊销节点，按到期日升序，没设到期日的排最后。
  - 列：节点 + 服务商；到期日 + 剩余天数标签；续费方式（“月付 ¥58”和“自动续费 / 手动续费”）；本周期流量（“已用 / 额度”、SVG 进度条、百分比），下面一行周期说明（“每月 N 日重置 · 上下行合计 · <预测文字>”）。
  - 不限额度的节点显示“不统计额度，只记录用量”。
  - 没有账单信息的节点显示“未设置”，但仍显示已用流量。
  - 剩余天数标签：
    - 小于 0：“已过期 N 天”，红色。
    - 等于 0：“今天到期”。
    - 不超过 3：红色。
    - 不超过 7：黄色。
    - 其余：灰色。
  - 进度条颜色：≥95% 红，≥80% 黄。
  - “编辑”是链接 `?edit=name#editor`。
- **编辑器**：`POST /billing/{name}`，字段和分组按设计稿（账单 / 流量 / 提醒规则）：
  - 服务商。
  - 到期日：`<input type=date>`，可留空。
  - 续费周期。
  - 每期价格：币种下拉加数字。
  - 自动续费：复选框，附设计稿说明文字。
  - 每周期额度（GB）。
  - 每月重置日：1 到 28 加“跟随到期日”。
  - 计费方式。
  - 校准本周期已用（GB）：选填，留空表示不改。占位符显示当前已用量。
  - 到期前提醒和流量提醒：复选框组。
  - 预测提醒：复选框。
  - 发送到：只列出已配置的渠道（Telegram / Webhook），一个都没配置时显示“未配置任何通知渠道”。设计稿里的“邮件”不做。

  保存后重定向到 `?edit=name&saved=1`，显示“已保存，提醒已按新规则重新排期”。校验失败返回 400，重新渲染表单，保留已填的值并显示错误。“放弃修改”是回到 `?edit=name` 的链接。
- **已续费一期**：`POST /billing/{name}/renewed`，到期日加一个周期。月份加法按月末截断，例如 01-31 加一个月是 02-28 或 02-29。`once` 周期不显示这个按钮。
- **提醒日程**：
  - 内容是两部分合在一起，按时间排序，最多 30 行：
    - 过去 24 小时已发送的提醒，取自 `reminders`。状态显示“已发送 · Telegram、Webhook”或“已记录 · 未选择渠道”。
    - 未来 14 天按日期可预见的提醒：到期提醒、自动续费提醒、周期重置（“流量周期重置，用量清零 · 只记录，不发送”），以及会触发的预测提醒（“预计 MM-DD 用完流量 · 预测提醒”）。
  - 底部文字照抄设计稿。没配置心跳时追加“（当前未配置外部心跳）”。
- **审计**：保存账单、校准、已续费一期、自动顺延都写 `audit_log`。

## 总览变更（`GET /`）

- 在统计卡和登录横幅之后、服务器表之前，加入设计稿的“续费与流量”区块：
  - 左栏“7 天内到期”：包含已过期的节点，最多 5 条。文案示例“10-30 到期 · 季付 $15 · 手动续费”。
  - 右栏“流量超过 80%”：最多 5 条。文案示例“930 GB / 1 TB · <预测文字>”。
  - 两栏各有空状态文案（“7 天内没有要续费的服务器”“没有流量超过 80% 的服务器”）。
  - 一条账单信息都没有时，区块里只显示“还没有设置账单信息，去设置 →”。
- 服务器表的节点名旁加标签：
  - “N 天后到期”：0 到 7 天，≤3 天红色，否则黄色。
  - “已过期”。
  - “流量 N%”：≥80%，≥95% 红色。

## 页面：公开页设置 `GET /public`

- **草稿与发布**：
  - 全部设置是一份 JSON 文档 `PublicConfig`：标题、导出间隔、访问方式、口令、字段开关、节点列表（内部名、是否公开、显示名）、公告列表。
  - 存两份：`public.draft` 和 `public.published`。两份不同时显示“有未发布的修改……”。
  - “保存并发布”把草稿复制为发布版，并立即触发一次导出。
- **页头**：
  - 发布状态标签（“已发布 / 未发布”）。
  - `public_url`，没配置时显示“未配置 public_url”。
  - “上次导出 HH:MM”或“从未导出”。
  - “预览公开页”链接。
  - “保存并发布”按钮：用 `form=` 属性提交主表单，带 `publish=1`。
- **主表单** `POST /public`（保存草稿；带 `publish=1` 时同时发布）：
  - 公开哪些节点：列出所有未吊销节点，列为“公开”复选框、内部名、公开显示名输入框、当前状态。
    - 显示名最多 32 个字符，勾选公开时必填。
    - 当前状态的“注意”标签旁加说明“公开页显示正常”。
    - 新接入的节点默认不公开。
  - 显示哪些信息：字段开关和说明文字照设计稿，但去掉“地区”这一项：显示名里自己写城市即可，少一个字段少一份泄露。
    - 配置：说明改为“内存和磁盘大小”，因为 agent 不采集 CPU 核数，本阶段也不改 agent。
    - CPU / 内存 / 磁盘占用。
    - 网络速率。
    - 运行时长。
    - 45 天可用率。
    - 离线提示。
  - 始终不公开：静态列表，照抄设计稿。
  - 基本设置：
    - 页面标题：最多 40 个字符，默认“服务器状态”。
    - 导出间隔：30 秒 / 1 分钟 / 5 分钟，附设计稿说明。
    - 访问方式：“任何人可访问”或“带口令的链接”。选口令方式时显示完整链接，并提供“更换口令”按钮（`POST /public/token`）。口令是 16 字节随机数的 base64url（22 个字符）。
- **公告**（单独的表单，改的都是草稿）：
  - 新增或编辑：`POST /public/announcements`，编辑时带 `id`；`?edit_ann=<id>` 时把表单填好。
  - 字段：
    - 标题：最多 80 个字符。
    - 相关节点：下拉列出公开节点的显示名，外加“全部 / 不指定”。
    - 状态：排查中 / 已修复，观察中 / 已恢复 / 计划维护 / 维护完成。
    - 时间：`datetime-local`，默认当前时间。
    - 内容：最多 1000 个字符。
  - 标题或内容为空时提示“填写标题和内容后才能添加。”
  - 最多 100 条。
  - 删除：`POST /public/announcements/{id}/delete`。确认步骤用 `<details>`，文案“删除后公开页上也会消失，不能恢复。”，按钮“保留 / 删除公告”。
- **预览**：`GET /public/preview` 用导出用的同一个模板渲染草稿和当前数据，在面板内展示（走面板 CSP，样式用 `/static/status.css`），页面顶部加一条“预览 · 未发布”。
- **底部说明**：照抄设计稿“公开页怎么生成”一段。
- **审计**：保存草稿、发布、增删改公告、更换口令都写 `audit_log`。

## 公开页导出（新包 `internal/server/public/`）

- **触发**：配置了 `public_dir` 且存在发布版时，按发布版的间隔导出，最短 30 秒。发布后立即导出一次。导出完成后写 `public.exported_at`。
- **输出位置**：
  - 公开访问时写在 `public_dir/` 下：`index.html`、`status.json`、`status.css`。
  - 口令访问时写在 `public_dir/<token>/` 下，同时删除 `public_dir/` 下这三个文件，根路径就没有内容。
  - 输出位置变了（换口令或改访问方式）时，删除旧位置的这三个文件，旧口令目录如果空了就 `os.Remove`。**不得使用 `os.RemoveAll`，不删除其他任何文件**。只把匹配 `^[A-Za-z0-9_-]{22}$` 的目录名当作口令目录。
- **写入方式**：先写同目录下的临时文件，再 rename。目录权限 0755，文件权限 0644。
- **页面内容**（`index.html`）：
  - 用 `html/template` 预先渲染，带 `<meta http-equiv="refresh" content="<间隔秒数>">`。
  - 没有任何 JS，没有内联样式和脚本，没有外部资源，使用系统字体。进度条和可用率格子用 SVG 属性画。
  - 布局和文案照 `Status.dc.html`：
    - 标题，以及“更新于 HH:MM · 每 30 秒刷新”。
    - 汇总横幅：“N 台正常运行，M 台离线”，全部正常时为“全部 N 台正常运行”。
    - 离线说明：开了离线提示时是“<显示名> 从 HH:MM 起没有响应。”，否则只列出显示名。
    - 正常 / 离线计数。
    - 每台服务器一张卡片：显示名、配置、状态、三项占用、离线说明、↑↓ 速率、运行时长、45 格可用率和图例、“45 天前 可用率 X 今天”。每个格子用 `<title>` 写明“MM-DD 全天在线 / 短暂中断（N 分钟）/ 中断 N 小时 M 分 / 无数据”。
    - 公告（有公告时才显示）。
    - 页脚“本页只展示运行状态，不包含 IP、服务商、账单和登录信息。由望楼生成”。
  - 字段开关关掉的内容，在 HTML 和 JSON 里都不出现。
- **状态与取值**：
  - 公开页的状态只有 `正常` 和 `离线`。资源告警算正常；失联或从未上报算离线。
  - 已吊销的节点即使勾选了公开也不导出。节点按显示名排序。
  - 取值精度：
    - 占用：整数百分比。
    - 速率：保留 2 位有效数字。
    - 运行时长：向下取整到天（“已运行 N 天”），离线时改为“离线 N 分钟 / N 小时”（只在开了离线提示时显示）。
    - 内存：小于 4 GB 时按 0.5 GB 取整，否则取整数 GB。
    - 磁盘：取整数 GB。
  - 生成时间截断到导出间隔。
- **`status.json`**（版本 1，字段关掉时省略）：
  ```json
  {"v":1,"title":"服务器状态","generated":"2026-10-27T14:32:00+08:00","interval":30,
   "summary":{"ok":6,"offline":1},
   "nodes":[{"name":"香港 · 01","status":"ok","specs":{"mem_gb":2,"disk_gb":40},
     "usage":{"cpu":14,"mem":41,"disk":46},"net":{"tx":1500000,"rx":8600000},
     "uptime_days":12,"offline_since":"2026-10-27T14:29:00+08:00",
     "availability":{"pct":"99.98","days":[{"date":"2026-09-13","state":"ok","down_s":0}]}}],
   "announcements":[{"time":"2026-10-27T14:35:00+08:00","title":"…","node":"北京 · 01","status":"investigating","body":"…"}]}
  ```
  - `name` 是显示名。
  - `state` 取值：`ok|partial|down|none`。
  - 公告的 `node` 是相关节点的显示名。相关节点已经不公开时省略这个字段。
  - **内部节点名不得出现在任何导出文件里**。

## Docker 与文档

- **Dockerfile**：server 镜像创建 `/public`，属主为运行用户（与 `/data` 一样），这样只读根文件系统加命名卷也能写入。
- **`compose.yml`**：
  - `wanglou-server` 增加环境变量：
    - `WANGLOU_PUBLIC_DIR: /public`
    - `WANGLOU_PUBLIC_URL: https://${STATUS_DOMAIN:-status.localhost}`
    - `WANGLOU_TIMEZONE: ${WANGLOU_TIMEZONE:-UTC}`
    - `WANGLOU_HEARTBEAT_URL: ${WANGLOU_HEARTBEAT_URL:-}`

    并挂载卷 `status_public:/public`。
  - `caddy` 以只读方式挂载 `status_public:/srv/status:ro`，并增加 `STATUS_DOMAIN: ${STATUS_DOMAIN:-status.localhost}`。默认值是 `.localhost`，不会去申请证书。
- **`Caddyfile`**：
  ```
  {$STATUS_DOMAIN} {
  	root * /srv/status
  	file_server
  	header {
  		Content-Security-Policy "default-src 'none'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
  		X-Content-Type-Options nosniff
  		Referrer-Policy no-referrer
  		-Server
  	}
  }
  ```
  不开 `browse`。
- **`.env.example`**：增加 `STATUS_DOMAIN`、`WANGLOU_TIMEZONE`（示例 `Asia/Shanghai`）、`WANGLOU_HEARTBEAT_URL`，全部附注释。
- **README**：
  - 续费与流量的用法。
  - 公开页的安全模型：静态导出，可以用 rsync 或对象存储同步到另一台机器。
  - 外部心跳配置。
  - 时区说明。
- **`make check-panel-assets`**：同样检查公开页模板和 `status.css`（放在 `internal/server/public/web/`）。

## 第三阶段验收

1. 前两阶段的全部验收项继续通过（`make check`）。`go.mod` 的 require 列表不变。
2. `git diff` 中 `cmd/wanglou-agent`、`internal/agent`、`internal/proto` 没有改动。
3. 测试至少覆盖：
   - **迁移**：v1 和 v3 的库升级到 v4，原有数据保留。
   - **流量记账**：正常增量、重启（uptime 变小、计数变小）、首次基线、超过 1 TB 的异常增量、饱和加法、四种计费口径、校准、周期滚动（含重置日 31 号在 2 月、跟随到期日、自然月）、跨零点拆分在线时长。
   - **可用率**：四种日状态的判定、45 天汇总、`first_seen` 之前算无数据。
   - **提醒纯函数**：
     - 到期前 N 天、当天、过期 1 天；09:00 之前不发；不补发错过的日期。
     - 自动续费只在前 3 天提醒，以及自动顺延（含月末截断）。
     - 同一次检查跨过多个流量阈值时只发最高的一条。
     - 每周期只预测提醒一次；数据不足时不预测。
     - 改到期日后重新提醒；去重键不重复。
   - **分发器**：`targets` 只投递给指定渠道；`notify` 为空时不发送；`billing`/`traffic` 不受静音影响；旧事件行为不变。
   - **续费页**：表单校验（非法日期、价格、阈值、渠道等返回 400）、保存、已续费一期、`once` 周期没有该按钮。
   - **公开页导出**：
     - **泄露测试**：节点名、IP、服务商、备注、指纹、bin 哈希、os/arch、登录用户名都设成独特的标记字符串，导出后在全部导出文件中搜索，一个都不能出现；字段开关关掉后，对应数据在 HTML 和 JSON 里都不出现。
     - 未公开和已吊销的节点不导出。
     - 口令模式：根目录没有页面；换口令后旧目录里的文件被清除，旧目录之外的文件不受影响；不匹配口令格式的目录永不删除。
     - 原子写入（失败时不留下半个文件）。
     - XSS：显示名、公告标题和内容里的 `<script>` 只以转义形式出现。
   - **公开页设置**：草稿与发布、显示名必填、公告增删改及上限、预览在面板 CSP 下正常渲染。
   - **路由**：新路由全部被第二阶段的路由表认证测试覆盖；接收端端口和面板端口上都没有公开页路由。
   - **心跳**：后台循环卡住时停止发送。
4. **端到端（我会亲自做）**：
   - 本地起服务端，接入 agent，在续费页编辑账单。
   - 用测试时钟或改数据验证提醒出现在提醒日程和事件里。
   - 发布公开页，在浏览器里分别打开导出文件和预览，与设计稿核对。
   - 切换口令模式，确认旧链接失效。
   - 跑一遍泄露检查（grep 导出目录）。

---

# 第四阶段：降采样与长期保留、事件可读性、吊销名称重新接入

前三个阶段的全部约束继续有效。**agent 和 `internal/proto` 仍然不改**，`go.mod` 的 require 列表不变。

## 降采样与保留

### 配置

| 键 | 默认 | 说明 |
|---|---|---|
| `retention_days` | `90` | 小时级数据、事件、登录记录保留的天数，取值 7 到 3650，超出范围拒绝启动。 |

### 存储（迁移到 `user_version=5`）

- 新建两张表 `metrics_1m` 和 `metrics_1h`，结构相同：
  ```
  node TEXT NOT NULL REFERENCES nodes(name), ts INTEGER NOT NULL,
  samples INTEGER NOT NULL,
  cpu REAL, cpu_max REAL, load1 REAL,
  mem_used REAL, mem_total REAL, swap_used REAL, swap_total REAL,
  disk_used REAL, disk_total REAL,
  net_tx REAL, net_rx REAL, net_tx_max REAL, net_rx_max REAL,
  tcp REAL, udp REAL,
  PRIMARY KEY(node, ts)
  ```
- `ts` 是桶的起点，按 Unix 时间对齐到整分钟或整点。
- 平均值字段取桶内平均，`*_max` 取桶内最大值，`samples` 是原始样本数。
- 小时桶由分钟桶生成，平均值按 `samples` 加权。
- 进度水位存在 `kv` 里：`rollup.1m` 和 `rollup.1h`，值是下一个待处理的桶起点。
  - 首次运行时，水位取对应源表最早的 `ts` 向下对齐后的值。
  - 源表为空时，水位取当前时间对齐后的值。

### 汇总任务（服务端每 60 秒运行一次）

- 只汇总已经结束的桶：分钟桶要求 `桶起点 + 60 <= now − 60`，留 1 分钟余量；小时桶同理。
- 用 `INSERT ... ON CONFLICT(node,ts) DO UPDATE`，重复执行结果相同（幂等）。
- 每个事务最多处理 6 小时的分钟桶，或者 7 天的小时桶，做完提交一次，循环直到追上当前时间，避免长时间占锁阻塞上报。
- 升级后第一次运行会把已有的原始数据补算进去。
- 汇总任务也纳入外部心跳的健康判定：卡住超过 5 分钟就停止心跳。

### 清理（改写现有 Cleanup）

- **原始 `metrics`**：保留 48 小时。
- **`metrics_1m`**：保留 14 天。
- **`metrics_1h`**、**`events`**、**`logins`**：保留 `retention_days` 天。
- **任何表都不能删掉还没汇总进下一级的数据**：
  - 原始数据只删 `ts < min(48 小时前, rollup.1m 水位)` 的部分。
  - 分钟数据只删 `ts < min(14 天前, rollup.1h 水位)` 的部分。
- `daily`、`reminders`、`audit_log` 的保留规则不变。

### 节点详情的历史图

- 时间范围改为 `1h | 24h | 7d | 30d | 90d`。只显示不超过 `retention_days` 的范围，请求超出的范围时回落到 `24h`。
- 各范围的数据源：

  | 范围 | 数据源 |
  |---|---|
  | 1h | 原始 `metrics` |
  | 24h | `metrics_1m` |
  | 7d | `metrics_1m` |
  | 30d | `metrics_1h` |
  | 90d | `metrics_1h` |

- 仍然在 SQL 里分桶，每条曲线最多 360 个点。
- 最近一段还没汇总的时间，用原始数据补上，保证图的右端不缺数据。
- 图表区说明文字标出精度：“数据精度：5 秒 / 1 分钟 / 1 小时”。
- **性能要求**：
  - 90d：构造 90 天的小时数据（约 2160 行），出图不超过 200 ms。
  - 7d：构造 7 天的分钟数据（约 1 万行），出图不超过 200 ms。
  - 两项都在测试里断言。
- 总览的迷你折线、最新指标、公开页、告警引擎继续读原始数据，行为不变。

### 文档

README 写明保留策略和数据库体积估算：每台节点约多少 MB，按 5 秒上报间隔、90 天保留计算，数字用测试库实测得出。

## 事件文案可读性

- 告警引擎新写入的事件 `detail` 改用中文、可读的格式：
  - `offline`：“最近一次上报 YYYY-MM-DD HH:MM:SS”（按 `timezone`）；从未上报过的写“从未上报”。
  - `recovered`：“重新开始上报，离线 X”，X 是离线时长，格式“N 秒 / N 分 N 秒 / N 小时 N 分”，由上一次 `last_seen` 计算。
  - `bin_changed`：“agent 二进制变化：<旧哈希> → <新哈希>”。
  - `login_new_ip`：“<用户> 从 <IP> 登录（首次出现的 IP）”。
  - `resource`：“内存超过 90%，已持续 5 分钟”或“磁盘超过 90%，已持续 5 分钟”，阈值和持续时长取当前配置。
- **兼容旧数据**：面板展示事件时经过一个 `describeEvent(kind, detail)` 函数。它识别第一到第三阶段写入的旧英文格式（`last seen <unix>`、`<user> from <ip>`、`memory`/`disk`、`<old> -> <new>`），转换成上面的中文显示；无法识别的原样转义输出。
- **Telegram 消息**改为“望楼 · <节点> · <中文类型>：<detail>”。中文类型名和面板共用一张表。
- Webhook 的 JSON 结构不变。

## 吊销过的节点名可以重新接入

- 面板接入流程允许使用已吊销的节点名，涉及注册码生成、粘贴预览、确认三步。
- 名称属于已吊销节点时：
  - 第 1 步和第 3 步都显示：“这个名称之前被吊销过。启用后会换成新公钥，历史数据保留，旧公钥永远不能再用。”
  - 确认时在同一个事务里更新 `pubkey`、`fingerprint`，令 `revoked_at=0`，并更新备注。`created_at`、`last_seq` 和历史数据保留。`last_seq` 保留，所以旧 agent 的上报即使被重放也会被拒绝。
  - **新公钥与旧公钥相同时拒绝**，提示“不能复用已吊销的公钥”。
  - 审计动作记为 `node_reenable`。
- 名称属于**未吊销**的节点时仍然拒绝，行为不变。
- 接收端 `POST /enroll` 不需要改，名称校验仍然以注册码记录为准。
- 命令行 `node add` 保持原样，遇到已存在的名称一律拒绝；README 注明重新启用请走面板接入流程。

## 第四阶段验收

1. `make check` 和 `go test ./...` 通过；agent、proto、go.mod 都没有改动。
2. 测试至少覆盖：
   - 迁移：v4 升级到 v5；首次运行汇总时补算已有的原始数据。
   - 汇总：
     - 分钟和小时汇总的数值正确，包括平均值、最大值、按样本数加权。
     - 重复执行结果相同。
     - 未结束的桶不汇总。
     - 分批提交，并且分批的结果与一次性处理相同。
   - 清理：不会删掉未汇总的数据；各表按各自期限删除；`retention_days` 的配置校验。
   - 历史图：每个范围用对的数据源；点数不超过 360；最近未汇总的时间段用原始数据补齐；超出保留期的范围回落到 24h。另含上面两项性能断言。
   - 心跳：汇总任务卡住时停止心跳。
   - 事件文案：五种新格式；旧英文格式的兼容显示；无法识别的内容只做转义输出（XSS）；Telegram 消息格式。
   - 重新接入：
     - 吊销后用新公钥通过注册码和粘贴两种方式各接入一次成功；成功后新 agent 上报 204、旧 key 上报 401。
     - 复用旧公钥被拒。
     - 未吊销的名称仍然被拒。
     - 历史数据保留，并写了审计。
3. 端到端（我会亲自做）：
   - 用带历史数据的库升级，确认补算完成。
   - 在浏览器里看 30d 和 90d 历史图。
   - 吊销一个节点后，用同名重新接入。
   - 检查总览和节点页的事件文案。

---

# 第五阶段：双接收端

目标：agent 同时向两台互相独立的接收端上报。任意一台宕机，**或者被攻破**，另一台照样能收数据、发告警。

前四个阶段的约束继续有效。本阶段**允许修改 agent**，但第一阶段的“agent 只出不进”四条硬约束一条都不能放松：

- 不监听端口；
- 不执行外部命令；
- 不读响应体，只看状态码；
- 没有远程配置下发。

`make check-agent-surface` 必须继续通过，agent stripped 后仍然不超过 8 MB。上报协议（签名串 `wanglou-v1`、请求头、JSON 结构）**不变**，旧版 agent 和新版服务端互相兼容。

## 架构

- 两台接收端运行同一个 `wanglou-server` 二进制，各自有独立的数据库、节点登记、告警引擎和通知渠道。两台之间**没有任何信任关系，也不同步数据**。
- 备用端可以不开面板（`panel_listen` 留空），只承担接收和告警。
- 节点公钥要在两台接收端上分别登记；吊销也要在两台上分别执行。这是有意的设计：任何一台都无法替另一台做决定。
- 本阶段不做“备用端在主端正常时自动静默”。理由：被攻破的主端可以继续让健康检查返回正常、同时吞掉告警，这样备用端就会一直保持静默，等于失效。代价是两边都会推送告警，所以用“告警范围”和“实例名”来减轻重复推送的打扰。

## agent

### 配置

新增键 `backup_server`，选填。

- 校验规则与 `server` 相同：https，`insecure_http` 时才允许 http，不能带用户信息、查询串、片段。
- 不能与 `server` 相同。比较前规范化：scheme 和 host 转小写，去掉末尾的 `/`。
- `init` 新增参数 `--backup-server <url>`，写入配置文件。
- 不配置 `backup_server` 时，行为与旧版完全一致，旧配置文件不用改。

### 上报循环（重写 `agent.Run`）

- **采样**：采样器按 `interval` 定时采样，**每个周期只采一次**（CPU 和网速是按两次采样的差值算的）。采样不受任何一个目标的网络状况影响。
- **发送**：每个目标（主、备）各有一个独立的发送者：
  - 同一时刻只有一个请求在飞。
  - 有自己的退避状态，规则沿用 `Backoff`，最长 60 秒。
  - 采样完成时，空闲且不在退避中的发送者立即发送这份报告；正忙或在退避中的发送者跳过这个周期，不排队、不积压。
  - 一个目标超时（10 秒）或长期不可达，绝不能拖慢采样，也不能拖慢另一个目标的发送。
- **签名**：每个目标的请求在发送时单独签名，使用各自取到的 `seq`。
  - `seq` 由一个共享的计数器生成，加互斥锁，持久化方式不变。
  - 每个目标看到的 `seq` 严格递增，中间可以有跳号，接收端只要求 `seq > last_seq`。
- **登录记录**：每个目标有独立的游标。
  - 主目标继续使用现有的 `<state_file>.logins.json`，升级后旧游标原样沿用。
  - 备目标使用 `<state_file>.backup.logins.json`。第一次启用时只建立基线，不上传历史。
  - 发给某个目标的报告，只带该目标游标之后的登录记录；只有发给该目标成功（204）后，才推进该目标的游标。
  - 因此一台接收端停机期间发生的登录，在它恢复后仍会补报给它，而且完全不影响另一台。
- **采集器接口**：拆成三个函数，取代原来 `Sample` 一次返回全部内容、`Acknowledge` 不分目标的做法：
  - `Sample()`：只返回指标，不含登录记录。
  - `Logins(target)`
  - `Acknowledge(target)`
- **日志**：失败日志带目标名，例如“report to backup failed: status 401”。连续失败只在状态变化时，或者每 10 分钟打印一次，避免刷屏。

### 注册码

`enroll <CODE>` 新增 `--backup` 参数：带上时，把公钥提交到 `backup_server`，否则提交到 `server`。

## 服务端

### 配置（新增键）

| 键 | 默认 | 说明 |
|---|---|---|
| `instance_name` | `望楼` | 通知消息的前缀，最多 16 个字符。备用端建议设为 `望楼·备`。Telegram 消息变成“<instance_name> · <节点> · <类型>：<内容>”。Webhook 的 JSON 加 `"instance"` 字段，其余字段不变。 |
| `alert_scope` | `all` | `all` 或 `security`。`security` 时只推送 `offline`、`recovered`、`login_new_ip`、`bin_changed`；其他事件照常记录，但直接标为已处理，不推送。 |
| `peer_url` | 空 | 另一台接收端的公开地址，例如 `https://backup.example.com`。https，`--insecure-http` 时才允许 http，不能带用户信息、查询串、片段。 |
| `backup_ingest_url` | 空 | 只用于面板展示：拼出 `init --backup-server` 命令，提示备用端登记步骤。校验规则同 `public_ingest_url`。 |

### 对端检查

配置了 `peer_url` 时，服务端运行对端检查：

- 每 30 秒 `GET <peer_url>/healthz`，超时 10 秒，不跟随重定向，响应体限长读取后丢弃。2xx 算正常，其他算失败。
- 连续 4 次失败（约 2 分钟），判定对端不可达，**直接**通过已配置的通知渠道发一次“对端接收端 <host> 不可达”。
- 判定不可达后，对端第一次恢复正常时，发一次“对端接收端 <host> 已恢复”。
- 这两条消息不经过 `events` 表，因为 `events.node` 必须指向一个节点。改在检查循环里直接调用各通知器：每个通知器失败最多重试 3 次，失败只记日志。
- 这两条消息不受 `alert_scope` 影响，始终推送。
- 对端检查**只读 HTTP 状态码**，不解析任何内容，也不因为对端的状态改变本端的任何行为。
- 面板的接收端卡片增加一行“对端接收端”：显示“正常 · N 秒前”“不可达 · N 分钟”或“未配置”。显示 host，不显示完整 URL。

### 面板提示（只在配置了 `backup_ingest_url` 时显示）

- **接入第 1 步**：生成的命令带上 `--backup-server '<backup_ingest_url>'`。
- **接入成功页**：增加一段“还需在备用接收端登记同一公钥”，给出可复制的命令：
  ```
  wanglou-server node add --name <name> --pubkey '<公钥行>'
  ```
  并说明也可以在备用端的面板里接入，或者用 `wanglou-agent enroll <备用端注册码> --backup`。
- **吊销确认区**：加一句“备用接收端上也要吊销：`wanglou-server node revoke --name <name>`”。

### Docker

- 新增 `deploy/docker/backup.compose.yml`：只有 `caddy` 和 `wanglou-server`，不开面板，不导出公开页。
  - 环境变量预设：
    - `WANGLOU_INSTANCE_NAME=望楼·备`
    - `WANGLOU_ALERT_SCOPE=security`
    - `WANGLOU_PEER_URL=https://${PRIMARY_DOMAIN}`
  - `.env` 需要 `DOMAIN`（备用端自己的域名）和 `PRIMARY_DOMAIN`。
  - 对应的 Caddyfile（`backup.Caddyfile`）只反代接收端。
- 主端 `compose.yml` 增加两个可选环境变量：
  - `WANGLOU_PEER_URL: ${BACKUP_DOMAIN:+https://${BACKUP_DOMAIN}}`
  - `WANGLOU_BACKUP_INGEST_URL`，同上。

  `BACKUP_DOMAIN` 为空时，两者都为空。
- `make check` 里的部署文件检查同时覆盖 `backup.compose.yml`，`docker compose config` 要能通过。

### README

新增“双接收端”一节：

- 部署步骤：备用端最好放在另一家服务商。
- 节点双登记和双吊销的做法。
- 安全模型说明：备用端为什么不在主端正常时静默。
- 重复告警的处理方式（`alert_scope`、`instance_name`）。

## 第五阶段验收

1. `make check` 和 `go test ./...` 都通过；agent 二进制不超过 8 MB；`check-agent-surface` 通过；`go.mod` 不变；`internal/proto` 不变。
2. 测试至少覆盖：
   - **agent 配置**：`backup_server` 的校验，包括与 `server` 相同时拒绝（大小写、末尾斜杠）；不配置备用端时，旧配置照常工作。
   - **上报循环**：用 `httptest` 起两台假接收端。
     - 两台都收到签名正确、`seq` 递增的报告。
     - 一台一直超时或返回 500，另一台的上报节奏不受影响：在测试时钟或短周期下统计次数，与单目标时一样。
     - 宕机的一台恢复后，退避结束就恢复接收。
     - 每个周期只采样一次，即两个目标收到的指标来自同一次采样。
     - `seq` 在并发发送下不重复，持久化后重启仍然递增。
   - **登录游标**：备目标宕机期间发生的登录，恢复后补报给备目标，主目标不会收到重复的记录；旧版单游标文件升级后沿用；备游标首次启用时只建立基线。
   - **enroll `--backup`**：请求发往备用端。
   - **服务端**：
     - `alert_scope=security` 的事件过滤；
     - `instance_name` 出现在 Telegram 和 Webhook 消息里；
     - 对端检查：连续 4 次失败才告警，恢复只告警一次，非 2xx 算失败，不跟随重定向；
     - 面板对端状态行；
     - `backup_ingest_url` 出现时，接入页和吊销区的提示。
   - **配置校验**：`peer_url`、`backup_ingest_url`、`instance_name` 长度、`alert_scope` 取值。
3. **端到端（我会亲自做）**：
   - 本地起两台服务端（各自的数据库和端口），同一个 agent 配置主备两个地址，两边都能看到数据。
   - 停掉备用端，主端不受影响；备用端恢复后继续收数，期间的登录记录补报过去。
   - 停掉主端，备用端照常接收；主端上配置的 `peer_url` 指向备用端，备用端停掉时能检测到并告警（用本地 webhook 接收器验证）。

# 第六轮：实测修复

在 Docker（colima，Linux arm64）上部署主备两端和容器版 agent 实测后发现的问题。本轮只修问题，不加新功能；`internal/proto` 不变，agent 仍然不监听、不执行命令、不读响应体。

## 1. arm64 上 wtmp 解析错误（严重）

现状：agent 把 wtmp 记录固定按 384 字节解析，这是 x86_64 glibc 的布局。arm64 glibc 的 `struct utmp` 是 400 字节，时间字段是 64 位。实测 arm64 主机的 wtmp 大小是 400 的倍数，agent 读到的全是错位数据，真实 ssh 登录完全没被采集，"新 IP 登录"告警在 ARM 服务器上失效，而且没有任何报错。

arm64 布局（已用真实 wtmp 验证）：

| 字段 | 偏移 | 类型 |
|---|---|---|
| ut_type | 0 | int16 |
| ut_pid | 4 | int32 |
| ut_line | 8 | 32 字节 |
| ut_id | 40 | 4 字节 |
| ut_user | 44 | 32 字节 |
| ut_host | 76 | 256 字节 |
| ut_exit | 332 | 2 个 int16 |
| ut_session | 336 | int64 |
| tv_sec | 344 | int64 |
| tv_usec | 352 | int64 |
| ut_addr_v6 | 360 | 16 字节 |
| 保留 + 对齐 | 376 | 共 24 字节，总长 400 |

amd64 布局不变：384 字节，tv_sec 在 340（int32），addr_v6 在 348。

要求：
- 记录布局按编译目标的 GOARCH 选择：amd64 用 384，arm64 用 400。可以用 build tag，也可以用常量表。其他架构沿用 384 的行为，不额外支持。
- `decodeWTMP`、`ParseWTMP`、增量游标（偏移、批量读取）都用同一个记录长度常量，不能再出现硬编码的 384。
- 游标兼容：已有游标文件的 `offset` 不是当前记录长度的整数倍时（arm64 用户升级后必然如此），不要拒绝启动。按"首次安装"处理：在文件当前末尾重新建立基线，不上传历史，并打印一行日志说明重建了基线。游标文件本身损坏（JSON 无法解析）时也同样处理，不再让 agent 起不来。
- 测试：在测试里用代码生成两种布局的记录作为数据（不要提交真实 wtmp 文件），覆盖解析、增量读取、主备两个游标，以及旧的 384 对齐游标在 400 布局下重建基线。

## 2. 新登记的节点马上报"失联 · 从未上报"

现状：命令行 `node add` 或面板接入后，agent 还没开始上报（通常还在装或在退避），过了 3 个上报周期（15 秒）就会产生一条"失联 · 从未上报"事件并推送，几秒后又推一条"恢复 · 首次开始上报"。每接一台机器都会收到两条误报。

要求：
- 从未上报过的节点（`last_seen = 0`）在登记后 10 分钟内不产生失联事件；超过 10 分钟仍未上报，只产生一次"失联 · 从未上报"。
- 吊销后重新接入的节点，按重新启用的时间算这 10 分钟，不能因为旧的 `last_seen` 立刻报失联。如果重新启用时没有更新可用的时间字段，就在重新启用时把 `last_seen` 清零、`created_at` 更新为启用时间，并说明理由。
- 已上报过的节点逻辑不变（3 个周期 + 进程启动宽限期）。
- 面板上从未上报的节点状态文字不变。

## 3. 一个通知渠道坏了，会拖住所有告警

现状：`Dispatcher.Run` 每秒取最早的 32 条未完成事件，逐条对每个渠道最多重试 4 次（间隔 1/2/4 秒）。如果某个渠道一直失败（例如 Telegram token 填错），这 32 条永远完不成：后面的新事件永远取不到，连正常的 Webhook 也收不到；每一轮还要卡几分钟。另外，没有配置任何渠道时，事件一直是未通知状态；之后再配置渠道，会把几个月的历史事件一次性推出去。

要求：
- 某条事件在某个渠道上失败后，这个"事件 + 渠道"进入退避（例如 30 秒起，每次翻倍，最长 10 分钟），退避期间不再尝试。退避状态放在内存里即可，重启后从头开始。
- 取待发事件时，跳过所有"仍需发送的渠道都在退避中"的事件，保证新事件能及时发出。失败的渠道不能拖慢其他渠道和后续事件：同一轮里，一次失败的发送最多花一次尝试的时间，不再在一轮里连续重试 4 次。
- 事件产生超过 24 小时还没发完的，放弃发送，标记为已通知，打一行日志（事件 id、渠道）。面板上的事件列表不受影响。
- 没有配置任何渠道时，事件直接标记为已通知，这样之后配置渠道也不会补发历史。`alert_scope` 的过滤行为不变。
- 测试：一个永远失败的渠道加一个正常渠道，连续产生 40 条事件，正常渠道在测试时间内收到全部 40 条；失败渠道按退避重试，不是每秒都重试；超过 24 小时的事件被放弃；没有渠道时事件直接标记为已通知。

## 4. 自动续费的月底日期漂移

现状：`Advance` 用"上一次到期日"的日期往后推，并按月底截断。1 月 31 日到期的月付机器会变成 2 月 28 日，之后一直是 28 日（3 月 28 日、4 月 28 日……）。比实际扣费日早 3 天，"3 天后自动扣费"的提醒就提前了。`ResetDay` 在没设重置日时取到期日的日期，所以流量重置日也会跟着漂。另外，到期日如果已经过去好几个周期，每分钟只推进一个周期，每次都产生一条事件。

要求：
- `billing` 表新增锚定日（例如 `anchor_day`，取值 1–31）。每次在面板保存到期日时，记录这个日期的"日"。迁移时用现有到期日的"日"回填。
- 自动顺延用锚定日计算：每个月取 `min(锚定日, 当月天数)`。示例：1 月 31 日 → 2 月 28 日（闰年 29 日）→ 3 月 31 日。
- `ResetDay` 在没设重置日时也用锚定日，不用当前到期日。
- 一次检查里直接推进到"今天前 1 天之后"的第一个到期日，只产生一条"已按自动续费顺延到 X"事件，只写一条审计记录。
- 测试：1 月 31 日月付连续推进一年；2 月 29 日年付；季付、半年付；过期 5 个周期一次追平；迁移回填。

## 5. 小问题

- **公开页网速格式**：公开页把 440 B/s 显示成 `4.4e+02 B/s`，999 B/s 显示成 `1e+03 B/s`。改成和面板一致的格式（例如 `440 B/s`、`13 KB/s`、`1.2 MB/s`），面板和公开页最好共用一个函数。
- **公开页运行时长**：运行不到 1 天时显示"已运行 0 天"，改成"已运行不到 1 天"。`status.json` 的字段不变。
- **节点详情页标题行**：备注为空时开头多了一个"· "。各段为空时不要输出多余的分隔符。
- **agent 恢复日志**：现在只打印失败，不打印恢复，看日志会以为一直是坏的。某个目标在失败后第一次发送成功时，打印一行"report to primary recovered after N failures"（或 backup）。

## 已在本轮由验收方直接修改

- `go.mod` 的 `go` 指令从 1.26.0 提到 1.26.10，`golang.org/x/sys` 升级到 v0.49.0。本机 Go 1.26.3 编出的二进制会带上 22 个已公开的标准库漏洞（`govulncheck` 结果）；提高最低版本后，旧工具链会自动下载修复版本。升级后 `govulncheck ./...` 没有发现漏洞。

### 验收中追加的修改（验收方直接完成）

- **对端状态**：之前连续检查失败但还没到 4 次时，面板仍显示"正常 · N 秒前"。现在显示"连续 N 次检查失败"。
- **面板时区**：容器默认时区是 UTC，面板里的登录记录、事件时间和图表坐标轴都显示成 UTC，没有使用 `timezone` 配置。现在服务端启动时把进程的 `time.Local` 设为配置的时区。
- **锚定日兜底**：新增 `Billing.Anchor()`。锚定日不合法时，用当前到期日的"日"代替，避免 `AddMonths` 收到 0 时把日期推回上个月，导致追平循环无法结束。
- **延迟送达的 Telegram 消息附上发生时间**：新的调度器会并发投递不同事件，渠道恢复后，同一节点的消息到达顺序可能和发生顺序不一致。按节点串行投递又违背"慢渠道不拖累其他渠道"的要求，所以改为：事件超过 60 秒才送达时，在消息末尾加上"（发生于 MM-DD HH:MM）"。Webhook 原本就带有 `ts` 字段。

## 第六轮验收

1. `make check`、`go test -race ./...` 通过；`govulncheck ./...` 无漏洞；agent 不超过 8 MB；`internal/proto` 不变。
2. 上面每一项都有对应的测试。
3. 端到端（验收方做）：在 arm64 Linux 虚拟机里用容器版 agent，真实 ssh 登录能被主备两端采集；备用端停机期间的登录在恢复后补报；新登记节点 10 分钟内不报失联；公开页网速格式正确。
