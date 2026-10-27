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
