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
  - `X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`、`X-Frame-Options: DENY`
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
