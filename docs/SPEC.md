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

## 不在本阶段

面板 Web 界面和登录、续费与流量、公开状态页、降采样。接口和表结构不要提前为它们做过度设计，但 `net_total` 要存下来。

## 验收标准

1. `go vet ./...` 和 `go test ./...` 全部通过；`CGO_ENABLED=0 GOOS=linux GOARCH=amd64` 和 `arm64` 都能编译出两个二进制。
2. agent 二进制（stripped）不超过 8 MB。
3. 静态检查：`cmd/wanglou-agent` 与 `internal/agent/...` 的依赖闭包里没有 `os/exec`、`net.Listen*`、`net/http` 的服务端用法。提供 `make check-agent-surface` 自动检查（用 `go list -deps` + grep 即可）。
4. 测试覆盖：签名正确/错误、篡改请求体、时间戳过期、seq 重放与回退、未登记节点、已吊销节点、限流、请求体超限、各 /proc 解析函数、失联与恢复判定、新 IP 登录判定。
5. 端到端测试：用 `httptest` 起接收端，真实 agent 上报客户端签名发送，数据落库可查。
6. `README.md`：本地开发运行步骤（macOS 上可用桩采集器跑通全流程）、部署步骤、安全模型一段话。
