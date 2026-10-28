# wanglou · 望楼

A small, outbound-only VPS monitor. Phase 1 provides signed telemetry ingestion,
SQLite storage, CLI enrollment and alerts. Phase 2 adds a separate web panel with
password + TOTP login, history charts and fingerprint-confirmed enrollment.
Go 1.26 or later is required. The only direct third-party dependency is
`modernc.org/sqlite`; its required transitive modules are recorded in go.mod/go.sum.
All binaries build with `CGO_ENABLED=0`.

## Local development (including macOS)

```sh
make build
mkdir -p .cache/demo
cat > .cache/demo/server.toml <<'CONFIG'
database = ".cache/demo/wanglou.db"
listen = "127.0.0.1:8443"
interval = "5s"
memory_threshold = 90
disk_threshold = 90
resource_duration = "5m"
CONFIG

bin/wanglou-server migrate --config .cache/demo/server.toml
bin/wanglou-agent init --name dev-node --server http://127.0.0.1:8443 \
  --insecure-http --key .cache/demo/node.key \
  --config .cache/demo/agent.toml --state .cache/demo/agent.seq
```

Copy the **public key line** printed by init (never the private key file), then:

```sh
bin/wanglou-server node add --config .cache/demo/server.toml --name dev-node \
  --pubkey 'wanglou-ed25519 <base64-public-key-from-init> dev-node'
bin/wanglou-agent fingerprint --key .cache/demo/node.key
bin/wanglou-server node list --config .cache/demo/server.toml
# Terminal 1:
bin/wanglou-server serve --config .cache/demo/server.toml --insecure-http
# Terminal 2:
bin/wanglou-agent run --config .cache/demo/agent.toml
# Terminal 3, after a report:
bin/wanglou-server node list --config .cache/demo/server.toml
```

The server's explicit development HTTP mode requires a loopback bind IP.
On macOS and other non-Linux systems the collector returns zero readings, the
actual OS/architecture, process uptime and the executable hash; this runs the
same signing, ingestion and database path. Stop either process with Ctrl-C.
`init` refuses to overwrite keys/configs unless `--force` is present.

## Configuration

Both configuration files use flat TOML keys. Supported syntax: quoted
single-line strings (including literal single-quoted strings), decimal numbers,
booleans, blank lines and `#` comments. Unknown or duplicate keys and unsupported
syntax are errors. The only array setting is `trusted_proxies`, a single-line
array of quoted CIDRs. Tables, other arrays, multiline strings and TOML date types
are not supported. Configuration is read locally, once at startup.

Agent defaults: `/etc/wanglou/agent.toml`, `/etc/wanglou/node.key`, 5 seconds.
The generated configuration contains:

```toml
name = "hk-01"
server = "https://monitor.example.com:8443"
key = "/etc/wanglou/node.key"
state_file = "/var/lib/wanglou/agent.seq"
interval = "5s"
insecure_http = false
proc_root = "/proc"
root_fs = "/"
wtmp_path = "/var/log/wtmp"
```

The agent reserves and fsyncs every sequence before sending. The next value is
`max(current Unix nanoseconds, previous + 1)`, preserving monotonicity across
network failures, restarts and clock rollback. Preserve the state file and run
one agent process per identity/state file. Network failures back off exponentially
from 1 second to 60 seconds; successful reports restore the configured interval.
Login state is stored next to `state_file`, with suffix `.logins.json`, and is
atomically written and fsynced. With no cursor, the newest wtmp login timestamp
and current byte offset form the baseline; historical logins are never uploaded.
Later reports include at most 32 logins, with the backlog sent in following
reports. The byte offset advances only after a 204 response. Restarts resume
from the saved cursor, including logins written during downtime. Rotation or
truncation restarts reading at byte zero and uses the saved timestamp plus
`(timestamp, user, IP)` boundary identities to suppress duplicates without
losing distinct logins in the same second. Preserve both state files.

Server defaults: `/etc/wanglou/server.toml`, `:8443`,
`/var/lib/wanglou/wanglou.db`. A production example:

```toml
database = "/var/lib/wanglou/wanglou.db"
listen = ":8443"
panel_listen = ":8444"
public_ingest_url = "https://monitor.example.com:8443"
panel_cookie_secure = true
tls_cert = "/etc/wanglou/tls/fullchain.pem"
tls_key = "/etc/wanglou/tls/privkey.pem"
interval = "5s"
memory_threshold = 90
disk_threshold = 90
resource_duration = "5m"
retention_days = 90
# Optional notifications (omit to retain events without sending):
# webhook_url = "https://hooks.example.com/wanglou"
# telegram_token = "bot-token"
# telegram_chat_id = "chat-id"
# telegram_api_base = "https://api.telegram.org"
```

The server configuration file is optional. Every server key can be overridden
with `WANGLOU_<UPPERCASE_KEY>`; environment values win, including empty strings.
Strings and durations are unquoted in the environment, booleans use `true`/`false`,
and `WANGLOU_TRUSTED_PROXIES` is a comma-separated CIDR list. Unknown `WANGLOU_*`
variables cause startup to fail. For a proxy deployment, set `listen_plain = true`
and a nonempty `trusted_proxies = ["172.30.0.0/24"]`; otherwise use TLS.
`--insecure-http` still requires a loopback IP, even with `listen_plain` enabled.
`GET /healthz` checks SQLite availability and returns empty 204 (503 if unavailable).
`wanglou-server healthcheck --url http://127.0.0.1:8080/healthz` exits successfully
only on 204, with a three-second timeout. It needs no configuration file.

Administration commands take `--config` after the subcommand, e.g.
`wanglou-server node revoke --name hk-01 --config /etc/wanglou/server.toml`.
`migrate` is idempotent; all server commands also ensure the schema exists.
Server `interval` must match the reporting interval used by the nodes; offline
means strictly more than three intervals without an accepted report.

Notifications run in a background worker using persisted `events` as a queue.
Each failed send has three retries (four total attempts) with exponential delay;
exhausted events remain pending for subsequent worker passes/restarts. Successful
delivery marks the event notified only after all configured destinations succeed.
Per-destination receipts in `event_deliveries` persist each confirmed success;
other destinations failing or a dispatcher restart will not resend it. Notifier
identities are stable hashes of their destination settings, independent of
configuration order. As with any external HTTP delivery, a crash after remote
acceptance but before the receipt commits, or an ambiguous transport failure,
can still cause a duplicate; this is not a transactional exactly-once protocol. No network calls occur while the ingestion transaction is held.

## Linux deployment

Build artifacts with `make cross-compile`. On each host create an unprivileged
`wanglou` system user/group and directories `/etc/wanglou` and `/var/lib/wanglou`.
Install the appropriate binary as root-owned mode 0755 in `/usr/local/bin/`.
Give `wanglou` ownership of `/var/lib/wanglou` (0700); keep `/etc/wanglou` and
configuration root-owned, with directory mode 0750 and config mode 0640 readable
by group `wanglou`.

For the agent, run `init --name ... --server https://...` on that VPS as an
administrator, then set `/etc/wanglou/node.key` owner to `wanglou:wanglou` and
mode to **0400**. Leave the generated sequence path in `/var/lib/wanglou`, and
give the agent config group `wanglou` read access. Independently compare the
printed SHA256 fingerprint with the server's `node add` output before starting.
The agent never uploads its private key. To re-enable a revoked name with a fresh key, use the panel enrollment flow
(code or paste) and compare fingerprints. CLI `node add` rejects every existing
name, including revoked ones.

For the receiver, install a server config and TLS certificate/key readable by
`wanglou`, then use `node add` on the receiving host with each node's public key.
Run administration commands as `wanglou` (or ensure the resulting SQLite files
remain owned by it). Keep the state directory and SQLite files private.

Install the matching file from `deploy/systemd/` into `/etc/systemd/system/`, then
run `systemctl daemon-reload` and `systemctl enable --now wanglou-agent` or
`wanglou-server`. Review service logs with `journalctl -u <service>`. The agent
unit enforces the specified sandbox, 24 MiB memory limit and 5% CPU quota; its
only writable persistent directory is `/var/lib/wanglou` for sequence state.
The server unit applies the same hardening, a 256 MiB memory limit and no CPU
quota, with a writable state directory for SQLite. `wtmp` is optional: unreadable/missing logs yield an empty
login list; no permissions escalation is attempted. The wtmp record layout follows
glibc for the build target: 384 bytes on amd64, 400 bytes (64-bit timestamps) on
arm64. An unreadable or misaligned login cursor is replaced by a fresh baseline at
the current end of wtmp.

The receiver runs as a single process per database. SQLite uses WAL, bounded
report writes, and transactions coupling replay state, telemetry and events.
Hourly cleanup also runs at startup; see the retention policy below. `known_ips` is a small persistent baseline table kept outside
raw-data retention. It contains no keys or control channel. First-report login
addresses are considered known; later new addresses alert until an administrator
marks the IP as common in the panel. Binary changes and sustained memory/disk pressure emit events; gaps over
three reporting intervals break a sustained episode. Metric timestamps are
server receipt times, avoiding signed client clock skew in alert durations.
Unsigned sequence/cumulative traffic counters use decimal TEXT in SQLite to
preserve all 64 bits. Completed data is downsampled in the background.

## Docker 一键部署

### 服务端：3 步

1. Prepare configuration on a Linux Docker host with DNS pointing to it and TCP
   ports 80/443 reachable:

   ```sh
   cd deploy/docker
   cp .env.example .env
   # Edit .env: set DOMAIN and PANEL_DOMAIN to your hostnames.
   # ACME_EMAIL is optional; see the Caddy contact instructions below.
   # Optional notifier settings must be supplied as a Telegram token/chat pair.
   ```

2. Start the server and Caddy (which automatically obtains HTTPS certificates):

   ```sh
   docker compose up -d
   docker compose ps
   ```

   The example selects `woaileipi/sand-monitor-server:latest` and
   `woaileipi/sand-monitor-agent:latest`. Both services retain `build:`; run
   `docker compose up -d --build` to build the server locally, or
   `docker compose -f agent.compose.yml build` for the agent. The backend subnet
   defaults to `172.30.0.0/24`; if it overlaps an existing Docker or host
   network, change `WANGLOU_BACKEND_SUBNET` in `.env` before starting. That one
   setting updates both the network subnet and `WANGLOU_TRUSTED_PROXIES`. The server has no published
   ports, runs as UID 65532 with a read-only root, and keeps SQLite in the
   `server_data` volume at `/data/wanglou.db`. Back up that volume.

3. Initialize the agent on each monitored host using one of the options below,
   then register only its printed public key and compare fingerprints:

   ```sh
   docker compose exec wanglou-server wanglou-server node add --name node-01 \
     --pubkey 'wanglou-ed25519 <base64-public-key-from-init> node-01'
   docker compose exec wanglou-server wanglou-server node list
   ```

   Agents send to `https://<DOMAIN>`; no agent port needs opening.

The backend is a standard Docker bridge network, allowing the server to reach
Telegram and webhook endpoints. The server publishes no ports; Caddy provides
the public HTTP/HTTPS entry point and joins both networks.

The default Caddyfile omits the optional ACME contact, so an empty `ACME_EMAIL`
is supported. To supply a contact, set a nonempty `ACME_EMAIL` in `.env` and
prepend this global block to `Caddyfile` before starting Caddy:

```caddyfile
{
    email {$ACME_EMAIL}
}
```

### Agent：推荐二进制 + systemd

Follow [Linux deployment](#linux-deployment): install the matching Linux binary,
run `init --name node-01 --server https://<DOMAIN>`, register its public key on the
server, and enable `wanglou-agent.service`. This avoids broad host mounts and
keeps the systemd memory/CPU limits. Keep the private key on its own host.

### Agent：可选容器

Use a Linux host; Docker Desktop on macOS observes its Linux VM, not the macOS
host. From `deploy/docker`, create a persistent state volume and initialize it
once (the image runs as UID/GID 65532):

```sh
docker volume create wanglou-agent-state
export WANGLOU_AGENT_IMAGE=woaileipi/sand-monitor-agent:latest
# If building locally, run: docker compose -f agent.compose.yml build
docker run --rm -v wanglou-agent-state:/var/lib/wanglou "$WANGLOU_AGENT_IMAGE" \
  init --name node-01 --server https://<DOMAIN> \
  --key /var/lib/wanglou/node.key --config /var/lib/wanglou/agent.toml \
  --state /var/lib/wanglou/agent.seq \
  --proc-root /host/proc --root-fs /host/root --wtmp-path /host/wtmp
# Register the printed public key with the server, then:
docker compose -f agent.compose.yml up -d
```

Replace `<DOMAIN>` before running the init command. The key is created with
mode **0400**, owned by 65532. Named volume initialization supplies a directory
owned by that UID; if using a bind directory instead, create it with owner
65532:65532 and mode 0700 first. Preserve the key, config, `agent.seq`, and
`agent.seq.logins.json` across container replacements. Do not share an identity
or state volume between hosts.

The agent uses the host network namespace and read-only mounts
`/proc:/host/proc`, `/:/host/root`, `/var/log/wtmp:/host/wtmp`. It keeps its own
PID namespace; collectors read the bind-mounted host `/proc`. Only its state
volume is writable; it drops all capabilities and uses `no-new-privileges`.
Host mounts expose local data to the container: use a trusted image. An existing
host wtmp file is required by this manifest; unreadable wtmp still yields an
empty login list. Collector paths are local config only (`proc_root`, `root_fs`,
`wtmp_path`); the matching init flags are shown above. The container agent still
opens no listener and executes no commands.

### 自有 TLS 证书，不用 Caddy

Run the server image directly, publishing its TLS port and mounting your own
certificate and key read-only. Place the files under `certs/` in the current
working directory and make them readable by UID 65532:

```sh
docker volume create wanglou-server-data
docker build --target server -t wanglou-server:local ../..
docker run -d --name wanglou-server --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true --memory 256m \
  -p 8443:8443 -v wanglou-server-data:/data \
  --mount type=bind,src="$PWD/certs/fullchain.pem",dst=/certs/fullchain.pem,readonly \
  --mount type=bind,src="$PWD/certs/privkey.pem",dst=/certs/privkey.pem,readonly \
  -e WANGLOU_DATABASE=/data/wanglou.db -e WANGLOU_LISTEN=:8443 \
  -e WANGLOU_TLS_CERT=/certs/fullchain.pem -e WANGLOU_TLS_KEY=/certs/privkey.pem \
  wanglou-server:local
```

Use `https://<DOMAIN>:8443` for these agents. This TLS deployment leaves
`listen_plain` disabled and needs no trusted proxy CIDRs.

### CI 与 Docker Hub

`ci.yml` runs vet, uncached tests, the agent surface check and deployment file
checks for pushes and pull requests. To publish images from your own repository,
add these in the repository's Actions settings:

- `DOCKERHUB_USERNAME`: your Docker Hub account, as an Actions **variable** or secret.
- `DOCKERHUB_TOKEN`: a Docker Hub access token with push permission (not a password),
  as an Actions **secret**.

After adding them, run the "Docker images" workflow manually (Actions → Run workflow)
or push to main.

`docker.yml` builds both targets for `linux/amd64` and `linux/arm64`. A `v1.2.3`
tag publishes `1.2.3`, `1.2`, and `latest`; main overwrites `edge`. Destinations are
`docker.io/<DOCKERHUB_USERNAME>/sand-monitor-server` and `sand-monitor-agent`.
Without both values, and always on PRs, it only builds and does not log in or
push. Set the image variables in your private `.env` to your namespace after
publishing. Workflows request only `contents: read`; actions use fixed versions.

## Security model

A compromised receiver cannot command, reconfigure or update an agent: agents
open no listening sockets, execute no external commands, reject redirects and
only inspect response status, discarding at most 4096 response bytes. Every node
has an independent locally generated Ed25519 private key in a 0400 file; the
receiver holds public keys only. Reports are authenticated with the exact
`wanglou-v1` canonical string and `X-Wanglou-*` headers in `docs/SPEC.md`, a
64 KiB body cap, a ±60 second clock window, persisted increasing sequences and
per-node 2/s, burst-5 rate limits. Before database lookup, an unauthenticated
remote-IP bucket allows 20 requests/s with a burst of 40. Its LRU map holds at
most 4096 addresses and evicts entries idle for five minutes. Forwarded IP
headers are ignored unless the direct peer matches a configured trusted proxy
CIDR. Trusted chains resolve to the rightmost untrusted address; that address
drives both the IP bucket and stored `last_ip`. Client failures are empty 4xx
responses; internal/storage
failures return empty 503 responses. Rejection counts are aggregated and logged
at most once per minute. Revocation stops a node without changing any other
identity. A compromised node can falsify its own telemetry. Use TLS and keep
host clocks synchronized.

## Verification

```sh
make check
# Equivalent individual checks:
make lint test cross-compile check-size check-agent-surface check-panel-assets check-files
```

`check-agent-surface` uses `go list -deps` for macOS/arm64 and both Linux targets.
It rejects `os/exec` anywhere in the dependency closure and checks AST use sites
in every nonstandard dependency for listening/server APIs and process execution,
including aliased imports. Standard-library net/http necessarily contains server
source definitions; importing its client does not mean those APIs are used.
The check's own negative tests verify forbidden constructs are rejected.

Tests cover all SPEC acceptance cases, fixtures for each allowed `/proc` parser
and wtmp, resource duration/reset behavior, retention, durable unsigned counters,
notification retries and a real agent → httptest receiver → SQLite round trip.
The httptest servers use `net.Pipe` connections and normal HTTP transports, so
these tests also run in sandboxes which prohibit loopback listening sockets.
No integration test is skipped. Linux collectors are cross-compiled here; run
`make test` on Linux to exercise live `/proc` sampling as well.

## Design notes

The flat TOML subset (plus the trusted-proxy string array) is intentional; no full TOML implementation is
required for these settings. Known login IPs persist independently of raw
telemetry retention. Unsigned counters use decimal SQLite TEXT to retain all
64 bits. Metric timestamps use server receipt time.

Resource checks only query `now - resource_duration - 3*interval` onward. A
small persistent per-resource active flag suppresses repeated events during
continuous high usage, including after a restart. Notification receipts are
removed with their events during retention cleanup.

Go builds use the caller's normal cache and module environment; the Makefile
only forces `CGO_ENABLED=0`. Validation output and machine-specific environment
paths are not stored in the repository.

## 面板 Web 界面（第二阶段）

面板和接收端由同一个进程提供，使用完全独立的监听端口。设置 `panel_listen`
启用面板；默认不启用。`public_ingest_url` 是接入命令中使用的接收端 HTTPS 地址。
`panel_cookie_secure` 默认 `true`，只有本地 `--insecure-http` 才能设为 `false`。
TLS 模式共用证书；`listen_plain` 模式共用可信代理配置。不要把接收端反代到面板端口。

Docker 部署时在 `.env` 设置 `DOMAIN=monitor.example.com` 和
`PANEL_DOMAIN=panel.example.com`，然后运行 `docker compose up -d`。
建议将面板放在 Cloudflare Access、Tailscale 或 Caddy `basic_auth` 后面。
在 `deploy/docker` 目录创建管理员：

```sh
docker compose exec wanglou-server wanglou-server admin add --user admin
```

命令只打印一次随机口令、TOTP 密钥及 `otpauth://` 地址。将密钥添加到验证器 App，
访问 `https://panel.example.com`，在同一个登录表单填写用户名、口令和 6 位验证码。
不要将口令、密钥或二维码存入代码仓库。也可使用 `--password-stdin` 输入至少 12 字符口令。
`admin list` 只显示用户名及时间；`admin passwd`、`admin reset-totp` 和 `admin remove`
会立即注销该用户的全部会话。这些命令接受 `--user` 与 `--config`。

本地开发可在工作目录创建以下配置（数据库路径按需调整）：

```toml
database = "dev.db"
listen = "127.0.0.1:8080"
panel_listen = "127.0.0.1:8081"
public_ingest_url = "http://127.0.0.1:8080"
panel_cookie_secure = false
```

```sh
go run ./cmd/wanglou-server admin add --user admin --config dev.toml
go run ./cmd/wanglou-server serve --config dev.toml --insecure-http
```

访问 `http://127.0.0.1:8081`。macOS 的桩采集器也可完成接入流程。
接入节点页先填写节点名与备注并更新命令，在节点安装二进制后运行页面上的 `init`
命令。可以粘贴公钥预览，也可以生成 10 分钟有效的一次性注册码，在节点运行：

```sh
sudo wanglou-agent enroll K7QF-29XM
# 使用非默认配置时：
wanglou-agent enroll K7QF-29XM --config agent.toml
```

核对 `wanglou-agent fingerprint` 与页面分组显示的完整指纹，勾选一致后启用，
然后启动 agent 的 `run` 服务。确认之前接收端始终拒收该节点的指标。
本地 `init` 还需要 `--insecure-http`，自定义密钥路径时 `fingerprint` 需要 `--key`。
静音只阻止通知发送，事件继续保存；某个通知渠道失败时按 30 秒起翻倍、最长 10 分钟退避重试，不影响其他渠道和后续事件，超过 24 小时仍未送达的事件不再发送；未配置任何渠道时事件只记录，之后配置渠道也不会补发历史。延迟送达的 Telegram 消息会附上事件发生时间。新登记的节点 10 分钟内未上报不算失联；吊销、备注、确认事件和标记常用 IP 只修改服务端数据库。
历史图提供 1 小时、24 小时、7 天、30 天和 90 天范围，在 SQL 中分桶，最多 360 点；页面每 5 秒刷新，
编辑表单时暂停刷新，禁用 JavaScript 仍可使用全部操作。

启动时数据库自动原地升级至 schema v5；升级前可备份数据库及 WAL。
新增会话保留至空闲 12 小时或绝对 7 天，注册码保留 1 天，审计记录保留 90 天。
`make check-panel-assets` 检查嵌入资源的 CSP 约束，并已并入 `make check`。


## 通知

Telegram 有两种配置方式：在面板“通知”（`/notify`）填写 bot token 和 chat id，保存后立即生效；或者在服务器配置文件中设置 `telegram_token`、`telegram_chat_id`（环境变量 `WANGLOU_TELEGRAM_TOKEN`、`WANGLOU_TELEGRAM_CHAT_ID`）。配置文件/环境变量优先：设置了 token 时，面板只读，并完全忽略数据库里的 Telegram 设置。Webhook 仍只通过配置文件或 `WANGLOU_WEBHOOK_URL` 设置。总览的渠道名单和续费页的“发送到”会随保存、停用立即更新；新配置不会补发已处理的历史事件。

1. 在 Telegram 打开 @BotFather，发送 `/newbot`，按提示创建机器人并取得 token。
2. 先给机器人发一条消息，再访问 `https://api.telegram.org/bot<token>/getUpdates`，在返回的 `message.chat.id` 中找到 chat id。群组的 id 通常为负数；公开频道也可用 `@频道名`。
3. 在通知页填写并保存，检查“已开始向这里发送告警通知”确认消息。token 留空表示沿用当前值，首次配置必填。测试按钮只向已保存的渠道发送，每 10 秒最多一次。

保存和停用需要重新输入管理员 TOTP；同一个验证码不能重复使用（包括登录时使用的验证码），请等下一个 30 秒窗口。15 分钟内失败 5 次，会拒绝该用户在这一窗口内的后续修改。修改前先向旧 Telegram 通知修改人、来源 IP 和新 chat id，停用前也会通知旧渠道；旧渠道发送失败仍继续操作，并在页面和审计中标明。旧渠道通知和新渠道确认各限时 5 秒，操作记录写入审计。页面只显示 token 后 4 位。

面板配置以明文保存在数据库 `kv` 表的 `notify.telegram` 中，**数据库备份包含 token**，请保护数据库和备份的访问权限。备用接收端没有面板，仍在自己的 `.env` 中设置通知渠道。

无法直连 Telegram 时，可在服务器配置中设置 `telegram_api_base`（环境变量 `WANGLOU_TELEGRAM_API_BASE`）为自建反向代理地址，默认 `https://api.telegram.org`；两种配置方式共用此地址。通知页只读显示地址，不允许从面板修改。必须为 HTTPS，不能带用户信息、查询参数或片段，末尾 `/` 自动去除；只有本地 `--insecure-http` 模式允许 HTTP，可用于假接收器验收。


## 续费与流量

在“续费与流量”中编辑节点的服务商、到期日、周期、价格、流量额度和通知规则。GB 按 10⁹ 字节计算，1000 GB 为 1 TB；可以选择上下行合计、仅出站、仅入站或两者较大值。首次上报只建立基线，之后服务端持续累加，agent 无需更改配置。用量与服务商后台不符时填写“校准本周期已用”，留空保留原值。

手动续费后点击“已续费一期”，按保存到期日时的“日”顺延，遇到小月取当月最后一天（1 月 31 日 → 2 月 28 日 → 3 月 31 日）。自动续费会在扣费前 3 天提醒，到期后第二天顺延；提醒日程显示近期记录和未来 14 天的可预见事项。日期提醒在本地 09:00 后检查，不补发错过的日期。未选择通知渠道时只记事件，续费和流量提醒不受告警静音影响。预测基于最近 3 个完整本地日；数据不足时不预测。

## 静态公开状态页

在“公开页”中选择节点、填写公开显示名和字段开关，保存草稿后可预览；点击“保存并发布”立即导出。新节点默认不公开。公告的编辑、删除和更换链接口令都先改草稿，发布后才影响访客。

配置 `public_dir` / `WANGLOU_PUBLIC_DIR` 为可写目录；`public_url` / `WANGLOU_PUBLIC_URL` 为展示用的 HTTPS 地址，例如 `https://status.example.com`。未配置目录时仍可编辑和预览。导出的公开页由独立静态服务器提供，接收端不提供公开页面，两个端口均不提供公开 JSON 路由。Docker Compose 已挂载 `status_public` 卷，Caddy 只读提供其中的文件；`STATUS_DOMAIN` 默认 `status.localhost`，正式使用时改为自己的域名。

导出文件只有 `index.html`、`status.json` 和 `status.css`，不含 IP、内部节点名、服务商、账单、备注、登录信息或身份信息。使用白名单结构生成，无 JavaScript 或外部资源；字段关闭时也从 JSON 省略。可以通过 rsync 或对象存储把这三个静态文件同步到另一台机器；目标机器不需要面板账号、接收端或任何密钥。公开页被攻破只能篡改页面显示。

访问方式为“公开”时，未登录访客访问面板首页会看到已发布的公开状态页，右上角的“登录”链接可进入管理面板，登录后首页仍是总览。此功能不依赖 `public_dir`。不想在面板域名上展示时，可以选择 token（口令）访问方式，或者把面板放在 Cloudflare Access 等认证服务后面。

口令模式使用随机链接目录。切换模式或发布新口令后，旧位置的三个导出文件会清理，其他文件保留；同步到其他机器时也需同步删除旧的导出文件。口令链接是持有链接即可访问的方式，分享时请按此理解。

## 外部心跳与时区

`heartbeat_url` / `WANGLOU_HEARTBEAT_URL` 可填外部心跳服务的 HTTPS 地址。服务端每 60 秒发送不带数据的 GET；只有离线检查和提醒检查在最近 2 分钟内都成功过、降采样任务在最近 5 分钟内成功过时才发送。总览显示最近成功时间或失败，不展示地址。请求超时 10 秒且不跟随重定向。

`timezone` / `WANGLOU_TIMEZONE` 控制到期日、09:00 提醒、流量重置和每日可用率统计；默认 `Local`，Compose 默认 `UTC`。建议部署时明确设置，例如 `Asia/Shanghai`，避免主机和容器默认时区不同。面板和日志里的时间也按这个时区显示。IANA 时区数据已编入服务端。公开页生成时间按导出间隔截断。`public_url`、`heartbeat_url` 只有本地开发的 `--insecure-http` 模式允许 HTTP。


## 降采样与长期保留

`retention_days` / `WANGLOU_RETENTION_DAYS` 默认 90，允许 7 到 3650，超出范围拒绝启动。
原始指标保留 48 小时，分钟汇总保留 14 天，小时汇总、事件和登录记录保留 `retention_days` 天。
每天可用率保留 60 天、提醒去重保留 400 天、审计保留 90 天；常用 IP 基线独立保留。

启动后及每 60 秒汇总一次，桶按 Unix 时间对齐并留 1 分钟余量；小时平均值按原始样本数加权。
升级至 v5 后自动补算现有原始数据，每个事务最多处理 6 小时分钟桶或 7 天小时桶。
清理以汇总水位为界，尚未进入下一级的数据继续保留。历史图的 1 小时读原始数据，
24 小时和 7 天读分钟数据，30 天和 90 天读小时数据，右端用原始数据补齐；超出保留期的范围回落到 24 小时。
总览、最新指标、公开页和告警仍读原始数据。

测试库实测：每台节点约 **8.56 MB**（8,564,736 字节，十进制 MB），按 5 秒上报、90 天保留，
包含 34,560 条原始指标、20,159 条分钟指标和 2,160 条小时指标及其索引。
可运行 `go test ./internal/server/store -run TestRetentionDatabaseSize -v -count=1` 复测。
这是单节点测试库在 `VACUUM` 和 WAL checkpoint 后的体积，字段使用变化的示例指标；不含事件和登录记录的可变增量。
实际运行还需为 WAL、空闲页和升级补算预留空间；定时清理不会自动缩小数据库文件。

吊销过的名称可在面板“接入节点”中通过注册码或粘贴新公钥重新启用。
步骤 1 和 3 会提示换钥及保留历史；确认时保留登记时间、上报序号和历史数据，并写入 `node_reenable` 审计。
吊销指纹永久保留，换名称或多轮换钥也不能复用已吊销的公钥；未吊销的名称仍拒绝覆盖。
命令行 `node add` 同样拒绝已吊销的公钥，遇到已有名称仍然拒绝。

## 双接收端

备用接收端建议部署在另一家服务商，使用独立数据库、节点登记和通知渠道。两端运行同一个服务端二进制，不共享密钥、不同步数据，也不互相授权。

1. 在备用机器复制 `deploy/docker/.env.example` 为 `.env`，把 `DOMAIN` 设为备用域名（如 `backup.example.com`），把 `PRIMARY_DOMAIN` 设为主端域名（如 `monitor.example.com`），配置备用端自己的通知渠道。运行 `docker compose -f backup.compose.yml up -d`（在 `deploy/docker` 下）。备用部署只有接收端和 Caddy，不启用面板或公开页，默认 `instance_name = "望楼·备"`、`alert_scope = "security"`。
2. 主端 `.env` 设置 `BACKUP_DOMAIN=backup.example.com`，重新运行 `docker compose up -d`。这会启用对端检查与面板的备用接入提示；留空则不启用。两端每 30 秒检查另一端的 `/healthz`，连续 4 次失败通知不可达，恢复时通知一次。检查只看状态码，不改变本端接收或告警行为。
3. 新节点运行 `sudo wanglou-agent init --name node-01 --server https://monitor.example.com --backup-server https://backup.example.com`。已有节点只需在本地配置加 `backup_server = "https://backup.example.com"` 后重启 agent。将同一条公钥分别登记在两端：`wanglou-server node add --name node-01 --pubkey '<init 输出的公钥行>'`。也可以在各自面板接入，备用端的注册码用 `wanglou-agent enroll <CODE> --backup` 提交；两端均需核对指纹后启用。
4. 吊销时在两端分别运行 `wanglou-server node revoke --name node-01`（主端也可用面板）。主端的吊销不会替备用端作决定。

agent 每周期只采样一次，两端独立发送、独立退避，忙碌目标跳过当次指标，不积压。登录游标分别持久化在 `<state_file>.logins.json` 和 `<state_file>.backup.logins.json`，各自在收到 204 后推进；一端恢复后补报它错过的登录，另一端不会重复收到。首次启用备用端时只建立登录基线，不发送历史记录。两个目标共享持久化 seq，每次发送独立签名，协议仍为 `wanglou-v1`。

备用端在主端健康时仍会独立告警：被攻破的主端可以继续返回正常健康状态、同时吞掉告警，因此不能根据主端健康检查静默备用端。用 `alert_scope = "security"` 只推送失联、恢复、新 IP 登录和二进制变化，资源与账单事件仍记录并标为已处理；默认 `all` 推送全部。用 `instance_name`（最多 16 个字符，默认“望楼”）区分 Telegram 前缀和 Webhook 的 `instance` 字段。对端不可达和恢复通知不受告警范围影响。
