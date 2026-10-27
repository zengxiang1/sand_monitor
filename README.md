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
# Optional notifications (omit to retain events without sending):
# webhook_url = "https://hooks.example.com/wanglou"
# telegram_token = "bot-token"
# telegram_chat_id = "chat-id"
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
The agent never uploads its private key. A fresh key requires a new node identity
or an explicit local database administration decision; adding an existing node
refuses to silently replace its key.

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
login list; no permissions escalation is attempted. Both Linux architectures
use glibc's little-endian 384-byte wtmp ABI.

The receiver runs as a single process per database. SQLite uses WAL, bounded
report writes, and transactions coupling replay state, telemetry and events.
Hourly cleanup removes metrics, logins and events older than seven days (also
runs at startup). `known_ips` is a small persistent baseline table kept outside
raw-data retention. It contains no keys or control channel. First-report login
addresses are considered known; later new addresses alert until an administrator
marks the IP as common in the panel. Binary changes and sustained memory/disk pressure emit events; gaps over
three reporting intervals break a sustained episode. Metric timestamps are
server receipt times, avoiding signed client clock skew in alert durations.
Unsigned sequence/cumulative traffic counters use decimal TEXT in SQLite to
preserve all 64 bits. Nothing is downsampled in phase 1.

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

   The example selects `zengxiang1/sand-monitor-server:latest` and
   `zengxiang1/sand-monitor-agent:latest`. Both services retain `build:`; run
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
export WANGLOU_AGENT_IMAGE=zengxiang1/sand-monitor-agent:latest
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
add these two repository **Actions secrets**:

- `DOCKERHUB_USERNAME`: your Docker Hub account.
- `DOCKERHUB_TOKEN`: a Docker Hub access token with push permission (not a password).

`docker.yml` builds both targets for `linux/amd64` and `linux/arm64`. A `v1.2.3`
tag publishes `1.2.3`, `1.2`, and `latest`; main publishes `edge` and
`sha-<short-hash>`. Destinations are
`docker.io/<DOCKERHUB_USERNAME>/sand-monitor-server` and `sand-monitor-agent`.
Without both secrets, and always on PRs, it only builds and does not log in or
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
seven-day retention. Unsigned counters use decimal SQLite TEXT to retain all
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
静音只阻止通知发送，事件继续保存；吊销、备注、确认事件和标记常用 IP 只修改服务端数据库。
历史图按 1 小时、24 小时、7 天范围在 SQL 中分桶，最多 360 点；页面每 5 秒刷新，
编辑表单时暂停刷新，禁用 JavaScript 仍可使用全部操作。

启动时数据库自动原地升级至 schema v3；升级前可备份数据库及 WAL。
新增会话保留至空闲 12 小时或绝对 7 天，注册码保留 1 天，审计记录保留 90 天。
`make check-panel-assets` 检查嵌入资源的 CSP 约束，并已并入 `make check`。
