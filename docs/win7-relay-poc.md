# NetBird 0.25.3 Windows 7 Relay 兼容 PoC

## 1. 结论与边界

本仓库是一个**实验性 PoC**，目标是在 NetBird `v0.25.3`（Go 1.20，最后一个官方支持
Windows 7 的版本）中接入 NetBird `v0.81.3` 的 Relay 协议，为 ICE 直连失败或生产环境
没有 TURN 的场景提供一条 Relay 兜底路径。

当前状态：

- CLI 与 Windows 服务入口可编译，Windows amd64 可执行文件已产出。
- Relay 协议握手、鉴权、订阅、传输、心跳和断线重连有单元测试覆盖。
- **尚未在真实 Windows 7 机器上运行验证**，也**没有使用生产有效 token 完成端到端打洞/传输验证**。
- 不能把本版本描述为“已完全支持 Windows 7”或“生产可用”。它只是可编译、可握手、
  等待现场联调的 PoC。

## 2. 基线与分支

- 上游：`https://github.com/netbirdio/netbird`
- 基线 tag：`v0.25.3`（`go.mod` 为 Go 1.20）
- fork：`https://github.com/KalebCheng/netbird`
- 分支：`codex/win7-relay`
- 参考实现：NetBird `v0.81.3` 的 `shared/relay/messages` 与
  `shared/relay/auth/hmac`

0.81.3 的服务端消息 `NetbirdConfig` 与 0.25.3 的 `WiretrusteeConfig` 在 wire 上都是
`LoginResponse/SyncResponse` 的字段 1，只是消息名不同。因此本次只给
`WiretrusteeConfig` 增加字段 4，不重命名旧消息。

## 3. 已完成

### 3.1 Management 协议兼容

- `management/proto/management.proto`
  - `WiretrusteeConfig.relay = 4`，类型为 `RelayConfig`
  - `RelayConfig { repeated string urls = 1; string tokenPayload = 2; string tokenSignature = 3; }`
  - `Route.Domains = 8`，同时补齐 `keepRoute = 9`、`skipAutoApply = 10`
- 已用仓库原有 `generate.sh`（protoc-gen-go v1.26）重新生成 `management.pb.go`。
- 旧字段号保持不变：`stuns=1`、`turns=2`、`signal=3`；`Route.ID..NetID = 1..7`。

### 3.2 最小 Relay 客户端

新增 `client/internal/relayclient`：

- `rels://host:443` 优先，转换为 `wss://host:443/relay`；支持 `rel://` 对应 `ws://`。
- 直接 TCP 拨号，不继承 `HTTP(S)_PROXY`。
- 使用 0.81.3 原样导入的 `shared/relay/messages` 与
  `shared/relay/auth/hmac`（含 HMAC-SHA256 v2 token）。
- 支持：
  - `auth` / `authResponse`
  - `subscribePeerState` / `peersOnline` / `peersWentOffline`
  - `transport` 双向收发
  - `healthCheck` 应答与服务端心跳超时检测
  - 断线后关闭所有 peer 连接、指数退避重连
  - 对端早到的 transport 消息做有限缓存
- 只使用 `gorilla/websocket v1.5.0`，不引入 quic-go、coder/websocket 等新依赖。

### 3.3 Engine / peer 接入

- 登录响应与 `SyncResponse` 都会解析 `WiretrusteeConfig.Relay`。
- `Engine` 创建并更新 Relay 客户端；URL 变化时重连，token 变化时下一次重连使用新 token。
- `peer.ConnConfig` 增加可选 `RelayDialer`。
- `peer.Conn.Open()` 在 `GatherCandidates()` 后**并行**启动 ICE 与 Relay：
  - 两者谁先成功就用谁，失败方被取消并清理；
  - 不再等待 `agent.Dial/Accept` 永久阻塞后才启动 Relay。
- Relay 成功后调用现有 `wgproxy.AddTurnConn()`，再调用
  `WgInterface.UpdatePeer()`，复用原有 WireGuard 与状态更新逻辑。
- 设置 `NB_FORCE_RELAY=1` 时可跳过 ICE，直接走 Relay（仍需要 Signal 完成
  offer/answer 握手）。
- Relay 断开后 `peer.Conn` 返回断线，Engine 现有 `connWorker` 自动重试。
- 修复 userspace `wgproxy` 在读写错误时忙循环的问题，并在关闭时同时关闭远端连接。

### 3.4 域名路由最小支持

- 解析 `Route.Domains`。
- 使用 `net.DefaultResolver.LookupIPAddr` 解析单个 A/AAAA，优先 IPv4。
- 生成 `/32` 或 `/128` 的合成路由，复用现有 `routemanager`：
  - 加入 WireGuard allowed IP；
  - 安装系统路由；
  - 路由 peer 断线时按原逻辑清理。
- 修复 Windows 下原实现用 `route add <CIDR>` 的问题，改为 `route add <dest> mask <mask> <gateway>`。
- 周期刷新，默认 60 秒，可用 `NB_DNS_ROUTE_INTERVAL`（秒）覆盖，最小 10 秒。
- 解析失败时保留上一次成功的地址，避免路由抖动。

已验证本机 DNS：

```text
inphile.insuresmart.com.cn -> 172.19.17.11
```

合成路由为 `172.19.17.11/32`。

### 3.5 构建产物

已在 `dist/` 生成（该目录被 `.gitignore` 忽略，不提交二进制）：

- `dist/netbird-0.25.3-relay-windows-amd64.exe`
- `dist/netbird-0.25.3-relay-darwin-arm64`
- `dist/nb-relayprobe-darwin-arm64`

Windows 二进制元数据：

```text
PE32+ executable (console) x86-64, for MS Windows
go1.20.14
```

## 4. 未完成 / 明确限制

1. **未在真实 Windows 7 上运行**。当前只完成交叉编译和 macOS 本机探测。
2. **未做生产 token 的完整端到端验证**。没有在生产环境注册新 peer，也没有读取现有
   peer 的私钥/token，因此只验证到 TLS + WebSocket + 鉴权被拒。
3. **Relay 仍依赖 Signal 握手**。0.25.3 的 `peer.Conn.Open()` 仍先通过 Signal 交换
   offer/answer；Relay 只是传输层兜底。
4. **需要两端都支持 Relay**。对端必须在线于同一个 Relay 服务；如果对端是原版
   0.25.3（没有 Relay 客户端），则无法使用本路径。
5. **只使用一个 Relay URL**。配置中有多个 URL 时会优先选择 `rels://...:443`，
   不做多 Relay 故障切换或实例选择。
6. **仅 WebSocket / TCP 443**。不支持 QUIC，不实现 0.81 的 transport 协商和 datagram fallback。
7. **域名路由是兼容层**。`net.LookupIPAddr` 不暴露 DNS TTL，因此只能周期刷新；
   每个域名只取一个地址，不做多 A/AAAA 全量下发、CNAME 链或 DNS 拦截。
   Windows 上当前只实现 IPv4 `/32` 系统路由；IPv6 `/128` 会返回“不支持”错误。
8. **GUI 未移植**。`client/ui` 依赖 Fyne/OpenGL，Windows 交叉编译会被排除；本次仅保留
   CLI 和 Windows 服务。
9. **未验证与 0.81.3 官方客户端的互操作**。协议字段兼容，但对端何时触发 Relay、
   早到消息如何处理仍需现场测试。

## 5. 构建

要求 Go 1.20.x。本机使用 Go 1.27 的 toolchain 拉起 1.20.14：

```bash
cd /Users/kkcheng/Desktop/Netbird/netbird-win7

# macOS 测试二进制
GOTOOLCHAIN=go1.20.14 GOFLAGS=-mod=mod \
  go build -trimpath -ldflags '-s -w' \
  -o dist/netbird-0.25.3-relay-darwin-arm64 ./client

# Windows 7 / amd64 CLI + service
GOTOOLCHAIN=go1.20.14 GOFLAGS=-mod=mod \
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -ldflags '-s -w' \
  -o dist/netbird-0.25.3-relay-windows-amd64.exe ./client

# Relay 探测工具（macOS）
GOTOOLCHAIN=go1.20.14 GOFLAGS=-mod=mod \
  go build -trimpath -ldflags '-s -w' \
  -o dist/nb-relayprobe-darwin-arm64 ./client/cmd/relayprobe
```

不要构建 `./client/...` 作为 Windows 交付物，因为它包含未移植的 Fyne GUI；应构建
`./client`（CLI/service 入口）。

## 6. 测试

### 6.1 单元测试

```bash
GOTOOLCHAIN=go1.20.14 GOFLAGS=-mod=mod \
  go test ./shared/relay/... ./client/internal/relayclient/...

GOTOOLCHAIN=go1.20.14 GOFLAGS=-mod=mod \
  go test -run 'TestDomainRoute' ./client/internal/routemanager/

GOTOOLCHAIN=go1.20.14 GOFLAGS=-mod=mod \
  go test -run 'TestToRoutes|TestCreateEngineConfig' ./client/internal/
```

覆盖内容：

- 0.81.3 原版 Relay 消息编解码测试
- HMAC token 生成/校验/过期测试
- 本实现的 auth 握手、peer online 订阅、transport 回显、health check 应答
- `NB_FORCE_RELAY=1` 时 peer 层不使用 ICE agent
- 域名路由展开、去重、解析失败保留旧地址

说明：`routemanager` 中依赖真实 WireGuard 接口的既有测试在本机因权限不足失败
（`operation not permitted`），与本 PoC 代码无关。

### 6.2 生产 Relay 连通性

```bash
dist/nb-relayprobe-darwin-arm64 \
  -url rels://netbird.insuresmart.tech:443 \
  -timeout 20s
```

实际输出：

```text
OK websocket connected: wss://netbird.insuresmart.tech:443/relay
sent auth: peerID=... token=false
AUTH NOT ACCEPTED (expected without a valid token): websocket: close 1006 (abnormal closure): unexpected EOF
```

这证明：

- DNS、TCP 443、TLS、HTTP Upgrade 到 `/relay` 均可达；
- 服务端按 0.81 Relay 协议等待 HMAC auth，无 token 时主动断开。

如能从 Management 获取某 peer 的 `TokenPayload` / `TokenSignature`，可继续：

```bash
dist/nb-relayprobe-darwin-arm64 \
  -url rels://netbird.insuresmart.tech:443 \
  -peer-id '<wireguard-public-key>' \
  -token-payload '<payload>' \
  -token-signature '<base64-signature>'
```

期望输出 `OK relay authenticated: instance=...`。

## 7. Windows 7 现场测试步骤

1. 使用管理员权限运行。
2. 将 `netbird-0.25.3-relay-windows-amd64.exe` 放到独立目录，不要覆盖现有
   `C:\Program Files\NetBird`。
3. 先用命令行登录/启动：

   ```bat
   netbird-0.25.3-relay-windows-amd64.exe up ^
     --management-url https://netbird.insuresmart.tech:443 ^
     --setup-key <setup-key>
   ```

   或安装为服务后启动：

   ```bat
   netbird-0.25.3-relay-windows-amd64.exe service install
   netbird-0.25.3-relay-windows-amd64.exe service start
   ```

4. 强制 Relay 验证：

   ```bat
   set NB_FORCE_RELAY=1
   netbird-0.25.3-relay-windows-amd64.exe up
   ```

5. 查看日志，关键日志包括：
   - `relay connection established`
   - `prepare the relayed connection, waiting for remote peer`
   - `connected to peer ... endpoint address`
   - peer 状态更新中 `Relayed=true`、`Direct=false`

6. `netbird status` 查看 peer 是否为 Connected / Relayed。

## 8. 已知风险

- Windows 7 的根证书库可能过旧，访问 `netbird.insuresmart.tech` 可能 TLS 校验失败；
  现场需确认系统时间、根证书和 TLS 1.2 支持。
- Win7 已停止安全更新，不建议作为长期生产客户端；本 PoC 只验证兼容性路径。
- Relay token 有有效期；依赖 Management `SyncResponse` 持续下发新 token。若 token
  过期且 Management 断连，Relay 会重连失败。
- 当前 Relay 连接使用单 WebSocket，多 peer 复用；单个 peer 的大量流量会影响同一
  Relay 上的其他 peer。
- `peer.Conn` 的 Relay 兜底目前与 Signal offer/answer 绑定，Signal 不可用时无法仅靠
  Relay 建立连接。
- 域名路由每 60 秒才刷新，DNS 变更后存在最长约 60 秒的窗口；如需更快可调小
  `NB_DNS_ROUTE_INTERVAL`。
- 本 PoC 未修改 `/Applications/NetBird.app`、`/etc/netbird` 或生产服务端配置。

## 9. 下一步

1. 在隔离测试环境申请一个测试 setup key，完成真实 token 的 Relay auth + 双端传输验证。
2. 在 Windows 7 SP1 实机安装测试，确认 wintun、服务、路由与 DNS 行为。
3. 与 0.81.3 官方客户端做互操作测试，必要时补充对端主动 Relay 的触发逻辑。
4. 增加多 Relay URL 选择、token 过期主动重连、Relay 流量指标。
5. GUI 另做简化版，不复用 0.25.3 的 Fyne 界面。
