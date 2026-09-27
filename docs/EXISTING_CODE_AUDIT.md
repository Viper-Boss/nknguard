# NasSimHub 现有网络代码审计

> 审计对象：`nas-comm-gateway-r6`（Go module `github.com/human-agent65535/modemdeck`，agent 为独立 module）
> 审计日期：2026-09-22 / 23
> 审计方式：只读。**未修改 NasSimHub 任何文件，未改变任何运行时行为。**
>
> **发布前提醒**：本文件与 `MIGRATION_PLAN.md` 描述的是私有仓库的内部结构。如果不希望公开，
> 请在推送到 GitHub 前把这两个文件移出 `docs/`。

## 0. 审计范围与局限（先说清楚）

- 逐行阅读：`agent/internal/dht/dht.go`、`agent/internal/wireguard/wireguard.go`、
  `internal/httpapi/homesim_wireguard_nkn.go`、`homesim_forward_nkn.go`（客户端部分）、
  `homesim_dht_nkn.go`（头部）、`homesim_nkn_network.go`（订阅/查询部分）、`cmd/nknpeer/main.go`、`go.mod`、`agent/go.mod`。
- 只读了函数签名与注释：`homesim_nkn_node.go`、`homesim_dht.go`、`homesim_wireguard.go`、
  `homesim_tunnel_lifecycle.go`、`homesim_nkn_lifecycle.go`、`agent/internal/httpapi/{dht,wireguard}.go`、
  `deploy/fnos/wireguard/{nkn-forward.sh,runtime.py}`。
- 只定位、未打开：`homesim_chat_nkn*.go`、`homesim_license_*nkn*.go`、`internal/agentclient/{dht,wireguard}.go`、
  `agent/internal/networking/egress_wireguard_test.go`、`internal/mobilepairing/*`、`deploy/fnos/nkn-node/*`、
  `deploy/fnos/wireguard/{wg-ctl.sh,wg-server-init.sh,wg0.conf.tmpl,install-runtime.sh,netns_smoke.py}`。
- **未运行 NasSimHub 测试基线**（规范 §38/§74 要求）：本次会话只能读取文件、不能在你的电脑上执行命令，
  且云端环境无法访问 Go 模块代理。**请在本机补跑一次** `go test ./...` 与 `cd agent && go test ./...` 并记录结果，
  作为后续反向接入的基线。

## 1. 结论摘要

| 能力 | NasSimHub 现状 | NKNGuard 处理 |
|---|---|---|
| NKN 客户端 | 有，nkn-sdk-go v1.4.8 MultiClient，按 seed 缓存，带中国社区 seed 优先 | 抽出 → `pkg/nknclient`（build tag `nknsdk`） |
| NKN 控制信令 | 有，但是 JSON 消息 + 一条 if 链分发；靠 NKN 加密和"已配对地址"认证，无统一签名/版本/防重放 | 重新设计 → `pkg/protocol` + `pkg/signaling`，沿用"只做信令、不授予权限"的原则 |
| NKN 主题目录 | 有，公开主题 `modemdecknet` 多时间窗订阅 | 思路复用 → `pkg/rendezvous/nkntopic`，但主题名由入网密钥派生，不公开可查 |
| DHT | 有，libp2p + Kademlia，私有前缀、连接闸门、mDNS、协议白名单 | 抽出 → `pkg/discovery/dht`（build tag `libp2pdht`），**新增**签名记录的发布与获取 |
| 经 NKN 传 DHT 引导地址 | 有，点对点加密发送给已配对对端 | 概念演化为 `PEER_INFO` 介绍消息 |
| WireGuard 管理 | 有，Go（agent）+ Python/Shell（FNOS 部署）两套 | Go 版抽出 → `pkg/wireguard`，补齐 AddPeer/UpdateEndpoint/重启不断流 |
| 经 NKN 通告 WG 端点 | 有，`homesim.wireguard.endpoint`，120 s 新鲜度，校验固定 NKN 地址 + 公钥 | 演化为签名 `CANDIDATE` + 签名 PeerRecord |
| 设备根身份 | **无**，身份分散在 NKN seed / libp2p key / WG key | **新增** `pkg/identity` |
| 入网/成员资格 | **无**统一机制，靠手工配对表 | **新增** `pkg/membership`（NetworkID + JoinSecret） |
| STUN / 候选收集 | **无** | **新增** `pkg/nat` |
| UDP 打洞 | **无**（依赖一端有公网或手填端点） | **新增**（WireGuard 握手打洞） |
| NKN 中继数据面 | **无**（NKN 只跑控制消息） | **新增** `pkg/relay` + `nknrelay` |
| 路径选择 / 状态机 | **无** | **新增** `pkg/mesh` |
| ACL | **无**（WG 层靠 AllowedIPs） | **新增** `pkg/acl` |
| doctor / 诊断包 | 有 agent 诊断日志，但非网络专用 | **新增** |

## 2. 文件级映射

耦合度：low = 基本自包含；medium = 依赖 NasSimHub 的 `*API`、settings JSON、agent HTTP；high = 业务逻辑。

| 当前文件 | 功能 | 耦合 | 可复用 | 目标模块 | 说明 |
|---|---|---:|---:|---|---|
| `agent/internal/dht/dht.go` | libp2p host、Kademlia server 模式、私有 `ProtocolPrefix`、`peerGate`、mDNS、协议白名单裁剪、身份 0600 持久化 | low | **是** | `pkg/discovery/dht` | 主体思路与安全控制全部保留；前缀改为 `/nknguard`；新增 Provide + `/nknguard/record/1.0.0` 取记录。`peerGate` 暂未搬（成员资格改由记录签名 + 证明决定），见迁移计划 |
| `agent/internal/dht/dht_test.go` | DHT 测试 | low | 部分 | `pkg/discovery/dht` | 需按新 API 改写 |
| `agent/internal/wireguard/wireguard.go` | `Manager`、`Runner` 接口（argv、不走 shell）、私钥 0600 不出机器、`State` 枚举、`parseDump`、`SetPeerEndpoint` | low | **是** | `pkg/wireguard` | 直接继承；新增 `AddPeer`、`UpdateEndpoint`、`RemovePeer`、`Down`，以及"接口已存在时不 setconf"防断流 |
| `agent/internal/wireguard/wireguard_test.go` | 测试 | low | 部分 | `pkg/wireguard` | 已按新接口重写同类测试 |
| `agent/internal/httpapi/wireguard.go` / `dht.go` | agent HTTP 接口（PUT 配置、GET 状态、POST 端点/拨号） | medium | 否 | — | NasSimHub 特有的"api 容器 → agent"通道；NKNGuard 用本地 Unix socket API 替代 |
| `internal/agentclient/{dht,wireguard}.go` | api 侧调用 agent 的客户端 | medium | 否 | — | 反向接入时改为调用 NKNGuard API |
| `internal/httpapi/homesim_forward_nkn.go` | NKN MultiClient 创建与缓存、seed RPC 优先级（内置节点 → 环境变量 → 中国社区 seed → 官方 seed）、连接超时、seed 解析 | medium | **是（客户端部分）** | `pkg/nknclient` | 连接逻辑已抽出；seed 优先级改为配置项 `nkn.seed_rpc`。"短信转发到 NKN"本身是业务，留在 NasSimHub |
| `internal/httpapi/homesim_wireguard_nkn.go` | `receiveNKNControl`（聊天/DHT/许可证/WG 端点的 if 链分发）、`wireGuardAnnouncement` | high | 思路 | `pkg/signaling`、`protocol.CandidateSet` | 保留的原则：信令不授予权限、必须 Encrypted、大小上限、新鲜度窗口、核对固定 NKN 地址 + 公钥。改进：统一签名信封、防重放缓存、版本协商、单一分发器 |
| `internal/httpapi/homesim_dht_nkn.go` | 经 NKN 点对点把 libp2p 地址发给已配对对端；`nknAddressIsPairedPeer` | medium | 思路 | `PEER_INFO` | "不往公开主题发地址"的顾虑被采纳：NKNGuard 的记录里只有 NKN 地址与候选端点，主题名由密钥派生 |
| `internal/httpapi/homesim_dht.go` | api 侧 DHT 设置与状态视图 | medium | 否 | — | NasSimHub UI/设置层 |
| `internal/httpapi/homesim_nkn_network.go` | 公开主题 `modemdecknet` 多窗口订阅、续订、退订、JSON-RPC 查订阅者、节点探测 | medium | 思路 | `pkg/rendezvous/nkntopic` | 订阅/查询 API 用法一致（`Subscribe`、`GetSubscribers`）；目的不同：NasSimHub 是公开目录，NKNGuard 是私有会合点 |
| `internal/httpapi/homesim_nkn_node.go` | 内置 NKN **全节点**（nknd）监管、钱包创建/导入/备份、seed 缓存采样 | high | 否 | — | NKNGuard 不运行 NKN 全节点。可选对接：把本机 nknd 的 RPC 填进 `nkn.seed_rpc` |
| `internal/httpapi/homesim_tunnel_lifecycle.go`、`homesim_nkn_lifecycle.go` | 重启后恢复 WG/DHT/NKN 已启用状态 | medium | 思路 | `internal/app`（崩溃恢复） | NKNGuard 守护进程自身负责恢复：身份、序号、虚拟 IP、对端缓存落盘 |
| `internal/httpapi/homesim_wireguard.go` | WG 设置模型（对端、端点校验、MTProto 设置）、状态转换 | high | 否 | — | UI/设置层；`validWGEndpoint` 的校验思路已体现在 `nat.EndpointCandidate.Usable` |
| `internal/httpapi/homesim_chat_nkn*.go`、`homesim_license_*nkn*.go` | 聊天、许可证身份与分发 | high | 否 | — | 业务，经 NKN 传输但与组网无关 |
| `cmd/nknpeer/main.go` | NKN 调试工具：gen/address/send/receive/subscribe/subscribers | low | 参考 | `pkg/nknclient`、`nkntopic` | 用作 nkn-sdk-go API 用法的权威参照（本仓库的 NKN 适配器即按其签名编写） |
| `agent/internal/networking/egress_wireguard_test.go` | 蜂窝出口经 WG 的数据面测试 | high | 否 | — | 模组数据面，与 mesh 无关 |
| `agent/internal/unixsocket/listener.go` | Unix socket 监听 | low | 参考 | `internal/app/api.go` | 本地 API 同样只走 Unix socket |
| `deploy/fnos/wireguard/runtime.py`、`wg-ctl.sh`、`wg-server-init.sh`、`wg0.conf.tmpl`、`install-runtime.sh` | FNOS 上的 Python/Shell WG 运行时（`hswg0`/`wg0`，iptables 链 `HOMESIM_WG`） | medium | 否 | 被 `pkg/wireguard` 取代 | 迁移完成前保留；与 NKNGuard 同时运行时注意接口名与网段冲突（`wg0` 10.66.0.0/24 vs `nkg0` 10.88.0.0/16） |
| `deploy/fnos/wireguard/nkn-forward.sh` | 把内置 nknd RPC DNAT 给 WG 对端 | high | 否 | — | NasSimHub 特有 |
| `deploy/fnos/nkn-node/*` | nknd 部署 | high | 否 | — | 不需要 |
| `internal/mobilepairing/*` | Cloudflare/推送配对 | high | 否 | — | 手机配对业务，非组网平面 |
| `internal/modemidentity/*`、`store/line_identity.go` | 模组/线路身份 | high | 否 | — | 名字含 identity，但与设备网络身份无关 |

## 3. 现有数据流（审计时）

```text
            ┌────────────── api 容器（无网络能力） ──────────────┐
 UI/设置 ──▶│ homesim_*_nkn.go ──(NKN MultiClient)──▶ NKN 网络 ──┼──▶ 已配对实例
            │   │  receiveNKNControl: chat / dht / license / wg   │
            │   ▼                                                │
            │ agentclient ──HTTP──┐                              │
            └─────────────────────┼──────────────────────────────┘
                                  ▼
            ┌──────────── agent 容器（host 网络、特权） ──────────┐
            │ internal/wireguard ── wg / ip ──▶ 内核 WG 接口      │
            │ internal/dht ── libp2p host / kad / mDNS ──▶ 对端   │
            └─────────────────────────────────────────────────────┘
 FNOS 宿主机：runtime.py / wg-ctl.sh 另管一个 WG 接口（手机接入用）
```

特点：
1. NKN 与 DHT 是**两条互为备份的控制通道**，只传地址与端点，从不传用户数据 —— NKNGuard 保留这一点，并在此基础上把 NKN 扩展为**中继数据面兜底**。
2. 认证依赖"NKN 加密 + 已配对 NKN 地址 + 固定 WG 公钥"，没有设备根身份，也没有统一的签名消息格式。
3. 没有 NAT 穿透：直连要求至少一端有可达端点（手填 `AdvertisedEndpoint`）。

## 4. NKN 官方组件复用情况

| 组件 | 使用方式 |
|---|---|
| `nknorg/nkn-sdk-go` v1.4.8 | **作为依赖直接使用**：账户、MultiClient、加密消息、`Subscribe`/`GetSubscribers`、会话（`Listen`/`Dial`/`Accept`，底层 ncp） |
| `nknorg/nkn-tunnel` | **未引入**。它解决的是"把一个端口经 NKN 转发出去"，NKNGuard 只需其中"建一条 NKN 会话"这一步，SDK 已直接提供；在其上加的只是 UDP 分帧（`pkg/relay/bridge.go`） |
| `nknorg/nconnect` | **未引入，仅作参考**。其 manager/member 模型需要一个在线管理节点，与"无中心"目标冲突（规范 §2.3） |

没有复制任何官方源码。

## 5. 尚未实现 / 需后续确认

- 规范 §38 的测试基线（见 §0）。
- `peerGate` 式的 libp2p 连接白名单尚未移植到 `pkg/discovery/dht`：目前任何 NKNGuard 节点都能连入 DHT，
  但只能拿到签名记录，无法冒充或授权。是否需要按成员资格限制 DHT 连接，待真实部署评估。
- NasSimHub 的"中国社区 seed 优先"策略：NKNGuard 通过 `nkn.seed_rpc` 配置实现，但默认值为空（使用 SDK 默认 seed）。
  在国内部署时建议把 NasSimHub 已验证的 seed 填入配置。
