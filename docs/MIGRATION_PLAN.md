# NasSimHub → NKNGuard 迁移计划

目标（规范 §1.2、§37、§45）：NKNGuard 成为通用组网基础设施，NasSimHub 成为它的消费者；
不长期维护两套网络代码；每次只替换一个模块，禁止大爆炸式重构。

## 阶段 0：独立验证 NKNGuard（不碰 NasSimHub）

1. 在能访问 Go 模块的机器上：`make deps && go vet -tags "nknsdk libp2pdht" ./... && make build`。
   这是 NKN / libp2p 适配器第一次对真实模块编译，**先做这一步**。
2. 两台 Linux（建议一台 VPS + 一台家里的 NAS）跑 `docs/NAT_TRAVERSAL.md` 末尾的测试矩阵。
3. 记录 `nknguard doctor` 在飞牛 NAS 上的输出（内核是否带 WireGuard 模块、NAT 类型）。
4. 24 小时双节点浸泡测试：RSS、goroutine 数、重连次数。

验收：两节点无手工填地址即可互通；阻断 UDP 后走中继仍可 ping；恢复后回到直连。

## 阶段 1：并行运行（NasSimHub 零改动）

- NAS 上用 systemd 单独运行 NKNGuard，接口 `nkg0`、网段 `10.88.0.0/16`，
  与 NasSimHub 现有 `wg0 10.66.0.0/24`、`hswg0` 互不冲突。
- NasSimHub 的手机接入 WG 服务端保持原样。
- 在 NasSimHub 仓库记录 NKNGuard 的本地 API（`/run/nknguard/nknguard.sock`）供后续接入。

## 阶段 2：状态只读接入

NasSimHub 新增一个 `MeshService` 适配器（规范 §37），只读：

```go
type MeshService interface {
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    Status(ctx context.Context) Status
    Peers(ctx context.Context) []PeerStatus
}
```

实现方式二选一：
- **A. 本地 API**（推荐起步）：NasSimHub 通过 Unix socket 调 `GET /v1/status`、`/v1/peers`。
  api 容器需挂载 `/run/nknguard`。进程隔离、版本可独立升级。
- **B. Go module**：`require github.com/Viper-Boss/nknguard`，在 agent 内直接构造 `mesh.Controller`。
  少一个进程，但把 NKNGuard 的依赖（nkn-sdk-go、libp2p）并入 agent 的构建。

UI 的 WireGuard / DHT 面板先改为显示 NKNGuard 状态。每步都跑 NasSimHub 原有测试。

## 阶段 3：逐个替换（每个一次提交、各自可回滚）

| 顺序 | 替换 | 被替换的 NasSimHub 代码 | 回滚方式 |
|---|---|---|---|
| 3.1 | 端点通告 | `homesim_wireguard_nkn.go` 的 `wireGuardAnnouncement` | 恢复旧 handler |
| 3.2 | DHT 引导 | `homesim_dht_nkn.go` + `agent/internal/dht` | 重新启用 agent DHT |
| 3.3 | 站点间 WG | agent `internal/wireguard` 的站点间对端 | 恢复旧 settings |
| 3.4 | 网络状态 API | `homesim_dht.go`、`homesim_wireguard.go` 的状态部分 | 恢复旧视图 |

**不迁移**（仍属于 NasSimHub）：聊天、许可证、短信转发、NKN 全节点与钱包、手机接入 WG 服务端（`runtime.py` / `wg0`）、
Cloudflare 配对。`receiveNKNControl` 的 if 链在 3.1 之后只剩业务消息，可继续由 NasSimHub 自己的 NKN 客户端处理，
或改为订阅 NKNGuard 的信令（v0.2 可考虑开放"应用消息"通道）。

## 阶段 4：删除重复代码

仅当阶段 3 各步在生产上稳定运行后，删除 NasSimHub 中对应的旧实现；删除前后都跑完整测试。

## 风险与注意

- **两个 NKN 客户端**：阶段 1–3 期间 NasSimHub 与 NKNGuard 各有一个 NKN 身份。这是有意的（隔离），代价是多一份连接。
- **根身份不同**：NKNGuard 设备 ID 与 NasSimHub 的 `NSH-410-xxxx` 设备 ID 是两套体系。
  反向接入时在 NasSimHub 侧维护映射（NasSimHub 设备 ID ↔ NKNGuard `nkg_` ID），不要让 NKNGuard 理解业务 ID。
- **飞牛 NAS 内核**：如果没有 WireGuard 内核模块，需要安装 `wireguard-go`；`doctor` 会提示。
- **时钟**：控制消息要求 ±2 分钟时钟误差，NAS 需开启 NTP。
