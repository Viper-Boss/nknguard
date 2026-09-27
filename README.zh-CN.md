# NKNGuard

**基于 NKN 的无服务器 WireGuard 组网。**

NKNGuard 把你的多台机器组成一个私有 WireGuard 网络，不需要任何中央协调服务器：
节点通过 [NKN](https://nkn.org) 网络互相发现、交换密钥，用 WireGuard 自己的握手包
打洞穿透 NAT；打不通时自动退回到经 NKN 中继的路径。

```text
Tailscale:  节点 ── 协调服务器 ── 节点            （+ DERP 中继）
NKNGuard:   节点 ── NKN 信令 / DHT ── 节点        （+ NKN 中继）
                        │
                        └─ 数据面：WireGuard，NAT 允许时一律直连
```

- **数据面是 WireGuard**：内核 WireGuard 或 wireguard-go，NKNGuard 不碰任何包加密。
- **控制面是 NKN**：带签名、带版本号的控制消息以端到端加密的 NKN 消息传输，链路上没有我们的服务器。
- **发现层默认不可信**：节点可通过 NKN 主题、私有 Kademlia DHT 或静态列表被找到。每条记录都由设备根密钥签名并携带入网证明，来源本身不带来任何信任。
- **先直连、后中继**：中继只保证"连得上"。走中继期间持续重试直连，一旦成功自动切回。
- **隧道比控制面活得久**：NKN 或 DHT 掉线时，已建立的 WireGuard 隧道继续工作；守护进程崩溃时接口和对端保持不变，直到它被重新拉起。

> **状态：开发预览版。** NAS/Linux 守护进程、浏览器控制面板、二维码授权、Windows 一键连接客户端和 NKN/WireGuard 通道已有实现及自动测试；尚未完成真实 fnOS、Windows 与跨 NAT 联调。Android 客户端已实现并通过自动化互通测试，尚未完成真机测试（见 [docs/ANDROID.md](docs/ANDROID.md)）。

## 快速开始

要求：Linux（amd64 / arm64）、`wireguard-tools`（`wg`、`ip`）、内核 WireGuard 或 `wireguard-go`、root 权限、时钟误差在 ±2 分钟内。

```bash
make deps && make build          # 需要 Go ≥ 1.25.7，首次需要能拉取 Go 模块
sudo ./scripts/install.sh
```

第一台设备：

```bash
sudo nknguard init --name nas-home
```

启动 NAS 并打开本地管理面板：

```bash
sudo systemctl enable --now nknguard
# 在 NAS 本机浏览器打开 http://127.0.0.1:7878/
# 或从电脑安全地转发：ssh -L 7878:127.0.0.1:7878 user@nas
```

浏览器使用管理员账号 `admin` 和首次安装时自己设置的密码登录；忘记密码时，NAS 管理员可运行 `sudo nknguard dashboard-password set` 重设。面板首页显示 NAS 的完整 NKN 地址并提供复制按钮，方便与客户端核对。首次打开面板自动显示五分钟有效的二维码。二维码只包含 NAS 身份公钥、NKN 地址和一次性申请令牌。另一台 Linux 设备可执行 `sudo nknguard pair '<二维码内容>' --name laptop`；Windows 客户端可粘贴二维码内容，在 NAS 面板核对六位码并批准。Windows 安装方式见 [docs/WINDOWS.md](docs/WINDOWS.md)。

默认开启设备级批准。NAS 可以在面板撤销单台设备。旧式 `join --secret` 和 `invite` 只在显式设置 `pairing.approval_required: false` 时可用。

面板默认只监听 NAS 的 `127.0.0.1:7878`。请勿把管理端口直接映射到公网。配对流程与部署细节见 [docs/PAIRING.md](docs/PAIRING.md)。

旧式模式的 ACL 默认**拒绝**，需要在 `/etc/nknguard/config.yaml` 中放行所需访问。设备级批准模式使用 NAS 本地批准名单：

```yaml
acl:
  default: deny
  rules:
    - src: laptop
      dst: nas-home
      action: allow
```

配对完成后，每台设备：

```bash
sudo systemctl enable --now nknguard      # 或前台运行：sudo nknguard up
nknguard status
nknguard doctor
```

## 节点如何互相发现

| 方式 | 配置 | 代价 |
|---|---|---|
| **NKN 主题**（默认开启） | 无需配置 | 主题名由入网密钥派生；订阅者列表公开，知道主题名的人能看到有哪些 NKN 地址 |
| **私有 DHT**（`libp2pdht` 构建标签） | 引导节点，或局域网 mDNS | 项目私有 Kademlia，绝不加入公共 IPFS DHT |
| **静态对端**（`static_peers`） | 互相填写对方 NKN 地址 | 完全不公开任何信息 |

无论来源如何，只有签名有效、入网证明匹配的记录才会被接纳，且只有 ACL 允许时才会建隧道。

## 局限（如实说明）

- **不是所有 NAT 都能穿透**。双方都在对称型 NAT 后面时几乎一定走中继。`nknguard doctor` 会告诉你属于哪种情况。
- **中继很慢**。走 NKN 会话，吞吐远低于直连，只是兜底。
- **内核 WireGuard 独占 UDP 端口**，公网端口是根据探测 socket 推断的（假设 NAT 保持端口不变）。大多数家用路由器成立，部分不成立。
- **成员证明仍基于共享密钥**。NAS 以批准的设备公钥身份名单执行单设备撤销；若共享密钥泄露或客户端身份私钥丢失，应重建/轮换网络凭证。密钥轮换自动化尚未实现。
- **Windows 客户端目前是预览版**，需要安装官方 WireGuard for Windows 与 Microsoft Edge；Android 客户端为预览版，见 [docs/ANDROID.md](docs/ANDROID.md)。当前仅 IPv4 覆盖网络，每个节点只能加入一个网络。
- **不匿名**。WireGuard 端点会向对端暴露 IP，NKN 地址可被长期关联，STUN 服务器能看到你的公网地址。
- **尚未完成真实网络验证**。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。此前已经发布的预览版二进制和历史提交仍按当时的 Apache-2.0 条款提供；本次修订及之后的版本采用 AGPL-3.0-only。
