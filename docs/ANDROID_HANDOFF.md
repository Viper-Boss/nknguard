# NKNGuard Android 客户端交接文档

更新时间：2026-09-27。交接基线：公开仓库
[`Viper-Boss/nknguard`](https://github.com/Viper-Boss/nknguard)，
`main` 的 GitHub 提交 `0205015634015b694253f19a39d5da668e2e8efc`
（本地对应提交 `ee32548`，源码树相同）。协议以本仓库代码为准；
本文是开发任务和索引，不是另一个独立的协议版本。

## 给接手开发者的任务

在本仓库新增一个真正可用的 Android 客户端。用户在 NAS 面板生成一次性
配对二维码，用 Android 手机扫描或粘贴其内容，手机通过 NKN 发送签名申请，
显示六位验证码；NAS 主人在面板核对并批准后，手机保存设备身份和入网材料。
以后用户点击“连接”才启动 Android VPN，优先尝试 WireGuard 直连 NAS，
无法直连时通过 NKN 会话转送 **WireGuard 密文**；点击“断开”要停止 VPN、
NKN 会话及相关后台任务。界面显示 NAS NKN 地址、虚拟 IP、真实链路状态
和流量，不得用定时动画冒充已经建立的链路。

交付 Android 工程、可安装的测试 APK、构建说明、关键互通测试和实机测试记录。
不要修改或重置现有 NAS 的身份、配对数据、管理密码及其他大盘数据；
不把任何真实密码、二维码、入网密钥或设备私钥提交到仓库。

## 当前项目状态

| 部分 | 当前状态 |
| --- | --- |
| fnOS NAS | ARM64 独立 systemd 服务运行在已有数据盘 `/mnt/docker-data/nknguard`；不是应用中心 FPK 安装。服务和 `nkg0` 已验证运行。|
| NAS 控制面板 | 仅监听 NAS 的 `127.0.0.1:7878`；管理员密码由用户设置，密码哈希已验证保存，旧随机密码文件已清除。|
| Windows 客户端 | 有 GUI 预览版和 ZIP；编译、单元测试通过，尚未完成与该 NAS 的真实端到端配对、直连、中继测试。|
| Android 客户端 | 已实现（`android/`、`internal/mobile`），自动化互通测试通过，APK 由 CI 构建；尚未真机测试。见 [ANDROID.md](ANDROID.md)。|
| FPK | 0.1.1 ARM64 包已构建并隔离测试；此 NAS 没有可用的应用中心安装卷，所以未在应用中心实装。|

不要将现有 Windows 预览版的功能描述直接当作 Android 已可互通的证据。
Android 联调若暴露协议问题，修复时应保持 NAS 与 Windows 的兼容性，
增加跨平台测试向量并记录协议变更。

## 必读源码与文档

- [`docs/PROTOCOL.md`](PROTOCOL.md)：v1 标识符、签名、消息、发现、帧格式和时间限制。
- [`docs/PAIRING.md`](PAIRING.md)：用户可见的配对、批准、撤销和路径选择。
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md)、[`docs/NAT_TRAVERSAL.md`](NAT_TRAVERSAL.md)、[`docs/SECURITY.md`](SECURITY.md)：控制面、NAT 与安全边界。
- `internal/app/pairing.go`、`internal/app/pair_client_nkn.go`：二维码编解码、申请、验证码、NAS 批准和客户端收取入网材料；这些是配对互通的代码依据。
- `pkg/protocol/{envelope,types}.go`、`pkg/identity/identity.go`、`pkg/membership/membership.go`：签名、设备 ID 和成员证明。
- `pkg/signaling/nknsignal/nknsignal.go`、`pkg/nknclient/client.go`：NKN 控制消息及地址规范化。
- `pkg/discovery/record.go`、`pkg/mesh/{controller,reconcile,selector,ipalloc}.go`：已签名对端记录、路径判断和虚拟 IP。
- `pkg/relay/{bridge,hub}.go`、`pkg/relay/nknrelay/nknrelay.go`：NKN 会话与 WireGuard 密文转发。
- `pkg/wireguard/manager.go`：需要在 Android 实现的数据面抽象。
- `cmd/nknguard/client_windows.go` 与 `cmd/nknguard/clientui/`：Windows 交互流程参考；不应直接移植窗口和提权方式。

## 必须保持的 v1 互通约束

1. 根身份是 Ed25519。设备 ID 为 `nkg_` 加根公钥 SHA-256 前 10 字节的
   小写、无填充 base32。NKN 账号种子与根身份、WireGuard 私钥是不同的密钥。
2. 配对 URI 为 `nknguard://pair/v1?data=` 加 URL 转义的、无填充
   base64url(JSON)。`PairInvite` 字段和校验见 `internal/app/pairing.go`：
   版本 1、NAS 设备 ID/根公钥/NKN 地址、网络 ID、令牌和过期时间。
   二维码 **不含** `join_secret`。邀请有效五分钟，NAS 重新生成邀请后旧令牌失效。
3. 配对申请是发往邀请中的 NAS NKN 地址的、根身份签名的 `PAIR_REQUEST`；
   字段为 `token`、`name`、`nkn_address`、`wireguard_public_key`。
   NAS 要求 NKN 实际来源地址与申请体地址相同。申请本身不授予成员资格。
4. 六位码的精确算法是
   `SHA256(JSON({"Token":token,"DeviceID":deviceID,"WGKey":wgPublicKey}))`
   前四字节大端整数模 `1000000`，再左侧补零至六位。这里的 JSON 字段名
   **首字母大写**，来自 Go 的匿名结构体；跨语言实现必须用测试向量核对。
5. 只有 NAS 本地批准后，手机才接受加密 NKN 消息 `PAIR_APPROVAL`。
   同时核对信封签名、二维码钉住的 NAS 根公钥与设备 ID、网络 ID、
   `invite_token`、`nas_address`。`join_secret` 只在这条已加密消息中传输，
   安全落盘，绝不写日志、通知、崩溃报告或普通偏好设置。
6. 信封为 Ed25519 签名的 JSON。签名字节是将 `signature` 设为 nil/省略后，
   用 Go `encoding/json` 按结构体声明顺序编码的结果；`[]byte` 是标准
   base64。跨语言实现必须逐字节匹配。接收端验证版本、设备 ID 与公钥绑定、
   网络与目标、签名、时钟窗口、重放、成员身份；限制 64 KiB。
7. 对端记录也按 Go JSON 规则签名，并带成员 HMAC 证明。发现到某个 NKN
   地址或 DHT 记录并不等于获得连接权限。记录默认有效两分钟，30 秒重发；
   只安装覆盖网络 CIDR 内的虚拟 IP 为 WireGuard AllowedIPs。
8. NKN 中继通过 ncp 会话传送 WireGuard 数据报：每帧为 **2 字节大端长度 +
   原始 WireGuard 密文**。不能把解密后的 IP 数据包直接发进 NKN。
   路径是否可用以 WireGuard 实际握手和流量为准，不能仅以 NKN 消息送达为准。

`docs/PROTOCOL.md` 的时序、能力名称及消息结构还需与源码同步核对；
遇到冲突以目前运行的 Go 实现为准，并在同一改动中修正文档与互通测试。

## Android 平台实现边界

现有 `internal/app.RunDaemon` **不能直接作为 Android 后台服务运行**：
`pkg/wireguard/host_other.go` 在非 Windows 平台选用 Linux `wg`/`ip`
管理器，`internal/app/privilege_other.go` 还要求 root。Android 应使用
`VpnService` 和获得用户授权的前台服务，配置仅到 NAS 覆盖网络地址的路由；
不能要求 root，也不能修改全机默认路由。NKN 的控制/中继连接必须用
`VpnService.protect()` 排除在 VPN 隧道之外，避免路由回环。

建议先做小型可编译探针，验证现有 Go NKN SDK/核心包能否通过 gomobile
或 JNI 在 Android 上稳定运行，再确定“复用 Go 协议核心 + Kotlin/Java
VPN 适配层”还是原生移植。**不要假定整个 Go 守护进程可直接打包为 APK。**
无论哪种实现，保持 v1 线协议完全一致。若移动端暂不参与 libp2p DHT，
可先使用二维码保存的 NAS NKN 地址作静态引导，再通过现有 NKN 信标更新；
DHT 是额外发现路径，不是首次配对或身份验证的前提。

手机密钥使用 Android Keystore 保护或加密包装，并明确备份/换机策略；
断开时销毁 VPN、关闭会话与 socket、停止前台服务，不删除用户已批准的
设备身份。被 NAS 撤销后必须显示失效状态，不能凭本地旧材料继续声称已连接。
界面应有相机扫码及粘贴回退、六位码核对、NAS NKN 地址显示、连接/断开、
直连/中继/等待/错误状态和可复制的脱敏诊断。

## 建议开发顺序与验收

1. **协议互通**：从 Go 实现导出固定测试向量，验证 Android 侧 QR 解析、
   设备 ID、六位码、签名字节、成员证明、签名记录与中继帧；包括篡改、
   过期、重放、错误来源地址测试。
2. **配对实机**：在 NAS 面板生成邀请，Android 扫码申请，双方六位码一致，
   NAS 批准后手机安全落盘；拒绝或超时不入网，重新生成邀请令旧申请失效。
3. **VPN 基础**：用户点击连接后请求 Android VPN 授权，只路由 NAS 的覆盖
   网络 IP；点击断开后路由和后台任务消失。验证飞牛客户端能访问 NAS 的
   虚拟 IP，普通手机上网不受影响。
4. **路径选择**：在不同网络下实测直连；限制 UDP 后实测 NKN 中继；恢复
   UDP 后实测返回直连。界面展示实际握手、路径、吞吐和错误；测试重连
   先尝试已验证的上次端点，同时获取最新信标。
5. **生命周期**：锁屏、网络切换、蜂窝/Wi-Fi 切换、NKN 暂断、NAS 重启、
   Android 杀进程、撤销授权、应用升级和卸载后均无错误 VPN 残留。

请在交付记录里分别标记“编译通过”“自动化测试通过”“真机配对通过”
“真机直连通过”“真机中继通过”；任何一项未测都明确写未测。
不以展示一个连接动画或能够打开 NAS 面板代替 VPN 端到端验收。
