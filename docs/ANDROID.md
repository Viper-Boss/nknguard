# NKNGuard Android 客户端

Android 客户端让手机扫描 NAS 面板上的一次性二维码完成配对，之后由用户点击
“连接”启动 VPN：优先 WireGuard 直连 NAS，无法直连时经 NKN 会话转送
**WireGuard 密文**。本文是构建说明、实现说明和测试记录。交接要求见
[ANDROID_HANDOFF.md](ANDROID_HANDOFF.md)。

## 结构

```text
Android 应用（Kotlin，android/app）              Go 协议核心（internal/mobile，android/core）
┌──────────────────────────────┐   stdin/stdout  ┌────────────────────────────────────────┐
│ MainActivity  扫码/粘贴/验证码 │ ◀─ JSON 行 ──▶ │ 配对：app.ParsePairInvite / PairCode    │
│ ScanActivity  Camera2 + ZXing │                 │ 网格：mesh.Controller（客户端角色）      │
│ NkgVpnService VpnService      │ ── TUN fd ────▶ │ 数据面：wireguard-go（pkg/wireguard/     │
│ SecretVault   Keystore 加密   │  Unix socket    │        userspace）                      │
│ NetworkInfo   本地地址/DNS    │  SCM_RIGHTS     │ NKN：nknsignal + nknrelay（ncp 会话）    │
└──────────────────────────────┘                 └────────────────────────────────────────┘
```

- **协议不重写。** 手机执行的签名、信封校验、配对校验、签名对端记录、成员证明、
  中继分帧和路径选择，都是 NAS 与 Windows 运行的同一份 Go 代码；Kotlin 只做界面、
  VPN 与密钥存储。这是“v1 线协议完全一致”最直接的保证。
- **核心是子进程，不是 JNI。** `libnkgcore.so` 其实是一个可执行文件，放在
  `lib/<abi>/` 下是为了让系统把它解压到应用的原生库目录——Android 10 以后应用
  只能执行那里的文件。构建不需要 NDK：arm64 用 `GOOS=android` 原生构建；Go 无法在
  不启用 cgo 时链接 android/arm 与 android/amd64，所以 32 位 ARM 与 x86_64
  （模拟器）用静态 Linux 构建，由应用通过 `SSL_CERT_DIR` 指定系统证书目录。
- **进程生命周期即 VPN 生命周期。** 应用把 TUN 描述符交给核心后立即关闭自己的副本，
  核心是唯一持有者。核心在标准输入关闭（应用进程死亡）时退出，内核随即删除 VPN
  接口，不会留下“看似连接、实际不通”的残留。
- **路由。** VPN 只添加当前 NAS 虚拟地址的 `/32` 路由、不设置 DNS，普通上网和域名解析不受
  影响；不需要 root，不改默认路由。应用把**自己**排除在 VPN 之外
  （`addDisallowedApplication`），核心里 NKN SDK、STUN、wireguard-go 打开的每一个
  socket 都走真实网络——效果等同于对每个 socket 调用 `VpnService.protect()`，但覆盖
  第三方库内部创建、应用无法逐个 protect 的 socket。
- **Android 特有适配。** Go 在 Android 11+ 无法枚举网卡、也没有 `resolv.conf`，
  应用把当前底层网络的本地地址和 DNS 报给核心；网络切换（Wi-Fi↔蜂窝）时核心重新
  绑定 WireGuard 套接字、重新收集候选地址并立即重试直连。

### 密钥与备份策略

根身份种子、WireGuard 私钥、NKN 种子和入网密钥只以内存形式存在于核心进程；持久化
的持久副本由 NAS 配置分别保存；原有 NAS 保留在 `files/secrets.bin`，新增 NAS 位于 `files/nas/<随机配置 ID>/secrets.bin`，由 Android Keystore 中生成、不可导出的 AES-256-GCM
密钥加密。应用关闭了云备份和设备迁移（`allowBackup=false` 与
`data_extraction_rules.xml`）：备份出去的密文在别的设备上无法解密。**换机需要重新
配对**，并建议在 NAS 面板撤销旧手机。入网密钥不会写入日志、通知、崩溃报告或普通偏好
设置；诊断信息对长十六进制/Base64 串做脱敏。

若系统恢复等原因导致 Keystore 密钥丢失，应用会把无法解密的文件改名保留、生成新
身份并提示重新配对。

### 撤销

NAS 端新增行为：对持有有效成员证明、签名与时效均合法、但不在批准名单中的设备发来的
`PEER_INFO`，NAS 用自己的根身份回复签名的 `ERROR NOT_AUTHORIZED`（每设备每分钟至多
一次，只回复记录中声明且与实际来源一致的 NKN 地址；无有效成员证明的陌生人得不到任何
回复）。手机验证它来自二维码中钉住的 NAS 身份后，结束会话、关闭 VPN、把配对标记为
失效，界面显示“授权已失效”，直到解除配对并重新扫码。旧版 Windows 客户端收到该消息
只会记录一条日志，兼容。

### 状态显示

界面与通知只显示观察到的事实：阶段为“已连接 · 直连 / NKN 中继”仅当 WireGuard 在
3 分钟内与 NAS 完成过握手且控制器选择了该路径；其余情况显示“正在连接 NKN”
“等待与 NAS 握手”等。显示内容包括 NAS NKN 地址（可复制）、NAS 设备 ID、本机与 NAS
虚拟 IP、链路、WireGuard 端点、最近握手时间、收发流量和本机 NKN 地址。连接卡片提供动画；动画展示状态，不代替实际握手结果，关闭系统动画时也会停止。

## 多 NAS 管理（0.2.12）

首页“我的 NAS”列出已保存的服务器。点“扫码添加 NAS”申请另一台 NAS 的授权，
在其控制台核对验证码并批准。点卡片切换，点卡片右侧菜单重命名或删除。
切换时先断开当前 VPN，再加载所选 NAS；不会同时接管多个 NAS 的网段。
各配置分别保存根身份、NKN 身份、WireGuard 密钥、入网密钥和连接缓存。
升级沿用原来的存储路径，不需要重新扫码；删除一台不影响其他台。

## 构建

需要 Go 1.25.7、JDK 17、Android SDK（compileSdk 35）。不需要 NDK。

```sh
cd android
./gradlew assembleDebug          # 会先执行 core/build.sh 构建三个 ABI 的 Go 核心
# 输出：app/build/outputs/apk/debug/app-debug.apk（包名 io.github.viperboss.nknguard.debug）
```

只构建核心：`android/core/build.sh [输出目录]`；`NKG_ABIS="arm64-v8a"` 可只构建
一个 ABI。已放好核心时用 `./gradlew assembleDebug -PskipGoCore=true`。

GitHub Actions 的 `android` 工作流在每次相关改动时运行核心测试、构建所有 ABI 的核心和
debug APK，并上传为构件 `NKNGuard-android-debug`。debug APK 由 CI 临时 debug 密钥签名，
不同次构建之间不能覆盖安装（需先卸载）；正式发布需要另行配置 release 签名密钥，
密钥不得提交到仓库。

## 使用

1. 在 NAS 面板“配对与授权”中生成二维码。
2. 手机打开 NKNGuard，点“扫码配对”（也可“粘贴配对内容”，或用系统相机扫码后
   由 `nknguard://pair/...` 链接直接打开应用）。确认 NAS 设备 ID 与设备名称后发送申请。
3. 手机显示六位验证码；在 NAS 面板核对同一验证码后点“核对后批准”。
4. 手机提示已批准后点“连接”，首次需同意系统 VPN 授权。连接后可用 NAS 的虚拟 IP
   （界面中“NAS 虚拟 IP”）访问 NAS 服务。点“断开”或通知中的“断开”停止 VPN、NKN
   会话和后台任务。

## 测试记录（2026-09-27）

| 项目 | 结果 | 说明 |
| --- | --- | --- |
| 编译通过 | **Go 核心：通过**（android/arm64、linux/arm、linux/amd64）；**Kotlin：通过**（本地以 API 34 android.jar 类型检查）；**APK：通过**（GitHub Actions run 36318344992） | 开发环境无法访问 Google Maven，APK 由 CI 用官方 SDK 构建 |
| 自动化测试通过 | **通过** | 见下 |
| 真机配对通过 | **未测** | 开发环境没有 Android 设备，也无法连到 NKN 网络 |
| 真机直连通过 | **未测** | 同上 |
| 真机中继通过 | **未测** | 同上 |

自动化测试覆盖（`go test -race`）：

- `internal/mobile`：进程内 NAS（生产用 `Pairing`、所有者角色 `mesh.Controller`、
  wireguard-go）与手机核心经真实 JSON 行接口完成：二维码解析 → 签名申请 →
  **双方六位码一致** → NAS 批准 → 入网密钥交给应用存储 → VPN 地址分配 → 经中继
  完成 WireGuard 握手 → **手机 TUN 的 ping 抵达 NAS TUN** → NAS 撤销 → 手机收到签名的
  NOT_AUTHORIZED、断开并显示失效 → 解除配对后设备 ID 不变。另测：冒充 NAS 的批准
  （错误身份、伪造设备 ID）被拒绝，二维码过期后配对失败；fd 交接（令牌、先到的 fd、
  超时）；密钥存储；诊断脱敏。
- `pkg/wireguard/userspace`：两台 wireguard-go 设备直连握手与计数、端点切换、主动
  握手、移除对端；经生产中继桥接器握手并确认中继流上不出现明文 IP 负载。
- `internal/vectors`：v1 线协议固定向量（见 [PROTOCOL.md](PROTOCOL.md)）。
- `pkg/mesh`：撤销设备收到 NOT_AUTHORIZED 且限速，陌生人无回复。
- 编译出的 Linux 版核心已用真实 stdin/stdout 协议做过冒烟测试。

尚需真机完成的验收（交接文档第 2–5 步）：真实 NAS 配对、蜂窝与 Wi-Fi 下直连、限制
UDP 后中继、恢复后切回直连、锁屏/网络切换/NAS 重启/杀进程/撤销/升级/卸载后无 VPN
残留。建议记录时复制应用内“诊断信息”。

## 已知限制

### 0.2.1 连接可靠性修复

- Go 核心发出密钥变更后等待应用的保存确认；Keystore/文件保存失败会导致初始化或配对失败，
  不再报告配对成功，之前的内存密钥保留。
- 缓存端点探测与 NKN 初始化并行；界面只有观察到实际 WireGuard 握手才显示直连成功。
  NKN 上线后立即请求 NAS 的最新签名记录。
- 断开超时会终止核心，必要时强制结束，并等待进程确认退出后移除通知；清理失败明确报告错误。
- 服务销毁只安排后台清理，不在主线程等待。旧核心退出事件不会清除新核心的请求。

本次源码修复不代替以下真机验收；请同时更新 APK 内置核心和 Kotlin 层，二者的本地 IPC 增加了
`secrets` 的 `sequence` 及 `secrets_ack` 确认消息，NAS/Windows 的 v1 网络协议不变。

- 覆盖网络固定为默认的 `10.88.0.0/16`（二维码不携带 NAS 的网段，Windows 客户端同样
  如此）。NAS 若改了 `overlay_cidr`，手机无法安装 NAS 的虚拟 IP。
- 手机不加入 NKN pub/sub 主题和私有 DHT，以配对时钉住的 NAS NKN 地址做静态引导，
  由 NAS 回复最新签名记录。NAS 更换 NKN 地址后需重新配对。
- 移动网络多为对称/运营商级 NAT，直连成功率取决于 NAS 一侧的 NAT；失败时走中继。
- 未实现开机自启与“始终开启的 VPN”；只在用户点击“连接”后运行。
