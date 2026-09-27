# 交接：Android 客户端第一版（2026-09-27）

分支：`claude/great-archimedes-42vbtk`（基于 `main` 91bf048，尚未开 PR、未合并）。
实现与测试记录详见 [ANDROID.md](ANDROID.md)；本文只列接手需要知道的事。

## 已完成

| 部分 | 位置 | 状态 |
| --- | --- | --- |
| 用户态 WireGuard（wireguard-go on TUN fd） | `pkg/wireguard/userspace` | 实现 + 测试通过 |
| Android 协议核心（JSON 行 IPC、配对、连接、撤销、fd 交接） | `internal/mobile` | 实现 + 端到端测试通过 |
| Android 核心可执行文件入口（嵌套 Go 模块，无需 NDK） | `android/core`（`build.sh`） | 三个 ABI 本地构建通过 |
| Android App（Kotlin，无 AndroidX/Play 服务） | `android/app` | 本地对 API 34 android.jar 类型检查通过 |
| NAS 撤销通知 `ERROR NOT_AUTHORIZED` | `pkg/mesh/controller.go` `refuseUnapproved` | 测试通过 |
| v1 线协议固定向量 | `internal/vectors/testdata/v1.json` | 测试通过 |
| 配对批准顺序修复（先落盘再发送，失败回滚） | `internal/app/pairing.go` `Approve` | 测试通过 |
| Android CI（构建核心 + debug APK 并上传构件） | `.github/workflows/android.yml` | **通过**：run 36318344992 用官方 SDK 构建出 APK，构件 `NKNGuard-android-debug`（18 MB，含 3 个 ABI 的核心） |

## 接手第一件事

1. 从 GitHub Actions `android` 工作流最新一次运行下载构件 `NKNGuard-android-debug`（首次运行已成功），解压得到 `app-debug.apk` 安装。
2. 真机验收（交接文档第 2–5 步全部**未测**）：NAS 面板生成二维码 → 手机扫码 → 核对六位码
   → 批准 → 连接 → 用 NAS 虚拟 IP 访问飞牛；限制 UDP 测中继；撤销后应显示“授权已失效”。
   注意：撤销通知需要 NAS 运行**本分支**构建的 nknguard，旧 NAS 只会不回应。
3. 通过后开 PR 合并到 `main`。

## 真机上最可能出问题的地方（未验证的假设）

- `libnkgcore.so` 作为可执行文件从 `nativeLibraryDir` 启动（依赖 `useLegacyPackaging=true`
  解压）。若启动失败，看应用内“复制诊断信息”里的核心日志。
- armeabi-v7a / x86_64 用的是静态 **Linux** 构建（Go 不支持无 cgo 的 android/arm、android/amd64），
  依赖 `SSL_CERT_DIR`；arm64 是 `GOOS=android` 原生构建，是主要目标。
- Android 14+ 前台服务类型：先试 `systemExempted`，失败回退 `specialUse`（`NkgVpnService.goForeground`）。
- 应用把自己排除在 VPN 外（`addDisallowedApplication`）代替 `protect()`；因此 `mesh.UDPNudge`
  在手机上无效，已改用 `userspace.Manager.Nudge` 直接触发握手。
- NKN 连接走核心自己的 DNS 解析器（`internal/mobile/dns.go`，应用上报的 DNS + 223.5.5.5 等兜底）。
- 通知栏“断开”用 `PendingIntent.getService`；如在某些 ROM 上后台启动被拦，改为广播接收器。
- 开发环境无法连到 NKN 网络，**真实 NKN 配对/中继从未跑过**，只在进程内环回传输上测过。

## 设计要点（改动前请读）

- IPC 协议：请求 `{"id","cmd","args"}` → 响应 `{"id","ok","error","result"}`；事件 `{"event","data"}`
  （`secrets`、`status`、`pair_status`、`revoked`）。命令：`init network parse_invite pair pair_cancel
  prepare connect disconnect status forget diagnostics shutdown`。状态修改类命令按到达顺序串行。
- `secrets` 事件携带全部密钥（base64），应用在读取下一行之前同步写入 Keystore 加密文件；
  核心不落盘任何密钥。
- `connect` 流程：`prepare` 得到虚拟 IP → `VpnService.Builder` 建接口（只路由 10.88.0.0/16）→
  `connect{token}` 与经 `files/run/tun.sock` 发送的 fd 并发，令牌配对 → 应用关闭自己的 fd 副本。

## 审查已有代码的结论（codex 提交）

- 已修：`Pairing.Approve` 先发送入网密钥后写批准名单——写盘失败会让手机拿到密钥却未被批准，
  且与新的撤销通知竞态。现改为先落盘/生效，发送失败回滚并保留待批准项。
- 已修（文档）：`PROTOCOL.md` 缺 `dht_addresses` 字段、未说明 Go JSON 的 `<>&` 转义规则。
- `go mod tidy` 把 `golang.org/x/crypto`、`x/term`（被直接使用）从 indirect 移为直接依赖。
- 检查无问题：面板与 Windows 客户端 UI 均用 `textContent`，配对申请中的设备名不会造成 XSS；
  面板仅限回环 Host、动作需同源头；Windows 客户端本地接口有会话 token + Origin 校验。
- 未修、建议后续：面板 Basic 认证每个请求都做 bcrypt 且无失败限速（仅本机监听，风险低）；
  网页修改密码不会删除旧版 `first-run.txt`（其中是已失效的旧密码）；
  Windows 客户端把会话 token 放在 Edge 命令行参数中（本机其他进程可见）；
  `deploy/systemd/nknguard-fnos-disk.service` 文档中以 `nknguard.service` 名称安装，建议统一命名。

## 未做

- 真机测试、release 签名、开机自启/始终开启 VPN、NAS 自定义 `overlay_cidr` 的支持
  （二维码不带网段）、手机端 NKN topic/DHT 发现、Kotlin 单元测试。
