开发预览版。/ Development preview.

## 下载 / Downloads

| 文件 / File | 平台 / Platform |
| --- | --- |
| `nknguard-linux-arm64` | NAS / Linux ARM64（飞牛 ARM 机型 / ARM fnOS） |
| `nknguard-linux-amd64` | NAS / Linux x86_64 |
| `NKNGuard-Windows-preview.zip` | Windows 10/11 原生客户端（需先安装 WireGuard for Windows / needs WireGuard for Windows） |
| `NKNGuard-Android-preview.apk` | Android 8.0+ |
| `SHA256SUMS` | 校验 / checksums: `sha256sum -c SHA256SUMS` |

## 更新内容 / What's new

- **断线后更快恢复**：以前直连断了要等 WireGuard 握手超过 3 分钟才发现；现在双方每 25 秒互发保活包，接收计数 55 秒不动就判定链路失效，再过 10 秒切到 NKN 中继并重新打洞，整体约 1 分钟。中继流断了也会自动重开。
  A dead path is now noticed after about a minute (received-byte silence) instead of three; silent relay streams are reopened.
- **换网络立即重连（Windows / Linux / NAS）**：程序每 5 秒检查本机地址，变化后立即给对端发包、重新探测地址并通知对端，不再等定时器。Android 之前已有系统网络变化通知，现在走同一套逻辑。
  The daemon watches local addresses and reconnects at once on a change, like the Android app.
- **休眠唤醒**：电脑睡眠后恢复时重新检查链路，不会把还能用的链路误判为断线。
  Paths are re-checked after resume from suspend instead of being declared dead.
- 包含 preview.4 的全部内容：Windows 原生客户端、面板配对链接、使用人数统计等。
  Includes everything from preview.4.
- v1 线协议未改变，新旧版本可以互通；但更快的断线判定只在升级后的一端生效，建议 NAS 和客户端都升级。
  The v1 wire protocol is unchanged; upgrade both ends to get the faster detection on both.

## 注意 / Caveats

- **Android 客户端尚未完成真机测试**；问题请附上 App 内“复制诊断信息”的内容。
  The Android client has **not yet been tested on real devices**.
- **新的 Windows 界面只在 Wine 中运行检查过**，尚未在真实 Windows 上测试托盘和 UAC 授权。
  The new Windows window was checked under Wine only; tray and UAC are untested on real Windows.
- APK 使用 CI 临时 debug 密钥签名，**升级前需先卸载旧版**。
  **Uninstall the previous APK before installing** (throwaway CI signing key).
- 程序均未进行代码签名；请勿为此关闭系统防护。
  Binaries are not code-signed; do not disable security software to run them.
- 升级 NAS 只需替换程序文件，身份、配对数据和面板密码不受影响。
  Upgrading the NAS only replaces the binary; identity, pairings and the dashboard password are kept.
