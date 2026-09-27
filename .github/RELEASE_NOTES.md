开发预览版。**首次包含 Android 客户端。** / Development preview. **First release with the Android client.**

## 下载 / Downloads

| 文件 / File | 平台 / Platform |
| --- | --- |
| `nknguard-linux-arm64` | NAS / Linux ARM64（飞牛 ARM 机型 / ARM fnOS） |
| `nknguard-linux-amd64` | NAS / Linux x86_64 |
| `NKNGuard-Windows-preview.zip` | Windows 10/11（需先安装 WireGuard for Windows 与 Edge / needs WireGuard for Windows and Edge） |
| `NKNGuard-Android-preview.apk` | Android 8.0+ |
| `SHA256SUMS` | 校验 / checksums: `sha256sum -c SHA256SUMS` |

## 更新内容 / What's new

- **Android 客户端**：扫码配对、六位码核对、一键连接，优先 WireGuard 直连，失败走 NKN 中继。
  Android client: scan-to-pair, six-digit code check, one-tap connect, direct WireGuard first with NKN relay fallback.
- **内置国内 NKN seed**：国内网络更容易连上 NKN；顺序为 `nkn.seed_rpc` → 国内 seed → 官方 seed。
  Built-in China NKN seed tried before the official seeds.
- **撤销通知**：NAS 撤销设备后，该设备收到签名通知并立即断开（需要 NAS 使用本版本）。
  Revoked devices receive a signed notice and disconnect (requires this NAS version).
- **配对批准更可靠**：先写入批准名单，再发送入网密钥。
  Pairing approval now persists before the join secret is sent.
- **面板**：错误密码限速；网页修改密码后删除旧版 `first-run.txt`。
  Dashboard: wrong-password back-off; web password change removes the legacy `first-run.txt`.
- v1 线协议未改变，与 v0.1.0-preview.1 的 NAS 和 Windows 客户端兼容。
  The v1 wire protocol is unchanged and compatible with preview.1.

## 注意 / Caveats

- **Android 客户端尚未完成真机测试**，请在非关键设备上试用，问题请附上 App 内“复制诊断信息”的内容。
  The Android client has **not yet been tested on real devices**; please attach the in-app diagnostics when reporting problems.
- APK 使用 CI 临时 debug 密钥签名，**升级前需先卸载旧版**。
  The APK is signed with a throwaway CI debug key; **uninstall the previous build before installing**.
- 所有程序均未进行代码签名，安全软件可能提示；请勿为此关闭系统防护。
  Binaries are not code-signed; do not disable security software to run them.
- 升级 NAS 只需替换程序文件，身份、配对数据和面板密码不受影响。
  Upgrading the NAS only replaces the binary; identity, pairings and the dashboard password are kept.
