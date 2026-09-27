开发预览版。/ Development preview.

## 下载 / Downloads

| 文件 / File | 平台 / Platform |
| --- | --- |
| `nknguard-linux-arm64` | NAS / Linux ARM64（飞牛 ARM 机型 / ARM fnOS） |
| `nknguard-linux-amd64` | NAS / Linux x86_64 |
| `NKNGuard-Windows-preview.zip` | Windows 10/11（需先安装 WireGuard for Windows 与 Edge / needs WireGuard for Windows and Edge） |
| `NKNGuard-Android-preview.apk` | Android 8.0+ |
| `SHA256SUMS` | 校验 / checksums: `sha256sum -c SHA256SUMS` |

## 更新内容 / What's new

- **匿名使用人数**：NAS 面板、Windows 客户端和 Android App 显示最近 24 小时 / 30 天 / 90 天运行过 NKNGuard 的设备数。数据来自 NKN 链上的零手续费订阅（`nknguard.usage.*`），不经过任何服务器；链上只出现一个由本机密钥单向派生的匿名公钥。默认开启，三端都可关闭，详见 [docs/USAGE_STATS.md](https://github.com/Viper-Boss/nknguard/blob/main/docs/USAGE_STATS.md)。
  Anonymous 24 h / 30 d / 90 d user counts from zero-fee NKN subscriptions, shown on all platforms; on by default, can be switched off.
- 包含 preview.2 的全部内容：Android 客户端、内置国内 NKN seed、撤销通知、配对批准修复、面板改进。
  Includes everything from preview.2.
- v1 线协议未改变。/ The v1 wire protocol is unchanged.

## 注意 / Caveats

- **Android 客户端尚未完成真机测试**；问题请附上 App 内“复制诊断信息”的内容。
  The Android client has **not yet been tested on real devices**.
- APK 使用 CI 临时 debug 密钥签名，**升级前需先卸载旧版**。
  **Uninstall the previous APK before installing** (throwaway CI signing key).
- 程序均未进行代码签名；请勿为此关闭系统防护。
  Binaries are not code-signed; do not disable security software to run them.
- 升级 NAS 只需替换程序文件，身份、配对数据和面板密码不受影响。
  Upgrading the NAS only replaces the binary; identity, pairings and the dashboard password are kept.
