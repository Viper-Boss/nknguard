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

- **Windows 客户端改为原生桌面程序**：不再打开 Edge 浏览器窗口。新界面有渐变横幅、白色卡片和圆角按钮；关闭窗口后缩到右下角托盘，连接保持，在托盘菜单中“退出”才断开；只允许运行一个实例。不再需要 Microsoft Edge。
  The Windows client is now a native Win32 app with a tray icon; Microsoft Edge is no longer needed.
- **NAS 面板显示配对链接**：二维码下方直接显示同内容的 `nknguard://pair/v1?...` 链接，可一键复制（浏览器不允许复制时自动选中）。
  The dashboard shows the pairing link as text next to the QR code.
- 包含 preview.3 的全部内容：匿名使用人数统计、Android 客户端、内置国内 NKN seed、撤销通知等。
  Includes everything from preview.3.
- v1 线协议未改变。/ The v1 wire protocol is unchanged.

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
